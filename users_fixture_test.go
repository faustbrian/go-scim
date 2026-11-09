package scim_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"sync"
	"testing"
	"time"

	authentication "github.com/faustbrian/go-authentication/v2"
	identity "github.com/faustbrian/go-identity"
	organization "github.com/faustbrian/go-organization"
	scim "github.com/faustbrian/go-scim"
)

type protocolFixture struct {
	service    *scim.UsersService
	store      *protocolStore
	mapper     *protocolMapper
	authorizer *protocolAuthorizer
}

func newProtocolFixture(t *testing.T) *protocolFixture { return configuredProtocolFixture(t, nil) }
func configuredProtocolFixture(t *testing.T, configure func(*scim.Config)) *protocolFixture {
	t.Helper()
	f := &protocolFixture{
		store:      &protocolStore{resources: make(map[fixtureResourceKey]scim.Resource), replay: make(map[string]fixtureReplay), pending: make(map[identity.CommandID]scim.WriteIntent)},
		mapper:     &protocolMapper{},
		authorizer: &protocolAuthorizer{},
	}
	limits := scim.DefaultLimits()
	limits.PageDefault, limits.PageMax = 2, 2
	var err error
	config := scim.Config{
		Store:          f.store,
		Authenticator:  protocolAuthenticator{},
		Authorizer:     f.authorizer,
		Mapper:         f.mapper,
		Limits:         limits,
		BaseURL:        "https://scim.example.test/v2",
		Now:            func() time.Time { return fixtureNow },
		RequestTimeout: time.Second,
	}
	if configure != nil {
		configure(&config)
	}
	f.service, err = scim.NewUsersService(config)
	if err != nil {
		t.Fatalf("construct Users protocol profile: %v", err)
	}
	return f
}

func (f *protocolFixture) call(t *testing.T, op scim.Operation, id string, version scim.Version, body string) scim.Response {
	t.Helper()
	return f.execute(t, scim.Request{Operation: op, ResourceID: id, IfMatch: version, Body: []byte(body)})
}

func (f *protocolFixture) execute(t *testing.T, req scim.Request) scim.Response {
	t.Helper()
	req.Credential = authentication.NewBearerCredential("fixture-connection")
	if len(req.Body) > 0 && req.ContentType == "" {
		req.ContentType = "application/scim+json"
	}
	r, err := f.service.Execute(context.Background(), req)
	if err != nil {
		t.Fatalf("%s failed: %v", req.Operation, err)
	}
	if r.Status != 204 && r.ContentType != "application/scim+json" {
		t.Fatalf("wrong response media type: %#v", r)
	}
	return r
}

func (f *protocolFixture) deny(t *testing.T, req scim.Request, status int, scimType string) *scim.Error {
	t.Helper()
	req.Credential = authentication.NewBearerCredential("fixture-connection")
	if len(req.Body) > 0 && req.ContentType == "" {
		req.ContentType = "application/scim+json"
	}
	r, err := f.service.Execute(context.Background(), req)
	return assertProtocolError(t, r, err, status, scimType)
}

// This authenticator deliberately recognizes only local fixture credentials.
// It proves credential-to-connection wiring, not a real token verifier. Neither
// requests nor a caller-supplied principal/Boolean can select the resulting scope.
type protocolAuthenticator struct{}

func (protocolAuthenticator) Authenticate(ctx context.Context, credential authentication.BearerCredential) (scim.Connection, error) {
	if err := boundedFixtureContext(ctx); err != nil {
		return scim.Connection{}, err
	}
	scope := scim.Scope{TenantID: identity.TenantID("tenant-a"), OrganizationID: organization.ID("org-a"), ProviderID: "provider-a", ConnectionID: "connection-a"}
	switch credential.Token() {
	case "fixture-connection":
	case "fixture-other-connection":
		scope.ConnectionID = "connection-b"
	case "unowned":
		scope.OrganizationID = ""
	case "expired":
		return scim.Connection{Scope: scope, CredentialID: "fixture-token", Version: 1, ExpiresAt: fixtureNow.Add(-time.Second), AuthorityReadBeganAt: fixtureNow, AuthorityValidUntil: fixtureNow.Add(20 * time.Second)}, nil
	default:
		return scim.Connection{}, errors.New("private token verifier diagnostic")
	}
	return scim.Connection{Scope: scope, CredentialID: "fixture-token", Version: 1, ExpiresAt: fixtureNow.Add(time.Hour), AuthorityReadBeganAt: fixtureNow, AuthorityValidUntil: fixtureNow.Add(20 * time.Second)}, nil
}

type protocolAuthorizer struct{ err error }

func (p *protocolAuthorizer) Authorize(ctx context.Context, connection scim.Connection, op scim.Operation, id string) error {
	if err := boundedFixtureContext(ctx); err != nil {
		return err
	}
	if connection.Scope.OrganizationID == "" || connection.CredentialID == "" || op == "" {
		return errors.New("invalid fixture authorization scope")
	}
	return p.err
}

// A mapper is a side-effect-free representation policy. Returning a mapped
// resource does not create a user, attach an identity or grant membership.
type protocolMapper struct {
	mu    sync.Mutex
	calls int
}

func (m *protocolMapper) MapUser(ctx context.Context, scope scim.Scope, input scim.WritableResource) (scim.WritableResource, error) {
	if err := boundedFixtureContext(ctx); err != nil {
		return scim.WritableResource{}, err
	}
	m.mu.Lock()
	m.calls++
	m.mu.Unlock()
	return input, nil
}

type fixtureResourceKey struct {
	scope scim.Scope
	id    string
}

type fixtureReplay struct {
	canonical string
	result    scim.WriteResult
}

// protocolStore is an explicitly trusted, process-local boundary double. It
// models snapshot, CAS and replay outcomes only. It is not a domain store,
// durable command journal, adapter, connection authority or provisioning engine.
// No lock survives a method return and it invokes no caller callbacks.
type protocolStore struct {
	mu                            sync.Mutex
	resources                     map[fixtureResourceKey]scim.Resource
	replay                        map[string]fixtureReplay
	pending                       map[identity.CommandID]scim.WriteIntent
	prepares                      int
	incomplete, conflict, unknown bool
	failure                       error
	lastOutcome                   scim.WriteOutcome
}

func (s *protocolStore) Get(ctx context.Context, scope scim.Scope, id string) (scim.Resource, error) {
	if err := boundedFixtureContext(ctx); err != nil {
		return scim.Resource{}, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.failure != nil {
		return scim.Resource{}, s.failure
	}
	r, ok := s.resources[fixtureResourceKey{scope, id}]
	if !ok {
		return scim.Resource{}, scim.ErrNotFound
	}
	return cloneFixtureResource(r), nil
}

func (s *protocolStore) Snapshot(ctx context.Context, scope scim.Scope, maximum scim.SnapshotBudget) (scim.Snapshot, error) {
	if err := boundedFixtureContext(ctx); err != nil {
		return scim.Snapshot{}, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.failure != nil {
		return scim.Snapshot{}, s.failure
	}
	result := scim.Snapshot{Complete: !s.incomplete}
	remaining := maximum.Bytes
	for key, resource := range s.resources {
		if key.scope == scope {
			encoded, err := json.Marshal(resource)
			if err != nil {
				return scim.Snapshot{}, err
			}
			if len(encoded) > remaining {
				result.Complete = false
				break
			}
			if len(result.Resources) >= maximum.Resources {
				result.Complete = false
				break
			}
			result.Resources = append(result.Resources, cloneFixtureResource(resource))
			remaining -= len(encoded)
		}
	}
	return result, nil
}

func fixtureReplayKey(intent scim.WriteIntent) string {
	scope := intent.Scope
	partition := string(scope.TenantID) + "\x00" + string(scope.OrganizationID) + "\x00" + scope.ProviderID + "\x00" + scope.ConnectionID + "\x00" + string(intent.Operation) + "\x00"
	if intent.IdempotencyKey != "" {
		return partition + "key:" + intent.IdempotencyKey
	}
	if intent.Operation == scim.UserDelete {
		return partition + "delete:" + string(intent.CanonicalRequest)
	}
	return partition + "command:" + string(intent.CommandID)
}

func (s *protocolStore) Prepare(ctx context.Context, intent scim.WriteIntent) (scim.PreparedWrite, error) {
	if err := boundedFixtureContext(ctx); err != nil {
		return scim.PreparedWrite{}, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.prepares++
	if s.failure != nil {
		return scim.PreparedWrite{}, s.failure
	}
	if _, err := identity.ParseCommandID(string(intent.CommandID)); err != nil || len(intent.CanonicalRequest) == 0 {
		return scim.PreparedWrite{}, errors.New("invalid fixture server-owned command")
	}
	prepared := scim.PreparedWrite{Intent: intent}
	replay, hasReplay := s.replay[fixtureReplayKey(intent)]
	if !hasReplay && intent.Operation == scim.UserDelete && intent.IdempotencyKey != "" {
		withoutKey := intent
		withoutKey.IdempotencyKey = ""
		replay, hasReplay = s.replay[fixtureReplayKey(withoutKey)]
	}
	if hasReplay {
		if replay.canonical != string(intent.CanonicalRequest) {
			return scim.PreparedWrite{}, scim.ErrConflict
		}
		result := cloneFixtureResult(replay.result)
		prepared.Replay = &result
		return prepared, nil
	}
	if resource, exists := s.resources[fixtureResourceKey{intent.Scope, intent.ResourceID}]; exists {
		current := cloneFixtureResource(resource)
		prepared.Current = &current
	}
	s.pending[intent.CommandID] = intent
	s.replay[fixtureReplayKey(intent)] = fixtureReplay{canonical: string(intent.CanonicalRequest), result: scim.WriteResult{Outcome: scim.WriteOutcomeInProgress}}
	return prepared, nil
}

func (s *protocolStore) Commit(ctx context.Context, prepared scim.PreparedWrite, change scim.Change) (scim.WriteResult, error) {
	if err := boundedFixtureContext(ctx); err != nil {
		return scim.WriteResult{}, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	intent, exists := s.pending[prepared.Intent.CommandID]
	if !exists {
		return scim.WriteResult{}, errors.New("unknown fixture admission")
	}
	if s.unknown {
		s.lastOutcome = scim.WriteOutcomeUnknown
		s.replay[fixtureReplayKey(intent)] = fixtureReplay{canonical: string(intent.CanonicalRequest), result: scim.WriteResult{Outcome: scim.WriteOutcomeUnknown}}
		return scim.WriteResult{Outcome: scim.WriteOutcomeUnknown}, nil
	}
	key := fixtureResourceKey{intent.Scope, intent.ResourceID}
	current, exists := s.resources[key]
	if s.conflict || intent.Operation != scim.UserCreate && (!exists || current.Version != intent.IfMatch) {
		return scim.WriteResult{}, scim.ErrPreconditionFailed
	}
	if change.Resource != nil {
		candidate := change.Resource
		candidateKey, err := scim.UsernameComparisonKey(candidate.Attributes["userName"].(string))
		if err != nil {
			return scim.WriteResult{}, err
		}
		for otherKey, resource := range s.resources {
			if otherKey.scope != intent.Scope || otherKey.id == candidate.ID {
				continue
			}
			existingKey, err := scim.UsernameComparisonKey(resource.Attributes["userName"].(string))
			if err != nil {
				return scim.WriteResult{}, err
			}
			if existingKey == candidateKey {
				return scim.WriteResult{}, scim.ErrUniqueness
			}
		}
		key.id = candidate.ID
		s.resources[key] = cloneFixtureResource(*candidate)
	} else if change.Delete {
		delete(s.resources, key)
	} else {
		return scim.WriteResult{}, errors.New("empty fixture change")
	}
	result := scim.WriteResult{Outcome: scim.WriteOutcomeCommitted, Resource: change.Resource}
	s.lastOutcome = result.Outcome
	s.replay[fixtureReplayKey(intent)] = fixtureReplay{canonical: string(intent.CanonicalRequest), result: cloneFixtureResult(result)}
	// DELETE recovery also remains available without an optional extension key.
	if intent.Operation == scim.UserDelete {
		withoutKey := intent
		withoutKey.IdempotencyKey = ""
		s.replay[fixtureReplayKey(withoutKey)] = fixtureReplay{canonical: string(intent.CanonicalRequest), result: cloneFixtureResult(result)}
	}
	delete(s.pending, intent.CommandID)
	return cloneFixtureResult(result), nil
}

func (s *protocolStore) Abort(ctx context.Context, prepared scim.PreparedWrite) error {
	if err := boundedFixtureContext(ctx); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.unknown {
		if intent, exists := s.pending[prepared.Intent.CommandID]; exists {
			s.replay[fixtureReplayKey(intent)] = fixtureReplay{canonical: string(intent.CanonicalRequest), result: scim.WriteResult{Outcome: scim.WriteOutcomeNotCommitted, Failure: prepared.Failure}}
		}
		delete(s.pending, prepared.Intent.CommandID)
	}
	return nil
}

func cloneFixtureResource(r scim.Resource) scim.Resource {
	encoded, err := json.Marshal(r.Attributes)
	if err != nil {
		panic("invalid fixture attributes")
	}
	r.Attributes = nil
	decoder := json.NewDecoder(bytes.NewReader(encoded))
	decoder.UseNumber()
	if err := decoder.Decode(&r.Attributes); err != nil {
		panic("invalid fixture attributes")
	}
	return r
}

func cloneFixtureResult(r scim.WriteResult) scim.WriteResult {
	if r.Resource != nil {
		resource := cloneFixtureResource(*r.Resource)
		r.Resource = &resource
	}
	return r
}

func boundedFixtureContext(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if _, ok := ctx.Deadline(); !ok {
		return errors.New("protocol did not bound external work")
	}
	return nil
}
