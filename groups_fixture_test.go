package scim_test

import (
	"context"
	"encoding/json"
	"errors"
	"sync"
	"testing"
	"time"

	authentication "github.com/faustbrian/go-authentication/v2"
	identity "github.com/faustbrian/go-identity"
	scim "github.com/faustbrian/go-scim"
)

const groupURN = "urn:ietf:params:scim:schemas:core:2.0:Group"

type groupFixture struct {
	service *scim.GroupsService
	store   *groupProtocolStore
	mapper  *groupProtocolMapper
}

func newGroupFixture(t *testing.T, configure func(*scim.GroupsConfig)) *groupFixture {
	t.Helper()
	f := &groupFixture{
		store: &groupProtocolStore{protocolStore: protocolStore{
			resources: map[fixtureResourceKey]scim.Resource{},
			replay:    map[string]fixtureReplay{},
			pending:   map[identity.CommandID]scim.WriteIntent{},
		}, users: map[fixtureResourceKey]bool{}},
		mapper: &groupProtocolMapper{},
	}
	limits := scim.DefaultLimits()
	limits.PageDefault, limits.PageMax = 2, 2
	c := scim.GroupsConfig{Store: f.store, Mapper: f.mapper, Authenticator: protocolAuthenticator{}, Authorizer: &protocolAuthorizer{}, Limits: limits, GroupMembers: scim.DefaultGroupMembers, BaseURL: "https://scim.example.test/v2", Now: func() time.Time { return fixtureNow }, RequestTimeout: time.Second}
	if configure != nil {
		configure(&c)
	}
	var err error
	f.service, err = scim.NewGroupsService(c)
	if err != nil {
		t.Fatalf("construct Groups protocol profile: %v", err)
	}
	return f
}

func (f *groupFixture) execute(t *testing.T, request scim.Request) scim.Response {
	t.Helper()
	response, err := f.raw(request)
	if err != nil {
		t.Fatalf("%s failed: %v", request.Operation, err)
	}
	return response
}

func (f *groupFixture) raw(request scim.Request) (scim.Response, error) {
	if request.Credential.Token() == "" {
		request.Credential = authentication.NewBearerCredential("fixture-connection")
	}
	if len(request.Body) > 0 && request.ContentType == "" {
		request.ContentType = "application/scim+json"
	}
	return f.service.Execute(context.Background(), request)
}

func (f *groupFixture) call(t *testing.T, operation scim.Operation, id string, version scim.Version, body string) scim.Response {
	t.Helper()
	return f.execute(t, scim.Request{Operation: operation, ResourceID: id, IfMatch: version, Body: []byte(body)})
}

func (f *groupFixture) deny(t *testing.T, request scim.Request, status int, kind string) {
	t.Helper()
	response, err := f.raw(request)
	assertProtocolError(t, response, err, status, kind)
}

func groupBody(name, suffix string) string {
	encoded, _ := json.Marshal(name)
	return `{"schemas":["` + groupURN + `"],"displayName":` + string(encoded) + suffix + `}`
}

func (f *groupFixture) addUser(id, credential string) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	c, err := (protocolAuthenticator{}).Authenticate(ctx, authentication.NewBearerCredential(credential))
	if err != nil {
		panic(err)
	}
	f.store.users[fixtureResourceKey{c.Scope, id}] = true
}

type groupProtocolMapper struct {
	mu    sync.Mutex
	calls int
}

func (m *groupProtocolMapper) MapGroup(ctx context.Context, _ scim.Scope, input scim.WritableResource) (scim.WritableResource, error) {
	if err := boundedFixtureContext(ctx); err != nil {
		return scim.WritableResource{}, err
	}
	m.mu.Lock()
	m.calls++
	m.mu.Unlock()
	return input, nil
}

// This is an honest trusted protocol boundary double, not an organization or
// durable adapter. User existence is explicitly seeded, never provisioned.
// The inherited local admission model is one authority for this fixture only.
type groupProtocolStore struct {
	protocolStore
	users map[fixtureResourceKey]bool
}

func (s *groupProtocolStore) GetGroup(ctx context.Context, scope scim.Scope, id string) (scim.Resource, error) {
	return s.Get(ctx, scope, id)
}

func (s *groupProtocolStore) SnapshotGroups(ctx context.Context, scope scim.Scope, budget scim.SnapshotBudget) (scim.Snapshot, error) {
	return s.Snapshot(ctx, scope, budget)
}

func (s *groupProtocolStore) PrepareGroup(ctx context.Context, intent scim.WriteIntent) (scim.PreparedWrite, error) {
	// Reuse only the trusted fixture's storage-neutral admission algorithm. Its
	// Users-only headerless-delete key is explicitly selected here for Groups.
	if intent.Operation != scim.GroupDelete {
		return s.Prepare(ctx, intent)
	}
	if err := boundedFixtureContext(ctx); err != nil {
		return scim.PreparedWrite{}, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.prepares++
	prepared := scim.PreparedWrite{Intent: intent}
	key := groupFixtureReplayKey(intent)
	replay, exists := s.replay[key]
	if !exists && intent.IdempotencyKey != "" {
		withoutKey := intent
		withoutKey.IdempotencyKey = ""
		replay, exists = s.replay[groupFixtureReplayKey(withoutKey)]
	}
	if exists {
		if replay.canonical != string(intent.CanonicalRequest) {
			return scim.PreparedWrite{}, scim.ErrConflict
		}
		result := cloneFixtureResult(replay.result)
		prepared.Replay = &result
		return prepared, nil
	}
	if current, ok := s.resources[fixtureResourceKey{intent.Scope, intent.ResourceID}]; ok {
		copy := cloneFixtureResource(current)
		prepared.Current = &copy
	}
	s.pending[intent.CommandID] = intent
	s.replay[key] = fixtureReplay{canonical: string(intent.CanonicalRequest), result: scim.WriteResult{Outcome: scim.WriteOutcomeInProgress}}
	return prepared, nil
}

func groupFixtureReplayKey(intent scim.WriteIntent) string {
	if intent.Operation == scim.GroupDelete && intent.IdempotencyKey == "" {
		intent.IdempotencyKey = "delete:" + string(intent.CanonicalRequest)
	}
	return fixtureReplayKey(intent)
}

func (s *groupProtocolStore) CommitGroup(ctx context.Context, prepared scim.PreparedWrite, change scim.Change) (scim.WriteResult, error) {
	if err := boundedFixtureContext(ctx); err != nil {
		return scim.WriteResult{}, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	intent, admitted := s.pending[prepared.Intent.CommandID]
	if !admitted {
		return scim.WriteResult{}, errors.New("unknown fixture admission")
	}
	key := fixtureResourceKey{intent.Scope, intent.ResourceID}
	current, exists := s.resources[key]
	if s.conflict || intent.Operation != scim.GroupCreate && (!exists || current.Version != intent.IfMatch) {
		return scim.WriteResult{}, scim.ErrPreconditionFailed
	}
	if s.unknown {
		result := scim.WriteResult{Outcome: scim.WriteOutcomeUnknown}
		s.lastOutcome = result.Outcome
		s.replay[groupFixtureReplayKey(intent)] = fixtureReplay{canonical: string(intent.CanonicalRequest), result: result}
		return result, nil
	}
	if change.Resource != nil {
		candidate := *change.Resource
		members, _ := candidate.Attributes["members"].([]any)
		for _, raw := range members {
			member := raw.(map[string]any)
			memberKey := fixtureResourceKey{intent.Scope, member["value"].(string)}
			if member["type"] == "User" {
				if !s.users[memberKey] {
					return scim.WriteResult{}, scim.ErrInvalidGroupMember
				}
			} else if _, ok := s.resources[memberKey]; !ok {
				return scim.WriteResult{}, scim.ErrInvalidGroupMember
			}
		}
		key.id = candidate.ID
		if intent.Operation == scim.GroupCreate {
			if _, collision := s.resources[key]; collision {
				return scim.WriteResult{}, scim.ErrConflict
			}
		}
		s.resources[key] = cloneFixtureResource(candidate)
	} else if change.Delete {
		delete(s.resources, key)
	} else {
		return scim.WriteResult{}, errors.New("empty fixture change")
	}
	result := scim.WriteResult{Outcome: scim.WriteOutcomeCommitted, Resource: change.Resource}
	s.lastOutcome = result.Outcome
	s.replay[groupFixtureReplayKey(intent)] = fixtureReplay{canonical: string(intent.CanonicalRequest), result: cloneFixtureResult(result)}
	if intent.Operation == scim.GroupDelete {
		withoutKey := intent
		withoutKey.IdempotencyKey = ""
		s.replay[groupFixtureReplayKey(withoutKey)] = fixtureReplay{canonical: string(intent.CanonicalRequest), result: cloneFixtureResult(result)}
	}
	delete(s.pending, intent.CommandID)
	return cloneFixtureResult(result), nil
}

func (s *groupProtocolStore) AbortGroup(ctx context.Context, prepared scim.PreparedWrite) error {
	if prepared.Intent.Operation == scim.GroupDelete {
		if err := boundedFixtureContext(ctx); err != nil {
			return err
		}
		s.mu.Lock()
		defer s.mu.Unlock()
		if intent, exists := s.pending[prepared.Intent.CommandID]; exists && !s.unknown {
			s.replay[groupFixtureReplayKey(intent)] = fixtureReplay{canonical: string(intent.CanonicalRequest), result: scim.WriteResult{Outcome: scim.WriteOutcomeNotCommitted, Failure: prepared.Failure}}
			delete(s.pending, intent.CommandID)
		}
		return nil
	}
	return s.Abort(ctx, prepared)
}
