package scim_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	authentication "github.com/faustbrian/go-authentication/v2"
	identity "github.com/faustbrian/go-identity"
	scim "github.com/faustbrian/go-scim"
)

type admittedGroupsCreator interface {
	ExecuteAdmittedCreate(context.Context, scim.Request, func(context.Context) *scim.Error) (scim.Response, error)
}

func admittedGroupCreates(t *testing.T, service *scim.GroupsService) admittedGroupsCreator {
	t.Helper()
	selected, ok := any(service).(admittedGroupsCreator)
	if !ok {
		t.Fatal("GroupsService has no explicit post-authorization admitted Create selection")
	}
	return selected
}

func admittedGroupCreateRequest(name string) scim.Request {
	return scim.Request{Operation: scim.GroupCreate, Credential: authentication.NewBearerCredential("fixture-connection"), ContentType: "application/scim+json", Body: []byte(groupBody(name, ""))}
}

type admittedGroupCreateStore struct {
	scim.GroupStore
	intents                     []scim.WriteIntent
	chosen, proposed, committed identity.CommandID
	commits, aborts             int
	beforePrepare               func(context.Context)
	afterCommit                 func()
}

func (s *admittedGroupCreateStore) PrepareGroup(ctx context.Context, intent scim.WriteIntent) (scim.PreparedWrite, error) {
	if s.beforePrepare != nil {
		s.beforePrepare(ctx)
	}
	s.proposed = intent.CommandID
	if s.chosen != "" {
		intent.CommandID = s.chosen
	}
	saved := intent
	saved.CanonicalRequest = bytes.Clone(intent.CanonicalRequest)
	s.intents = append(s.intents, saved)
	return s.GroupStore.PrepareGroup(ctx, intent)
}

func (s *admittedGroupCreateStore) CommitGroup(ctx context.Context, prepared scim.PreparedWrite, change scim.Change) (scim.WriteResult, error) {
	s.commits++
	s.committed = prepared.Intent.CommandID
	result, err := s.GroupStore.CommitGroup(ctx, prepared, change)
	if s.afterCommit != nil {
		s.afterCommit()
	}
	return result, err
}

func (s *admittedGroupCreateStore) AbortGroup(ctx context.Context, prepared scim.PreparedWrite) error {
	s.aborts++
	return s.GroupStore.AbortGroup(ctx, prepared)
}

func TestGroupsAdmittedCreateRetainsCanonicalCommandMappingAndReplay(t *testing.T) {
	command, err := identity.NewCommandID()
	if err != nil {
		t.Fatal(err)
	}
	var writes *admittedGroupCreateStore
	policy := &protocolAuthorizer{}
	f := newGroupFixture(t, func(c *scim.GroupsConfig) {
		c.Authorizer = policy
		writes = &admittedGroupCreateStore{GroupStore: c.Store, chosen: command}
		c.Store = writes
	})
	f.addUser("member-a", "fixture-connection")
	request := admittedGroupCreateRequest("admitted-group")
	request.Body = []byte(groupBody("admitted-group", `,"members":[{"value":"member-a","$ref":"Users/member-a"}]`))
	request.IdempotencyKey = "group-create-key"
	calls := 0
	writes.beforePrepare = func(ctx context.Context) {
		if calls != len(writes.intents)+1 || boundedFixtureContext(ctx) != nil {
			t.Fatal("Group Store admission preceded its once-per-attempt bounded gate")
		}
	}
	created, err := admittedGroupCreates(t, f.service).ExecuteAdmittedCreate(context.Background(), request, func(ctx context.Context) *scim.Error {
		calls++
		if boundedFixtureContext(ctx) != nil || f.mapper.calls != 0 || len(writes.intents) != 0 || len(f.store.resources) != 0 {
			t.Fatal("Group gate followed mapping or command effects")
		}
		return nil
	})
	if err != nil || created.Status != 201 || calls != 1 || writes.commits != 1 || writes.aborts != 0 || writes.committed != command || writes.proposed == command || f.mapper.calls != 1 || len(f.store.resources) != 1 {
		t.Fatal("Group admission changed canonical creation or Store-owned command", err)
	}
	var canonical struct {
		Operation scim.Operation
		ID        string
		IfMatch   scim.Version
		Body      map[string]any
	}
	intent := writes.intents[0]
	if json.Unmarshal(intent.CanonicalRequest, &canonical) != nil || canonical.Operation != scim.GroupCreate || canonical.ID != "" || canonical.IfMatch != "" || canonical.Body["displayName"] != "admitted-group" || intent.Scope != intent.Connection.Scope || intent.Connection.Version != 1 || intent.IdempotencyKey != request.IdempotencyKey {
		t.Fatal("Group admission replaced normalized canonical input or authenticated scope")
	}
	member := object(t, created.Body)["members"].([]any)[0].(map[string]any)
	if member["value"] != "member-a" || member["type"] != "User" || member["$ref"] != "https://scim.example.test/v2/Users/member-a" || created.ETag == "" || created.Location == "" {
		t.Fatal("Group creation lost normalized typed membership, location or version")
	}
	replay, err := admittedGroupCreates(t, f.service).ExecuteAdmittedCreate(context.Background(), request, func(context.Context) *scim.Error { calls++; return nil })
	if err != nil || replay.Status != created.Status || replay.ETag != created.ETag || replay.Location != created.Location || !bytes.Equal(replay.Body, created.Body) || calls != 2 || writes.commits != 1 || f.mapper.calls != 1 || len(writes.intents) != 2 || !bytes.Equal(intent.CanonicalRequest, writes.intents[1].CanonicalRequest) {
		t.Fatal("Group retry bypassed admission or changed original semantic replay", err)
	}
	denied, err := admittedGroupCreates(t, f.service).ExecuteAdmittedCreate(context.Background(), request, func(context.Context) *scim.Error { calls++; return scim.NewError(403, "") })
	assertProtocolError(t, denied, err, 403, "")
	if calls != 3 || writes.commits != 1 || len(writes.intents) != 2 {
		t.Fatal("denied replay reached Group command authority")
	}
}

func TestGroupsAdmittedCreateRejectsBeforeGateMappingOrStore(t *testing.T) {
	for _, tc := range []struct {
		name                  string
		change                func(*scim.Request)
		deny, cancel, nilGate bool
		status                int
	}{
		{name: "unknown bearer", change: func(r *scim.Request) { r.Credential = authentication.NewBearerCredential("unknown") }, status: 401},
		{name: "invalid bearer", change: func(r *scim.Request) { r.Credential = authentication.NewBearerCredential("invalid bearer") }, status: 401},
		{name: "expired bearer", change: func(r *scim.Request) { r.Credential = authentication.NewBearerCredential("expired") }, status: 401},
		{name: "unowned bearer", change: func(r *scim.Request) { r.Credential = authentication.NewBearerCredential("unowned") }, status: 401},
		{name: "policy denial", deny: true, status: 403},
		{name: "canceled parent", cancel: true, status: 503},
		{name: "missing gate", nilGate: true, status: 503},
		{name: "User Create", change: func(r *scim.Request) { r.Operation = scim.UserCreate }, status: 501},
		{name: "Group Get", change: func(r *scim.Request) { r.Operation = scim.GroupGet }, status: 501},
		{name: "Group Replace", change: func(r *scim.Request) { r.Operation = scim.GroupReplace }, status: 501},
		{name: "Group Patch", change: func(r *scim.Request) { r.Operation = scim.GroupPatch }, status: 501},
		{name: "Group Delete", change: func(r *scim.Request) { r.Operation = scim.GroupDelete }, status: 501},
		{name: "discovery", change: func(r *scim.Request) { r.Operation = scim.ServiceProviderConfig }, status: 501},
		{name: "Bulk", change: func(r *scim.Request) { r.Operation = scim.Bulk }, status: 501},
		{name: "missing body", change: func(r *scim.Request) { r.Body = nil }, status: 400},
		{name: "malformed JSON", change: func(r *scim.Request) { r.Body = []byte(`{"schemas":[`) }, status: 400},
		{name: "case alias", change: func(r *scim.Request) { r.Body = []byte(groupBody("one", `,"DISPLAYNAME":"two"`)) }, status: 400},
		{name: "server metadata", change: func(r *scim.Request) { r.Body = []byte(groupBody("one", `,"id":"client-owned"`)) }, status: 400},
		{name: "missing displayName", change: func(r *scim.Request) { r.Body = []byte(`{"schemas":["` + groupURN + `"]}`) }, status: 400},
		{name: "wrong schema", change: func(r *scim.Request) { r.Body = []byte(userBody("not-a-Group", "")) }, status: 400},
		{name: "client target", change: func(r *scim.Request) { r.ResourceID = "client-owned" }, status: 400},
		{name: "client precondition", change: func(r *scim.Request) { r.IfMatch = `"client-owned"` }, status: 400},
		{name: "invalid projection", change: func(r *scim.Request) { r.Query.Attributes = "userName" }, status: 400},
		{name: "foreign reference", change: func(r *scim.Request) {
			r.Body = []byte(groupBody("one", `,"members":[{"value":"member-a","$ref":"https://foreign.example.test/v2/Users/member-a"}]`))
		}, status: 400},
		{name: "mismatched reference type", change: func(r *scim.Request) {
			r.Body = []byte(groupBody("one", `,"members":[{"value":"member-a","type":"Group","$ref":"Users/member-a"}]`))
		}, status: 400},
		{name: "duplicate members", change: func(r *scim.Request) { r.Body = []byte(groupBody("one", `,"members":[{"value":"a"},{"value":"a"}]`)) }, status: 400},
		{name: "member ceiling", change: func(r *scim.Request) { r.Body = []byte(groupBody("one", `,"members":[{"value":"a"},{"value":"b"}]`)) }, status: 400},
		{name: "oversized string", change: func(r *scim.Request) {
			r.Body = []byte(groupBody(strings.Repeat("x", scim.DefaultLimits().StringBytes+1), ""))
		}, status: 400},
		{name: "oversized body", change: func(r *scim.Request) { r.Body = bytes.Repeat([]byte(" "), scim.DefaultLimits().BodyBytes+1) }, status: 413},
		{name: "content type", change: func(r *scim.Request) { r.ContentType = "application/json" }, status: 415},
		{name: "content encoding", change: func(r *scim.Request) { r.ContentEncoding = "gzip" }, status: 415},
	} {
		t.Run(tc.name, func(t *testing.T) {
			policy := &protocolAuthorizer{}
			f := newGroupFixture(t, func(c *scim.GroupsConfig) { c.Authorizer = policy; c.GroupMembers = 1 })
			if tc.deny {
				policy.err = errors.New("private policy diagnostic")
			}
			request := admittedGroupCreateRequest("unadmitted")
			if tc.change != nil {
				tc.change(&request)
			}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			if tc.cancel {
				cancel()
			}
			calls := 0
			var gate func(context.Context) *scim.Error
			if !tc.nilGate {
				gate = func(context.Context) *scim.Error { calls++; return nil }
			}
			out, err := admittedGroupCreates(t, f.service).ExecuteAdmittedCreate(ctx, request, gate)
			assertProtocolError(t, out, err, tc.status, "")
			if calls != 0 || f.store.prepares != 0 || f.mapper.calls != 0 || len(f.store.resources) != 0 || out.Status != 0 || out.ETag != "" || out.Location != "" || out.ContentType != "" {
				t.Fatal("invalid or unauthorized Group create charged admission or disclosed effects")
			}
		})
	}
	for _, service := range []*scim.GroupsService{nil, new(scim.GroupsService)} {
		out, err := admittedGroupCreates(t, service).ExecuteAdmittedCreate(context.Background(), admittedGroupCreateRequest("invalid-service"), func(context.Context) *scim.Error { t.Fatal("invalid service invoked gate"); return nil })
		assertProtocolError(t, out, err, 503, "")
	}
}

func TestGroupsAdmittedCreateNormalizesDenialBeforeEffects(t *testing.T) {
	for _, tc := range []struct {
		name   string
		deny   func(context.Context) *scim.Error
		status int
		retry  uint32
	}{
		{name: "policy", deny: func(context.Context) *scim.Error { return scim.NewError(403, "") }, status: 403},
		{name: "quota", deny: func(context.Context) *scim.Error { return scim.NewRateLimitedError(1250 * time.Millisecond) }, status: 429, retry: 2},
		{name: "quota unknown", deny: func(context.Context) *scim.Error { return scim.NewError(429, "") }, status: 503},
		{name: "quota zero", deny: func(context.Context) *scim.Error { return scim.NewRateLimitedError(0) }, status: 503},
		{name: "unavailable", deny: func(context.Context) *scim.Error { return scim.NewError(503, "") }, status: 503},
		{name: "unsupported", deny: func(context.Context) *scim.Error { return scim.NewError(404, "") }, status: 503},
		{name: "typed", deny: func(context.Context) *scim.Error { return scim.NewError(400, "invalidValue") }, status: 503},
		{name: "panic", deny: func(context.Context) *scim.Error { panic("private gate diagnostic") }, status: 503},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newGroupFixture(t, nil)
			calls := 0
			out, err := admittedGroupCreates(t, f.service).ExecuteAdmittedCreate(context.Background(), admittedGroupCreateRequest("denied"), func(ctx context.Context) *scim.Error { calls++; return tc.deny(ctx) })
			denied := assertProtocolError(t, out, err, tc.status, "")
			if calls != 1 || denied.SCIMType() != "" || denied.RetryAfterSeconds() != tc.retry || f.store.prepares != 0 || f.mapper.calls != 0 || len(f.store.resources) != 0 || out.Status != 0 || out.Location != "" || out.ETag != "" || out.ContentType != "" {
				t.Fatal("Group denial lost redaction or reached command/mapping effects")
			}
		})
	}
}

func TestGroupsAdmittedCreateRejectsDescendantReentryEvenInvalidWrappers(t *testing.T) {
	for _, nested := range []string{"ordinary Group", "admitted Group", "Group read", "foreign operation", "missing gate", "nil service", "uninitialized service", "sibling User"} {
		t.Run(nested, func(t *testing.T) {
			f := newGroupFixture(t, nil)
			users := newProtocolFixture(t)
			request := admittedGroupCreateRequest("reentry")
			calls := 0
			out, err := admittedGroupCreates(t, f.service).ExecuteAdmittedCreate(context.Background(), request, func(ctx context.Context) *scim.Error {
				calls++
				ctx, cancel := context.WithCancel(ctx)
				defer cancel()
				var inner scim.Response
				var innerErr error
				gate := func(context.Context) *scim.Error { t.Fatal("nested gate executed"); return nil }
				switch nested {
				case "ordinary Group":
					inner, innerErr = f.service.Execute(ctx, request)
				case "admitted Group":
					inner, innerErr = admittedGroupCreates(t, f.service).ExecuteAdmittedCreate(ctx, request, gate)
				case "Group read":
					inner, innerErr = admittedGroups(t, f.service).ExecuteAdmittedRead(ctx, admittedGroupReadRequest(scim.GroupList, ""), gate)
				case "foreign operation":
					request.Operation = scim.UserCreate
					inner, innerErr = admittedGroupCreates(t, f.service).ExecuteAdmittedCreate(ctx, request, gate)
				case "missing gate":
					inner, innerErr = admittedGroupCreates(t, f.service).ExecuteAdmittedCreate(ctx, request, nil)
				case "nil service":
					inner, innerErr = admittedGroupCreates(t, nil).ExecuteAdmittedCreate(ctx, request, nil)
				case "uninitialized service":
					inner, innerErr = admittedGroupCreates(t, new(scim.GroupsService)).ExecuteAdmittedCreate(ctx, request, nil)
				case "sibling User":
					inner, innerErr = users.service.Execute(ctx, admittedCreateRequest("sibling"))
				}
				assertProtocolError(t, inner, innerErr, 503, "")
				return nil
			})
			assertProtocolError(t, out, err, 503, "")
			if calls != 1 || f.store.prepares != 0 || f.mapper.calls != 0 || len(f.store.resources) != 0 || users.store.prepares != 0 || users.mapper.calls != 0 {
				t.Fatal("ignored nested denial escaped Group invocation fence")
			}
		})
	}
}

func TestGroupsAdmittedCreateRetainsOriginalAuthorityAndLateCommitFence(t *testing.T) {
	for _, stage := range []string{"before gate", "gate allow", "gate deny", "gate quota", "cancel gate", "late commit", "cancel commit"} {
		t.Run(stage, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
			defer cancel()
			connection, err := (protocolAuthenticator{}).Authenticate(ctx, authentication.NewBearerCredential("fixture-connection"))
			if err != nil {
				t.Fatal(err)
			}
			clock := &freshnessFixture{test: t, now: fixtureNow.Add(19 * time.Second), connection: connection, visits: make(map[string]int)}
			var writes *admittedGroupCreateStore
			f := newGroupFixture(t, func(c *scim.GroupsConfig) {
				c.Now = func() time.Time { return clock.now }
				c.RequestTimeout = time.Minute
				c.Authenticator = freshnessAuthenticator{state: clock}
				c.Authorizer = freshnessAuthorizer{Authorizer: c.Authorizer, state: clock}
				writes = &admittedGroupCreateStore{GroupStore: c.Store}
				c.Store = writes
			})
			if stage == "before gate" {
				clock.advanceAt, clock.advanceTo = "authorize", connection.AuthorityValidUntil
			}
			if stage == "late commit" || stage == "cancel commit" {
				writes.afterCommit = func() {
					if stage == "late commit" {
						clock.now = connection.AuthorityValidUntil
					} else {
						cancel()
					}
				}
			}
			calls := 0
			out, err := admittedGroupCreates(t, f.service).ExecuteAdmittedCreate(ctx, admittedGroupCreateRequest("original-budget"), func(gate context.Context) *scim.Error {
				calls++
				deadline, ok := gate.Deadline()
				if !ok || time.Until(deadline) > time.Second+100*time.Millisecond || clock.policyCalls != 1 {
					t.Fatal("Group gate renewed authority or preceded current operation authorization")
				}
				switch stage {
				case "gate allow", "gate deny", "gate quota":
					clock.now = connection.AuthorityValidUntil
				case "cancel gate":
					cancel()
				}
				if stage == "gate deny" || stage == "cancel gate" {
					return scim.NewError(403, "")
				}
				if stage == "gate quota" {
					return scim.NewRateLimitedError(time.Second)
				}
				return nil
			})
			assertProtocolError(t, out, err, 503, "")
			wantCalls, wantWrites := 1, 0
			if stage == "before gate" {
				wantCalls = 0
			}
			if stage == "late commit" || stage == "cancel commit" {
				wantWrites = 1
				if f.store.lastOutcome != scim.WriteOutcomeCommitted || writes.aborts != 0 {
					t.Fatal("late disclosure fence rewrote a committed Group result")
				}
			}
			if calls != wantCalls || len(writes.intents) != wantWrites || writes.commits != wantWrites || f.mapper.calls != wantWrites || len(f.store.resources) != wantWrites || out.Status != 0 || out.Location != "" || out.ETag != "" || out.ContentType != "" {
				t.Fatal("Group authority/cancellation boundary leaked metadata or crossed the no-effect fence")
			}
		})
	}
}

func TestGroupsAdmittedCreateRetainsEarlierParentAndRequestDeadlines(t *testing.T) {
	for _, earlier := range []string{"parent", "request"} {
		t.Run(earlier, func(t *testing.T) {
			f := newGroupFixture(t, func(c *scim.GroupsConfig) {
				if earlier == "request" {
					c.RequestTimeout = 150 * time.Millisecond
				}
			})
			ctx := context.Background()
			bound := time.Now().Add(150 * time.Millisecond)
			if earlier == "parent" {
				var cancel context.CancelFunc
				ctx, cancel = context.WithDeadline(ctx, bound)
				defer cancel()
			}
			out, err := admittedGroupCreates(t, f.service).ExecuteAdmittedCreate(ctx, admittedGroupCreateRequest("bounded"), func(gate context.Context) *scim.Error {
				deadline, ok := gate.Deadline()
				if !ok || deadline.After(bound.Add(25*time.Millisecond)) {
					t.Fatal("Group gate extended earlier parent or request budget")
				}
				return scim.NewError(403, "")
			})
			assertProtocolError(t, out, err, 403, "")
			if f.store.prepares != 0 || f.mapper.calls != 0 || len(f.store.resources) != 0 {
				t.Fatal("bounded denial reached Group resource effects")
			}
		})
	}
}

func TestGroupsAdmittedCreatePreservesStoreMemberAndCASAuthority(t *testing.T) {
	for _, scenario := range []string{"missing member", "foreign member", "wrong member type", "CAS denial", "unknown outcome"} {
		t.Run(scenario, func(t *testing.T) {
			var writes *admittedGroupCreateStore
			f := newGroupFixture(t, func(c *scim.GroupsConfig) {
				writes = &admittedGroupCreateStore{GroupStore: c.Store}
				c.Store = writes
			})
			request := admittedGroupCreateRequest("store-authority")
			request.IdempotencyKey = "store-authority-key"
			if scenario == "foreign member" {
				f.addUser("member-a", "fixture-other-connection")
			}
			if scenario == "wrong member type" {
				f.addUser("member-a", "fixture-connection")
				request.Body = []byte(groupBody("store-authority", `,"members":[{"value":"member-a","type":"Group"}]`))
			} else if scenario == "missing member" || scenario == "foreign member" {
				request.Body = []byte(groupBody("store-authority", `,"members":[{"value":"member-a"}]`))
			}
			calls := 0
			out, err := admittedGroupCreates(t, f.service).ExecuteAdmittedCreate(context.Background(), request, func(context.Context) *scim.Error {
				calls++
				f.store.conflict = scenario == "CAS denial"
				f.store.unknown = scenario == "unknown outcome"
				return nil
			})
			status, aborts := 400, 1
			if scenario == "CAS denial" {
				status = 412
			}
			if scenario == "unknown outcome" {
				status, aborts = 503, 0
			}
			assertProtocolError(t, out, err, status, "")
			if calls != 1 || len(writes.intents) != 1 || writes.commits != 1 || writes.aborts != aborts || f.mapper.calls != 1 || len(f.store.resources) != 0 {
				t.Fatal("allowed gate bypassed exact-scope Group member/CAS/outcome authority")
			}
			if scenario == "unknown outcome" {
				replay, replayErr := admittedGroupCreates(t, f.service).ExecuteAdmittedCreate(context.Background(), request, func(context.Context) *scim.Error { calls++; return nil })
				assertProtocolError(t, replay, replayErr, 503, "")
				if calls != 2 || writes.commits != 1 || writes.aborts != 0 || f.mapper.calls != 1 {
					t.Fatal("unknown Group outcome became permission for a second effect")
				}
			}
		})
	}
}

func TestGroupsAdmittedCreatePreservesOrdinaryAndSiblingSelections(t *testing.T) {
	f := newGroupFixture(t, nil)
	request := admittedGroupCreateRequest("ordinary-group")
	out, err := admittedGroupCreates(t, f.service).ExecuteAdmittedCreate(context.Background(), request, func(context.Context) *scim.Error { return scim.NewError(403, "") })
	assertProtocolError(t, out, err, 403, "")
	created, err := f.service.Execute(context.Background(), request)
	if err != nil || created.Status != 201 || len(f.store.resources) != 1 || f.mapper.calls != 1 {
		t.Fatal("per-call Group denial changed ordinary Group creation", err)
	}
	id := object(t, created.Body)["id"].(string)
	read, err := admittedGroups(t, f.service).ExecuteAdmittedRead(context.Background(), admittedGroupReadRequest(scim.GroupGet, id), func(context.Context) *scim.Error { return nil })
	if err != nil || read.ETag != created.ETag || !bytes.Equal(read.Body, created.Body) {
		t.Fatal("Group Create admission changed admitted Group reads", err)
	}
	users := newProtocolFixture(t)
	user, err := admittedCreates(t, users.service).ExecuteAdmittedCreate(context.Background(), admittedCreateRequest("sibling-user"), func(context.Context) *scim.Error { return nil })
	if err != nil || user.Status != 201 || users.mapper.calls != 1 || len(users.store.resources) != 1 {
		t.Fatal("Group Create admission changed sibling User Create", err)
	}
	f.call(t, scim.ServiceProviderConfig, "", "", "")
}

func FuzzGroupsAdmittedCreateJSON(f *testing.F) {
	f.Add([]byte(groupBody("valid", "")))
	f.Add([]byte(groupBody("members", `,"members":[{"value":"member-a"}]`)))
	f.Add([]byte(groupBody("duplicate", `,"DISPLAYNAME":"collision"`)))
	f.Add([]byte(`{"schemas":[`))
	f.Fuzz(func(t *testing.T, body []byte) {
		fixture := newGroupFixture(t, nil)
		request := admittedGroupCreateRequest("fuzz")
		request.Body = body
		calls := 0
		out, err := admittedGroupCreates(t, fixture.service).ExecuteAdmittedCreate(context.Background(), request, func(context.Context) *scim.Error { calls++; return scim.NewError(403, "") })
		var denied *scim.Error
		if !errors.As(err, &denied) || calls > 1 || out.Status != 0 || len(out.Body) != 0 || out.ETag != "" || out.Location != "" || out.ContentType != "" || fixture.store.prepares != 0 || fixture.mapper.calls != 0 || len(fixture.store.resources) != 0 {
			t.Fatal("bounded Group input escaped denial before mapping or command effects")
		}
	})
}
