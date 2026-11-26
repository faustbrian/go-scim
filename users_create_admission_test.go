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

type admittedUsersCreator interface {
	ExecuteAdmittedCreate(context.Context, scim.Request, func(context.Context) *scim.Error) (scim.Response, error)
}

func admittedCreates(t *testing.T, service *scim.UsersService) admittedUsersCreator {
	t.Helper()
	selected, ok := any(service).(admittedUsersCreator)
	if !ok {
		t.Fatal("UsersService has no explicit post-authorization admitted Create selection")
	}
	return selected
}

func admittedCreateRequest(name string) scim.Request {
	return scim.Request{Operation: scim.UserCreate, Credential: authentication.NewBearerCredential("fixture-connection"), ContentType: "application/scim+json", Body: []byte(userBody(name, ""))}
}

type admittedCreateStore struct {
	scim.Store
	intents         []scim.WriteIntent
	commits, aborts int
	beforePrepare   func(context.Context)
}

func (s *admittedCreateStore) Prepare(ctx context.Context, intent scim.WriteIntent) (scim.PreparedWrite, error) {
	if s.beforePrepare != nil {
		s.beforePrepare(ctx)
	}
	saved := intent
	saved.CanonicalRequest = bytes.Clone(intent.CanonicalRequest)
	s.intents = append(s.intents, saved)
	return s.Store.Prepare(ctx, intent)
}

func (s *admittedCreateStore) Commit(ctx context.Context, prepared scim.PreparedWrite, change scim.Change) (scim.WriteResult, error) {
	s.commits++
	return s.Store.Commit(ctx, prepared, change)
}
func (s *admittedCreateStore) Abort(ctx context.Context, prepared scim.PreparedWrite) error {
	s.aborts++
	return s.Store.Abort(ctx, prepared)
}

func TestUsersAdmittedCreateRetainsCanonicalStoreCommandAndReplay(t *testing.T) {
	command, err := identity.NewCommandID()
	if err != nil {
		t.Fatal(err)
	}
	var owner *ownerCommandStore
	var writes *admittedCreateStore
	f := configuredProtocolFixture(t, func(c *scim.Config) {
		owner = &ownerCommandStore{Store: c.Store, chosen: command}
		writes = &admittedCreateStore{Store: owner}
		c.Store = writes
	})
	request := admittedCreateRequest("admitted-original")
	request.IdempotencyKey = "original-create-key"
	calls := 0
	writes.beforePrepare = func(ctx context.Context) {
		if calls != len(writes.intents)+1 {
			t.Fatal("Store admission did not follow exactly one gate per request")
		}
		if boundedFixtureContext(ctx) != nil {
			t.Fatal("Store received no bounded original context")
		}
	}
	gate := func(ctx context.Context) *scim.Error {
		calls++
		if boundedFixtureContext(ctx) != nil || writes.commits != 0 || f.mapper.calls != 0 || len(writes.intents) != 0 {
			t.Fatal("first gate followed mapping or command effects, or had no budget")
		}
		return nil
	}
	created, err := admittedCreates(t, f.service).ExecuteAdmittedCreate(context.Background(), request, gate)
	if err != nil || created.Status != 201 || calls != 1 || writes.commits != 1 || writes.aborts != 0 || owner.committed != command || owner.proposed == command || f.mapper.calls != 1 || len(writes.intents) != 1 {
		t.Fatal("admitted Create did not keep the real canonical write and durable owner's original command", err)
	}
	intent := writes.intents[0]
	var canonical struct {
		Operation scim.Operation
		ID        string
		IfMatch   scim.Version
		Body      map[string]any
		Query     scim.Query
	}
	if json.Unmarshal(intent.CanonicalRequest, &canonical) != nil || canonical.Operation != scim.UserCreate || canonical.ID != "" || canonical.IfMatch != "" || canonical.Body["userName"] != "admitted-original" || intent.IdempotencyKey != request.IdempotencyKey || intent.Scope != intent.Connection.Scope || intent.Connection.Version != 1 {
		t.Fatal("Create admission replaced canonical input, scope or original connection")
	}
	replay, err := admittedCreates(t, f.service).ExecuteAdmittedCreate(context.Background(), request, func(context.Context) *scim.Error { calls++; return nil })
	if err != nil || replay.Status != created.Status || replay.ETag != created.ETag || replay.Location != created.Location || !bytes.Equal(replay.Body, created.Body) || calls != 2 || writes.commits != 1 || f.mapper.calls != 1 || len(writes.intents) != 2 || !bytes.Equal(intent.CanonicalRequest, writes.intents[1].CanonicalRequest) {
		t.Fatal("admitted retry changed canonical replay or repeated its write", err)
	}
	denied, err := admittedCreates(t, f.service).ExecuteAdmittedCreate(context.Background(), request, func(context.Context) *scim.Error { calls++; return scim.NewRateLimitedError(time.Second) })
	assertProtocolError(t, denied, err, 429, "")
	if calls != 3 || writes.commits != 1 || len(writes.intents) != 2 {
		t.Fatal("denied replay bypassed admission or performed command work")
	}
}

func TestUsersAdmittedCreateRejectsBeforeChargingOrWriting(t *testing.T) {
	for _, tc := range []struct {
		name                        string
		change                      func(*scim.Request)
		policyDeny, cancel, nilGate bool
		status                      int
	}{
		{name: "unknown bearer", change: func(r *scim.Request) { r.Credential = authentication.NewBearerCredential("unknown-fixture") }, status: 401},
		{name: "invalid bearer", change: func(r *scim.Request) { r.Credential = authentication.NewBearerCredential("invalid bearer") }, status: 401},
		{name: "expired bearer", change: func(r *scim.Request) { r.Credential = authentication.NewBearerCredential("expired") }, status: 401},
		{name: "unowned bearer", change: func(r *scim.Request) { r.Credential = authentication.NewBearerCredential("unowned") }, status: 401},
		{name: "unauthorized", policyDeny: true, status: 403},
		{name: "canceled", cancel: true, status: 503},
		{name: "missing gate", nilGate: true, status: 503},
		{name: "read not selected", change: func(r *scim.Request) { r.Operation = scim.UserGet }, status: 501},
		{name: "replace not selected", change: func(r *scim.Request) { r.Operation = scim.UserReplace }, status: 501},
		{name: "Groups not selected", change: func(r *scim.Request) { r.Operation = scim.GroupCreate }, status: 501},
		{name: "Bulk not selected", change: func(r *scim.Request) { r.Operation = scim.Bulk }, status: 501},
		{name: "missing body", change: func(r *scim.Request) { r.Body = nil }, status: 400},
		{name: "malformed JSON", change: func(r *scim.Request) { r.Body = []byte(`{"schemas":[`) }, status: 400},
		{name: "duplicate member", change: func(r *scim.Request) { r.Body = []byte(userBody("duplicate", `,"userName":"again"`)) }, status: 400},
		{name: "case alias", change: func(r *scim.Request) { r.Body = []byte(userBody("alias", `,"USERNAME":"again"`)) }, status: 400},
		{name: "unknown schema", change: func(r *scim.Request) { r.Body = []byte(`{"schemas":["urn:unknown"],"userName":"schema"}`) }, status: 400},
		{name: "missing username", change: func(r *scim.Request) { r.Body = []byte(`{"schemas":["` + userURN + `"],"displayName":"no username"}`) }, status: 400},
		{name: "credential write", change: func(r *scim.Request) { r.Body = []byte(userBody("password", `,"password":"never-store-this"`)) }, status: 400},
		{name: "server metadata", change: func(r *scim.Request) { r.Body = []byte(userBody("server", `,"id":"client-owned"`)) }, status: 400},
		{name: "client target", change: func(r *scim.Request) { r.ResourceID = "client-owned" }, status: 400},
		{name: "invalid query", change: func(r *scim.Request) { r.Query.Attributes = "password" }, status: 400},
		{name: "oversized string", change: func(r *scim.Request) {
			r.Body = []byte(userBody(strings.Repeat("x", scim.DefaultLimits().StringBytes+1), ""))
		}, status: 400},
		{name: "oversized body", change: func(r *scim.Request) { r.Body = bytes.Repeat([]byte(" "), scim.DefaultLimits().BodyBytes+1) }, status: 413},
		{name: "unsupported content type", change: func(r *scim.Request) { r.ContentType = "application/json" }, status: 415},
		{name: "unsupported encoding", change: func(r *scim.Request) { r.ContentEncoding = "gzip" }, status: 415},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var writes *admittedCreateStore
			f := configuredProtocolFixture(t, func(c *scim.Config) { writes = &admittedCreateStore{Store: c.Store}; c.Store = writes })
			if tc.policyDeny {
				f.authorizer.err = errors.New("private policy diagnostic")
			}
			request := admittedCreateRequest("unadmitted")
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
			out, err := admittedCreates(t, f.service).ExecuteAdmittedCreate(ctx, request, gate)
			assertProtocolError(t, out, err, tc.status, "")
			if calls != 0 || len(writes.intents) != 0 || writes.commits != 0 || writes.aborts != 0 || f.mapper.calls != 0 || len(f.store.resources) != 0 {
				t.Fatal("invalid or unauthorized Create charged admission, mapped or performed command work")
			}
		})
	}
}

func TestUsersAdmittedCreateNormalizesDenialsBeforeCommandEffects(t *testing.T) {
	for _, tc := range []struct {
		name   string
		deny   func(context.Context) *scim.Error
		status int
		retry  uint32
	}{
		{name: "policy", deny: func(context.Context) *scim.Error { return scim.NewError(403, "") }, status: 403},
		{name: "quota", deny: func(context.Context) *scim.Error { return scim.NewRateLimitedError(1250 * time.Millisecond) }, status: 429, retry: 2},
		{name: "quota unknown wait", deny: func(context.Context) *scim.Error { return scim.NewError(429, "") }, status: 503},
		{name: "quota zero wait", deny: func(context.Context) *scim.Error { return scim.NewRateLimitedError(0) }, status: 503},
		{name: "unavailable", deny: func(context.Context) *scim.Error { return scim.NewError(503, "") }, status: 503},
		{name: "unsupported denial", deny: func(context.Context) *scim.Error { return scim.NewError(404, "") }, status: 503},
		{name: "typed denial", deny: func(context.Context) *scim.Error { return scim.NewError(400, "invalidValue") }, status: 503},
		{name: "panic", deny: func(context.Context) *scim.Error { panic("private gate diagnostic") }, status: 503},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newProtocolFixture(t)
			calls := 0
			out, err := admittedCreates(t, f.service).ExecuteAdmittedCreate(context.Background(), admittedCreateRequest("denied-create"), func(ctx context.Context) *scim.Error { calls++; return tc.deny(ctx) })
			denied := assertProtocolError(t, out, err, tc.status, "")
			if calls != 1 || f.store.prepares != 0 || f.mapper.calls != 0 || len(f.store.resources) != 0 || denied.SCIMType() != "" || denied.RetryAfterSeconds() != tc.retry {
				t.Fatal("gate denial was not redacted before command or mapping effects")
			}
		})
	}
}

func TestUsersAdmittedCreateGateConsumesExclusiveOriginalAuthority(t *testing.T) {
	for _, denial := range []*scim.Error{nil, scim.NewError(403, ""), scim.NewRateLimitedError(time.Second)} {
		f, clock := newFreshnessFixture(t)
		clock.now = fixtureNow.Add(19 * time.Second)
		calls := 0
		out, err := admittedCreates(t, f.service).ExecuteAdmittedCreate(context.Background(), admittedCreateRequest("expired-gate"), func(ctx context.Context) *scim.Error {
			calls++
			deadline, ok := ctx.Deadline()
			if !ok || time.Until(deadline) > time.Second+100*time.Millisecond || clock.policyCalls != 1 {
				t.Fatal("Create gate renewed original authority or preceded authorization")
			}
			clock.now = clock.connection.AuthorityValidUntil
			return denial
		})
		assertProtocolError(t, out, err, 503, "")
		if calls != 1 || clock.visits["prepare"] != 0 || clock.visits["map"] != 0 || clock.visits["commit"] != 0 {
			t.Fatal("expired Create gate reached mapping or command work")
		}
	}
}

func TestUsersAdmittedCreateRejectsAuthorityDriftBeforeGate(t *testing.T) {
	f, clock := newFreshnessFixture(t)
	clock.advanceAt = "authorize"
	clock.advanceTo = clock.connection.AuthorityValidUntil
	calls := 0
	out, err := admittedCreates(t, f.service).ExecuteAdmittedCreate(context.Background(), admittedCreateRequest("expired-before-gate"), func(context.Context) *scim.Error {
		calls++
		return nil
	})
	assertProtocolError(t, out, err, 503, "")
	if calls != 0 || clock.visits["prepare"] != 0 || clock.visits["map"] != 0 || clock.visits["commit"] != 0 {
		t.Fatal("expired authorization charged admission or reached command work")
	}
}

func TestUsersAdmittedCreateCancellationAndEarlierParentDeadline(t *testing.T) {
	f := newProtocolFixture(t)
	ctx, cancel := context.WithTimeout(context.Background(), 150*time.Millisecond)
	defer cancel()
	parentDeadline, _ := ctx.Deadline()
	calls := 0
	out, err := admittedCreates(t, f.service).ExecuteAdmittedCreate(ctx, admittedCreateRequest("canceled-gate"), func(gate context.Context) *scim.Error {
		calls++
		deadline, ok := gate.Deadline()
		if !ok || deadline.After(parentDeadline) {
			t.Fatal("Create gate extended earlier parent deadline")
		}
		cancel()
		return scim.NewError(403, "")
	})
	assertProtocolError(t, out, err, 503, "")
	if calls != 1 || f.store.prepares != 0 || f.mapper.calls != 0 {
		t.Fatal("gate cancellation reached command work")
	}
}

func TestUsersAdmittedCreateRejectsReentrantGateBeforeWrites(t *testing.T) {
	for _, selection := range []string{"ordinary", "admitted"} {
		t.Run(selection, func(t *testing.T) {
			f := newProtocolFixture(t)
			selected := admittedCreates(t, f.service)
			request := admittedCreateRequest("reentrant-create")
			calls, nestedCalls := 0, 0
			out, err := selected.ExecuteAdmittedCreate(context.Background(), request, func(ctx context.Context) *scim.Error {
				calls++
				var nested scim.Response
				var nestedErr error
				if selection == "ordinary" {
					nested, nestedErr = f.service.Execute(ctx, request)
				} else {
					nested, nestedErr = selected.ExecuteAdmittedCreate(ctx, request, func(context.Context) *scim.Error { nestedCalls++; return nil })
				}
				assertProtocolError(t, nested, nestedErr, 503, "")
				return nil
			})
			assertProtocolError(t, out, err, 503, "")
			if calls != 1 || nestedCalls != 0 || f.store.prepares != 0 || f.mapper.calls != 0 || len(f.store.resources) != 0 {
				t.Fatal("reentrant Create gate escaped fail-closed command fence")
			}
		})
	}
}

func TestUsersAdmittedCreateRetainsLateCommitDisclosureFence(t *testing.T) {
	f, clock := newFreshnessFixture(t)
	clock.advanceAfterCommit = true
	calls := 0
	out, err := admittedCreates(t, f.service).ExecuteAdmittedCreate(context.Background(), admittedCreateRequest("committed-before-expiry"), func(context.Context) *scim.Error { calls++; return nil })
	assertProtocolError(t, out, err, 503, "")
	if calls != 1 || clock.visits["commit"] != 1 || f.store.lastOutcome != scim.WriteOutcomeCommitted || len(f.store.resources) != 1 {
		t.Fatal("late disclosure changed the actual committed result or repeated admission")
	}
}

func TestUsersAdmittedCreatePreservesExistingOrdinaryPhysicalBehavior(t *testing.T) {
	f := newProtocolFixture(t)
	selected := admittedCreates(t, f.service)
	request := admittedCreateRequest("ordinary-after-gate")
	denied, err := selected.ExecuteAdmittedCreate(context.Background(), request, func(context.Context) *scim.Error { return scim.NewError(403, "") })
	assertProtocolError(t, denied, err, 403, "")
	ordinary, err := f.service.Execute(context.Background(), request)
	if err != nil || ordinary.Status != 201 || f.store.prepares != 1 || f.mapper.calls != 1 || len(f.store.resources) != 1 {
		t.Fatal("explicit Create admission changed ordinary physical creation", err)
	}
	id := object(t, ordinary.Body)["id"].(string)
	read, err := admittedUsers(t, f.service).ExecuteAdmittedRead(context.Background(), scim.Request{Operation: scim.UserGet, ResourceID: id, Credential: request.Credential}, func(context.Context) *scim.Error { return nil })
	if err != nil || read.Status != 200 || read.ETag != ordinary.ETag {
		t.Fatal("explicit Create selection changed admitted reads", err)
	}
	var nilService *scim.UsersService
	out, err := admittedCreates(t, nilService).ExecuteAdmittedCreate(context.Background(), request, func(context.Context) *scim.Error { return nil })
	assertProtocolError(t, out, err, 503, "")
}

func FuzzUsersAdmittedCreateJSON(f *testing.F) {
	f.Add([]byte(userBody("fuzz-valid", "")))
	f.Add([]byte(userBody("fuzz-duplicate", `,"USERNAME":"collision"`)))
	f.Add([]byte(userBody("fuzz-secret", `,"password":"unsupported"`)))
	f.Add([]byte(`{"schemas":[`))
	f.Fuzz(func(t *testing.T, body []byte) {
		fixture := newProtocolFixture(t)
		request := admittedCreateRequest("fuzz-create")
		request.Body = body
		calls := 0
		out, err := admittedCreates(t, fixture.service).ExecuteAdmittedCreate(context.Background(), request, func(context.Context) *scim.Error { calls++; return scim.NewError(403, "") })
		var denied *scim.Error
		if !errors.As(err, &denied) || calls > 1 || out.Status != 0 || len(out.Body) != 0 || out.ETag != "" || out.Location != "" || out.ContentType != "" || fixture.store.prepares != 0 || fixture.mapper.calls != 0 || len(fixture.store.resources) != 0 {
			t.Fatal("bounded admitted input escaped denial before mapping or command effects")
		}
	})
}
