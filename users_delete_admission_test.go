package scim_test

import (
	"bytes"
	"context"
	"errors"
	"testing"
	"time"

	authentication "github.com/faustbrian/go-authentication/v2"
	scim "github.com/faustbrian/go-scim"
)

type admittedUsersDeleter interface {
	ExecuteAdmittedDelete(context.Context, scim.Request, func(context.Context) *scim.Error) (scim.Response, error)
}

func admittedDeletes(t *testing.T, service *scim.UsersService) admittedUsersDeleter {
	t.Helper()
	selected, ok := any(service).(admittedUsersDeleter)
	if !ok {
		t.Fatal("UsersService has no explicit conditional admitted Delete selection")
	}
	return selected
}

func admittedDeleteRequest(created scim.Response, t *testing.T) scim.Request {
	t.Helper()
	return scim.Request{Operation: scim.UserDelete, Credential: authentication.NewBearerCredential("fixture-connection"), ResourceID: object(t, created.Body)["id"].(string), IfMatch: created.ETag}
}

func TestUsersAdmittedDeleteRetainsConditionalHeaderlessReplay(t *testing.T) {
	var writes *admittedCreateStore
	f := configuredProtocolFixture(t, func(c *scim.Config) { writes = &admittedCreateStore{Store: c.Store}; c.Store = writes })
	created := f.call(t, scim.UserCreate, "", "", userBody("admitted-delete-original", ""))
	request := admittedDeleteRequest(created, t)
	writes.intents = nil
	writes.commits = 0
	writes.aborts = 0
	mapsBefore := f.mapper.calls
	calls := 0
	gate := func(ctx context.Context) *scim.Error {
		calls++
		if boundedFixtureContext(ctx) != nil || len(writes.intents) != calls-1 {
			t.Fatal("Delete command admission preceded the once-per-attempt bounded gate")
		}
		return nil
	}
	deleted, err := admittedDeletes(t, f.service).ExecuteAdmittedDelete(context.Background(), request, gate)
	if err != nil || deleted.Status != 204 || len(deleted.Body) != 0 || deleted.ETag != "" || deleted.Location != "" || deleted.ContentType != "" || calls != 1 || writes.commits != 1 || writes.aborts != 0 || len(f.store.resources) != 0 || f.mapper.calls != mapsBefore {
		t.Fatal("admitted Delete did not retain conditional Store deletion", err)
	}
	original := writes.intents[0]
	if original.Operation != scim.UserDelete || original.ResourceID != request.ResourceID || original.IfMatch != request.IfMatch || original.IdempotencyKey != "" || original.CommandID == "" || original.Scope != original.Connection.Scope {
		t.Fatal("Delete gate changed original target, precondition, scope or headerless command")
	}
	replay, err := admittedDeletes(t, f.service).ExecuteAdmittedDelete(context.Background(), request, gate)
	if err != nil || replay.Status != 204 || len(replay.Body) != 0 || calls != 2 || writes.commits != 1 || writes.aborts != 0 || len(writes.intents) != 2 || !bytes.Equal(original.CanonicalRequest, writes.intents[1].CanonicalRequest) {
		t.Fatal("headerless Delete replay rechecked the tombstone, rewrote canonical intent or repeated effects", err)
	}
}

func TestUsersAdmittedDeletePreflightRejectsBeforeGateOrReceipt(t *testing.T) {
	for _, tc := range []struct {
		name                string
		change              func(*scim.Request)
		policyDeny, nilGate bool
		status              int
	}{
		{name: "missing target", change: func(r *scim.Request) { r.ResourceID = "" }, status: 404},
		{name: "unsafe target", change: func(r *scim.Request) { r.ResourceID = "other/user" }, status: 404},
		{name: "missing If-Match", change: func(r *scim.Request) { r.IfMatch = "" }, status: 428},
		{name: "weak If-Match", change: func(r *scim.Request) { r.IfMatch = `W/"weak"` }, status: 400},
		{name: "wildcard If-Match", change: func(r *scim.Request) { r.IfMatch = "*" }, status: 400},
		{name: "multiple If-Match", change: func(r *scim.Request) { r.IfMatch = `"one","two"` }, status: 400},
		{name: "unexpected body", change: func(r *scim.Request) { r.Body = []byte(`{}`); r.ContentType = "application/scim+json" }, status: 400},
		{name: "invalid projection", change: func(r *scim.Request) { r.Query.Attributes = "password" }, status: 400},
		{name: "invalid credential", change: func(r *scim.Request) { r.Credential = authentication.NewBearerCredential("unknown-fixture") }, status: 401},
		{name: "operation policy denial", policyDeny: true, status: 403},
		{name: "missing gate", nilGate: true, status: 503},
		{name: "Create not selected", change: func(r *scim.Request) { r.Operation = scim.UserCreate }, status: 501},
		{name: "Get not selected", change: func(r *scim.Request) { r.Operation = scim.UserGet }, status: 501},
		{name: "Group Delete not selected", change: func(r *scim.Request) { r.Operation = scim.GroupDelete }, status: 501},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newProtocolFixture(t)
			created := f.call(t, scim.UserCreate, "", "", userBody("delete-preflight", ""))
			request := admittedDeleteRequest(created, t)
			if tc.change != nil {
				tc.change(&request)
			}
			if tc.policyDeny {
				f.authorizer.err = errors.New("private policy diagnostic")
			}
			preparesBefore, mapsBefore := f.store.prepares, f.mapper.calls
			calls := 0
			var gate func(context.Context) *scim.Error
			if !tc.nilGate {
				gate = func(context.Context) *scim.Error { calls++; return nil }
			}
			out, err := admittedDeletes(t, f.service).ExecuteAdmittedDelete(context.Background(), request, gate)
			assertProtocolError(t, out, err, tc.status, "")
			if calls != 0 || f.store.prepares != preparesBefore || f.mapper.calls != mapsBefore || len(f.store.resources) != 1 {
				t.Fatal("Delete preflight charged admission, created a receipt or removed the User")
			}
		})
	}
}

func TestUsersAdmittedDeleteGateDenialPreservesUserAndCommandAbsence(t *testing.T) {
	for _, tc := range []struct {
		name   string
		denial func(context.Context) *scim.Error
		status int
		retry  uint32
	}{
		{name: "quota", denial: func(context.Context) *scim.Error { return scim.NewRateLimitedError(1250 * time.Millisecond) }, status: 429, retry: 2},
		{name: "unknown quota wait", denial: func(context.Context) *scim.Error { return scim.NewError(429, "") }, status: 503},
		{name: "unavailable", denial: func(context.Context) *scim.Error { return scim.NewError(503, "") }, status: 503},
		{name: "policy", denial: func(context.Context) *scim.Error { return scim.NewError(403, "") }, status: 403},
		{name: "panic", denial: func(context.Context) *scim.Error { panic("private gate diagnostic") }, status: 503},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newProtocolFixture(t)
			created := f.call(t, scim.UserCreate, "", "", userBody("delete-denied", ""))
			before := f.store.prepares
			calls := 0
			out, err := admittedDeletes(t, f.service).ExecuteAdmittedDelete(context.Background(), admittedDeleteRequest(created, t), func(ctx context.Context) *scim.Error { calls++; return tc.denial(ctx) })
			denied := assertProtocolError(t, out, err, tc.status, "")
			if calls != 1 || denied.RetryAfterSeconds() != tc.retry || f.store.prepares != before || len(f.store.resources) != 1 {
				t.Fatal("Delete denial charged twice, changed retry metadata or crossed receipt/effect boundary")
			}
		})
	}
}

func TestUsersAdmittedDeleteLeavesStaleCASWithStoreAfterGate(t *testing.T) {
	var writes *admittedCreateStore
	f := configuredProtocolFixture(t, func(c *scim.Config) { writes = &admittedCreateStore{Store: c.Store}; c.Store = writes })
	created := f.call(t, scim.UserCreate, "", "", userBody("delete-stale", ""))
	request := admittedDeleteRequest(created, t)
	request.IfMatch = `"stale-version"`
	writes.commits, writes.aborts = 0, 0
	calls := 0
	for range 2 {
		out, err := admittedDeletes(t, f.service).ExecuteAdmittedDelete(context.Background(), request, func(context.Context) *scim.Error { calls++; return nil })
		assertProtocolError(t, out, err, 412, "")
	}
	if calls != 2 || writes.commits != 0 || writes.aborts != 1 || len(f.store.resources) != 1 {
		t.Fatal("Delete gate moved stateful CAS before admission or changed the original failed receipt replay")
	}
}

func TestUsersAdmittedDeletePreservesUnknownOutcomeOnRetry(t *testing.T) {
	var writes *admittedCreateStore
	f := configuredProtocolFixture(t, func(c *scim.Config) { writes = &admittedCreateStore{Store: c.Store}; c.Store = writes })
	created := f.call(t, scim.UserCreate, "", "", userBody("delete-unknown", ""))
	request := admittedDeleteRequest(created, t)
	writes.commits, writes.aborts = 0, 0
	f.store.unknown = true
	calls := 0
	for range 2 {
		out, err := admittedDeletes(t, f.service).ExecuteAdmittedDelete(context.Background(), request, func(context.Context) *scim.Error { calls++; return nil })
		assertProtocolError(t, out, err, 503, "")
	}
	if calls != 2 || writes.commits != 1 || writes.aborts != 0 || f.store.lastOutcome != scim.WriteOutcomeUnknown || len(f.store.resources) != 1 {
		t.Fatal("admitted Delete retried, aborted or promoted the existing unknown Store outcome")
	}
}

func TestUsersAdmittedDeleteConsumesOriginalAuthorityDeadline(t *testing.T) {
	f, clock := newFreshnessFixture(t)
	created := f.call(t, scim.UserCreate, "", "", userBody("delete-expiry", ""))
	clock.visits = make(map[string]int)
	clock.policyCalls = 0
	clock.now = fixtureNow.Add(19 * time.Second)
	calls := 0
	out, err := admittedDeletes(t, f.service).ExecuteAdmittedDelete(context.Background(), admittedDeleteRequest(created, t), func(ctx context.Context) *scim.Error {
		calls++
		deadline, bounded := ctx.Deadline()
		if !bounded || time.Until(deadline) > time.Second+100*time.Millisecond || clock.policyCalls != 1 {
			t.Fatal("Delete admission preceded authorization or renewed original authority")
		}
		clock.now = clock.connection.AuthorityValidUntil
		return scim.NewRateLimitedError(time.Second)
	})
	assertProtocolError(t, out, err, 503, "")
	if calls != 1 || clock.visits["prepare"] != 0 || clock.visits["commit"] != 0 || len(f.store.resources) != 1 {
		t.Fatal("expired Delete admission reached receipt or protected effects")
	}
}

func TestUsersAdmittedDeleteWithholdsLateCommittedResult(t *testing.T) {
	f, clock := newFreshnessFixture(t)
	created := f.call(t, scim.UserCreate, "", "", userBody("delete-late-commit", ""))
	clock.visits = make(map[string]int)
	clock.advanceAfterCommit = true
	calls := 0
	out, err := admittedDeletes(t, f.service).ExecuteAdmittedDelete(context.Background(), admittedDeleteRequest(created, t), func(context.Context) *scim.Error { calls++; return nil })
	assertProtocolError(t, out, err, 503, "")
	if calls != 1 || clock.visits["commit"] != 1 || f.store.lastOutcome != scim.WriteOutcomeCommitted || len(f.store.resources) != 0 {
		t.Fatal("late Delete disclosure changed the committed outcome or repeated protected effects")
	}
}

func TestUsersAdmittedDeleteCancellationAndReentryFailBeforeReceipt(t *testing.T) {
	for _, stage := range []string{"cancel", "reentry"} {
		t.Run(stage, func(t *testing.T) {
			f := newProtocolFixture(t)
			created := f.call(t, scim.UserCreate, "", "", userBody("delete-gate-fence", ""))
			request := admittedDeleteRequest(created, t)
			before := f.store.prepares
			ctx, cancel := context.WithTimeout(context.Background(), 150*time.Millisecond)
			defer cancel()
			parentDeadline, _ := ctx.Deadline()
			calls := 0
			out, err := admittedDeletes(t, f.service).ExecuteAdmittedDelete(ctx, request, func(gateCtx context.Context) *scim.Error {
				calls++
				deadline, bounded := gateCtx.Deadline()
				if !bounded || deadline.After(parentDeadline) {
					t.Fatal("Delete gate extended the parent deadline")
				}
				if stage == "cancel" {
					cancel()
				} else {
					nested, nestedErr := f.service.Execute(gateCtx, request)
					assertProtocolError(t, nested, nestedErr, 503, "")
				}
				return nil
			})
			assertProtocolError(t, out, err, 503, "")
			if calls != 1 || f.store.prepares != before || len(f.store.resources) != 1 {
				t.Fatal("canceled or reentrant Delete admission reached command receipt or mutation")
			}
		})
	}
}

func TestUsersAdmittedDeletePreservesOrdinaryDeleteAndExistingKeyBehavior(t *testing.T) {
	f := newProtocolFixture(t)
	created := f.call(t, scim.UserCreate, "", "", userBody("delete-ordinary", ""))
	request := admittedDeleteRequest(created, t)
	request.IdempotencyKey = "existing-native-delete-lookup"
	denied, err := admittedDeletes(t, f.service).ExecuteAdmittedDelete(context.Background(), request, func(context.Context) *scim.Error { return scim.NewError(403, "") })
	assertProtocolError(t, denied, err, 403, "")
	ordinary, err := f.service.Execute(context.Background(), request)
	if err != nil || ordinary.Status != 204 || len(f.store.resources) != 0 {
		t.Fatal("explicit admission changed ordinary Delete or its existing native lookup key", err)
	}
	replay, err := admittedDeletes(t, f.service).ExecuteAdmittedDelete(context.Background(), request, func(context.Context) *scim.Error { return nil })
	if err != nil || replay.Status != 204 {
		t.Fatal("admitted native lookup changed original ordinary Delete replay", err)
	}
}

func FuzzUsersAdmittedDeletePreflight(f *testing.F) {
	f.Add("bounded-target", `"strong-version"`)
	f.Add("other/user", `W/"weak"`)
	f.Add("", "")
	f.Fuzz(func(t *testing.T, target, version string) {
		fixture := newProtocolFixture(t)
		calls := 0
		out, err := admittedDeletes(t, fixture.service).ExecuteAdmittedDelete(context.Background(), scim.Request{Operation: scim.UserDelete, Credential: authentication.NewBearerCredential("fixture-connection"), ResourceID: target, IfMatch: scim.Version(version)}, func(context.Context) *scim.Error { calls++; return scim.NewError(403, "") })
		var denied *scim.Error
		if !errors.As(err, &denied) || calls > 1 || out.Status != 0 || len(out.Body) != 0 || out.ETag != "" || out.Location != "" || fixture.store.prepares != 0 || fixture.mapper.calls != 0 || len(fixture.store.resources) != 0 {
			t.Fatal("bounded admitted Delete preflight escaped denial before receipt or protected effects")
		}
	})
}
