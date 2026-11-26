package scim_test

import (
	"context"
	"errors"
	"testing"
	"time"

	authentication "github.com/faustbrian/go-authentication/v2"
	scim "github.com/faustbrian/go-scim"
)

type admittedUsersReader interface {
	ExecuteAdmittedRead(context.Context, scim.Request, func(context.Context) *scim.Error) (scim.Response, error)
}

func admittedUsers(t *testing.T, service *scim.UsersService) admittedUsersReader {
	t.Helper()
	selected, ok := any(service).(admittedUsersReader)
	if !ok {
		t.Fatal("UsersService has no explicit post-authorization admitted read selection")
	}
	return selected
}

type admittedReadStore struct {
	scim.Store
	gets, snapshots int
	beforeRead      func(context.Context)
}

func (s *admittedReadStore) Get(ctx context.Context, scope scim.Scope, id string) (scim.Resource, error) {
	s.gets++
	if s.beforeRead != nil {
		s.beforeRead(ctx)
	}
	return s.Store.Get(ctx, scope, id)
}

func (s *admittedReadStore) Snapshot(ctx context.Context, scope scim.Scope, budget scim.SnapshotBudget) (scim.Snapshot, error) {
	s.snapshots++
	if s.beforeRead != nil {
		s.beforeRead(ctx)
	}
	return s.Store.Snapshot(ctx, scope, budget)
}

func admittedReadRequest(op scim.Operation) scim.Request {
	return scim.Request{Operation: op, ResourceID: "selected-user", Credential: authentication.NewBearerCredential("fixture-connection")}
}

func TestUsersAdmittedReadAllowsGetAndListAfterGate(t *testing.T) {
	for _, op := range []scim.Operation{scim.UserGet, scim.UserList} {
		t.Run(string(op), func(t *testing.T) {
			var reads *admittedReadStore
			f := configuredProtocolFixture(t, func(c *scim.Config) {
				reads = &admittedReadStore{Store: c.Store}
				c.Store = reads
			})
			created := f.call(t, scim.UserCreate, "", "", userBody("admitted-reader", ""))
			id := object(t, created.Body)["id"].(string)
			request := admittedReadRequest(op)
			request.ResourceID = ""
			if op == scim.UserGet {
				request.ResourceID = id
			}
			calls := 0
			reads.beforeRead = func(context.Context) {
				if calls != 1 {
					t.Fatal("resource work did not follow exactly one allowed gate")
				}
			}
			out, err := admittedUsers(t, f.service).ExecuteAdmittedRead(context.Background(), request, func(ctx context.Context) *scim.Error {
				calls++
				if ctx.Err() != nil {
					t.Fatal("gate received canceled context")
				}
				if _, ok := ctx.Deadline(); !ok {
					t.Fatal("gate received unbounded context")
				}
				if reads.gets != 0 || reads.snapshots != 0 {
					t.Fatal("resource I/O preceded the gate")
				}
				return nil
			})
			if err != nil || out.Status != 200 || out.ContentType != "application/scim+json" || calls != 1 {
				t.Fatalf("admitted read: status %d, gate calls %d, error %v", out.Status, calls, err)
			}
			doc := object(t, out.Body)
			if op == scim.UserGet {
				if doc["id"] != id || out.ETag != created.ETag || reads.gets != 1 || reads.snapshots != 0 {
					t.Fatal("admitted Get did not return the selected resource and version")
				}
			} else {
				resources := doc["Resources"].([]any)
				if doc["totalResults"] != float64(1) || len(resources) != 1 || resources[0].(map[string]any)["id"] != id || reads.snapshots != 1 || reads.gets != 0 {
					t.Fatal("admitted List did not return the scoped resource snapshot")
				}
			}
		})
	}
}

func TestUsersAdmittedReadRejectsBeforeGateAndResourceIO(t *testing.T) {
	for _, tc := range []struct {
		name       string
		operation  scim.Operation
		credential string
		policyDeny bool
		cancel     bool
		nilGate    bool
		status     int
	}{
		{name: "unknown bearer", operation: scim.UserGet, credential: "unknown-fixture", status: 401},
		{name: "invalid bearer", operation: scim.UserList, credential: "invalid bearer", status: 401},
		{name: "expired bearer", operation: scim.UserGet, credential: "expired", status: 401},
		{name: "unowned connection", operation: scim.UserList, credential: "unowned", status: 401},
		{name: "denied policy", operation: scim.UserGet, policyDeny: true, status: 403},
		{name: "canceled request", operation: scim.UserList, cancel: true, status: 503},
		{name: "missing gate", operation: scim.UserGet, nilGate: true, status: 503},
		{name: "create unsupported", operation: scim.UserCreate, status: 501},
		{name: "search unsupported", operation: scim.UserSearch, status: 501},
		{name: "groups unsupported", operation: scim.GroupGet, status: 501},
		{name: "discovery unsupported", operation: scim.ServiceProviderConfig, status: 501},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var reads *admittedReadStore
			f := configuredProtocolFixture(t, func(c *scim.Config) {
				reads = &admittedReadStore{Store: c.Store}
				c.Store = reads
			})
			if tc.policyDeny {
				f.authorizer.err = errors.New("private policy diagnostic")
			}
			request := admittedReadRequest(tc.operation)
			if tc.credential != "" {
				request.Credential = authentication.NewBearerCredential(tc.credential)
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
			out, err := admittedUsers(t, f.service).ExecuteAdmittedRead(ctx, request, gate)
			assertProtocolError(t, out, err, tc.status, "")
			if calls != 0 || reads.gets != 0 || reads.snapshots != 0 || f.store.prepares != 0 || out.Status != 0 || out.ETag != "" || out.Location != "" || out.ContentType != "" {
				t.Fatal("rejected selection reached the gate, storage or response metadata")
			}
		})
	}
}

func TestUsersAdmittedReadNormalizesGateDenialWithoutResourceIO(t *testing.T) {
	for _, tc := range []struct {
		name  string
		deny  func(context.Context) *scim.Error
		code  int
		retry uint32
	}{
		{name: "policy", deny: func(context.Context) *scim.Error { return scim.NewError(403, "") }, code: 403},
		{name: "quota", deny: func(context.Context) *scim.Error { return scim.NewRateLimitedError(1250 * time.Millisecond) }, code: 429, retry: 2},
		{name: "quota without wait", deny: func(context.Context) *scim.Error { return scim.NewError(429, "") }, code: 503},
		{name: "unsupported denial", deny: func(context.Context) *scim.Error { return scim.NewError(404, "") }, code: 503},
		{name: "typed parser denial", deny: func(context.Context) *scim.Error { return scim.NewError(400, "invalidValue") }, code: 503},
		{name: "unavailable", deny: func(context.Context) *scim.Error { return scim.NewError(503, "") }, code: 503},
		{name: "panic", deny: func(context.Context) *scim.Error { panic("private gate diagnostic") }, code: 503},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var reads *admittedReadStore
			f := configuredProtocolFixture(t, func(c *scim.Config) {
				reads = &admittedReadStore{Store: c.Store}
				c.Store = reads
			})
			calls := 0
			out, err := admittedUsers(t, f.service).ExecuteAdmittedRead(context.Background(), admittedReadRequest(scim.UserGet), func(ctx context.Context) *scim.Error {
				calls++
				return tc.deny(ctx)
			})
			denied := assertProtocolError(t, out, err, tc.code, "")
			if calls != 1 || reads.gets != 0 || reads.snapshots != 0 || f.store.prepares != 0 || denied.RetryAfterSeconds() != tc.retry || denied.SCIMType() != "" {
				t.Fatal("gate denial was not normalized before storage")
			}
		})
	}
}

func TestUsersAdmittedReadGateConsumesOriginalAuthorityBudget(t *testing.T) {
	for _, denial := range []*scim.Error{nil, scim.NewError(403, ""), scim.NewRateLimitedError(time.Second)} {
		for _, op := range []scim.Operation{scim.UserGet, scim.UserList} {
			f, clock := newFreshnessFixture(t)
			clock.now = fixtureNow.Add(19 * time.Second)
			calls := 0
			out, err := admittedUsers(t, f.service).ExecuteAdmittedRead(context.Background(), admittedReadRequest(op), func(ctx context.Context) *scim.Error {
				calls++
				deadline, ok := ctx.Deadline()
				if !ok || time.Until(deadline) > time.Second+100*time.Millisecond {
					t.Fatal("gate renewed the original authority budget")
				}
				clock.now = clock.connection.AuthorityValidUntil
				return denial
			})
			assertProtocolError(t, out, err, 503, "")
			if calls != 1 || clock.visits["get"] != 0 || clock.visits["snapshot"] != 0 {
				t.Fatal("expired gate reached resource I/O")
			}
		}
	}
}

func TestUsersAdmittedReadCancellationAndFinalDisclosureFence(t *testing.T) {
	for _, stage := range []string{"gate", "get", "snapshot"} {
		t.Run(stage, func(t *testing.T) {
			f, clock := newFreshnessFixture(t)
			created := f.call(t, scim.UserCreate, "", "", userBody("final-admitted-fence", ""))
			clock.visits = make(map[string]int)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			op := scim.UserGet
			if stage == "snapshot" {
				op = scim.UserList
			}
			if stage != "gate" {
				clock.advanceAt = stage
				clock.advanceTo = clock.connection.AuthorityValidUntil
			}
			request := admittedReadRequest(op)
			request.ResourceID = object(t, created.Body)["id"].(string)
			if op == scim.UserList {
				request.ResourceID = ""
			}
			out, err := admittedUsers(t, f.service).ExecuteAdmittedRead(ctx, request, func(context.Context) *scim.Error {
				if stage == "gate" {
					cancel()
					return scim.NewError(403, "")
				}
				return nil
			})
			assertProtocolError(t, out, err, 503, "")
			if stage == "gate" && (clock.visits["get"] != 0 || clock.visits["snapshot"] != 0) {
				t.Fatal("gate cancellation reached resource I/O")
			}
		})
	}
}

func TestUsersAdmittedReadRejectsAuthorityDriftBeforeGate(t *testing.T) {
	f, clock := newFreshnessFixture(t)
	clock.advanceAt = "authorize"
	clock.advanceTo = clock.connection.AuthorityValidUntil
	calls := 0
	out, err := admittedUsers(t, f.service).ExecuteAdmittedRead(context.Background(), admittedReadRequest(scim.UserGet), func(context.Context) *scim.Error {
		calls++
		return nil
	})
	assertProtocolError(t, out, err, 503, "")
	if calls != 0 || clock.visits["get"] != 0 || clock.visits["snapshot"] != 0 {
		t.Fatal("stale authorization reached the gate or storage")
	}
}

func TestUsersAdmittedReadRetainsEarlierParentDeadline(t *testing.T) {
	f, clock := newFreshnessFixture(t)
	ctx, cancel := context.WithTimeout(context.Background(), 150*time.Millisecond)
	defer cancel()
	parentDeadline, _ := ctx.Deadline()
	calls := 0
	out, err := admittedUsers(t, f.service).ExecuteAdmittedRead(ctx, admittedReadRequest(scim.UserGet), func(ctx context.Context) *scim.Error {
		calls++
		deadline, ok := ctx.Deadline()
		if !ok || deadline.After(parentDeadline) {
			t.Fatal("gate extended the parent deadline")
		}
		return scim.NewError(403, "")
	})
	assertProtocolError(t, out, err, 403, "")
	if calls != 1 || clock.visits["get"] != 0 || clock.visits["snapshot"] != 0 {
		t.Fatal("denied bounded gate reached storage")
	}
}

func TestUsersAdmittedReadDoesNotAlterOrdinaryExecute(t *testing.T) {
	f := newProtocolFixture(t)
	selected := admittedUsers(t, f.service)
	request := admittedReadRequest(scim.UserList)
	request.ResourceID = ""
	denied, err := selected.ExecuteAdmittedRead(context.Background(), request, func(context.Context) *scim.Error { return scim.NewError(403, "") })
	assertProtocolError(t, denied, err, 403, "")
	ordinary, err := f.service.Execute(context.Background(), request)
	if err != nil || ordinary.Status != 200 || object(t, ordinary.Body)["totalResults"] != float64(0) {
		t.Fatal("per-call read admission changed ordinary execution")
	}
	created := f.call(t, scim.UserCreate, "", "", userBody("ordinary-after-admission", ""))
	if created.Status != 201 {
		t.Fatal("per-call read admission changed ordinary writes")
	}
}
