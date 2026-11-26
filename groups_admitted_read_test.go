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

type admittedGroupsReader interface {
	ExecuteAdmittedRead(context.Context, scim.Request, func(context.Context) *scim.Error) (scim.Response, error)
}

func admittedGroups(t *testing.T, service *scim.GroupsService) admittedGroupsReader {
	t.Helper()
	selected, ok := any(service).(admittedGroupsReader)
	if !ok {
		t.Fatal("GroupsService has no explicit post-authorization admitted read selection")
	}
	return selected
}

type admittedGroupReadStore struct {
	scim.GroupStore
	gets, snapshots int
	beforeRead      func(context.Context, scim.Scope)
	afterRead       func()
}

func (s *admittedGroupReadStore) GetGroup(ctx context.Context, scope scim.Scope, id string) (scim.Resource, error) {
	s.gets++
	if s.beforeRead != nil {
		s.beforeRead(ctx, scope)
	}
	resource, err := s.GroupStore.GetGroup(ctx, scope, id)
	if s.afterRead != nil {
		s.afterRead()
	}
	return resource, err
}

func (s *admittedGroupReadStore) SnapshotGroups(ctx context.Context, scope scim.Scope, budget scim.SnapshotBudget) (scim.Snapshot, error) {
	s.snapshots++
	if s.beforeRead != nil {
		s.beforeRead(ctx, scope)
	}
	snapshot, err := s.GroupStore.SnapshotGroups(ctx, scope, budget)
	if s.afterRead != nil {
		s.afterRead()
	}
	return snapshot, err
}

func admittedGroupReadRequest(op scim.Operation, id string) scim.Request {
	return scim.Request{Operation: op, ResourceID: id, Credential: authentication.NewBearerCredential("fixture-connection")}
}

func newAdmittedGroupReadFixture(t *testing.T) (*groupFixture, *admittedGroupReadStore, *freshnessFixture) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	connection, err := (protocolAuthenticator{}).Authenticate(ctx, authentication.NewBearerCredential("fixture-connection"))
	if err != nil {
		t.Fatal(err)
	}
	clock := &freshnessFixture{test: t, now: fixtureNow, connection: connection, visits: make(map[string]int)}
	var reads *admittedGroupReadStore
	f := newGroupFixture(t, func(c *scim.GroupsConfig) {
		c.Now = func() time.Time { return clock.now }
		c.RequestTimeout = time.Minute
		c.Authenticator = freshnessAuthenticator{state: clock}
		c.Authorizer = freshnessAuthorizer{Authorizer: c.Authorizer, state: clock}
		reads = &admittedGroupReadStore{GroupStore: c.Store}
		c.Store = reads
	})
	return f, reads, clock
}

func TestGroupsAdmittedReadAllowsGetAndFilteredPageAfterGate(t *testing.T) {
	for _, op := range []scim.Operation{scim.GroupGet, scim.GroupList} {
		t.Run(string(op), func(t *testing.T) {
			f, reads, clock := newAdmittedGroupReadFixture(t)
			f.addUser("member-a", "fixture-connection")
			selected := f.call(t, scim.GroupCreate, "", "", groupBody("Zulu", `,"members":[{"value":"member-a"}]`))
			f.call(t, scim.GroupCreate, "", "", groupBody("alpha", `,"members":[{"value":"member-a"}]`))
			f.call(t, scim.GroupCreate, "", "", groupBody("Other", ""))
			id := object(t, selected.Body)["id"].(string)
			request := admittedGroupReadRequest(op, id)
			request.Query.Attributes = "displayName"
			if op == scim.GroupList {
				count := 1
				request.ResourceID = ""
				request.Query = scim.Query{Filter: `members[value eq "member-a" and type eq "user"]`, SortBy: "displayName", StartIndex: 2, Count: &count, Attributes: "displayName"}
			}
			clock.policyCalls = 0
			calls := 0
			reads.beforeRead = func(ctx context.Context, scope scim.Scope) {
				if calls != 1 || boundedFixtureContext(ctx) != nil || scope != clock.connection.Scope {
					t.Fatal("resource read preceded its allowed gate or changed authenticated scope")
				}
			}
			out, err := admittedGroups(t, f.service).ExecuteAdmittedRead(context.Background(), request, func(ctx context.Context) *scim.Error {
				calls++
				if boundedFixtureContext(ctx) != nil || clock.policyCalls != 1 || reads.gets != 0 || reads.snapshots != 0 {
					t.Fatal("gate preceded current authorization or followed resource I/O")
				}
				return nil
			})
			if err != nil || out.Status != 200 || out.ContentType != "application/scim+json" || calls != 1 {
				t.Fatalf("admitted Group read: status %d, gate calls %d, error %v", out.Status, calls, err)
			}
			doc := object(t, out.Body)
			if op == scim.GroupList {
				resources := doc["Resources"].([]any)
				if doc["totalResults"] != float64(2) || doc["startIndex"] != float64(2) || doc["itemsPerPage"] != float64(1) || len(resources) != 1 || reads.snapshots != 1 || reads.gets != 0 {
					t.Fatal("admitted List lost exact filtered snapshot, pagination or sort")
				}
				doc = resources[0].(map[string]any)
			} else if out.ETag != selected.ETag || out.Location != selected.Location || reads.gets != 1 || reads.snapshots != 0 {
				t.Fatal("admitted Get lost original version or location")
			}
			if doc["id"] != id || doc["displayName"] != "Zulu" || doc["members"] != nil || doc["meta"].(map[string]any)["version"] != string(selected.ETag) {
				t.Fatal("admitted read lost selected Group identity, projection or version")
			}
		})
	}
}

func TestGroupsAdmittedReadRejectsBeforeGateAndStore(t *testing.T) {
	for _, tc := range []struct {
		name       string
		operation  scim.Operation
		credential string
		policyDeny bool
		cancel     bool
		nilGate    bool
		status     int
	}{
		{name: "unknown bearer", operation: scim.GroupGet, credential: "unknown-fixture", status: 401},
		{name: "invalid bearer", operation: scim.GroupList, credential: "invalid bearer", status: 401},
		{name: "expired bearer", operation: scim.GroupGet, credential: "expired", status: 401},
		{name: "unowned bearer", operation: scim.GroupList, credential: "unowned", status: 401},
		{name: "operation denied", operation: scim.GroupGet, policyDeny: true, status: 403},
		{name: "canceled parent", operation: scim.GroupList, cancel: true, status: 503},
		{name: "missing gate", operation: scim.GroupGet, nilGate: true, status: 503},
		{name: "Group search", operation: scim.GroupSearch, status: 501},
		{name: "Group create", operation: scim.GroupCreate, status: 501},
		{name: "Group replace", operation: scim.GroupReplace, status: 501},
		{name: "Group patch", operation: scim.GroupPatch, status: 501},
		{name: "Group delete", operation: scim.GroupDelete, status: 501},
		{name: "User get", operation: scim.UserGet, status: 501},
		{name: "User list", operation: scim.UserList, status: 501},
		{name: "root search", operation: scim.Search, status: 501},
		{name: "discovery", operation: scim.ServiceProviderConfig, status: 501},
		{name: "Bulk", operation: scim.Bulk, status: 501},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var reads *admittedGroupReadStore
			policy := &protocolAuthorizer{}
			f := newGroupFixture(t, func(c *scim.GroupsConfig) {
				reads = &admittedGroupReadStore{GroupStore: c.Store}
				c.Store, c.Authorizer = reads, policy
			})
			if tc.policyDeny {
				policy.err = errors.New("private policy diagnostic")
			}
			request := admittedGroupReadRequest(tc.operation, "selected-group")
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
			out, err := admittedGroups(t, f.service).ExecuteAdmittedRead(ctx, request, gate)
			assertProtocolError(t, out, err, tc.status, "")
			if calls != 0 || reads.gets != 0 || reads.snapshots != 0 || f.store.prepares != 0 || out.Status != 0 || out.ETag != "" || out.Location != "" || out.ContentType != "" {
				t.Fatal("rejected read reached admission, Store or response metadata")
			}
		})
	}
	for _, service := range []*scim.GroupsService{nil, new(scim.GroupsService)} {
		out, err := admittedGroups(t, service).ExecuteAdmittedRead(context.Background(), admittedGroupReadRequest(scim.GroupGet, "selected-group"), func(context.Context) *scim.Error {
			t.Fatal("uninitialized service invoked gate")
			return nil
		})
		assertProtocolError(t, out, err, 503, "")
	}
}

func TestGroupsAdmittedReadNormalizesDenialsBeforeStore(t *testing.T) {
	for _, op := range []scim.Operation{scim.GroupGet, scim.GroupList} {
		for _, tc := range []struct {
			name   string
			deny   func(context.Context) *scim.Error
			status int
			retry  uint32
		}{
			{name: "policy", deny: func(context.Context) *scim.Error { return scim.NewError(403, "") }, status: 403},
			{name: "quota", deny: func(context.Context) *scim.Error { return scim.NewRateLimitedError(1250 * time.Millisecond) }, status: 429, retry: 2},
			{name: "quota without wait", deny: func(context.Context) *scim.Error { return scim.NewError(429, "") }, status: 503},
			{name: "unavailable", deny: func(context.Context) *scim.Error { return scim.NewError(503, "") }, status: 503},
			{name: "unsupported status", deny: func(context.Context) *scim.Error { return scim.NewError(404, "") }, status: 503},
			{name: "typed error", deny: func(context.Context) *scim.Error { return scim.NewError(400, "invalidValue") }, status: 503},
			{name: "panic", deny: func(context.Context) *scim.Error { panic("private gate diagnostic") }, status: 503},
		} {
			t.Run(string(op)+"/"+tc.name, func(t *testing.T) {
				f, reads, _ := newAdmittedGroupReadFixture(t)
				calls := 0
				out, err := admittedGroups(t, f.service).ExecuteAdmittedRead(context.Background(), admittedGroupReadRequest(op, "selected-group"), func(ctx context.Context) *scim.Error {
					calls++
					return tc.deny(ctx)
				})
				denied := assertProtocolError(t, out, err, tc.status, "")
				if calls != 1 || reads.gets != 0 || reads.snapshots != 0 || f.store.prepares != 0 || denied.RetryAfterSeconds() != tc.retry || denied.SCIMType() != "" || out.Status != 0 || out.ETag != "" || out.Location != "" || out.ContentType != "" {
					t.Fatal("denial lost redaction or exposed a Group/Store operation")
				}
			})
		}
	}
}

func TestGroupsAdmittedReadRetainsOriginalBudgetAndDisclosureFence(t *testing.T) {
	for _, op := range []scim.Operation{scim.GroupGet, scim.GroupList} {
		for _, stage := range []string{"before gate", "gate allow", "gate deny", "gate quota", "cancel gate", "late resource", "cancel resource"} {
			t.Run(string(op)+"/"+stage, func(t *testing.T) {
				f, reads, clock := newAdmittedGroupReadFixture(t)
				created := f.call(t, scim.GroupCreate, "", "", groupBody("original-budget", ""))
				clock.policyCalls = 0
				clock.now = fixtureNow.Add(19 * time.Second)
				ctx, cancel := context.WithCancel(context.Background())
				defer cancel()
				if stage == "before gate" {
					clock.advanceAt, clock.advanceTo = "authorize", clock.connection.AuthorityValidUntil
				}
				if stage == "late resource" || stage == "cancel resource" {
					reads.afterRead = func() {
						if stage == "late resource" {
							clock.now = clock.connection.AuthorityValidUntil
						} else {
							cancel()
						}
					}
				}
				calls := 0
				request := admittedGroupReadRequest(op, object(t, created.Body)["id"].(string))
				if op == scim.GroupList {
					request.ResourceID = ""
				}
				out, err := admittedGroups(t, f.service).ExecuteAdmittedRead(ctx, request, func(ctx context.Context) *scim.Error {
					calls++
					deadline, ok := ctx.Deadline()
					if !ok || time.Until(deadline) > time.Second+100*time.Millisecond {
						t.Fatal("gate renewed the original authority budget")
					}
					switch stage {
					case "gate allow", "gate deny", "gate quota":
						clock.now = clock.connection.AuthorityValidUntil
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
				wantCalls, wantReads := 1, 0
				if stage == "before gate" {
					wantCalls = 0
				}
				if stage == "late resource" || stage == "cancel resource" {
					wantReads = 1
				}
				if calls != wantCalls || reads.gets+reads.snapshots != wantReads || out.Status != 0 || out.Location != "" || out.ETag != "" || out.ContentType != "" {
					t.Fatal("cancellation/expiry disclosed a late result or crossed the gate fence")
				}
			})
		}
	}
}

func TestGroupsAdmittedReadRetainsEarlierParentAndRequestDeadlines(t *testing.T) {
	for _, earlier := range []string{"parent", "request"} {
		t.Run(earlier, func(t *testing.T) {
			var reads *admittedGroupReadStore
			f := newGroupFixture(t, func(c *scim.GroupsConfig) {
				reads = &admittedGroupReadStore{GroupStore: c.Store}
				c.Store = reads
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
			out, err := admittedGroups(t, f.service).ExecuteAdmittedRead(ctx, admittedGroupReadRequest(scim.GroupList, ""), func(ctx context.Context) *scim.Error {
				deadline, ok := ctx.Deadline()
				if !ok || deadline.After(bound.Add(25*time.Millisecond)) {
					t.Fatal("gate extended the earlier parent or request budget")
				}
				return scim.NewError(403, "")
			})
			assertProtocolError(t, out, err, 403, "")
			if reads.gets != 0 || reads.snapshots != 0 {
				t.Fatal("deadline inspection denial reached resource I/O")
			}
		})
	}
}

func TestGroupsAdmittedReadRejectsDescendantReentryWithoutStore(t *testing.T) {
	for _, nested := range []string{"ordinary Group", "admitted Group", "unselected Group", "missing Group gate", "nil Group service", "uninitialized Group service", "sibling User"} {
		t.Run(nested, func(t *testing.T) {
			f, reads, _ := newAdmittedGroupReadFixture(t)
			var userReads *admittedReadStore
			users := configuredProtocolFixture(t, func(c *scim.Config) { userReads = &admittedReadStore{Store: c.Store}; c.Store = userReads })
			calls := 0
			var inner scim.Response
			var innerErr error
			out, err := admittedGroups(t, f.service).ExecuteAdmittedRead(context.Background(), admittedGroupReadRequest(scim.GroupList, ""), func(ctx context.Context) *scim.Error {
				calls++
				ctx, cancel := context.WithCancel(ctx)
				defer cancel()
				switch nested {
				case "ordinary Group":
					inner, innerErr = f.service.Execute(ctx, admittedGroupReadRequest(scim.GroupList, ""))
				case "admitted Group":
					inner, innerErr = admittedGroups(t, f.service).ExecuteAdmittedRead(ctx, admittedGroupReadRequest(scim.GroupList, ""), func(context.Context) *scim.Error {
						t.Fatal("reentry invoked a nested gate")
						return nil
					})
				case "unselected Group":
					inner, innerErr = admittedGroups(t, f.service).ExecuteAdmittedRead(ctx, admittedGroupReadRequest(scim.GroupSearch, ""), func(context.Context) *scim.Error {
						t.Fatal("unselected reentry invoked a nested gate")
						return nil
					})
				case "missing Group gate":
					inner, innerErr = admittedGroups(t, f.service).ExecuteAdmittedRead(ctx, admittedGroupReadRequest(scim.GroupList, ""), nil)
				case "nil Group service":
					inner, innerErr = admittedGroups(t, nil).ExecuteAdmittedRead(ctx, admittedGroupReadRequest(scim.GroupList, ""), nil)
				case "uninitialized Group service":
					inner, innerErr = admittedGroups(t, new(scim.GroupsService)).ExecuteAdmittedRead(ctx, admittedGroupReadRequest(scim.GroupList, ""), nil)
				case "sibling User":
					inner, innerErr = users.service.Execute(ctx, admittedReadRequest(scim.UserList))
				}
				return nil
			})
			assertProtocolError(t, out, err, 503, "")
			assertProtocolError(t, inner, innerErr, 503, "")
			if calls != 1 || reads.gets != 0 || reads.snapshots != 0 || userReads.gets != 0 || userReads.snapshots != 0 || f.store.prepares != 0 {
				t.Fatal("ignored nested denial allowed resource I/O")
			}
		})
	}
}

func TestGroupsAdmittedReadPreservesOrdinaryAndSiblingSelections(t *testing.T) {
	f := newGroupFixture(t, nil)
	created := f.call(t, scim.GroupCreate, "", "", groupBody("ordinary-group", ""))
	id := object(t, created.Body)["id"].(string)
	out, err := admittedGroups(t, f.service).ExecuteAdmittedRead(context.Background(), admittedGroupReadRequest(scim.GroupGet, id), func(context.Context) *scim.Error { return scim.NewError(403, "") })
	assertProtocolError(t, out, err, 403, "")
	if read := f.call(t, scim.GroupGet, id, "", ""); !bytes.Equal(read.Body, created.Body) || read.ETag != created.ETag {
		t.Fatal("per-call admission changed ordinary Group reads")
	}
	f.call(t, scim.GroupCreate, "", "", groupBody("ordinary-write-after-denial", ""))
	f.call(t, scim.ServiceProviderConfig, "", "", "")
	f.call(t, scim.GroupSearch, "", "", `{"schemas":["urn:ietf:params:scim:api:messages:2.0:SearchRequest"]}`)
	users := newProtocolFixture(t)
	user := users.call(t, scim.UserCreate, "", "", userBody("sibling-user", ""))
	request := admittedReadRequest(scim.UserGet)
	request.ResourceID = object(t, user.Body)["id"].(string)
	read, err := admittedUsers(t, users.service).ExecuteAdmittedRead(context.Background(), request, func(context.Context) *scim.Error { return nil })
	if err != nil || !bytes.Equal(read.Body, user.Body) || read.ETag != user.ETag {
		t.Fatal("Group selection changed admitted User reads", err)
	}
	out, err = admittedUsers(t, users.service).ExecuteAdmittedRead(context.Background(), admittedGroupReadRequest(scim.GroupGet, id), func(context.Context) *scim.Error {
		t.Fatal("User selection admitted a Group operation")
		return nil
	})
	assertProtocolError(t, out, err, 501, "")
}
