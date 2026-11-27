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

type admittedGroupsDeleter interface {
	ExecuteAdmittedDelete(context.Context, scim.Request, func(context.Context) *scim.Error) (scim.Response, error)
}

func admittedGroupDeletes(t *testing.T, service *scim.GroupsService) admittedGroupsDeleter {
	t.Helper()
	selected, ok := any(service).(admittedGroupsDeleter)
	if !ok {
		t.Fatal("GroupsService has no explicit conditional admitted Delete selection")
	}
	return selected
}

func admittedGroupDeleteRequest(t *testing.T, created scim.Response) scim.Request {
	t.Helper()
	return scim.Request{Operation: scim.GroupDelete, Credential: authentication.NewBearerCredential("fixture-connection"), ResourceID: object(t, created.Body)["id"].(string), IfMatch: created.ETag}
}

func TestGroupsAdmittedDeleteRetainsHeaderlessAndOptionalKeyReplayWithoutRelatedEffects(t *testing.T) {
	for _, initialKey := range []string{"", "optional-delete-key"} {
		t.Run("initial key "+initialKey, func(t *testing.T) {
			command, err := identity.NewCommandID()
			if err != nil {
				t.Fatal(err)
			}
			var writes *admittedGroupCreateStore
			f := newGroupFixture(t, func(c *scim.GroupsConfig) { writes = &admittedGroupCreateStore{GroupStore: c.Store}; c.Store = writes })
			f.addUser("member-a", "fixture-connection")
			nested := f.call(t, scim.GroupCreate, "", "", groupBody("nested", ""))
			foreign := f.execute(t, scim.Request{Operation: scim.GroupCreate, Credential: authentication.NewBearerCredential("fixture-other-connection"), Body: []byte(groupBody("foreign", ""))})
			nestedID := object(t, nested.Body)["id"].(string)
			created := f.call(t, scim.GroupCreate, "", "", groupBody("deleted parent", `,"members":[{"value":"member-a"},{"value":"`+nestedID+`","type":"Group"}]`))
			request := admittedGroupDeleteRequest(t, created)
			request.IdempotencyKey = initialKey
			writes.chosen, writes.intents = command, nil
			writes.commits, writes.aborts = 0, 0
			mapsBefore := f.mapper.calls
			calls := 0
			writes.beforePrepare = func(ctx context.Context) {
				if boundedFixtureContext(ctx) != nil || calls != len(writes.intents)+1 {
					t.Fatal("Group Delete Store admission preceded its bounded once-per-attempt gate")
				}
			}
			gate := func(ctx context.Context) *scim.Error {
				calls++
				if boundedFixtureContext(ctx) != nil || len(writes.intents) != calls-1 || f.mapper.calls != mapsBefore {
					t.Fatal("Group Delete gate followed command or mapping effects")
				}
				return nil
			}
			deleted, err := admittedGroupDeletes(t, f.service).ExecuteAdmittedDelete(context.Background(), request, gate)
			if err != nil || deleted.Status != 204 || len(deleted.Body) != 0 || deleted.ETag != "" || deleted.Location != "" || deleted.ContentType != "" || calls != 1 || writes.commits != 1 || writes.aborts != 0 || writes.proposed == command || writes.committed != command || f.mapper.calls != mapsBefore || len(f.store.resources) != 2 || len(f.store.users) != 1 {
				t.Fatal("Group Delete changed original command ownership, empty success or related resources", err)
			}
			intent := writes.intents[0]
			var canonical struct {
				Operation scim.Operation
				ID        string
				IfMatch   scim.Version
				Body      any
			}
			if json.Unmarshal(intent.CanonicalRequest, &canonical) != nil || canonical.Operation != scim.GroupDelete || canonical.ID != request.ResourceID || canonical.IfMatch != request.IfMatch || canonical.Body != nil || intent.IdempotencyKey != initialKey || intent.Scope != intent.Connection.Scope || intent.Connection.Version != 1 {
				t.Fatal("Group Delete changed canonical target, original precondition or authenticated command scope")
			}
			for _, replayKey := range []string{"", "optional-delete-key"} {
				request.IdempotencyKey = replayKey
				replay, replayErr := admittedGroupDeletes(t, f.service).ExecuteAdmittedDelete(context.Background(), request, gate)
				if replayErr != nil || replay.Status != 204 || len(replay.Body) != 0 || replay.ETag != "" || replay.Location != "" || replay.ContentType != "" || writes.commits != 1 || writes.aborts != 0 || f.mapper.calls != mapsBefore || !bytes.Equal(intent.CanonicalRequest, writes.intents[len(writes.intents)-1].CanonicalRequest) {
					t.Fatal("Group Delete optional/headerless replay rechecked the tombstone or repeated effects", replayErr)
				}
			}
			denied, err := admittedGroupDeletes(t, f.service).ExecuteAdmittedDelete(context.Background(), request, func(context.Context) *scim.Error { calls++; return scim.NewError(403, "") })
			assertProtocolError(t, denied, err, 403, "")
			if calls != 4 || len(writes.intents) != 3 || writes.commits != 1 || len(f.store.resources) != 2 || len(f.store.users) != 1 {
				t.Fatal("Group Delete replay bypassed current admission or removed related resources")
			}
			read := f.call(t, scim.GroupGet, nestedID, "", "")
			foreignRead := f.execute(t, scim.Request{Operation: scim.GroupGet, Credential: authentication.NewBearerCredential("fixture-other-connection"), ResourceID: object(t, foreign.Body)["id"].(string)})
			if read.ETag != nested.ETag || !bytes.Equal(read.Body, nested.Body) || foreignRead.ETag != foreign.ETag || !bytes.Equal(foreignRead.Body, foreign.Body) {
				t.Fatal("deleting a parent Group changed nested or foreign-connection Groups")
			}
		})
	}
}

func TestGroupsAdmittedDeletePreflightRejectsBeforeGateOrResourceIO(t *testing.T) {
	for _, tc := range []struct {
		name                string
		change              func(*scim.Request)
		policyDeny, nilGate bool
		status              int
	}{
		{name: "missing target", change: func(r *scim.Request) { r.ResourceID = "" }, status: 404},
		{name: "unsafe target", change: func(r *scim.Request) { r.ResourceID = "other/group" }, status: 404},
		{name: "oversized target", change: func(r *scim.Request) { r.ResourceID = strings.Repeat("x", scim.DefaultLimits().StringBytes+1) }, status: 400},
		{name: "missing If-Match", change: func(r *scim.Request) { r.IfMatch = "" }, status: 428},
		{name: "weak If-Match", change: func(r *scim.Request) { r.IfMatch = `W/"weak"` }, status: 400},
		{name: "wildcard If-Match", change: func(r *scim.Request) { r.IfMatch = "*" }, status: 400},
		{name: "multiple If-Match", change: func(r *scim.Request) { r.IfMatch = `"one","two"` }, status: 400},
		{name: "unexpected body", change: func(r *scim.Request) { r.ContentType = "application/scim+json"; r.Body = []byte(`{}`) }, status: 400},
		{name: "unsupported body media", change: func(r *scim.Request) { r.ContentType = "application/json"; r.Body = []byte(`{}`) }, status: 415},
		{name: "invalid projection", change: func(r *scim.Request) { r.Query.Attributes = "userName" }, status: 400},
		{name: "encoding", change: func(r *scim.Request) { r.ContentEncoding = "gzip" }, status: 415},
		{name: "oversized optional key", change: func(r *scim.Request) { r.IdempotencyKey = strings.Repeat("x", 257) }, status: 400},
		{name: "invalid bearer", change: func(r *scim.Request) { r.Credential = authentication.NewBearerCredential("invalid bearer") }, status: 401},
		{name: "unknown bearer", change: func(r *scim.Request) { r.Credential = authentication.NewBearerCredential("unknown") }, status: 401},
		{name: "expired bearer", change: func(r *scim.Request) { r.Credential = authentication.NewBearerCredential("expired") }, status: 401},
		{name: "unowned bearer", change: func(r *scim.Request) { r.Credential = authentication.NewBearerCredential("unowned") }, status: 401},
		{name: "operation denial", policyDeny: true, status: 403},
		{name: "missing gate", nilGate: true, status: 503},
		{name: "Group Create", change: func(r *scim.Request) { r.Operation = scim.GroupCreate }, status: 501},
		{name: "Group Get", change: func(r *scim.Request) { r.Operation = scim.GroupGet }, status: 501},
		{name: "Group List", change: func(r *scim.Request) { r.Operation = scim.GroupList }, status: 501},
		{name: "Group Search", change: func(r *scim.Request) { r.Operation = scim.GroupSearch }, status: 501},
		{name: "Group Replace", change: func(r *scim.Request) { r.Operation = scim.GroupReplace }, status: 501},
		{name: "Group Patch", change: func(r *scim.Request) { r.Operation = scim.GroupPatch }, status: 501},
		{name: "User Delete", change: func(r *scim.Request) { r.Operation = scim.UserDelete }, status: 501},
		{name: "discovery", change: func(r *scim.Request) { r.Operation = scim.ServiceProviderConfig }, status: 501},
		{name: "Bulk", change: func(r *scim.Request) { r.Operation = scim.Bulk }, status: 501},
	} {
		t.Run(tc.name, func(t *testing.T) {
			policy := &protocolAuthorizer{}
			var reads *admittedGroupReadStore
			f := newGroupFixture(t, func(c *scim.GroupsConfig) {
				c.Authorizer = policy
				reads = &admittedGroupReadStore{GroupStore: c.Store}
				c.Store = reads
			})
			created := f.call(t, scim.GroupCreate, "", "", groupBody("preserved", ""))
			request := admittedGroupDeleteRequest(t, created)
			if tc.change != nil {
				tc.change(&request)
			}
			if tc.policyDeny {
				policy.err = errors.New("private policy diagnostic")
			}
			before, mapsBefore := f.store.prepares, f.mapper.calls
			calls := 0
			var gate func(context.Context) *scim.Error
			if !tc.nilGate {
				gate = func(context.Context) *scim.Error { calls++; return nil }
			}
			out, err := admittedGroupDeletes(t, f.service).ExecuteAdmittedDelete(context.Background(), request, gate)
			assertProtocolError(t, out, err, tc.status, "")
			if calls != 0 || f.store.prepares != before || f.mapper.calls != mapsBefore || reads.gets != 0 || reads.snapshots != 0 || len(f.store.resources) != 1 || out.Status != 0 || out.ETag != "" || out.Location != "" || out.ContentType != "" {
				t.Fatal("Group Delete preflight charged admission or crossed command/resource effects")
			}
		})
	}
	for _, service := range []*scim.GroupsService{nil, new(scim.GroupsService)} {
		out, err := admittedGroupDeletes(t, service).ExecuteAdmittedDelete(context.Background(), scim.Request{Operation: scim.GroupDelete}, func(context.Context) *scim.Error { t.Fatal("invalid service invoked gate"); return nil })
		assertProtocolError(t, out, err, 503, "")
	}
}

func TestGroupsAdmittedDeleteDenialsPreserveGroupWithoutEffects(t *testing.T) {
	for _, tc := range []struct {
		name   string
		deny   func(context.Context) *scim.Error
		status int
		retry  uint32
	}{
		{name: "policy", deny: func(context.Context) *scim.Error { return scim.NewError(403, "") }, status: 403},
		{name: "quota", deny: func(context.Context) *scim.Error { return scim.NewRateLimitedError(1250 * time.Millisecond) }, status: 429, retry: 2},
		{name: "unknown quota", deny: func(context.Context) *scim.Error { return scim.NewError(429, "") }, status: 503},
		{name: "unavailable", deny: func(context.Context) *scim.Error { return scim.NewError(503, "") }, status: 503},
		{name: "unsupported", deny: func(context.Context) *scim.Error { return scim.NewError(404, "") }, status: 503},
		{name: "typed", deny: func(context.Context) *scim.Error { return scim.NewError(400, "invalidValue") }, status: 503},
		{name: "panic", deny: func(context.Context) *scim.Error { panic("private gate diagnostic") }, status: 503},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var reads *admittedGroupReadStore
			f := newGroupFixture(t, func(c *scim.GroupsConfig) { reads = &admittedGroupReadStore{GroupStore: c.Store}; c.Store = reads })
			created := f.call(t, scim.GroupCreate, "", "", groupBody("preserved", ""))
			before, mapsBefore := f.store.prepares, f.mapper.calls
			calls := 0
			out, err := admittedGroupDeletes(t, f.service).ExecuteAdmittedDelete(context.Background(), admittedGroupDeleteRequest(t, created), func(ctx context.Context) *scim.Error { calls++; return tc.deny(ctx) })
			denied := assertProtocolError(t, out, err, tc.status, "")
			if calls != 1 || denied.SCIMType() != "" || denied.RetryAfterSeconds() != tc.retry || f.store.prepares != before || f.mapper.calls != mapsBefore || reads.gets != 0 || reads.snapshots != 0 || out.Status != 0 || out.ETag != "" || out.Location != "" || out.ContentType != "" {
				t.Fatal("Group Delete denial lost redaction or reached command/resource effects")
			}
			read := f.call(t, scim.GroupGet, object(t, created.Body)["id"].(string), "", "")
			if read.ETag != created.ETag || !bytes.Equal(read.Body, created.Body) {
				t.Fatal("denied Group Delete changed the current representation")
			}
		})
	}
}

func TestGroupsAdmittedDeleteRetainsStorePreconditionCASAndUnknownAuthority(t *testing.T) {
	for _, scenario := range []string{"stale", "commit conflict", "unknown", "foreign target"} {
		t.Run(scenario, func(t *testing.T) {
			var writes *admittedGroupCreateStore
			f := newGroupFixture(t, func(c *scim.GroupsConfig) { writes = &admittedGroupCreateStore{GroupStore: c.Store}; c.Store = writes })
			created := f.call(t, scim.GroupCreate, "", "", groupBody("preserved", ""))
			request := admittedGroupDeleteRequest(t, created)
			if scenario == "stale" {
				request.IfMatch = `"stale-version"`
			} else if scenario == "foreign target" {
				request.Credential = authentication.NewBearerCredential("fixture-other-connection")
			}
			f.store.conflict, f.store.unknown = scenario == "commit conflict", scenario == "unknown"
			writes.intents = nil
			writes.commits, writes.aborts = 0, 0
			mapsBefore := f.mapper.calls
			calls := 0
			for range 2 {
				out, err := admittedGroupDeletes(t, f.service).ExecuteAdmittedDelete(context.Background(), request, func(context.Context) *scim.Error { calls++; return nil })
				status := 412
				if scenario == "unknown" {
					status = 503
				} else if scenario == "foreign target" {
					status = 404
				}
				assertProtocolError(t, out, err, status, "")
			}
			wantCommits, wantAborts := 1, 1
			if scenario == "stale" || scenario == "foreign target" {
				wantCommits = 0
			} else if scenario == "unknown" {
				wantAborts = 0
			}
			if calls != 2 || len(writes.intents) != 2 || writes.commits != wantCommits || writes.aborts != wantAborts || f.mapper.calls != mapsBefore || len(f.store.resources) != 1 || scenario == "unknown" && f.store.lastOutcome != scim.WriteOutcomeUnknown {
				t.Fatal("Group Delete admission replaced native current target/precondition/CAS/outcome authority")
			}
			read := f.call(t, scim.GroupGet, request.ResourceID, "", "")
			if read.ETag != created.ETag || !bytes.Equal(read.Body, created.Body) {
				t.Fatal("rejected or uncertain Group Delete removed the original Group")
			}
		})
	}
}

func TestGroupsAdmittedDeleteRejectsDescendantReentryEvenInvalidWrappers(t *testing.T) {
	for _, nested := range []string{"ordinary Group", "admitted Delete", "Group Patch", "Group read", "foreign operation", "missing gate", "nil service", "uninitialized service", "sibling User"} {
		t.Run(nested, func(t *testing.T) {
			f := newGroupFixture(t, nil)
			users := newProtocolFixture(t)
			created := f.call(t, scim.GroupCreate, "", "", groupBody("preserved", ""))
			request := admittedGroupDeleteRequest(t, created)
			before, mapsBefore := f.store.prepares, f.mapper.calls
			calls := 0
			out, err := admittedGroupDeletes(t, f.service).ExecuteAdmittedDelete(context.Background(), request, func(ctx context.Context) *scim.Error {
				calls++
				child, cancel := context.WithCancel(ctx)
				defer cancel()
				var inner scim.Response
				var innerErr error
				gate := func(context.Context) *scim.Error { t.Fatal("nested gate executed"); return nil }
				switch nested {
				case "ordinary Group":
					inner, innerErr = f.service.Execute(child, request)
				case "admitted Delete":
					inner, innerErr = admittedGroupDeletes(t, f.service).ExecuteAdmittedDelete(child, request, gate)
				case "Group Patch":
					inner, innerErr = admittedGroupPatches(t, f.service).ExecuteAdmittedPatch(child, admittedGroupPatchRequest(t, created, `{"op":"replace","path":"displayName","value":"nested"}`), gate)
				case "Group read":
					inner, innerErr = admittedGroups(t, f.service).ExecuteAdmittedRead(child, admittedGroupReadRequest(scim.GroupList, ""), gate)
				case "foreign operation":
					request.Operation = scim.UserDelete
					inner, innerErr = admittedGroupDeletes(t, f.service).ExecuteAdmittedDelete(child, request, gate)
				case "missing gate":
					inner, innerErr = admittedGroupDeletes(t, f.service).ExecuteAdmittedDelete(child, request, nil)
				case "nil service":
					inner, innerErr = admittedGroupDeletes(t, nil).ExecuteAdmittedDelete(child, request, nil)
				case "uninitialized service":
					inner, innerErr = admittedGroupDeletes(t, new(scim.GroupsService)).ExecuteAdmittedDelete(child, request, nil)
				case "sibling User":
					inner, innerErr = users.service.Execute(child, admittedCreateRequest("nested-user"))
				}
				assertProtocolError(t, inner, innerErr, 503, "")
				return nil
			})
			assertProtocolError(t, out, err, 503, "")
			if calls != 1 || f.store.prepares != before || f.mapper.calls != mapsBefore || users.store.prepares != 0 || users.mapper.calls != 0 || len(f.store.resources) != 1 {
				t.Fatal("ignored nested denial escaped Group Delete invocation fence")
			}
		})
	}
}

func TestGroupsAdmittedDeleteRetainsAuthorityCancellationAndLateDisclosure(t *testing.T) {
	for _, stage := range []string{"before gate", "gate allow", "gate deny", "gate quota", "cancel gate", "late commit", "cancel commit"} {
		t.Run(stage, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
			defer cancel()
			connection, err := (protocolAuthenticator{}).Authenticate(ctx, authentication.NewBearerCredential("fixture-connection"))
			if err != nil {
				t.Fatal(err)
			}
			clock := &freshnessFixture{test: t, now: fixtureNow, connection: connection, visits: make(map[string]int)}
			var writes *admittedGroupCreateStore
			f := newGroupFixture(t, func(c *scim.GroupsConfig) {
				c.Now = func() time.Time { return clock.now }
				c.RequestTimeout = time.Minute
				c.Authenticator = freshnessAuthenticator{state: clock}
				c.Authorizer = freshnessAuthorizer{Authorizer: c.Authorizer, state: clock}
				writes = &admittedGroupCreateStore{GroupStore: c.Store}
				c.Store = writes
			})
			created := f.call(t, scim.GroupCreate, "", "", groupBody("original", ""))
			writes.intents = nil
			writes.commits, writes.aborts = 0, 0
			mapsBefore := f.mapper.calls
			clock.policyCalls, clock.now = 0, fixtureNow.Add(19*time.Second)
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
			out, err := admittedGroupDeletes(t, f.service).ExecuteAdmittedDelete(ctx, admittedGroupDeleteRequest(t, created), func(gate context.Context) *scim.Error {
				calls++
				deadline, ok := gate.Deadline()
				if !ok || time.Until(deadline) > time.Second+100*time.Millisecond || clock.policyCalls != 1 {
					t.Fatal("Group Delete gate renewed authority or preceded operation authorization")
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
			wantCalls, wantWrites, wantResources := 1, 0, 1
			if stage == "before gate" {
				wantCalls = 0
			}
			if stage == "late commit" || stage == "cancel commit" {
				wantWrites, wantResources = 1, 0
				if f.store.lastOutcome != scim.WriteOutcomeCommitted || writes.aborts != 0 {
					t.Fatal("Group Delete disclosure fence rewrote the committed outcome")
				}
			}
			if calls != wantCalls || len(writes.intents) != wantWrites || writes.commits != wantWrites || f.mapper.calls != mapsBefore || len(f.store.resources) != wantResources || out.Status != 0 || out.ETag != "" || out.Location != "" || out.ContentType != "" {
				t.Fatal("Group Delete authority/cancellation leaked metadata or crossed no-effect fence")
			}
		})
	}
}

func TestGroupsAdmittedDeleteRetainsEarlierDeadlinesAndCancellation(t *testing.T) {
	for _, scenario := range []string{"parent", "request", "already canceled", "gate timeout"} {
		t.Run(scenario, func(t *testing.T) {
			f := newGroupFixture(t, func(c *scim.GroupsConfig) {
				if scenario == "request" {
					c.RequestTimeout = 150 * time.Millisecond
				}
			})
			created := f.call(t, scim.GroupCreate, "", "", groupBody("preserved", ""))
			before, mapsBefore := f.store.prepares, f.mapper.calls
			bound := time.Now().Add(150 * time.Millisecond)
			ctx, cancel := context.WithDeadline(context.Background(), bound)
			defer cancel()
			if scenario == "request" {
				ctx = context.Background()
			} else if scenario == "already canceled" {
				cancel()
			}
			calls := 0
			out, err := admittedGroupDeletes(t, f.service).ExecuteAdmittedDelete(ctx, admittedGroupDeleteRequest(t, created), func(gate context.Context) *scim.Error {
				calls++
				deadline, ok := gate.Deadline()
				if !ok || deadline.After(bound.Add(25*time.Millisecond)) {
					t.Fatal("Group Delete gate extended an earlier parent or request deadline")
				}
				if scenario == "gate timeout" {
					<-gate.Done()
				}
				return scim.NewError(403, "")
			})
			status, wantCalls := 403, 1
			if scenario == "already canceled" {
				status, wantCalls = 503, 0
			} else if scenario == "gate timeout" {
				status = 503
			}
			assertProtocolError(t, out, err, status, "")
			if calls != wantCalls || f.store.prepares != before || f.mapper.calls != mapsBefore || len(f.store.resources) != 1 {
				t.Fatal("bounded or canceled Group Delete crossed command/resource effects")
			}
		})
	}
}

func TestGroupsAdmittedDeletePreservesOrdinaryAndSiblingSelections(t *testing.T) {
	f := newGroupFixture(t, nil)
	created := f.call(t, scim.GroupCreate, "", "", groupBody("ordinary", ""))
	request := admittedGroupDeleteRequest(t, created)
	ordinary, err := f.service.Execute(context.Background(), request)
	if err != nil || ordinary.Status != 204 {
		t.Fatal("ordinary Group Delete failed", err)
	}
	before, mapsBefore := f.store.prepares, f.mapper.calls
	denied, err := admittedGroupDeletes(t, f.service).ExecuteAdmittedDelete(context.Background(), request, func(context.Context) *scim.Error { return scim.NewError(403, "") })
	assertProtocolError(t, denied, err, 403, "")
	if f.store.prepares != before || f.mapper.calls != mapsBefore {
		t.Fatal("ordinary Group Delete replay bypassed admission")
	}
	replay, err := admittedGroupDeletes(t, f.service).ExecuteAdmittedDelete(context.Background(), request, func(context.Context) *scim.Error { return nil })
	if err != nil || replay.Status != 204 || len(replay.Body) != 0 || f.mapper.calls != mapsBefore {
		t.Fatal("Group Delete changed ordinary headerless replay", err)
	}
	other, err := admittedGroupCreates(t, f.service).ExecuteAdmittedCreate(context.Background(), admittedGroupCreateRequest("separate Group"), func(context.Context) *scim.Error { return nil })
	if err != nil || other.Status != 201 {
		t.Fatal("Group Delete changed admitted Group creation", err)
	}
	read, err := admittedGroups(t, f.service).ExecuteAdmittedRead(context.Background(), admittedGroupReadRequest(scim.GroupGet, object(t, other.Body)["id"].(string)), func(context.Context) *scim.Error { return nil })
	if err != nil || read.ETag != other.ETag || !bytes.Equal(read.Body, other.Body) {
		t.Fatal("Group Delete changed admitted Group reads", err)
	}
}
