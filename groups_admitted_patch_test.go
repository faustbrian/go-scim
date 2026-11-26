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

type admittedGroupsPatcher interface {
	ExecuteAdmittedPatch(context.Context, scim.Request, func(context.Context) *scim.Error) (scim.Response, error)
}

func admittedGroupPatches(t *testing.T, service *scim.GroupsService) admittedGroupsPatcher {
	t.Helper()
	selected, ok := any(service).(admittedGroupsPatcher)
	if !ok {
		t.Fatal("GroupsService has no explicit conditional admitted Patch selection")
	}
	return selected
}

func admittedGroupPatchRequest(t *testing.T, created scim.Response, operations string) scim.Request {
	t.Helper()
	return scim.Request{Operation: scim.GroupPatch, Credential: authentication.NewBearerCredential("fixture-connection"), ResourceID: object(t, created.Body)["id"].(string), IfMatch: created.ETag, ContentType: "application/scim+json", Body: []byte(patchBody(operations))}
}

func TestGroupsAdmittedPatchRetainsWholePatchCanonicalCommandAndReplay(t *testing.T) {
	command, err := identity.NewCommandID()
	if err != nil {
		t.Fatal(err)
	}
	var writes *admittedGroupCreateStore
	f := newGroupFixture(t, func(c *scim.GroupsConfig) {
		writes = &admittedGroupCreateStore{GroupStore: c.Store, chosen: command}
		c.Store = writes
	})
	f.addUser("member-a", "fixture-connection")
	f.addUser("member-b", "fixture-connection")
	created := f.call(t, scim.GroupCreate, "", "", groupBody("original", `,"externalId":"preserved","members":[{"value":"member-a","display":"Before"}]`))
	request := admittedGroupPatchRequest(t, created, `{"op":"replace","path":"displayName","value":"updated"},{"op":"remove","path":"members[value eq \"member-a\"]"},{"op":"add","path":"members","value":[{"value":"member-a","display":"After"},{"value":"member-b","$ref":"Users/member-b"}]}`)
	request.IdempotencyKey = "group-patch-key"
	writes.intents = nil
	writes.commits, writes.aborts = 0, 0
	mapsBefore := f.mapper.calls
	calls := 0
	writes.beforePrepare = func(ctx context.Context) {
		if boundedFixtureContext(ctx) != nil || calls != len(writes.intents)+1 {
			t.Fatal("Group Patch Store admission preceded its bounded once-per-attempt gate")
		}
	}
	gate := func(ctx context.Context) *scim.Error {
		calls++
		if boundedFixtureContext(ctx) != nil || len(writes.intents) != calls-1 || f.mapper.calls != mapsBefore {
			t.Fatal("Group Patch gate followed command or mapping effects")
		}
		return nil
	}
	patched, err := admittedGroupPatches(t, f.service).ExecuteAdmittedPatch(context.Background(), request, gate)
	if err != nil || patched.Status != 200 || patched.ETag == created.ETag || patched.Location != created.Location || calls != 1 || writes.commits != 1 || writes.aborts != 0 || writes.proposed == command || writes.committed != command || f.mapper.calls != mapsBefore+1 {
		t.Fatal("Group Patch changed conditional write or original command ownership", err)
	}
	doc := object(t, patched.Body)
	members := doc["members"].([]any)
	first, second := members[0].(map[string]any), members[1].(map[string]any)
	if doc["displayName"] != "updated" || doc["externalId"] != "preserved" || len(members) != 2 || first["value"] != "member-a" || first["display"] != "After" || second["value"] != "member-b" || second["type"] != "User" || second["$ref"] != "https://scim.example.test/v2/Users/member-b" {
		t.Fatal("Group Patch lost ordered remove/add semantics, siblings or normalized membership")
	}
	intent := writes.intents[0]
	var canonical struct {
		Operation scim.Operation
		ID        string
		IfMatch   scim.Version
		Body      map[string]any
	}
	if json.Unmarshal(intent.CanonicalRequest, &canonical) != nil || canonical.Operation != scim.GroupPatch || canonical.ID != request.ResourceID || canonical.IfMatch != request.IfMatch || len(canonical.Body["Operations"].([]any)) != 3 || intent.IdempotencyKey != request.IdempotencyKey || intent.Scope != intent.Connection.Scope || intent.Connection.Version != 1 {
		t.Fatal("Group Patch rewrote complete canonical input or authenticated command scope")
	}
	mapsBefore = f.mapper.calls
	replay, err := admittedGroupPatches(t, f.service).ExecuteAdmittedPatch(context.Background(), request, gate)
	if err != nil || replay.Status != patched.Status || replay.ETag != patched.ETag || replay.Location != patched.Location || !bytes.Equal(replay.Body, patched.Body) || calls != 2 || writes.commits != 1 || f.mapper.calls != mapsBefore || !bytes.Equal(intent.CanonicalRequest, writes.intents[1].CanonicalRequest) {
		t.Fatal("Group Patch replay rechecked stale If-Match or repeated mapping/commit", err)
	}
	denied, err := admittedGroupPatches(t, f.service).ExecuteAdmittedPatch(context.Background(), request, func(context.Context) *scim.Error { calls++; return scim.NewError(403, "") })
	assertProtocolError(t, denied, err, 403, "")
	if calls != 3 || len(writes.intents) != 2 || writes.commits != 1 || f.mapper.calls != mapsBefore {
		t.Fatal("Group Patch replay bypassed current admission")
	}
}

func TestGroupsAdmittedPatchPreflightRejectsBeforeGateOrResourceIO(t *testing.T) {
	for _, tc := range []struct {
		name                string
		change              func(*scim.Request)
		policyDeny, nilGate bool
		status              int
	}{
		{name: "missing target", change: func(r *scim.Request) { r.ResourceID = "" }, status: 404},
		{name: "unsafe target", change: func(r *scim.Request) { r.ResourceID = "other/group" }, status: 404},
		{name: "missing If-Match", change: func(r *scim.Request) { r.IfMatch = "" }, status: 428},
		{name: "weak If-Match", change: func(r *scim.Request) { r.IfMatch = `W/"weak"` }, status: 400},
		{name: "wildcard If-Match", change: func(r *scim.Request) { r.IfMatch = "*" }, status: 400},
		{name: "multiple If-Match", change: func(r *scim.Request) { r.IfMatch = `"one","two"` }, status: 400},
		{name: "missing body", change: func(r *scim.Request) { r.Body = nil }, status: 400},
		{name: "malformed JSON", change: func(r *scim.Request) { r.Body = []byte(`{"schemas":[`) }, status: 400},
		{name: "case alias", change: func(r *scim.Request) {
			r.Body = []byte(patchBody(`{"op":"add","OP":"replace","path":"displayName","value":"x"}`))
		}, status: 400},
		{name: "wrong schema", change: func(r *scim.Request) { r.Body = []byte(`{"schemas":["urn:unknown"],"Operations":[]}`) }, status: 400},
		{name: "empty operations", change: func(r *scim.Request) { r.Body = []byte(patchBody("")) }, status: 400},
		{name: "invalid verb", change: func(r *scim.Request) { r.Body = []byte(patchBody(`{"op":"delete","path":"displayName"}`)) }, status: 400},
		{name: "missing value", change: func(r *scim.Request) { r.Body = []byte(patchBody(`{"op":"replace","path":"displayName"}`)) }, status: 400},
		{name: "User path", change: func(r *scim.Request) { r.Body = []byte(patchBody(`{"op":"remove","path":"userName"}`)) }, status: 400},
		{name: "unknown member child", change: func(r *scim.Request) {
			r.Body = []byte(patchBody(`{"op":"add","path":"members","value":[{"value":"a","unknown":"x"}]}`))
		}, status: 400},
		{name: "pathless User field", change: func(r *scim.Request) { r.Body = []byte(patchBody(`{"op":"add","value":{"active":true}}`)) }, status: 400},
		{name: "invalid projection", change: func(r *scim.Request) { r.Query.Attributes = "userName" }, status: 400},
		{name: "operation ceiling", change: func(r *scim.Request) {
			r.Body = []byte(patchBody(strings.TrimSuffix(strings.Repeat(`{"op":"replace","path":"displayName","value":"x"},`, scim.DefaultLimits().PatchOperations+1), ",")))
		}, status: 400},
		{name: "path ceiling", change: func(r *scim.Request) {
			r.Body = []byte(patchBody(`{"op":"remove","path":"` + strings.Repeat("x", scim.DefaultLimits().PathBytes+1) + `"}`))
		}, status: 400},
		{name: "string ceiling", change: func(r *scim.Request) {
			r.Body = []byte(patchBody(`{"op":"replace","path":"displayName","value":"` + strings.Repeat("x", scim.DefaultLimits().StringBytes+1) + `"}`))
		}, status: 400},
		{name: "body ceiling", change: func(r *scim.Request) { r.Body = bytes.Repeat([]byte(" "), scim.DefaultLimits().BodyBytes+1) }, status: 413},
		{name: "media type", change: func(r *scim.Request) { r.ContentType = "application/json" }, status: 415},
		{name: "encoding", change: func(r *scim.Request) { r.ContentEncoding = "gzip" }, status: 415},
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
		{name: "Group Delete", change: func(r *scim.Request) { r.Operation = scim.GroupDelete }, status: 501},
		{name: "User Patch", change: func(r *scim.Request) { r.Operation = scim.UserPatch }, status: 501},
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
			created := f.call(t, scim.GroupCreate, "", "", groupBody("original", ""))
			request := admittedGroupPatchRequest(t, created, `{"op":"replace","path":"displayName","value":"unadmitted"}`)
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
			out, err := admittedGroupPatches(t, f.service).ExecuteAdmittedPatch(context.Background(), request, gate)
			assertProtocolError(t, out, err, tc.status, "")
			if calls != 0 || f.store.prepares != before || f.mapper.calls != mapsBefore || reads.gets != 0 || reads.snapshots != 0 || len(f.store.resources) != 1 || out.Status != 0 || out.ETag != "" || out.Location != "" || out.ContentType != "" {
				t.Fatal("Group Patch preflight charged admission or crossed command/resource effects")
			}
		})
	}
	for _, service := range []*scim.GroupsService{nil, new(scim.GroupsService)} {
		out, err := admittedGroupPatches(t, service).ExecuteAdmittedPatch(context.Background(), scim.Request{Operation: scim.GroupPatch}, func(context.Context) *scim.Error { t.Fatal("invalid service invoked gate"); return nil })
		assertProtocolError(t, out, err, 503, "")
	}
}

func TestGroupsAdmittedPatchDenialsPreserveGroupWithoutEffects(t *testing.T) {
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
			out, err := admittedGroupPatches(t, f.service).ExecuteAdmittedPatch(context.Background(), admittedGroupPatchRequest(t, created, `{"op":"replace","path":"displayName","value":"denied"}`), func(ctx context.Context) *scim.Error { calls++; return tc.deny(ctx) })
			denied := assertProtocolError(t, out, err, tc.status, "")
			if calls != 1 || denied.SCIMType() != "" || denied.RetryAfterSeconds() != tc.retry || f.store.prepares != before || f.mapper.calls != mapsBefore || reads.gets != 0 || reads.snapshots != 0 || out.Status != 0 || out.ETag != "" || out.Location != "" || out.ContentType != "" {
				t.Fatal("Group Patch denial lost redaction or reached command/resource effects")
			}
			read := f.call(t, scim.GroupGet, object(t, created.Body)["id"].(string), "", "")
			if read.ETag != created.ETag || !bytes.Equal(read.Body, created.Body) {
				t.Fatal("denied Group Patch changed the current representation")
			}
		})
	}
}

func TestGroupsAdmittedPatchRetainsNativeNoopRollbackMemberCASAndUnknownOutcomes(t *testing.T) {
	for _, scenario := range []string{"noop", "rollback", "member ceiling", "missing member", "foreign member", "wrong member type", "stale", "commit conflict", "unknown"} {
		t.Run(scenario, func(t *testing.T) {
			var writes *admittedGroupCreateStore
			f := newGroupFixture(t, func(c *scim.GroupsConfig) {
				c.GroupMembers = 1
				writes = &admittedGroupCreateStore{GroupStore: c.Store}
				c.Store = writes
			})
			f.addUser("member-a", "fixture-connection")
			created := f.call(t, scim.GroupCreate, "", "", groupBody("original", `,"members":[{"value":"member-a","display":"Before"}]`))
			operations := `{"op":"replace","path":"displayName","value":"changed"}`
			switch scenario {
			case "noop":
				operations = `{"op":"add","value":{"members":[{"value":"member-a"}]}}`
			case "rollback":
				operations += `,{"op":"replace","path":"members[value eq \"member-a\"].display","value":"Changed"}`
			case "member ceiling":
				f.addUser("member-b", "fixture-connection")
				operations += `,{"op":"add","path":"members","value":[{"value":"member-b"}]}`
			case "missing member", "foreign member", "wrong member type":
				if scenario == "foreign member" {
					f.addUser("member-b", "fixture-other-connection")
				} else if scenario == "wrong member type" {
					f.addUser("member-b", "fixture-connection")
				}
				member := `{"value":"member-b"}`
				if scenario == "wrong member type" {
					member = `{"value":"member-b","type":"Group"}`
				}
				operations += `,{"op":"remove","path":"members"},{"op":"add","path":"members","value":[` + member + `]}`
			}
			request := admittedGroupPatchRequest(t, created, operations)
			request.IdempotencyKey = "native-group-patch"
			if scenario == "stale" {
				request.IfMatch = `"stale-version"`
			}
			f.store.conflict, f.store.unknown = scenario == "commit conflict", scenario == "unknown"
			writes.intents = nil
			writes.commits, writes.aborts = 0, 0
			calls := 0
			for range 2 {
				out, err := admittedGroupPatches(t, f.service).ExecuteAdmittedPatch(context.Background(), request, func(context.Context) *scim.Error { calls++; return nil })
				switch scenario {
				case "noop":
					if err != nil || out.Status != 200 || out.ETag != created.ETag || !bytes.Equal(out.Body, created.Body) {
						t.Fatal("admitted no-op Group Patch changed original metadata or replay", err)
					}
				case "rollback":
					assertProtocolError(t, out, err, 400, "mutability")
				case "member ceiling", "missing member", "foreign member", "wrong member type":
					assertProtocolError(t, out, err, 400, "invalidValue")
				case "stale", "commit conflict":
					assertProtocolError(t, out, err, 412, "")
				case "unknown":
					assertProtocolError(t, out, err, 503, "")
				}
			}
			wantCommits, wantAborts := 1, 1
			if scenario == "stale" || scenario == "rollback" || scenario == "member ceiling" {
				wantCommits = 0
			} else if scenario == "noop" || scenario == "unknown" {
				wantAborts = 0
			}
			if calls != 2 || len(writes.intents) != 2 || writes.commits != wantCommits || writes.aborts != wantAborts || len(f.store.resources) != 1 || scenario == "unknown" && f.store.lastOutcome != scim.WriteOutcomeUnknown {
				t.Fatal("Group Patch admission replaced native membership, rollback, CAS or outcome authority")
			}
			read := f.call(t, scim.GroupGet, request.ResourceID, "", "")
			if read.ETag != created.ETag || !bytes.Equal(read.Body, created.Body) {
				t.Fatal("failed, no-op or unknown Group Patch changed the current representation")
			}
		})
	}
}

func TestGroupsAdmittedPatchRejectsDescendantReentryEvenInvalidWrappers(t *testing.T) {
	for _, nested := range []string{"ordinary Group", "admitted Patch", "Group Replace", "Group Create", "Group read", "foreign operation", "missing gate", "nil service", "uninitialized service", "sibling User"} {
		t.Run(nested, func(t *testing.T) {
			f := newGroupFixture(t, nil)
			users := newProtocolFixture(t)
			created := f.call(t, scim.GroupCreate, "", "", groupBody("original", ""))
			request := admittedGroupPatchRequest(t, created, `{"op":"replace","path":"displayName","value":"changed"}`)
			before, mapsBefore := f.store.prepares, f.mapper.calls
			calls := 0
			out, err := admittedGroupPatches(t, f.service).ExecuteAdmittedPatch(context.Background(), request, func(ctx context.Context) *scim.Error {
				calls++
				child, cancel := context.WithCancel(ctx)
				defer cancel()
				var inner scim.Response
				var innerErr error
				gate := func(context.Context) *scim.Error { t.Fatal("nested gate executed"); return nil }
				switch nested {
				case "ordinary Group":
					inner, innerErr = f.service.Execute(child, request)
				case "admitted Patch":
					inner, innerErr = admittedGroupPatches(t, f.service).ExecuteAdmittedPatch(child, request, gate)
				case "Group Replace":
					inner, innerErr = admittedGroupReplaces(t, f.service).ExecuteAdmittedReplace(child, admittedGroupReplaceRequest(t, created, groupBody("nested", "")), gate)
				case "Group Create":
					inner, innerErr = admittedGroupCreates(t, f.service).ExecuteAdmittedCreate(child, admittedGroupCreateRequest("nested"), gate)
				case "Group read":
					inner, innerErr = admittedGroups(t, f.service).ExecuteAdmittedRead(child, admittedGroupReadRequest(scim.GroupList, ""), gate)
				case "foreign operation":
					request.Operation = scim.UserPatch
					inner, innerErr = admittedGroupPatches(t, f.service).ExecuteAdmittedPatch(child, request, gate)
				case "missing gate":
					inner, innerErr = admittedGroupPatches(t, f.service).ExecuteAdmittedPatch(child, request, nil)
				case "nil service":
					inner, innerErr = admittedGroupPatches(t, nil).ExecuteAdmittedPatch(child, request, nil)
				case "uninitialized service":
					inner, innerErr = admittedGroupPatches(t, new(scim.GroupsService)).ExecuteAdmittedPatch(child, request, nil)
				case "sibling User":
					inner, innerErr = users.service.Execute(child, admittedCreateRequest("nested-user"))
				}
				assertProtocolError(t, inner, innerErr, 503, "")
				return nil
			})
			assertProtocolError(t, out, err, 503, "")
			if calls != 1 || f.store.prepares != before || f.mapper.calls != mapsBefore || users.store.prepares != 0 || users.mapper.calls != 0 || len(f.store.resources) != 1 {
				t.Fatal("ignored nested denial escaped Group Patch invocation fence")
			}
		})
	}
}

func TestGroupsAdmittedPatchRetainsAuthorityCancellationAndLateDisclosure(t *testing.T) {
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
			out, err := admittedGroupPatches(t, f.service).ExecuteAdmittedPatch(ctx, admittedGroupPatchRequest(t, created, `{"op":"replace","path":"displayName","value":"changed"}`), func(gate context.Context) *scim.Error {
				calls++
				deadline, ok := gate.Deadline()
				if !ok || time.Until(deadline) > time.Second+100*time.Millisecond || clock.policyCalls != 1 {
					t.Fatal("Group Patch gate renewed authority or preceded operation authorization")
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
					t.Fatal("Group Patch disclosure fence rewrote the committed outcome")
				}
			}
			if calls != wantCalls || len(writes.intents) != wantWrites || writes.commits != wantWrites || f.mapper.calls != mapsBefore+wantWrites || len(f.store.resources) != 1 || out.Status != 0 || out.ETag != "" || out.Location != "" || out.ContentType != "" {
				t.Fatal("Group Patch authority/cancellation leaked metadata or crossed no-effect fence")
			}
		})
	}
}

func TestGroupsAdmittedPatchRetainsEarlierDeadlinesAndCancellation(t *testing.T) {
	for _, scenario := range []string{"parent", "request", "already canceled", "gate timeout"} {
		t.Run(scenario, func(t *testing.T) {
			f := newGroupFixture(t, func(c *scim.GroupsConfig) {
				if scenario == "request" {
					c.RequestTimeout = 150 * time.Millisecond
				}
			})
			created := f.call(t, scim.GroupCreate, "", "", groupBody("original", ""))
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
			out, err := admittedGroupPatches(t, f.service).ExecuteAdmittedPatch(ctx, admittedGroupPatchRequest(t, created, `{"op":"replace","path":"displayName","value":"changed"}`), func(gate context.Context) *scim.Error {
				calls++
				deadline, ok := gate.Deadline()
				if !ok || deadline.After(bound.Add(25*time.Millisecond)) {
					t.Fatal("Group Patch gate extended an earlier parent or request deadline")
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
			if calls != wantCalls || f.store.prepares != before || f.mapper.calls != mapsBefore {
				t.Fatal("bounded or canceled Group Patch crossed command/mapping effects")
			}
		})
	}
}

func TestGroupsAdmittedPatchPreservesOrdinaryAndSiblingSelections(t *testing.T) {
	f := newGroupFixture(t, nil)
	created := f.call(t, scim.GroupCreate, "", "", groupBody("original", ""))
	request := admittedGroupPatchRequest(t, created, `{"op":"replace","path":"displayName","value":"ordinary"}`)
	request.IdempotencyKey = "ordinary-group-patch"
	ordinary, err := f.service.Execute(context.Background(), request)
	if err != nil || ordinary.Status != 200 {
		t.Fatal("ordinary Group Patch failed", err)
	}
	before, mapsBefore := f.store.prepares, f.mapper.calls
	denied, err := admittedGroupPatches(t, f.service).ExecuteAdmittedPatch(context.Background(), request, func(context.Context) *scim.Error { return scim.NewError(403, "") })
	assertProtocolError(t, denied, err, 403, "")
	if f.store.prepares != before || f.mapper.calls != mapsBefore {
		t.Fatal("ordinary Group Patch replay bypassed admission")
	}
	replay, err := admittedGroupPatches(t, f.service).ExecuteAdmittedPatch(context.Background(), request, func(context.Context) *scim.Error { return nil })
	if err != nil || replay.ETag != ordinary.ETag || !bytes.Equal(replay.Body, ordinary.Body) || f.mapper.calls != mapsBefore {
		t.Fatal("Group Patch changed ordinary canonical replay", err)
	}
	read, err := admittedGroups(t, f.service).ExecuteAdmittedRead(context.Background(), admittedGroupReadRequest(scim.GroupGet, request.ResourceID), func(context.Context) *scim.Error { return nil })
	if err != nil || read.ETag != ordinary.ETag || !bytes.Equal(read.Body, ordinary.Body) {
		t.Fatal("Group Patch changed admitted Group reads", err)
	}
	replaced, err := admittedGroupReplaces(t, f.service).ExecuteAdmittedReplace(context.Background(), admittedGroupReplaceRequest(t, ordinary, groupBody("separate replacement", "")), func(context.Context) *scim.Error { return nil })
	if err != nil || replaced.Status != 200 {
		t.Fatal("Group Patch changed admitted Group replacement", err)
	}
}
