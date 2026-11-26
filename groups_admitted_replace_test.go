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

type admittedGroupsReplacer interface {
	ExecuteAdmittedReplace(context.Context, scim.Request, func(context.Context) *scim.Error) (scim.Response, error)
}

func admittedGroupReplaces(t *testing.T, service *scim.GroupsService) admittedGroupsReplacer {
	t.Helper()
	selected, ok := any(service).(admittedGroupsReplacer)
	if !ok {
		t.Fatal("GroupsService has no explicit conditional admitted Replace selection")
	}
	return selected
}

func admittedGroupReplaceRequest(t *testing.T, created scim.Response, body string) scim.Request {
	t.Helper()
	return scim.Request{Operation: scim.GroupReplace, Credential: authentication.NewBearerCredential("fixture-connection"), ResourceID: object(t, created.Body)["id"].(string), IfMatch: created.ETag, ContentType: "application/scim+json", Body: []byte(body)}
}

func TestGroupsAdmittedReplaceRetainsReplacementOriginalCommandAndReplay(t *testing.T) {
	command, err := identity.NewCommandID()
	if err != nil {
		t.Fatal(err)
	}
	var writes *admittedGroupCreateStore
	f := newGroupFixture(t, func(c *scim.GroupsConfig) {
		writes = &admittedGroupCreateStore{GroupStore: c.Store, chosen: command}
		c.Store = writes
	})
	f.addUser("old-member", "fixture-connection")
	f.addUser("new-member", "fixture-connection")
	created := f.call(t, scim.GroupCreate, "", "", groupBody("original", `,"externalId":"omitted-correlation","members":[{"value":"old-member"}]`))
	request := admittedGroupReplaceRequest(t, created, groupBody("replacement", `,"members":[{"value":"new-member","$ref":"Users/new-member"}]`))
	request.IdempotencyKey = "group-replace-key"
	writes.intents = nil
	writes.commits, writes.aborts = 0, 0
	mapsBefore := f.mapper.calls
	calls := 0
	writes.beforePrepare = func(ctx context.Context) {
		if boundedFixtureContext(ctx) != nil || calls != len(writes.intents)+1 {
			t.Fatal("Group Replace Store admission preceded its bounded once-per-attempt gate")
		}
	}
	gate := func(ctx context.Context) *scim.Error {
		calls++
		if boundedFixtureContext(ctx) != nil || f.mapper.calls != mapsBefore || len(writes.intents) != calls-1 {
			t.Fatal("Group Replace gate followed mapping or command effects")
		}
		return nil
	}
	replaced, err := admittedGroupReplaces(t, f.service).ExecuteAdmittedReplace(context.Background(), request, gate)
	if err != nil || replaced.Status != 200 || replaced.ETag == created.ETag || replaced.Location != created.Location || calls != 1 || writes.commits != 1 || writes.aborts != 0 || writes.proposed == command || writes.committed != command || f.mapper.calls != mapsBefore+1 {
		t.Fatal("Group Replace changed conditional write or original command ownership", err)
	}
	doc := object(t, replaced.Body)
	member := doc["members"].([]any)[0].(map[string]any)
	if doc["id"] != request.ResourceID || doc["displayName"] != "replacement" || doc["externalId"] != nil || member["value"] != "new-member" || member["type"] != "User" || member["$ref"] != "https://scim.example.test/v2/Users/new-member" {
		t.Fatal("Group Replace merged omitted fields or lost normalized typed membership")
	}
	intent := writes.intents[0]
	var canonical struct {
		Operation scim.Operation
		ID        string
		IfMatch   scim.Version
		Body      map[string]any
	}
	if json.Unmarshal(intent.CanonicalRequest, &canonical) != nil || canonical.Operation != scim.GroupReplace || canonical.ID != request.ResourceID || canonical.IfMatch != request.IfMatch || canonical.Body["displayName"] != "replacement" || intent.Scope != intent.Connection.Scope || intent.Connection.Version != 1 || intent.IdempotencyKey != request.IdempotencyKey {
		t.Fatal("Group Replace changed normalized canonical input or authenticated command scope")
	}
	request.Body = []byte(`{ "members":[{"$ref":"Users/new-member","value":"new-member"}], "displayName":"replacement", "schemas":["` + groupURN + `"] }`)
	mapsBefore = f.mapper.calls
	replay, err := admittedGroupReplaces(t, f.service).ExecuteAdmittedReplace(context.Background(), request, gate)
	if err != nil || replay.Status != replaced.Status || replay.ETag != replaced.ETag || replay.Location != replaced.Location || !bytes.Equal(replay.Body, replaced.Body) || calls != 2 || writes.commits != 1 || f.mapper.calls != mapsBefore || !bytes.Equal(intent.CanonicalRequest, writes.intents[1].CanonicalRequest) {
		t.Fatal("Group Replace replay rechecked stale If-Match or repeated mapping/commit", err)
	}
	denied, err := admittedGroupReplaces(t, f.service).ExecuteAdmittedReplace(context.Background(), request, func(context.Context) *scim.Error { calls++; return scim.NewError(403, "") })
	assertProtocolError(t, denied, err, 403, "")
	if calls != 3 || len(writes.intents) != 2 || writes.commits != 1 || f.mapper.calls != mapsBefore {
		t.Fatal("denied Group Replace replay reached command authority")
	}
	writes.beforePrepare = nil
	request = admittedGroupReplaceRequest(t, replaced, groupBody("empty replacement", ""))
	empty, err := admittedGroupReplaces(t, f.service).ExecuteAdmittedReplace(context.Background(), request, func(context.Context) *scim.Error { calls++; return nil })
	if err != nil || empty.Status != 200 {
		t.Fatal("Group replacement with omitted members failed", err)
	}
	members, _ := object(t, empty.Body)["members"].([]any)
	if len(members) != 0 {
		t.Fatal("Group Replace retained omitted members as though it were PATCH")
	}
}

func TestGroupsAdmittedReplacePreflightRejectsBeforeGateOrResourceIO(t *testing.T) {
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
		{name: "duplicate field", change: func(r *scim.Request) { r.Body = []byte(groupBody("one", `,"displayName":"two"`)) }, status: 400},
		{name: "case alias", change: func(r *scim.Request) { r.Body = []byte(groupBody("one", `,"DISPLAYNAME":"two"`)) }, status: 400},
		{name: "missing displayName", change: func(r *scim.Request) { r.Body = []byte(`{"schemas":["` + groupURN + `"]}`) }, status: 400},
		{name: "wrong schema", change: func(r *scim.Request) { r.Body = []byte(userBody("not-a-group", "")) }, status: 400},
		{name: "server ID", change: func(r *scim.Request) { r.Body = []byte(groupBody("one", `,"id":"client-owned"`)) }, status: 400},
		{name: "server metadata", change: func(r *scim.Request) { r.Body = []byte(groupBody("one", `,"meta":{"version":"client-owned"}`)) }, status: 400},
		{name: "invalid projection", change: func(r *scim.Request) { r.Query.Attributes = "userName" }, status: 400},
		{name: "foreign reference", change: func(r *scim.Request) {
			r.Body = []byte(groupBody("one", `,"members":[{"value":"a","$ref":"https://foreign.example.test/v2/Users/a"}]`))
		}, status: 400},
		{name: "mismatched reference type", change: func(r *scim.Request) {
			r.Body = []byte(groupBody("one", `,"members":[{"value":"a","type":"Group","$ref":"Users/a"}]`))
		}, status: 400},
		{name: "duplicate members", change: func(r *scim.Request) { r.Body = []byte(groupBody("one", `,"members":[{"value":"a"},{"value":"a"}]`)) }, status: 400},
		{name: "member ceiling", change: func(r *scim.Request) { r.Body = []byte(groupBody("one", `,"members":[{"value":"a"},{"value":"b"}]`)) }, status: 400},
		{name: "oversized string", change: func(r *scim.Request) {
			r.Body = []byte(groupBody(strings.Repeat("x", scim.DefaultLimits().StringBytes+1), ""))
		}, status: 400},
		{name: "oversized body", change: func(r *scim.Request) { r.Body = bytes.Repeat([]byte(" "), scim.DefaultLimits().BodyBytes+1) }, status: 413},
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
		{name: "Group Patch", change: func(r *scim.Request) { r.Operation = scim.GroupPatch }, status: 501},
		{name: "Group Delete", change: func(r *scim.Request) { r.Operation = scim.GroupDelete }, status: 501},
		{name: "User Replace", change: func(r *scim.Request) { r.Operation = scim.UserReplace }, status: 501},
		{name: "discovery", change: func(r *scim.Request) { r.Operation = scim.ServiceProviderConfig }, status: 501},
		{name: "Bulk", change: func(r *scim.Request) { r.Operation = scim.Bulk }, status: 501},
	} {
		t.Run(tc.name, func(t *testing.T) {
			policy := &protocolAuthorizer{}
			var reads *admittedGroupReadStore
			f := newGroupFixture(t, func(c *scim.GroupsConfig) {
				c.Authorizer, c.GroupMembers = policy, 1
				reads = &admittedGroupReadStore{GroupStore: c.Store}
				c.Store = reads
			})
			created := f.call(t, scim.GroupCreate, "", "", groupBody("preflight original", ""))
			request := admittedGroupReplaceRequest(t, created, groupBody("unadmitted", ""))
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
			out, err := admittedGroupReplaces(t, f.service).ExecuteAdmittedReplace(context.Background(), request, gate)
			assertProtocolError(t, out, err, tc.status, "")
			if calls != 0 || f.store.prepares != before || f.mapper.calls != mapsBefore || reads.gets != 0 || reads.snapshots != 0 || len(f.store.resources) != 1 || out.Status != 0 || out.ETag != "" || out.Location != "" || out.ContentType != "" {
				t.Fatal("Group Replace preflight charged admission or crossed resource/command effects")
			}
		})
	}
	for _, service := range []*scim.GroupsService{nil, new(scim.GroupsService)} {
		out, err := admittedGroupReplaces(t, service).ExecuteAdmittedReplace(context.Background(), scim.Request{Operation: scim.GroupReplace}, func(context.Context) *scim.Error { t.Fatal("invalid service invoked gate"); return nil })
		assertProtocolError(t, out, err, 503, "")
	}
}

func TestGroupsAdmittedReplaceDenialsPreserveGroupWithoutEffects(t *testing.T) {
	for _, tc := range []struct {
		name   string
		deny   func(context.Context) *scim.Error
		status int
		retry  uint32
	}{
		{name: "policy", deny: func(context.Context) *scim.Error { return scim.NewError(403, "") }, status: 403},
		{name: "quota", deny: func(context.Context) *scim.Error { return scim.NewRateLimitedError(1250 * time.Millisecond) }, status: 429, retry: 2},
		{name: "unknown quota", deny: func(context.Context) *scim.Error { return scim.NewError(429, "") }, status: 503},
		{name: "zero quota", deny: func(context.Context) *scim.Error { return scim.NewRateLimitedError(0) }, status: 503},
		{name: "unavailable", deny: func(context.Context) *scim.Error { return scim.NewError(503, "") }, status: 503},
		{name: "unsupported", deny: func(context.Context) *scim.Error { return scim.NewError(404, "") }, status: 503},
		{name: "typed", deny: func(context.Context) *scim.Error { return scim.NewError(400, "invalidValue") }, status: 503},
		{name: "panic", deny: func(context.Context) *scim.Error { panic("private gate diagnostic") }, status: 503},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var reads *admittedGroupReadStore
			f := newGroupFixture(t, func(c *scim.GroupsConfig) { reads = &admittedGroupReadStore{GroupStore: c.Store}; c.Store = reads })
			created := f.call(t, scim.GroupCreate, "", "", groupBody("preserved", `,"externalId":"preserved-correlation"`))
			before, mapsBefore := f.store.prepares, f.mapper.calls
			calls := 0
			out, err := admittedGroupReplaces(t, f.service).ExecuteAdmittedReplace(context.Background(), admittedGroupReplaceRequest(t, created, groupBody("denied", "")), func(ctx context.Context) *scim.Error { calls++; return tc.deny(ctx) })
			denied := assertProtocolError(t, out, err, tc.status, "")
			if calls != 1 || denied.SCIMType() != "" || denied.RetryAfterSeconds() != tc.retry || f.store.prepares != before || f.mapper.calls != mapsBefore || reads.gets != 0 || reads.snapshots != 0 || out.Status != 0 || out.ETag != "" || out.Location != "" || out.ContentType != "" {
				t.Fatal("Group Replace denial lost redaction or reached resource/command effects")
			}
			read := f.call(t, scim.GroupGet, object(t, created.Body)["id"].(string), "", "")
			if read.ETag != created.ETag || !bytes.Equal(read.Body, created.Body) {
				t.Fatal("denied Group Replace changed the original representation")
			}
		})
	}
}

func TestGroupsAdmittedReplaceRetainsStoreMemberCASAndOutcomeAuthority(t *testing.T) {
	for _, scenario := range []string{"missing member", "foreign member", "wrong member type", "immutable member", "stale", "commit conflict", "unknown"} {
		t.Run(scenario, func(t *testing.T) {
			var writes *admittedGroupCreateStore
			f := newGroupFixture(t, func(c *scim.GroupsConfig) { writes = &admittedGroupCreateStore{GroupStore: c.Store}; c.Store = writes })
			f.addUser("old-member", "fixture-connection")
			created := f.call(t, scim.GroupCreate, "", "", groupBody("original", `,"members":[{"value":"old-member","display":"Original display"}]`))
			request := admittedGroupReplaceRequest(t, created, groupBody("replacement", ""))
			request.IdempotencyKey = "store-owned-replace"
			switch scenario {
			case "missing member", "foreign member":
				request.Body = []byte(groupBody("replacement", `,"members":[{"value":"new-member"}]`))
				if scenario == "foreign member" {
					f.addUser("new-member", "fixture-other-connection")
				}
			case "wrong member type":
				f.addUser("new-member", "fixture-connection")
				request.Body = []byte(groupBody("replacement", `,"members":[{"value":"new-member","type":"Group"}]`))
			case "immutable member":
				request.Body = []byte(groupBody("replacement", `,"members":[{"value":"old-member","display":"Changed display"}]`))
			case "stale":
				request.IfMatch = `"stale-version"`
			}
			f.store.conflict, f.store.unknown = scenario == "commit conflict", scenario == "unknown"
			writes.intents = nil
			writes.commits, writes.aborts = 0, 0
			mapsBefore := f.mapper.calls
			calls := 0
			for range 2 {
				out, err := admittedGroupReplaces(t, f.service).ExecuteAdmittedReplace(context.Background(), request, func(context.Context) *scim.Error { calls++; return nil })
				status, kind := 400, "invalidValue"
				if scenario == "immutable member" {
					kind = "mutability"
				} else if scenario == "stale" || scenario == "commit conflict" {
					status, kind = 412, ""
				} else if scenario == "unknown" {
					status, kind = 503, ""
				}
				assertProtocolError(t, out, err, status, kind)
			}
			wantCommits, wantAborts, wantMaps := 1, 1, 1
			if scenario == "stale" || scenario == "immutable member" {
				wantCommits, wantMaps = 0, 0
			} else if scenario == "unknown" {
				wantAborts = 0
			}
			if calls != 2 || len(writes.intents) != 2 || writes.commits != wantCommits || writes.aborts != wantAborts || f.mapper.calls != mapsBefore+wantMaps || len(f.store.resources) != 1 || scenario == "unknown" && f.store.lastOutcome != scim.WriteOutcomeUnknown {
				t.Fatal("Group Replace admission replaced Store member/CAS/replay/outcome authority")
			}
			read := f.call(t, scim.GroupGet, request.ResourceID, "", "")
			if read.ETag != created.ETag || !bytes.Equal(read.Body, created.Body) {
				t.Fatal("rejected or uncertain Group Replace changed the current Group")
			}
		})
	}
}

func TestGroupsAdmittedReplaceRejectsDescendantReentryEvenInvalidWrappers(t *testing.T) {
	for _, nested := range []string{"ordinary Group", "admitted Replace", "Group read", "Group Create", "foreign operation", "missing gate", "nil service", "uninitialized service", "sibling User"} {
		t.Run(nested, func(t *testing.T) {
			f := newGroupFixture(t, nil)
			users := newProtocolFixture(t)
			created := f.call(t, scim.GroupCreate, "", "", groupBody("original", ""))
			request := admittedGroupReplaceRequest(t, created, groupBody("replacement", ""))
			before, mapsBefore := f.store.prepares, f.mapper.calls
			calls := 0
			out, err := admittedGroupReplaces(t, f.service).ExecuteAdmittedReplace(context.Background(), request, func(ctx context.Context) *scim.Error {
				calls++
				child, cancel := context.WithCancel(ctx)
				defer cancel()
				var inner scim.Response
				var innerErr error
				gate := func(context.Context) *scim.Error { t.Fatal("nested gate executed"); return nil }
				switch nested {
				case "ordinary Group":
					inner, innerErr = f.service.Execute(child, request)
				case "admitted Replace":
					inner, innerErr = admittedGroupReplaces(t, f.service).ExecuteAdmittedReplace(child, request, gate)
				case "Group read":
					inner, innerErr = admittedGroups(t, f.service).ExecuteAdmittedRead(child, admittedGroupReadRequest(scim.GroupList, ""), gate)
				case "Group Create":
					inner, innerErr = admittedGroupCreates(t, f.service).ExecuteAdmittedCreate(child, admittedGroupCreateRequest("nested"), gate)
				case "foreign operation":
					request.Operation = scim.UserReplace
					inner, innerErr = admittedGroupReplaces(t, f.service).ExecuteAdmittedReplace(child, request, gate)
				case "missing gate":
					inner, innerErr = admittedGroupReplaces(t, f.service).ExecuteAdmittedReplace(child, request, nil)
				case "nil service":
					inner, innerErr = admittedGroupReplaces(t, nil).ExecuteAdmittedReplace(child, request, nil)
				case "uninitialized service":
					inner, innerErr = admittedGroupReplaces(t, new(scim.GroupsService)).ExecuteAdmittedReplace(child, request, nil)
				case "sibling User":
					inner, innerErr = users.service.Execute(child, admittedCreateRequest("nested-user"))
				}
				assertProtocolError(t, inner, innerErr, 503, "")
				return nil
			})
			assertProtocolError(t, out, err, 503, "")
			if calls != 1 || f.store.prepares != before || f.mapper.calls != mapsBefore || users.store.prepares != 0 || users.mapper.calls != 0 || len(f.store.resources) != 1 {
				t.Fatal("ignored nested denial escaped Group Replace invocation fence")
			}
		})
	}
}

func TestGroupsAdmittedReplaceRetainsOriginalAuthorityAndLateDisclosureFence(t *testing.T) {
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
			clock.policyCalls = 0
			clock.now = fixtureNow.Add(19 * time.Second)
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
			out, err := admittedGroupReplaces(t, f.service).ExecuteAdmittedReplace(ctx, admittedGroupReplaceRequest(t, created, groupBody("replacement", "")), func(gate context.Context) *scim.Error {
				calls++
				deadline, ok := gate.Deadline()
				if !ok || time.Until(deadline) > time.Second+100*time.Millisecond || clock.policyCalls != 1 {
					t.Fatal("Group Replace gate renewed authority or preceded operation authorization")
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
					t.Fatal("Group Replace disclosure fence rewrote a committed outcome")
				}
			}
			if calls != wantCalls || len(writes.intents) != wantWrites || writes.commits != wantWrites || f.mapper.calls != mapsBefore+wantWrites || len(f.store.resources) != 1 || out.Status != 0 || out.ETag != "" || out.Location != "" || out.ContentType != "" {
				t.Fatal("Group Replace authority/cancellation boundary leaked metadata or crossed the no-effect fence")
			}
		})
	}
}

func TestGroupsAdmittedReplaceRetainsEarlierDeadlinesAndCancellation(t *testing.T) {
	for _, scenario := range []string{"parent", "request", "already canceled"} {
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
			out, err := admittedGroupReplaces(t, f.service).ExecuteAdmittedReplace(ctx, admittedGroupReplaceRequest(t, created, groupBody("replacement", "")), func(gate context.Context) *scim.Error {
				calls++
				deadline, ok := gate.Deadline()
				if !ok || deadline.After(bound.Add(25*time.Millisecond)) {
					t.Fatal("Group Replace gate extended an earlier parent or request deadline")
				}
				return scim.NewError(403, "")
			})
			status, wantCalls := 403, 1
			if scenario == "already canceled" {
				status, wantCalls = 503, 0
			}
			assertProtocolError(t, out, err, status, "")
			if calls != wantCalls || f.store.prepares != before || f.mapper.calls != mapsBefore {
				t.Fatal("bounded or canceled Group Replace crossed command/mapping effects")
			}
		})
	}
}

func TestGroupsAdmittedReplacePreservesOrdinaryAndSiblingSelections(t *testing.T) {
	f := newGroupFixture(t, nil)
	created := f.call(t, scim.GroupCreate, "", "", groupBody("ordinary original", ""))
	request := admittedGroupReplaceRequest(t, created, groupBody("ordinary replacement", ""))
	request.IdempotencyKey = "ordinary-group-replace"
	ordinary, err := f.service.Execute(context.Background(), request)
	if err != nil || ordinary.Status != 200 {
		t.Fatal("ordinary Group Replace failed", err)
	}
	before, mapsBefore := f.store.prepares, f.mapper.calls
	denied, err := admittedGroupReplaces(t, f.service).ExecuteAdmittedReplace(context.Background(), request, func(context.Context) *scim.Error { return scim.NewError(403, "") })
	assertProtocolError(t, denied, err, 403, "")
	if f.store.prepares != before || f.mapper.calls != mapsBefore {
		t.Fatal("original Group Replace replay bypassed admission")
	}
	replay, err := admittedGroupReplaces(t, f.service).ExecuteAdmittedReplace(context.Background(), request, func(context.Context) *scim.Error { return nil })
	if err != nil || replay.ETag != ordinary.ETag || !bytes.Equal(replay.Body, ordinary.Body) || f.mapper.calls != mapsBefore {
		t.Fatal("Group Replace selection changed ordinary execution replay", err)
	}
	read, err := admittedGroups(t, f.service).ExecuteAdmittedRead(context.Background(), admittedGroupReadRequest(scim.GroupGet, request.ResourceID), func(context.Context) *scim.Error { return nil })
	if err != nil || read.ETag != ordinary.ETag || !bytes.Equal(read.Body, ordinary.Body) {
		t.Fatal("Group Replace changed admitted Group reads", err)
	}
	other, err := admittedGroupCreates(t, f.service).ExecuteAdmittedCreate(context.Background(), admittedGroupCreateRequest("separate create"), func(context.Context) *scim.Error { return nil })
	if err != nil || other.Status != 201 || len(f.store.resources) != 2 {
		t.Fatal("Group Replace changed admitted Group creation", err)
	}
}
