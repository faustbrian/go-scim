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

type admittedUsersReplacer interface {
	ExecuteAdmittedReplace(context.Context, scim.Request, func(context.Context) *scim.Error) (scim.Response, error)
}

func admittedReplaces(t *testing.T, service *scim.UsersService) admittedUsersReplacer {
	t.Helper()
	selected, ok := any(service).(admittedUsersReplacer)
	if !ok {
		t.Fatal("UsersService has no explicit conditional admitted Replace selection")
	}
	return selected
}

func admittedReplaceRequest(t *testing.T, created scim.Response, body string) scim.Request {
	t.Helper()
	return scim.Request{Operation: scim.UserReplace, Credential: authentication.NewBearerCredential("fixture-connection"), ResourceID: object(t, created.Body)["id"].(string), IfMatch: created.ETag, ContentType: "application/scim+json", Body: []byte(body)}
}

func TestUsersAdmittedReplaceRetainsFullReplacementOriginalCommandAndReplay(t *testing.T) {
	command, err := identity.NewCommandID()
	if err != nil {
		t.Fatal(err)
	}
	var writes *admittedCreateStore
	var owner *ownerCommandStore
	f := configuredProtocolFixture(t, func(c *scim.Config) {
		owner = &ownerCommandStore{Store: c.Store, chosen: command}
		writes = &admittedCreateStore{Store: owner}
		c.Store = writes
	})
	created := f.call(t, scim.UserCreate, "", "", userBody("replace-original", `,"externalId":"old-correlation","displayName":"Omitted display","name":{"familyName":"Omitted name"},"emails":[{"value":"old@example.test"}]`))
	request := admittedReplaceRequest(t, created, userBody("replace-updated", `,"active":true`))
	request.IdempotencyKey = "original-replace-key"
	writes.intents = nil
	writes.commits, writes.aborts = 0, 0
	mapsBefore := f.mapper.calls
	calls := 0
	gate := func(ctx context.Context) *scim.Error {
		calls++
		if boundedFixtureContext(ctx) != nil || len(writes.intents) != calls-1 {
			t.Fatal("Replace command admission preceded the once-per-attempt bounded gate")
		}
		return nil
	}
	replaced, err := admittedReplaces(t, f.service).ExecuteAdmittedReplace(context.Background(), request, gate)
	if err != nil || replaced.Status != 200 || replaced.ETag == created.ETag || replaced.Location != created.Location || calls != 1 || writes.commits != 1 || writes.aborts != 0 || owner.proposed == command || owner.committed != command || f.mapper.calls != mapsBefore+1 {
		t.Fatal("admitted Replace changed conditional Store write or original command ownership", err)
	}
	doc := object(t, replaced.Body)
	if doc["userName"] != "replace-updated" || doc["active"] != true || doc["id"] != request.ResourceID {
		t.Fatal("Replace lost the complete replacement or original target")
	}
	for _, omitted := range []string{"externalId", "displayName", "name", "emails"} {
		if _, exists := doc[omitted]; exists {
			t.Fatalf("Replace retained omitted writable field %s as though it were PATCH", omitted)
		}
	}
	intent := writes.intents[0]
	var canonical struct {
		Operation scim.Operation
		ID        string
		IfMatch   scim.Version
		Body      map[string]any
	}
	if json.Unmarshal(intent.CanonicalRequest, &canonical) != nil || canonical.Operation != scim.UserReplace || canonical.ID != request.ResourceID || canonical.IfMatch != request.IfMatch || canonical.Body["userName"] != "replace-updated" || canonical.Body["active"] != true || intent.IdempotencyKey != request.IdempotencyKey || intent.Scope != intent.Connection.Scope {
		t.Fatal("Replace admission rewrote canonical input, precondition or command scope")
	}
	request.Body = []byte(`{ "active":true, "userName":"replace-updated", "schemas":["` + userURN + `"] }`)
	replay, err := admittedReplaces(t, f.service).ExecuteAdmittedReplace(context.Background(), request, gate)
	if err != nil || replay.Status != replaced.Status || replay.ETag != replaced.ETag || replay.Location != replaced.Location || !bytes.Equal(replay.Body, replaced.Body) || calls != 2 || writes.commits != 1 || f.mapper.calls != mapsBefore+1 || !bytes.Equal(intent.CanonicalRequest, writes.intents[1].CanonicalRequest) {
		t.Fatal("Replace replay rechecked stale original If-Match or repeated mapping/commit", err)
	}
}

func TestUsersAdmittedReplacePreflightRejectsBeforeGateOrResourceIO(t *testing.T) {
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
		{name: "missing representation", change: func(r *scim.Request) { r.Body = nil }, status: 400},
		{name: "malformed JSON", change: func(r *scim.Request) { r.Body = []byte(`{"schemas":[`) }, status: 400},
		{name: "duplicate field", change: func(r *scim.Request) { r.Body = []byte(userBody("first", `,"userName":"second"`)) }, status: 400},
		{name: "case alias", change: func(r *scim.Request) { r.Body = []byte(userBody("first", `,"USERNAME":"second"`)) }, status: 400},
		{name: "missing required username", change: func(r *scim.Request) { r.Body = []byte(`{"schemas":["` + userURN + `"],"displayName":"no username"}`) }, status: 400},
		{name: "unknown schema", change: func(r *scim.Request) { r.Body = []byte(`{"schemas":["urn:unknown"],"userName":"unknown"}`) }, status: 400},
		{name: "password representation", change: func(r *scim.Request) { r.Body = []byte(userBody("private", `,"password":"private-value"`)) }, status: 400},
		{name: "client generated id", change: func(r *scim.Request) { r.Body = []byte(userBody("client-id", `,"id":"client-supplied"`)) }, status: 400},
		{name: "client generated metadata", change: func(r *scim.Request) {
			r.Body = []byte(userBody("client-meta", `,"meta":{"version":"client-supplied"}`))
		}, status: 400},
		{name: "invalid scalar", change: func(r *scim.Request) { r.Body = []byte(userBody("invalid", `,"active":"not-a-boolean"`)) }, status: 400},
		{name: "oversized string", change: func(r *scim.Request) {
			r.Body = []byte(userBody(strings.Repeat("x", scim.DefaultLimits().StringBytes+1), ""))
		}, status: 400},
		{name: "oversized body", change: func(r *scim.Request) { r.Body = bytes.Repeat([]byte(" "), scim.DefaultLimits().BodyBytes+1) }, status: 413},
		{name: "invalid projection", change: func(r *scim.Request) { r.Query.Attributes = "password" }, status: 400},
		{name: "unsupported media", change: func(r *scim.Request) { r.ContentType = "application/json" }, status: 415},
		{name: "unsupported encoding", change: func(r *scim.Request) { r.ContentEncoding = "gzip" }, status: 415},
		{name: "unknown bearer", change: func(r *scim.Request) { r.Credential = authentication.NewBearerCredential("unknown-fixture") }, status: 401},
		{name: "expired bearer", change: func(r *scim.Request) { r.Credential = authentication.NewBearerCredential("expired") }, status: 401},
		{name: "unowned bearer", change: func(r *scim.Request) { r.Credential = authentication.NewBearerCredential("unowned") }, status: 401},
		{name: "operation denial", policyDeny: true, status: 403},
		{name: "missing gate", nilGate: true, status: 503},
		{name: "Create not selected", change: func(r *scim.Request) { r.Operation = scim.UserCreate }, status: 501},
		{name: "Get not selected", change: func(r *scim.Request) { r.Operation = scim.UserGet }, status: 501},
		{name: "Patch not selected", change: func(r *scim.Request) { r.Operation = scim.UserPatch }, status: 501},
		{name: "Delete not selected", change: func(r *scim.Request) { r.Operation = scim.UserDelete }, status: 501},
		{name: "Group Replace not selected", change: func(r *scim.Request) { r.Operation = scim.GroupReplace }, status: 501},
		{name: "Bulk not selected", change: func(r *scim.Request) { r.Operation = scim.Bulk }, status: 501},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var reads *admittedReadStore
			f := configuredProtocolFixture(t, func(c *scim.Config) { reads = &admittedReadStore{Store: c.Store}; c.Store = reads })
			created := f.call(t, scim.UserCreate, "", "", userBody("replace-preflight", ""))
			request := admittedReplaceRequest(t, created, userBody("replace-unadmitted", ""))
			if tc.change != nil {
				tc.change(&request)
			}
			if tc.policyDeny {
				f.authorizer.err = errors.New("private policy diagnostic")
			}
			before, mapsBefore := f.store.prepares, f.mapper.calls
			calls := 0
			var gate func(context.Context) *scim.Error
			if !tc.nilGate {
				gate = func(context.Context) *scim.Error { calls++; return nil }
			}
			out, err := admittedReplaces(t, f.service).ExecuteAdmittedReplace(context.Background(), request, gate)
			assertProtocolError(t, out, err, tc.status, "")
			if calls != 0 || f.store.prepares != before || f.mapper.calls != mapsBefore || reads.gets != 0 || reads.snapshots != 0 || len(f.store.resources) != 1 {
				t.Fatal("Replace preflight charged admission or crossed resource/command effects")
			}
		})
	}
	for _, service := range []*scim.UsersService{nil, new(scim.UsersService)} {
		out, err := admittedReplaces(t, service).ExecuteAdmittedReplace(context.Background(), scim.Request{Operation: scim.UserReplace}, func(context.Context) *scim.Error { t.Fatal("invalid service invoked gate"); return nil })
		assertProtocolError(t, out, err, 503, "")
	}
}

func TestUsersAdmittedReplaceGateDenialsPreserveUserWithoutResourceOrCommandIO(t *testing.T) {
	for _, tc := range []struct {
		name   string
		deny   func(context.Context) *scim.Error
		status int
		retry  uint32
	}{
		{name: "quota", deny: func(context.Context) *scim.Error { return scim.NewRateLimitedError(1250 * time.Millisecond) }, status: 429, retry: 2},
		{name: "unknown quota wait", deny: func(context.Context) *scim.Error { return scim.NewError(429, "") }, status: 503},
		{name: "policy", deny: func(context.Context) *scim.Error { return scim.NewError(403, "") }, status: 403},
		{name: "unavailable", deny: func(context.Context) *scim.Error { return scim.NewError(503, "") }, status: 503},
		{name: "unsupported denial", deny: func(context.Context) *scim.Error { return scim.NewError(404, "") }, status: 503},
		{name: "typed denial", deny: func(context.Context) *scim.Error { return scim.NewError(400, "invalidValue") }, status: 503},
		{name: "panic", deny: func(context.Context) *scim.Error { panic("private gate diagnostic") }, status: 503},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var reads *admittedReadStore
			f := configuredProtocolFixture(t, func(c *scim.Config) { reads = &admittedReadStore{Store: c.Store}; c.Store = reads })
			created := f.call(t, scim.UserCreate, "", "", userBody("replace-denied", `,"displayName":"Preserve on denial"`))
			before, mapsBefore := f.store.prepares, f.mapper.calls
			calls := 0
			out, err := admittedReplaces(t, f.service).ExecuteAdmittedReplace(context.Background(), admittedReplaceRequest(t, created, userBody("replace-denied-new", "")), func(ctx context.Context) *scim.Error { calls++; return tc.deny(ctx) })
			denied := assertProtocolError(t, out, err, tc.status, "")
			if calls != 1 || denied.SCIMType() != "" || denied.RetryAfterSeconds() != tc.retry || f.store.prepares != before || f.mapper.calls != mapsBefore || reads.gets != 0 || reads.snapshots != 0 {
				t.Fatal("Replace denial escaped redaction or crossed resource/command effects")
			}
			read := f.call(t, scim.UserGet, object(t, created.Body)["id"].(string), "", "")
			if read.ETag != created.ETag || !bytes.Equal(read.Body, created.Body) {
				t.Fatal("denied Replace removed or changed the existing User representation")
			}
		})
	}
}

func TestUsersAdmittedReplaceKeepsStoreCASAndUnknownOutcomeOwnership(t *testing.T) {
	for _, scenario := range []string{"stale", "commit conflict", "unknown"} {
		t.Run(scenario, func(t *testing.T) {
			var writes *admittedCreateStore
			f := configuredProtocolFixture(t, func(c *scim.Config) { writes = &admittedCreateStore{Store: c.Store}; c.Store = writes })
			created := f.call(t, scim.UserCreate, "", "", userBody("replace-store-original", ""))
			request := admittedReplaceRequest(t, created, userBody("replace-store-updated", ""))
			request.IdempotencyKey = "replace-original-replay"
			if scenario == "stale" {
				request.IfMatch = `"stale-version"`
			}
			f.store.conflict = scenario == "commit conflict"
			f.store.unknown = scenario == "unknown"
			writes.commits, writes.aborts = 0, 0
			calls := 0
			for range 2 {
				out, err := admittedReplaces(t, f.service).ExecuteAdmittedReplace(context.Background(), request, func(context.Context) *scim.Error { calls++; return nil })
				status := 412
				if scenario == "unknown" {
					status = 503
				}
				assertProtocolError(t, out, err, status, "")
			}
			wantCommits, wantAborts := 1, 1
			if scenario == "stale" {
				wantCommits = 0
			} else if scenario == "unknown" {
				wantAborts = 0
			}
			if calls != 2 || writes.commits != wantCommits || writes.aborts != wantAborts || len(f.store.resources) != 1 || scenario == "unknown" && f.store.lastOutcome != scim.WriteOutcomeUnknown {
				t.Fatal("Replace admission changed stateful CAS, original failure replay or unknown outcome ownership")
			}
			read := f.call(t, scim.UserGet, request.ResourceID, "", "")
			if read.ETag != created.ETag || !bytes.Equal(read.Body, created.Body) {
				t.Fatal("rejected or uncertain Replace changed the current resource")
			}
		})
	}
}

func TestUsersAdmittedReplaceRetainsOriginalAuthorityAndLateDisclosureFence(t *testing.T) {
	for _, scenario := range []string{"expires before gate", "expires in gate", "late commit"} {
		t.Run(scenario, func(t *testing.T) {
			f, clock := newFreshnessFixture(t)
			created := f.call(t, scim.UserCreate, "", "", userBody("replace-authority", ""))
			clock.visits = make(map[string]int)
			clock.policyCalls = 0
			clock.now = fixtureNow.Add(19 * time.Second)
			if scenario == "expires before gate" {
				clock.advanceAt, clock.advanceTo = "authorize", clock.connection.AuthorityValidUntil
			}
			clock.advanceAfterCommit = scenario == "late commit"
			calls := 0
			out, err := admittedReplaces(t, f.service).ExecuteAdmittedReplace(context.Background(), admittedReplaceRequest(t, created, userBody("replace-authority-updated", "")), func(ctx context.Context) *scim.Error {
				calls++
				deadline, bounded := ctx.Deadline()
				if !bounded || time.Until(deadline) > time.Second+100*time.Millisecond || clock.policyCalls != 1 {
					t.Fatal("Replace gate preceded operation authorization or renewed original authority")
				}
				if scenario == "expires in gate" {
					clock.now = clock.connection.AuthorityValidUntil
					return scim.NewRateLimitedError(time.Second)
				}
				return nil
			})
			assertProtocolError(t, out, err, 503, "")
			wantCalls := 1
			if scenario == "expires before gate" {
				wantCalls = 0
			}
			if calls != wantCalls {
				t.Fatal("Replace gate charged expired authority or did not run once")
			}
			if scenario != "late commit" && (clock.visits["prepare"] != 0 || clock.visits["map"] != 0 || clock.visits["commit"] != 0) {
				t.Fatal("expired Replace authority reached resource/command effects")
			}
			if scenario == "late commit" && (clock.visits["commit"] != 1 || f.store.lastOutcome != scim.WriteOutcomeCommitted) {
				t.Fatal("late Replace disclosure changed Store's committed outcome")
			}
		})
	}
}

func TestUsersAdmittedReplaceCancellationAndDescendantReentryPrecedeEffects(t *testing.T) {
	for _, scenario := range []string{"already canceled", "cancel in gate", "reentry"} {
		t.Run(scenario, func(t *testing.T) {
			f := newProtocolFixture(t)
			created := f.call(t, scim.UserCreate, "", "", userBody("replace-context", ""))
			request := admittedReplaceRequest(t, created, userBody("replace-context-updated", ""))
			before, mapsBefore := f.store.prepares, f.mapper.calls
			ctx, cancel := context.WithTimeout(context.Background(), 150*time.Millisecond)
			defer cancel()
			if scenario == "already canceled" {
				cancel()
			}
			parentDeadline, _ := ctx.Deadline()
			calls := 0
			out, err := admittedReplaces(t, f.service).ExecuteAdmittedReplace(ctx, request, func(gateCtx context.Context) *scim.Error {
				calls++
				deadline, bounded := gateCtx.Deadline()
				if !bounded || deadline.After(parentDeadline) {
					t.Fatal("Replace gate extended earlier parent budget")
				}
				if scenario == "cancel in gate" {
					cancel()
				} else {
					child, childCancel := context.WithCancel(gateCtx)
					defer childCancel()
					nested, nestedErr := f.service.Execute(child, request)
					assertProtocolError(t, nested, nestedErr, 503, "")
				}
				return nil
			})
			assertProtocolError(t, out, err, 503, "")
			wantCalls := 1
			if scenario == "already canceled" {
				wantCalls = 0
			}
			if calls != wantCalls || f.store.prepares != before || f.mapper.calls != mapsBefore {
				t.Fatal("canceled or reentrant Replace admission reached resource/command effects")
			}
		})
	}
}

func TestUsersAdmittedReplacePreservesOrdinaryExecutionAndGatesOriginalReplay(t *testing.T) {
	f := newProtocolFixture(t)
	created := f.call(t, scim.UserCreate, "", "", userBody("replace-ordinary-original", ""))
	request := admittedReplaceRequest(t, created, userBody("replace-ordinary-updated", ""))
	request.IdempotencyKey = "ordinary-replace-key"
	ordinary, err := f.service.Execute(context.Background(), request)
	if err != nil || ordinary.Status != 200 {
		t.Fatal("ordinary Replace failed", err)
	}
	before, mapsBefore := f.store.prepares, f.mapper.calls
	denied, err := admittedReplaces(t, f.service).ExecuteAdmittedReplace(context.Background(), request, func(context.Context) *scim.Error { return scim.NewError(403, "") })
	assertProtocolError(t, denied, err, 403, "")
	if f.store.prepares != before || f.mapper.calls != mapsBefore {
		t.Fatal("original Replace replay bypassed its admission gate")
	}
	replay, err := admittedReplaces(t, f.service).ExecuteAdmittedReplace(context.Background(), request, func(context.Context) *scim.Error { return nil })
	if err != nil || replay.Status != ordinary.Status || replay.ETag != ordinary.ETag || !bytes.Equal(replay.Body, ordinary.Body) || f.mapper.calls != mapsBefore {
		t.Fatal("admitted Replace changed ordinary command replay or repeated mapping", err)
	}
}
