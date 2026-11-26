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
	scim "github.com/faustbrian/go-scim"
)

type admittedUsersPatcher interface {
	ExecuteAdmittedPatch(context.Context, scim.Request, func(context.Context) *scim.Error) (scim.Response, error)
}

func admittedPatches(t *testing.T, service *scim.UsersService) admittedUsersPatcher {
	t.Helper()
	selected, ok := any(service).(admittedUsersPatcher)
	if !ok {
		t.Fatal("UsersService has no explicit conditional admitted Patch selection")
	}
	return selected
}

func admittedPatchRequest(t *testing.T, created scim.Response, operations string) scim.Request {
	t.Helper()
	return scim.Request{Operation: scim.UserPatch, Credential: authentication.NewBearerCredential("fixture-connection"), ResourceID: object(t, created.Body)["id"].(string), IfMatch: created.ETag, ContentType: "application/scim+json", Body: []byte(patchBody(operations))}
}

func TestUsersAdmittedPatchRetainsWholePatchCanonicalCommandAndReplay(t *testing.T) {
	var writes *admittedCreateStore
	f := configuredProtocolFixture(t, func(c *scim.Config) {
		writes = &admittedCreateStore{Store: c.Store}
		c.Store = writes
	})
	created := f.call(t, scim.UserCreate, "", "", userBody("patch-original", `,"name":{"familyName":"Preserved"}`))
	request := admittedPatchRequest(t, created, `{"op":"replace","path":"userName","value":"patch-updated"},{"op":"add","path":"name.givenName","value":"Added"},{"op":"add","path":"emails","value":[{"value":"old@example.test","type":"work"}]},{"op":"replace","path":"emails[type eq \"work\"].value","value":"new@example.test"}`)
	request.IdempotencyKey = "existing-patch-key"
	writes.intents = nil
	writes.commits, writes.aborts = 0, 0
	mapsBefore := f.mapper.calls
	calls := 0
	gate := func(ctx context.Context) *scim.Error {
		calls++
		if boundedFixtureContext(ctx) != nil || len(writes.intents) != calls-1 {
			t.Fatal("Patch command admission preceded the once-per-attempt bounded gate")
		}
		return nil
	}
	patched, err := admittedPatches(t, f.service).ExecuteAdmittedPatch(context.Background(), request, gate)
	if err != nil || patched.Status != 200 || patched.ETag == created.ETag || patched.Location != created.Location || calls != 1 || writes.commits != 1 || writes.aborts != 0 || f.mapper.calls != mapsBefore+1 {
		t.Fatal("admitted Patch changed conditional write semantics", err)
	}
	doc := object(t, patched.Body)
	name := doc["name"].(map[string]any)
	emails := doc["emails"].([]any)
	if doc["userName"] != "patch-updated" || name["givenName"] != "Added" || name["familyName"] != "Preserved" || len(emails) != 1 || emails[0].(map[string]any)["value"] != "new@example.test" {
		t.Fatal("admission dropped or reordered part of the parsed Patch")
	}
	intent := writes.intents[0]
	var canonical struct {
		Operation scim.Operation
		ID        string
		IfMatch   scim.Version
		Body      map[string]any
	}
	if json.Unmarshal(intent.CanonicalRequest, &canonical) != nil || canonical.Operation != scim.UserPatch || canonical.ID != request.ResourceID || canonical.IfMatch != request.IfMatch || len(canonical.Body["Operations"].([]any)) != 4 || intent.CommandID == "" || intent.IdempotencyKey != request.IdempotencyKey || intent.Scope != intent.Connection.Scope {
		t.Fatal("Patch admission rewrote canonical intent or Store command scope")
	}
	replay, err := admittedPatches(t, f.service).ExecuteAdmittedPatch(context.Background(), request, gate)
	if err != nil || replay.Status != patched.Status || replay.ETag != patched.ETag || replay.Location != patched.Location || !bytes.Equal(replay.Body, patched.Body) || calls != 2 || writes.commits != 1 || f.mapper.calls != mapsBefore+1 || !bytes.Equal(intent.CanonicalRequest, writes.intents[1].CanonicalRequest) {
		t.Fatal("Patch replay re-evaluated stale If-Match or repeated protected effects", err)
	}
}

func TestUsersAdmittedPatchPreflightRejectsBeforeGateOrIO(t *testing.T) {
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
		{name: "missing body", change: func(r *scim.Request) { r.Body = nil }, status: 400},
		{name: "malformed JSON", change: func(r *scim.Request) { r.Body = []byte(`{"schemas":[`) }, status: 400},
		{name: "case alias", change: func(r *scim.Request) {
			r.Body = []byte(patchBody(`{"op":"add","OP":"replace","path":"displayName","value":"x"}`))
		}, status: 400},
		{name: "wrong schema", change: func(r *scim.Request) { r.Body = []byte(`{"schemas":["urn:unknown"],"Operations":[]}`) }, status: 400},
		{name: "empty operations", change: func(r *scim.Request) { r.Body = []byte(patchBody("")) }, status: 400},
		{name: "invalid verb", change: func(r *scim.Request) { r.Body = []byte(patchBody(`{"op":"delete","path":"displayName"}`)) }, status: 400},
		{name: "missing value", change: func(r *scim.Request) { r.Body = []byte(patchBody(`{"op":"replace","path":"displayName"}`)) }, status: 400},
		{name: "invalid path", change: func(r *scim.Request) { r.Body = []byte(patchBody(`{"op":"remove","path":"name.missing"}`)) }, status: 400},
		{name: "password path", change: func(r *scim.Request) {
			r.Body = []byte(patchBody(`{"op":"replace","path":"password","value":"private-value"}`))
		}, status: 400},
		{name: "pathless password", change: func(r *scim.Request) { r.Body = []byte(patchBody(`{"op":"add","value":{"password":"private-value"}}`)) }, status: 400},
		{name: "too many operations", change: func(r *scim.Request) {
			r.Body = []byte(patchBody(strings.TrimSuffix(strings.Repeat(`{"op":"replace","path":"displayName","value":"x"},`, scim.DefaultLimits().PatchOperations+1), ",")))
		}, status: 400},
		{name: "oversized path", change: func(r *scim.Request) {
			r.Body = []byte(patchBody(`{"op":"remove","path":"` + strings.Repeat("x", scim.DefaultLimits().PathBytes+1) + `"}`))
		}, status: 400},
		{name: "oversized string", change: func(r *scim.Request) {
			r.Body = []byte(patchBody(`{"op":"replace","path":"displayName","value":"` + strings.Repeat("x", scim.DefaultLimits().StringBytes+1) + `"}`))
		}, status: 400},
		{name: "oversized body", change: func(r *scim.Request) { r.Body = bytes.Repeat([]byte(" "), scim.DefaultLimits().BodyBytes+1) }, status: 413},
		{name: "invalid projection", change: func(r *scim.Request) { r.Query.Attributes = "password" }, status: 400},
		{name: "unsupported media", change: func(r *scim.Request) { r.ContentType = "application/json" }, status: 415},
		{name: "unsupported encoding", change: func(r *scim.Request) { r.ContentEncoding = "gzip" }, status: 415},
		{name: "invalid credential", change: func(r *scim.Request) { r.Credential = authentication.NewBearerCredential("unknown-fixture") }, status: 401},
		{name: "operation policy denial", policyDeny: true, status: 403},
		{name: "missing gate", nilGate: true, status: 503},
		{name: "Replace not selected", change: func(r *scim.Request) { r.Operation = scim.UserReplace }, status: 501},
		{name: "Create not selected", change: func(r *scim.Request) { r.Operation = scim.UserCreate }, status: 501},
		{name: "Get not selected", change: func(r *scim.Request) { r.Operation = scim.UserGet }, status: 501},
		{name: "Delete not selected", change: func(r *scim.Request) { r.Operation = scim.UserDelete }, status: 501},
		{name: "Group Patch not selected", change: func(r *scim.Request) { r.Operation = scim.GroupPatch }, status: 501},
		{name: "Bulk not selected", change: func(r *scim.Request) { r.Operation = scim.Bulk }, status: 501},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var reads *admittedReadStore
			f := configuredProtocolFixture(t, func(c *scim.Config) { reads = &admittedReadStore{Store: c.Store}; c.Store = reads })
			created := f.call(t, scim.UserCreate, "", "", userBody("patch-preflight", ""))
			request := admittedPatchRequest(t, created, `{"op":"replace","path":"displayName","value":"uncharged"}`)
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
			out, err := admittedPatches(t, f.service).ExecuteAdmittedPatch(context.Background(), request, gate)
			assertProtocolError(t, out, err, tc.status, "")
			if calls != 0 || f.store.prepares != before || f.mapper.calls != mapsBefore || reads.gets != 0 || reads.snapshots != 0 || len(f.store.resources) != 1 {
				t.Fatal("Patch preflight charged admission or reached resource/command effects")
			}
		})
	}
	for _, service := range []*scim.UsersService{nil, new(scim.UsersService)} {
		out, err := admittedPatches(t, service).ExecuteAdmittedPatch(context.Background(), scim.Request{Operation: scim.UserPatch}, func(context.Context) *scim.Error { t.Fatal("invalid service invoked gate"); return nil })
		assertProtocolError(t, out, err, 503, "")
	}
}

func TestUsersAdmittedPatchDenialPrecedesResourceAndCommandIO(t *testing.T) {
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
			created := f.call(t, scim.UserCreate, "", "", userBody("patch-denied", ""))
			before, mapsBefore := f.store.prepares, f.mapper.calls
			calls := 0
			out, err := admittedPatches(t, f.service).ExecuteAdmittedPatch(context.Background(), admittedPatchRequest(t, created, `{"op":"replace","path":"displayName","value":"denied"}`), func(ctx context.Context) *scim.Error { calls++; return tc.deny(ctx) })
			denied := assertProtocolError(t, out, err, tc.status, "")
			if calls != 1 || denied.SCIMType() != "" || denied.RetryAfterSeconds() != tc.retry || f.store.prepares != before || f.mapper.calls != mapsBefore || reads.gets != 0 || reads.snapshots != 0 {
				t.Fatal("Patch gate denial escaped redaction or preceded resource/command effects")
			}
			read := f.call(t, scim.UserGet, object(t, created.Body)["id"].(string), "", "")
			if !bytes.Equal(read.Body, created.Body) || read.ETag != created.ETag {
				t.Fatal("denied Patch changed the resource")
			}
		})
	}
}

func TestUsersAdmittedPatchKeepsStoreCASRollbackNoopAndUnknownOutcomes(t *testing.T) {
	for _, scenario := range []string{"stale", "commit conflict", "rollback", "noop", "unknown"} {
		t.Run(scenario, func(t *testing.T) {
			var writes *admittedCreateStore
			f := configuredProtocolFixture(t, func(c *scim.Config) { writes = &admittedCreateStore{Store: c.Store}; c.Store = writes })
			created := f.call(t, scim.UserCreate, "", "", userBody("patch-store-owned", ""))
			operations := `{"op":"replace","path":"displayName","value":"changed"}`
			if scenario == "rollback" {
				operations += `,{"op":"remove","path":"userName"}`
			} else if scenario == "noop" {
				operations = `{"op":"replace","path":"userName","value":"patch-store-owned"}`
			}
			request := admittedPatchRequest(t, created, operations)
			request.IdempotencyKey = "patch-store-replay"
			if scenario == "stale" {
				request.IfMatch = `"stale-version"`
			}
			f.store.conflict = scenario == "commit conflict"
			f.store.unknown = scenario == "unknown"
			writes.commits, writes.aborts = 0, 0
			calls := 0
			for range 2 {
				out, err := admittedPatches(t, f.service).ExecuteAdmittedPatch(context.Background(), request, func(context.Context) *scim.Error { calls++; return nil })
				switch scenario {
				case "noop":
					if err != nil || out.Status != 200 || out.ETag != created.ETag || !bytes.Equal(out.Body, created.Body) {
						t.Fatal("admitted no-op Patch changed original metadata or replay", err)
					}
				case "stale", "commit conflict":
					assertProtocolError(t, out, err, 412, "")
				case "rollback":
					assertProtocolError(t, out, err, 400, "mutability")
				case "unknown":
					assertProtocolError(t, out, err, 503, "")
				}
			}
			wantCommits, wantAborts := 0, 1
			if scenario == "noop" || scenario == "unknown" || scenario == "commit conflict" {
				wantCommits = 1
			}
			if scenario == "noop" || scenario == "unknown" {
				wantAborts = 0
			}
			if calls != 2 || writes.commits != wantCommits || writes.aborts != wantAborts || len(f.store.resources) != 1 {
				t.Fatal("admission changed Store CAS, failure replay or uncertain outcome ownership")
			}
			read := f.call(t, scim.UserGet, request.ResourceID, "", "")
			if read.ETag != created.ETag || !bytes.Equal(read.Body, created.Body) || scenario == "unknown" && f.store.lastOutcome != scim.WriteOutcomeUnknown {
				t.Fatal("failed, no-op or unknown Patch changed the resource or durable outcome")
			}
		})
	}
}

func TestUsersAdmittedPatchConsumesOriginalAuthorityAndWithholdsLateCommit(t *testing.T) {
	for _, scenario := range []string{"expires in gate", "late commit"} {
		t.Run(scenario, func(t *testing.T) {
			f, clock := newFreshnessFixture(t)
			created := f.call(t, scim.UserCreate, "", "", userBody("patch-authority", ""))
			clock.visits = make(map[string]int)
			clock.policyCalls = 0
			clock.now = fixtureNow.Add(19 * time.Second)
			clock.advanceAfterCommit = scenario == "late commit"
			calls := 0
			request := admittedPatchRequest(t, created, `{"op":"replace","path":"displayName","value":"late"}`)
			out, err := admittedPatches(t, f.service).ExecuteAdmittedPatch(context.Background(), request, func(ctx context.Context) *scim.Error {
				calls++
				deadline, bounded := ctx.Deadline()
				if !bounded || time.Until(deadline) > time.Second+100*time.Millisecond || clock.policyCalls != 1 {
					t.Fatal("Patch admission preceded authorization or renewed original authority")
				}
				if scenario == "expires in gate" {
					clock.now = clock.connection.AuthorityValidUntil
					return scim.NewRateLimitedError(time.Second)
				}
				return nil
			})
			assertProtocolError(t, out, err, 503, "")
			if calls != 1 {
				t.Fatal("Patch admission did not run once")
			}
			if scenario == "expires in gate" && (clock.visits["prepare"] != 0 || clock.visits["map"] != 0 || clock.visits["commit"] != 0) {
				t.Fatal("expired Patch gate reached resource or command effects")
			}
			if scenario == "late commit" && (clock.visits["commit"] != 1 || f.store.lastOutcome != scim.WriteOutcomeCommitted) {
				t.Fatal("late Patch disclosure changed the Store's committed outcome")
			}
		})
	}
}

func TestUsersAdmittedPatchCancellationTimeoutAndReentryPrecedeReceipt(t *testing.T) {
	for _, scenario := range []string{"already canceled", "cancel in gate", "timeout", "reentry"} {
		t.Run(scenario, func(t *testing.T) {
			f := newProtocolFixture(t)
			created := f.call(t, scim.UserCreate, "", "", userBody("patch-context", ""))
			request := admittedPatchRequest(t, created, `{"op":"replace","path":"displayName","value":"blocked"}`)
			before, mapsBefore := f.store.prepares, f.mapper.calls
			ctx, cancel := context.WithTimeout(context.Background(), 25*time.Millisecond)
			defer cancel()
			if scenario == "already canceled" {
				cancel()
			}
			parentDeadline, _ := ctx.Deadline()
			calls := 0
			out, err := admittedPatches(t, f.service).ExecuteAdmittedPatch(ctx, request, func(gateCtx context.Context) *scim.Error {
				calls++
				deadline, bounded := gateCtx.Deadline()
				if !bounded || deadline.After(parentDeadline) {
					t.Fatal("Patch gate extended the parent budget")
				}
				switch scenario {
				case "cancel in gate":
					cancel()
				case "timeout":
					<-gateCtx.Done()
				case "reentry":
					nestedCtx, nestedCancel := context.WithCancel(gateCtx)
					defer nestedCancel()
					nested, nestedErr := f.service.Execute(nestedCtx, request)
					assertProtocolError(t, nested, nestedErr, 503, "")
				}
				return nil
			})
			assertProtocolError(t, out, err, 503, "")
			wantCalls := 1
			if scenario == "already canceled" {
				wantCalls = 0
			}
			if calls != wantCalls || f.store.prepares != before || f.mapper.calls != mapsBefore || len(f.store.resources) != 1 {
				t.Fatal("canceled, timed-out or reentrant Patch reached resource/command effects")
			}
		})
	}
}

func TestUsersAdmittedPatchPreservesOrdinaryExecutionAndRequiresGateForReplay(t *testing.T) {
	f := newProtocolFixture(t)
	created := f.call(t, scim.UserCreate, "", "", userBody("patch-ordinary", ""))
	request := admittedPatchRequest(t, created, `{"op":"replace","path":"displayName","value":"ordinary"}`)
	request.IdempotencyKey = "ordinary-patch-key"
	ordinary, err := f.service.Execute(context.Background(), request)
	if err != nil || ordinary.Status != 200 {
		t.Fatal("ordinary Patch failed", err)
	}
	before := f.store.prepares
	denied, err := admittedPatches(t, f.service).ExecuteAdmittedPatch(context.Background(), request, func(context.Context) *scim.Error { return scim.NewError(403, "") })
	assertProtocolError(t, denied, err, 403, "")
	if f.store.prepares != before {
		t.Fatal("Patch replay bypassed the gate")
	}
	replay, err := admittedPatches(t, f.service).ExecuteAdmittedPatch(context.Background(), request, func(context.Context) *scim.Error { return nil })
	if err != nil || replay.Status != ordinary.Status || replay.ETag != ordinary.ETag || !bytes.Equal(replay.Body, ordinary.Body) {
		t.Fatal("admitted Patch changed ordinary canonical replay", err)
	}
}
