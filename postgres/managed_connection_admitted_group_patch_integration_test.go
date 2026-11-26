//go:build integration

package scimpostgres

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	authentication "github.com/faustbrian/go-authentication/v2"
	"github.com/faustbrian/go-authorization/v3"
	identity "github.com/faustbrian/go-identity"
	scim "github.com/faustbrian/go-scim"
)

type managedAdmittedGroupPatcher interface {
	ExecuteManagedAdmittedGroupPatch(context.Context, identity.TenantID, scim.Request, int, scim.ProtocolAdmission) (scim.Response, error)
}

func managedGroupPatcher(t *testing.T, service *ManagedConnectionService) managedAdmittedGroupPatcher {
	t.Helper()
	selected, ok := any(service).(managedAdmittedGroupPatcher)
	if !ok {
		t.Fatal("managed connection service has no explicit admitted conditional Group Patch selection")
	}
	return selected
}

func managedGroupPatchBody(operations string) []byte {
	return []byte(`{"schemas":["urn:ietf:params:scim:api:messages:2.0:PatchOp"],"Operations":[` + operations + `]}`)
}

func assertManagedGroupPatchClient(t *testing.T, f *managedConnectionAdminFixture, ctx context.Context, client scim.ProtocolClient) {
	t.Helper()
	deadline, bounded := ctx.Deadline()
	if ctx.Err() != nil || !bounded || !deadline.After(time.Now()) || time.Until(deadline) > f.config.MaximumDuration || client.ID != f.config.ActorID || client.TenantID != f.tenant {
		t.Fatal("Group Patch gate lost the configured service-account client, exact tenant or original bounded context")
	}
}

func TestManagedConnectionAdmittedGroupPatchDenialsPrecedeNativeEffects(t *testing.T) {
	f, service := managedGroupCreateFixture(t)
	selected := managedGroupPatcher(t, service)
	connection := managedGroupReplaceConnection(t, f, service, "group-patch-denials")
	_, created := managedGroupReplaceSeed(t, f, service, connection.Bearer, "group-patch-denials-seed", `{"schemas":["urn:ietf:params:scim:schemas:core:2.0:Group"],"displayName":"Original"}`)
	request := scim.Request{Operation: scim.GroupPatch, Credential: connection.Bearer, ResourceID: groupID(t, created), IfMatch: created.ETag, ContentType: "application/scim+json", Body: managedGroupPatchBody(`{"op":"replace","path":"displayName","value":"Patched"}`)}
	before := managedGroupCreateState(t, f)
	assertUnchanged := func(t *testing.T) {
		t.Helper()
		if managedGroupCreateState(t, f) != before {
			t.Fatal("unadmitted Group Patch changed resources, commands, request mappings, audit or outbox")
		}
	}
	t.Run("ordinary managed provisioning stays closed", func(t *testing.T) {
		out, err := service.ExecuteManagedProvisioning(f.ctx, f.tenant, request)
		assertManagedReadDenial(t, out, err, 501)
		assertUnchanged(t)
	})
	for _, tc := range []struct {
		name     string
		change   func(*scim.Request)
		tenant   identity.TenantID
		maximum  int
		nilGate  bool
		policy   bool
		canceled bool
		status   int
	}{
		{name: "unissued bearer", change: func(r *scim.Request) {
			r.Credential = authentication.NewBearerCredential("not-an-issued-managed-bearer")
		}, status: 401},
		{name: "foreign tenant", tenant: "AAAAAAAAAAAAAAAAAAAAAQ", status: 401},
		{name: "native authorization", policy: true, status: 403},
		{name: "missing gate", nilGate: true, status: 503},
		{name: "canceled parent", canceled: true, status: 503},
		{name: "negative ceiling", maximum: -1, status: 503},
		{name: "oversized ceiling", maximum: scim.DefaultGroupMembers + 1, status: 503},
		{name: "missing target", change: func(r *scim.Request) { r.ResourceID = "" }, status: 404},
		{name: "unsafe target", change: func(r *scim.Request) { r.ResourceID = "other/group" }, status: 404},
		{name: "missing If-Match", change: func(r *scim.Request) { r.IfMatch = "" }, status: 428},
		{name: "weak If-Match", change: func(r *scim.Request) { r.IfMatch = `W/"weak"` }, status: 400},
		{name: "wildcard If-Match", change: func(r *scim.Request) { r.IfMatch = "*" }, status: 400},
		{name: "multiple If-Match", change: func(r *scim.Request) { r.IfMatch = `"one","two"` }, status: 400},
		{name: "caller key", change: func(r *scim.Request) { r.IdempotencyKey = "caller-selected-group-patch" }, status: 400},
		{name: "malformed JSON", change: func(r *scim.Request) { r.Body = []byte(`{"schemas":[`) }, status: 400},
		{name: "empty PatchOp", change: func(r *scim.Request) { r.Body = managedGroupPatchBody("") }, status: 400},
		{name: "case alias", change: func(r *scim.Request) {
			r.Body = managedGroupPatchBody(`{"op":"add","OP":"replace","path":"displayName","value":"x"}`)
		}, status: 400},
		{name: "User path", change: func(r *scim.Request) { r.Body = managedGroupPatchBody(`{"op":"remove","path":"userName"}`) }, status: 400},
		{name: "unknown member child", change: func(r *scim.Request) {
			r.Body = managedGroupPatchBody(`{"op":"add","path":"members","value":[{"value":"member","unknown":"x"}]}`)
		}, status: 400},
		{name: "invalid projection", change: func(r *scim.Request) { r.Query.Attributes = "userName" }, status: 400},
		{name: "User Patch", change: func(r *scim.Request) { r.Operation = scim.UserPatch }, status: 501},
		{name: "Group Create", change: func(r *scim.Request) { r.Operation = scim.GroupCreate }, status: 501},
		{name: "Group Get", change: func(r *scim.Request) { r.Operation = scim.GroupGet }, status: 501},
		{name: "Group List", change: func(r *scim.Request) { r.Operation = scim.GroupList }, status: 501},
		{name: "Group Search", change: func(r *scim.Request) { r.Operation = scim.GroupSearch }, status: 501},
		{name: "Group Replace", change: func(r *scim.Request) { r.Operation = scim.GroupReplace }, status: 501},
		{name: "Group Delete", change: func(r *scim.Request) { r.Operation = scim.GroupDelete }, status: 501},
		{name: "discovery", change: func(r *scim.Request) { r.Operation = scim.ServiceProviderConfig }, status: 501},
		{name: "Bulk", change: func(r *scim.Request) { r.Operation = scim.Bulk }, status: 501},
	} {
		t.Run(tc.name, func(t *testing.T) {
			candidate := request
			if tc.change != nil {
				tc.change(&candidate)
			}
			tenant, maximum := f.tenant, scim.DefaultGroupMembers
			if tc.tenant != "" {
				tenant = tc.tenant
			}
			if tc.maximum != 0 {
				maximum = tc.maximum
			}
			f.deny.Store(tc.policy)
			defer f.deny.Store(false)
			ctx, cancel := context.WithCancel(f.ctx)
			defer cancel()
			if tc.canceled {
				cancel()
			}
			calls := 0
			var gate scim.ProtocolAdmission
			if !tc.nilGate {
				gate = func(context.Context, scim.ProtocolClient) *scim.Error { calls++; return nil }
			}
			out, err := selected.ExecuteManagedAdmittedGroupPatch(ctx, tenant, candidate, maximum, gate)
			assertManagedReadDenial(t, out, err, tc.status)
			if calls != 0 {
				t.Fatal("Group Patch preflight denial invoked admission")
			}
			assertUnchanged(t)
		})
	}
	for _, denial := range []string{"quota", "policy", "unavailable", "panic", "cancel", "deadline"} {
		t.Run("gate/"+denial, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(f.ctx, 250*time.Millisecond)
			defer cancel()
			originalDeadline, _ := ctx.Deadline()
			calls, status := 0, 503
			out, err := selected.ExecuteManagedAdmittedGroupPatch(ctx, f.tenant, request, scim.DefaultGroupMembers, func(ctx context.Context, client scim.ProtocolClient) *scim.Error {
				calls++
				assertManagedGroupPatchClient(t, f, ctx, client)
				deadline, _ := ctx.Deadline()
				if deadline.After(originalDeadline) {
					t.Fatal("Group Patch gate renewed the earlier parent deadline")
				}
				assertUnchanged(t)
				switch denial {
				case "quota":
					status = 429
					return scim.NewRateLimitedError(1250 * time.Millisecond)
				case "policy":
					status = 403
					return scim.NewError(403, "")
				case "panic":
					panic("private gate diagnostic")
				case "cancel":
					cancel()
					return scim.NewError(403, "")
				case "deadline":
					<-ctx.Done()
					return nil
				default:
					return scim.NewError(503, "")
				}
			})
			assertManagedReadDenial(t, out, err, status)
			var protocol *scim.Error
			if !errors.As(err, &protocol) || protocol.SCIMType() != "" || status == 429 && protocol.RetryAfterSeconds() != 2 || calls != 1 {
				t.Fatal("Group Patch gate denial lost redaction, retry delay or exactly-once admission")
			}
			assertUnchanged(t)
		})
	}
}

func TestManagedConnectionAdmittedGroupPatchRetainsTypedOrderNoOpAndHeaderlessOriginals(t *testing.T) {
	f, service := managedGroupCreateFixture(t)
	selected := managedGroupPatcher(t, service)
	connection := managedGroupReplaceConnection(t, f, service, "group-patch-owner")
	other := managedGroupReplaceConnection(t, f, service, "group-patch-other")
	seedUser := func(bearer authentication.BearerCredential, name string) scim.Response {
		t.Helper()
		user, err := service.ExecuteManagedProvisioning(f.ctx, f.tenant, scim.Request{Operation: scim.UserCreate, Credential: bearer, IdempotencyKey: name, ContentType: "application/scim+json", Body: []byte(`{"schemas":["urn:ietf:params:scim:schemas:core:2.0:User"],"userName":"` + name + `"}`)})
		if err != nil || user.Status != 201 {
			t.Fatal("seed exact managed User member", err)
		}
		return user
	}
	user, foreignUser := seedUser(connection.Bearer, "patch-owned-user"), seedUser(other.Bearer, "patch-foreign-user")
	groups, child := managedGroupReplaceSeed(t, f, service, connection.Bearer, "patch-owned-child", `{"schemas":["urn:ietf:params:scim:schemas:core:2.0:Group"],"displayName":"Owned child"}`)
	_, foreignGroup := managedGroupReplaceSeed(t, f, service, other.Bearer, "patch-foreign-child", `{"schemas":["urn:ietf:params:scim:schemas:core:2.0:Group"],"displayName":"Foreign child"}`)
	userID, childID := parseNativeUser(t, user).ID, groupID(t, child)
	_, created := managedGroupReplaceSeed(t, f, service, connection.Bearer, "patch-original-parent", `{"schemas":["urn:ietf:params:scim:schemas:core:2.0:Group"],"displayName":"Original","externalId":"preserved-correlation","members":[{"value":"`+userID+`","type":"User","display":"Before"}]}`)
	id := groupID(t, created)
	request := scim.Request{Operation: scim.GroupPatch, Credential: connection.Bearer, ResourceID: id, IfMatch: created.ETag, ContentType: "application/scim+json", Body: managedGroupPatchBody(`{"op":"replace","path":"displayName","value":"Patched"},{"op":"remove","path":"members[value eq \"` + userID + `\"]"},{"op":"add","path":"members","value":[{"value":"` + userID + `","type":"User","display":"After"},{"value":"` + childID + `","type":"Group"}]}`)}
	before := managedGroupCreateState(t, f)
	calls := 0
	gate := func(ctx context.Context, client scim.ProtocolClient) *scim.Error {
		calls++
		assertManagedGroupPatchClient(t, f, ctx, client)
		if calls == 1 && managedGroupCreateState(t, f) != before {
			t.Fatal("Group Patch preparation or protected effects preceded admission")
		}
		return nil
	}
	patched, err := selected.ExecuteManagedAdmittedGroupPatch(f.ctx, f.tenant, request, 2, gate)
	if err != nil || patched.Status != 200 || patched.ETag == created.ETag || patched.Location != created.Location || patched.ContentType != created.ContentType || groupID(t, patched) != id || calls != 1 {
		t.Fatal("admitted Group Patch lost conditional native write metadata", err)
	}
	var changed struct {
		DisplayName string
		ExternalID  string
		Members     []struct{ Value, Type, Display string }
		Meta        struct{ Created string }
	}
	var original struct{ Meta struct{ Created string } }
	if json.Unmarshal(patched.Body, &changed) != nil || json.Unmarshal(created.Body, &original) != nil || changed.DisplayName != "Patched" || changed.ExternalID != "preserved-correlation" || changed.Meta.Created != original.Meta.Created || len(changed.Members) != 2 || changed.Members[0].Value != userID || changed.Members[0].Type != "User" || changed.Members[0].Display != "After" || changed.Members[1].Value != childID || changed.Members[1].Type != "Group" {
		t.Fatal("Group Patch lost ordered fresh remove/add member semantics, typed links or untouched fields")
	}
	configuration, writes := service.config, service.writer().config
	configuration.Writes = &writes
	restarted, err := NewManagedConnectionService(f.pool, configuration)
	if err != nil {
		t.Fatal("reconstruct Group Patch runtime without invocation state", err)
	}
	selected = managedGroupPatcher(t, restarted)
	committedState := managedGroupCreateState(t, f)
	var formatted bytes.Buffer
	if err := json.Indent(&formatted, request.Body, "", "  "); err != nil {
		t.Fatal("format equivalent Group PatchOp", err)
	}
	retry := request
	retry.Body = formatted.Bytes()
	assertReplay := func(t *testing.T, attempt scim.Request, expected scim.Response) {
		t.Helper()
		before := managedGroupCreateState(t, f)
		priorCalls := calls
		out, err := selected.ExecuteManagedAdmittedGroupPatch(f.ctx, f.tenant, attempt, 2, gate)
		if err != nil || out.Status != expected.Status || out.ContentType != expected.ContentType || out.ETag != expected.ETag || out.Location != expected.Location || !bytes.Equal(out.Body, expected.Body) || calls != priorCalls+1 || managedGroupCreateState(t, f) != before {
			t.Fatal("headerless Group Patch replay changed original metadata, resource or protected effects", err)
		}
	}
	assertReplay(t, retry, patched)
	if managedGroupCreateState(t, f) != committedState {
		t.Fatal("equivalent canonical retry changed native original custody")
	}
	noOp := request
	noOp.IfMatch = patched.ETag
	noOp.Body = managedGroupPatchBody(`{"op":"replace","path":"displayName","value":"Patched"}`)
	unchanged, err := selected.ExecuteManagedAdmittedGroupPatch(f.ctx, f.tenant, noOp, 2, gate)
	if err != nil || unchanged.Status != 200 || unchanged.ETag != patched.ETag || unchanged.Location != patched.Location || !bytes.Equal(unchanged.Body, patched.Body) {
		t.Fatal("exact no-op Group Patch changed its resource, ETag or modification metadata", err)
	}
	assertReplay(t, noOp, unchanged)
	advance := noOp
	advance.Body = managedGroupPatchBody(`{"op":"replace","path":"displayName","value":"After no-op"}`)
	current, err := selected.ExecuteManagedAdmittedGroupPatch(f.ctx, f.tenant, advance, 2, gate)
	if err != nil || current.Status != 200 || current.ETag == patched.ETag {
		t.Fatal("advancing Group Patch after exact no-op failed", err)
	}
	assertReplay(t, noOp, unchanged)
	assertReplay(t, request, patched)
	var generation, commands, audits, events int
	if err := f.pool.Raw().QueryRow(f.ctx, `SELECT s.generation,
 (SELECT count(*) FROM identity.commands WHERE purpose=$3 AND state='committed'),
 (SELECT count(*) FROM audit.identity_command_bindings a JOIN identity.commands c USING(command_id) WHERE c.purpose=$3 AND c.state='committed'),
 (SELECT count(*) FROM public.identity_outbox_bindings o JOIN identity.commands c USING(command_id) WHERE c.purpose=$3)
FROM scim.groups s WHERE s.tenant_id=$1 AND s.resource_id=$2`, string(f.tenant), id, string(scim.GroupPatch)).Scan(&generation, &commands, &audits, &events); err != nil || generation != 3 || commands != 3 || audits != 3 || events != 3 {
		t.Fatalf("Group Patch/no-op/replay custody mismatch: generation=%d committed commands=%d committed audits=%d outbox events=%d query failed=%t", generation, commands, audits, events, err != nil)
	}
	for _, attempt := range []scim.Request{request, noOp} {
		t.Run("original replay requires current authority and gate", func(t *testing.T) {
			before := managedGroupCreateState(t, f)
			f.deny.Store(true)
			attempts := 0
			out, err := selected.ExecuteManagedAdmittedGroupPatch(f.ctx, f.tenant, attempt, 2, func(context.Context, scim.ProtocolClient) *scim.Error { attempts++; return nil })
			f.deny.Store(false)
			assertManagedReadDenial(t, out, err, 403)
			if attempts != 0 || managedGroupCreateState(t, f) != before {
				t.Fatal("historical Group Patch or no-op bypassed current operation authority")
			}
			out, err = selected.ExecuteManagedAdmittedGroupPatch(f.ctx, f.tenant, attempt, 2, func(context.Context, scim.ProtocolClient) *scim.Error { attempts++; return scim.NewError(403, "") })
			assertManagedReadDenial(t, out, err, 403)
			if attempts != 1 || managedGroupCreateState(t, f) != before {
				t.Fatal("historical Group Patch or no-op bypassed current admission")
			}
		})
	}
	assertCurrent := func(t *testing.T) {
		t.Helper()
		read, err := groups.Execute(f.ctx, scim.Request{Operation: scim.GroupGet, Credential: connection.Bearer, ResourceID: id})
		if err != nil || read.Status != 200 || read.ETag != current.ETag || !bytes.Equal(read.Body, current.Body) {
			t.Fatal("denied Group Patch changed the committed projection", err)
		}
	}
	for _, change := range []struct {
		name   string
		change func(*scim.Request)
		status int
	}{
		{"changed input", func(r *scim.Request) {
			r.Body = managedGroupPatchBody(`{"op":"replace","path":"displayName","value":"Changed stale intent"}`)
		}, 412},
		{"changed query", func(r *scim.Request) { r.Query.Attributes = "id,displayName" }, 412},
		{"foreign target scope", func(r *scim.Request) { r.Credential = other.Bearer }, 404},
	} {
		t.Run(change.name, func(t *testing.T) {
			candidate := request
			change.change(&candidate)
			attempts := 0
			out, err := selected.ExecuteManagedAdmittedGroupPatch(f.ctx, f.tenant, candidate, 2, func(context.Context, scim.ProtocolClient) *scim.Error { attempts++; return nil })
			assertManagedReadDenial(t, out, err, change.status)
			if attempts != 1 {
				t.Fatal("changed or foreign Group Patch did not consume exactly one admission")
			}
			assertCurrent(t)
		})
	}
	for _, member := range []struct{ name, id, kind string }{
		{"foreign User", parseNativeUser(t, foreignUser).ID, "User"},
		{"foreign Group", groupID(t, foreignGroup), "Group"},
		{"User to Group switch", userID, "Group"},
		{"Group to User switch", childID, "User"},
	} {
		t.Run(member.name+" cannot be added", func(t *testing.T) {
			candidate := request
			candidate.IfMatch = current.ETag
			candidate.Body = managedGroupPatchBody(`{"op":"replace","path":"members","value":[{"value":"` + member.id + `","type":"` + member.kind + `"}]}`)
			attempts := 0
			out, err := selected.ExecuteManagedAdmittedGroupPatch(f.ctx, f.tenant, candidate, 2, func(ctx context.Context, client scim.ProtocolClient) *scim.Error {
				attempts++
				assertManagedGroupPatchClient(t, f, ctx, client)
				return nil
			})
			assertManagedReadDenial(t, out, err, 400)
			if attempts != 1 {
				t.Fatal("typed native member integrity did not follow exactly one admission")
			}
			assertCurrent(t)
		})
	}
	for _, member := range []struct {
		operation scim.Operation
		bearer    authentication.BearerCredential
		original  scim.Response
		id        string
	}{
		{scim.UserGet, connection.Bearer, user, userID},
		{scim.GroupGet, connection.Bearer, child, childID},
		{scim.UserGet, other.Bearer, foreignUser, parseNativeUser(t, foreignUser).ID},
		{scim.GroupGet, other.Bearer, foreignGroup, groupID(t, foreignGroup)},
	} {
		candidate := scim.Request{Operation: member.operation, Credential: member.bearer, ResourceID: member.id}
		var out scim.Response
		if member.operation == scim.UserGet {
			out, err = service.ExecuteManagedProvisioning(f.ctx, f.tenant, candidate)
		} else {
			out, err = service.ExecuteManagedAdmittedGroupRead(f.ctx, f.tenant, candidate, scim.DefaultGroupMembers, func(context.Context, scim.ProtocolClient) *scim.Error { return nil })
		}
		if err != nil || out.Status != 200 || out.ETag != member.original.ETag || !bytes.Equal(out.Body, member.original.Body) {
			t.Fatal("Group Patch changed a referenced owned or foreign resource", err)
		}
	}
	t.Run("ordinary Group execution retains headerless policy", func(t *testing.T) {
		ordinary := request
		ordinary.IfMatch = current.ETag
		ordinary.Body = managedGroupPatchBody(`{"op":"replace","path":"displayName","value":"Ordinary patch"}`)
		out, err := groups.Execute(f.ctx, ordinary)
		if err != nil || out.Status != 200 {
			t.Fatal("ordinary Group Patch stopped accepting headerless mutation", err)
		}
		out, err = groups.Execute(f.ctx, ordinary)
		assertManagedReadDenial(t, out, err, 412)
	})
}

func TestManagedConnectionAdmittedGroupPatchRetainsAtomicCASAndDenialAudit(t *testing.T) {
	f, service := managedGroupCreateFixture(t)
	selected := managedGroupPatcher(t, service)
	connection := managedGroupReplaceConnection(t, f, service, "group-patch-cas")
	_, created := managedGroupReplaceSeed(t, f, service, connection.Bearer, "group-patch-cas-seed", `{"schemas":["urn:ietf:params:scim:schemas:core:2.0:Group"],"displayName":"Original"}`)
	request := scim.Request{Operation: scim.GroupPatch, Credential: connection.Bearer, ResourceID: groupID(t, created), IfMatch: created.ETag, ContentType: "application/scim+json"}
	prepared, release, finished := make(chan struct{}), make(chan struct{}), make(chan struct{})
	var entered, unblocked sync.Once
	unblock := func() { unblocked.Do(func() { close(release) }) }
	defer unblock()
	configuration, writes := service.config, service.writer().config
	underlying := writes.Provisioning.Authorization
	writes.Provisioning.Authorization = configuredPolicy(func(ctx context.Context, decision authorization.DecisionContext) (authorization.Decision, error) {
		i, _ := currentInvocation(ctx)
		if decision.Request.Action == authorization.Action(scim.GroupPatch) && decision.Request.Resource.Type == "identity.scim.group" && i != nil && i.phase != nil {
			entered.Do(func() {
				close(prepared)
				select {
				case <-release:
				case <-ctx.Done():
				}
			})
		}
		return underlying.Decide(ctx, decision)
	})
	configuration.Writes = &writes
	paused, err := NewManagedConnectionService(f.pool, configuration)
	if err != nil {
		t.Fatal("compose losing managed Group Patch writer", err)
	}
	pausedSelection := managedGroupPatcher(t, paused)
	var calls atomic.Int32
	gate := func(context.Context, scim.ProtocolClient) *scim.Error { calls.Add(1); return nil }
	type result struct {
		response scim.Response
		err      error
	}
	results := make(chan result, 1)
	loser := request
	loser.Body = managedGroupPatchBody(`{"op":"replace","path":"displayName","value":"Rejected loser"}`)
	go func() {
		defer close(finished)
		out, err := pausedSelection.ExecuteManagedAdmittedGroupPatch(f.ctx, f.tenant, loser, 0, gate)
		results <- result{out, err}
	}()
	defer func() {
		unblock()
		select {
		case <-finished:
		case <-f.ctx.Done():
			t.Error("losing managed Group Patch writer did not terminate")
		}
	}()
	select {
	case <-prepared:
	case got := <-results:
		t.Fatal("losing managed Group Patch did not reach native preparation", got.err)
	case <-f.ctx.Done():
		t.Fatal("losing managed Group Patch preparation did not arrive")
	}
	winner := request
	winner.Body = managedGroupPatchBody(`{"op":"replace","path":"displayName","value":"Winner"}`)
	committed, err := selected.ExecuteManagedAdmittedGroupPatch(f.ctx, f.tenant, winner, 0, gate)
	if err != nil || committed.Status != 200 || committed.ETag == created.ETag {
		t.Fatal("winning managed Group Patch did not commit", err)
	}
	unblock()
	select {
	case got := <-results:
		assertManagedReadDenial(t, got.response, got.err, 412)
	case <-f.ctx.Done():
		t.Fatal("losing managed Group Patch did not finish")
	}
	before := managedGroupCreateState(t, f)
	out, err := selected.ExecuteManagedAdmittedGroupPatch(f.ctx, f.tenant, loser, 0, gate)
	assertManagedReadDenial(t, out, err, 412)
	if managedGroupCreateState(t, f) != before {
		t.Fatal("losing Group Patch retry duplicated its durable denial audit")
	}
	var generation, committedCommands, aborted, committedAudits, abortedAudits, events int
	if err := f.pool.Raw().QueryRow(f.ctx, `SELECT s.generation,
 (SELECT count(*) FROM identity.commands WHERE purpose=$3 AND state='committed'),
 (SELECT count(*) FROM identity.commands WHERE purpose=$3 AND state='aborted'),
 (SELECT count(*) FROM audit.identity_command_bindings a JOIN identity.commands c USING(command_id) WHERE c.purpose=$3 AND c.state='committed'),
 (SELECT count(*) FROM audit.identity_command_bindings a JOIN identity.commands c USING(command_id) WHERE c.purpose=$3 AND c.state='aborted'),
 (SELECT count(*) FROM public.identity_outbox_bindings o JOIN identity.commands c USING(command_id) WHERE c.purpose=$3)
FROM scim.groups s WHERE s.tenant_id=$1 AND s.resource_id=$2`, string(f.tenant), request.ResourceID, string(scim.GroupPatch)).Scan(&generation, &committedCommands, &aborted, &committedAudits, &abortedAudits, &events); err != nil || calls.Load() != 3 || generation != 2 || committedCommands != 1 || aborted != 1 || committedAudits != 1 || abortedAudits != 1 || events != 1 {
		t.Fatalf("concurrent Group Patch custody mismatch: gate calls=%d generation=%d committed commands=%d aborted commands=%d committed audits=%d aborted audits=%d outbox events=%d query failed=%t", calls.Load(), generation, committedCommands, aborted, committedAudits, abortedAudits, events, err != nil)
	}
}
