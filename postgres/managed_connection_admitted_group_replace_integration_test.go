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

type managedAdmittedGroupReplacer interface {
	ExecuteManagedAdmittedGroupReplace(context.Context, identity.TenantID, scim.Request, int, scim.ProtocolAdmission) (scim.Response, error)
}

func managedGroupReplacer(t *testing.T, service *ManagedConnectionService) managedAdmittedGroupReplacer {
	t.Helper()
	selected, ok := any(service).(managedAdmittedGroupReplacer)
	if !ok {
		t.Fatal("managed connection service has no explicit admitted conditional Group Replace selection")
	}
	return selected
}

func managedGroupReplaceConnection(t *testing.T, f *managedConnectionAdminFixture, service *ManagedConnectionService, key string) ConnectionCreateResult {
	t.Helper()
	connection, err := service.ConnectionCreate(f.ctx, managedConnectionCreateRequest(t, f, "managed-group-replace-provider", key))
	if err != nil || connection.Bearer.Token() == "" {
		t.Fatal("issue actual managed bearer for Group Replace", err)
	}
	return connection
}

func managedGroupReplaceSeed(t *testing.T, f *managedConnectionAdminFixture, service *ManagedConnectionService, bearer authentication.BearerCredential, key, body string) (*GroupsService, scim.Response) {
	t.Helper()
	source, err := service.loadManagedProvisioning(f.ctx, f.tenant, bearer)
	if err != nil {
		t.Fatal("load exact managed Group fixture scope", err)
	}
	groups, err := NewGroupsService(source, scim.DefaultGroupMembers)
	if err != nil {
		t.Fatal("compose existing native Groups fixture", err)
	}
	created, err := groups.Execute(f.ctx, scim.Request{Operation: scim.GroupCreate, Credential: bearer, IdempotencyKey: key, ContentType: "application/scim+json", Body: []byte(body)})
	if err != nil || created.Status != 201 {
		t.Fatal("seed actual native Group before admitted Replace", err)
	}
	return groups, created
}

func assertManagedGroupReplaceClient(t *testing.T, f *managedConnectionAdminFixture, ctx context.Context, client scim.ProtocolClient) {
	t.Helper()
	deadline, bounded := ctx.Deadline()
	if ctx.Err() != nil || !bounded || !deadline.After(time.Now()) || time.Until(deadline) > f.config.MaximumDuration || client.ID != f.config.ActorID || client.TenantID != f.tenant {
		t.Fatal("Group Replace gate lost the configured service-account client, exact tenant or original bounded context")
	}
}

func TestManagedConnectionAdmittedGroupReplaceDenialsPrecedeNativeEffects(t *testing.T) {
	f, service := managedGroupCreateFixture(t)
	selected := managedGroupReplacer(t, service)
	connection := managedGroupReplaceConnection(t, f, service, "group-replace-denials")
	_, created := managedGroupReplaceSeed(t, f, service, connection.Bearer, "group-replace-denials-seed", `{"schemas":["urn:ietf:params:scim:schemas:core:2.0:Group"],"displayName":"Original"}`)
	request := scim.Request{Operation: scim.GroupReplace, Credential: connection.Bearer, ResourceID: groupID(t, created), IfMatch: created.ETag, ContentType: "application/scim+json", Body: []byte(`{"schemas":["urn:ietf:params:scim:schemas:core:2.0:Group"],"displayName":"Replacement"}`)}
	before := managedGroupCreateState(t, f)
	assertUnchanged := func(t *testing.T) {
		t.Helper()
		if managedGroupCreateState(t, f) != before {
			t.Fatal("unadmitted Group Replace changed resources, commands, request mappings, audit or outbox")
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
		{name: "caller key", change: func(r *scim.Request) { r.IdempotencyKey = "caller-selected-group-replace" }, status: 400},
		{name: "missing displayName", change: func(r *scim.Request) { r.Body = []byte(`{"schemas":["urn:ietf:params:scim:schemas:core:2.0:Group"]}`) }, status: 400},
		{name: "malformed JSON", change: func(r *scim.Request) { r.Body = []byte(`{"schemas":[`) }, status: 400},
		{name: "case alias", change: func(r *scim.Request) {
			r.Body = []byte(`{"schemas":["urn:ietf:params:scim:schemas:core:2.0:Group"],"displayName":"one","DISPLAYNAME":"two"}`)
		}, status: 400},
		{name: "mismatched member reference", change: func(r *scim.Request) {
			r.Body = []byte(`{"schemas":["urn:ietf:params:scim:schemas:core:2.0:Group"],"displayName":"one","members":[{"value":"member","type":"Group","$ref":"Users/member"}]}`)
		}, status: 400},
		{name: "User Replace", change: func(r *scim.Request) { r.Operation = scim.UserReplace }, status: 501},
		{name: "Group Create", change: func(r *scim.Request) { r.Operation = scim.GroupCreate }, status: 501},
		{name: "Group Get", change: func(r *scim.Request) { r.Operation = scim.GroupGet }, status: 501},
		{name: "Group List", change: func(r *scim.Request) { r.Operation = scim.GroupList }, status: 501},
		{name: "Group Search", change: func(r *scim.Request) { r.Operation = scim.GroupSearch }, status: 501},
		{name: "Group Patch", change: func(r *scim.Request) { r.Operation = scim.GroupPatch }, status: 501},
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
			out, err := selected.ExecuteManagedAdmittedGroupReplace(ctx, tenant, candidate, maximum, gate)
			assertManagedReadDenial(t, out, err, tc.status)
			if calls != 0 {
				t.Fatal("Group Replace preflight denial invoked admission")
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
			out, err := selected.ExecuteManagedAdmittedGroupReplace(ctx, f.tenant, request, scim.DefaultGroupMembers, func(ctx context.Context, client scim.ProtocolClient) *scim.Error {
				calls++
				assertManagedGroupReplaceClient(t, f, ctx, client)
				deadline, _ := ctx.Deadline()
				if deadline.After(originalDeadline) {
					t.Fatal("Group Replace gate renewed the earlier parent deadline")
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
				t.Fatal("Group Replace gate denial lost redaction, retry delay or exactly-once admission")
			}
			assertUnchanged(t)
		})
	}
}

func TestManagedConnectionAdmittedGroupReplaceRetainsHeaderlessOriginalAndTypedMembers(t *testing.T) {
	f, service := managedGroupCreateFixture(t)
	selected := managedGroupReplacer(t, service)
	connection := managedGroupReplaceConnection(t, f, service, "group-replace-owner")
	other := managedGroupReplaceConnection(t, f, service, "group-replace-other")
	seedUser := func(bearer authentication.BearerCredential, name string) scim.Response {
		t.Helper()
		user, err := service.ExecuteManagedProvisioning(f.ctx, f.tenant, scim.Request{Operation: scim.UserCreate, Credential: bearer, IdempotencyKey: name, ContentType: "application/scim+json", Body: []byte(`{"schemas":["urn:ietf:params:scim:schemas:core:2.0:User"],"userName":"` + name + `"}`)})
		if err != nil || user.Status != 201 {
			t.Fatal("seed exact managed User member", err)
		}
		return user
	}
	user, foreignUser := seedUser(connection.Bearer, "replace-owned-user"), seedUser(other.Bearer, "replace-foreign-user")
	groups, child := managedGroupReplaceSeed(t, f, service, connection.Bearer, "replace-owned-child", `{"schemas":["urn:ietf:params:scim:schemas:core:2.0:Group"],"displayName":"Owned child"}`)
	_, foreignGroup := managedGroupReplaceSeed(t, f, service, other.Bearer, "replace-foreign-child", `{"schemas":["urn:ietf:params:scim:schemas:core:2.0:Group"],"displayName":"Foreign child"}`)
	_, created := managedGroupReplaceSeed(t, f, service, connection.Bearer, "replace-original-parent", `{"schemas":["urn:ietf:params:scim:schemas:core:2.0:Group"],"displayName":"Original","externalId":"omitted-correlation"}`)
	id, userID, childID := groupID(t, created), parseNativeUser(t, user).ID, groupID(t, child)
	request := scim.Request{Operation: scim.GroupReplace, Credential: connection.Bearer, ResourceID: id, IfMatch: created.ETag, ContentType: "application/scim+json", Body: []byte(`{"schemas":["urn:ietf:params:scim:schemas:core:2.0:Group"],"displayName":"Replacement","members":[{"value":"` + userID + `","type":"User"},{"value":"` + childID + `","type":"Group"}]}`)}
	before := managedGroupCreateState(t, f)
	calls := 0
	denied := true
	gate := func(ctx context.Context, client scim.ProtocolClient) *scim.Error {
		calls++
		assertManagedGroupReplaceClient(t, f, ctx, client)
		if calls <= 2 && managedGroupCreateState(t, f) != before {
			t.Fatal("Group Replace preparation or protected effects preceded admission")
		}
		if denied {
			return scim.NewRateLimitedError(time.Second)
		}
		return nil
	}
	if out, err := selected.ExecuteManagedAdmittedGroupReplace(f.ctx, f.tenant, request, 0, gate); protocolStatus(err) != 400 || out.Status != 0 || calls != 0 || managedGroupCreateState(t, f) != before {
		t.Fatal("zero member ceiling did not reject members before admission or effects", err)
	}
	out, err := selected.ExecuteManagedAdmittedGroupReplace(f.ctx, f.tenant, request, 2, gate)
	assertManagedReadDenial(t, out, err, 429)
	if calls != 1 || managedGroupCreateState(t, f) != before {
		t.Fatal("prior gate denial retained command custody or changed resources")
	}
	denied = false
	replaced, err := selected.ExecuteManagedAdmittedGroupReplace(f.ctx, f.tenant, request, 2, gate)
	if err != nil || replaced.Status != 200 || replaced.ETag == created.ETag || replaced.Location != created.Location || replaced.ContentType != created.ContentType || groupID(t, replaced) != id || calls != 2 {
		t.Fatal("admitted Group Replace did not preserve native conditional write metadata", err)
	}
	var replacement struct {
		DisplayName string
		ExternalID  string
		Members     []struct{ Value, Type string }
		Meta        struct{ Created string }
	}
	var original struct{ Meta struct{ Created string } }
	if json.Unmarshal(replaced.Body, &replacement) != nil || json.Unmarshal(created.Body, &original) != nil || replacement.DisplayName != "Replacement" || replacement.ExternalID != "" || replacement.Meta.Created != original.Meta.Created || len(replacement.Members) != 2 || replacement.Members[0].Value != userID || replacement.Members[0].Type != "User" || replacement.Members[1].Value != childID || replacement.Members[1].Type != "Group" {
		t.Fatal("full Group replacement retained omitted fields or lost creation metadata and typed member links")
	}
	committedState := managedGroupCreateState(t, f)
	configuration, writes := service.config, service.writer().config
	configuration.Writes = &writes
	restarted, err := NewManagedConnectionService(f.pool, configuration)
	if err != nil {
		t.Fatal("reconstruct Group Replace runtime without invocation state", err)
	}
	retry := request
	retry.Body = []byte(`{ "members":[{"type":"User","value":"` + userID + `"},{"type":"Group","value":"` + childID + `"}], "displayName":"Replacement", "schemas":["urn:ietf:params:scim:schemas:core:2.0:Group"] }`)
	replay, err := managedGroupReplacer(t, restarted).ExecuteManagedAdmittedGroupReplace(f.ctx, f.tenant, retry, 2, gate)
	if err != nil || replay.Status != replaced.Status || replay.ContentType != replaced.ContentType || replay.ETag != replaced.ETag || replay.Location != replaced.Location || !bytes.Equal(replay.Body, replaced.Body) || calls != 3 || managedGroupCreateState(t, f) != committedState {
		t.Fatal("durable headerless Group Replace retry lost original result or repeated effects", err)
	}
	var generation, commands, audits, events int
	if err := f.pool.Raw().QueryRow(f.ctx, `SELECT s.generation,
 (SELECT count(*) FROM identity.commands c WHERE c.command_id=decode(translate(s.command_id,'-_','+/')||'==','base64') AND c.purpose=$3 AND c.state='committed'),
 (SELECT count(*) FROM audit.identity_command_bindings a WHERE a.command_id=decode(translate(s.command_id,'-_','+/')||'==','base64')),
 (SELECT count(*) FROM public.identity_outbox_bindings o WHERE o.command_id=decode(translate(s.command_id,'-_','+/')||'==','base64'))
FROM scim.groups s WHERE s.tenant_id=$1 AND s.resource_id=$2`, string(f.tenant), id, string(scim.GroupReplace)).Scan(&generation, &commands, &audits, &events); err != nil || generation != 2 || commands != 1 || audits != 1 || events != 1 {
		t.Fatal("Group Replace/replay did not retain one changed generation and original command/audit/outbox", err)
	}
	assertCurrent := func(t *testing.T) {
		t.Helper()
		read, err := groups.Execute(f.ctx, scim.Request{Operation: scim.GroupGet, Credential: connection.Bearer, ResourceID: id})
		if err != nil || read.Status != 200 || read.ETag != replaced.ETag || !bytes.Equal(read.Body, replaced.Body) {
			t.Fatal("denied Group Replace changed the committed projection", err)
		}
	}
	t.Run("replay still requires current operation authority", func(t *testing.T) {
		f.deny.Store(true)
		defer f.deny.Store(false)
		attempts := 0
		out, err := selected.ExecuteManagedAdmittedGroupReplace(f.ctx, f.tenant, request, 2, func(context.Context, scim.ProtocolClient) *scim.Error { attempts++; return nil })
		assertManagedReadDenial(t, out, err, 403)
		if attempts != 0 || managedGroupCreateState(t, f) != committedState {
			t.Fatal("historical Group Replace result bypassed current operation authority")
		}
	})
	t.Run("replay still requires admission", func(t *testing.T) {
		attempts := 0
		out, err := selected.ExecuteManagedAdmittedGroupReplace(f.ctx, f.tenant, request, 2, func(context.Context, scim.ProtocolClient) *scim.Error { attempts++; return scim.NewError(403, "") })
		assertManagedReadDenial(t, out, err, 403)
		if attempts != 1 || managedGroupCreateState(t, f) != committedState {
			t.Fatal("historical Group Replace result bypassed the current admission gate")
		}
	})
	for _, change := range []struct {
		name   string
		change func(*scim.Request)
	}{
		{"changed body", func(r *scim.Request) {
			r.Body = []byte(`{"schemas":["urn:ietf:params:scim:schemas:core:2.0:Group"],"displayName":"Different"}`)
		}},
		{"changed member type", func(r *scim.Request) {
			r.Body = []byte(`{"schemas":["urn:ietf:params:scim:schemas:core:2.0:Group"],"displayName":"Replacement","members":[{"value":"` + userID + `","type":"Group"},{"value":"` + childID + `","type":"Group"}]}`)
		}},
		{"changed query", func(r *scim.Request) { r.Query.Attributes = "id,displayName" }},
	} {
		t.Run(change.name+" cannot replay the original", func(t *testing.T) {
			candidate := request
			change.change(&candidate)
			attempts := 0
			out, err := selected.ExecuteManagedAdmittedGroupReplace(f.ctx, f.tenant, candidate, 2, func(context.Context, scim.ProtocolClient) *scim.Error { attempts++; return nil })
			assertManagedReadDenial(t, out, err, 412)
			if attempts != 1 {
				t.Fatal("changed canonical input did not consume exactly one admitted attempt")
			}
			assertCurrent(t)
		})
	}
	t.Run("foreign connection cannot select target or original", func(t *testing.T) {
		candidate := request
		candidate.Credential = other.Bearer
		attempts := 0
		out, err := selected.ExecuteManagedAdmittedGroupReplace(f.ctx, f.tenant, candidate, 2, func(context.Context, scim.ProtocolClient) *scim.Error { attempts++; return nil })
		assertManagedReadDenial(t, out, err, 404)
		if attempts != 1 {
			t.Fatal("foreign target did not remain behind the current connection gate")
		}
		assertCurrent(t)
	})
	for _, member := range []struct{ name, id, kind string }{
		{"foreign User", parseNativeUser(t, foreignUser).ID, "User"},
		{"foreign Group", groupID(t, foreignGroup), "Group"},
		{"User to Group switch", userID, "Group"},
		{"Group to User switch", childID, "User"},
	} {
		t.Run(member.name+" cannot change the Group", func(t *testing.T) {
			candidate := request
			candidate.IfMatch = replaced.ETag
			candidate.Body = []byte(`{"schemas":["urn:ietf:params:scim:schemas:core:2.0:Group"],"displayName":"Denied foreign link","members":[{"value":"` + member.id + `","type":"` + member.kind + `"}]}`)
			attempts := 0
			out, err := selected.ExecuteManagedAdmittedGroupReplace(f.ctx, f.tenant, candidate, 2, func(ctx context.Context, client scim.ProtocolClient) *scim.Error {
				attempts++
				assertManagedGroupReplaceClient(t, f, ctx, client)
				return nil
			})
			assertManagedReadDenial(t, out, err, 400)
			if attempts != 1 {
				t.Fatal("typed member integrity did not follow exactly one admission")
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
			t.Fatal("Group Replace changed a referenced owned or foreign resource", err)
		}
	}
	t.Run("omitted members replace rather than merge", func(t *testing.T) {
		empty := request
		empty.IfMatch = replaced.ETag
		empty.Body = []byte(`{"schemas":["urn:ietf:params:scim:schemas:core:2.0:Group"],"displayName":"Empty replacement"}`)
		out, err := selected.ExecuteManagedAdmittedGroupReplace(f.ctx, f.tenant, empty, 2, func(context.Context, scim.ProtocolClient) *scim.Error { return nil })
		if err != nil || out.Status != 200 {
			t.Fatal("Group replacement with omitted members failed", err)
		}
		var resource struct{ Members []json.RawMessage }
		if json.Unmarshal(out.Body, &resource) != nil || len(resource.Members) != 0 {
			t.Fatal("Group replacement retained omitted members as a PATCH merge")
		}
	})
	t.Run("ordinary Group execution retains its headerless policy", func(t *testing.T) {
		_, original := managedGroupReplaceSeed(t, f, service, connection.Bearer, "ordinary-group-replace-seed", `{"schemas":["urn:ietf:params:scim:schemas:core:2.0:Group"],"displayName":"Ordinary original"}`)
		ordinary := request
		ordinary.ResourceID, ordinary.IfMatch = groupID(t, original), original.ETag
		ordinary.Body = []byte(`{"schemas":["urn:ietf:params:scim:schemas:core:2.0:Group"],"displayName":"Ordinary replacement"}`)
		out, err := groups.Execute(f.ctx, ordinary)
		if err != nil || out.Status != 200 {
			t.Fatal("ordinary native Group Replace stopped accepting a headerless mutation", err)
		}
		out, err = groups.Execute(f.ctx, ordinary)
		assertManagedReadDenial(t, out, err, 412)
	})
}

func TestManagedConnectionAdmittedGroupReplaceRetainsAtomicCAS(t *testing.T) {
	f, service := managedGroupCreateFixture(t)
	selected := managedGroupReplacer(t, service)
	connection := managedGroupReplaceConnection(t, f, service, "group-replace-cas")
	_, created := managedGroupReplaceSeed(t, f, service, connection.Bearer, "group-replace-cas-seed", `{"schemas":["urn:ietf:params:scim:schemas:core:2.0:Group"],"displayName":"Original"}`)
	request := scim.Request{Operation: scim.GroupReplace, Credential: connection.Bearer, ResourceID: groupID(t, created), IfMatch: created.ETag, ContentType: "application/scim+json"}
	prepared, release, finished := make(chan struct{}), make(chan struct{}), make(chan struct{})
	var entered, unblocked sync.Once
	unblock := func() { unblocked.Do(func() { close(release) }) }
	defer unblock()
	configuration, writes := service.config, service.writer().config
	underlying := writes.Provisioning.Authorization
	writes.Provisioning.Authorization = configuredPolicy(func(ctx context.Context, decision authorization.DecisionContext) (authorization.Decision, error) {
		i, _ := currentInvocation(ctx)
		if decision.Request.Action == authorization.Action(scim.GroupReplace) && decision.Request.Resource.Type == "identity.scim.group" && i != nil && i.phase != nil {
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
		t.Fatal("compose losing managed Group Replace writer", err)
	}
	pausedSelection := managedGroupReplacer(t, paused)
	var calls atomic.Int32
	gate := func(context.Context, scim.ProtocolClient) *scim.Error {
		calls.Add(1)
		return nil
	}
	type result struct {
		response scim.Response
		err      error
	}
	results := make(chan result, 1)
	loser := request
	loser.Body = []byte(`{"schemas":["urn:ietf:params:scim:schemas:core:2.0:Group"],"displayName":"Rejected loser"}`)
	go func() {
		defer close(finished)
		out, err := pausedSelection.ExecuteManagedAdmittedGroupReplace(f.ctx, f.tenant, loser, 0, gate)
		results <- result{out, err}
	}()
	defer func() {
		unblock()
		select {
		case <-finished:
		case <-f.ctx.Done():
			t.Error("losing managed Group Replace writer did not terminate")
		}
	}()
	select {
	case <-prepared:
	case got := <-results:
		t.Fatal("losing managed Group Replace did not reach native preparation", got.err)
	case <-f.ctx.Done():
		t.Fatal("losing managed Group Replace preparation did not arrive")
	}
	winner := request
	winner.Body = []byte(`{"schemas":["urn:ietf:params:scim:schemas:core:2.0:Group"],"displayName":"Winner"}`)
	committedResult, err := selected.ExecuteManagedAdmittedGroupReplace(f.ctx, f.tenant, winner, 0, gate)
	if err != nil || committedResult.Status != 200 || committedResult.ETag == created.ETag {
		t.Fatal("winning managed Group Replace did not commit", err)
	}
	unblock()
	select {
	case got := <-results:
		if protocolStatus(got.err) != 412 || got.response.Status != 0 {
			t.Fatal("frozen losing managed Group Replace did not retain atomic precondition", got.err)
		}
	case <-f.ctx.Done():
		t.Fatal("losing managed Group Replace did not finish")
	}
	var generation, committed, aborted, committedAudits, abortedAudits, events int
	if err := f.pool.Raw().QueryRow(f.ctx, `SELECT s.generation,
 (SELECT count(*) FROM identity.commands WHERE purpose=$3 AND state='committed'),
 (SELECT count(*) FROM identity.commands WHERE purpose=$3 AND state='aborted'),
 (SELECT count(*) FROM audit.identity_command_bindings a JOIN identity.commands c USING(command_id) WHERE c.purpose=$3 AND c.state='committed'),
 (SELECT count(*) FROM audit.identity_command_bindings a JOIN identity.commands c USING(command_id) WHERE c.purpose=$3 AND c.state='aborted'),
 (SELECT count(*) FROM public.identity_outbox_bindings o JOIN identity.commands c USING(command_id) WHERE c.purpose=$3)
FROM scim.groups s WHERE s.tenant_id=$1 AND s.resource_id=$2`, string(f.tenant), request.ResourceID, string(scim.GroupReplace)).Scan(&generation, &committed, &aborted, &committedAudits, &abortedAudits, &events); err != nil || calls.Load() != 2 || generation != 2 || committed != 1 || aborted != 1 || committedAudits != 1 || abortedAudits != 1 || events != 1 {
		t.Fatalf("concurrent admitted Group Replace custody mismatch: gate calls=%d generation=%d committed commands=%d aborted commands=%d committed audits=%d aborted audits=%d outbox events=%d query failed=%t", calls.Load(), generation, committed, aborted, committedAudits, abortedAudits, events, err != nil)
	}
}
