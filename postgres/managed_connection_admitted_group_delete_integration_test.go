//go:build integration

package scimpostgres

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	authentication "github.com/faustbrian/go-authentication/v2"
	identity "github.com/faustbrian/go-identity"
	organizationpg "github.com/faustbrian/go-organization/postgres"
	scim "github.com/faustbrian/go-scim"
)

type managedAdmittedGroupDeleter interface {
	ExecuteManagedAdmittedGroupDelete(context.Context, identity.TenantID, scim.Request, int, scim.ProtocolAdmission) (scim.Response, error)
}

func managedGroupDeleter(t *testing.T, service *ManagedConnectionService) managedAdmittedGroupDeleter {
	t.Helper()
	selected, ok := any(service).(managedAdmittedGroupDeleter)
	if !ok {
		t.Fatal("managed connection service has no explicit admitted conditional Group Delete selection")
	}
	return selected
}

func assertManagedGroupDeleteClient(t *testing.T, f *managedConnectionAdminFixture, ctx context.Context, client scim.ProtocolClient) {
	t.Helper()
	deadline, bounded := ctx.Deadline()
	if ctx.Err() != nil || !bounded || !deadline.After(time.Now()) || time.Until(deadline) > f.config.MaximumDuration || client.ID != f.config.ActorID || client.TenantID != f.tenant {
		t.Fatal("Group Delete gate lost the configured service-account client, exact tenant or original bounded context")
	}
}

func assertManagedGroupDeleted(t *testing.T, out scim.Response, err error) {
	t.Helper()
	if err != nil || out.Status != 204 || len(out.Body) != 0 || out.ETag != "" || out.Location != "" || out.ContentType != "" {
		t.Fatal("Group Delete did not return its canonical empty 204", err)
	}
}

func TestManagedConnectionAdmittedGroupDeleteDenialsPrecedeNativeEffects(t *testing.T) {
	f, service := managedGroupCreateFixture(t)
	selected := managedGroupDeleter(t, service)
	connection := managedGroupReplaceConnection(t, f, service, "group-delete-denials")
	_, created := managedGroupReplaceSeed(t, f, service, connection.Bearer, "group-delete-denials-seed", `{"schemas":["urn:ietf:params:scim:schemas:core:2.0:Group"],"displayName":"Preserved"}`)
	request := scim.Request{Operation: scim.GroupDelete, Credential: connection.Bearer, ResourceID: groupID(t, created), IfMatch: created.ETag}
	before := managedGroupCreateState(t, f)
	assertUnchanged := func(t *testing.T) {
		t.Helper()
		if managedGroupCreateState(t, f) != before {
			t.Fatal("unadmitted Group Delete changed resources, commands, request mappings, audit or outbox")
		}
	}
	t.Run("ordinary managed provisioning stays closed", func(t *testing.T) {
		out, err := service.ExecuteManagedProvisioning(f.ctx, f.tenant, request)
		assertManagedReadDenial(t, out, err, 501)
		assertUnchanged(t)
	})
	for _, tc := range []struct {
		name    string
		change  func(*scim.Request)
		tenant  identity.TenantID
		maximum int
		nilGate bool
		policy  bool
		status  int
	}{
		{name: "unissued bearer", change: func(r *scim.Request) {
			r.Credential = authentication.NewBearerCredential("not-an-issued-managed-bearer")
		}, status: 401},
		{name: "foreign tenant", tenant: "AAAAAAAAAAAAAAAAAAAAAQ", status: 401},
		{name: "current operation denial", policy: true, status: 403},
		{name: "missing gate", nilGate: true, status: 503},
		{name: "negative ceiling", maximum: -1, status: 503},
		{name: "oversized ceiling", maximum: scim.DefaultGroupMembers + 1, status: 503},
		{name: "missing target", change: func(r *scim.Request) { r.ResourceID = "" }, status: 404},
		{name: "missing If-Match", change: func(r *scim.Request) { r.IfMatch = "" }, status: 428},
		{name: "weak If-Match", change: func(r *scim.Request) { r.IfMatch = `W/"weak"` }, status: 400},
		{name: "unexpected body", change: func(r *scim.Request) { r.ContentType = "application/scim+json"; r.Body = []byte(`{}`) }, status: 400},
		{name: "oversized optional alias", change: func(r *scim.Request) { r.IdempotencyKey = strings.Repeat("x", 257) }, status: 400},
		{name: "User Delete", change: func(r *scim.Request) { r.Operation = scim.UserDelete }, status: 501},
		{name: "Group Get", change: func(r *scim.Request) { r.Operation = scim.GroupGet }, status: 501},
		{name: "Group Replace", change: func(r *scim.Request) { r.Operation = scim.GroupReplace }, status: 501},
		{name: "Group Patch", change: func(r *scim.Request) { r.Operation = scim.GroupPatch }, status: 501},
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
			calls := 0
			var gate scim.ProtocolAdmission
			if !tc.nilGate {
				gate = func(context.Context, scim.ProtocolClient) *scim.Error { calls++; return nil }
			}
			out, err := selected.ExecuteManagedAdmittedGroupDelete(f.ctx, tenant, candidate, maximum, gate)
			assertManagedReadDenial(t, out, err, tc.status)
			if calls != 0 {
				t.Fatal("Group Delete preflight denial invoked admission")
			}
			assertUnchanged(t)
		})
	}
	for _, status := range []int{403, 429} {
		calls := 0
		out, err := selected.ExecuteManagedAdmittedGroupDelete(f.ctx, f.tenant, request, 0, func(ctx context.Context, client scim.ProtocolClient) *scim.Error {
			calls++
			assertManagedGroupDeleteClient(t, f, ctx, client)
			assertUnchanged(t)
			if status == 429 {
				return scim.NewRateLimitedError(1250 * time.Millisecond)
			}
			return scim.NewError(status, "")
		})
		assertManagedReadDenial(t, out, err, status)
		var protocol *scim.Error
		if !errors.As(err, &protocol) || protocol.SCIMType() != "" || status == 429 && protocol.RetryAfterSeconds() != 2 || calls != 1 {
			t.Fatal("Group Delete gate denial lost redaction, retry delay or exactly-once admission")
		}
		assertUnchanged(t)
	}
}

func TestManagedConnectionAdmittedGroupDeleteRetainsCanonicalAliasReplayAndRelatedResources(t *testing.T) {
	f, service := managedGroupCreateFixture(t)
	selected := managedGroupDeleter(t, service)
	installSource(t, f.ctx, f.pool, organizationpg.DirectoryMembershipMigrationSource{Version: 52})
	connection := managedGroupReplaceConnection(t, f, service, "group-delete-owner")
	other := managedGroupReplaceConnection(t, f, service, "group-delete-other")
	user, err := service.ExecuteManagedProvisioning(f.ctx, f.tenant, scim.Request{Operation: scim.UserCreate, Credential: connection.Bearer, IdempotencyKey: "group-delete-user", ContentType: "application/scim+json", Body: []byte(`{"schemas":["urn:ietf:params:scim:schemas:core:2.0:User"],"userName":"group-delete-member"}`)})
	if err != nil || user.Status != 201 {
		t.Fatal("seed actual managed User member", err)
	}
	userID := parseNativeUser(t, user).ID
	var kernelUser string
	if err := f.pool.Raw().QueryRow(f.ctx, `SELECT user_id FROM scim.users WHERE tenant_id=$1 AND resource_id=$2`, string(f.tenant), userID).Scan(&kernelUser); err != nil {
		t.Fatal("read actual source-owned User identity binding", err)
	}
	scope := connection.Connection.Scope()
	seedManagedWithdrawalMember(t, f, kernelUser)
	seedManagedWithdrawalGrant(t, f, kernelUser, string(scope.ProviderID), string(scope.ProviderConnectionID), userID)
	groups, child := managedGroupReplaceSeed(t, f, service, connection.Bearer, "group-delete-child", `{"schemas":["urn:ietf:params:scim:schemas:core:2.0:Group"],"displayName":"Nested member remains"}`)
	childID := groupID(t, child)
	_, created := managedGroupReplaceSeed(t, f, service, connection.Bearer, "group-delete-parent", `{"schemas":["urn:ietf:params:scim:schemas:core:2.0:Group"],"displayName":"Delete parent only","members":[{"value":"`+userID+`","type":"User"},{"value":"`+childID+`","type":"Group"}]}`)
	id := groupID(t, created)
	request := scim.Request{Operation: scim.GroupDelete, Credential: connection.Bearer, ResourceID: id, IfMatch: created.ETag}
	relatedState := func(t *testing.T) string {
		t.Helper()
		var state string
		if err := f.pool.Raw().QueryRow(f.ctx, `SELECT jsonb_build_object(
 'user',(SELECT to_jsonb(u) FROM identity.users u WHERE tenant_id=$1 AND user_id=$2),
 'attributes',(SELECT jsonb_agg(to_jsonb(a) ORDER BY to_jsonb(a)::text) FROM identity.user_attributes a WHERE tenant_id=$1 AND user_id=$2),
 'projection',(SELECT to_jsonb(s) FROM scim.users s WHERE tenant_id=$1 AND resource_id=$3),
 'organization',(SELECT to_jsonb(o) FROM organization.organizations o WHERE tenant_id=$1 AND organization_id=$4),
 'membership',(SELECT to_jsonb(m) FROM organization.memberships m WHERE tenant_id=$1 AND organization_id=$4 AND user_id=$2),
 'grant',(SELECT to_jsonb(g) FROM organization.directory_membership_grants g WHERE tenant_id=$1 AND organization_id=$4 AND user_id=$2 AND resource_id=$3),
 'nested',(SELECT to_jsonb(g) FROM scim.groups g WHERE tenant_id=$1 AND resource_id=$5))::text`, string(f.tenant), kernelUser, userID, string(f.organization), childID).Scan(&state); err != nil {
			t.Fatal("snapshot actual member, nested Group and organization resources", err)
		}
		return state
	}
	beforeRelated := relatedState(t)
	assertLive := func(t *testing.T) {
		t.Helper()
		out, err := groups.Execute(f.ctx, scim.Request{Operation: scim.GroupGet, Credential: connection.Bearer, ResourceID: id})
		if err != nil || out.Status != 200 || out.ETag != created.ETag || !bytes.Equal(out.Body, created.Body) || relatedState(t) != beforeRelated {
			t.Fatal("denied Group Delete changed target or related resources", err)
		}
	}
	for _, tc := range []struct {
		name   string
		change func(*scim.Request)
		status int
	}{
		{"stale target", func(r *scim.Request) { r.IfMatch = `"stale-version"` }, 412},
		{"foreign connection", func(r *scim.Request) { r.Credential = other.Bearer }, 404},
	} {
		t.Run(tc.name, func(t *testing.T) {
			candidate := request
			tc.change(&candidate)
			calls := 0
			out, err := selected.ExecuteManagedAdmittedGroupDelete(f.ctx, f.tenant, candidate, 2, func(ctx context.Context, client scim.ProtocolClient) *scim.Error {
				calls++
				assertManagedGroupDeleteClient(t, f, ctx, client)
				return nil
			})
			assertManagedReadDenial(t, out, err, tc.status)
			if calls != 1 {
				t.Fatal("stale or foreign Group Delete did not consume exactly one current admission")
			}
			assertLive(t)
		})
	}
	before := managedGroupCreateState(t, f)
	calls := 0
	gate := func(ctx context.Context, client scim.ProtocolClient) *scim.Error {
		calls++
		assertManagedGroupDeleteClient(t, f, ctx, client)
		if calls == 1 && managedGroupCreateState(t, f) != before {
			t.Fatal("native Group deletion effects preceded admission")
		}
		return nil
	}
	out, err := selected.ExecuteManagedAdmittedGroupDelete(f.ctx, f.tenant, request, 2, gate)
	assertManagedGroupDeleted(t, out, err)
	configuration, writes := service.config, service.writer().config
	configuration.Writes = &writes
	restarted, err := NewManagedConnectionService(f.pool, configuration)
	if err != nil {
		t.Fatal("reconstruct managed Group Delete runtime without invocation state", err)
	}
	selected = managedGroupDeleter(t, restarted)
	committedState := managedGroupCreateState(t, f)
	out, err = selected.ExecuteManagedAdmittedGroupDelete(f.ctx, f.tenant, request, 2, gate)
	assertManagedGroupDeleted(t, out, err)
	if calls != 2 || managedGroupCreateState(t, f) != committedState {
		t.Fatal("durable headerless Group Delete retry duplicated native effects")
	}
	alias := request
	alias.IdempotencyKey = "group-delete-original-alias"
	out, err = selected.ExecuteManagedAdmittedGroupDelete(f.ctx, f.tenant, alias, 2, gate)
	assertManagedGroupDeleted(t, out, err)
	afterAlias := managedGroupCreateState(t, f)
	for _, retry := range []scim.Request{request, alias} {
		priorCalls := calls
		out, err := selected.ExecuteManagedAdmittedGroupDelete(f.ctx, f.tenant, retry, 2, gate)
		assertManagedGroupDeleted(t, out, err)
		if calls != priorCalls+1 || managedGroupCreateState(t, f) != afterAlias {
			t.Fatal("headerless/optional-alias replay did not share one original Group deletion")
		}
	}
	t.Run("reused alias cannot retarget", func(t *testing.T) {
		candidate := alias
		candidate.ResourceID, candidate.IfMatch = childID, child.ETag
		priorCalls := calls
		out, err := selected.ExecuteManagedAdmittedGroupDelete(f.ctx, f.tenant, candidate, 2, gate)
		assertManagedReadDenial(t, out, err, 409)
		if calls != priorCalls+1 || managedGroupCreateState(t, f) != afterAlias || relatedState(t) != beforeRelated {
			t.Fatal("reused Group Delete alias retargeted original custody or deleted a nested member")
		}
	})
	t.Run("replay still requires current authority and admission", func(t *testing.T) {
		f.deny.Store(true)
		attempts := 0
		out, err := selected.ExecuteManagedAdmittedGroupDelete(f.ctx, f.tenant, alias, 2, func(context.Context, scim.ProtocolClient) *scim.Error { attempts++; return nil })
		f.deny.Store(false)
		assertManagedReadDenial(t, out, err, 403)
		if attempts != 0 || managedGroupCreateState(t, f) != afterAlias {
			t.Fatal("historical Group deletion bypassed current operation authority")
		}
		out, err = selected.ExecuteManagedAdmittedGroupDelete(f.ctx, f.tenant, request, 2, func(context.Context, scim.ProtocolClient) *scim.Error { attempts++; return scim.NewError(403, "") })
		assertManagedReadDenial(t, out, err, 403)
		if attempts != 1 || managedGroupCreateState(t, f) != afterAlias {
			t.Fatal("historical Group deletion bypassed current admission")
		}
	})
	var generation, committed, audits, events int
	var tombstone, empty bool
	if err := f.pool.Raw().QueryRow(f.ctx, `SELECT s.generation,s.deleted_at IS NOT NULL,s.resource=convert_to('null','UTF8'),
 (SELECT count(*) FROM identity.commands WHERE purpose=$3 AND state='committed'),
 (SELECT count(*) FROM audit.identity_command_bindings a JOIN identity.commands c USING(command_id) WHERE c.purpose=$3 AND c.state='committed'),
 (SELECT count(*) FROM public.identity_outbox_bindings o JOIN identity.commands c USING(command_id) WHERE c.purpose=$3)
FROM scim.groups s WHERE s.tenant_id=$1 AND s.resource_id=$2`, string(f.tenant), id, string(scim.GroupDelete)).Scan(&generation, &tombstone, &empty, &committed, &audits, &events); err != nil || generation != 2 || !tombstone || !empty || committed != 1 || audits != 1 || events != 1 {
		t.Fatalf("Group Delete/replay custody mismatch: generation=%d tombstone=%t empty projection=%t committed commands=%d committed audits=%d outbox events=%d query failed=%t", generation, tombstone, empty, committed, audits, events, err != nil)
	}
	if relatedState(t) != beforeRelated {
		t.Fatal("Group Delete changed User, nested Group, membership contribution or organization resources")
	}
	read, err := groups.Execute(f.ctx, scim.Request{Operation: scim.GroupGet, Credential: connection.Bearer, ResourceID: id})
	assertManagedReadDenial(t, read, err, 404)
	for _, member := range []struct {
		operation scim.Operation
		id        string
		original  scim.Response
	}{{scim.UserGet, userID, user}, {scim.GroupGet, childID, child}} {
		request := scim.Request{Operation: member.operation, Credential: connection.Bearer, ResourceID: member.id}
		var read scim.Response
		if member.operation == scim.UserGet {
			read, err = service.ExecuteManagedProvisioning(f.ctx, f.tenant, request)
		} else {
			read, err = groups.Execute(f.ctx, request)
		}
		if err != nil || read.Status != 200 || read.ETag != member.original.ETag || !bytes.Equal(read.Body, member.original.Body) {
			t.Fatal("Group Delete changed a referenced member's existing read behavior", err)
		}
	}
	out, err = groups.Execute(f.ctx, request)
	assertManagedGroupDeleted(t, out, err)
	if managedGroupCreateState(t, f) != afterAlias {
		t.Fatal("ordinary Group Delete no longer shares canonical original replay")
	}
}
