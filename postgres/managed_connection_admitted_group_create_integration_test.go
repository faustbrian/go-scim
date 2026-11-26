//go:build integration

package scimpostgres

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"

	authentication "github.com/faustbrian/go-authentication/v2"
	identity "github.com/faustbrian/go-identity"
	scim "github.com/faustbrian/go-scim"
)

type managedAdmittedGroupCreator interface {
	ExecuteManagedAdmittedGroupCreate(context.Context, identity.TenantID, scim.Request, int, scim.ProtocolAdmission) (scim.Response, error)
}

func managedGroupCreateFixture(t *testing.T) (*managedConnectionAdminFixture, *ManagedConnectionService) {
	t.Helper()
	f := newManagedConnectionAdminFixture(t)
	service, _ := newManagedConnectionWriteFixture(t, f)
	history, err := (GroupsMigrationSource{Base: UsersMigrationSource{Base: MigrationSource{Version: 40}, Version: 41}, Version: 43}).Load(f.ctx)
	if err != nil {
		t.Fatal("load existing native Groups migration", err)
	}
	if _, err := f.pool.Raw().Exec(f.ctx, history[len(history)-1].UpSQL()); err != nil {
		t.Fatal("apply existing native Groups migration", err)
	}
	return f, service
}

func managedGroupCreateState(t *testing.T, f *managedConnectionAdminFixture) string {
	t.Helper()
	var state string
	if err := f.pool.Raw().QueryRow(f.ctx, `SELECT jsonb_build_object(
 'users',(SELECT count(*) FROM identity.users),
 'attributes',(SELECT count(*) FROM identity.user_attributes),
 'user_projections',(SELECT jsonb_agg(jsonb_build_array(resource_id,generation,encode(resource,'base64')) ORDER BY resource_id) FROM scim.users),
 'groups',(SELECT jsonb_agg(jsonb_build_array(resource_id,generation,command_id,encode(resource,'base64')) ORDER BY resource_id) FROM scim.groups),
 'commands',(SELECT count(*) FROM identity.commands),
 'request_mappings',(SELECT count(*) FROM identity.request_key_mappings),
 'audits',(SELECT count(*) FROM audit.records),
 'outbox',(SELECT count(*) FROM public.outbox_messages))::text`).Scan(&state); err != nil {
		t.Fatal("observe native Group protected-effect state", err)
	}
	return state
}

func assertManagedGroupCreateClient(t *testing.T, f *managedConnectionAdminFixture, ctx context.Context, client scim.ProtocolClient) {
	t.Helper()
	deadline, bounded := ctx.Deadline()
	if ctx.Err() != nil || !bounded || !deadline.After(time.Now()) || time.Until(deadline) > f.config.MaximumDuration || client.ID != f.config.ActorID || client.TenantID != f.tenant {
		t.Fatal("Group Create gate lost the configured service-account client, exact tenant or original bounded context")
	}
}

func TestManagedConnectionAdmittedGroupCreateDenialsPrecedeNativeEffects(t *testing.T) {
	f, service := managedGroupCreateFixture(t)
	connection, err := service.ConnectionCreate(f.ctx, managedConnectionCreateRequest(t, f, "managed-group-create-provider", "managed-group-create-denials"))
	if err != nil || connection.Bearer.Token() == "" {
		t.Fatal("issue actual managed bearer for Group Create", err)
	}
	selected, ok := any(service).(managedAdmittedGroupCreator)
	if !ok {
		t.Fatal("managed connection service has no explicit admitted Group Create selection")
	}
	request := scim.Request{Operation: scim.GroupCreate, Credential: connection.Bearer, IdempotencyKey: "managed-group-create-original", ContentType: "application/scim+json", Body: []byte(`{"schemas":["urn:ietf:params:scim:schemas:core:2.0:Group"],"displayName":"Original"}`)}
	before := managedGroupCreateState(t, f)
	assertUnchanged := func(t *testing.T) {
		t.Helper()
		if managedGroupCreateState(t, f) != before {
			t.Fatal("unadmitted Group Create changed resources, commands, request mappings, audit or outbox")
		}
	}

	t.Run("preflight denials do not invoke admission", func(t *testing.T) {
		for _, tc := range []struct {
			name      string
			operation scim.Operation
			tenant    identity.TenantID
			bearer    authentication.BearerCredential
			body      string
			maximum   int
			nilGate   bool
			policy    bool
			canceled  bool
			status    int
		}{
			{name: "unissued bearer", bearer: authentication.NewBearerCredential("not-an-issued-managed-bearer"), status: 401},
			{name: "foreign tenant", tenant: "AAAAAAAAAAAAAAAAAAAAAQ", status: 401},
			{name: "native authorization", policy: true, status: 403},
			{name: "missing gate", nilGate: true, status: 503},
			{name: "canceled parent", canceled: true, status: 503},
			{name: "negative ceiling", maximum: -1, status: 503},
			{name: "oversized ceiling", maximum: scim.DefaultGroupMembers + 1, status: 503},
			{name: "malformed Group", body: `{"schemas":["urn:ietf:params:scim:schemas:core:2.0:Group"],"externalId":"missing displayName"}`, status: 400},
			{name: "case-colliding attributes", body: `{"schemas":["urn:ietf:params:scim:schemas:core:2.0:Group"],"displayName":"one","DISPLAYNAME":"two"}`, status: 400},
			{name: "User create", operation: scim.UserCreate, status: 501},
			{name: "Group get", operation: scim.GroupGet, status: 501},
			{name: "Group list", operation: scim.GroupList, status: 501},
			{name: "Group search", operation: scim.GroupSearch, status: 501},
			{name: "Group replace", operation: scim.GroupReplace, status: 501},
			{name: "Group patch", operation: scim.GroupPatch, status: 501},
			{name: "Group delete", operation: scim.GroupDelete, status: 501},
			{name: "discovery", operation: scim.ServiceProviderConfig, status: 501},
			{name: "Bulk", operation: scim.Bulk, status: 501},
		} {
			t.Run(tc.name, func(t *testing.T) {
				candidate := request
				if tc.operation != "" {
					candidate.Operation = tc.operation
				}
				if tc.bearer.Token() != "" {
					candidate.Credential = tc.bearer
				}
				if tc.body != "" {
					candidate.Body = []byte(tc.body)
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
				out, err := selected.ExecuteManagedAdmittedGroupCreate(ctx, tenant, candidate, maximum, gate)
				assertManagedReadDenial(t, out, err, tc.status)
				if calls != 0 {
					t.Fatal("Group Create preflight denial invoked admission")
				}
				assertUnchanged(t)
			})
		}
	})

	for _, denial := range []string{"quota", "policy", "unavailable", "panic", "cancel", "deadline"} {
		t.Run("gate/"+denial, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(f.ctx, 250*time.Millisecond)
			defer cancel()
			originalDeadline, _ := ctx.Deadline()
			calls, status := 0, 503
			out, err := selected.ExecuteManagedAdmittedGroupCreate(ctx, f.tenant, request, scim.DefaultGroupMembers, func(ctx context.Context, client scim.ProtocolClient) *scim.Error {
				calls++
				assertManagedGroupCreateClient(t, f, ctx, client)
				deadline, _ := ctx.Deadline()
				if deadline.After(originalDeadline) {
					t.Fatal("Group Create gate renewed the earlier parent deadline")
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
				t.Fatal("Group Create denial lost redaction, positive retry delay or exactly-once admission")
			}
			assertUnchanged(t)
		})
	}
}

func TestManagedConnectionAdmittedGroupCreateRetainsOriginalAndMemberIsolation(t *testing.T) {
	f, service := managedGroupCreateFixture(t)
	selected, ok := any(service).(managedAdmittedGroupCreator)
	if !ok {
		t.Fatal("managed connection service has no explicit admitted Group Create selection")
	}
	createConnection := func(key string) ConnectionCreateResult {
		t.Helper()
		result, err := service.ConnectionCreate(f.ctx, managedConnectionCreateRequest(t, f, "same-group-provider", key))
		if err != nil || result.Bearer.Token() == "" {
			t.Fatal("issue distinct same-provider managed bearer", err)
		}
		return result
	}
	connection, other := createConnection("group-create-owner"), createConnection("group-create-other")
	seedMembers := func(bearer authentication.BearerCredential, name string) (scim.Response, scim.Response) {
		t.Helper()
		user, err := service.ExecuteManagedProvisioning(f.ctx, f.tenant, scim.Request{Operation: scim.UserCreate, Credential: bearer, IdempotencyKey: name + "-user", ContentType: "application/scim+json", Body: []byte(`{"schemas":["urn:ietf:params:scim:schemas:core:2.0:User"],"userName":"` + name + `"}`)})
		if err != nil || user.Status != 201 {
			t.Fatal("seed actual source-owned User member", err)
		}
		source, err := service.loadManagedProvisioning(f.ctx, f.tenant, bearer)
		if err != nil {
			t.Fatal("load exact native member scope", err)
		}
		groups, err := NewGroupsService(source, scim.DefaultGroupMembers)
		if err != nil {
			t.Fatal("compose existing native Groups fixture", err)
		}
		group, err := groups.Execute(f.ctx, scim.Request{Operation: scim.GroupCreate, Credential: bearer, IdempotencyKey: name + "-group", ContentType: "application/scim+json", Body: []byte(`{"schemas":["urn:ietf:params:scim:schemas:core:2.0:Group"],"displayName":"` + name + `"}`)})
		if err != nil || group.Status != 201 {
			t.Fatal("seed actual source-owned Group member", err)
		}
		return user, group
	}
	user, child := seedMembers(connection.Bearer, "owned-member")
	foreignUser, foreignGroup := seedMembers(other.Bearer, "foreign-member")
	userID, childID := parseNativeUser(t, user).ID, groupID(t, child)
	request := scim.Request{Operation: scim.GroupCreate, Credential: connection.Bearer, IdempotencyKey: "managed-group-create-original-with-members", ContentType: "application/scim+json", Body: []byte(`{"schemas":["urn:ietf:params:scim:schemas:core:2.0:Group"],"displayName":"Parent","members":[{"value":"` + userID + `","type":"User"},{"value":"` + childID + `","type":"Group"}]}`)}
	before := managedGroupCreateState(t, f)
	calls := 0
	gate := func(ctx context.Context, client scim.ProtocolClient) *scim.Error {
		calls++
		assertManagedGroupCreateClient(t, f, ctx, client)
		if calls == 1 && managedGroupCreateState(t, f) != before {
			t.Fatal("native Group command or projection effects preceded admission")
		}
		return nil
	}
	if out, err := selected.ExecuteManagedAdmittedGroupCreate(f.ctx, f.tenant, request, 0, gate); protocolStatus(err) != 400 || out.Status != 0 || calls != 0 || managedGroupCreateState(t, f) != before {
		t.Fatal("zero member ceiling did not reject members before admission or effects", err)
	}
	created, err := selected.ExecuteManagedAdmittedGroupCreate(f.ctx, f.tenant, request, 2, gate)
	if err != nil || created.Status != 201 || calls != 1 {
		t.Fatal("allowed Group Create did not commit through the existing native Store", err)
	}
	id := groupID(t, created)
	var resource struct {
		Members []struct{ Value, Type string }
	}
	if json.Unmarshal(created.Body, &resource) != nil || len(resource.Members) != 2 || resource.Members[0].Value != userID || resource.Members[0].Type != "User" || resource.Members[1].Value != childID || resource.Members[1].Type != "Group" {
		t.Fatal("native Group response lost exact typed User and Group links")
	}
	committed := managedGroupCreateState(t, f)
	configuration, writes := service.config, service.writer().config
	configuration.Writes = &writes
	restarted, err := NewManagedConnectionService(f.pool, configuration)
	if err != nil {
		t.Fatal("reconstruct managed runtime without invocation memory", err)
	}
	replay, err := any(restarted).(managedAdmittedGroupCreator).ExecuteManagedAdmittedGroupCreate(f.ctx, f.tenant, request, 2, gate)
	if err != nil || replay.Status != created.Status || replay.ETag != created.ETag || replay.Location != created.Location || replay.ContentType != created.ContentType || !bytes.Equal(replay.Body, created.Body) || calls != 2 || managedGroupCreateState(t, f) != committed {
		t.Fatal("durable same-key replay changed the original Group, metadata, charge count or effects", err)
	}
	var projections, commands, audits, events, generation int
	if err := f.pool.Raw().QueryRow(f.ctx, `SELECT
 (SELECT count(*) FROM scim.groups WHERE tenant_id=$1 AND resource_id=$2),
 (SELECT count(*) FROM identity.commands c JOIN scim.groups s ON c.command_id=decode(translate(s.command_id,'-_','+/')||'==','base64') WHERE s.tenant_id=$1 AND s.resource_id=$2 AND c.state='committed'),
 (SELECT count(*) FROM audit.identity_command_bindings a JOIN scim.groups s ON a.command_id=decode(translate(s.command_id,'-_','+/')||'==','base64') WHERE s.tenant_id=$1 AND s.resource_id=$2),
 (SELECT count(*) FROM public.identity_outbox_bindings o JOIN scim.groups s ON o.command_id=decode(translate(s.command_id,'-_','+/')||'==','base64') WHERE s.tenant_id=$1 AND s.resource_id=$2),
 (SELECT generation FROM scim.groups WHERE tenant_id=$1 AND resource_id=$2)`, string(f.tenant), id).Scan(&projections, &commands, &audits, &events, &generation); err != nil || projections != 1 || commands != 1 || audits != 1 || events != 1 || generation != 1 {
		t.Fatal("Group replay did not retain one projection, original command, audit and outbox at generation one", err)
	}
	t.Run("changed input cannot reuse the original key", func(t *testing.T) {
		changed := request
		changed.Body = []byte(`{"schemas":["urn:ietf:params:scim:schemas:core:2.0:Group"],"displayName":"Different original"}`)
		attempts := 0
		out, err := selected.ExecuteManagedAdmittedGroupCreate(f.ctx, f.tenant, changed, 2, func(ctx context.Context, client scim.ProtocolClient) *scim.Error {
			attempts++
			assertManagedGroupCreateClient(t, f, ctx, client)
			return nil
		})
		assertManagedReadDenial(t, out, err, 409)
		if attempts != 1 || managedGroupCreateState(t, f) != committed {
			t.Fatal("changed Group input reused original custody or produced effects")
		}
	})
	t.Run("replay still requires current operation authority", func(t *testing.T) {
		f.deny.Store(true)
		defer f.deny.Store(false)
		attempts := 0
		out, err := selected.ExecuteManagedAdmittedGroupCreate(f.ctx, f.tenant, request, 2, func(context.Context, scim.ProtocolClient) *scim.Error { attempts++; return nil })
		assertManagedReadDenial(t, out, err, 403)
		if attempts != 0 || managedGroupCreateState(t, f) != committed {
			t.Fatal("historical Group result bypassed current authority")
		}
	})

	for _, member := range []struct{ key, id, kind string }{
		{"foreign-user", parseNativeUser(t, foreignUser).ID, "User"},
		{"foreign-group", groupID(t, foreignGroup), "Group"},
		{"wrong-type", userID, "Group"},
	} {
		t.Run(member.key, func(t *testing.T) {
			candidate := request
			candidate.IdempotencyKey = "managed-group-create-" + member.key
			candidate.Body = []byte(`{"schemas":["urn:ietf:params:scim:schemas:core:2.0:Group"],"displayName":"Denied foreign link","members":[{"value":"` + member.id + `","type":"` + member.kind + `"}]}`)
			attempts := 0
			out, err := selected.ExecuteManagedAdmittedGroupCreate(f.ctx, f.tenant, candidate, 2, func(ctx context.Context, client scim.ProtocolClient) *scim.Error {
				attempts++
				assertManagedGroupCreateClient(t, f, ctx, client)
				return nil
			})
			assertManagedReadDenial(t, out, err, 400)
			if attempts != 1 {
				t.Fatal("native member integrity did not run after one admitted attempt")
			}
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
		{scim.GroupGet, connection.Bearer, created, id},
	} {
		candidate := scim.Request{Operation: member.operation, Credential: member.bearer, ResourceID: member.id}
		var out scim.Response
		if member.operation == scim.UserGet {
			out, err = service.ExecuteManagedProvisioning(f.ctx, f.tenant, candidate)
		} else {
			out, err = service.ExecuteManagedAdmittedGroupRead(f.ctx, f.tenant, candidate, scim.DefaultGroupMembers, func(context.Context, scim.ProtocolClient) *scim.Error { return nil })
		}
		if err != nil || out.Status != 200 || out.ETag != member.original.ETag || !bytes.Equal(out.Body, member.original.Body) {
			t.Fatal("Group Create changed an owned or foreign member resource", err)
		}
	}
	var groups, committedGroups int
	if err := f.pool.Raw().QueryRow(f.ctx, `SELECT
 (SELECT count(*) FROM scim.groups),
 (SELECT count(*) FROM identity.commands WHERE purpose=$1 AND state='committed')`, string(scim.GroupCreate)).Scan(&groups, &committedGroups); err != nil || groups != 3 || committedGroups != 3 {
		t.Fatal("foreign or wrong-type member attempts left an additional Group or committed command", err)
	}
	foreignGet := scim.Request{Operation: scim.GroupGet, Credential: other.Bearer, ResourceID: id}
	out, err := service.ExecuteManagedAdmittedGroupRead(f.ctx, f.tenant, foreignGet, scim.DefaultGroupMembers, func(context.Context, scim.ProtocolClient) *scim.Error { return nil })
	assertManagedReadDenial(t, out, err, 404)
}
