//go:build integration

package scimpostgres

import (
	"bytes"
	"context"
	"errors"
	"testing"
	"time"

	authentication "github.com/faustbrian/go-authentication/v2"
	identity "github.com/faustbrian/go-identity"
	scim "github.com/faustbrian/go-scim"
)

func TestManagedConnectionAdmittedCreateUsesIssuedBearerAndCanonicalNativeWrite(t *testing.T) {
	f := newManagedConnectionAdminFixture(t)
	service, _ := newManagedConnectionWriteFixture(t, f)
	connection, err := service.ConnectionCreate(f.ctx, managedConnectionCreateRequest(t, f, "managed-admitted-create-provider", "managed-admitted-create-connection"))
	if err != nil || connection.Bearer.Token() == "" {
		t.Fatal("issue actual managed connection before admitted Create", err)
	}
	selected, ok := any(service).(interface {
		ExecuteManagedAdmittedCreate(context.Context, identity.TenantID, scim.Request, scim.ProtocolAdmission) (scim.Response, error)
	})
	if !ok {
		t.Fatal("managed connection service has no explicit admitted User Create selection")
	}
	request := scim.Request{Operation: scim.UserCreate, Credential: connection.Bearer, IdempotencyKey: "managed-admitted-create-original", ContentType: "application/scim+json", Body: []byte(`{"schemas":["urn:ietf:params:scim:schemas:core:2.0:User"],"userName":"managed-admitted-person"}`)}
	snapshot := func() string {
		t.Helper()
		var state string
		if err := f.pool.Raw().QueryRow(f.ctx, `SELECT jsonb_build_object(
   'users',(SELECT count(*) FROM identity.users),
   'attributes',(SELECT count(*) FROM identity.user_attributes),
   'projections',(SELECT count(*) FROM scim.users),
   'commands',(SELECT count(*) FROM identity.commands),
   'request_mappings',(SELECT count(*) FROM identity.request_key_mappings),
   'audits',(SELECT count(*) FROM audit.records),
   'outbox',(SELECT count(*) FROM public.outbox_messages))::text`).Scan(&state); err != nil {
			t.Fatal("read exact native protected-effect counts", err)
		}
		return state
	}
	before := snapshot()
	attempts := 0
	var denial *scim.Error
	gate := func(ctx context.Context, client scim.ProtocolClient) *scim.Error {
		attempts++
		deadline, bounded := ctx.Deadline()
		if ctx.Err() != nil || !bounded || !deadline.After(time.Now()) || time.Until(deadline) > f.config.MaximumDuration || client.ID != f.config.ActorID || client.TenantID != f.tenant {
			t.Error("Create gate lost current configured service-account client, tenant or original bounded context")
			return scim.NewError(503, "")
		}
		return denial
	}
	assertUnchanged := func() {
		t.Helper()
		if after := snapshot(); after != before {
			t.Fatal("unadmitted Create changed command custody, identity/projection, attributes, audit or outbox")
		}
	}

	t.Run("invalid credential does not charge", func(t *testing.T) {
		invalid := request
		invalid.Credential = authentication.NewBearerCredential("not-an-issued-managed-bearer")
		out, err := selected.ExecuteManagedAdmittedCreate(f.ctx, f.tenant, invalid, gate)
		assertManagedReadDenial(t, out, err, 401)
		if attempts != 0 {
			t.Fatal("unknown managed credential charged Create admission")
		}
		assertUnchanged()
	})
	t.Run("foreign tenant does not charge", func(t *testing.T) {
		out, err := selected.ExecuteManagedAdmittedCreate(f.ctx, "AAAAAAAAAAAAAAAAAAAAAQ", request, gate)
		assertManagedReadDenial(t, out, err, 401)
		if attempts != 0 {
			t.Fatal("foreign tenant charged Create admission")
		}
		assertUnchanged()
	})
	t.Run("native authorization does not charge", func(t *testing.T) {
		f.deny.Store(true)
		defer f.deny.Store(false)
		out, err := selected.ExecuteManagedAdmittedCreate(f.ctx, f.tenant, request, gate)
		assertManagedReadDenial(t, out, err, 403)
		if attempts != 0 {
			t.Fatal("native operation denial charged Create admission")
		}
		assertUnchanged()
	})
	t.Run("malformed input does not charge", func(t *testing.T) {
		for _, body := range []string{
			`{"schemas":["urn:ietf:params:scim:schemas:core:2.0:User"],"userName":"first","USERNAME":"collision"}`,
			`{"schemas":["urn:ietf:params:scim:schemas:core:2.0:User"],"displayName":"missing username"}`,
		} {
			malformed := request
			malformed.Body = []byte(body)
			out, err := selected.ExecuteManagedAdmittedCreate(f.ctx, f.tenant, malformed, gate)
			assertManagedReadDenial(t, out, err, 400)
		}
		if attempts != 0 {
			t.Fatal("malformed or schema-invalid Create charged admission")
		}
		assertUnchanged()
	})
	t.Run("missing gate fails closed", func(t *testing.T) {
		out, err := selected.ExecuteManagedAdmittedCreate(f.ctx, f.tenant, request, nil)
		assertManagedReadDenial(t, out, err, 503)
		assertUnchanged()
	})
	t.Run("other operations remain unselected", func(t *testing.T) {
		for _, operation := range []scim.Operation{scim.UserGet, scim.UserList, scim.UserReplace, scim.UserPatch, scim.UserDelete, scim.GroupCreate, scim.Bulk} {
			unsupported := request
			unsupported.Operation = operation
			out, err := selected.ExecuteManagedAdmittedCreate(f.ctx, f.tenant, unsupported, gate)
			assertManagedReadDenial(t, out, err, 501)
		}
		if attempts != 0 {
			t.Fatal("unselected operation charged Create admission")
		}
		assertUnchanged()
	})
	t.Run("quota denial preserves original key without effects", func(t *testing.T) {
		denial = scim.NewRateLimitedError(1250 * time.Millisecond)
		out, err := selected.ExecuteManagedAdmittedCreate(f.ctx, f.tenant, request, gate)
		assertManagedReadDenial(t, out, err, 429)
		var limited *scim.Error
		if !errors.As(err, &limited) || limited.RetryAfterSeconds() != 2 || attempts != 1 {
			t.Fatal("Create quota denial lost bounded retry metadata or charged more than once")
		}
		assertUnchanged()
	})
	t.Run("unavailable gate has no protected effects", func(t *testing.T) {
		denial = scim.NewError(503, "")
		out, err := selected.ExecuteManagedAdmittedCreate(f.ctx, f.tenant, request, gate)
		assertManagedReadDenial(t, out, err, 503)
		if attempts != 2 {
			t.Fatal("unavailable Create gate was not invoked exactly once")
		}
		assertUnchanged()
	})
	t.Run("gate cancellation overrides denial before effects", func(t *testing.T) {
		ctx, cancel := context.WithCancel(f.ctx)
		defer cancel()
		calls := 0
		out, err := selected.ExecuteManagedAdmittedCreate(ctx, f.tenant, request, func(ctx context.Context, client scim.ProtocolClient) *scim.Error {
			calls++
			if client.ID != f.config.ActorID || client.TenantID != f.tenant {
				t.Error("canceled gate lost exact configured client")
			}
			cancel()
			return scim.NewError(403, "")
		})
		assertManagedReadDenial(t, out, err, 503)
		if calls != 1 {
			t.Fatal("canceled Create gate was not invoked exactly once")
		}
		assertUnchanged()
	})
	t.Run("earlier gate deadline expires before effects", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(f.ctx, 250*time.Millisecond)
		defer cancel()
		originalDeadline, _ := ctx.Deadline()
		calls := 0
		out, err := selected.ExecuteManagedAdmittedCreate(ctx, f.tenant, request, func(gateCtx context.Context, client scim.ProtocolClient) *scim.Error {
			calls++
			deadline, bounded := gateCtx.Deadline()
			if !bounded || deadline.After(originalDeadline) || client.ID != f.config.ActorID || client.TenantID != f.tenant {
				t.Error("Create gate renewed its earlier deadline or substituted configured client")
			}
			<-gateCtx.Done()
			return nil
		})
		assertManagedReadDenial(t, out, err, 503)
		if calls != 1 {
			t.Fatal("deadline-expired Create gate was not invoked exactly once")
		}
		assertUnchanged()
	})

	denial = nil
	created, err := selected.ExecuteManagedAdmittedCreate(f.ctx, f.tenant, request, gate)
	if err != nil || created.Status != 201 || attempts != 3 || parseNativeUser(t, created).UserName != "managed-admitted-person" {
		t.Fatal("allowed original key did not execute exactly one native User create", err)
	}
	id := parseNativeUser(t, created).ID
	committed := snapshot()
	replay, err := selected.ExecuteManagedAdmittedCreate(f.ctx, f.tenant, request, gate)
	if err != nil || replay.Status != created.Status || replay.ETag != created.ETag || replay.Location != created.Location || !bytes.Equal(replay.Body, created.Body) || attempts != 4 {
		t.Fatal("same-key admitted retry changed the exact original User result or charge count", err)
	}
	if after := snapshot(); after != committed {
		t.Fatal("same-key admitted replay duplicated native protected effects")
	}
	get := scim.Request{Operation: scim.UserGet, Credential: connection.Bearer, ResourceID: id}
	read, err := service.ExecuteManagedProvisioning(f.ctx, f.tenant, get)
	if err != nil || read.Status != 200 || parseNativeUser(t, read).ID != id || read.ETag != created.ETag {
		t.Fatal("ordinary native read did not observe the persisted admitted User", err)
	}
	var users, projections, attributes, commands, audits, events int
	if err := f.pool.Raw().QueryRow(f.ctx, `SELECT
  (SELECT count(*) FROM identity.users u JOIN scim.users s USING(tenant_id,user_id) WHERE s.tenant_id=$1 AND s.resource_id=$2),
  (SELECT count(*) FROM scim.users WHERE tenant_id=$1 AND resource_id=$2),
  (SELECT count(*) FROM identity.user_attributes a JOIN scim.users s USING(tenant_id,user_id) WHERE s.tenant_id=$1 AND s.resource_id=$2),
  (SELECT count(*) FROM identity.commands c JOIN scim.users s ON c.command_id=decode(translate(s.command_id,'-_','+/')||'==','base64') WHERE s.tenant_id=$1 AND s.resource_id=$2 AND c.state='committed'),
  (SELECT count(*) FROM audit.identity_command_bindings a JOIN scim.users s ON a.command_id=decode(translate(s.command_id,'-_','+/')||'==','base64') WHERE s.tenant_id=$1 AND s.resource_id=$2),
  (SELECT count(*) FROM public.identity_outbox_bindings o JOIN scim.users s ON o.command_id=decode(translate(s.command_id,'-_','+/')||'==','base64') WHERE s.tenant_id=$1 AND s.resource_id=$2)`, string(f.tenant), id).Scan(&users, &projections, &attributes, &commands, &audits, &events); err != nil || users != 1 || projections != 1 || attributes != 1 || commands != 1 || audits != 1 || events != 1 {
		t.Fatal("admitted Create/replay did not retain exactly one native User, selected attribute, projection, command, protected audit and outbox", err)
	}
}
