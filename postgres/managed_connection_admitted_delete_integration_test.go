//go:build integration

package scimpostgres

import (
	"context"
	"errors"
	"testing"
	"time"

	authentication "github.com/faustbrian/go-authentication/v2"
	identity "github.com/faustbrian/go-identity"
	organizationpg "github.com/faustbrian/go-organization/postgres"
	scim "github.com/faustbrian/go-scim"
)

func TestManagedConnectionAdmittedDeletePreservesConditionalWithdrawalAndHeaderlessReplay(t *testing.T) {
	f := newManagedConnectionAdminFixture(t)
	service, _ := newManagedConnectionWriteFixture(t, f)
	installSource(t, f.ctx, f.pool, organizationpg.DirectoryMembershipMigrationSource{Version: 52})
	connection, err := service.ConnectionCreate(f.ctx, managedConnectionCreateRequest(t, f, "managed-admitted-delete", "managed-admitted-delete-connection"))
	if err != nil || connection.Bearer.Token() == "" {
		t.Fatal("issue actual managed connection for conditional admitted Delete", err)
	}
	created, err := service.ExecuteManagedProvisioning(f.ctx, f.tenant, scim.Request{Operation: scim.UserCreate, Credential: connection.Bearer, IdempotencyKey: "managed-admitted-delete-person", ContentType: "application/scim+json", Body: []byte(`{"schemas":["urn:ietf:params:scim:schemas:core:2.0:User"],"userName":"managed-admitted-delete-person"}`)})
	if err != nil || created.Status != 201 {
		t.Fatal("create actual native User before admitted Delete", err)
	}
	resourceID := parseNativeUser(t, created).ID
	var userID string
	if err := f.pool.Raw().QueryRow(f.ctx, `SELECT user_id FROM scim.users WHERE tenant_id=$1 AND resource_id=$2`, string(f.tenant), resourceID).Scan(&userID); err != nil {
		t.Fatal("read exact native identity binding", err)
	}
	seedManagedWithdrawalMember(t, f, userID)
	scope := connection.Connection.Scope()
	seedManagedWithdrawalGrant(t, f, userID, string(scope.ProviderID), string(scope.ProviderConnectionID), resourceID)
	selected, ok := any(service).(interface {
		ExecuteManagedAdmittedDelete(context.Context, identity.TenantID, scim.Request, scim.ProtocolAdmission) (scim.Response, error)
	})
	if !ok {
		t.Fatal("managed connection service has no explicit admitted conditional User Delete selection")
	}
	request := scim.Request{Operation: scim.UserDelete, Credential: connection.Bearer, ResourceID: resourceID, IfMatch: created.ETag}
	mutableState := func(t *testing.T) string {
		t.Helper()
		var state string
		if err := f.pool.Raw().QueryRow(f.ctx, `SELECT jsonb_build_object(
   'projection',(SELECT to_jsonb(s) FROM scim.users s WHERE tenant_id=$1 AND resource_id=$2),
   'identity',(SELECT to_jsonb(u) FROM identity.users u WHERE tenant_id=$1 AND user_id=$3),
   'membership',(SELECT to_jsonb(m) FROM organization.memberships m WHERE tenant_id=$1 AND organization_id=$4 AND user_id=$3),
   'grant',(SELECT to_jsonb(g) FROM organization.directory_membership_grants g WHERE tenant_id=$1 AND organization_id=$4 AND user_id=$3 AND resource_id=$2))::text`, string(f.tenant), resourceID, userID, string(f.organization)).Scan(&state); err != nil {
			t.Fatal("snapshot actual scoped User/membership contribution", err)
		}
		return state
	}
	receiptState := func(t *testing.T) string {
		t.Helper()
		var state string
		if err := f.pool.Raw().QueryRow(f.ctx, `SELECT jsonb_build_object(
   'commands',(SELECT count(*) FROM identity.commands),
   'request_mappings',(SELECT count(*) FROM identity.request_key_mappings),
   'audits',(SELECT count(*) FROM audit.records),
   'outbox',(SELECT count(*) FROM public.outbox_messages))::text`).Scan(&state); err != nil {
			t.Fatal("snapshot actual command, request mapping, audit and outbox counts", err)
		}
		return state
	}
	before, beforeReceipts := mutableState(t), receiptState(t)
	assertUnchanged := func(t *testing.T) {
		t.Helper()
		if mutableState(t) != before || receiptState(t) != beforeReceipts {
			t.Fatal("unadmitted Delete changed protected state or original command/receipt custody")
		}
	}
	attempts := 0
	var denial *scim.Error
	gate := func(ctx context.Context, client scim.ProtocolClient) *scim.Error {
		attempts++
		deadline, bounded := ctx.Deadline()
		if ctx.Err() != nil || !bounded || !deadline.After(time.Now()) || time.Until(deadline) > f.config.MaximumDuration || client.ID != f.config.ActorID || client.TenantID != f.tenant {
			t.Error("Delete gate lost exact configured native client, tenant or bounded original context")
			return scim.NewError(503, "")
		}
		return denial
	}
	t.Run("wrong bearer does not charge", func(t *testing.T) {
		invalid := request
		invalid.Credential = authentication.NewBearerCredential("not-an-issued-managed-bearer")
		out, err := selected.ExecuteManagedAdmittedDelete(f.ctx, f.tenant, invalid, gate)
		assertManagedReadDenial(t, out, err, 401)
		if attempts != 0 {
			t.Fatal("invalid bearer charged Delete admission")
		}
		assertUnchanged(t)
	})
	t.Run("wrong tenant does not charge", func(t *testing.T) {
		out, err := selected.ExecuteManagedAdmittedDelete(f.ctx, "AAAAAAAAAAAAAAAAAAAAAQ", request, gate)
		assertManagedReadDenial(t, out, err, 401)
		if attempts != 0 {
			t.Fatal("foreign tenant charged Delete admission")
		}
		assertUnchanged(t)
	})
	t.Run("current authority denial does not charge", func(t *testing.T) {
		f.deny.Store(true)
		defer f.deny.Store(false)
		out, err := selected.ExecuteManagedAdmittedDelete(f.ctx, f.tenant, request, gate)
		assertManagedReadDenial(t, out, err, 403)
		if attempts != 0 {
			t.Fatal("current native operation denial charged Delete admission")
		}
		assertUnchanged(t)
	})
	t.Run("invalid preconditions do not charge", func(t *testing.T) {
		for _, candidate := range []struct {
			version scim.Version
			status  int
		}{{"", 428}, {`W/"weak"`, 400}, {"*", 400}} {
			invalid := request
			invalid.IfMatch = candidate.version
			out, err := selected.ExecuteManagedAdmittedDelete(f.ctx, f.tenant, invalid, gate)
			assertManagedReadDenial(t, out, err, candidate.status)
		}
		if attempts != 0 {
			t.Fatal("missing or invalid If-Match charged Delete admission")
		}
		assertUnchanged(t)
	})
	t.Run("missing gate and other operations remain closed", func(t *testing.T) {
		out, err := selected.ExecuteManagedAdmittedDelete(f.ctx, f.tenant, request, nil)
		assertManagedReadDenial(t, out, err, 503)
		for _, operation := range []scim.Operation{scim.UserCreate, scim.UserGet, scim.UserList, scim.UserReplace, scim.UserPatch, scim.GroupDelete, scim.Bulk} {
			other := request
			other.Operation = operation
			out, err := selected.ExecuteManagedAdmittedDelete(f.ctx, f.tenant, other, gate)
			assertManagedReadDenial(t, out, err, 501)
		}
		if attempts != 0 {
			t.Fatal("missing or unselected admission reached gate")
		}
		assertUnchanged(t)
	})
	t.Run("quota denial charges once without receipt or effects", func(t *testing.T) {
		denial = scim.NewRateLimitedError(1250 * time.Millisecond)
		out, err := selected.ExecuteManagedAdmittedDelete(f.ctx, f.tenant, request, gate)
		var limited *scim.Error
		assertManagedReadDenial(t, out, err, 429)
		if !errors.As(err, &limited) || limited.RetryAfterSeconds() != 2 || attempts != 1 {
			t.Fatal("Delete quota denial lost its bounded positive retry metadata or charged twice")
		}
		assertUnchanged(t)
	})
	denial = nil
	stale := request
	staleVersion, err := identity.NewCommandID()
	if err != nil {
		t.Fatal(err)
	}
	stale.IfMatch = scim.Version(`"` + string(staleVersion) + `"`)
	out, err := selected.ExecuteManagedAdmittedDelete(f.ctx, f.tenant, stale, gate)
	assertManagedReadDenial(t, out, err, 412)
	if attempts != 2 || mutableState(t) != before {
		t.Fatal("stale live Delete bypassed its single gate or changed User/membership state")
	}
	for index := range 2 {
		response, err := selected.ExecuteManagedAdmittedDelete(f.ctx, f.tenant, request, gate)
		if err != nil || response.Status != 204 || len(response.Body) != 0 || response.ContentType != "" || response.ETag != "" || response.Location != "" || attempts != index+3 {
			t.Fatal("admitted conditional Delete/headerless replay lost canonical empty 204 or charged twice", err)
		}
		if index == 0 {
			before, beforeReceipts = mutableState(t), receiptState(t)
		} else {
			assertUnchanged(t)
		}
	}
	var tombstoned, identityActive, memberActive, grantActive bool
	var memberVersion, grantVersion string
	if err := f.pool.Raw().QueryRow(f.ctx, `SELECT
  (SELECT deleted_at IS NOT NULL FROM scim.users WHERE tenant_id=$1 AND resource_id=$2),
  (SELECT status='active' FROM identity.users WHERE tenant_id=$1 AND user_id=$3),
  EXISTS(SELECT 1 FROM organization.memberships WHERE tenant_id=$1 AND organization_id=$4 AND user_id=$3 AND state='active'),
  (SELECT authorization_version::text FROM organization.memberships WHERE tenant_id=$1 AND organization_id=$4 AND user_id=$3),
  (SELECT active FROM organization.directory_membership_grants WHERE tenant_id=$1 AND organization_id=$4 AND user_id=$3 AND resource_id=$2),
  (SELECT version::text FROM organization.directory_membership_grants WHERE tenant_id=$1 AND organization_id=$4 AND user_id=$3 AND resource_id=$2)`, string(f.tenant), resourceID, userID, string(f.organization)).Scan(&tombstoned, &identityActive, &memberActive, &memberVersion, &grantActive, &grantVersion); err != nil || !tombstoned || !identityActive || memberActive || memberVersion != "2" || grantActive || grantVersion != "2" {
		t.Fatal("admitted Delete/replay did not retire exactly one source contribution and leave the global identity active", err)
	}
	read, err := service.ExecuteManagedProvisioning(f.ctx, f.tenant, scim.Request{Operation: scim.UserGet, Credential: connection.Bearer, ResourceID: resourceID})
	assertManagedReadDenial(t, read, err, 404)
}
