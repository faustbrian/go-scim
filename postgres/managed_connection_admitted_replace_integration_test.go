//go:build integration

package scimpostgres

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

func TestManagedConnectionAdmittedReplacePreservesFullReplacementAndHeaderlessReplay(t *testing.T) {
	f := newManagedConnectionAdminFixture(t)
	service, _ := newManagedConnectionWriteFixture(t, f)
	selected, ok := any(service).(interface {
		ExecuteManagedAdmittedReplace(context.Context, identity.TenantID, scim.Request, scim.ProtocolAdmission) (scim.Response, error)
	})
	if !ok {
		t.Fatal("managed connection service has no explicit admitted conditional User Replace selection")
	}
	connection, err := service.ConnectionCreate(f.ctx, managedConnectionCreateRequest(t, f, "managed-admitted-replace", "managed-admitted-replace-connection"))
	if err != nil || connection.Bearer.Token() == "" {
		t.Fatal("issue actual managed connection for admitted Replace", err)
	}
	created, err := service.ExecuteManagedProvisioning(f.ctx, f.tenant, scim.Request{Operation: scim.UserCreate, Credential: connection.Bearer, ContentType: "application/scim+json", Body: []byte(`{"schemas":["urn:ietf:params:scim:schemas:core:2.0:User"],"userName":"managed-replace-original","externalId":"omitted-correlation","name":{"familyName":"Omitted name"},"emails":[{"value":"old@example.test"}]}`)})
	if err != nil || created.Status != 201 {
		t.Fatal("create actual native User before admitted Replace", err)
	}
	resourceID := parseNativeUser(t, created).ID
	scope := connection.Connection.Scope()
	var userID string
	if err := f.pool.Raw().QueryRow(f.ctx, `SELECT user_id FROM scim.users WHERE tenant_id=$1 AND organization_id=$2 AND provider_id=$3 AND connection_id=$4 AND resource_id=$5`, string(f.tenant), string(scope.OrganizationID), string(scope.ProviderID), string(scope.ProviderConnectionID), resourceID).Scan(&userID); err != nil {
		t.Fatal("read exact managed User identity binding", err)
	}
	request := scim.Request{Operation: scim.UserReplace, Credential: connection.Bearer, ResourceID: resourceID, IfMatch: created.ETag, ContentType: "application/scim+json", Body: []byte(`{"schemas":["urn:ietf:params:scim:schemas:core:2.0:User"],"userName":"managed-replace-updated","active":true}`)}
	mutableState := func(t *testing.T) string {
		t.Helper()
		var state string
		if err := f.pool.Raw().QueryRow(f.ctx, `SELECT jsonb_build_object(
   'projection',(SELECT to_jsonb(s) FROM scim.users s WHERE tenant_id=$1 AND organization_id=$2 AND provider_id=$3 AND connection_id=$4 AND resource_id=$5),
   'identity',(SELECT to_jsonb(u) FROM identity.users u WHERE tenant_id=$1 AND user_id=$6),
   'attributes',(SELECT to_jsonb(a) FROM identity.user_attributes a WHERE tenant_id=$1 AND user_id=$6))::text`, string(f.tenant), string(scope.OrganizationID), string(scope.ProviderID), string(scope.ProviderConnectionID), resourceID, userID).Scan(&state); err != nil {
			t.Fatal("snapshot exact managed User projection, identity and mapped fields", err)
		}
		return state
	}
	receiptState := func(t *testing.T) string {
		t.Helper()
		var state string
		if err := f.pool.Raw().QueryRow(f.ctx, `SELECT jsonb_build_object(
   'commands',(SELECT count(*) FROM identity.commands WHERE tenant_id=$1 AND purpose=$2),
   'request_mappings',(SELECT count(*) FROM identity.request_key_mappings WHERE tenant_id=$1 AND route_id=$2),
   'audits',(SELECT count(*) FROM audit.identity_command_bindings a JOIN identity.commands c USING(command_id) WHERE c.tenant_id=$1 AND c.purpose=$2),
   'outbox',(SELECT count(*) FROM public.identity_outbox_bindings o JOIN identity.commands c USING(command_id) WHERE c.tenant_id=$1 AND c.purpose=$2))::text`, string(f.tenant), string(scim.UserReplace)).Scan(&state); err != nil {
			t.Fatal("snapshot native Replace command, mapping, audit and outbox custody", err)
		}
		return state
	}
	before, beforeReceipts := mutableState(t), receiptState(t)
	assertUnchanged := func(t *testing.T) {
		t.Helper()
		if mutableState(t) != before || receiptState(t) != beforeReceipts {
			t.Fatal("unadmitted Replace changed protected state or command/receipt custody")
		}
	}
	attempts := 0
	var denial *scim.Error
	gate := func(ctx context.Context, client scim.ProtocolClient) *scim.Error {
		attempts++
		deadline, bounded := ctx.Deadline()
		if ctx.Err() != nil || !bounded || !deadline.After(time.Now()) || time.Until(deadline) > f.config.MaximumDuration || client.ID != f.config.ActorID || client.TenantID != f.tenant {
			t.Error("Replace gate lost exact configured client, tenant or original bounded context")
			return scim.NewError(503, "")
		}
		return denial
	}
	t.Run("ordinary managed Replace stays closed", func(t *testing.T) {
		out, err := service.ExecuteManagedProvisioning(f.ctx, f.tenant, request)
		assertManagedReadDenial(t, out, err, 501)
		assertUnchanged(t)
	})
	t.Run("invalid credential and tenant do not charge", func(t *testing.T) {
		invalid := request
		invalid.Credential = authentication.NewBearerCredential("not-an-issued-managed-bearer")
		out, err := selected.ExecuteManagedAdmittedReplace(f.ctx, f.tenant, invalid, gate)
		assertManagedReadDenial(t, out, err, 401)
		out, err = selected.ExecuteManagedAdmittedReplace(f.ctx, "AAAAAAAAAAAAAAAAAAAAAQ", request, gate)
		assertManagedReadDenial(t, out, err, 401)
		if attempts != 0 {
			t.Fatal("invalid credential or foreign tenant charged Replace admission")
		}
		assertUnchanged(t)
	})
	t.Run("caller key cannot select custody or charge", func(t *testing.T) {
		invalid := request
		invalid.IdempotencyKey = "caller-selected-replace-key"
		out, err := selected.ExecuteManagedAdmittedReplace(f.ctx, f.tenant, invalid, gate)
		assertManagedReadDenial(t, out, err, 400)
		if attempts != 0 {
			t.Fatal("caller-selected key charged Replace admission")
		}
		assertUnchanged(t)
	})
	t.Run("current operation denial does not charge", func(t *testing.T) {
		f.deny.Store(true)
		defer f.deny.Store(false)
		out, err := selected.ExecuteManagedAdmittedReplace(f.ctx, f.tenant, request, gate)
		assertManagedReadDenial(t, out, err, 403)
		if attempts != 0 {
			t.Fatal("current native operation denial charged Replace admission")
		}
		assertUnchanged(t)
	})
	t.Run("missing or malformed precondition does not charge", func(t *testing.T) {
		for _, candidate := range []struct {
			version scim.Version
			status  int
		}{{"", 428}, {`W/"weak"`, 400}, {"*", 400}, {`"one","two"`, 400}} {
			invalid := request
			invalid.IfMatch = candidate.version
			out, err := selected.ExecuteManagedAdmittedReplace(f.ctx, f.tenant, invalid, gate)
			assertManagedReadDenial(t, out, err, candidate.status)
		}
		if attempts != 0 {
			t.Fatal("missing or malformed If-Match charged Replace admission")
		}
		assertUnchanged(t)
	})
	t.Run("invalid replacement does not charge", func(t *testing.T) {
		for _, body := range []string{
			`{"schemas":[`,
			`{"schemas":["urn:ietf:params:scim:schemas:core:2.0:User"],"displayName":"missing username"}`,
			`{"schemas":["urn:ietf:params:scim:schemas:core:2.0:User"],"userName":"collision","USERNAME":"collision"}`,
			`{"schemas":["urn:ietf:params:scim:schemas:core:2.0:User"],"userName":"password","password":"private-value"}`,
		} {
			invalid := request
			invalid.Body = []byte(body)
			out, err := selected.ExecuteManagedAdmittedReplace(f.ctx, f.tenant, invalid, gate)
			assertManagedReadDenial(t, out, err, 400)
		}
		if attempts != 0 {
			t.Fatal("invalid complete replacement charged admission")
		}
		assertUnchanged(t)
	})
	t.Run("missing gate and other selections remain closed", func(t *testing.T) {
		out, err := selected.ExecuteManagedAdmittedReplace(f.ctx, f.tenant, request, nil)
		assertManagedReadDenial(t, out, err, 503)
		for _, operation := range []scim.Operation{scim.UserCreate, scim.UserGet, scim.UserList, scim.UserPatch, scim.UserDelete, scim.GroupReplace, scim.Bulk} {
			other := request
			other.Operation = operation
			out, err := selected.ExecuteManagedAdmittedReplace(f.ctx, f.tenant, other, gate)
			assertManagedReadDenial(t, out, err, 501)
		}
		if attempts != 0 {
			t.Fatal("missing or unselected admission reached Replace gate")
		}
		assertUnchanged(t)
	})
	t.Run("quota denial charges once without receipt or mutation", func(t *testing.T) {
		denial = scim.NewRateLimitedError(1250 * time.Millisecond)
		out, err := selected.ExecuteManagedAdmittedReplace(f.ctx, f.tenant, request, gate)
		assertManagedReadDenial(t, out, err, 429)
		var limited *scim.Error
		if !errors.As(err, &limited) || limited.SCIMType() != "" || limited.RetryAfterSeconds() != 2 || attempts != 1 {
			t.Fatal("Replace quota denial lost redacted retry metadata or charged twice")
		}
		assertUnchanged(t)
	})
	denial = nil
	stale := request
	version, err := identity.NewCommandID()
	if err != nil {
		t.Fatal(err)
	}
	stale.IfMatch = scim.Version(`"` + string(version) + `"`)
	out, err := selected.ExecuteManagedAdmittedReplace(f.ctx, f.tenant, stale, gate)
	assertManagedReadDenial(t, out, err, 412)
	if attempts != 2 || mutableState(t) != before {
		t.Fatal("stale current Replace precondition skipped admission or changed protected User state")
	}
	replaced, err := selected.ExecuteManagedAdmittedReplace(f.ctx, f.tenant, request, gate)
	if err != nil || replaced.Status != 200 || replaced.ContentType != "application/scim+json" || replaced.ETag == created.ETag || len(replaced.ETag) <= 2 || !strings.HasPrefix(string(replaced.ETag), `"`) || !strings.HasSuffix(string(replaced.ETag), `"`) || replaced.Location != created.Location || attempts != 3 {
		t.Fatal("admitted conditional Replace did not return one changed strong ETag and canonical User", err)
	}
	after := parseNativeUser(t, replaced)
	if after.ID != resourceID || after.UserName != "managed-replace-updated" || after.Active == nil || !*after.Active || after.Meta.Created != parseNativeUser(t, created).Meta.Created {
		t.Fatal("Replace lost complete input, original identity or creation metadata")
	}
	var replacement map[string]any
	if json.Unmarshal(replaced.Body, &replacement) != nil {
		t.Fatal("decode replacement User")
	}
	for _, omitted := range []string{"externalId", "name", "emails"} {
		if _, exists := replacement[omitted]; exists {
			t.Fatalf("Replace retained omitted writable field %s as a PATCH merge", omitted)
		}
	}
	managedNative := *f.nativeFixture
	managedNative.config.Scope.TenantID = f.tenant
	assertNativeMappedFields(t, &managedNative, userID, "managed-replace-updated", "")
	before, beforeReceipts = mutableState(t), receiptState(t)
	retry := request
	retry.Body = []byte(`{ "active":true, "userName":"managed-replace-updated", "schemas":["urn:ietf:params:scim:schemas:core:2.0:User"] }`)
	replay, err := selected.ExecuteManagedAdmittedReplace(f.ctx, f.tenant, retry, gate)
	if err != nil || replay.Status != replaced.Status || replay.ContentType != replaced.ContentType || replay.ETag != replaced.ETag || replay.Location != replaced.Location || !bytes.Equal(replay.Body, replaced.Body) || attempts != 4 {
		t.Fatal("headerless equivalent Replace retry rechecked stale original precondition or changed receipt", err)
	}
	assertUnchanged(t)
	var generation int64
	var projectionWire []byte
	var committed, audits, events int
	if err := f.pool.Raw().QueryRow(f.ctx, `SELECT s.generation,s.resource,
  (SELECT count(*) FROM identity.commands c WHERE c.command_id=decode(translate(s.command_id,'-_','+/')||'==','base64') AND c.tenant_id=$1 AND c.purpose=$6 AND c.state='committed'),
  (SELECT count(*) FROM audit.identity_command_bindings a WHERE a.command_id=decode(translate(s.command_id,'-_','+/')||'==','base64')),
  (SELECT count(*) FROM public.identity_outbox_bindings o WHERE o.command_id=decode(translate(s.command_id,'-_','+/')||'==','base64'))
FROM scim.users s WHERE s.tenant_id=$1 AND s.organization_id=$2 AND s.provider_id=$3 AND s.connection_id=$4 AND s.resource_id=$5 AND s.deleted_at IS NULL`, string(f.tenant), string(scope.OrganizationID), string(scope.ProviderID), string(scope.ProviderConnectionID), resourceID, string(scim.UserReplace)).Scan(&generation, &projectionWire, &committed, &audits, &events); err != nil || generation != 2 || committed != 1 || audits != 1 || events != 1 {
		t.Fatal("Replace/replay did not persist exactly one generation and original command/audit/outbox", err)
	}
	var projection scim.Resource
	if json.Unmarshal(projectionWire, &projection) != nil || projection.ID != resourceID || projection.Version != replaced.ETag || projection.Attributes["userName"] != "managed-replace-updated" || projection.ExternalID != "" {
		t.Fatal("persisted full replacement differs from original returned User/version")
	}
	read, err := service.ExecuteManagedProvisioning(f.ctx, f.tenant, scim.Request{Operation: scim.UserGet, Credential: connection.Bearer, ResourceID: resourceID})
	if err != nil || read.Status != 200 || read.ETag != replaced.ETag || !bytes.Equal(read.Body, replaced.Body) {
		t.Fatal("ordinary managed read did not observe persisted admitted replacement", err)
	}
	out, err = service.ExecuteManagedProvisioning(f.ctx, f.tenant, request)
	assertManagedReadDenial(t, out, err, 501)
	assertUnchanged(t)
}
