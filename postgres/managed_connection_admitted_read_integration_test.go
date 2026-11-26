//go:build integration

package scimpostgres

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"

	authentication "github.com/faustbrian/go-authentication/v2"
	identity "github.com/faustbrian/go-identity"
	scim "github.com/faustbrian/go-scim"
)

func TestManagedConnectionAdmittedReadsUseIssuedBearerAndConfiguredClient(t *testing.T) {
	f := newManagedConnectionAdminFixture(t)
	service, _ := newManagedConnectionWriteFixture(t, f)
	connection, err := service.ConnectionCreate(f.ctx, managedConnectionCreateRequest(t, f, "managed-read-provider", "managed-read-connection"))
	if err != nil || connection.Bearer.Token() == "" {
		t.Fatal("issue an actual managed connection bearer", err)
	}
	created, err := service.ExecuteManagedProvisioning(f.ctx, f.tenant, scim.Request{
		Operation: scim.UserCreate, Credential: connection.Bearer, IdempotencyKey: "managed-admitted-read-person",
		ContentType: "application/scim+json", Body: []byte(`{"schemas":["urn:ietf:params:scim:schemas:core:2.0:User"],"userName":"managed-admitted-person"}`),
	})
	if err != nil || created.Status != 201 {
		t.Fatal("create the issued connection's actual source-owned User", err)
	}
	id := parseNativeUser(t, created).ID
	selected, ok := any(service).(interface {
		ExecuteManagedAdmittedRead(context.Context, identity.TenantID, scim.Request, scim.ProtocolAdmission) (scim.Response, error)
	})
	if !ok {
		t.Fatal("managed connection service has no explicit admitted Get/List selection")
	}
	request := scim.Request{Operation: scim.UserGet, Credential: connection.Bearer, ResourceID: id}
	attempts := 0
	var denial *scim.Error
	gate := func(ctx context.Context, client scim.ProtocolClient) *scim.Error {
		attempts++
		deadline, bounded := ctx.Deadline()
		if ctx.Err() != nil || !bounded || !deadline.After(time.Now()) || time.Until(deadline) > f.config.MaximumDuration || client.ID != f.config.ActorID || client.TenantID != f.tenant {
			t.Error("gate did not receive the current configured service-account client and bounded tenant scope")
			return scim.NewError(503, "")
		}
		return denial
	}

	t.Run("untrusted bearer does not charge", func(t *testing.T) {
		invalid := request
		invalid.Credential = authentication.NewBearerCredential("not-an-issued-managed-bearer")
		out, err := selected.ExecuteManagedAdmittedRead(f.ctx, f.tenant, invalid, gate)
		assertManagedReadDenial(t, out, err, 401)
		if attempts != 0 {
			t.Fatal("untrusted bearer reached admission")
		}
	})
	t.Run("foreign tenant does not charge", func(t *testing.T) {
		out, err := selected.ExecuteManagedAdmittedRead(f.ctx, "AAAAAAAAAAAAAAAAAAAAAQ", request, gate)
		assertManagedReadDenial(t, out, err, 401)
		if attempts != 0 {
			t.Fatal("foreign-tenant bearer reached admission")
		}
	})
	t.Run("native authorization denial does not charge", func(t *testing.T) {
		f.deny.Store(true)
		defer f.deny.Store(false)
		out, err := selected.ExecuteManagedAdmittedRead(f.ctx, f.tenant, request, gate)
		assertManagedReadDenial(t, out, err, 403)
		if attempts != 0 {
			t.Fatal("native authorization denial reached admission")
		}
	})
	t.Run("missing gate fails closed", func(t *testing.T) {
		out, err := selected.ExecuteManagedAdmittedRead(f.ctx, f.tenant, request, nil)
		assertManagedReadDenial(t, out, err, 503)
	})
	t.Run("write and search remain unselected", func(t *testing.T) {
		for _, operation := range []scim.Operation{scim.UserCreate, scim.UserDelete, scim.UserSearch, scim.GroupGet, scim.ServiceProviderConfig} {
			unsupported := request
			unsupported.Operation = operation
			out, err := selected.ExecuteManagedAdmittedRead(f.ctx, f.tenant, unsupported, gate)
			assertManagedReadDenial(t, out, err, 501)
		}
		if attempts != 0 {
			t.Fatal("unsupported selection reached admission")
		}
	})
	t.Run("canceled request does not charge", func(t *testing.T) {
		ctx, cancel := context.WithCancel(f.ctx)
		cancel()
		out, err := selected.ExecuteManagedAdmittedRead(ctx, f.tenant, request, gate)
		assertManagedReadDenial(t, out, err, 503)
		if attempts != 0 {
			t.Fatal("canceled request reached admission")
		}
	})
	t.Run("quota denial discloses no resource", func(t *testing.T) {
		denial = scim.NewRateLimitedError(1250 * time.Millisecond)
		out, err := selected.ExecuteManagedAdmittedRead(f.ctx, f.tenant, request, gate)
		assertManagedReadDenial(t, out, err, 429)
		var limited *scim.Error
		if !errors.As(err, &limited) || limited.RetryAfterSeconds() != 2 || attempts != 1 {
			t.Fatal("quota denial lost its positive retry delay or charged more than once")
		}
	})
	t.Run("admission policy denial discloses no resource", func(t *testing.T) {
		denial = scim.NewError(403, "")
		out, err := selected.ExecuteManagedAdmittedRead(f.ctx, f.tenant, request, gate)
		assertManagedReadDenial(t, out, err, 403)
		if attempts != 2 {
			t.Fatal("admission policy was not evaluated exactly once")
		}
	})
	t.Run("gate cancellation overrides its denial", func(t *testing.T) {
		ctx, cancel := context.WithCancel(f.ctx)
		defer cancel()
		calls := 0
		out, err := selected.ExecuteManagedAdmittedRead(ctx, f.tenant, request, func(ctx context.Context, client scim.ProtocolClient) *scim.Error {
			calls++
			if client.ID != f.config.ActorID || client.TenantID != f.tenant {
				t.Error("canceled admission did not retain configured client scope")
			}
			cancel()
			return scim.NewError(403, "")
		})
		assertManagedReadDenial(t, out, err, 503)
		if calls != 1 {
			t.Fatal("canceled gate was not called exactly once")
		}
	})
	t.Run("allowed Get reads the exact source User", func(t *testing.T) {
		denial = nil
		out, err := selected.ExecuteManagedAdmittedRead(f.ctx, f.tenant, request, gate)
		if err != nil || out.Status != 200 || parseNativeUser(t, out).ID != id || out.ETag != created.ETag || attempts != 3 {
			t.Fatal("admitted managed Get did not return the exact original User and version once", err)
		}
	})
	t.Run("allowed List reads the exact source snapshot", func(t *testing.T) {
		list := request
		list.Operation, list.ResourceID = scim.UserList, ""
		out, err := selected.ExecuteManagedAdmittedRead(f.ctx, f.tenant, list, gate)
		var page struct {
			TotalResults int
			ItemsPerPage int
			Resources    []struct{ ID string }
		}
		if err != nil || out.Status != 200 || json.Unmarshal(out.Body, &page) != nil || page.TotalResults != 1 || page.ItemsPerPage != 1 || len(page.Resources) != 1 || page.Resources[0].ID != id || attempts != 4 {
			t.Fatal("admitted managed List did not return its exact complete snapshot once", err)
		}
	})
	t.Run("ordinary managed read remains unchanged", func(t *testing.T) {
		denial = scim.NewError(403, "")
		out, err := service.ExecuteManagedProvisioning(f.ctx, f.tenant, request)
		if err != nil || out.Status != 200 || parseNativeUser(t, out).ID != id || attempts != 4 {
			t.Fatal("explicit admission changed ordinary managed reads", err)
		}
	})
}

func assertManagedReadDenial(t *testing.T, response scim.Response, err error, status int) {
	t.Helper()
	if protocolStatus(err) != status || response.Status != 0 || len(response.Body) != 0 || response.ContentType != "" || response.ETag != "" || response.Location != "" {
		t.Fatalf("want redacted managed read denial %d with no resource or metadata; got status %d and error %v", status, response.Status, err)
	}
}
