//go:build integration

package scimpostgres

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/faustbrian/go-authorization/v3"
	identity "github.com/faustbrian/go-identity"
	scim "github.com/faustbrian/go-scim"
)

func TestManagedConnectionGetAndListRequireCurrentAdministrator(t *testing.T) {
	f := newManagedConnectionAdminFixture(t)
	installManagedConnectionFixtureMigration(t, f.nativeFixture)
	const first, second = scim.ConnectionID("AAAAAAAAAAAAAAAAAAAABA"), scim.ConnectionID("AAAAAAAAAAAAAAAAAAAABQ")
	seedManagedReadBinding(t, f, first, "AAAAAAAAAAAAAAAAAAAABg")
	seedManagedReadBinding(t, f, second, "AAAAAAAAAAAAAAAAAAAABw")
	allow := true
	var afterFirstDecision func()
	policy := configuredPolicy(func(_ context.Context, d authorization.DecisionContext) (authorization.Decision, error) {
		outcome := authorization.Deny
		if allow && d.Request.Subject.ID == authorization.SubjectID(f.actor) && d.Request.Subject.Kind == authorization.SubjectUser && d.Request.Action == "org:scim-read" && d.Request.Resource.ID == authorization.ResourceID(f.organization) && d.Request.Tenant == authorization.TenantID(f.tenant) {
			outcome = authorization.Allow
			if afterFirstDecision != nil {
				afterFirstDecision()
				afterFirstDecision = nil
			}
		}
		return authorization.Decision{Outcome: outcome, Revision: d.PolicyRevision}, nil
	})
	service, err := NewManagedConnectionService(f.pool, ManagedConnectionServiceConfig{
		Sessions: f.sessions, Authorization: policy, PolicyVersion: 1,
		MaximumDuration: 3 * time.Second, CursorKey: [32]byte{76}, Limits: f.config.Limits,
	})
	if err != nil {
		t.Fatal("managed read service composition", err)
	}
	request := ConnectionGetRequest{Authentication: f.admin, ConnectionID: first}
	got, err := service.ConnectionGet(f.ctx, request)
	if err != nil || got.Scope().ProviderConnectionID != first || got.Scope().OrganizationID != f.organization || got.Version() != 1 || got.DeprovisionPolicy() != scim.RemoveMembership {
		t.Fatal("read lost exact persisted scope, version, or policy", err)
	}
	mappings := got.Mappings().Entries()
	if len(mappings) != 1 || mappings[0].Source.String() != "userName" || mappings[0].Target != "scim_user_name" || !mappings[0].Writable {
		t.Fatal("read lost original validated mappings")
	}
	list := ConnectionListRequest{Authentication: f.admin, OrganizationID: f.organization, Limit: 1}
	page, err := service.ConnectionList(f.ctx, list)
	if err != nil || len(page.Connections) != 1 || page.Connections[0].Scope().ProviderConnectionID != first || page.NextCursor == "" {
		t.Fatal("first page did not return the bounded sorted projection and cursor", err)
	}
	list.Cursor = page.NextCursor
	page, err = service.ConnectionList(f.ctx, list)
	if err != nil || len(page.Connections) != 1 || page.Connections[0].Scope().ProviderConnectionID != second || page.NextCursor != "" {
		t.Fatal("continuation did not return the unique successor and final page", err)
	}
	wrongTenant := request
	wrongTenant.Authentication.TenantID = "AAAAAAAAAAAAAAAAAAAAAQ"
	if projection, err := service.ConnectionGet(f.ctx, wrongTenant); !isManagedReadForbidden(err) || projection.Version() != 0 {
		t.Fatal("cross-tenant bearer disclosed the managed record", err)
	}
	missing := request
	missing.ConnectionID = "AAAAAAAAAAAAAAAAAAAACQ"
	if projection, err := service.ConnectionGet(f.ctx, missing); !isManagedReadForbidden(err) || projection.Version() != 0 {
		t.Fatal("missing connection did not use the nondisclosing result", err)
	}
	allow = false
	if projection, err := service.ConnectionGet(f.ctx, request); !isManagedReadForbidden(err) || projection.Version() != 0 {
		t.Fatal("current policy denial disclosed the managed record", err)
	}
	allow = true
	afterFirstDecision = func() {
		if _, err := f.pool.Raw().Exec(f.ctx, `UPDATE organization.memberships SET role='member',version=version+1,authorization_version=authorization_version+1 WHERE tenant_id=$1 AND organization_id=$2 AND user_id=$3`, string(f.tenant), string(f.organization), string(f.actor)); err != nil {
			t.Fatal("change the fixture's current membership", err)
		}
	}
	if projection, err := service.ConnectionGet(f.ctx, request); !isManagedReadForbidden(err) || projection.Version() != 0 {
		t.Fatal("demotion during the initial policy decision did not invalidate the read", err)
	}
	if page, err := service.ConnectionList(f.ctx, list); !isManagedReadForbidden(err) || len(page.Connections) != 0 || page.NextCursor != "" {
		t.Fatal("demoted administrator retained List access", err)
	}
}

func seedManagedReadBinding(t *testing.T, f *managedConnectionAdminFixture, connection scim.ConnectionID, command string) {
	t.Helper()
	if _, err := f.pool.Raw().Exec(f.ctx, `INSERT INTO scim.connections(tenant_id,organization_id,provider_id,connection_id,credential_id,credential_digest,configuration_digest,version,state,expires_at,authority_version,organization_credential_version,command_id,effect_digest) VALUES($1,$2,'managed-provider',$3,'managed-fixture',sha256('credential'),sha256('configuration'),1,'active',clock_timestamp()+interval '1 hour',1,1,$4,sha256('effect'))`, string(f.tenant), string(f.organization), string(connection), command); err != nil {
		t.Fatal("seed managed read binding", err)
	}
	if _, err := f.pool.Raw().Exec(f.ctx, `INSERT INTO scim.managed_connections(tenant_id,organization_id,provider_id,connection_id,mappings,deprovision_policy) VALUES($1,$2,'managed-provider',$3,$4,'remove-membership')`, string(f.tenant), string(f.organization), string(connection), []byte(`[{"source":"userName","target":"scim_user_name","writable":true}]`)); err != nil {
		t.Fatal("seed isolated managed read metadata", err)
	}
}

func isManagedReadForbidden(err error) bool {
	var denied identity.ForbiddenError
	return errors.As(err, &denied)
}
