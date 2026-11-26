//go:build integration

package scimpostgres

import (
	"fmt"
	"testing"
	"time"

	authoritypg "github.com/faustbrian/go-authorization/v3/postgres"
	identity "github.com/faustbrian/go-identity"
	organizationpg "github.com/faustbrian/go-organization/postgres"
	scim "github.com/faustbrian/go-scim"
)

func TestManagedUserDeleteWithdrawsOnlyItsExactDirectorySource(t *testing.T) {
	for _, scenario := range []struct {
		name         string
		localMember  bool
		selected     bool
		other        bool
		memberActive bool
		outboxFault  bool
	}{
		{name: "last-source", selected: true},
		{name: "other-source", selected: true, other: true, memberActive: true},
		{name: "local-only", localMember: true, memberActive: true},
		{name: "no-member"},
		{name: "outbox-rollback", selected: true, memberActive: true, outboxFault: true},
	} {
		t.Run(scenario.name, func(t *testing.T) {
			f := newManagedConnectionAdminFixture(t)
			service, _ := newManagedConnectionWriteFixture(t, f)
			installSource(t, f.ctx, f.pool, organizationpg.DirectoryMembershipMigrationSource{Version: 52})
			connection, err := service.ConnectionCreate(f.ctx, managedConnectionCreateRequest(t, f, "managed-withdrawal", "managed-delete-connection"))
			if err != nil || connection.Bearer.Token() == "" {
				t.Fatal("create managed provisioning connection", err)
			}
			created, err := service.ExecuteManagedProvisioning(f.ctx, f.tenant, scim.Request{
				Operation: scim.UserCreate, Credential: connection.Bearer, IdempotencyKey: "managed-delete-person",
				ContentType: "application/scim+json", Body: []byte(fmt.Sprintf(`{"schemas":["urn:ietf:params:scim:schemas:core:2.0:User"],"userName":%q}`, scenario.name)),
			})
			if err != nil || created.Status != 201 {
				t.Fatal("create actual primary SCIM resource before deprovisioning", err)
			}
			source := connection.Connection.Scope()
			resourceID := parseNativeUser(t, created).ID
			var userID string
			if err := f.pool.Raw().QueryRow(f.ctx, `SELECT user_id FROM scim.users WHERE tenant_id=$1 AND organization_id=$2 AND provider_id=$3 AND connection_id=$4 AND resource_id=$5`, string(f.tenant), string(f.organization), string(source.ProviderID), string(source.ProviderConnectionID), resourceID).Scan(&userID); err != nil {
				t.Fatal("observe exact persisted resource-to-user binding", err)
			}
			if scenario.selected || scenario.localMember {
				seedManagedWithdrawalMember(t, f, userID)
			}
			if scenario.selected {
				seedManagedWithdrawalGrant(t, f, userID, string(source.ProviderID), string(source.ProviderConnectionID), resourceID)
			}
			if scenario.other {
				seedManagedWithdrawalGrant(t, f, userID, "other-provider", "other-connection", "other-resource")
			}
			request := scim.Request{Operation: scim.UserDelete, Credential: connection.Bearer, ResourceID: resourceID, IfMatch: created.ETag, IdempotencyKey: "managed-delete-original"}
			if scenario.outboxFault {
				assertManagedWithdrawalRollbackOnOutboxFailure(t, f, service, request, userID)
				return
			}
			if scenario.name == "last-source" {
				staleID, err := identity.NewCommandID()
				if err != nil {
					t.Fatal(err)
				}
				stale := request
				stale.IfMatch, stale.IdempotencyKey = `"`+scim.Version(staleID)+`"`, "managed-delete-stale"
				if _, err := service.ExecuteManagedProvisioning(f.ctx, f.tenant, stale); protocolStatus(err) != 412 {
					t.Fatal("stale precondition must not mutate the projection or membership", err)
				}
			}
			for range 2 {
				response, err := service.ExecuteManagedProvisioning(f.ctx, f.tenant, request)
				if err != nil || response.Status != 204 {
					t.Fatalf("managed delete and exact original retry must finish atomically: status=%d err=%v", response.Status, err)
				}
			}
			if _, err := service.ExecuteManagedProvisioning(f.ctx, f.tenant, scim.Request{
				Operation: scim.UserGet, Credential: connection.Bearer, ResourceID: resourceID,
			}); protocolStatus(err) != 404 {
				t.Fatal("a successful delete must no longer expose the SCIM resource", err)
			}
			var tombstoned bool
			if err := f.pool.Raw().QueryRow(f.ctx, `SELECT deleted_at IS NOT NULL FROM scim.users WHERE tenant_id=$1 AND organization_id=$2 AND provider_id=$3 AND connection_id=$4 AND resource_id=$5`, string(f.tenant), string(f.organization), string(source.ProviderID), string(source.ProviderConnectionID), resourceID).Scan(&tombstoned); err != nil || !tombstoned {
				t.Fatal("original managed resource tombstone is missing", err)
			}
			var stillActive bool
			var lastVersion string
			if err := f.pool.Raw().QueryRow(f.ctx, `SELECT EXISTS(SELECT 1 FROM organization.memberships WHERE tenant_id=$1 AND organization_id=$2 AND user_id=$3 AND state='active'), COALESCE((SELECT authorization_version::text FROM organization.memberships WHERE tenant_id=$1 AND organization_id=$2 AND user_id=$3),'0')`, string(f.tenant), string(f.organization), userID).Scan(&stillActive, &lastVersion); err != nil || stillActive != scenario.memberActive {
				t.Fatal("delete did not preserve the intended membership scope", err)
			}
			expectedVersion := "0"
			if scenario.localMember || scenario.other {
				expectedVersion = "1"
			} else if scenario.selected {
				expectedVersion = "2"
			}
			if lastVersion != expectedVersion {
				t.Fatalf("authorization epoch advanced outside the selected last-source withdrawal: got %s; want %s", lastVersion, expectedVersion)
			}
			if scenario.selected {
				var active bool
				var version string
				if err := f.pool.Raw().QueryRow(f.ctx, `SELECT active,version::text FROM organization.directory_membership_grants WHERE tenant_id=$1 AND organization_id=$2 AND user_id=$3 AND member_version=1 AND provider_id=$4 AND connection_id=$5 AND resource_id=$6`, string(f.tenant), string(f.organization), userID, string(source.ProviderID), string(source.ProviderConnectionID), resourceID).Scan(&active, &version); err != nil || active || version != "2" {
					t.Fatal("exact source was not retired once", err)
				}
			}
			if scenario.other {
				var active bool
				if err := f.pool.Raw().QueryRow(f.ctx, `SELECT active FROM organization.directory_membership_grants WHERE tenant_id=$1 AND organization_id=$2 AND user_id=$3 AND member_version=1 AND provider_id='other-provider' AND connection_id='other-connection'`, string(f.tenant), string(f.organization), userID).Scan(&active); err != nil || !active {
					t.Fatal("a different provider's exact contribution was removed", err)
				}
			}
		})
	}
}

func assertManagedWithdrawalRollbackOnOutboxFailure(t *testing.T, f *managedConnectionAdminFixture, service *ManagedConnectionService, request scim.Request, user string) {
	t.Helper()
	// Fail in the mandatory outbox after verifying both provisional writes
	// reached the same transaction. A normal failure cannot disclose success.
	if _, err := f.pool.Raw().Exec(f.ctx, `CREATE FUNCTION scim.fixture_managed_delete_outbox_fault() RETURNS trigger LANGUAGE plpgsql AS $f$
BEGIN
 IF EXISTS (SELECT 1 FROM scim.users WHERE deleted_at IS NOT NULL)
  AND EXISTS (SELECT 1 FROM organization.directory_membership_grants WHERE version=2 AND NOT active) THEN
  RAISE EXCEPTION 'owned original managed delete outbox fault';
 END IF;
 RETURN NEW;
END $f$;
CREATE TRIGGER fixture_managed_delete_outbox_fault BEFORE INSERT ON public.outbox_messages
FOR EACH ROW EXECUTE FUNCTION scim.fixture_managed_delete_outbox_fault()`); err != nil {
		t.Fatal("install the isolated mandatory outbox fault", err)
	}
	failed, err := service.ExecuteManagedProvisioning(f.ctx, f.tenant, request)
	if protocolStatus(err) != 503 || failed.Status != 0 {
		t.Fatalf("outbox failure must roll back both provisional writes: status=%d err=%v", failed.Status, err)
	}
	var live, grant, member bool
	if err := f.pool.Raw().QueryRow(f.ctx, `SELECT
 EXISTS(SELECT 1 FROM scim.users WHERE resource_id=$1 AND deleted_at IS NULL AND generation=1),
 EXISTS(SELECT 1 FROM organization.directory_membership_grants WHERE user_id=$2 AND resource_id=$1 AND active AND version=1),
 EXISTS(SELECT 1 FROM organization.memberships WHERE user_id=$2 AND state='active' AND authorization_version=1)`, request.ResourceID, user).Scan(&live, &grant, &member); err != nil || !live || !grant || !member {
		t.Fatalf("no partial effect may escape rollback: resource=%v grant=%v member=%v err=%v", live, grant, member, err)
	}
	if _, err := f.pool.Raw().Exec(f.ctx, `DROP TRIGGER fixture_managed_delete_outbox_fault ON public.outbox_messages;
DROP FUNCTION scim.fixture_managed_delete_outbox_fault()`); err != nil {
		t.Fatal("remove only the owned outbox fault before the exact retry", err)
	}
}

func seedManagedWithdrawalMember(t *testing.T, f *managedConnectionAdminFixture, userID string) {
	t.Helper()
	scope, err := organizationpg.OrganizationAuthorityScope(f.tenant, f.organization, identity.UserID(userID))
	if err != nil {
		t.Fatal("construct exact target organization authority selector", err)
	}
	if _, err := authoritypg.InitializeAuthority(f.ctx, f.pool.Raw(), scope, time.Second); err != nil {
		t.Fatal("initialize exact target organization authority", err)
	}
	if _, err := f.pool.Raw().Exec(f.ctx, `INSERT INTO organization.memberships(tenant_id,organization_id,user_id,role,state,version,authorization_version) VALUES($1,$2,$3,'member','active',1,1)`, string(f.tenant), string(f.organization), userID); err != nil {
		t.Fatal("seed canonical membership at version one", err)
	}
	if _, err := f.pool.Raw().Exec(f.ctx, `UPDATE organization.organizations SET member_count=member_count+1,version=version+1 WHERE tenant_id=$1 AND organization_id=$2`, string(f.tenant), string(f.organization)); err != nil {
		t.Fatal("keep the original fixture aggregate aligned with the membership", err)
	}
}

func seedManagedWithdrawalGrant(t *testing.T, f *managedConnectionAdminFixture, userID, providerID, connectionID, resourceID string) {
	t.Helper()
	if _, err := f.pool.Raw().Exec(f.ctx, `INSERT INTO organization.directory_membership_grants(tenant_id,organization_id,user_id,member_version,provider_id,connection_id,resource_id,version,active) VALUES($1,$2,$3,1,$4,$5,$6,1,true)`, string(f.tenant), string(f.organization), userID, providerID, connectionID, resourceID); err != nil {
		t.Fatal("seed exact active source attribution", err)
	}
}
