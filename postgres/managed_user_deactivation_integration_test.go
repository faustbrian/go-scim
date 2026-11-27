//go:build integration

package scimpostgres

import (
	"bytes"
	"context"
	"encoding/json"
	"strings"
	"testing"

	audit "github.com/faustbrian/go-audit"
	identity "github.com/faustbrian/go-identity"
	organizationpg "github.com/faustbrian/go-organization/postgres"
	scim "github.com/faustbrian/go-scim"
)

func TestManagedUserDeactivationWithdrawsOnlyItsCurrentSource(t *testing.T) {
	for _, scenario := range []struct {
		name        string
		selected    bool
		otherSource bool
		memberLives bool
	}{
		{name: "last-source", selected: true},
		{name: "another-connection", selected: true, otherSource: true, memberLives: true},
		{name: "independent-local-member", memberLives: true},
	} {
		t.Run(scenario.name, func(t *testing.T) {
			f := newManagedUserDeactivationFixture(t)
			if scenario.selected {
				seedManagedWithdrawalGrant(t, f.admin, f.userID, string(f.scope.ProviderID), string(f.scope.ProviderConnectionID), f.request.ResourceID)
			}
			if scenario.otherSource {
				seedManagedWithdrawalGrant(t, f.admin, f.userID, string(f.scope.ProviderID), "other-connection", "other-resource")
			}
			deactivated, err := f.service.ExecuteManagedAdmittedPatch(f.admin.ctx, f.admin.tenant, f.request, f.admit(t))
			if err != nil || deactivated.Status != 200 {
				t.Fatalf("explicit active:false must return the ordinary typed Patch result: status=%d err=%v", deactivated.Status, err)
			}
			user := parseNativeUser(t, deactivated)
			if user.ID != f.request.ResourceID || user.Active == nil || *user.Active || user.UserName != "managed-deactivation-person" || user.Meta.Created != parseNativeUser(t, f.created).Meta.Created {
				t.Fatal("deactivation must retain the original resource and creation time and set active:false")
			}
			strongVersion := strings.HasPrefix(string(deactivated.ETag), `"`) && strings.HasSuffix(string(deactivated.ETag), `"`)
			if deactivated.ETag == f.created.ETag || !strongVersion || deactivated.ContentType != "application/scim+json" || deactivated.Location != f.created.Location {
				t.Fatal("deactivation must return the ordinary representation with an advanced strong ETag")
			}
			read, err := f.service.ExecuteManagedProvisioning(f.admin.ctx, f.admin.tenant, scim.Request{Operation: scim.UserGet, Credential: f.request.Credential, ResourceID: f.request.ResourceID})
			if err != nil || read.Status != 200 || read.ETag != deactivated.ETag || !bytes.Equal(read.Body, deactivated.Body) {
				t.Fatal("deactivation must retain a readable projection rather than a tombstone", err)
			}
			var active bool
			var memberAuthority string
			if err := f.admin.pool.Raw().QueryRow(f.admin.ctx, `SELECT state='active',authorization_version::text FROM organization.memberships WHERE tenant_id=$1 AND organization_id=$2 AND user_id=$3`, string(f.admin.tenant), string(f.scope.OrganizationID), f.userID).Scan(&active, &memberAuthority); err != nil || active != scenario.memberLives {
				t.Fatal("deactivation removed the wrong membership scope or retained the last directory-owned membership", err)
			}
			wantAuthority := "1"
			if !scenario.memberLives {
				wantAuthority = "2"
			}
			if memberAuthority != wantAuthority || f.authorityVersion(t) != wantAuthority {
				t.Fatal("only final-source withdrawal may advance the exact organization membership authority")
			}
			if scenario.selected {
				var version string
				if err := f.admin.pool.Raw().QueryRow(f.admin.ctx, `SELECT active,version::text FROM organization.directory_membership_grants WHERE tenant_id=$1 AND organization_id=$2 AND user_id=$3 AND member_version=1 AND provider_id=$4 AND connection_id=$5 AND resource_id=$6`, string(f.admin.tenant), string(f.scope.OrganizationID), f.userID, string(f.scope.ProviderID), string(f.scope.ProviderConnectionID), f.request.ResourceID).Scan(&active, &version); err != nil || active || version != "2" {
					t.Fatal("deactivation must retire exactly the current source contribution once", err)
				}
			}
			if scenario.otherSource {
				if err := f.admin.pool.Raw().QueryRow(f.admin.ctx, `SELECT active AND version=1 FROM organization.directory_membership_grants WHERE tenant_id=$1 AND organization_id=$2 AND user_id=$3 AND member_version=1 AND provider_id=$4 AND connection_id='other-connection' AND resource_id='other-resource'`, string(f.admin.tenant), string(f.scope.OrganizationID), f.userID, string(f.scope.ProviderID)).Scan(&active); err != nil || !active {
					t.Fatal("another connection under the same provider must retain its original contribution", err)
				}
			}
			f.assertGlobalUserActive(t)
			var generation, commands, audits, events int
			if err := f.admin.pool.Raw().QueryRow(f.admin.ctx, `SELECT s.generation,
 (SELECT count(*) FROM identity.commands c WHERE c.command_id=decode(translate(s.command_id,'-_','+/')||'==','base64') AND c.state='committed' AND c.purpose=$6),
 (SELECT count(*) FROM audit.identity_command_bindings a WHERE a.command_id=decode(translate(s.command_id,'-_','+/')||'==','base64')),
 (SELECT count(*) FROM public.identity_outbox_bindings o WHERE o.command_id=decode(translate(s.command_id,'-_','+/')||'==','base64'))
FROM scim.users s WHERE tenant_id=$1 AND organization_id=$2 AND provider_id=$3 AND connection_id=$4 AND resource_id=$5 AND deleted_at IS NULL`, string(f.admin.tenant), string(f.scope.OrganizationID), string(f.scope.ProviderID), string(f.scope.ProviderConnectionID), f.request.ResourceID, string(scim.UserPatch)).Scan(&generation, &commands, &audits, &events); err != nil || generation != 2 || commands != 1 || audits != 1 || events != 1 {
				t.Fatal("deactivation must commit one projection generation with one original Patch command, audit and event", err)
			}
			beforeReplay := f.snapshot(t)
			var formatted bytes.Buffer
			if err := json.Indent(&formatted, f.request.Body, "", "  "); err != nil {
				t.Fatal(err)
			}
			retry := f.request
			retry.Body = formatted.Bytes()
			replayed, err := f.service.ExecuteManagedAdmittedPatch(f.admin.ctx, f.admin.tenant, retry, f.admit(t))
			if err != nil || replayed.Status != deactivated.Status || replayed.ContentType != deactivated.ContentType || replayed.ETag != deactivated.ETag || replayed.Location != deactivated.Location || !bytes.Equal(replayed.Body, deactivated.Body) || f.snapshot(t) != beforeReplay {
				t.Fatal("equivalent replay with the original If-Match must return the original response without another projection, grant, audit or event change", err)
			}
			if scenario.name == "last-source" {
				f.assertNoRegrant(t, deactivated.ETag)
			}
		})
	}
}

func TestManagedUserDeactivationRollsBackProjectionAndWithdrawalTogether(t *testing.T) {
	f := newManagedUserDeactivationFixture(t)
	seedManagedWithdrawalGrant(t, f.admin, f.userID, string(f.scope.ProviderID), string(f.scope.ProviderConnectionID), f.request.ResourceID)
	before := f.snapshot(t)
	if _, err := f.admin.pool.Raw().Exec(f.admin.ctx, `CREATE FUNCTION scim.fixture_deactivation_outbox_fault() RETURNS trigger LANGUAGE plpgsql AS $f$
BEGIN
 IF EXISTS (SELECT 1 FROM scim.users WHERE deleted_at IS NULL AND generation=2 AND convert_from(resource,'UTF8')::jsonb->'Attributes'->'active'='false'::jsonb)
  AND EXISTS (SELECT 1 FROM organization.directory_membership_grants WHERE version=2 AND NOT active) THEN
  RAISE EXCEPTION 'owned managed deactivation outbox fault';
 END IF;
 RETURN NEW;
END $f$;
CREATE TRIGGER fixture_deactivation_outbox_fault BEFORE INSERT ON public.outbox_messages
FOR EACH ROW EXECUTE FUNCTION scim.fixture_deactivation_outbox_fault()`); err != nil {
		t.Fatal("install the isolated pre-commit failure after both provisional effects", err)
	}
	failed, err := f.service.ExecuteManagedAdmittedPatch(f.admin.ctx, f.admin.tenant, f.request, f.admit(t))
	unchanged := f.snapshot(t) == before
	if protocolStatus(err) != 503 || failed.Status != 0 || !unchanged {
		t.Fatalf("pre-commit failure must roll back the projection, grant and authority without a success audit or event: response=%d protocol=%d unchanged=%v err=%v", failed.Status, protocolStatus(err), unchanged, err)
	}
	if _, err := f.admin.pool.Raw().Exec(f.admin.ctx, `DROP TRIGGER fixture_deactivation_outbox_fault ON public.outbox_messages;
DROP FUNCTION scim.fixture_deactivation_outbox_fault()`); err != nil {
		t.Fatal("remove only the owned pre-commit failure before retry", err)
	}
	retried, err := f.service.ExecuteManagedAdmittedPatch(f.admin.ctx, f.admin.tenant, f.request, f.admit(t))
	if protocolStatus(err) != 503 || retried.Status != 0 || f.snapshot(t) != before {
		t.Fatal("exact replay of the terminal rollback must not reopen the command or apply a partial change", err)
	}
	var failures int
	if err := f.admin.pool.Raw().QueryRow(f.admin.ctx, `SELECT count(*) FROM audit.records WHERE tenant_id=$1 AND action=$2 AND subject_id=$3 AND outcome=$4`, string(f.admin.tenant), string(scim.UserPatch), f.request.ResourceID, int16(audit.OutcomeFailed)).Scan(&failures); err != nil || failures != 1 {
		t.Fatal("the original rollback retains only one required failure audit", failures, err)
	}
	f.assertGlobalUserActive(t)
}

type managedUserDeactivationFixture struct {
	admin   *managedConnectionAdminFixture
	service *ManagedConnectionService
	scope   scim.ConnectionScope
	userID  string
	created scim.Response
	request scim.Request
}

func newManagedUserDeactivationFixture(t *testing.T) *managedUserDeactivationFixture {
	t.Helper()
	f := &managedUserDeactivationFixture{admin: newManagedConnectionAdminFixture(t)}
	f.service, _ = newManagedConnectionWriteFixture(t, f.admin)
	installSource(t, f.admin.ctx, f.admin.pool, organizationpg.DirectoryMembershipMigrationSource{Version: 52})
	connection, err := f.service.ConnectionCreate(f.admin.ctx, managedConnectionCreateRequest(t, f.admin, "managed-deactivation", "managed-deactivation-connection"))
	if err != nil || connection.Bearer.Token() == "" || connection.Connection.DeprovisionPolicy() != scim.RemoveMembership {
		t.Fatal("issue a real connection with its persisted RemoveMembership policy", err)
	}
	f.scope = connection.Connection.Scope()
	f.created, err = f.service.ExecuteManagedProvisioning(f.admin.ctx, f.admin.tenant, scim.Request{Operation: scim.UserCreate, Credential: connection.Bearer, ContentType: "application/scim+json", Body: []byte(`{"schemas":["urn:ietf:params:scim:schemas:core:2.0:User"],"userName":"managed-deactivation-person","active":true}`)})
	if err != nil || f.created.Status != 201 {
		t.Fatal("create an active persisted projection through the actual managed connection", err)
	}
	resourceID := parseNativeUser(t, f.created).ID
	if err := f.admin.pool.Raw().QueryRow(f.admin.ctx, `SELECT user_id FROM scim.users WHERE tenant_id=$1 AND organization_id=$2 AND provider_id=$3 AND connection_id=$4 AND resource_id=$5`, string(f.admin.tenant), string(f.scope.OrganizationID), string(f.scope.ProviderID), string(f.scope.ProviderConnectionID), resourceID).Scan(&f.userID); err != nil {
		t.Fatal("read the exact persisted managed identity binding", err)
	}
	seedManagedWithdrawalMember(t, f.admin, f.userID)
	f.request = scim.Request{Operation: scim.UserPatch, Credential: connection.Bearer, ResourceID: resourceID, IfMatch: f.created.ETag, ContentType: "application/scim+json", Body: []byte(`{"schemas":["urn:ietf:params:scim:api:messages:2.0:PatchOp"],"Operations":[{"op":"replace","path":"active","value":false}]}`)}
	return f
}

func (f *managedUserDeactivationFixture) admit(t *testing.T) scim.ProtocolAdmission {
	t.Helper()
	return func(ctx context.Context, client scim.ProtocolClient) *scim.Error {
		if ctx.Err() != nil || client.ID != f.admin.config.ActorID || client.TenantID != f.admin.tenant {
			t.Error("deactivation admission lost the original configured principal or exact tenant")
			return scim.NewError(503, "")
		}
		return nil
	}
}

func (f *managedUserDeactivationFixture) authorityVersion(t *testing.T) string {
	t.Helper()
	scope, err := organizationpg.OrganizationAuthorityScope(f.admin.tenant, f.scope.OrganizationID, identity.UserID(f.userID))
	if err != nil {
		t.Fatal(err)
	}
	var version string
	if err := f.admin.pool.Raw().QueryRow(f.admin.ctx, `SELECT version::text FROM authorization_subject_authorities WHERE tenant_id=$1 AND policy_namespace=$2 AND subject_id=$3`, string(scope.TenantID), scope.PolicyNamespace, string(scope.SubjectID)).Scan(&version); err != nil {
		t.Fatal("observe the exact organization member's authority", err)
	}
	return version
}

func (f *managedUserDeactivationFixture) membershipSnapshot(t *testing.T) string {
	t.Helper()
	var snapshot string
	if err := f.admin.pool.Raw().QueryRow(f.admin.ctx, `SELECT jsonb_build_object(
 'membership',(SELECT to_jsonb(m) FROM organization.memberships m WHERE tenant_id=$1 AND organization_id=$2 AND user_id=$3),
 'grants',(SELECT jsonb_agg(to_jsonb(g) ORDER BY to_jsonb(g)::text) FROM organization.directory_membership_grants g WHERE tenant_id=$1 AND organization_id=$2 AND user_id=$3),
 'organization',(SELECT to_jsonb(o) FROM organization.organizations o WHERE tenant_id=$1 AND organization_id=$2))::text`, string(f.admin.tenant), string(f.scope.OrganizationID), f.userID).Scan(&snapshot); err != nil {
		t.Fatal("snapshot scoped membership and every retained contribution", err)
	}
	return snapshot + f.authorityVersion(t)
}

func (f *managedUserDeactivationFixture) snapshot(t *testing.T) string {
	t.Helper()
	var snapshot string
	if err := f.admin.pool.Raw().QueryRow(f.admin.ctx, `SELECT jsonb_build_object(
 'projection',(SELECT to_jsonb(s) FROM scim.users s WHERE tenant_id=$1 AND organization_id=$2 AND provider_id=$3 AND connection_id=$4 AND resource_id=$5),
 'identity',(SELECT to_jsonb(u) FROM identity.users u WHERE tenant_id=$1 AND user_id=$6),
	 'audits',(SELECT count(*) FROM audit.records WHERE outcome=$7),
	 'outbox',(SELECT count(*) FROM public.outbox_messages))::text`, string(f.admin.tenant), string(f.scope.OrganizationID), string(f.scope.ProviderID), string(f.scope.ProviderConnectionID), f.request.ResourceID, f.userID, int16(audit.OutcomeSucceeded)).Scan(&snapshot); err != nil {
		t.Fatal("snapshot projection, global identity and committed audit/event effects", err)
	}
	return snapshot + f.membershipSnapshot(t)
}

func (f *managedUserDeactivationFixture) assertGlobalUserActive(t *testing.T) {
	t.Helper()
	var active bool
	if err := f.admin.pool.Raw().QueryRow(f.admin.ctx, `SELECT status='active' FROM identity.users WHERE tenant_id=$1 AND user_id=$2`, string(f.admin.tenant), f.userID).Scan(&active); err != nil || !active {
		t.Fatal("scoped deactivation must not disable the global User", err)
	}
}

func (f *managedUserDeactivationFixture) assertNoRegrant(t *testing.T, version scim.Version) {
	t.Helper()
	before := f.membershipSnapshot(t)
	for _, body := range []string{
		`{"schemas":["urn:ietf:params:scim:api:messages:2.0:PatchOp"],"Operations":[{"op":"replace","path":"active","value":true}]}`,
		`{"schemas":["urn:ietf:params:scim:api:messages:2.0:PatchOp"],"Operations":[{"op":"remove","path":"active"}]}`,
	} {
		request := f.request
		request.IfMatch, request.Body = version, []byte(body)
		response, err := f.service.ExecuteManagedAdmittedPatch(f.admin.ctx, f.admin.tenant, request, f.admit(t))
		if err != nil || response.Status != 200 || f.membershipSnapshot(t) != before {
			t.Fatal("active:true or absent active must not re-grant removed membership or authority", err)
		}
		user := parseNativeUser(t, response)
		if strings.Contains(body, `"op":"remove"`) {
			if user.Active != nil {
				t.Fatal("removing active must leave it absent in the retained projection")
			}
		} else if user.Active == nil || !*user.Active {
			t.Fatal("active:true must remain an ordinary projection update")
		}
		version = response.ETag
		f.assertGlobalUserActive(t)
	}
}
