//go:build integration

package scimpostgres

import (
	"errors"
	"testing"
	"time"

	"github.com/faustbrian/go-authorization/v3"
	authoritypg "github.com/faustbrian/go-authorization/v3/postgres"
	identity "github.com/faustbrian/go-identity"
	organizationpg "github.com/faustbrian/go-organization/postgres"
	scim "github.com/faustbrian/go-scim"
)

func TestManagedConnectionCreateRevealsOnceAndRecoversOriginalRecord(t *testing.T) {
	f := newManagedConnectionAdminFixture(t)
	service, credentialKey := newManagedConnectionWriteFixture(t, f)
	const provider = scim.ProviderID("managed-provider")
	request := managedConnectionCreateRequest(t, f, provider, "managed-connection-test-create")
	first, err := service.ConnectionCreate(f.ctx, request)
	if err != nil || first.Bearer.Token() == "" || first.Connection.Version() != 1 || first.Connection.DeprovisionPolicy() != scim.RemoveMembership {
		t.Fatal("original create did not issue one managed bearer with the durable record", err)
	}
	scope := first.Connection.Scope()
	if scope.TenantID != f.tenant || scope.OrganizationID != f.organization || scope.ProviderID != provider {
		t.Fatal("original create did not bind exact owner scope")
	}
	second, err := service.ConnectionCreate(f.ctx, request)
	if err != nil || second.Bearer.Token() != "" || second.Connection.Scope() != scope || second.Connection.Version() != 1 {
		t.Fatal("same key did not recover the exact original record without a bearer", err)
	}
	read, err := service.ConnectionGet(f.ctx, ConnectionGetRequest{Authentication: f.admin, ConnectionID: scope.ProviderConnectionID})
	if err != nil || read.Scope() != scope || read.Version() != 1 {
		t.Fatal("durable read after original write lost the record", err)
	}
	changed := request
	changed.ProviderID = "other-provider"
	var conflict identity.ConflictError
	if output, err := service.ConnectionCreate(f.ctx, changed); !errors.As(err, &conflict) || output.Bearer.Token() != "" || output.Connection.Version() != 0 {
		t.Fatal("changed intent reused a successful request key", err)
	}
	var credential string
	var storedDigest []byte
	err = f.pool.Raw().QueryRow(f.ctx, `SELECT credential_id,credential_digest FROM scim.connections WHERE tenant_id=$1 AND organization_id=$2 AND provider_id=$3 AND connection_id=$4`, string(scope.TenantID), string(scope.OrganizationID), string(scope.ProviderID), string(scope.ProviderConnectionID)).Scan(&credential, &storedDigest)
	if err != nil || len(storedDigest) != 32 || !matchManagedBearer(scope, identity.SubjectID(credential), credentialKey, first.Bearer, [32]byte(storedDigest)) {
		t.Fatal("original managed binding does not hold the exact scoped digest", err)
	}
	page, err := service.ConnectionList(f.ctx, ConnectionListRequest{Authentication: f.admin, OrganizationID: f.organization, Limit: 20})
	if err != nil || len(page.Connections) != 1 || page.Connections[0].Scope() != scope || page.NextCursor != "" {
		t.Fatal("create replay or conflict produced additional records", err)
	}
	provision := scim.Request{Operation: scim.UserCreate, Credential: first.Bearer, IdempotencyKey: "managed-person-fixture", ContentType: "application/scim+json", Body: []byte(`{"schemas":["urn:ietf:params:scim:schemas:core:2.0:User"],"userName":"managed-person"}`)}
	if response, err := service.ExecuteManagedProvisioning(f.ctx, "AAAAAAAAAAAAAAAAAAAAAQ", provision); err == nil || response.Status != 0 {
		t.Fatal("wrong-tenant bearer returned a provisioning response", err)
	}
	created, err := service.ExecuteManagedProvisioning(f.ctx, f.tenant, provision)
	if err != nil || created.Status != 201 || parseNativeUser(t, created).UserName != "managed-person" {
		t.Fatal("the issued bearer could not provision a user under the persisted mappings", err)
	}
	id := parseNativeUser(t, created).ID
	getUser := scim.Request{Operation: scim.UserGet, ResourceID: id, Credential: first.Bearer}
	if response, err := service.ExecuteManagedProvisioning(f.ctx, f.tenant, getUser); err != nil || response.Status != 200 || parseNativeUser(t, response).ID != id {
		t.Fatal("the issued bearer could not read the original managed user", err)
	}
	if _, err := f.pool.Raw().Exec(f.ctx, `UPDATE scim.connections SET state='revoked' WHERE tenant_id=$1 AND organization_id=$2 AND provider_id=$3 AND connection_id=$4`, string(scope.TenantID), string(scope.OrganizationID), string(scope.ProviderID), string(scope.ProviderConnectionID)); err != nil {
		t.Fatal("change the exact fixture binding to revoked", err)
	}
	if response, err := service.ExecuteManagedProvisioning(f.ctx, f.tenant, getUser); err == nil || response.Status != 0 {
		t.Fatal("a revoked managed bearer still returned a provisioning response", err)
	}
}

func newManagedConnectionWriteFixture(t *testing.T, f *managedConnectionAdminFixture) (*ManagedConnectionService, [32]byte) {
	t.Helper()
	installManagedConnectionFixtureMigration(t, f.nativeFixture)
	provisioningScope := authoritypg.AuthorityScope{
		TenantID: authorization.TenantID(f.tenant), PolicyNamespace: f.config.AuthorityNamespace,
		SubjectID: authorization.SubjectID(f.config.ActorID),
	}
	if _, err := authoritypg.InitializeAuthority(f.ctx, f.pool.Raw(), provisioningScope, time.Second); err != nil {
		t.Fatal("seed the existing provisioning principal's policy authority in the managed tenant", err)
	}
	orgScope, err := organizationpg.OrganizationAuthorityScope(f.tenant, f.organization, f.actor)
	if err != nil {
		t.Fatal("build exact organization administrator authority scope", err)
	}
	if _, err := authoritypg.InitializeAuthority(f.ctx, f.pool.Raw(), orgScope, time.Second); err != nil {
		t.Fatal("seed exact organization administrator authority", err)
	}
	provisioning := f.config
	provisioning.Scope = scim.Scope{}
	provisioning.Credential = ConfiguredCredential{}
	provisioning.ConnectionVersion = 0
	provisioning.CredentialExpiresAt = time.Time{}
	credentialKey := [32]byte{79}
	service, err := NewManagedConnectionService(f.pool, ManagedConnectionServiceConfig{
		Sessions: f.sessions, Authorization: f.config.Authorization, PolicyVersion: 1,
		MaximumDuration: 3 * time.Second, CursorKey: [32]byte{78}, Limits: f.config.Limits,
		Writes: &ManagedConnectionWriteConfig{
			SessionStorage: f.sessionConfig, Provisioning: provisioning, Keyring: f.keys,
			CredentialKey: credentialKey, CredentialLifetime: time.Hour,
		},
	})
	if err != nil {
		t.Fatal("compose real managed connection service", err)
	}
	return service, credentialKey
}

func managedConnectionCreateRequest(t *testing.T, f *managedConnectionAdminFixture, provider scim.ProviderID, rawKey string) ConnectionCreateRequest {
	t.Helper()
	path, err := scim.ParseMappingPath("userName", nil, f.config.Limits)
	if err != nil {
		t.Fatal("validate original mapping", err)
	}
	mappings, err := scim.NewMappingSet([]scim.Mapping{{Source: path, Target: f.config.UserNameField, Writable: true}})
	if err != nil {
		t.Fatal("validate original mapping set", err)
	}
	key, err := identity.NewIdempotencyKey([]byte(rawKey))
	if err != nil {
		t.Fatal("validate initiating request key", err)
	}
	return ConnectionCreateRequest{Authentication: f.admin, OrganizationID: f.organization, ProviderID: provider, Mappings: mappings, IdempotencyKey: key}
}
