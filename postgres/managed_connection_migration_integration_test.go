//go:build integration

package scimpostgres

import (
	"errors"
	"testing"

	scim "github.com/faustbrian/go-scim"
	"github.com/jackc/pgx/v5/pgconn"
)

func TestManagedConnectionMigrationPreservesExistingProvisioning(t *testing.T) {
	f := newNativeFixture(t)
	userID := createNativeNamed(t, f, "ProvisionedBeforeManagement", "Original profile")
	installManagedConnectionFixtureMigration(t, f)

	response, err := f.service.Execute(f.ctx, scim.Request{Operation: scim.UserGet, Credential: f.bearer, ResourceID: userID})
	if err != nil || response.Status != 200 || parseNativeUser(t, response).UserName != "ProvisionedBeforeManagement" {
		t.Fatal("managed metadata migration changed existing configured provisioning", err)
	}
	var count int
	if err := f.pool.Raw().QueryRow(f.ctx, `SELECT count(*) FROM scim.managed_connections`).Scan(&count); err != nil || count != 0 {
		t.Fatal("migration automatically treated a configured connection as managed", err)
	}
}

func TestManagedConnectionMigrationRequiresExactBindingAndTenantUniqueID(t *testing.T) {
	f := newNativeFixture(t)
	installManagedConnectionFixtureMigration(t, f)
	const tenant, orgA, orgB = "AAAAAAAAAAAAAAAAAAAAAQ", "AAAAAAAAAAAAAAAAAAAAAg", "AAAAAAAAAAAAAAAAAAAAAw"
	const connection = "AAAAAAAAAAAAAAAAAAAABA"
	for _, org := range []struct{ id, slug string }{{orgA, "managed-one"}, {orgB, "managed-two"}} {
		_, err := f.pool.Raw().Exec(f.ctx, `INSERT INTO organization.organizations(tenant_id,organization_id,slug,name,state,version,member_count,owner_count,credential_version) VALUES($1,$2,$3,'Managed test organization','active',1,1,1,1)`, tenant, org.id, org.slug)
		if err != nil {
			t.Fatal("seed managed organization", err)
		}
	}
	insertRecord := func(org, provider string) error {
		_, err := f.pool.Raw().Exec(f.ctx, `INSERT INTO scim.managed_connections(tenant_id,organization_id,provider_id,connection_id,mappings,deprovision_policy) VALUES($1,$2,$3,$4,$5,'remove-membership')`, tenant, org, provider, connection, []byte(`[{"source":"userName","target":"username","writable":true}]`))
		return err
	}
	if err := insertRecord(orgA, "managed-provider"); !managedMigrationSQLState(err, "23503") {
		t.Fatal("managed metadata without an exact credential binding was accepted", err)
	}
	for _, binding := range []struct{ org, command string }{{orgA, "AAAAAAAAAAAAAAAAAAAABQ"}, {orgB, "AAAAAAAAAAAAAAAAAAAABg"}} {
		_, err := f.pool.Raw().Exec(f.ctx, `INSERT INTO scim.connections(tenant_id,organization_id,provider_id,connection_id,credential_id,credential_digest,configuration_digest,version,state,expires_at,authority_version,organization_credential_version,command_id,effect_digest) VALUES($1,$2,'managed-provider',$3,'managed-fixture',sha256('credential'),sha256('configuration'),1,'active',clock_timestamp()+interval '1 hour',1,1,$4,sha256('effect'))`, tenant, binding.org, connection, binding.command)
		if err != nil {
			t.Fatal("seed exact credential binding", err)
		}
	}
	if err := insertRecord(orgA, "other-provider"); !managedMigrationSQLState(err, "23503") {
		t.Fatal("managed metadata did not bind the exact provider", err)
	}
	if err := insertRecord(orgA, "managed-provider"); err != nil {
		t.Fatal("exact managed record was rejected", err)
	}
	if err := insertRecord(orgB, "managed-provider"); !managedMigrationSQLState(err, "23505") {
		t.Fatal("same tenant reused a managed connection ID across organizations", err)
	}
}

func installManagedConnectionFixtureMigration(t *testing.T, f *nativeFixture) {
	t.Helper()
	base := UsersMigrationSource{Base: MigrationSource{Version: 40}, Version: 41}
	history, err := (ManagedConnectionsMigrationSource{Base: base, Version: 42}).Load(f.ctx)
	if err != nil || len(history) != 3 {
		t.Fatal("load managed connection migration after the installed history", err)
	}
	if _, err := f.pool.Raw().Exec(f.ctx, history[2].UpSQL()); err != nil {
		t.Fatal("apply managed connection migration", err)
	}
}

func managedMigrationSQLState(err error, code string) bool {
	var pgErr *pgconn.PgError
	return errors.As(err, &pgErr) && pgErr.Code == code
}
