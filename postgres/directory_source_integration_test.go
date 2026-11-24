//go:build integration

package scimpostgres

import (
	"testing"
	"time"

	scim "github.com/faustbrian/go-scim"
)

func TestDirectorySourceObservesExactConfiguredPrimaryOwners(t *testing.T) {
	f := newNativeFixture(t)
	groups, err := NewGroupsService(f.service, 0)
	if err != nil {
		t.Fatal(err)
	}
	// Source facts do not authorize synchronization or consult a new permission.
	f.deny.Store(true)
	start := time.Now().UTC()
	observation, err := groups.ObserveDirectorySource(f.ctx, f.config.Scope)
	if err != nil {
		t.Fatal("active configured source unavailable", err)
	}
	bindings, err := observation.Bindings()
	if err != nil || bindings.Scope != f.config.Scope || bindings.ActorID != f.config.ActorID || bindings.ConnectionVersion != 1 || bindings.ReadStartedAt.Before(start) || bindings.ReadStartedAt.After(time.Now().UTC()) || !bindings.ValidUntil.After(bindings.ReadStartedAt) || bindings.ValidUntil.After(bindings.ReadStartedAt.Add(20*time.Second)) {
		t.Fatal("configured source lost exact identity or original bounded freshness", err)
	}
	copyOfObservation := observation
	again, err := copyOfObservation.Bindings()
	if err != nil || again != bindings {
		t.Fatal("copying observation renewed or changed source bindings", err)
	}
	for _, change := range []func(*scim.Scope){
		func(s *scim.Scope) { s.TenantID = "another-tenant" },
		func(s *scim.Scope) { s.OrganizationID = "another-organization" },
		func(s *scim.Scope) { s.ProviderID = "another-provider" },
		func(s *scim.Scope) { s.ConnectionID = "another-connection" },
	} {
		foreign := f.config.Scope
		change(&foreign)
		if observed, err := groups.ObserveDirectorySource(f.ctx, foreign); err == nil || observed.source != nil {
			t.Fatal("configured source exposed foreign scope")
		}
	}
}

func TestDirectorySourceRejectsDisabledOrChangedPrimaryOwners(t *testing.T) {
	for _, test := range []struct {
		name   string
		change string
	}{
		{"global missing", `UPDATE identity.global_authorities SET authority_id='another-deployment' WHERE authority_id='scim-deployment'`},
		{"tenant disabled", `UPDATE identity.tenant_authorities SET enabled=false,version=version+1 WHERE tenant_id='tenant-a'`},
		{"organization archived", `UPDATE organization.organizations SET state='archived',version=version+1 WHERE tenant_id='tenant-a' AND organization_id='organization-a'`},
		// The pinned organization trigger owns credential epochs. A normal
		// archive/restore leaves the active owner at a newer revocation epoch;
		// direct epoch updates correctly fail rather than supplying this fixture.
		{"organization credential stale", `UPDATE organization.organizations SET state='archived',version=version+1 WHERE tenant_id='tenant-a' AND organization_id='organization-a'; UPDATE organization.organizations SET state='active',version=version+1 WHERE tenant_id='tenant-a' AND organization_id='organization-a'`},
		{"connection revoked", `UPDATE scim.connections SET state='revoked',version=version+1 WHERE tenant_id='tenant-a' AND connection_id='connection-a'`},
		{"connection expired", `UPDATE scim.connections SET expires_at=clock_timestamp()-interval '1 second' WHERE tenant_id='tenant-a' AND connection_id='connection-a'`},
		{"connection credential changed", `UPDATE scim.connections SET credential_digest=decode(repeat('00',32),'hex') WHERE tenant_id='tenant-a' AND connection_id='connection-a'`},
		{"connection configuration changed", `UPDATE scim.connections SET configuration_digest=decode(repeat('00',32),'hex') WHERE tenant_id='tenant-a' AND connection_id='connection-a'`},
		{"connection authority stale", `UPDATE scim.connections SET authority_version=authority_version+1 WHERE tenant_id='tenant-a' AND connection_id='connection-a'`},
	} {
		t.Run(test.name, func(t *testing.T) {
			f := newNativeFixture(t)
			groups, err := NewGroupsService(f.service, 0)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := groups.ObserveDirectorySource(f.ctx, f.config.Scope); err != nil {
				t.Fatal("configured source baseline unavailable", err)
			}
			if _, err := f.pool.Raw().Exec(f.ctx, test.change); err != nil {
				t.Fatal("change disposable primary owner", err)
			}
			if observed, err := groups.ObserveDirectorySource(f.ctx, f.config.Scope); err == nil || observed.source != nil {
				t.Fatal("disabled or changed primary owner admitted a source")
			}
		})
	}
}
