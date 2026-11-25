//go:build integration

package scimpostgres

import (
	"reflect"
	"testing"
	"time"

	identity "github.com/faustbrian/go-identity"
	kernel "github.com/faustbrian/go-identity/postgres"
	organizationpg "github.com/faustbrian/go-organization/postgres"
)

func directoryRoleSuccessorWork(t *testing.T) (*nativeFixture, *directoryGroupRoleWorkOwner, *kernel.Coordinator, *kernel.ContributorRegistry, identity.CommandResult) {
	t.Helper()
	f, owner := directoryGroupRoleWorkFixture(t)
	installSource(t, f.ctx, f.pool, organizationpg.DirectoryMembershipMigrationSource{Version: 66})
	installSource(t, f.ctx, f.pool, organizationpg.DirectoryMembershipSuccessorMigrationSource{Version: 67})
	installSource(t, f.ctx, f.pool, organizationpg.DirectoryTeamRoleSuccessorMigrationSource{Version: 68})
	owner.recordRoleSuccessor = true
	coordinator, registry := directorySourceWorkCoordinator(t, f, owner)
	command, plan := directoryRoleSuccessorCommand(t, f, owner, coordinator, registry)
	receipt, err := executeDirectorySourceWork(f.ctx, coordinator, command, plan)
	if err != nil || receipt.Outcome != identity.CommitOutcomeCommitted || receipt.Feature == nil || receipt.AuditEventID == "" {
		t.Fatal("original configured role Work did not commit with its real receipt", receipt.Outcome, err)
	}
	return f, owner, coordinator, registry, receipt
}

func directoryRoleSuccessorCommand(t *testing.T, f *nativeFixture, owner *directoryGroupRoleWorkOwner, coordinator *kernel.Coordinator, registry *kernel.ContributorRegistry) (identity.Command, kernel.CommandPlan) {
	t.Helper()
	fields := make([]identity.FeatureField, 0, 4)
	for _, field := range []func() (identity.FeatureField, error){owner.observation.Field, owner.edge.Field, owner.grant.Field, owner.update.Field} {
		value, err := field()
		if err != nil {
			t.Fatal(err)
		}
		fields = append(fields, value)
	}
	return directoryGroupRoleWorkCommand(t, f, coordinator, registry, owner, fields)
}

func TestDirectoryRoleSuccessorContinuesOriginalSealAndFencesNextGroupChild(t *testing.T) {
	f, owner, coordinator, registry, receipt := directoryRoleSuccessorWork(t)
	groups, original := owner.groups, owner.observation
	originalBindings, err := original.Bindings()
	if err != nil {
		t.Fatal(err)
	}
	originalField, err := original.Field()
	if err != nil {
		t.Fatal(err)
	}
	originalSnapshot, err := f.service.captureAdmission(f.ctx, original.admission)
	if err != nil {
		t.Fatal(err)
	}
	successor, err := groups.AdvanceDirectorySourceAfterRoleCommit(f.ctx, original, owner.source, receipt)
	if err != nil {
		t.Fatal("continue from exact original committed role receipt", err)
	}
	wantAdmission := original.admission
	wantAdmission.organization.Version++
	if successor.source != original.source || !reflect.DeepEqual(successor.admission, wantAdmission) {
		t.Fatal("role continuation changed more than the original organization version")
	}
	bindings, err := successor.Bindings()
	if err != nil || bindings != originalBindings {
		t.Fatal("role continuation changed configured identity, authority read time or original deadline", err)
	}
	wantSnapshot := originalSnapshot
	wantSnapshot.OrganizationVersion++
	snapshot, err := f.service.captureAdmission(f.ctx, successor.admission)
	if err != nil || snapshot != wantSnapshot {
		t.Fatal("role continuation refreshed original owner epochs or deadlines", err)
	}
	successorField, err := successor.Field()
	if err != nil || reflect.DeepEqual(successorField, originalField) {
		t.Fatal("role successor did not bind its changed organization version", err)
	}
	if retained, err := original.Field(); err != nil || !reflect.DeepEqual(retained, originalField) {
		t.Fatal("role continuation mutated the original sealed source", err)
	}

	foreignNative, err := NewService(f.pool, f.config, f.keys)
	if err != nil {
		t.Fatal(err)
	}
	foreignGroups, err := NewGroupsService(foreignNative, 0)
	if err != nil {
		t.Fatal(err)
	}
	for _, mode := range []string{"foreign-service", "actor", "provider", "connection", "group", "role", "member-resource", "mapping-version", "expired"} {
		t.Run(mode, func(t *testing.T) {
			service, observed, source, result := groups, original, owner.source, receipt
			switch mode {
			case "foreign-service":
				service = foreignGroups
			case "actor":
				result.Binding.ActorID = "other-service"
			case "provider":
				source.Scope.ProviderID = "other-provider"
			case "connection":
				source.Scope.ConnectionID = "other-connection"
			case "group":
				source.Scope.GroupID = "other-group"
			case "role":
				source.RoleID = "other-role"
			case "member-resource":
				source.MemberResourceID = "other-member"
			case "mapping-version":
				source.MappingVersion++
			case "expired":
				observed.admission.connection.AuthorityReadBeganAt = observed.admission.connection.AuthorityReadBeganAt.Add(-time.Minute)
				observed.admission.connection.AuthorityValidUntil = observed.admission.connection.AuthorityValidUntil.Add(-time.Minute)
				observed.admission.organization.ReadStartedAt = observed.admission.organization.ReadStartedAt.Add(-time.Minute)
				observed.admission.organization.VerifiedAt = observed.admission.organization.VerifiedAt.Add(-time.Minute)
				observed.admission.organization.ValidUntil = observed.admission.organization.ValidUntil.Add(-time.Minute)
			}
			got, err := service.AdvanceDirectorySourceAfterRoleCommit(f.ctx, observed, source, result)
			if err == nil || !reflect.DeepEqual(got, DirectorySourceObservation{}) {
				t.Fatal("unproven role continuation returned usable source evidence", mode, err)
			}
		})
	}
	if _, err := groups.AdvanceDirectorySourceAfterRoleCommit(f.ctx, original, owner.source, receipt); err != nil {
		t.Fatal("negative cases changed original role successor evidence", err)
	}

	current, err := f.service.organizations.ObserveDirectoryTeamMembership(f.ctx, owner.source.Scope)
	if err != nil {
		t.Fatal(err)
	}
	owner.input.OrganizationVersion, owner.input.CredentialVersion = current.OrganizationVersion, current.CredentialVersion
	owner.input.MemberVersion, owner.input.MemberAuthorizationVersion = current.MemberVersion, current.MemberAuthorizationVersion
	owner.input.TeamVersion, owner.input.User.Version, owner.input.ExpectedVersion = current.TeamVersion, current.UserVersion, current.Version
	owner.grant, err = organizationpg.NewDirectoryTeamGrantUpdate(owner.input)
	if err != nil {
		t.Fatal(err)
	}
	owner.update, err = organizationpg.NewDirectoryTeamRoleUpdate(owner.grant, owner.source, 1)
	if err != nil {
		t.Fatal(err)
	}
	staleCommand, stalePlan := directoryRoleSuccessorCommand(t, f, owner, coordinator, registry)
	if got, err := executeDirectorySourceWork(f.ctx, coordinator, staleCommand, stalePlan); err == nil || got.Outcome == identity.CommitOutcomeCommitted {
		t.Fatal("next real Group role child accepted stale original source authority", got.Outcome, err)
	}
	owner.observation = successor
	nextCommand, nextPlan := directoryRoleSuccessorCommand(t, f, owner, coordinator, registry)
	next, err := executeDirectorySourceWork(f.ctx, coordinator, nextCommand, nextPlan)
	if err != nil || next.Outcome != identity.CommitOutcomeCommitted || next.Feature == nil || next.Feature.BeforeVersion != 1 || next.Feature.AfterVersion != 2 {
		t.Fatal("next real Group role child rejected derived source authority", next.Outcome, err)
	}
	var effects int
	if err := f.pool.Raw().QueryRow(f.ctx, `SELECT count(*) FROM public.directory_source_test_effects`).Scan(&effects); err != nil || effects != 2 {
		t.Fatal("stale Group child persisted an effect or derived child failed to commit", effects, err)
	}
}

func TestDirectoryRoleSuccessorRestartPrefixRequiresCurrentExactConfiguredSeal(t *testing.T) {
	f, owner, _, _, receipt := directoryRoleSuccessorWork(t)
	original := owner.observation
	current, err := owner.groups.ObserveDirectorySource(f.ctx, f.config.Scope)
	if err != nil {
		t.Fatal("observe current configured seal after restart", err)
	}
	child, err := organizationpg.NewDirectoryTeamRoleCommittedChild(owner.source, receipt)
	if err != nil {
		t.Fatal("prepare original real role child for historical prefix", err)
	}
	prefix := []organizationpg.DirectorySourceCommittedChild{child}
	if err := owner.groups.ValidateDirectorySourceSuccessorPrefix(f.ctx, current, prefix); err != nil {
		t.Fatal("current configured seal rejected exact durable role prefix", err)
	}
	if err := owner.groups.ValidateDirectorySourceSuccessorPrefix(f.ctx, original, prefix); err == nil {
		t.Fatal("stale original seal accepted a role prefix reaching a newer owner version")
	}
	foreignSource, foreignReceipt := owner.source, receipt
	foreignSource.Scope.ProviderID = "other-provider"
	foreignReceipt.Binding.RecordID, err = foreignSource.Scope.RecordID()
	if err != nil {
		t.Fatal(err)
	}
	foreignChild, err := organizationpg.NewDirectoryTeamRoleCommittedChild(foreignSource, foreignReceipt)
	if err != nil {
		t.Fatal("prepare structurally valid foreign source for rejection", err)
	}
	if err := owner.groups.ValidateDirectorySourceSuccessorPrefix(f.ctx, current, []organizationpg.DirectorySourceCommittedChild{foreignChild}); err == nil {
		t.Fatal("configured current seal accepted a foreign source prefix")
	}
	foreignNative, err := NewService(f.pool, f.config, f.keys)
	if err != nil {
		t.Fatal(err)
	}
	foreignGroups, err := NewGroupsService(foreignNative, 0)
	if err != nil {
		t.Fatal(err)
	}
	if err := foreignGroups.ValidateDirectorySourceSuccessorPrefix(f.ctx, current, prefix); err == nil {
		t.Fatal("prefix validation transferred an original seal to another configured service")
	}
	if err := owner.groups.ValidateDirectorySourceSuccessorPrefix(f.ctx, current, prefix); err != nil {
		t.Fatal("rejected prefixes changed exact persisted role evidence", err)
	}
	if _, err := f.pool.Raw().Exec(f.ctx, `UPDATE organization.organizations SET version=version+1 WHERE tenant_id='tenant-a' AND organization_id='organization-a'`); err != nil {
		t.Fatal(err)
	}
	later, err := owner.groups.ObserveDirectorySource(f.ctx, f.config.Scope)
	if err != nil {
		t.Fatal(err)
	}
	if err := owner.groups.ValidateDirectorySourceSuccessorPrefix(f.ctx, later, prefix); err == nil {
		t.Fatal("historical role prefix adopted an unrelated later owner transition")
	}
}
