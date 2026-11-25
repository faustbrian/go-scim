//go:build integration

package scimpostgres

import (
	"reflect"
	"testing"
	"time"

	identity "github.com/faustbrian/go-identity"
	organization "github.com/faustbrian/go-organization"
	organizationpg "github.com/faustbrian/go-organization/postgres"
	scim "github.com/faustbrian/go-scim"
)

func TestDirectorySourceSuccessorContinuesOriginalSealedObservation(t *testing.T) {
	f := newNativeFixture(t)
	installSource(t, f.ctx, f.pool, organizationpg.DirectoryMembershipMigrationSource{Version: 22})
	installSource(t, f.ctx, f.pool, organizationpg.DirectoryMembershipSuccessorMigrationSource{Version: 23})
	groups, err := NewGroupsService(f.service, 0)
	if err != nil {
		t.Fatal(err)
	}
	created, err := f.service.Execute(f.ctx, scim.Request{Operation: scim.UserCreate, Credential: f.bearer, IdempotencyKey: "directory-source-successor-user", ContentType: "application/scim+json", Body: []byte(`{"schemas":["urn:ietf:params:scim:schemas:core:2.0:User"],"userName":"SourceSuccessor","active":true}`)})
	if err != nil {
		t.Fatal("create exact source user", err)
	}
	user := parseNativeUser(t, created).ID
	original, err := groups.ObserveDirectorySource(f.ctx, f.config.Scope)
	if err != nil {
		t.Fatal("observe original generation source", err)
	}
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
	scope := f.config.Scope
	source := organizationpg.DirectoryMembershipSource{TenantID: scope.TenantID, OrganizationID: organization.ID(scope.OrganizationID), UserID: identity.UserID(user), ProviderID: organization.ID(scope.ProviderID), ConnectionID: organization.ID(scope.ConnectionID), ResourceID: organization.ID(user)}
	before, err := f.service.organizations.ObserveDirectoryMembership(f.ctx, source)
	if err != nil {
		t.Fatal(err)
	}
	update, err := organizationpg.NewDirectoryMembershipUpdate(organizationpg.DirectoryMembershipInput{
		Source: source, ActorID: f.config.ActorID, Organization: original.admission.organization,
		MemberVersion: before.Member.Version, MemberAuthorizationVersion: before.Member.AuthorizationVersion,
		ExpectedVersion: before.ContributionVersion, Action: organizationpg.DirectoryMembershipGrant,
		User:           identity.User{TenantID: scope.TenantID, ID: source.UserID, Status: identity.StatusActive, Version: 1},
		MaximumMembers: 10, MaximumPerUser: 10,
	})
	if err != nil {
		t.Fatal(err)
	}
	userOwner := &directoryMembershipTestOwner{
		groups: groups, observation: original, update: update, recordSuccessor: true,
		evidence: DirectoryUserMembershipEvidence{ResourceID: user, Revision: created.ETag, State: DirectoryMembershipUserActive},
		op:       identity.FeatureOperation{Owner: "sso", OperationID: "identity.sso.directory-sync.apply-user-admission", SchemaID: "sso.directory-user-admission", SchemaVersion: 1, RecordRequirement: identity.FeatureRecordRequired},
	}
	userCoordinator, userPlan := prepareDirectoryMembershipTest(t, f, userOwner, source.UserID)
	receipt, err := executeDirectorySourceWork(f.ctx, userCoordinator, userOwner.command, userPlan)
	if err != nil || receipt.Outcome != identity.CommitOutcomeCommitted || receipt.Feature == nil {
		t.Fatal("original source User admission did not commit", receipt.Outcome, err)
	}
	successor, err := groups.AdvanceDirectorySourceAfterUserCommit(f.ctx, original, user, receipt)
	if err != nil {
		t.Fatal("continue from exact committed User receipt", err)
	}
	wantAdmission := original.admission
	wantAdmission.organization.Version++
	if successor.source != original.source || !reflect.DeepEqual(successor.admission, wantAdmission) {
		t.Fatal("continuation changed more than the original organization version")
	}
	successorBindings, err := successor.Bindings()
	if err != nil || successorBindings != originalBindings {
		t.Fatal("continuation renewed or changed original bindings", err)
	}
	successorSnapshot, err := f.service.captureAdmission(f.ctx, successor.admission)
	wantSnapshot := originalSnapshot
	wantSnapshot.OrganizationVersion++
	if err != nil || successorSnapshot != wantSnapshot {
		t.Fatal("continuation replaced original authority epochs, snapshots or deadlines", err)
	}
	successorField, err := successor.Field()
	if err != nil || reflect.DeepEqual(successorField, originalField) {
		t.Fatal("successor did not bind its changed organization version", err)
	}
	retainedField, err := original.Field()
	if err != nil || !reflect.DeepEqual(retainedField, originalField) {
		t.Fatal("continuation mutated the sealed original source", err)
	}

	child := &directorySourceWorkOwner{groups: groups, observation: original}
	childCoordinator, registry := directorySourceWorkCoordinator(t, f, child)
	staleCommand, stalePlan := directorySourceWorkCommand(t, f, childCoordinator, registry, child, originalField, f.config.ActorID)
	staleResult, err := executeDirectorySourceWork(f.ctx, childCoordinator, staleCommand, stalePlan)
	if err == nil || staleResult.Outcome == identity.CommitOutcomeCommitted {
		t.Fatal("next Group child accepted the stale original organization authority")
	}
	child.observation = successor
	nextCommand, nextPlan := directorySourceWorkCommand(t, f, childCoordinator, registry, child, successorField, f.config.ActorID)
	nextResult, err := executeDirectorySourceWork(f.ctx, childCoordinator, nextCommand, nextPlan)
	if err != nil || nextResult.Outcome != identity.CommitOutcomeCommitted || nextResult.Feature == nil {
		t.Fatal("next borrowed Group source fence rejected the derived observation", nextResult.Outcome, err)
	}
	var effects int
	if err := f.pool.Raw().QueryRow(f.ctx, `SELECT count(*) FROM public.directory_source_test_effects`).Scan(&effects); err != nil || effects != 1 {
		t.Fatal("stale source left an effect or derived child failed to persist", effects, err)
	}

	foreignNative, err := NewService(f.pool, f.config, f.keys)
	if err != nil {
		t.Fatal(err)
	}
	foreignGroups, err := NewGroupsService(foreignNative, 0)
	if err != nil {
		t.Fatal(err)
	}
	wrongActor, wrongCorrelation := receipt, receipt
	wrongActor.Binding.ActorID = "other-service"
	wrongCorrelation.Binding.CorrelationID = "other-generation"
	foreignResource, err := identity.NewSubjectID()
	if err != nil || string(foreignResource) == user {
		t.Fatal("create a distinct canonical source resource", err)
	}
	expired := original
	expired.admission.connection.AuthorityReadBeganAt = expired.admission.connection.AuthorityReadBeganAt.Add(-time.Minute)
	expired.admission.connection.AuthorityValidUntil = expired.admission.connection.AuthorityValidUntil.Add(-time.Minute)
	expired.admission.organization.ReadStartedAt = expired.admission.organization.ReadStartedAt.Add(-time.Minute)
	expired.admission.organization.VerifiedAt = expired.admission.organization.VerifiedAt.Add(-time.Minute)
	expired.admission.organization.ValidUntil = expired.admission.organization.ValidUntil.Add(-time.Minute)
	for _, tc := range []struct {
		name     string
		groups   *GroupsService
		original DirectorySourceObservation
		resource string
		receipt  identity.CommandResult
	}{
		{name: "foreign configured service", groups: foreignGroups, original: original, resource: user, receipt: receipt},
		{name: "changed actor", groups: groups, original: original, resource: user, receipt: wrongActor},
		{name: "changed resource", groups: groups, original: original, resource: string(foreignResource), receipt: receipt},
		{name: "malformed resource", groups: groups, original: original, resource: "another-resource", receipt: receipt},
		{name: "changed correlation", groups: groups, original: original, resource: user, receipt: wrongCorrelation},
		{name: "expired original", groups: groups, original: expired, resource: user, receipt: receipt},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := tc.groups.AdvanceDirectorySourceAfterUserCommit(f.ctx, tc.original, tc.resource, tc.receipt)
			if err == nil || !reflect.DeepEqual(got, DirectorySourceObservation{}) {
				t.Fatal("invalid continuation returned usable source evidence", err)
			}
		})
	}
}
