//go:build integration

package scimpostgres

import (
	"context"
	"strconv"
	"testing"
	"time"

	"github.com/faustbrian/go-audit"
	"github.com/faustbrian/go-authorization/v3"
	authoritypg "github.com/faustbrian/go-authorization/v3/postgres"
	identity "github.com/faustbrian/go-identity"
	kernel "github.com/faustbrian/go-identity/postgres"
	organization "github.com/faustbrian/go-organization"
	organizationpg "github.com/faustbrian/go-organization/postgres"
	scim "github.com/faustbrian/go-scim"
)

type directoryGroupRoleWorkOwner struct {
	directorySourceWorkOwner
	edge   DirectoryGroupEdge
	source organizationpg.DirectoryTeamRoleSource
	input  organizationpg.DirectoryTeamGrantInput
	grant  organizationpg.DirectoryTeamGrantUpdate
	update organizationpg.DirectoryTeamRoleUpdate
	locked organizationpg.DirectoryTeamRoleLock
	late   string
}

func (p *directoryGroupRoleWorkOwner) ValidateFeatureCommand(command identity.Command, plan kernel.CommandPlan) error {
	spec, ok := command.Feature()
	if !ok || command != p.command || spec.Operation != p.FeatureOperations()[0] || plan.Lifecycle == nil ||
		plan.Lifecycle.BeforeVersion != p.grant.BeforeVersion() || plan.Lifecycle.AfterVersion != p.grant.AfterVersion() {
		return identity.ForbiddenError{}
	}
	return nil
}

func (p *directoryGroupRoleWorkOwner) ApplyFeature(ctx context.Context, w kernel.Work, command identity.Command) (identity.FeatureReceipt, error) {
	p.applyCalls++
	if p.reconstruct {
		spec, _ := command.Feature()
		var err error
		command, err = identity.NewFeatureCommand(spec)
		if err != nil {
			return identity.FeatureReceipt{}, err
		}
	}
	var owner kernel.FeatureExecutionContributor = p
	if p.foreign {
		copyOfOwner := *p
		owner = &copyOfOwner
	}
	var err error
	p.locked, err = p.groups.LockDirectoryGroupRole(ctx, w, owner, command, p.observation, p.edge, p.source, p.update)
	if err != nil {
		return identity.FeatureReceipt{}, err
	}
	if err := p.groups.native.organizations.ApplyDirectoryTeamRoleUpdate(ctx, w, p, command, p.update, p.locked); err != nil {
		return identity.FeatureReceipt{}, err
	}
	spec, _ := command.Feature()
	if _, err := w.Exec(ctx, `INSERT INTO public.directory_source_test_effects(command_id) VALUES($1)`, string(spec.Binding.CommandID)); err != nil {
		return identity.FeatureReceipt{}, err
	}
	var sql string
	switch p.late {
	case "edge":
		sql = `UPDATE scim.groups SET resource=convert_to('null','UTF8'),deleted_at=clock_timestamp(),generation=generation+1 WHERE resource_id=$1`
	case "connection":
		sql = `UPDATE scim.connections SET state='revoked',version=version+1 WHERE connection_id='connection-a' AND $1::text<>''`
	case "organization":
		sql = `UPDATE organization.organizations SET version=version+1 WHERE organization_id='organization-a' AND $1::text<>''`
	case "credential":
		sql = `UPDATE organization.organizations SET state='archived',version=version+1 WHERE organization_id='organization-a' AND $1::text<>''`
	case "deadline":
		p.observation.admission.connection.AuthorityValidUntil = time.Now().Add(-time.Second)
	}
	if sql != "" {
		if _, err := w.Exec(ctx, sql, p.edge.GroupID); err != nil {
			return identity.FeatureReceipt{}, err
		}
	}
	return identity.FeatureReceipt{Operation: p.FeatureOperations()[0], BeforeVersion: p.grant.BeforeVersion(), AfterVersion: p.grant.AfterVersion()}, nil
}

func (p *directoryGroupRoleWorkOwner) CheckFeatureCommit(ctx context.Context, w kernel.Work, command identity.Command) error {
	p.finalCalls++
	if command != p.command {
		return identity.ForbiddenError{}
	}
	if err := p.groups.native.organizations.RequireDirectoryTeamRoleUpdate(ctx, w, p, command, p.update, p.locked); err != nil {
		return err
	}
	return p.groups.RequireDirectoryGroupRoleAtCommit(ctx, w, p, command, p.observation, p.edge, p.source, p.locked)
}

func directoryGroupRoleWorkFixture(t *testing.T) (*nativeFixture, *directoryGroupRoleWorkOwner) {
	t.Helper()
	f, groups := nativeGroupsFixture(t)
	user := createNativeNamed(t, f, "RoleWorkUser", "Role Work")
	response, err := groups.Execute(f.ctx, groupRequest(f, scim.GroupCreate, "", "", "role-work-group", `{"schemas":["urn:ietf:params:scim:schemas:core:2.0:Group"],"displayName":"Role Work","members":[{"value":"`+user+`","type":"User"}]}`))
	if err != nil {
		t.Fatal(err)
	}
	installSource(t, f.ctx, f.pool, organizationpg.TeamMigrationSource{Version: 60})
	installSource(t, f.ctx, f.pool, organizationpg.TeamLifecycleMigrationSource{Version: 61})
	installSource(t, f.ctx, f.pool, organizationpg.DynamicRoleMigrationSource{Version: 62})
	installSource(t, f.ctx, f.pool, organizationpg.TeamRoleBindingMigrationSource{Version: 63})
	installSource(t, f.ctx, f.pool, organizationpg.DirectoryTeamGrantMigrationSource{Version: 64})
	installSource(t, f.ctx, f.pool, organizationpg.DirectoryTeamRoleMigrationSource{Version: 65})
	for _, sql := range []string{
		`INSERT INTO organization.memberships(tenant_id,organization_id,user_id,role,state,version,authorization_version) VALUES('tenant-a','organization-a',$1,'member','active',1,1)`,
		`INSERT INTO organization.teams(tenant_id,organization_id,team_id,name,version) SELECT 'tenant-a','organization-a','team-a','Role Work',1 WHERE $1::text<>''`,
		`INSERT INTO organization.custom_roles(tenant_id,organization_id,role_id,name,version,state,statements) SELECT 'tenant-a','organization-a','reader','Reader',1,'active','[]' WHERE $1::text<>''`,
		`INSERT INTO organization.team_role_bindings(tenant_id,organization_id,team_id,role_id,version,state) SELECT 'tenant-a','organization-a','team-a','reader',1,'active' WHERE $1::text<>''`,
	} {
		if _, err := f.pool.Raw().Exec(f.ctx, sql, user); err != nil {
			t.Fatal("install native member and selected role", err)
		}
	}
	authority, err := organizationpg.OrganizationAuthorityScope(f.config.Scope.TenantID, f.config.Scope.OrganizationID, identity.UserID(user))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := authoritypg.InitializeAuthority(f.ctx, f.pool.Raw(), authority, time.Second); err != nil {
		t.Fatal(err)
	}
	scope := organizationpg.DirectoryTeamGrantScope{TenantID: f.config.Scope.TenantID, OrganizationID: f.config.Scope.OrganizationID, ProviderID: organization.ID(f.config.Scope.ProviderID), ConnectionID: organization.ID(f.config.Scope.ConnectionID), GroupID: organization.ID(groupID(t, response)), TeamID: "team-a", UserID: identity.UserID(user)}
	input := organizationpg.DirectoryTeamGrantInput{Scope: scope, ActorID: f.config.ActorID, User: identity.User{ID: scope.UserID, TenantID: scope.TenantID, Status: identity.StatusActive, Version: 1}, OrganizationVersion: 1, CredentialVersion: 1, MemberVersion: 1, MemberAuthorizationVersion: 1, TeamVersion: 1, Active: true}
	grant, err := organizationpg.NewDirectoryTeamGrantUpdate(input)
	if err != nil {
		t.Fatal(err)
	}
	source := organizationpg.DirectoryTeamRoleSource{Scope: scope, MemberResourceID: organization.ID(user), RoleID: "reader", ProviderVersion: 1, MappingVersion: 1, ConnectionVersion: 1}
	update, err := organizationpg.NewDirectoryTeamRoleUpdate(grant, source, 1)
	if err != nil {
		t.Fatal(err)
	}
	observation, err := groups.ObserveDirectorySource(f.ctx, f.config.Scope)
	if err != nil {
		t.Fatal(err)
	}
	return f, &directoryGroupRoleWorkOwner{directorySourceWorkOwner: directorySourceWorkOwner{groups: groups, observation: observation}, edge: DirectoryGroupEdge{GroupID: string(scope.GroupID), UserID: user, Present: true}, source: source, input: input, grant: grant, update: update}
}

func directoryGroupRoleWorkCommand(t *testing.T, f *nativeFixture, coordinator *kernel.Coordinator, registry *kernel.ContributorRegistry, owner *directoryGroupRoleWorkOwner, fields []identity.FeatureField) (identity.Command, kernel.CommandPlan) {
	t.Helper()
	commandID, err := identity.NewCommandID()
	if err != nil {
		t.Fatal(err)
	}
	operation := owner.FeatureOperations()[0]
	binding := identity.CommandBinding{CommandID: commandID, TenantID: f.config.Scope.TenantID, UserID: owner.source.Scope.UserID, ActorID: f.config.ActorID, ActorKind: authorization.SubjectServiceAccount, OperationID: operation.OperationID, PolicyID: f.config.PolicyID, PolicyVersion: f.config.PolicyVersion, SchemaID: operation.SchemaID, SchemaVersion: operation.SchemaVersion, CorrelationID: "directory-role-test", RecordID: owner.grant.RecordID()}
	command, err := identity.NewFeatureCommand(identity.FeatureCommandSpec{Binding: binding, Operation: operation, Fields: fields})
	if err != nil {
		t.Fatal(err)
	}
	owner.command = command
	builder, err := audit.NewBuilder(audit.BuilderConfig{})
	if err != nil {
		t.Fatal(err)
	}
	before, after := owner.grant.BeforeVersion(), owner.grant.AfterVersion()
	record, err := builder.Build(audit.RecordInput{OccurredAt: time.Now().UTC(), Action: operation.OperationID, Outcome: audit.OutcomeSucceeded, Actor: audit.ActorInput{Kind: audit.ActorService, ID: string(binding.ActorID)}, Subject: audit.SubjectInput{Type: "team_membership", ID: binding.RecordID}, Context: audit.ContextInput{TenantID: string(binding.TenantID), CorrelationID: binding.CorrelationID}, Policy: audit.PolicyMetadata{PolicyID: binding.PolicyID, Version: "1"}, Changes: audit.ChangeSetInput{Redacted: true}, Attributes: map[string]string{"command.id": string(binding.CommandID), "aggregate.type": "team_membership", "aggregate.id": binding.RecordID, "aggregate.before_version": strconv.FormatUint(before, 10), "aggregate.after_version": strconv.FormatUint(after, 10), "retention.class": "protected"}})
	if err != nil {
		t.Fatal(err)
	}
	digest, err := kernel.FeatureAuditBindingDigest(binding, operation, "team_membership", record)
	if err != nil {
		t.Fatal(err)
	}
	plan, err := coordinator.PrepareCommandPlan(binding, command, kernel.CommandPlan{Contributors: registry.Descriptors(), Feature: &kernel.FeatureRegistration{Contributor: owner.Descriptor(), Operation: operation}, SubjectType: "team_membership", Lifecycle: &kernel.LifecyclePlan{EventType: "directory.team-membership.changed.v1", BeforeVersion: before, AfterVersion: after}, Audits: []kernel.AuditPlan{{EventType: operation.OperationID, SchemaVersion: 1, BindingDigest: digest, RetentionPolicyVersion: 1, RequiredRecordCount: 1, MaxRecordBytes: 16384, MaxAggregateBytes: 16384, RetentionClass: "protected", Required: true}}})
	if err != nil {
		t.Fatal(err)
	}
	return command, plan
}

func TestDirectoryGroupRoleNativeWorkExactSourceAndRollback(t *testing.T) {
	for _, mode := range []string{"exact", "absent edge active update", "inactive source User", "foreign tenant", "foreign organization", "foreign provider", "foreign connection", "stale connection", "wrong group", "wrong member", "wrong target", "wrong role source", "missing source field", "missing edge field", "wrong role field", "foreign owner", "reconstructed command", "late edge", "late connection", "late organization", "late credential", "late deadline"} {
		t.Run(mode, func(t *testing.T) {
			f, owner := directoryGroupRoleWorkFixture(t)
			sourceField, err := owner.observation.Field()
			if err != nil {
				t.Fatal(err)
			}
			edgeField, err := owner.edge.Field()
			if err != nil {
				t.Fatal(err)
			}
			grantField, err := owner.grant.Field()
			if err != nil {
				t.Fatal(err)
			}
			roleField, err := owner.update.Field()
			if err != nil {
				t.Fatal(err)
			}
			switch mode {
			case "absent edge active update":
				current, err := owner.groups.Execute(f.ctx, groupRequest(f, scim.GroupGet, owner.edge.GroupID, "", "", ""))
				if err != nil {
					t.Fatal(err)
				}
				if _, err := owner.groups.Execute(f.ctx, groupRequest(f, scim.GroupPatch, owner.edge.GroupID, current.ETag, "unlink-role-source", `{"schemas":["urn:ietf:params:scim:api:messages:2.0:PatchOp"],"Operations":[{"op":"remove","path":"members"}]}`)); err != nil {
					t.Fatal("remove real role source edge", err)
				}
				owner.edge.Present = false
				edgeField, err = owner.edge.Field()
				if err != nil {
					t.Fatal(err)
				}
			case "inactive source User":
				current, err := f.service.Execute(f.ctx, scim.Request{Operation: scim.UserGet, Credential: f.bearer, ResourceID: owner.edge.UserID})
				if err != nil {
					t.Fatal(err)
				}
				if _, err := f.service.Execute(f.ctx, scim.Request{Operation: scim.UserPatch, Credential: f.bearer, ResourceID: owner.edge.UserID, IfMatch: current.ETag, ContentType: "application/scim+json", Body: []byte(`{"schemas":["urn:ietf:params:scim:api:messages:2.0:PatchOp"],"Operations":[{"op":"replace","path":"active","value":false}]}`)}); err != nil {
					t.Fatal("deactivate real source User", err)
				}
				var version string
				if err := f.pool.Raw().QueryRow(f.ctx, `SELECT version::text FROM identity.users WHERE tenant_id=$1 AND user_id=$2`, string(owner.input.Scope.TenantID), owner.edge.UserID).Scan(&version); err != nil {
					t.Fatal(err)
				}
				owner.input.User.Version, err = strconv.ParseUint(version, 10, 64)
				if err != nil {
					t.Fatal(err)
				}
				owner.grant, err = organizationpg.NewDirectoryTeamGrantUpdate(owner.input)
				if err != nil {
					t.Fatal(err)
				}
				owner.update, err = organizationpg.NewDirectoryTeamRoleUpdate(owner.grant, owner.source, 1)
				if err != nil {
					t.Fatal(err)
				}
				grantField, err = owner.grant.Field()
				if err != nil {
					t.Fatal(err)
				}
				roleField, err = owner.update.Field()
				if err != nil {
					t.Fatal(err)
				}
			case "foreign tenant":
				owner.source.Scope.TenantID = "other-tenant"
			case "foreign organization":
				owner.source.Scope.OrganizationID = "other-organization"
			case "foreign provider":
				owner.source.Scope.ProviderID = "other-provider"
			case "foreign connection":
				owner.source.Scope.ConnectionID = "other-connection"
			case "stale connection":
				owner.source.ConnectionVersion++
			case "wrong group":
				owner.source.Scope.GroupID = "other-group"
			case "wrong member":
				owner.source.MemberResourceID = "other-member"
			case "wrong target":
				owner.source.Scope.UserID = "other-user"
			case "wrong role source":
				owner.source.RoleID = "other-role"
			case "missing source field":
				sourceField.Name = "test.missing-source"
			case "missing edge field":
				edgeField.Name = "test.missing-edge"
			case "wrong role field":
				roleField.Value.Bytes[0] ^= 1
			case "foreign owner":
				owner.foreign = true
			case "reconstructed command":
				owner.reconstruct = true
			case "late edge", "late connection", "late organization", "late credential", "late deadline":
				owner.late = mode[len("late "):]
			}
			coordinator, registry := directorySourceWorkCoordinator(t, f, owner)
			command, plan := directoryGroupRoleWorkCommand(t, f, coordinator, registry, owner, []identity.FeatureField{sourceField, edgeField, grantField, roleField})
			var auditsBefore, eventsBefore int
			if err := f.pool.Raw().QueryRow(f.ctx, `SELECT (SELECT count(*) FROM audit.identity_command_bindings),(SELECT count(*) FROM public.outbox_messages)`).Scan(&auditsBefore, &eventsBefore); err != nil {
				t.Fatal(err)
			}
			result, err := executeDirectorySourceWork(f.ctx, coordinator, command, plan)
			wantEffects := 0
			if mode == "exact" {
				wantEffects = 1
				if err != nil || result.Outcome != identity.CommitOutcomeCommitted {
					t.Fatal("exact source failed native role commit", result.Outcome, err)
				}
				replay, err := executeDirectorySourceWork(f.ctx, coordinator, command, plan)
				if err != nil || replay.Outcome != identity.CommitOutcomeCommitted || replay.Feature == nil || result.Feature == nil || *replay.Feature != *result.Feature {
					t.Fatal("role replay lost original receipt", err)
				}
			} else if err == nil || result.Outcome == identity.CommitOutcomeCommitted {
				t.Fatal("mismatched or late-changed role source committed", result.Outcome, err)
			}
			var effects, grants, roles, auditsAfter, eventsAfter int
			var organizationVersion, memberAuthorizationVersion string
			if err := f.pool.Raw().QueryRow(f.ctx, `SELECT (SELECT count(*) FROM public.directory_source_test_effects),(SELECT count(*) FROM organization.directory_team_grants),(SELECT count(*) FROM organization.directory_team_role_grants),(SELECT count(*) FROM audit.identity_command_bindings),(SELECT count(*) FROM public.outbox_messages),(SELECT version::text FROM organization.organizations WHERE organization_id='organization-a'),(SELECT authorization_version::text FROM organization.memberships)`).Scan(&effects, &grants, &roles, &auditsAfter, &eventsAfter, &organizationVersion, &memberAuthorizationVersion); err != nil {
				t.Fatal(err)
			}
			wantVersion := "1"
			if wantEffects == 1 {
				wantVersion = "2"
			}
			if effects != wantEffects || grants != wantEffects || roles != wantEffects || eventsAfter-eventsBefore != wantEffects || auditsAfter-auditsBefore != 1 || organizationVersion != wantVersion || memberAuthorizationVersion != wantVersion || owner.applyCalls != 1 {
				t.Fatal("role source lost atomic projection, audit, authorization or replay", effects, grants, roles, eventsAfter-eventsBefore, auditsAfter-auditsBefore, organizationVersion, memberAuthorizationVersion, owner.applyCalls)
			}
			if owner.late != "" {
				var groupLive, connectionLive, organizationLive bool
				if err := f.pool.Raw().QueryRow(f.ctx, `SELECT (SELECT deleted_at IS NULL FROM scim.groups WHERE resource_id=$1),(SELECT state='active' AND version=1 FROM scim.connections WHERE connection_id='connection-a'),(SELECT state='active' AND credential_version=1 FROM organization.organizations WHERE organization_id='organization-a')`, owner.edge.GroupID).Scan(&groupLive, &connectionLive, &organizationLive); err != nil || !groupLive || !connectionLive || !organizationLive || owner.finalCalls != 1 {
					t.Fatal("late role-source mismatch escaped rollback", err)
				}
			}
			if mode == "exact" {
				verifyDirectoryGroupRoleWithdrawal(t, f, owner, coordinator, registry)
			}
		})
	}
}

func verifyDirectoryGroupRoleWithdrawal(t *testing.T, f *nativeFixture, owner *directoryGroupRoleWorkOwner, coordinator *kernel.Coordinator, registry *kernel.ContributorRegistry) {
	t.Helper()
	group, err := owner.groups.Execute(f.ctx, groupRequest(f, scim.GroupGet, owner.edge.GroupID, "", "", ""))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := owner.groups.Execute(f.ctx, groupRequest(f, scim.GroupPatch, owner.edge.GroupID, group.ETag, "withdraw-role-edge", `{"schemas":["urn:ietf:params:scim:api:messages:2.0:PatchOp"],"Operations":[{"op":"remove","path":"members"}]}`)); err != nil {
		t.Fatal("withdraw exact native Group edge", err)
	}
	owner.edge.Present = false
	owner.observation, err = owner.groups.ObserveDirectorySource(f.ctx, f.config.Scope)
	if err != nil {
		t.Fatal(err)
	}
	repository := owner.groups.native.organizations
	initial, err := repository.ObserveDirectoryTeamMembership(f.ctx, owner.source.Scope)
	if err != nil || !initial.Source || initial.Version != 1 {
		t.Fatal("missing role grant predecessor", err)
	}
	owner.input.Active, owner.input.ExpectedVersion = false, initial.Version
	owner.input.OrganizationVersion = initial.OrganizationVersion
	owner.input.MemberAuthorizationVersion = initial.MemberAuthorizationVersion
	owner.grant, err = organizationpg.NewDirectoryTeamGrantUpdate(owner.input)
	if err != nil {
		t.Fatal(err)
	}
	owner.update, err = organizationpg.NewDirectoryTeamRoleUpdate(owner.grant, owner.source, 0)
	if err != nil {
		t.Fatal(err)
	}
	fields := make([]identity.FeatureField, 0, 4)
	for _, field := range []func() (identity.FeatureField, error){owner.observation.Field, owner.edge.Field, owner.grant.Field, owner.update.Field} {
		f, err := field()
		if err != nil {
			t.Fatal(err)
		}
		fields = append(fields, f)
	}
	command, plan := directoryGroupRoleWorkCommand(t, f, coordinator, registry, owner, fields)
	out, err := executeDirectorySourceWork(f.ctx, coordinator, command, plan)
	if err != nil || out.Outcome != identity.CommitOutcomeCommitted || out.Feature == nil || out.Feature.BeforeVersion != 1 || out.Feature.AfterVersion != 2 {
		t.Fatal("exact absent edge did not withdraw its own role", err)
	}
	replayed, err := executeDirectorySourceWork(f.ctx, coordinator, command, plan)
	if err != nil || replayed.Feature == nil || *replayed.Feature != *out.Feature || owner.applyCalls != 2 {
		t.Fatal("original withdrawal receipt was not recovered exactly", err)
	}
	after, err := repository.ObserveDirectoryTeamMembership(f.ctx, owner.source.Scope)
	var roles int
	readErr := f.pool.Raw().QueryRow(f.ctx, "SELECT count(*) FROM organization.directory_team_role_grants").Scan(&roles)
	if err != nil || readErr != nil || after.Source || after.Local || after.Version != 2 || roles != 0 ||
		after.OrganizationVersion != initial.OrganizationVersion+1 || after.MemberAuthorizationVersion != initial.MemberAuthorizationVersion+1 {
		t.Fatal("scoped withdrawal did not leave exactly its original tombstone", err, readErr)
	}
}
