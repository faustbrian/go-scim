//go:build integration

package scimpostgres

import (
	"context"
	"errors"
	"reflect"
	"strconv"
	"testing"
	"time"

	"github.com/faustbrian/go-audit"
	auditpg "github.com/faustbrian/go-audit/postgres"
	"github.com/faustbrian/go-authorization/v3"
	identity "github.com/faustbrian/go-identity"
	kernel "github.com/faustbrian/go-identity/postgres"
	organization "github.com/faustbrian/go-organization"
	organizationpg "github.com/faustbrian/go-organization/postgres"
	scim "github.com/faustbrian/go-scim"
	lifecyclepg "github.com/faustbrian/go-transactional-outbox/postgres/identity"
)

// The coordinator, source and organization writer are real. This participant
// exercises their shared Work; native SSO owns the generation and admission.
type directoryMembershipTestOwner struct {
	groups          *GroupsService
	observation     DirectorySourceObservation
	evidence        DirectoryUserMembershipEvidence
	update          organizationpg.DirectoryMembershipUpdate
	effect          organizationpg.DirectoryMembershipEffect
	op              identity.FeatureOperation
	command         identity.Command
	zeroEffect      bool
	recordSuccessor bool
	applyCalls      int
	afterLock       func(context.Context, kernel.Work) error
}

func (p *directoryMembershipTestOwner) Descriptor() kernel.ContributorDescriptor {
	return kernel.ContributorDescriptor{Owner: "sso/postgres", ContractID: p.op.SchemaID, Version: 1}
}

func (p *directoryMembershipTestOwner) FeatureOperations() []identity.FeatureOperation {
	return []identity.FeatureOperation{p.op}
}

func (p *directoryMembershipTestOwner) ValidateFeatureCommand(command identity.Command, plan kernel.CommandPlan) error {
	if command != p.command || plan.Lifecycle == nil || plan.Lifecycle.BeforeVersion != p.update.BeforeVersion() || plan.Lifecycle.AfterVersion != p.update.AfterVersion() {
		return identity.ForbiddenError{}
	}
	return nil
}

func (p *directoryMembershipTestOwner) ApplyFeature(ctx context.Context, w kernel.Work, command identity.Command) (identity.FeatureReceipt, error) {
	p.applyCalls++
	locked, err := p.groups.LockDirectoryUserMembership(ctx, w, p, command, p.observation, p.evidence, p.update)
	if err != nil {
		return identity.FeatureReceipt{}, err
	}
	if p.afterLock != nil {
		if err := p.afterLock(ctx, w); err != nil {
			return identity.FeatureReceipt{}, err
		}
	}
	p.effect, err = p.groups.native.organizations.ApplyDirectoryMembershipUpdate(ctx, w, p, command, p.update, locked)
	if err != nil {
		return identity.FeatureReceipt{}, err
	}
	if p.recordSuccessor {
		if err := p.groups.native.organizations.RecordDirectoryMembershipSuccessor(ctx, w, p, command, p.effect); err != nil {
			return identity.FeatureReceipt{}, err
		}
	}
	return identity.FeatureReceipt{Operation: p.op, BeforeVersion: p.update.BeforeVersion(), AfterVersion: p.update.AfterVersion()}, nil
}

func (p *directoryMembershipTestOwner) CheckFeatureCommit(ctx context.Context, w kernel.Work, command identity.Command) error {
	if command != p.command {
		return identity.ForbiddenError{}
	}
	if err := p.groups.native.organizations.RequireDirectoryMembershipEffect(ctx, w, p, command, p.update, p.effect); err != nil {
		return err
	}
	effect := p.effect
	if p.zeroEffect {
		effect = organizationpg.DirectoryMembershipEffect{}
	}
	return p.groups.RequireDirectoryUserMembershipAtCommit(ctx, w, p, command, p.observation, p.evidence, effect)
}

func (*directoryMembershipTestOwner) RecoverParticipant(context.Context, kernel.RecoveryWork) (kernel.RecoveryStatus, error) {
	return kernel.RecoveryUnknown, nil
}

func directoryMembershipPatchWaitsForWork(ctx context.Context, f *nativeFixture, w kernel.Work, patch scim.Request, finished chan<- error) error {
	rows, err := w.Query(ctx, `SELECT pg_backend_pid()`)
	if err != nil {
		return err
	}
	var pid int64
	if !rows.Next() || rows.Scan(&pid) != nil || rows.Next() || rows.Err() != nil {
		rows.Close()
		return errors.New("could not identify the borrowed transaction")
	}
	rows.Close()
	go func() {
		_, err := f.service.Execute(f.ctx, patch)
		finished <- err
	}()
	await, cancel := context.WithTimeout(ctx, time.Second)
	defer cancel()
	ticker := time.NewTicker(5 * time.Millisecond)
	defer ticker.Stop()
	for {
		var blocked bool
		err := f.pool.Raw().QueryRow(await, `SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE datname=current_database() AND wait_event_type='Lock' AND $1=ANY(pg_blocking_pids(pid)))`, int32(pid)).Scan(&blocked)
		if err != nil {
			return err
		}
		if blocked {
			return nil
		}
		select {
		case <-await.Done():
			return errors.New("native PATCH never waited behind the borrowed transaction")
		case <-ticker.C:
		}
	}
}

func prepareDirectoryMembershipTest(t *testing.T, f *nativeFixture, p *directoryMembershipTestOwner, target identity.UserID) (*kernel.Coordinator, kernel.CommandPlan) {
	t.Helper()
	domain, err := kernel.NewRepository(f.pool, kernel.Config{MaximumDuration: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	audits, err := auditpg.NewIdentityContributor(auditpg.Config{})
	if err != nil {
		t.Fatal(err)
	}
	outbox, err := lifecyclepg.NewContributor()
	if err != nil {
		t.Fatal(err)
	}
	registry, err := kernel.NewContributorRegistry([]kernel.Contributor{domain, audits, outbox, p})
	if err != nil {
		t.Fatal(err)
	}
	coordinator, err := kernel.NewCoordinator(f.pool, registry, f.config.Coordinator)
	if err != nil {
		t.Fatal(err)
	}
	fields := make([]identity.FeatureField, 0, 3)
	for _, makeField := range []func() (identity.FeatureField, error){p.observation.Field, p.evidence.Field, p.update.Field} {
		field, err := makeField()
		if err != nil {
			t.Fatal(err)
		}
		fields = append(fields, field)
	}
	commandID, err := identity.NewCommandID()
	if err != nil {
		t.Fatal(err)
	}
	b := identity.CommandBinding{CommandID: commandID, TenantID: f.config.Scope.TenantID, UserID: target, ActorID: f.config.ActorID, ActorKind: authorization.SubjectServiceAccount, OperationID: p.op.OperationID, PolicyID: f.config.PolicyID, PolicyVersion: f.config.PolicyVersion, SchemaID: p.op.SchemaID, SchemaVersion: p.op.SchemaVersion, CorrelationID: "directory-membership-test", RecordID: p.update.RecordID()}
	p.command, err = identity.NewFeatureCommand(identity.FeatureCommandSpec{Binding: b, Operation: p.op, Fields: fields})
	if err != nil {
		t.Fatal(err)
	}
	const subject = "directory_membership"
	before, after := p.update.BeforeVersion(), p.update.AfterVersion()
	builder, err := audit.NewBuilder(audit.BuilderConfig{})
	if err != nil {
		t.Fatal(err)
	}
	record, err := builder.Build(audit.RecordInput{OccurredAt: time.Now().UTC(), Action: p.op.OperationID, Outcome: audit.OutcomeSucceeded, Actor: audit.ActorInput{Kind: audit.ActorService, ID: string(b.ActorID)}, Subject: audit.SubjectInput{Type: subject, ID: b.RecordID}, Context: audit.ContextInput{TenantID: string(b.TenantID), CorrelationID: b.CorrelationID}, Policy: audit.PolicyMetadata{PolicyID: b.PolicyID, Version: "1"}, Changes: audit.ChangeSetInput{Redacted: true}, Attributes: map[string]string{"command.id": string(b.CommandID), "aggregate.type": subject, "aggregate.id": b.RecordID, "aggregate.before_version": strconv.FormatUint(before, 10), "aggregate.after_version": strconv.FormatUint(after, 10), "retention.class": "protected"}})
	if err != nil {
		t.Fatal(err)
	}
	digest, err := kernel.FeatureAuditBindingDigest(b, p.op, subject, record)
	if err != nil {
		t.Fatal(err)
	}
	plan, err := coordinator.PrepareCommandPlan(b, p.command, kernel.CommandPlan{Contributors: registry.Descriptors(), Feature: &kernel.FeatureRegistration{Contributor: p.Descriptor(), Operation: p.op}, SubjectType: subject, Lifecycle: &kernel.LifecyclePlan{EventType: "sso.directory_sync.membership_changed.v1", BeforeVersion: before, AfterVersion: after}, Audits: []kernel.AuditPlan{{EventType: p.op.OperationID, SchemaVersion: 1, BindingDigest: digest, RetentionPolicyVersion: 1, RequiredRecordCount: 1, MaxRecordBytes: 16384, MaxAggregateBytes: 16384, RetentionClass: "protected", Required: true}}})
	if err != nil {
		t.Fatal(err)
	}
	return coordinator, plan
}

func TestDirectoryUserMembershipComposesWithOriginalSource(t *testing.T) {
	for _, deleted := range []bool{false, true} {
		label := "inactive revision"
		if deleted {
			label = "delete tombstone"
		}
		t.Run(label, func(t *testing.T) {
			f := newNativeFixture(t)
			installSource(t, f.ctx, f.pool, organizationpg.DirectoryMembershipMigrationSource{Version: 22})
			groups, err := NewGroupsService(f.service, 0)
			if err != nil {
				t.Fatal(err)
			}
			response, err := f.service.Execute(f.ctx, scim.Request{Operation: scim.UserCreate, Credential: f.bearer, IdempotencyKey: "directory-membership-create", ContentType: "application/scim+json", Body: []byte(`{"schemas":["urn:ietf:params:scim:schemas:core:2.0:User"],"userName":"DirectoryMember","displayName":"Directory Member","active":true}`)})
			if err != nil {
				t.Fatal("create source user", err)
			}
			user := parseNativeUser(t, response).ID
			cfg := f.config.Scope
			source := organizationpg.DirectoryMembershipSource{TenantID: cfg.TenantID, OrganizationID: organization.ID(cfg.OrganizationID), UserID: identity.UserID(user), ProviderID: organization.ID(cfg.ProviderID), ConnectionID: organization.ID(cfg.ConnectionID), ResourceID: organization.ID(user)}
			query := organization.CredentialAuthorityQuery{TenantID: source.TenantID, OrganizationID: source.OrganizationID, ActorID: source.UserID}
			store := f.service.organizations
			var afterLock func(context.Context, kernel.Work) error
			run := func(e DirectoryUserMembershipEvidence, grant, zeroEffect, wantCommit bool) {
				t.Helper()
				observation, err := groups.ObserveDirectorySource(f.ctx, cfg)
				if err != nil {
					t.Fatal(err)
				}
				latest, err := store.ObserveDirectoryMembership(f.ctx, source)
				if err != nil {
					t.Fatal(err)
				}
				input := organizationpg.DirectoryMembershipInput{Source: source, ActorID: f.config.ActorID, Organization: observation.admission.organization, MemberVersion: latest.Member.Version, MemberAuthorizationVersion: latest.Member.AuthorizationVersion, ExpectedVersion: latest.ContributionVersion, Action: organizationpg.DirectoryMembershipWithdraw}
				op := directoryUserDeprovisionRegistration().Operation
				if grant {
					input.Action, input.User, input.MaximumMembers, input.MaximumPerUser = organizationpg.DirectoryMembershipGrant, identity.User{TenantID: source.TenantID, ID: source.UserID, Status: identity.StatusActive, Version: 1}, 10, 10
					op = identity.FeatureOperation{Owner: "sso", OperationID: "identity.sso.directory-sync.apply-user-admission", SchemaID: "sso.directory-user-admission", SchemaVersion: 1, RecordRequirement: identity.FeatureRecordRequired}
				}
				update, err := organizationpg.NewDirectoryMembershipUpdate(input)
				if err != nil {
					t.Fatal("prepare scoped organization membership", err)
				}
				p := &directoryMembershipTestOwner{groups: groups, observation: observation, evidence: e, update: update, op: op, zeroEffect: zeroEffect, afterLock: afterLock}
				c, plan := prepareDirectoryMembershipTest(t, f, p, source.UserID)
				out, err := executeDirectorySourceWork(f.ctx, c, p.command, plan)
				if wantCommit {
					if err != nil || out.Outcome != identity.CommitOutcomeCommitted || out.Feature == nil {
						t.Fatal("combined source and organization operation did not commit", out.Outcome, err)
					}
					replay, err := executeDirectorySourceWork(f.ctx, c, p.command, plan)
					if err != nil || !reflect.DeepEqual(out, replay) || p.applyCalls != 1 {
						t.Fatal("combined child replay repeated or changed its committed effect", err)
					}
				} else if err == nil || out.Outcome == identity.CommitOutcomeCommitted {
					t.Fatal("unproven source membership committed", out.Outcome, err)
				}
			}
			active := DirectoryUserMembershipEvidence{ResourceID: user, Revision: response.ETag, State: DirectoryMembershipUserActive}
			wrongOperation := active
			wrongOperation.State = DirectoryMembershipUserInactive
			run(wrongOperation, true, false, false)
			run(active, true, false, true)
			granted, err := store.ObserveCredentialAuthority(f.ctx, query)
			if err != nil || !granted.Actor.Active || granted.Version != 2 {
				t.Fatal("real active revision did not create effective membership", err)
			}
			withdraw := DirectoryUserMembershipEvidence{ResourceID: user, State: DirectoryMembershipUserInactive}
			if deleted {
				if _, err := f.service.Execute(f.ctx, scim.Request{Operation: scim.UserDelete, Credential: f.bearer, ResourceID: user, IfMatch: response.ETag}); err != nil {
					t.Fatal(err)
				}
				var retained string
				if err := f.pool.Raw().QueryRow(f.ctx, `SELECT command_id FROM scim.users WHERE resource_id=$1 AND deleted_at IS NOT NULL`, user).Scan(&retained); err != nil {
					t.Fatal(err)
				}
				withdraw.Revision, withdraw.State = scim.Version(`"`+retained+`"`), DirectoryMembershipUserDeleted
			} else {
				inactive, err := f.service.Execute(f.ctx, scim.Request{Operation: scim.UserPatch, Credential: f.bearer, ResourceID: user, IfMatch: response.ETag, ContentType: "application/scim+json", Body: []byte(`{"schemas":["urn:ietf:params:scim:api:messages:2.0:PatchOp"],"Operations":[{"op":"replace","path":"active","value":false}]}`)})
				if err != nil {
					t.Fatal(err)
				}
				withdraw.Revision = inactive.ETag
			}
			stale := withdraw
			stale.Revision = response.ETag
			run(stale, false, false, false)
			run(withdraw, false, true, false)
			if retained, err := store.ObserveCredentialAuthority(f.ctx, query); err != nil || retained.Actor != granted.Actor || retained.Version != granted.Version {
				t.Fatal("failed final proof did not roll back the scoped withdrawal", err)
			}
			var patchResult chan error
			if !deleted {
				patchResult = make(chan error, 1)
				patch := scim.Request{Operation: scim.UserPatch, Credential: f.bearer, ResourceID: user, IfMatch: withdraw.Revision, ContentType: "application/scim+json", Body: []byte(`{"schemas":["urn:ietf:params:scim:api:messages:2.0:PatchOp"],"Operations":[{"op":"replace","path":"displayName","value":"Concurrent attribute update"}]}`)}
				afterLock = func(ctx context.Context, w kernel.Work) error {
					return directoryMembershipPatchWaitsForWork(ctx, f, w, patch, patchResult)
				}
			}
			run(withdraw, false, false, true)
			if patchResult != nil {
				select {
				case err := <-patchResult:
					if err == nil {
						t.Fatal("a native PATCH kept stale organization authority across withdrawal")
					}
				case <-f.ctx.Done():
					t.Fatal("native PATCH could not settle after the new organization version committed")
				}
				current, err := f.service.Execute(f.ctx, scim.Request{Operation: scim.UserGet, Credential: f.bearer, ResourceID: user})
				if err != nil || current.ETag != withdraw.Revision {
					t.Fatal("rejected native PATCH changed the exact SCIM revision", err)
				}
			}
			if _, err := store.ObserveCredentialAuthority(f.ctx, query); err == nil {
				t.Fatal("withdrawal left effective organization access")
			}
			var status string
			if err := f.pool.Raw().QueryRow(f.ctx, `SELECT status FROM identity.users WHERE tenant_id=$1 AND user_id=$2`, string(source.TenantID), user).Scan(&status); err != nil || status != "active" {
				t.Fatal("source withdrawal changed the global account", err)
			}
		})
	}
}
