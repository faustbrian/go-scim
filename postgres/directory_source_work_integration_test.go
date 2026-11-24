//go:build integration

package scimpostgres

import (
	"context"
	"testing"
	"time"

	"github.com/faustbrian/go-audit"
	auditpg "github.com/faustbrian/go-audit/postgres"
	"github.com/faustbrian/go-authorization/v3"
	identity "github.com/faustbrian/go-identity"
	kernel "github.com/faustbrian/go-identity/postgres"
	lifecyclepg "github.com/faustbrian/go-transactional-outbox/postgres/identity"
)

// This trusted test contributor borrows the actual coordinator's Work. Its
// harmless table effect proves atomic fencing, not production SSO authorization
// or a directory-team mapping implementation.
type directorySourceWorkOwner struct {
	groups      *GroupsService
	observation DirectorySourceObservation
	command     identity.Command
	reconstruct bool
	foreign     bool
	revokeLate  bool
	applyCalls  int
	finalCalls  int
}

func (*directorySourceWorkOwner) Descriptor() kernel.ContributorDescriptor {
	return kernel.ContributorDescriptor{Owner: "sso/postgres", ContractID: "sso.directory-team-membership", Version: 1}
}

func (*directorySourceWorkOwner) FeatureOperations() []identity.FeatureOperation {
	return []identity.FeatureOperation{{Owner: "sso", OperationID: "identity.sso.directory-sync.apply-child", SchemaID: "sso.directory-team-membership", SchemaVersion: 1, RecordRequirement: identity.FeatureRecordRequired, SubjectRequirement: identity.FeatureSubjectUser, VersionPolicy: identity.FeatureVersionSequential}}
}

func (p *directorySourceWorkOwner) ValidateFeatureCommand(command identity.Command, plan kernel.CommandPlan) error {
	spec, ok := command.Feature()
	if !ok || command != p.command || spec.Operation != p.FeatureOperations()[0] || plan.Lifecycle == nil || plan.Lifecycle.BeforeVersion != 0 || plan.Lifecycle.AfterVersion != 1 {
		return identity.ForbiddenError{}
	}
	return nil
}

func (p *directorySourceWorkOwner) ApplyFeature(ctx context.Context, w kernel.Work, command identity.Command) (identity.FeatureReceipt, error) {
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
	if err := p.groups.RequireDirectorySource(ctx, w, owner, command, p.observation); err != nil {
		return identity.FeatureReceipt{}, err
	}
	spec, _ := command.Feature()
	if _, err := w.Exec(ctx, `INSERT INTO public.directory_source_test_effects(command_id) VALUES($1)`, string(spec.Binding.CommandID)); err != nil {
		return identity.FeatureReceipt{}, err
	}
	if p.revokeLate {
		// Fault injection stays in the same actual transaction: the final fence
		// must reject it and roll back both this change and the earlier effect.
		if _, err := w.Exec(ctx, `UPDATE scim.connections SET state='revoked',version=version+1 WHERE tenant_id='tenant-a' AND connection_id='connection-a'`); err != nil {
			return identity.FeatureReceipt{}, err
		}
	}
	return identity.FeatureReceipt{Operation: p.FeatureOperations()[0], BeforeVersion: 0, AfterVersion: 1}, nil
}

func (p *directorySourceWorkOwner) CheckFeatureCommit(ctx context.Context, w kernel.Work, command identity.Command) error {
	p.finalCalls++
	if command != p.command {
		return identity.ForbiddenError{}
	}
	return p.groups.RequireDirectorySourceAtCommit(ctx, w, p, command, p.observation)
}

func (*directorySourceWorkOwner) RecoverParticipant(context.Context, kernel.RecoveryWork) (kernel.RecoveryStatus, error) {
	return kernel.RecoveryUnknown, nil
}

func directorySourceWorkCoordinator(t *testing.T, f *nativeFixture, owner *directorySourceWorkOwner) (*kernel.Coordinator, *kernel.ContributorRegistry) {
	t.Helper()
	if _, err := f.pool.Raw().Exec(f.ctx, `CREATE TABLE public.directory_source_test_effects(command_id text PRIMARY KEY)`); err != nil {
		t.Fatal("create harmless test effect owner", err)
	}
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
	registry, err := kernel.NewContributorRegistry([]kernel.Contributor{domain, audits, outbox, owner})
	if err != nil {
		t.Fatal(err)
	}
	coordinator, err := kernel.NewCoordinator(f.pool, registry, f.config.Coordinator)
	if err != nil {
		t.Fatal(err)
	}
	return coordinator, registry
}

func directorySourceWorkCommand(t *testing.T, f *nativeFixture, coordinator *kernel.Coordinator, registry *kernel.ContributorRegistry, owner *directorySourceWorkOwner, field identity.FeatureField, actor identity.ActorID) (identity.Command, kernel.CommandPlan) {
	t.Helper()
	commandID, err := identity.NewCommandID()
	if err != nil {
		t.Fatal(err)
	}
	userID, err := identity.NewSubjectID()
	if err != nil {
		t.Fatal(err)
	}
	operation := owner.FeatureOperations()[0]
	binding := identity.CommandBinding{CommandID: commandID, TenantID: f.config.Scope.TenantID, UserID: identity.UserID(userID), ActorID: actor, ActorKind: authorization.SubjectServiceAccount, OperationID: operation.OperationID, PolicyID: f.config.PolicyID, PolicyVersion: f.config.PolicyVersion, SchemaID: operation.SchemaID, SchemaVersion: operation.SchemaVersion, CorrelationID: "directory-source-test", RecordID: "directory-source-test-effect"}
	command, err := identity.NewFeatureCommand(identity.FeatureCommandSpec{Binding: binding, Operation: operation, Fields: []identity.FeatureField{field}})
	if err != nil {
		t.Fatal(err)
	}
	owner.command = command
	builder, err := audit.NewBuilder(audit.BuilderConfig{})
	if err != nil {
		t.Fatal(err)
	}
	record, err := builder.Build(audit.RecordInput{OccurredAt: time.Now().UTC(), Action: operation.OperationID, Outcome: audit.OutcomeSucceeded, Actor: audit.ActorInput{Kind: audit.ActorService, ID: string(binding.ActorID)}, Subject: audit.SubjectInput{Type: "team_membership", ID: binding.RecordID}, Context: audit.ContextInput{TenantID: string(binding.TenantID), CorrelationID: binding.CorrelationID}, Policy: audit.PolicyMetadata{PolicyID: binding.PolicyID, Version: "1"}, Changes: audit.ChangeSetInput{Redacted: true}, Attributes: map[string]string{"command.id": string(binding.CommandID), "aggregate.type": "team_membership", "aggregate.id": binding.RecordID, "aggregate.before_version": "0", "aggregate.after_version": "1", "retention.class": "protected"}})
	if err != nil {
		t.Fatal(err)
	}
	digest, err := kernel.FeatureAuditBindingDigest(binding, operation, "team_membership", record)
	if err != nil {
		t.Fatal(err)
	}
	plan, err := coordinator.PrepareCommandPlan(binding, command, kernel.CommandPlan{Contributors: registry.Descriptors(), Feature: &kernel.FeatureRegistration{Contributor: owner.Descriptor(), Operation: operation}, SubjectType: "team_membership", Lifecycle: &kernel.LifecyclePlan{EventType: "directory.team-membership.changed.v1", BeforeVersion: 0, AfterVersion: 1}, Audits: []kernel.AuditPlan{{EventType: operation.OperationID, SchemaVersion: 1, BindingDigest: digest, RetentionPolicyVersion: 1, RequiredRecordCount: 1, MaxRecordBytes: 16384, MaxAggregateBytes: 16384, RetentionClass: "protected", Required: true}}})
	if err != nil {
		t.Fatal(err)
	}
	return command, plan
}

func executeDirectorySourceWork(ctx context.Context, coordinator *kernel.Coordinator, command identity.Command, plan kernel.CommandPlan) (identity.CommandResult, error) {
	spec, _ := command.Feature()
	reservation, result, err := coordinator.ReserveCommand(ctx, spec.Binding, command, plan)
	if err != nil || result.Outcome != identity.CommitOutcomeInProgress {
		return result, err
	}
	w, err := coordinator.Begin(ctx, reservation)
	if err != nil {
		return result, err
	}
	defer func() { _, _ = coordinator.Abort(w, identity.UnavailableError{}) }()
	result, err = coordinator.ApplyFeature(ctx, w, command)
	if err != nil {
		return coordinator.Abort(w, err)
	}
	return coordinator.Commit(w, result)
}

func TestDirectorySourceNativeWorkExactEvidenceCommitReplayAndRollback(t *testing.T) {
	for _, mode := range []string{"exact source", "wrong commitment", "missing commitment", "zero observation", "foreign service", "foreign owner", "foreign actor", "reconstructed command", "stale tenant epoch", "late connection revocation"} {
		t.Run(mode, func(t *testing.T) {
			f := newNativeFixture(t)
			groups, err := NewGroupsService(f.service, 0)
			if err != nil {
				t.Fatal(err)
			}
			observation, err := groups.ObserveDirectorySource(f.ctx, f.config.Scope)
			if err != nil {
				t.Fatal("observe configured original source", err)
			}
			field, err := observation.Field()
			if err != nil {
				t.Fatal("bind original source before reservation", err)
			}
			owner := &directorySourceWorkOwner{groups: groups, observation: observation}
			actor := f.config.ActorID
			switch mode {
			case "wrong commitment":
				field.Value.Bytes[0] ^= 1
			case "missing commitment":
				field.Name = "test.other-source"
			case "zero observation":
				owner.observation = DirectorySourceObservation{}
			case "foreign service":
				foreign, err := NewService(f.pool, f.config, f.keys)
				if err != nil {
					t.Fatal(err)
				}
				owner.groups, err = NewGroupsService(foreign, 0)
				if err != nil {
					t.Fatal(err)
				}
			case "foreign owner":
				owner.foreign = true
			case "foreign actor":
				actor = "another-service"
			case "reconstructed command":
				owner.reconstruct = true
			case "stale tenant epoch":
				if _, err := f.pool.Raw().Exec(f.ctx, `UPDATE identity.tenant_authorities SET version=version+1 WHERE tenant_id='tenant-a'`); err != nil {
					t.Fatal(err)
				}
			case "late connection revocation":
				owner.revokeLate = true
			}
			coordinator, registry := directorySourceWorkCoordinator(t, f, owner)
			command, plan := directorySourceWorkCommand(t, f, coordinator, registry, owner, field, actor)
			var auditsBefore, eventsBefore int
			if err := f.pool.Raw().QueryRow(f.ctx, `SELECT (SELECT count(*) FROM audit.identity_command_bindings),(SELECT count(*) FROM public.outbox_messages)`).Scan(&auditsBefore, &eventsBefore); err != nil {
				t.Fatal(err)
			}
			result, err := executeDirectorySourceWork(f.ctx, coordinator, command, plan)
			wantEffects, wantFinalCalls := 0, 0
			wantAuditOutcome := audit.OutcomeDenied
			if mode == "exact source" {
				wantEffects, wantFinalCalls = 1, 1
				wantAuditOutcome = audit.OutcomeSucceeded
				if err != nil || result.Outcome != identity.CommitOutcomeCommitted || result.Feature == nil || result.Feature.BeforeVersion != 0 || result.Feature.AfterVersion != 1 {
					t.Fatal("exact original source failed native commit", result.Outcome, err)
				}
				replay, err := executeDirectorySourceWork(f.ctx, coordinator, command, plan)
				if err != nil || replay.Outcome != identity.CommitOutcomeCommitted || replay.Feature == nil || *replay.Feature != *result.Feature {
					t.Fatal("native source command did not replay original receipt", replay.Outcome, err)
				}
			} else {
				if err == nil || result.Outcome == identity.CommitOutcomeCommitted {
					t.Fatal("invalid original source committed native work", result.Outcome)
				}
				if owner.revokeLate {
					wantFinalCalls = 1
				}
				if owner.foreign || owner.reconstruct {
					// Invalid Work custody is classified as a dependency failure,
					// not as a source-authority denial by the coordinator.
					wantAuditOutcome = audit.OutcomeFailed
				}
			}
			if owner.applyCalls != 1 || owner.finalCalls != wantFinalCalls {
				t.Fatal("native callback boundary or replay changed", owner.applyCalls, owner.finalCalls)
			}
			var effects, auditsAfter, eventsAfter, committed, matchingAuditOutcomes int
			spec, _ := command.Feature()
			if err := f.pool.Raw().QueryRow(f.ctx, `SELECT
 (SELECT count(*) FROM public.directory_source_test_effects),
 (SELECT count(*) FROM audit.identity_command_bindings),
 (SELECT count(*) FROM public.outbox_messages),
 (SELECT count(*) FROM identity.commands WHERE command_id=decode(translate($1,'-_','+/')||'==','base64') AND state='committed'),
 (SELECT count(*) FROM audit.identity_command_bindings b JOIN audit.records r ON r.record_id=b.event_id WHERE b.command_id=decode(translate($1,'-_','+/')||'==','base64') AND r.outcome=$2)`, string(spec.Binding.CommandID), int16(wantAuditOutcome)).Scan(&effects, &auditsAfter, &eventsAfter, &committed, &matchingAuditOutcomes); err != nil {
				t.Fatal("read actual effect/audit/outbox/journal", err)
			}
			if effects != wantEffects || auditsAfter-auditsBefore != 1 || eventsAfter-eventsBefore != wantEffects || committed != wantEffects || matchingAuditOutcomes != 1 {
				t.Fatal("source fence lost atomic commit/rollback or terminal audit outcome", effects, auditsAfter-auditsBefore, eventsAfter-eventsBefore, committed, matchingAuditOutcomes)
			}
			if owner.revokeLate {
				var active bool
				if err := f.pool.Raw().QueryRow(f.ctx, `SELECT state='active' AND version=1 FROM scim.connections WHERE tenant_id='tenant-a' AND connection_id='connection-a'`).Scan(&active); err != nil || !active {
					t.Fatal("late source revocation escaped native rollback", err)
				}
			}
		})
	}
}
