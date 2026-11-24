//go:build integration

package scimpostgres

import (
	"bytes"
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/faustbrian/go-audit"
	"github.com/faustbrian/go-authorization/v3"
	identity "github.com/faustbrian/go-identity"
	kernel "github.com/faustbrian/go-identity/postgres"
	scim "github.com/faustbrian/go-scim"
)

type directoryUserDeprovisionWorkOwner struct {
	directorySourceWorkOwner
	evidence          DirectoryUserDeprovisionEvidence
	late              string
	groupRegistration bool
	groupFence        bool
	readUntil         time.Time
}

func (p *directoryUserDeprovisionWorkOwner) Descriptor() kernel.ContributorDescriptor {
	if p.groupRegistration {
		return p.directorySourceWorkOwner.Descriptor()
	}
	return kernel.ContributorDescriptor{Owner: "sso/postgres", ContractID: "sso.directory-user-deprovision", Version: 1}
}

func (p *directoryUserDeprovisionWorkOwner) FeatureOperations() []identity.FeatureOperation {
	if p.groupRegistration {
		return p.directorySourceWorkOwner.FeatureOperations()
	}
	return []identity.FeatureOperation{{Owner: "sso", OperationID: "identity.sso.directory-sync.apply-user-deprovision", SchemaID: "sso.directory-user-deprovision", SchemaVersion: 1, RecordRequirement: identity.FeatureRecordRequired, SubjectRequirement: identity.FeatureSubjectUser, VersionPolicy: identity.FeatureVersionSequential}}
}

func (p *directoryUserDeprovisionWorkOwner) ValidateFeatureCommand(command identity.Command, plan kernel.CommandPlan) error {
	spec, ok := command.Feature()
	if !ok || command != p.command || spec.Operation != p.FeatureOperations()[0] || plan.Lifecycle == nil || plan.Lifecycle.BeforeVersion != 0 || plan.Lifecycle.AfterVersion != 1 {
		return identity.ForbiddenError{}
	}
	return nil
}

func (p *directoryUserDeprovisionWorkOwner) ApplyFeature(ctx context.Context, w kernel.Work, command identity.Command) (identity.FeatureReceipt, error) {
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
	if p.groupFence {
		if err := p.groups.RequireDirectorySource(ctx, w, owner, command, p.observation); err != nil {
			return identity.FeatureReceipt{}, err
		}
	} else if err := p.groups.RequireDirectoryUserDeprovision(ctx, w, owner, command, p.observation, p.evidence); err != nil {
		return identity.FeatureReceipt{}, err
	}
	spec, _ := command.Feature()
	if _, err := w.Exec(ctx, `INSERT INTO public.directory_source_test_effects(command_id) VALUES($1)`, string(spec.Binding.CommandID)); err != nil {
		return identity.FeatureReceipt{}, err
	}
	switch p.late {
	case "projection":
		if _, err := w.Exec(ctx, `UPDATE scim.users SET resource=convert_to('null','UTF8') WHERE resource_id=$1`, p.evidence.ResourceID); err != nil {
			return identity.FeatureReceipt{}, err
		}
	case "revision":
		p.evidence.Revision = scim.Version(`"AAAAAAAAAAAAAAAAAAAAAQ"`)
	case "source":
		if _, err := w.Exec(ctx, `UPDATE scim.connections SET state='revoked',version=version+1 WHERE tenant_id='tenant-a' AND connection_id='connection-a'`); err != nil {
			return identity.FeatureReceipt{}, err
		}
	}
	return identity.FeatureReceipt{Operation: p.FeatureOperations()[0], BeforeVersion: 0, AfterVersion: 1}, nil
}

func (p *directoryUserDeprovisionWorkOwner) CheckFeatureCommit(ctx context.Context, w kernel.Work, command identity.Command) error {
	p.finalCalls++
	if command != p.command {
		return identity.ForbiddenError{}
	}
	if !p.readUntil.IsZero() {
		rows, err := w.Query(ctx, `SELECT set_config('scim.test_user_read_until',$1,true)`, p.readUntil.Format(time.RFC3339Nano))
		if err != nil {
			return err
		}
		for rows.Next() {
			var setting string
			if err := rows.Scan(&setting); err != nil {
				rows.Close()
				return err
			}
		}
		rows.Close()
		if err := rows.Err(); err != nil {
			return err
		}
	}
	return p.groups.RequireDirectoryUserDeprovisionAtCommit(ctx, w, p, command, p.observation, p.evidence)
}

func directoryUserDeprovisionWorkCommand(t *testing.T, f *nativeFixture, coordinator *kernel.Coordinator, registry *kernel.ContributorRegistry, owner *directoryUserDeprovisionWorkOwner, target string, fields []identity.FeatureField) (identity.Command, kernel.CommandPlan) {
	t.Helper()
	commandID, err := identity.NewCommandID()
	if err != nil {
		t.Fatal(err)
	}
	operation := owner.FeatureOperations()[0]
	binding := identity.CommandBinding{CommandID: commandID, TenantID: f.config.Scope.TenantID, UserID: identity.UserID(target), ActorID: f.config.ActorID, ActorKind: authorization.SubjectServiceAccount, OperationID: operation.OperationID, PolicyID: f.config.PolicyID, PolicyVersion: f.config.PolicyVersion, SchemaID: operation.SchemaID, SchemaVersion: operation.SchemaVersion, CorrelationID: "directory-user-test", RecordID: "directory-user-test-effect"}
	command, err := identity.NewFeatureCommand(identity.FeatureCommandSpec{Binding: binding, Operation: operation, Fields: fields})
	if err != nil {
		t.Fatal(err)
	}
	owner.command = command
	builder, err := audit.NewBuilder(audit.BuilderConfig{})
	if err != nil {
		t.Fatal(err)
	}
	record, err := builder.Build(audit.RecordInput{OccurredAt: time.Now().UTC(), Action: operation.OperationID, Outcome: audit.OutcomeSucceeded, Actor: audit.ActorInput{Kind: audit.ActorService, ID: string(binding.ActorID)}, Subject: audit.SubjectInput{Type: "directory_user", ID: binding.RecordID}, Context: audit.ContextInput{TenantID: string(binding.TenantID), CorrelationID: binding.CorrelationID}, Policy: audit.PolicyMetadata{PolicyID: binding.PolicyID, Version: "1"}, Changes: audit.ChangeSetInput{Redacted: true}, Attributes: map[string]string{"command.id": string(binding.CommandID), "aggregate.type": "directory_user", "aggregate.id": binding.RecordID, "aggregate.before_version": "0", "aggregate.after_version": "1", "retention.class": "protected"}})
	if err != nil {
		t.Fatal(err)
	}
	digest, err := kernel.FeatureAuditBindingDigest(binding, operation, "directory_user", record)
	if err != nil {
		t.Fatal(err)
	}
	plan, err := coordinator.PrepareCommandPlan(binding, command, kernel.CommandPlan{Contributors: registry.Descriptors(), Feature: &kernel.FeatureRegistration{Contributor: owner.Descriptor(), Operation: operation}, SubjectType: "directory_user", Lifecycle: &kernel.LifecyclePlan{EventType: "directory.user.deprovisioned.v1", BeforeVersion: 0, AfterVersion: 1}, Audits: []kernel.AuditPlan{{EventType: operation.OperationID, SchemaVersion: 1, BindingDigest: digest, RetentionPolicyVersion: 1, RequiredRecordCount: 1, MaxRecordBytes: 16384, MaxAggregateBytes: 16384, RetentionClass: "protected", Required: true}}})
	if err != nil {
		t.Fatal(err)
	}
	return command, plan
}

func TestDirectoryUserDeprovisionNativeWorkExactSourceRevisionAndRollback(t *testing.T) {
	for _, mode := range []string{"inactive", "tombstone", "active", "active absent", "active string", "wrong revision", "deleted with live revision", "live claimed deleted", "deleted claimed live", "tombstone payload", "wrong target", "mapped identity", "unknown resource", "foreign scope", "retyped resource", "wrong commitment", "missing commitment", "retyped commitment", "missing source commitment", "zero observation", "foreign service", "foreign owner", "reconstructed command", "group registration", "group fence", "late projection", "late revision", "late source"} {
		t.Run(mode, func(t *testing.T) {
			f := newNativeFixture(t)
			groups, err := NewGroupsService(f.service, 0)
			if err != nil {
				t.Fatal(err)
			}
			user := createNativeNamed(t, f, "DeprovisionUser", "Source identity")
			current, err := f.service.Execute(f.ctx, scim.Request{Operation: scim.UserGet, Credential: f.bearer, ResourceID: user})
			if err != nil {
				t.Fatal(err)
			}
			inactive, err := f.service.Execute(f.ctx, scim.Request{Operation: scim.UserPatch, Credential: f.bearer, ResourceID: user, IfMatch: current.ETag, ContentType: "application/scim+json", Body: []byte(`{"schemas":["urn:ietf:params:scim:api:messages:2.0:PatchOp"],"Operations":[{"op":"replace","path":"active","value":false}]}`)})
			if err != nil {
				t.Fatal("real source inactive PATCH", err)
			}
			evidence := DirectoryUserDeprovisionEvidence{ResourceID: user, Revision: inactive.ETag}
			if mode == "active" {
				active, err := f.service.Execute(f.ctx, scim.Request{Operation: scim.UserPatch, Credential: f.bearer, ResourceID: user, IfMatch: inactive.ETag, ContentType: "application/scim+json", Body: []byte(`{"schemas":["urn:ietf:params:scim:api:messages:2.0:PatchOp"],"Operations":[{"op":"replace","path":"active","value":true}]}`)})
				if err != nil {
					t.Fatal("real source active PATCH", err)
				}
				evidence.Revision = active.ETag
			}
			deleted := mode == "tombstone" || mode == "deleted with live revision" || mode == "deleted claimed live" || mode == "tombstone payload"
			if deleted {
				if _, err := f.service.Execute(f.ctx, scim.Request{Operation: scim.UserDelete, Credential: f.bearer, ResourceID: user, IfMatch: inactive.ETag}); err != nil {
					t.Fatal("real source DELETE", err)
				}
				var retainedCommand string
				if err := f.pool.Raw().QueryRow(f.ctx, `SELECT command_id FROM scim.users WHERE resource_id=$1`, user).Scan(&retainedCommand); err != nil {
					t.Fatal(err)
				}
				evidence.Deleted, evidence.Revision = true, scim.Version(`"`+retainedCommand+`"`)
			}
			target := user
			switch mode {
			case "wrong revision":
				evidence.Revision = current.ETag
			case "deleted with live revision":
				evidence.Revision = inactive.ETag
			case "live claimed deleted":
				evidence.Deleted = true
			case "deleted claimed live":
				evidence.Deleted = false
			case "unknown resource":
				id, err := identity.NewSubjectID()
				if err != nil {
					t.Fatal(err)
				}
				evidence.ResourceID = string(id)
			case "wrong target", "mapped identity":
				target = createNativeNamed(t, f, "OtherDeprovisionUser", "Other identity")
				if mode == "mapped identity" {
					if _, err := f.pool.Raw().Exec(f.ctx, `DELETE FROM scim.users WHERE resource_id=$1`, target); err != nil {
						t.Fatal(err)
					}
					if _, err := f.pool.Raw().Exec(f.ctx, `UPDATE scim.users SET user_id=$2 WHERE resource_id=$1`, user, target); err != nil {
						t.Fatal(err)
					}
				}
			case "foreign scope":
				foreignConfig := f.config
				foreignConfig.Scope.ConnectionID = "connection-b"
				foreign, err := NewService(f.pool, foreignConfig, f.keys)
				if err != nil {
					t.Fatal(err)
				}
				if _, err := foreign.InitializeConfiguredConnection(f.ctx); err != nil {
					t.Fatal(err)
				}
				if _, err := f.pool.Raw().Exec(f.ctx, `UPDATE scim.users SET connection_id='connection-b' WHERE resource_id=$1`, user); err != nil {
					t.Fatal(err)
				}
			}
			var originalWire []byte
			if err := f.pool.Raw().QueryRow(f.ctx, `SELECT resource FROM scim.users WHERE resource_id=$1`, user).Scan(&originalWire); err != nil {
				t.Fatal(err)
			}
			if mode == "active absent" || mode == "active string" || mode == "retyped resource" || mode == "tombstone payload" {
				var resource scim.Resource
				wire := originalWire
				if mode == "tombstone payload" {
					// A live payload cannot be admitted merely because deleted_at is set.
					resource = scim.Resource{ID: user, Schemas: []string{"urn:ietf:params:scim:schemas:core:2.0:User"}, Version: evidence.Revision, CreatedAt: time.Now().UTC(), LastModified: time.Now().UTC(), Attributes: map[string]any{"active": false}}
				} else if err := json.Unmarshal(wire, &resource); err != nil {
					t.Fatal(err)
				}
				switch mode {
				case "active absent":
					delete(resource.Attributes, "active")
				case "active string":
					resource.Attributes["active"] = "false"
				case "retyped resource":
					resource.Schemas = []string{"urn:ietf:params:scim:schemas:core:2.0:Group"}
				}
				wire, err = json.Marshal(resource)
				if err != nil {
					t.Fatal(err)
				}
				if _, err := f.pool.Raw().Exec(f.ctx, `UPDATE scim.users SET resource=$2 WHERE resource_id=$1`, user, wire); err != nil {
					t.Fatal(err)
				}
			}
			observation, err := groups.ObserveDirectorySource(f.ctx, f.config.Scope)
			if err != nil {
				t.Fatal(err)
			}
			sourceField, err := observation.Field()
			if err != nil {
				t.Fatal(err)
			}
			field, err := evidence.Field()
			if err != nil {
				t.Fatal(err)
			}
			owner := &directoryUserDeprovisionWorkOwner{directorySourceWorkOwner: directorySourceWorkOwner{groups: groups, observation: observation}, evidence: evidence}
			switch mode {
			case "wrong commitment":
				field.Value.Bytes[0] ^= 1
			case "missing commitment":
				field.Name = "test.not-user-deprovision"
			case "retyped commitment":
				field.Value = identity.FeatureValue{Kind: identity.FeatureText, Text: "false"}
			case "missing source commitment":
				sourceField.Name = "test.not-source"
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
			case "reconstructed command":
				owner.reconstruct = true
			case "group registration":
				owner.groupRegistration = true
			case "group fence":
				owner.groupFence = true
			case "late projection":
				owner.late = "projection"
			case "late revision":
				owner.late = "revision"
			case "late source":
				owner.late = "source"
			}
			coordinator, registry := directorySourceWorkCoordinator(t, f, owner)
			command, plan := directoryUserDeprovisionWorkCommand(t, f, coordinator, registry, owner, target, []identity.FeatureField{sourceField, field})
			var auditsBefore, eventsBefore int
			if err := f.pool.Raw().QueryRow(f.ctx, `SELECT (SELECT count(*) FROM audit.identity_command_bindings),(SELECT count(*) FROM public.outbox_messages)`).Scan(&auditsBefore, &eventsBefore); err != nil {
				t.Fatal(err)
			}
			result, err := executeDirectorySourceWork(f.ctx, coordinator, command, plan)
			wantCommit := mode == "inactive" || mode == "tombstone" || mode == "mapped identity"
			if wantCommit && (err != nil || result.Outcome != identity.CommitOutcomeCommitted) {
				t.Fatal("exact source User evidence failed native commit", result.Outcome, err)
			}
			if !wantCommit && (err == nil || result.Outcome == identity.CommitOutcomeCommitted) {
				t.Fatal("unproven User deprovision committed", result.Outcome, err)
			}
			wantEffects, wantFinal := 0, 0
			if wantCommit {
				wantEffects, wantFinal = 1, 1
				replay, err := executeDirectorySourceWork(f.ctx, coordinator, command, plan)
				if err != nil || replay.Outcome != identity.CommitOutcomeCommitted || replay.Feature == nil || result.Feature == nil || *replay.Feature != *result.Feature {
					t.Fatal("User deprovision replay changed receipt", err)
				}
			}
			if owner.late != "" {
				wantFinal = 1
			}
			var effects, auditsAfter, eventsAfter int
			if err := f.pool.Raw().QueryRow(f.ctx, `SELECT (SELECT count(*) FROM public.directory_source_test_effects),(SELECT count(*) FROM audit.identity_command_bindings),(SELECT count(*) FROM public.outbox_messages)`).Scan(&effects, &auditsAfter, &eventsAfter); err != nil {
				t.Fatal(err)
			}
			if effects != wantEffects || eventsAfter-eventsBefore != wantEffects || auditsAfter-auditsBefore != 1 || owner.applyCalls != 1 || owner.finalCalls != wantFinal {
				t.Fatal("User fence lost atomicity or replay", effects, eventsAfter-eventsBefore, auditsAfter-auditsBefore, owner.applyCalls, owner.finalCalls)
			}
			if owner.late != "" {
				var retained []byte
				var active bool
				if err := f.pool.Raw().QueryRow(f.ctx, `SELECT resource,(SELECT state='active' AND version=1 FROM scim.connections WHERE connection_id='connection-a') FROM scim.users WHERE resource_id=$1`, user).Scan(&retained, &active); err != nil || !active || !bytes.Equal(retained, originalWire) {
					t.Fatal("late User/source change escaped rollback", err)
				}
			}
		})
	}
}

func TestDirectoryUserDeprovisionFinalReadCannotOutliveOriginalSource(t *testing.T) {
	f := newNativeFixture(t)
	groups, err := NewGroupsService(f.service, 0)
	if err != nil {
		t.Fatal(err)
	}
	user := createNativeNamed(t, f, "DeprovisionExpiryUser", "Source identity")
	current, err := f.service.Execute(f.ctx, scim.Request{Operation: scim.UserGet, Credential: f.bearer, ResourceID: user})
	if err != nil {
		t.Fatal(err)
	}
	inactive, err := f.service.Execute(f.ctx, scim.Request{Operation: scim.UserPatch, Credential: f.bearer, ResourceID: user, IfMatch: current.ETag, ContentType: "application/scim+json", Body: []byte(`{"schemas":["urn:ietf:params:scim:api:messages:2.0:PatchOp"],"Operations":[{"op":"replace","path":"active","value":false}]}`)})
	if err != nil {
		t.Fatal("real inactive PATCH", err)
	}
	// Delay only the final source read, without changing the source facts.
	if _, err := f.pool.Raw().Exec(f.ctx, `ALTER TABLE scim.users RENAME TO directory_user_expiry_users;
 CREATE FUNCTION scim.directory_user_test_delay(value bytea) RETURNS bytea LANGUAGE plpgsql VOLATILE AS $$
 DECLARE deadline text;
 BEGIN
  deadline := current_setting('scim.test_user_read_until',true);
  IF deadline IS NOT NULL AND deadline<>'' THEN
   PERFORM pg_sleep(LEAST(2.5,GREATEST(0,extract(epoch FROM (deadline::timestamptz-clock_timestamp())))+0.05));
  END IF;
  RETURN value;
 END $$;
 CREATE VIEW scim.users AS SELECT tenant_id,organization_id,provider_id,connection_id,resource_id,user_id,
 username_key,username_digest,external_id,scim.directory_user_test_delay(resource) AS resource,
 command_id,effect_digest,generation,deleted_at FROM scim.directory_user_expiry_users`); err != nil {
		t.Fatal("install owned delayed source read", err)
	}
	observation, err := groups.ObserveDirectorySource(f.ctx, f.config.Scope)
	if err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().UTC().Add(2 * time.Second)
	observation.admission.connection.AuthorityValidUntil = deadline
	sourceField, err := observation.Field()
	if err != nil {
		t.Fatal(err)
	}
	evidence := DirectoryUserDeprovisionEvidence{ResourceID: user, Revision: inactive.ETag}
	field, err := evidence.Field()
	if err != nil {
		t.Fatal(err)
	}
	owner := &directoryUserDeprovisionWorkOwner{directorySourceWorkOwner: directorySourceWorkOwner{groups: groups, observation: observation}, evidence: evidence, readUntil: deadline}
	coordinator, registry := directorySourceWorkCoordinator(t, f, owner)
	command, plan := directoryUserDeprovisionWorkCommand(t, f, coordinator, registry, owner, user, []identity.FeatureField{sourceField, field})
	var eventsBefore int
	if err := f.pool.Raw().QueryRow(f.ctx, `SELECT count(*) FROM public.outbox_messages`).Scan(&eventsBefore); err != nil {
		t.Fatal(err)
	}
	result, err := executeDirectorySourceWork(f.ctx, coordinator, command, plan)
	if owner.applyCalls != 1 || owner.finalCalls != 1 {
		t.Fatal("deadline must cross inside final read", owner.applyCalls, owner.finalCalls, err)
	}
	if err == nil || result.Outcome == identity.CommitOutcomeCommitted {
		t.Fatal("User deprovision outlived original freshness", result.Outcome, err)
	}
	spec, _ := command.Feature()
	var effects, eventsAfter, successAudits, committed int
	var expired bool
	if err := f.pool.Raw().QueryRow(f.ctx, `SELECT
 (SELECT count(*) FROM public.directory_source_test_effects),
 (SELECT count(*) FROM public.outbox_messages),
 (SELECT count(*) FROM audit.identity_command_bindings b JOIN audit.records r ON r.record_id=b.event_id WHERE b.command_id=decode(translate($1,'-_','+/')||'==','base64') AND r.outcome=$3),
 (SELECT count(*) FROM identity.commands WHERE command_id=decode(translate($1,'-_','+/')||'==','base64') AND state='committed'),
 clock_timestamp()>$2`, string(spec.Binding.CommandID), deadline, int16(audit.OutcomeSucceeded)).Scan(&effects, &eventsAfter, &successAudits, &committed, &expired); err != nil {
		t.Fatal(err)
	}
	if effects != 0 || eventsAfter != eventsBefore || successAudits != 0 || committed != 0 || !expired {
		t.Fatal("source-read expiry escaped rollback", effects, eventsAfter-eventsBefore, successAudits, committed, expired)
	}
}
