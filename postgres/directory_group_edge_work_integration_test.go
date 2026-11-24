//go:build integration

package scimpostgres

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/faustbrian/go-audit"
	"github.com/faustbrian/go-authorization/v3"
	identity "github.com/faustbrian/go-identity"
	kernel "github.com/faustbrian/go-identity/postgres"
	scim "github.com/faustbrian/go-scim"
)

type directoryGroupEdgeWorkOwner struct {
	directorySourceWorkOwner
	edge DirectoryGroupEdge
	late string
}

func (p *directoryGroupEdgeWorkOwner) ApplyFeature(ctx context.Context, w kernel.Work, command identity.Command) (identity.FeatureReceipt, error) {
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
	if err := p.groups.RequireDirectoryGroupEdge(ctx, w, owner, command, p.observation, p.edge); err != nil {
		return identity.FeatureReceipt{}, err
	}
	spec, _ := command.Feature()
	if _, err := w.Exec(ctx, `INSERT INTO public.directory_source_test_effects(command_id) VALUES($1)`, string(spec.Binding.CommandID)); err != nil {
		return identity.FeatureReceipt{}, err
	}
	switch p.late {
	case "source":
		if _, err := w.Exec(ctx, `UPDATE scim.connections SET state='revoked',version=version+1 WHERE tenant_id='tenant-a' AND connection_id='connection-a'`); err != nil {
			return identity.FeatureReceipt{}, err
		}
	case "edge":
		if _, err := w.Exec(ctx, `UPDATE scim.groups SET resource=convert_to('null','UTF8'),deleted_at=clock_timestamp(),generation=generation+1 WHERE resource_id=$1`, p.edge.GroupID); err != nil {
			return identity.FeatureReceipt{}, err
		}
	}
	return identity.FeatureReceipt{Operation: p.FeatureOperations()[0], BeforeVersion: 0, AfterVersion: 1}, nil
}

func (p *directoryGroupEdgeWorkOwner) CheckFeatureCommit(ctx context.Context, w kernel.Work, command identity.Command) error {
	p.finalCalls++
	if command != p.command {
		return identity.ForbiddenError{}
	}
	return p.groups.RequireDirectoryGroupEdgeAtCommit(ctx, w, p, command, p.observation, p.edge)
}

func directoryGroupEdgeWorkCommand(t *testing.T, f *nativeFixture, coordinator *kernel.Coordinator, registry *kernel.ContributorRegistry, owner *directoryGroupEdgeWorkOwner, target string, fields []identity.FeatureField) (identity.Command, kernel.CommandPlan) {
	t.Helper()
	commandID, err := identity.NewCommandID()
	if err != nil {
		t.Fatal(err)
	}
	operation := owner.FeatureOperations()[0]
	binding := identity.CommandBinding{CommandID: commandID, TenantID: f.config.Scope.TenantID, UserID: identity.UserID(target), ActorID: f.config.ActorID, ActorKind: authorization.SubjectServiceAccount, OperationID: operation.OperationID, PolicyID: f.config.PolicyID, PolicyVersion: f.config.PolicyVersion, SchemaID: operation.SchemaID, SchemaVersion: operation.SchemaVersion, CorrelationID: "directory-edge-test", RecordID: "directory-edge-test-effect"}
	command, err := identity.NewFeatureCommand(identity.FeatureCommandSpec{Binding: binding, Operation: operation, Fields: fields})
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

func TestDirectoryGroupEdgeNativeWorkExactProjectionAndRollback(t *testing.T) {
	for _, mode := range []string{
		"present", "absent", "group tombstone", "user tombstone removal", "mapped identity",
		"unknown group", "unknown removal group", "absent claimed present", "present claimed absent",
		"wrong target", "wrong commitment", "missing commitment", "missing source commitment",
		"case changed user", "nested group", "foreign scope", "deleted user", "unknown user mapping", "unknown removal user mapping",
		"malformed group", "malformed members", "malformed user", "foreign owner", "reconstructed command",
		"late edge mismatch", "late source mismatch",
	} {
		t.Run(mode, func(t *testing.T) {
			f, groups := nativeGroupsFixture(t)
			user := createNativeNamed(t, f, "EdgeUser", "Exact member")
			target := user
			response, err := groups.Execute(f.ctx, groupRequest(f, scim.GroupCreate, "", "", "edge-group", `{"schemas":["urn:ietf:params:scim:schemas:core:2.0:Group"],"displayName":"Exact group","members":[{"value":"`+user+`","type":"User"}]}`))
			if err != nil {
				t.Fatal("create real scoped Group", err)
			}
			group := groupID(t, response)
			edge := DirectoryGroupEdge{GroupID: group, UserID: user, Present: true}
			wantCommit := mode == "present" || mode == "absent" || mode == "group tombstone" || mode == "user tombstone removal" || mode == "mapped identity"
			switch mode {
			case "absent", "user tombstone removal", "absent claimed present":
				if _, err := groups.Execute(f.ctx, groupRequest(f, scim.GroupPatch, group, response.ETag, "remove-member", `{"schemas":["urn:ietf:params:scim:api:messages:2.0:PatchOp"],"Operations":[{"op":"remove","path":"members"}]}`)); err != nil {
					t.Fatal("remove real Group edge", err)
				}
				edge.Present = mode == "absent claimed present"
			case "group tombstone":
				if _, err := groups.Execute(f.ctx, groupRequest(f, scim.GroupDelete, group, response.ETag, "", "")); err != nil {
					t.Fatal("delete real Group", err)
				}
				edge.Present = false
			case "present claimed absent":
				edge.Present = false
			case "unknown group", "unknown removal group":
				id, err := identity.NewSubjectID()
				if err != nil {
					t.Fatal(err)
				}
				edge.GroupID, edge.Present = string(id), mode == "unknown group"
			case "case changed user":
				for index, char := range user[:len(user)-1] {
					if char >= 'a' && char <= 'z' || char >= 'A' && char <= 'Z' {
						replacement := strings.ToUpper(string(char))
						if replacement == string(char) {
							replacement = strings.ToLower(string(char))
						}
						edge.UserID = user[:index] + replacement + user[index+1:]
						break
					}
				}
			case "nested group":
				parent, err := groups.Execute(f.ctx, groupRequest(f, scim.GroupCreate, "", "", "nested-parent", `{"schemas":["urn:ietf:params:scim:schemas:core:2.0:Group"],"displayName":"Nested parent","members":[{"value":"`+group+`","type":"Group"}]}`))
				if err != nil {
					t.Fatal("create real nested Group reference", err)
				}
				edge.GroupID = groupID(t, parent)
			case "wrong target", "mapped identity":
				target = createNativeNamed(t, f, "OtherEdgeUser", "Other identity")
				if mode == "mapped identity" {
					if _, err := f.pool.Raw().Exec(f.ctx, `DELETE FROM scim.users WHERE resource_id=$1`, target); err != nil {
						t.Fatal(err)
					}
					if _, err := f.pool.Raw().Exec(f.ctx, `UPDATE scim.users SET user_id=$2 WHERE resource_id=$1`, user, target); err != nil {
						t.Fatal(err)
					}
				}
			case "unknown user mapping", "unknown removal user mapping":
				if mode == "unknown removal user mapping" {
					if _, err := groups.Execute(f.ctx, groupRequest(f, scim.GroupDelete, group, response.ETag, "", "")); err != nil {
						t.Fatal("delete Group before absent-edge claim", err)
					}
					edge.Present = false
				}
				if _, err := f.pool.Raw().Exec(f.ctx, `DELETE FROM scim.users WHERE resource_id=$1`, user); err != nil {
					t.Fatal(err)
				}
			case "malformed group", "malformed members":
				payload := `null`
				if mode == "malformed members" {
					var wire []byte
					if err := f.pool.Raw().QueryRow(f.ctx, `SELECT resource FROM scim.groups WHERE resource_id=$1`, group).Scan(&wire); err != nil {
						t.Fatal(err)
					}
					var resource scim.Resource
					if err := json.Unmarshal(wire, &resource); err != nil {
						t.Fatal(err)
					}
					resource.Attributes["members"] = "not-an-array"
					wire, err = json.Marshal(resource)
					if err != nil {
						t.Fatal(err)
					}
					payload = string(wire)
				}
				if _, err := f.pool.Raw().Exec(f.ctx, `UPDATE scim.groups SET resource=convert_to($2,'UTF8') WHERE resource_id=$1`, group, payload); err != nil {
					t.Fatal(err)
				}
			case "malformed user":
				if _, err := f.pool.Raw().Exec(f.ctx, `UPDATE scim.users SET resource=convert_to('null','UTF8') WHERE resource_id=$1`, user); err != nil {
					t.Fatal(err)
				}
			}
			if mode == "deleted user" || mode == "user tombstone removal" {
				current, err := f.service.Execute(f.ctx, scim.Request{Operation: scim.UserGet, Credential: f.bearer, ResourceID: user})
				if err != nil || current.ETag == "" {
					t.Fatal("read real User version before deletion", err)
				}
				if _, err := f.service.Execute(f.ctx, scim.Request{Operation: scim.UserDelete, Credential: f.bearer, ResourceID: user, IfMatch: current.ETag}); err != nil {
					t.Fatal("delete real User", err)
				}
			}
			if mode == "foreign scope" {
				foreignConfig := f.config
				foreignConfig.Scope.ConnectionID = "connection-b"
				foreignService, err := NewService(f.pool, foreignConfig, f.keys)
				if err != nil {
					t.Fatal(err)
				}
				if _, err := foreignService.InitializeConfiguredConnection(f.ctx); err != nil {
					t.Fatal(err)
				}
				if _, err := f.pool.Raw().Exec(f.ctx, `UPDATE scim.groups SET connection_id='connection-b' WHERE resource_id=$1`, group); err != nil {
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
			edgeField, err := edge.Field()
			if err != nil {
				t.Fatal(err)
			}
			owner := &directoryGroupEdgeWorkOwner{directorySourceWorkOwner: directorySourceWorkOwner{groups: groups, observation: observation}, edge: edge}
			switch mode {
			case "wrong commitment":
				edgeField.Value.Bytes[0] ^= 1
			case "missing commitment":
				edgeField.Name = "test.not-an-edge"
			case "missing source commitment":
				sourceField.Name = "test.not-a-source"
			case "foreign owner":
				owner.foreign = true
			case "reconstructed command":
				owner.reconstruct = true
			case "late edge mismatch":
				owner.late = "edge"
			case "late source mismatch":
				owner.late = "source"
			}
			coordinator, registry := directorySourceWorkCoordinator(t, f, owner)
			command, plan := directoryGroupEdgeWorkCommand(t, f, coordinator, registry, owner, target, []identity.FeatureField{sourceField, edgeField})
			var auditsBefore, eventsBefore int
			if err := f.pool.Raw().QueryRow(f.ctx, `SELECT (SELECT count(*) FROM audit.identity_command_bindings),(SELECT count(*) FROM public.outbox_messages)`).Scan(&auditsBefore, &eventsBefore); err != nil {
				t.Fatal(err)
			}
			result, err := executeDirectorySourceWork(f.ctx, coordinator, command, plan)
			if wantCommit && (err != nil || result.Outcome != identity.CommitOutcomeCommitted) {
				t.Fatal("current exact edge failed native commit", result.Outcome, err)
			}
			if !wantCommit && (err == nil || result.Outcome == identity.CommitOutcomeCommitted) {
				t.Fatal("unproven claimed edge committed", result.Outcome, err)
			}
			wantEffects, wantFinal := 0, 0
			if wantCommit {
				wantEffects, wantFinal = 1, 1
				replay, err := executeDirectorySourceWork(f.ctx, coordinator, command, plan)
				if err != nil || replay.Outcome != identity.CommitOutcomeCommitted || replay.Feature == nil || result.Feature == nil || *replay.Feature != *result.Feature {
					t.Fatal("exact edge native replay changed receipt", err)
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
				t.Fatal("edge fence lost native atomicity/replay", effects, eventsAfter-eventsBefore, auditsAfter-auditsBefore, owner.applyCalls, owner.finalCalls)
			}
			if owner.late != "" {
				var groupActive, connectionActive bool
				if err := f.pool.Raw().QueryRow(f.ctx, `SELECT (SELECT deleted_at IS NULL FROM scim.groups WHERE resource_id=$1),(SELECT state='active' AND version=1 FROM scim.connections WHERE connection_id='connection-a')`, group).Scan(&groupActive, &connectionActive); err != nil || !groupActive || !connectionActive {
					t.Fatal("late source/edge fault escaped rollback", err)
				}
			}
		})
	}
}
