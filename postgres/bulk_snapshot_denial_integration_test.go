//go:build integration

package scimpostgres

import (
	"bytes"
	"encoding/json"
	"errors"
	"testing"

	"github.com/faustbrian/go-audit"
	scim "github.com/faustbrian/go-scim"
)

func installSnapshotValidationSchema(t *testing.T, f *nativeFixture) {
	t.Helper()
	base := BulkGroupMutationMigrationSource{Base: bulkTypedValidationTestBase(), Version: 45}
	expandBulkTypedValidation(t, f, base)
	expandBulkSnapshotValidation(t, f, BulkTypedValidationMigrationSource{Base: base, Version: 46, ValidationVersion: 47})
}

func TestNativeBulkSnapshotDenialRetainsOriginalOutcomeAfterLaterWrite(t *testing.T) {
	for _, scenario := range []struct{ kind, patch string }{
		{"noTarget", `{"schemas":["urn:ietf:params:scim:api:messages:2.0:PatchOp"],"Operations":[{"op":"remove","path":"emails[type eq \"work\"]"}]}`},
		{"mutability", `{"schemas":["urn:ietf:params:scim:api:messages:2.0:PatchOp"],"Operations":[{"op":"replace","path":"displayName","value":"Must roll back"},{"op":"remove","path":"userName"}]}`},
	} {
		t.Run(scenario.kind, func(t *testing.T) {
			f, legacy, _ := mixedUserMutationFixture(t)
			installSnapshotValidationSchema(t, f)
			service := legacy.WithTypedValidation()
			id := createNativeNamed(t, f, "snapshot-denial", "Original display")
			original := readMixedMutationUser(t, f, id)
			ordinary := scim.Request{
				Operation: scim.UserPatch, Credential: f.bearer, ResourceID: id, IfMatch: original.ETag,
				ContentType: "application/scim+json", Body: []byte(scenario.patch),
			}
			response, err := f.service.Execute(f.ctx, ordinary)
			var denial *scim.Error
			if !errors.As(err, &denial) || denial.StatusCode() != 400 || denial.SCIMType() != scenario.kind || len(response.Body) != 0 {
				t.Fatal("ordinary User PATCH must first demonstrate the exact snapshot-derived protocol denial", response, err)
			}
			if current := readMixedMutationUser(t, f, id); current.ETag != original.ETag || !bytes.Equal(current.Body, original.Body) {
				t.Fatal("ordinary failed PATCH must not apply any prospective field change")
			}

			body, err := json.Marshal(map[string]any{
				"schemas":      []string{"urn:ietf:params:scim:api:messages:2.0:BulkRequest"},
				"failOnErrors": 1,
				"Operations": []map[string]any{
					{"method": "PATCH", "path": "/Users/" + id, "version": original.ETag, "data": json.RawMessage(scenario.patch)},
					{"method": "POST", "path": "/Groups", "bulkId": "cutoff-successor", "data": json.RawMessage(`{"schemas":["urn:ietf:params:scim:schemas:core:2.0:Group"],"displayName":"Must not be created"}`)},
				},
			})
			if err != nil {
				t.Fatal("encode the exact failed PATCH and independent cutoff successor", err)
			}
			request := BulkAdmissionRequest{Credential: f.bearer, Body: body}
			plan, err := scim.ParseBulk(body, nil, scim.DefaultBulkPolicy(), scim.DefaultLimits())
			if err != nil {
				t.Fatal("snapshot-dependent PATCH must parse before a current resource is supplied", err)
			}
			operations := plan.Operations()
			if len(operations) != 2 || operations[0].Error != nil || operations[0].Version != string(original.ETag) ||
				operations[0].Target.ResourceID != id || operations[1].Error != nil {
				t.Fatal("the fixture must have no planner denial and must preserve the exact original If-Match", operations)
			}
			parent, err := service.Admit(f.ctx, request)
			if err != nil || parent.ChildCount != 2 {
				t.Fatal("admit the original snapshot-dependent PATCH and cutoff successor", err)
			}
			child := originalStructuralBulkChild(t, f, parent, 0)
			successor := originalBulkChild(t, f, parent, 1)
			wire, err := service.ExecuteBulk(f.ctx, request)
			if err != nil {
				t.Fatal("native Bulk must retain the ordinary snapshot denial as a typed child result", err)
			}
			var result struct {
				Schemas    []string
				Operations []map[string]json.RawMessage
			}
			if err := json.Unmarshal(wire, &result); err != nil || len(result.Schemas) != 1 ||
				result.Schemas[0] != "urn:ietf:params:scim:api:messages:2.0:BulkResponse" || len(result.Operations) != 1 {
				t.Fatal("return only the failed PATCH and omit its audited cutoff successor", err)
			}
			var method, status, location string
			var failure struct {
				Schemas          []string
				Status, SCIMType string
			}
			operation := result.Operations[0]
			if json.Unmarshal(operation["method"], &method) != nil || json.Unmarshal(operation["status"], &status) != nil ||
				json.Unmarshal(operation["location"], &location) != nil || json.Unmarshal(operation["response"], &failure) != nil ||
				method != "PATCH" || status != "400" || location != f.config.BaseURL+"/Users/"+id ||
				failure.Status != "400" || failure.SCIMType != scenario.kind || len(failure.Schemas) != 1 ||
				failure.Schemas[0] != "urn:ietf:params:scim:api:messages:2.0:Error" || len(operation) != 4 {
				t.Fatal("retain the original typed snapshot denial and target Location without a result version")
			}
			wantFailure := scim.BulkChildResult{Status: scim.BulkChildFailed, Code: 400, SCIMType: scenario.kind}
			wantSkipped := scim.BulkChildResult{Status: scim.BulkChildSkipped, SkipReason: scim.BulkSkipFailOnErrors}
			wantFailedState := dependencyCutoffChild{status: "failed", reason: "none", code: 400, failed: 1, cutoff: true,
				hasResource: true, receipts: 1, audits: 1, applyAudits: 1, boundApplyAudits: 1}
			wantSkippedState := dependencyCutoffChild{status: "skipped", reason: "fail-on-errors", failed: 1, cutoff: true,
				audits: 1, skipAudits: 1, protectedSkipAudits: 1}
			requireRetained := func() {
				t.Helper()
				if originalStructuralBulkChild(t, f, parent, 0) != child || originalBulkChild(t, f, parent, 1) != successor ||
					readDependencyCutoffChild(t, f, parent, 0) != wantFailedState || readDependencyCutoffChild(t, f, parent, 1) != wantSkippedState {
					t.Fatal("retain one failure and protected cutoff audit without resource mutation or child outbox effects")
				}
				var protected int
				err := f.pool.Raw().QueryRow(f.ctx, `SELECT count(*) FROM audit.records r
 JOIN audit.identity_command_bindings a ON a.event_id=r.record_id
 JOIN identity.commands c ON c.command_id=a.command_id
 WHERE r.correlation_id=$1 AND r.subject_id=$2 AND r.subject_type='scim_bulk_child'
 AND r.action='identity.scim.bulk_apply_child' AND r.outcome=$3 AND a.event_index=0 AND c.state='aborted'
 AND c.command_id=decode(translate($2::text,'-_','+/')||'==','base64')
 AND convert_from(r.canonical_record,'UTF8')::jsonb#>>'{attributes,retention.class}'='protected'`,
					string(parent.CommandID), child.command, int16(audit.OutcomeDenied)).Scan(&protected)
				if err != nil || protected != 1 {
					t.Fatal("retain exactly one protected snapshot denial audit bound to its aborted child command", protected, err)
				}
			}
			requireRetained()
			if current := readMixedMutationUser(t, f, id); current.ETag != original.ETag || !bytes.Equal(current.Body, original.Body) {
				t.Fatal("snapshot denial must roll back every prospective change and preserve the original version")
			}

			later, err := f.service.Execute(f.ctx, scim.Request{
				Operation: scim.UserPatch, Credential: f.bearer, ResourceID: id, IfMatch: original.ETag,
				ContentType: "application/scim+json", Body: []byte(`{"schemas":["urn:ietf:params:scim:api:messages:2.0:PatchOp"],"Operations":[{"op":"replace","path":"displayName","value":"Later ordinary state"},{"op":"add","path":"emails","value":[{"type":"work","value":"later@example.test"}]}]}`),
			})
			if err != nil || later.Status != 200 || later.ETag == original.ETag {
				t.Fatal("advance the resource and supply a matching filtered target through an ordinary write", err)
			}
			for range 2 {
				for ordinal, want := range []scim.BulkChildResult{wantFailure, wantSkipped} {
					if actual, err := service.ExecuteChild(f.ctx, request, ordinal); err != nil || actual != want {
						t.Fatal("replay the original outcome, not a fresh stale-version check or new snapshot evaluation", ordinal, actual, err)
					}
				}
				if replay, err := service.ExecuteBulk(f.ctx, request); err != nil || !bytes.Equal(replay, wire) {
					t.Fatal("later resource changes must not replace the retained whole-Bulk response", err)
				}
				if replay, err := service.ReadResult(f.ctx, request); err != nil || !bytes.Equal(replay, wire) {
					t.Fatal("retained response bytes must survive the later ordinary write", err)
				}
				requireRetained()
				if current := readMixedMutationUser(t, f, id); current.ETag != later.ETag || !bytes.Equal(current.Body, later.Body) {
					t.Fatal("replaying the old failed PATCH must preserve the later User state and version")
				}
			}
		})
	}
}

func TestNativeBulkSnapshotDenialRetainsGroupMissingPatchTarget(t *testing.T) {
	f, legacy, _ := mixedUserMutationFixture(t)
	installSnapshotValidationSchema(t, f)
	groups := groupsOnPool(t, f, f.pool)
	seed, err := groups.Execute(f.ctx, groupRequest(f, scim.GroupCreate, "", "", "snapshot-empty-group", `{"schemas":["urn:ietf:params:scim:schemas:core:2.0:Group"],"displayName":"No members"}`))
	if err != nil {
		t.Fatal("seed the original Group", err)
	}
	id := groupID(t, seed)
	const patch = `{"schemas":["urn:ietf:params:scim:api:messages:2.0:PatchOp"],"Operations":[{"op":"remove","path":"members[value eq \"missing\"]"}]}`
	if _, err := groups.Execute(f.ctx, groupRequest(f, scim.GroupPatch, id, seed.ETag, "", patch)); protocolStatus(err) != 400 {
		t.Fatal("ordinary Group PATCH must reject the nonmatching member filter", err)
	}
	request := mixedUserMutationRequest(t, f, []map[string]any{{
		"method": "PATCH", "path": "/Groups/" + id, "version": seed.ETag, "data": json.RawMessage(patch),
	}})
	service := legacy.WithTypedValidation()
	wire, err := service.ExecuteBulk(f.ctx, request)
	if err != nil {
		t.Fatal("retain the original Group snapshot denial", err)
	}
	requirePlannerPathFailureWire(t, wire, 1, 0, 400, "noTarget", f.config.BaseURL+"/Groups/"+id)
	if replay, err := service.ReadResult(f.ctx, request); err != nil || !bytes.Equal(wire, replay) {
		t.Fatal("read back the exact Group outcome", err)
	}
	current, err := groups.Execute(f.ctx, groupRequest(f, scim.GroupGet, id, "", "", ""))
	if err != nil || current.ETag != seed.ETag || !bytes.Equal(current.Body, seed.Body) {
		t.Fatal("denial must not alter the Group resource or version", err)
	}
}
