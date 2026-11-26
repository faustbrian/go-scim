//go:build integration

package scimpostgres

import (
	"bytes"
	"encoding/json"
	"testing"

	"github.com/faustbrian/go-audit"
	scim "github.com/faustbrian/go-scim"
)

func TestNativeBulkExecuteStructuralDenialRetainsCutoff(t *testing.T) {
	f, service, runner := nativeBulkExecutionFixture(t)
	const body = `{"schemas":["urn:ietf:params:scim:api:messages:2.0:BulkRequest"],"failOnErrors":1,"Operations":[` +
		`{"method":"POST","path":"/Unknown","bulkId":"bad","data":{}},` +
		`{"method":"POST","path":"/Groups","bulkId":"independent-group","data":{"schemas":["urn:ietf:params:scim:schemas:core:2.0:Group"],"displayName":"Independent"}}]}`
	request := BulkAdmissionRequest{Credential: f.bearer, Body: []byte(body)}
	parent, err := service.Admit(f.ctx, request)
	if err != nil || parent.ChildCount != 2 {
		t.Fatal("admit the original structural denial and independent successor", err)
	}
	originals := [2]admittedBulkChild{
		originalStructuralBulkChild(t, f, parent, 0),
		originalBulkChild(t, f, parent, 1),
	}
	if originals[0].resource != "" || originals[0].command == originals[1].command {
		t.Fatal("the original invalid operation must have its own command without a resource allocation")
	}
	wire, err := runner.ExecuteBulk(f.ctx, request)
	if err != nil {
		t.Fatal("structural validation must settle the first child as 400 invalidValue, not reject the Bulk request", protocolStatus(err), err)
	}
	var response struct {
		Schemas    []string
		Operations []struct {
			Method, BulkID, Status, Location, Version string
			Response                                  struct {
				Schemas          []string
				Status, SCIMType string
			}
		}
	}
	if err := json.Unmarshal(wire, &response); err != nil || len(response.Schemas) != 1 ||
		response.Schemas[0] != "urn:ietf:params:scim:api:messages:2.0:BulkResponse" || len(response.Operations) != 1 {
		t.Fatal("return only the original processed denial, omitting its skipped successor", err)
	}
	failed := response.Operations[0]
	if failed.Method != "POST" || failed.BulkID != "bad" || failed.Status != "400" ||
		failed.Location != "" || failed.Version != "" || failed.Response.Status != "400" ||
		failed.Response.SCIMType != "invalidValue" || len(failed.Response.Schemas) != 1 ||
		failed.Response.Schemas[0] != "urn:ietf:params:scim:api:messages:2.0:Error" {
		t.Fatal("the original invalid path must expose its typed denial without Location or version")
	}
	wantResults := [2]scim.BulkChildResult{
		{Status: scim.BulkChildFailed, Code: 400, SCIMType: "invalidValue"},
		{Status: scim.BulkChildSkipped, SkipReason: scim.BulkSkipFailOnErrors},
	}
	wantStates := [2]dependencyCutoffChild{
		{status: "failed", reason: "none", code: 400, failed: 1, cutoff: true, receipts: 1,
			audits: 1, applyAudits: 1, boundApplyAudits: 1},
		{status: "skipped", reason: "fail-on-errors", failed: 1, cutoff: true,
			audits: 1, skipAudits: 1, protectedSkipAudits: 1},
	}
	for range 2 {
		for ordinal, want := range wantResults {
			if result, err := service.ExecuteChild(f.ctx, request, ordinal); err != nil || result != want {
				t.Fatal("replay the original structural denial and audited cutoff without executing the Group", ordinal, result, err)
			}
			if originalStructuralBulkChild(t, f, parent, ordinal) != originals[ordinal] ||
				readDependencyCutoffChild(t, f, parent, ordinal) != wantStates[ordinal] {
				t.Fatal("retain original allocations, one failure, protected audits and zero child Group or outbox effects", ordinal)
			}
		}
		var protectedFailures int
		err := f.pool.Raw().QueryRow(f.ctx, `SELECT count(*) FROM audit.records r
 JOIN audit.identity_command_bindings a ON a.event_id=r.record_id
 JOIN identity.commands c ON c.command_id=a.command_id
 WHERE r.correlation_id=$1 AND r.subject_id=$2 AND r.subject_type='scim_bulk_child'
  AND r.action='identity.scim.bulk_apply_child' AND r.outcome=$3 AND a.event_index=0
  AND c.command_id=decode(translate($2::text,'-_','+/')||'==','base64') AND c.state='aborted'
  AND convert_from(r.canonical_record,'UTF8')::jsonb#>>'{attributes,retention.class}'='protected'`,
			string(parent.CommandID), originals[0].command, int16(audit.OutcomeDenied)).Scan(&protectedFailures)
		if err != nil || protectedFailures != 1 {
			t.Fatal("the original structural denial must retain exactly one protected audit bound to its aborted command", protectedFailures, err)
		}
		if replay, err := runner.ExecuteBulk(f.ctx, request); err != nil || !bytes.Equal(replay, wire) {
			t.Fatal("exact synchronous replay must return the original terminal response bytes", err)
		}
		if replay, err := service.ReadResult(f.ctx, request); err != nil || !bytes.Equal(replay, wire) {
			t.Fatal("the retained terminal body must equal the original synchronous response", err)
		}
		// This aggregate excludes internal validation commands; their audit is checked above.
		requireMixedBulkCounts(t, f, [8]int{0, 0, 0, 1, 1, 1, 1, 2})
	}
}

func TestNativeBulkExecuteStructuralDenialContinuesWithoutCutoff(t *testing.T) {
	f, service, runner := nativeBulkExecutionFixture(t)
	const body = `{"schemas":["urn:ietf:params:scim:api:messages:2.0:BulkRequest"],"failOnErrors":0,"Operations":[` +
		`{"method":"POST","path":"/Unknown","bulkId":"bad","data":{}},` +
		`{"method":"POST","path":"/Groups","bulkId":"independent-group","data":{"schemas":["urn:ietf:params:scim:schemas:core:2.0:Group"],"displayName":"Independent"}}]}`
	request := BulkAdmissionRequest{Credential: f.bearer, Body: []byte(body)}
	parent, err := service.Admit(f.ctx, request)
	if err != nil || parent.ChildCount != 2 {
		t.Fatal("admit the original structural denial and independent successor with cutoff disabled", err)
	}
	originals := [2]admittedBulkChild{
		originalStructuralBulkChild(t, f, parent, 0),
		originalBulkChild(t, f, parent, 1),
	}
	if originals[0].resource != "" || originals[0].command == originals[1].command {
		t.Fatal("the original invalid operation must have its own command without a resource allocation")
	}
	wire, err := runner.ExecuteBulk(f.ctx, request)
	if err != nil {
		t.Fatal("structural denial must not prevent an independent successor when cutoff is disabled", protocolStatus(err), err)
	}
	var response struct {
		Schemas    []string
		Operations []struct {
			Method, BulkID, Status, Location, Version string
			Response                                  struct {
				Schemas          []string
				Status, SCIMType string
			}
		}
	}
	if err := json.Unmarshal(wire, &response); err != nil || len(response.Schemas) != 1 ||
		response.Schemas[0] != "urn:ietf:params:scim:api:messages:2.0:BulkResponse" || len(response.Operations) != 2 {
		t.Fatal("return both processed children with cutoff disabled", err)
	}
	failed, succeeded := response.Operations[0], response.Operations[1]
	if failed.Method != "POST" || failed.BulkID != "bad" || failed.Status != "400" ||
		failed.Location != "" || failed.Version != "" || failed.Response.Status != "400" ||
		failed.Response.SCIMType != "invalidValue" || len(failed.Response.Schemas) != 1 ||
		failed.Response.Schemas[0] != "urn:ietf:params:scim:api:messages:2.0:Error" ||
		succeeded.Method != "POST" || succeeded.BulkID != "independent-group" || succeeded.Status != "201" ||
		succeeded.Location != f.config.BaseURL+"/Groups/"+originals[1].resource || !nativeVersion(scim.Version(succeeded.Version)) {
		t.Fatal("return the original structural denial followed by the independent Group success in request order")
	}
	wantFailed := scim.BulkChildResult{Status: scim.BulkChildFailed, Code: 400, SCIMType: "invalidValue"}
	wantCreated := scim.BulkChildResult{
		Status: scim.BulkChildSucceeded, Code: 201, ResourceID: originals[1].resource, Version: scim.Version(succeeded.Version),
	}
	wantFailedState := dependencyCutoffChild{
		status: "failed", reason: "none", code: 400, failed: 1, receipts: 1,
		audits: 1, applyAudits: 1, boundApplyAudits: 1,
	}
	for range 2 {
		if result, err := service.ExecuteChild(f.ctx, request, 0); err != nil || result != wantFailed {
			t.Fatal("replay the original structural denial with cutoff disabled", result, err)
		}
		if result, err := service.ExecuteChild(f.ctx, request, 1); err != nil || result != wantCreated {
			t.Fatal("replay the independent Group success without reallocating or creating another Group", result, err)
		}
		requireCommittedBulkChild(t, f, parent, 1, originals[1], wantCreated)
		if readDependencyCutoffChild(t, f, parent, 0) != wantFailedState {
			t.Fatal("retain exactly one structural failure without cutoff, resource result, Group or child outbox effects")
		}
		for ordinal, original := range originals {
			if originalStructuralBulkChild(t, f, parent, ordinal) != original {
				t.Fatal("replay replaced an original child allocation", ordinal)
			}
		}
		if replay, err := runner.ExecuteBulk(f.ctx, request); err != nil || !bytes.Equal(replay, wire) {
			t.Fatal("exact synchronous replay must return the original ordered denial and success bytes", err)
		}
		if replay, err := service.ReadResult(f.ctx, request); err != nil || !bytes.Equal(replay, wire) {
			t.Fatal("the retained terminal body must equal the original ordered synchronous response", err)
		}
		requireMixedBulkCounts(t, f, [8]int{0, 0, 1, 2, 2, 2, 1, 2})
	}
}

func originalStructuralBulkChild(t *testing.T, f *nativeFixture, parent BulkAdmission, ordinal int) admittedBulkChild {
	t.Helper()
	var child admittedBulkChild
	if err := f.pool.Raw().QueryRow(f.ctx, `SELECT command_id,coalesce(resource_id,'') FROM scim.bulk_children WHERE parent_id=$1 AND ordinal=$2`, string(parent.CommandID), ordinal).Scan(&child.command, &child.resource); err != nil {
		t.Fatal("read the original structural child allocation", err)
	}
	if child.command == "" || child.command == string(parent.CommandID) {
		t.Fatal("child lacks an independent original command allocation")
	}
	return child
}
