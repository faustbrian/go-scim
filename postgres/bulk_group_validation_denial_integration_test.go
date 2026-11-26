//go:build integration

package scimpostgres

import (
	"bytes"
	"encoding/json"
	"testing"

	"github.com/faustbrian/go-audit"
	scim "github.com/faustbrian/go-scim"
)

func TestNativeBulkExecuteGroupValidationDenialRetainsCutoff(t *testing.T) {
	f, service, runner := nativeBulkExecutionFixture(t)
	const body = `{"schemas":["urn:ietf:params:scim:api:messages:2.0:BulkRequest"],"failOnErrors":1,"Operations":[` +
		`{"method":"POST","path":"/Groups","bulkId":"invalid-group","data":{"schemas":["urn:ietf:params:scim:schemas:core:2.0:Group"]}},` +
		`{"method":"POST","path":"/Groups","bulkId":"independent-group","data":{"schemas":["urn:ietf:params:scim:schemas:core:2.0:Group"],"displayName":"Independent"}}]}`
	request := BulkAdmissionRequest{Credential: f.bearer, Body: []byte(body)}
	wire, err := runner.ExecuteBulk(f.ctx, request)
	if err != nil {
		t.Fatal("Group validation must settle the first child as 400 invalidValue, not reject the Bulk request", protocolStatus(err), err)
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
		t.Fatal("return one processed child in the terminal Bulk response, omitting its skipped successor", err)
	}
	failed := response.Operations[0]
	if failed.Method != "POST" || failed.BulkID != "invalid-group" || failed.Status != "400" ||
		failed.Location != "" || failed.Version != "" || failed.Response.Status != "400" ||
		failed.Response.SCIMType != "invalidValue" || len(failed.Response.Schemas) != 1 ||
		failed.Response.Schemas[0] != "urn:ietf:params:scim:api:messages:2.0:Error" {
		t.Fatal("only the original invalid Group POST must expose its typed denial, without Location or version")
	}
	parent, err := service.Admit(f.ctx, request)
	if err != nil || parent.ChildCount != 2 {
		t.Fatal("retain the original invalid child and independent successor allocations", err)
	}
	originals := [2]admittedBulkChild{originalBulkChild(t, f, parent, 0), originalBulkChild(t, f, parent, 1)}
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
				t.Fatal("replay the original validation denial and audited cutoff without executing either Group", ordinal, result, err)
			}
			if originalBulkChild(t, f, parent, ordinal) != originals[ordinal] ||
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
			t.Fatal("the original failed child must retain exactly one protected denial bound to its aborted command", protectedFailures, err)
		}
		if replay, err := runner.ExecuteBulk(f.ctx, request); err != nil || !bytes.Equal(replay, wire) {
			t.Fatal("exact synchronous replay must return the original terminal response bytes", err)
		}
		if replay, err := service.ReadResult(f.ctx, request); err != nil || !bytes.Equal(replay, wire) {
			t.Fatal("the retained terminal body must equal the original synchronous response", err)
		}
		// The skip has its own protected audit, but no identity command to join.
		requireMixedBulkCounts(t, f, [8]int{0, 0, 0, 1, 2, 1, 1, 2})
	}
}
