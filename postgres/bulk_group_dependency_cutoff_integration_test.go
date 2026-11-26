//go:build integration

package scimpostgres

import (
	"bytes"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/faustbrian/go-audit"
	scim "github.com/faustbrian/go-scim"
)

func TestNativeGroupBulkDependencyCutoffSkipsBlockedChildAfterPredecessorSuccess(t *testing.T) {
	f, service := bulkChildExecutionFixture(t)
	const body = `{"schemas":["urn:ietf:params:scim:api:messages:2.0:BulkRequest"],"failOnErrors":1,"Operations":[` +
		`{"method":"POST","path":"/Groups","bulkId":"first","data":{"schemas":["urn:ietf:params:scim:schemas:core:2.0:Group"],"displayName":"First"}},` +
		`{"method":"POST","path":"/Groups","bulkId":"unrelated-denial","data":{"schemas":["urn:ietf:params:scim:schemas:core:2.0:Group"],"displayName":"Denied","members":[{"type":"Group","value":"missing-group"}]}},` +
		`{"method":"POST","path":"/Groups","bulkId":"second","data":{"schemas":["urn:ietf:params:scim:schemas:core:2.0:Group"],"displayName":"Second","members":[{"type":"Group","value":"bulkId:first"}]}}]}`
	request := BulkAdmissionRequest{Credential: f.bearer, Body: []byte(body)}
	parent, err := service.Admit(f.ctx, request)
	if err != nil || parent.ChildCount != 3 {
		t.Fatal("admit the predecessor, unrelated denial and dependent", err)
	}
	first := originalBulkChild(t, f, parent, 0)
	dependent := originalBulkChild(t, f, parent, 2)

	_, _ = service.ExecuteChild(f.ctx, request, 2)
	requireDependencyCutoffBlocked(t, f, service, request, parent, 2, 0, false)
	created, err := service.ExecuteChild(f.ctx, request, 0)
	if err != nil {
		t.Fatal("commit the predecessor before the unrelated failure", err)
	}
	requireCommittedBulkChild(t, f, parent, 0, first, created)
	requireDependencyCutoffBlocked(t, f, service, request, parent, 2, 0, false)

	wantFailed := scim.BulkChildResult{Status: scim.BulkChildFailed, Code: 400, SCIMType: "invalidValue"}
	if result, err := service.ExecuteChild(f.ctx, request, 1); err != nil || result != wantFailed {
		t.Fatal("the unrelated failure must activate the cutoff", result, err)
	}
	requireDependencyCutoffBlocked(t, f, service, request, parent, 2, 1, true)

	wantSkipped := scim.BulkChildResult{Status: scim.BulkChildSkipped, SkipReason: scim.BulkSkipFailOnErrors}
	if result, err := service.ExecuteChild(f.ctx, request, 2); err != nil || result != wantSkipped {
		t.Fatal("a previously blocked child with a successful predecessor must skip after cutoff", result, err)
	}
	state := readDependencyCutoffChild(t, f, parent, 2)
	if state.status != "skipped" || state.reason != "fail-on-errors" || state.code != 0 || state.hasResource || state.hasVersion ||
		state.failed != 1 || !state.cutoff || state.groups != 0 || state.outbox != 0 || state.committed != 0 ||
		state.applyAudits != 0 || state.skipAudits != 1 || state.protectedSkipAudits != 1 || state.audits != 1 {
		t.Fatal("resolved blocked child must retain only its protected skip and must not count or execute", state)
	}
	if retained := originalBulkChild(t, f, parent, 2); retained != dependent {
		t.Fatal("skip replaced the dependent's original allocation")
	}

	wire, err := service.ReadResult(f.ctx, request)
	if err != nil {
		t.Fatal("read the terminal response after resolving the blocked child", err)
	}
	var response struct {
		Operations []struct{ BulkID, Status, Location, Version string }
	}
	if err := json.Unmarshal(wire, &response); err != nil || len(response.Operations) != 2 ||
		response.Operations[0].BulkID != "first" || response.Operations[0].Status != "201" ||
		response.Operations[0].Location != f.config.BaseURL+"/Groups/"+first.resource || response.Operations[0].Version != string(created.Version) ||
		response.Operations[1].BulkID != "unrelated-denial" || response.Operations[1].Status != "400" ||
		response.Operations[1].Location != "" || response.Operations[1].Version != "" {
		t.Fatal("wire response must contain exactly the original success and unrelated denial in request order", err)
	}
	requireDependencyCutoffReplay(t, f, service, request, parent, wire, []scim.BulkChildResult{created, wantFailed, wantSkipped})
	requireCommittedBulkChild(t, f, parent, 0, first, created)
}

func TestNativeGroupBulkDependencyCutoffRetainsBlockedChildFailureAfterPredecessorDenial(t *testing.T) {
	f, service := bulkChildExecutionFixture(t)
	body := strings.Replace(dependentGroupBulkFixture, `"Operations":[`, `"failOnErrors":1,"Operations":[`, 1)
	body = strings.Replace(body, `"displayName":"First"`,
		`"displayName":"First","members":[{"type":"Group","value":"missing-group"}]`, 1)
	request := BulkAdmissionRequest{Credential: f.bearer, Body: []byte(body)}
	parent, err := service.Admit(f.ctx, request)
	if err != nil || parent.ChildCount != 2 {
		t.Fatal("admit the failing predecessor and dependent", err)
	}
	dependent := originalBulkChild(t, f, parent, 1)

	_, _ = service.ExecuteChild(f.ctx, request, 1)
	requireDependencyCutoffBlocked(t, f, service, request, parent, 1, 0, false)
	wantFailed := scim.BulkChildResult{Status: scim.BulkChildFailed, Code: 400, SCIMType: "invalidValue"}
	if result, err := service.ExecuteChild(f.ctx, request, 0); err != nil || result != wantFailed {
		t.Fatal("the predecessor denial must activate the cutoff", result, err)
	}
	requireDependencyCutoffBlocked(t, f, service, request, parent, 1, 1, true)

	wantDependencyFailure := scim.BulkChildResult{Status: scim.BulkChildFailed, Code: 424}
	if result, err := service.ExecuteChild(f.ctx, request, 1); err != nil || result != wantDependencyFailure {
		t.Fatal("a known failed dependency must permanently fail rather than skip at cutoff", result, err)
	}
	state := readDependencyCutoffChild(t, f, parent, 1)
	if state.status != "failed" || state.reason != "none" || state.code != 424 || state.hasResource || state.hasVersion ||
		state.failed != 2 || !state.cutoff || state.groups != 0 || state.outbox != 0 || state.committed != 0 ||
		state.applyAudits != 1 || state.boundApplyAudits != 1 || state.skipAudits != 0 || state.protectedSkipAudits != 0 || state.audits != 1 {
		t.Fatal("dependency failure must be retained and counted exactly once without Group or skip effects", state)
	}
	if retained := originalBulkChild(t, f, parent, 1); retained != dependent {
		t.Fatal("dependency failure replaced the original allocation")
	}

	wire, err := service.ReadResult(f.ctx, request)
	if err != nil {
		t.Fatal("both known failures must form a terminal response", err)
	}
	var response struct {
		Operations []struct {
			BulkID, Status, Location, Version string
			Response                          struct{ Status, Detail string }
		}
	}
	if err := json.Unmarshal(wire, &response); err != nil || len(response.Operations) != 2 ||
		response.Operations[0].BulkID != "first" || response.Operations[0].Status != "400" ||
		response.Operations[1].BulkID != "second" || response.Operations[1].Status != "424" ||
		response.Operations[1].Response.Status != "424" || response.Operations[1].Response.Detail != "Dependency failed" {
		t.Fatal("terminal wire response must include the processed dependency failure in original order", err)
	}
	for _, operation := range response.Operations {
		if operation.Location != "" || operation.Version != "" {
			t.Fatal("failed Group creates must not disclose preallocated resource results")
		}
	}
	requireDependencyCutoffReplay(t, f, service, request, parent, wire, []scim.BulkChildResult{wantFailed, wantDependencyFailure})
}

type dependencyCutoffChild struct {
	status, reason                        string
	code, failed                          int
	hasResource, hasVersion, cutoff       bool
	groups, outbox, receipts, committed   int
	audits, applyAudits, boundApplyAudits int
	skipAudits, protectedSkipAudits       int
}

func readDependencyCutoffChild(t *testing.T, f *nativeFixture, parent BulkAdmission, ordinal int) dependencyCutoffChild {
	t.Helper()
	var child dependencyCutoffChild
	err := f.pool.Raw().QueryRow(f.ctx, `SELECT b.status,b.skip_reason,coalesce(b.result_code,0),
 b.result_resource_id IS NOT NULL,b.result_version IS NOT NULL,p.failed_count,p.cutoff_active,
 (SELECT count(*) FROM scim.groups WHERE command_id=b.command_id),
 (SELECT count(*) FROM public.identity_outbox_bindings WHERE command_id=decode(translate(b.command_id,'-_','+/')||'==','base64')),
 (SELECT count(*) FROM identity.commands WHERE command_id=decode(translate(b.command_id,'-_','+/')||'==','base64')),
 (SELECT count(*) FROM identity.commands WHERE command_id=decode(translate(b.command_id,'-_','+/')||'==','base64') AND state='committed'),
 (SELECT count(*) FROM audit.records WHERE subject_id=b.command_id AND correlation_id=b.parent_id),
 (SELECT count(*) FROM audit.records WHERE subject_id=b.command_id AND correlation_id=b.parent_id AND action='identity.scim.bulk_apply_child'),
 (SELECT count(*) FROM audit.records r JOIN audit.identity_command_bindings a ON a.event_id=r.record_id
  WHERE a.command_id=decode(translate(b.command_id,'-_','+/')||'==','base64') AND a.event_index=0
   AND r.subject_id=b.command_id AND r.subject_type='scim_bulk_child' AND r.correlation_id=b.parent_id
   AND r.action='identity.scim.bulk_apply_child' AND r.outcome=$3),
 (SELECT count(*) FROM audit.records WHERE subject_id=b.command_id AND correlation_id=b.parent_id AND action='identity.scim.bulk_skip_child'),
 (SELECT count(*) FROM audit.records r JOIN audit.identity_command_bindings a ON a.event_id=r.record_id
  WHERE a.command_id=decode(translate(b.command_id,'-_','+/')||'==','base64') AND a.event_index=0
   AND r.subject_id=b.command_id AND r.subject_type='scim_bulk_child' AND r.correlation_id=b.parent_id
   AND r.action='identity.scim.bulk_skip_child' AND r.outcome=$3
   AND convert_from(r.canonical_record,'UTF8')::jsonb->>'reason_code'='identity.scim.fail_on_errors_cutoff'
   AND convert_from(r.canonical_record,'UTF8')::jsonb#>>'{attributes,retention.class}'='protected')
 FROM scim.bulk_children b JOIN scim.bulk_requests p USING(parent_id)
 WHERE b.parent_id=$1 AND b.ordinal=$2`, string(parent.CommandID), ordinal, int16(audit.OutcomeDenied)).Scan(
		&child.status, &child.reason, &child.code, &child.hasResource, &child.hasVersion, &child.failed, &child.cutoff,
		&child.groups, &child.outbox, &child.receipts, &child.committed,
		&child.audits, &child.applyAudits, &child.boundApplyAudits, &child.skipAudits, &child.protectedSkipAudits)
	if err != nil {
		t.Fatal("read dependency checkpoint and exact child effects", ordinal, err)
	}
	return child
}

func requireDependencyCutoffBlocked(t *testing.T, f *nativeFixture, service *GroupBulkService, request BulkAdmissionRequest, parent BulkAdmission, ordinal, failures int, cutoff bool) {
	t.Helper()
	state := readDependencyCutoffChild(t, f, parent, ordinal)
	want := dependencyCutoffChild{status: "dependency-blocked", reason: "none", failed: failures, cutoff: cutoff}
	if state != want {
		t.Fatal("the blocked child must remain incomplete without wire results, counts, audits or mutation until selected", state)
	}
	if wire, err := service.ReadResult(f.ctx, request); !errors.Is(err, scim.ErrBulkIncomplete) || len(wire) != 0 {
		t.Fatal("a blocked child must withhold the complete terminal Bulk response even after cutoff", err)
	}
}

func requireDependencyCutoffReplay(t *testing.T, f *nativeFixture, service *GroupBulkService, request BulkAdmissionRequest, parent BulkAdmission, wire []byte, results []scim.BulkChildResult) {
	t.Helper()
	originals := make([]admittedBulkChild, len(results))
	states := make([]dependencyCutoffChild, len(results))
	for ordinal := range results {
		originals[ordinal] = originalBulkChild(t, f, parent, ordinal)
		states[ordinal] = readDependencyCutoffChild(t, f, parent, ordinal)
	}
	for range 2 {
		for ordinal, want := range results {
			if actual, err := service.ExecuteChild(f.ctx, request, ordinal); err != nil || actual != want {
				t.Fatal("retry must return the original retained child result", ordinal, actual, err)
			}
		}
		if replayed, err := service.ReadResult(f.ctx, request); err != nil || !bytes.Equal(wire, replayed) {
			t.Fatal("retry must preserve the exact terminal wire bytes", err)
		}
		for ordinal := range results {
			if originalBulkChild(t, f, parent, ordinal) != originals[ordinal] || readDependencyCutoffChild(t, f, parent, ordinal) != states[ordinal] {
				t.Fatal("replay changed original allocations, failure count, audits or effects", ordinal)
			}
		}
	}
}
