//go:build integration

package scimpostgres

import (
	"bytes"
	"context"
	"encoding/json"
	"testing"

	"github.com/faustbrian/go-authorization/v3"
	scim "github.com/faustbrian/go-scim"
)

func bulkGroupDeleteRequest(t *testing.T, f *nativeFixture, id string, version scim.Version) BulkAdmissionRequest {
	t.Helper()
	body, err := json.Marshal(map[string]any{
		"schemas": []string{"urn:ietf:params:scim:api:messages:2.0:BulkRequest"},
		"Operations": []map[string]any{{
			"method": "DELETE", "path": "/Groups/" + id, "version": version,
		}},
	})
	if err != nil {
		t.Fatal("encode the original DELETE precondition", err)
	}
	return BulkAdmissionRequest{Credential: f.bearer, Body: body}
}

func bulkGroupDeleteChildCommand(t *testing.T, f *nativeFixture, parent BulkAdmission) string {
	t.Helper()
	var command string
	if err := f.pool.Raw().QueryRow(f.ctx, `SELECT command_id FROM scim.bulk_children WHERE parent_id=$1 AND ordinal=0`, string(parent.CommandID)).Scan(&command); err != nil || command == "" || command == string(parent.CommandID) {
		t.Fatal("DELETE must retain its original independent child command", err)
	}
	return command
}

func requireBulkDeleteCommittedEffects(t *testing.T, f *nativeFixture, parent BulkAdmission, childCommand, id string) {
	t.Helper()
	var status, resource string
	var code, committed, audits, events int
	var version *string
	err := f.pool.Raw().QueryRow(f.ctx, `SELECT b.status,b.result_code,b.result_resource_id,b.result_version,
 (SELECT count(*) FROM identity.commands c WHERE c.command_id=decode(translate(b.command_id,'-_','+/')||'==','base64') AND c.state='committed'),
 (SELECT count(*) FROM audit.identity_command_bindings a JOIN audit.records r ON r.record_id=a.event_id
  WHERE a.command_id=decode(translate(b.command_id,'-_','+/')||'==','base64')
  AND r.action='identity.scim.bulk_apply_child' AND r.subject_type='scim_bulk_child'
  AND r.subject_id=b.command_id AND r.correlation_id=b.parent_id),
 (SELECT count(*) FROM public.identity_outbox_bindings o WHERE o.command_id=decode(translate(b.command_id,'-_','+/')||'==','base64'))
 FROM scim.bulk_children b WHERE b.parent_id=$1 AND b.ordinal=0 AND b.command_id=$2`, string(parent.CommandID), childCommand).Scan(
		&status, &code, &resource, &version, &committed, &audits, &events)
	if err != nil || status != "succeeded" || code != 204 || resource != id || version != nil || committed != 1 || audits != 1 || events != 1 {
		t.Fatal("DELETE must retain one empty-version success, original committed command, audit and outbox", status, code, committed, audits, events, err)
	}
}

func TestNativeGroupBulkDeleteCommitsAndReplaysWithoutDeletingMembers(t *testing.T) {
	f, service := bulkChildExecutionFixture(t)
	installBulkGroupMutationSchema(t, f)
	groups := groupsOnPool(t, f, f.pool)
	userID := createNativeNamed(t, f, "BulkDeleteMember", "Member remains")
	userBefore, err := f.service.Execute(f.ctx, scim.Request{Operation: scim.UserGet, Credential: f.bearer, ResourceID: userID})
	if err != nil {
		t.Fatal("read the original User member", err)
	}
	member, err := groups.Execute(f.ctx, groupRequest(f, scim.GroupCreate, "", "", "bulk-delete-member", `{"schemas":["urn:ietf:params:scim:schemas:core:2.0:Group"],"displayName":"Member remains"}`))
	if err != nil {
		t.Fatal("create the nested Group member", err)
	}
	memberID := groupID(t, member)
	created, err := groups.Execute(f.ctx, groupRequest(f, scim.GroupCreate, "", "", "bulk-delete-target", `{"schemas":["urn:ietf:params:scim:schemas:core:2.0:Group"],"displayName":"Delete only this Group","members":[{"type":"User","value":"`+userID+`"},{"type":"Group","value":"`+memberID+`"}]}`))
	if err != nil {
		t.Fatal("create the Group selected for Bulk deletion", err)
	}
	id := groupID(t, created)
	request := bulkGroupDeleteRequest(t, f, id, created.ETag)
	parent, err := service.Admit(f.ctx, request)
	if err != nil || parent.ChildCount != 1 {
		t.Fatal("admit one acyclic Group DELETE", err)
	}
	childCommand := bulkGroupDeleteChildCommand(t, f, parent)
	if current, err := groups.Execute(f.ctx, groupRequest(f, scim.GroupGet, id, "", "", "")); err != nil || current.ETag != created.ETag || !bytes.Equal(current.Body, created.Body) {
		t.Fatal("admission must not execute the DELETE", err)
	}

	want := scim.BulkChildResult{Status: scim.BulkChildSucceeded, Code: 204, ResourceID: id}
	if result, err := service.ExecuteChild(f.ctx, request, 0); err != nil || result != want {
		t.Fatal("execute the original Group DELETE without a result version", result, err)
	}
	requireBulkDeleteCommittedEffects(t, f, parent, childCommand, id)
	var command string
	var generation int64
	var tombstone, emptyProjection bool
	err = f.pool.Raw().QueryRow(f.ctx, `SELECT command_id,generation,deleted_at IS NOT NULL,resource=convert_to('null','UTF8') FROM scim.groups WHERE resource_id=$1`, id).Scan(
		&command, &generation, &tombstone, &emptyProjection)
	if err != nil || command != childCommand || generation != 2 || !tombstone || !emptyProjection {
		t.Fatal("the original child must tombstone exactly its target once", generation, tombstone, emptyProjection, err)
	}
	if _, err := groups.Execute(f.ctx, groupRequest(f, scim.GroupGet, id, "", "", "")); protocolStatus(err) != 404 {
		t.Fatal("the deleted Group remains readable", err)
	}
	if current, err := groups.Execute(f.ctx, groupRequest(f, scim.GroupGet, memberID, "", "", "")); err != nil || current.ETag != member.ETag || !bytes.Equal(current.Body, member.Body) {
		t.Fatal("Bulk DELETE must not remove or modify its Group member", err)
	}
	if current, err := f.service.Execute(f.ctx, scim.Request{Operation: scim.UserGet, Credential: f.bearer, ResourceID: userID}); err != nil || current.ETag != userBefore.ETag || !bytes.Equal(current.Body, userBefore.Body) {
		t.Fatal("Bulk DELETE must not remove or modify its User member", err)
	}

	wire, err := service.ReadResult(f.ctx, request)
	if err != nil {
		t.Fatal("read the terminal DELETE result", err)
	}
	var response struct {
		Schemas    []string
		Operations []map[string]json.RawMessage
	}
	if err := json.Unmarshal(wire, &response); err != nil || len(response.Schemas) != 1 || response.Schemas[0] != "urn:ietf:params:scim:api:messages:2.0:BulkResponse" || len(response.Operations) != 1 {
		t.Fatal("DELETE did not produce one SCIM BulkResponse operation", err)
	}
	operation := response.Operations[0]
	var method, status, location string
	if json.Unmarshal(operation["method"], &method) != nil || json.Unmarshal(operation["status"], &status) != nil || json.Unmarshal(operation["location"], &location) != nil ||
		method != "DELETE" || status != "204" || location != f.config.BaseURL+"/Groups/"+id || len(operation) != 3 {
		t.Fatal("DELETE wire result must contain only method, status and target location, without a version or response body")
	}
	if replayed, err := service.ExecuteChild(f.ctx, request, 0); err != nil || replayed != want {
		t.Fatal("the tombstone must not change the original DELETE result", replayed, err)
	}

	if tag, err := f.pool.Raw().Exec(f.ctx, `DELETE FROM scim.groups WHERE resource_id=$1 AND deleted_at IS NOT NULL`, id); err != nil || tag.RowsAffected() != 1 {
		t.Fatal("expire only the owned target tombstone", err)
	}
	if replayed, err := service.ExecuteChild(f.ctx, request, 0); err != nil || replayed != want {
		t.Fatal("terminal DELETE replay must survive target tombstone expiry", replayed, err)
	}
	if replayed, err := service.ReadResult(f.ctx, request); err != nil || !bytes.Equal(replayed, wire) {
		t.Fatal("tombstone expiry must not reconstruct or change retained response bytes", err)
	}
	requireBulkDeleteCommittedEffects(t, f, parent, childCommand, id)
	var targets int
	if err := f.pool.Raw().QueryRow(f.ctx, `SELECT count(*) FROM scim.groups WHERE resource_id=$1`, id).Scan(&targets); err != nil || targets != 0 {
		t.Fatal("terminal replay recreated the expired target projection", targets, err)
	}
	restricted := *f
	restricted.config.Authorization = configuredPolicy(func(ctx context.Context, decision authorization.DecisionContext) (authorization.Decision, error) {
		if decision.Request.Action == authorization.Action(scim.GroupDelete) && string(decision.Request.Resource.ID) == id {
			return authorization.Decision{Outcome: authorization.Deny, Revision: decision.PolicyRevision}, nil
		}
		return f.config.Authorization.Decide(ctx, decision)
	})
	restrictedBulk, err := NewGroupBulkService(groupsOnPool(t, &restricted, f.pool), service.request, service.response)
	if err != nil {
		t.Fatal("build a current policy that still permits Bulk but denies the exact Group deletion", err)
	}
	if got, err := restrictedBulk.ExecuteChild(f.ctx, request, 0); protocolStatus(err) != 403 || got != (scim.BulkChildResult{}) {
		t.Fatal("Bulk permission must not disclose a denied child operation", err)
	}
	if got, err := restrictedBulk.ReadResult(f.ctx, request); protocolStatus(err) != 403 || len(got) != 0 {
		t.Fatal("Bulk permission must not disclose the denied child's terminal wire result", err)
	}
	f.deny.Store(true)
	if result, err := service.ExecuteChild(f.ctx, request, 0); protocolStatus(err) != 403 || result != (scim.BulkChildResult{}) {
		t.Fatal("terminal DELETE replay must still require current authority", err)
	}
	if result, err := service.ReadResult(f.ctx, request); protocolStatus(err) != 403 || len(result) != 0 {
		t.Fatal("terminal DELETE response must not bypass current authority", err)
	}
}

func TestNativeGroupBulkDeleteRetainsStalePrecondition(t *testing.T) {
	f, service := bulkChildExecutionFixture(t)
	installBulkGroupMutationSchema(t, f)
	groups := groupsOnPool(t, f, f.pool)
	created, err := groups.Execute(f.ctx, groupRequest(f, scim.GroupCreate, "", "", "bulk-stale-delete-target", `{"schemas":["urn:ietf:params:scim:schemas:core:2.0:Group"],"displayName":"Before admission"}`))
	if err != nil {
		t.Fatal("create the stale DELETE target", err)
	}
	id := groupID(t, created)
	request := bulkGroupDeleteRequest(t, f, id, created.ETag)
	parent, err := service.Admit(f.ctx, request)
	if err != nil || parent.ChildCount != 1 {
		t.Fatal("admit the DELETE with its exact original version", err)
	}
	childCommand := bulkGroupDeleteChildCommand(t, f, parent)
	winner, err := groups.Execute(f.ctx, groupRequest(f, scim.GroupReplace, id, created.ETag, "advance-before-bulk-delete", `{"schemas":["urn:ietf:params:scim:schemas:core:2.0:Group"],"displayName":"Changed after admission"}`))
	if err != nil || winner.ETag == created.ETag {
		t.Fatal("advance the Group after Bulk admission", err)
	}
	want := scim.BulkChildResult{Status: scim.BulkChildFailed, Code: 412}
	for range 2 {
		if result, err := service.ExecuteChild(f.ctx, request, 0); err != nil || result != want {
			t.Fatal("retain and replay the original stale If-Match denial", result, err)
		}
	}
	if current, err := groups.Execute(f.ctx, groupRequest(f, scim.GroupGet, id, "", "", "")); err != nil || current.ETag != winner.ETag || !bytes.Equal(current.Body, winner.Body) {
		t.Fatal("a stale Bulk DELETE must not remove or modify the winning Group", err)
	}
	var failed, aborted, audits, events int
	var status string
	var code int
	var resource, version *string
	err = f.pool.Raw().QueryRow(f.ctx, `SELECT b.status,b.result_code,b.result_resource_id,b.result_version,p.failed_count,
 (SELECT count(*) FROM identity.commands c WHERE c.command_id=decode(translate(b.command_id,'-_','+/')||'==','base64') AND c.state='aborted'),
 (SELECT count(*) FROM audit.records r WHERE r.subject_id=b.command_id AND r.correlation_id=b.parent_id AND r.action='identity.scim.bulk_apply_child'),
 (SELECT count(*) FROM public.identity_outbox_bindings o WHERE o.command_id=decode(translate(b.command_id,'-_','+/')||'==','base64'))
 FROM scim.bulk_children b JOIN scim.bulk_requests p USING(parent_id) WHERE b.parent_id=$1 AND b.command_id=$2`, string(parent.CommandID), childCommand).Scan(
		&status, &code, &resource, &version, &failed, &aborted, &audits, &events)
	if err != nil || status != "failed" || code != 412 || resource != nil || version != nil || failed != 1 || aborted != 1 || audits != 1 || events != 0 {
		t.Fatal("stale DELETE must retain one denial and no success effects", status, code, failed, aborted, audits, events, err)
	}
	wire, err := service.ReadResult(f.ctx, request)
	if err != nil {
		t.Fatal("read the terminal stale DELETE denial", err)
	}
	var response struct {
		Operations []struct {
			Method, Status, Location, Version string
			Response                          *struct {
				Schemas  []string
				Status   string
				SCIMType string `json:"scimType"`
			}
		}
	}
	if json.Unmarshal(wire, &response) != nil || len(response.Operations) != 1 || response.Operations[0].Method != "DELETE" || response.Operations[0].Status != "412" ||
		response.Operations[0].Location != f.config.BaseURL+"/Groups/"+id || response.Operations[0].Version != "" || response.Operations[0].Response == nil {
		t.Fatal("terminal stale DELETE must encode its original typed SCIM 412 result")
	}
	denial := response.Operations[0].Response
	if denial.Status != "412" || denial.SCIMType != "" || len(denial.Schemas) != 1 || denial.Schemas[0] != "urn:ietf:params:scim:api:messages:2.0:Error" {
		t.Fatal("the retained 412 must use the SCIM Error schema without an unregistered scimType")
	}
	if replayed, err := service.ReadResult(f.ctx, request); err != nil || !bytes.Equal(replayed, wire) {
		t.Fatal("retained stale DELETE response changed on repeat", err)
	}
}
