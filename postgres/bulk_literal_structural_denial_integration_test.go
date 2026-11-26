//go:build integration

package scimpostgres

import (
	"bytes"
	"context"
	"encoding/json"
	"testing"

	"github.com/faustbrian/go-audit"
	"github.com/faustbrian/go-authorization/v3"
	scim "github.com/faustbrian/go-scim"
)

func TestNativeBulkLiteralStructuralDenialPreservesUsersAndGroups(t *testing.T) {
	f, service, _ := mixedUserMutationFixture(t)
	userID := createNativeNamed(t, f, "literal-user", "Unchanged User")
	user := readMixedMutationUser(t, f, userID)
	groups := groupsOnPool(t, f, f.pool)
	group, err := groups.Execute(f.ctx, groupRequest(f, scim.GroupCreate, "", "", "literal-all-methods", `{"schemas":["urn:ietf:params:scim:schemas:core:2.0:Group"],"displayName":"Unchanged Group"}`))
	if err != nil {
		t.Fatal("seed the literal Group", err)
	}
	groupResourceID := groupID(t, group)
	var operations []map[string]any
	paths := []string{"/Users/" + userID, "/Groups/" + groupResourceID}
	methods := []string{"PUT", "PATCH", "DELETE"}
	for index, resource := range []scim.Response{user, group} {
		for _, method := range methods {
			operation := map[string]any{"method": method, "path": paths[index], "version": resource.ETag}
			if method == "DELETE" {
				operation["data"] = map[string]any{}
			}
			operations = append(operations, operation)
		}
	}
	request := mixedUserMutationRequest(t, f, operations)
	wire, err := service.ExecuteBulk(f.ctx, request)
	if err != nil {
		t.Fatal("settle all six structural denials", err)
	}
	var response struct {
		Operations []struct {
			Method, Status, Location, Version string
			Response                          struct{ SCIMType string }
		}
	}
	if err := json.Unmarshal(wire, &response); err != nil || len(response.Operations) != len(operations) {
		t.Fatal("return each structurally denied operation", err)
	}
	for i, result := range response.Operations {
		if result.Method != methods[i%len(methods)] || result.Status != "400" || result.Response.SCIMType != "invalidValue" ||
			result.Location != f.config.BaseURL+paths[i/len(methods)] || result.Version != "" {
			t.Fatalf("unexpected structural result at ordinal %d: %+v", i, result)
		}
	}
	currentUser := readMixedMutationUser(t, f, userID)
	currentGroup, err := groups.Execute(f.ctx, groupRequest(f, scim.GroupGet, groupResourceID, "", "", ""))
	if err != nil || !bytes.Equal(user.Body, currentUser.Body) || !bytes.Equal(group.Body, currentGroup.Body) ||
		user.ETag != currentUser.ETag || group.ETag != currentGroup.ETag {
		t.Fatal("structural denials must not mutate either resource", err)
	}
}

func TestNativeBulkLiteralStructuralDenialRequiresCurrentGroupPatchAuthority(t *testing.T) {
	f, _, _ := nativeBulkExecutionFixture(t)
	installBulkGroupMutationSchema(t, f)
	groups := groupsOnPool(t, f, f.pool)
	seed, err := groups.Execute(f.ctx, groupRequest(f, scim.GroupCreate, "", "", "literal-structural-target", `{"schemas":["urn:ietf:params:scim:schemas:core:2.0:Group"],"displayName":"Unchanged target"}`))
	if err != nil {
		t.Fatal("seed the literal PATCH target", err)
	}
	id := groupID(t, seed)
	projection := func() string {
		t.Helper()
		var snapshot string
		if err := f.pool.Raw().QueryRow(f.ctx, `SELECT to_jsonb(g)::text FROM scim.groups g WHERE resource_id=$1`, id).Scan(&snapshot); err != nil {
			t.Fatal("read the complete original Group projection", err)
		}
		return snapshot
	}
	before := projection()
	body, err := json.Marshal(map[string]any{
		"schemas": []string{"urn:ietf:params:scim:api:messages:2.0:BulkRequest"},
		"Operations": []map[string]any{{
			"method": "PATCH", "path": "/Groups/" + id, "version": seed.ETag,
		}},
	})
	if err != nil {
		t.Fatal("encode a literal PATCH with its version but without data", err)
	}
	request := BulkAdmissionRequest{Credential: f.bearer, Body: body}
	denyPatch := true
	restricted := *f
	restricted.config.Authorization = configuredPolicy(func(ctx context.Context, decision authorization.DecisionContext) (authorization.Decision, error) {
		if denyPatch && decision.Request.Action == authorization.Action(scim.GroupPatch) &&
			decision.Request.Resource.Type == "identity.scim.group" && string(decision.Request.Resource.ID) == id {
			return authorization.Decision{Outcome: authorization.Deny, Revision: decision.PolicyRevision}, nil
		}
		return f.config.Authorization.Decide(ctx, decision)
	})
	service, err := NewBulkService(groupsOnPool(t, &restricted, f.pool), scim.DefaultBulkPolicy(), scim.DefaultBulkResponsePolicy())
	if err != nil {
		t.Fatal("configure the native service with exact-target PATCH denial and unchanged Bulk authority", err)
	}
	parent, err := service.Admit(f.ctx, request)
	if err != nil || parent.ChildCount != 1 {
		t.Fatal("Bulk authority must admit the structurally invalid literal PATCH", err)
	}
	original := originalStructuralBulkChild(t, f, parent, 0)
	wantPending := dependencyCutoffChild{status: "admitted", reason: "none"}
	if result, err := service.ExecuteChild(f.ctx, request, 0); protocolStatus(err) != 403 || result != (scim.BulkChildResult{}) {
		t.Fatal("missing data must not let Bulk authority bypass exact-target PATCH denial", result, err)
	}
	if state := readDependencyCutoffChild(t, f, parent, 0); state != wantPending {
		t.Fatal("denied child execution must leave the child unsettled without journal, audit or outbox effects", state)
	}
	if wire, err := service.ExecuteBulk(f.ctx, request); protocolStatus(err) != 403 || len(wire) != 0 {
		t.Fatal("synchronous execution must withhold the structural response without current PATCH authority", err)
	}
	if state := readDependencyCutoffChild(t, f, parent, 0); state != wantPending || projection() != before {
		t.Fatal("denied synchronous execution must preserve the original child and Group projection", state)
	}

	denyPatch = false
	wire, err := service.ExecuteBulk(f.ctx, request)
	if err != nil {
		t.Fatal("current PATCH authority must allow one durable structural denial", err)
	}
	var response struct {
		Schemas    []string
		Operations []map[string]json.RawMessage
	}
	if err := json.Unmarshal(wire, &response); err != nil || len(response.Schemas) != 1 ||
		response.Schemas[0] != "urn:ietf:params:scim:api:messages:2.0:BulkResponse" || len(response.Operations) != 1 {
		t.Fatal("return exactly one structural denial in a SCIM BulkResponse", err)
	}
	operation := response.Operations[0]
	var method, status, location string
	var denial struct {
		Schemas          []string
		Status, SCIMType string
	}
	if json.Unmarshal(operation["method"], &method) != nil || json.Unmarshal(operation["status"], &status) != nil ||
		json.Unmarshal(operation["location"], &location) != nil || json.Unmarshal(operation["response"], &denial) != nil ||
		method != "PATCH" || status != "400" || location != f.config.BaseURL+"/Groups/"+id ||
		denial.Status != "400" || denial.SCIMType != "invalidValue" || len(denial.Schemas) != 1 ||
		denial.Schemas[0] != "urn:ietf:params:scim:api:messages:2.0:Error" || len(operation) != 4 {
		t.Fatal("the literal structural denial must retain the exact Group Location and typed 400 without a version")
	}
	if _, exists := operation["version"]; exists {
		t.Fatal("a failed literal PATCH must not disclose a result version")
	}
	wantFailed := scim.BulkChildResult{Status: scim.BulkChildFailed, Code: 400, SCIMType: "invalidValue"}
	if result, err := service.ExecuteChild(f.ctx, request, 0); err != nil || result != wantFailed {
		t.Fatal("replay the original structural denial without executing the Group PATCH", result, err)
	}
	if replay, err := service.ReadResult(f.ctx, request); err != nil || !bytes.Equal(replay, wire) {
		t.Fatal("current PATCH authority must disclose the identical retained structural response", err)
	}
	wantSettled := dependencyCutoffChild{
		status: "failed", reason: "none", code: 400, failed: 1, receipts: 1,
		audits: 1, applyAudits: 1, boundApplyAudits: 1,
	}
	requireRetained := func() {
		t.Helper()
		if state := readDependencyCutoffChild(t, f, parent, 0); state != wantSettled ||
			originalStructuralBulkChild(t, f, parent, 0) != original || projection() != before {
			t.Fatal("retain exactly one original structural failure without changing the Group or creating child outbox effects", state)
		}
		var protectedFailures int
		err := f.pool.Raw().QueryRow(f.ctx, `SELECT count(*) FROM audit.records r
 JOIN audit.identity_command_bindings a ON a.event_id=r.record_id
 JOIN identity.commands c ON c.command_id=a.command_id
 WHERE r.correlation_id=$1 AND r.subject_id=$2 AND r.subject_type='scim_bulk_child'
  AND r.action='identity.scim.bulk_apply_child' AND r.outcome=$3 AND a.event_index=0
  AND c.command_id=decode(translate($2::text,'-_','+/')||'==','base64') AND c.state='aborted'
  AND convert_from(r.canonical_record,'UTF8')::jsonb#>>'{attributes,retention.class}'='protected'`,
			string(parent.CommandID), original.command, int16(audit.OutcomeDenied)).Scan(&protectedFailures)
		if err != nil || protectedFailures != 1 {
			t.Fatal("retain exactly one protected structural denial audit bound to its aborted child command", protectedFailures, err)
		}
	}
	requireRetained()

	denyPatch = true
	if result, err := service.ExecuteChild(f.ctx, request, 0); protocolStatus(err) != 403 || result != (scim.BulkChildResult{}) {
		t.Fatal("revoked exact-target PATCH authority must withhold the retained child result", result, err)
	}
	if replay, err := service.ReadResult(f.ctx, request); protocolStatus(err) != 403 || len(replay) != 0 {
		t.Fatal("revoked exact-target PATCH authority must withhold the retained wire response", err)
	}
	if replay, err := service.ExecuteBulk(f.ctx, request); protocolStatus(err) != 403 || len(replay) != 0 {
		t.Fatal("revoked exact-target PATCH authority must withhold synchronous terminal replay", err)
	}
	requireRetained()
}
