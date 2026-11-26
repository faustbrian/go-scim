//go:build integration

package scimpostgres

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"strconv"
	"sync/atomic"
	"testing"

	"github.com/faustbrian/go-audit"
	"github.com/faustbrian/go-authorization/v3"
	scim "github.com/faustbrian/go-scim"
)

const unsupportedMoveData = `{"schemas":["urn:ietf:params:scim:api:messages:2.0:PatchOp"],"Operations":[{"op":"replace","path":"displayName","value":"Must not apply"}]}`

func requireUnsupportedMovePlan(t *testing.T, request BulkAdmissionRequest, ordinal int, symbolic bool) {
	t.Helper()
	plan, err := scim.ParseBulk(request.Body, nil, scim.DefaultBulkPolicy(), scim.DefaultLimits())
	if err != nil {
		t.Fatal("unsupported MOVE must remain an admitted child error, not an envelope failure", err)
	}
	operations := plan.Operations()
	if ordinal >= len(operations) {
		t.Fatal("the original MOVE declaration is missing")
	}
	op := operations[ordinal]
	if op.Method != "MOVE" || op.Error == nil || op.Error.StatusCode() != 400 || op.Error.SCIMType() != "invalidValue" || op.Target.ResourceType == "" {
		t.Fatal("the usable target must not turn an unsupported method into a resource operation", op)
	}
	if symbolic {
		if op.Target.BulkID != "target" || op.Target.ResourceID != "" || len(op.Dependencies) != 1 || op.Dependencies[0] != 0 {
			t.Fatal("retain the original symbolic target and its real predecessor dependency", op)
		}
	} else if op.Target.ResourceID == "" || op.Target.BulkID != "" || len(op.Dependencies) != 0 {
		t.Fatal("the literal MOVE fixture must have a usable resource target without dependencies", op)
	}
}

func unsupportedMoveService(t *testing.T, f *nativeFixture) (*BulkService, *atomic.Bool, *atomic.Int64) {
	t.Helper()
	allowCreate := new(atomic.Bool)
	unrecognizedRequests := new(atomic.Int64)
	restricted := *f
	restricted.config.Authorization = configuredPolicy(func(ctx context.Context, decision authorization.DecisionContext) (authorization.Decision, error) {
		if decision.Request.Action == authorization.Action(scim.Bulk) {
			return f.config.Authorization.Decide(ctx, decision)
		}
		if decision.Request.Action == authorization.Action(scim.GroupCreate) &&
			decision.Request.Resource.Type == "identity.scim.group" && decision.Request.Resource.ID == "" {
			if allowCreate.Load() {
				return f.config.Authorization.Decide(ctx, decision)
			}
		} else {
			unrecognizedRequests.Add(1)
		}
		return authorization.Decision{Outcome: authorization.Deny, Revision: decision.PolicyRevision}, nil
	})
	service, err := NewBulkService(groupsOnPool(t, &restricted, f.pool), scim.DefaultBulkPolicy(), scim.DefaultBulkResponsePolicy())
	if err != nil {
		t.Fatal("configure Bulk-only authority with a separately grantable Group-create permission", err)
	}
	return service, allowCreate, unrecognizedRequests
}

func requireUnsupportedMoveWire(t *testing.T, wire []byte, count, ordinal, code int, kind, hiddenID string) {
	t.Helper()
	var response struct {
		Schemas    []string
		Operations []map[string]json.RawMessage
	}
	if err := json.Unmarshal(wire, &response); err != nil || len(response.Schemas) != 1 ||
		response.Schemas[0] != "urn:ietf:params:scim:api:messages:2.0:BulkResponse" || len(response.Operations) != count {
		t.Fatal("return exactly the processed declarations in the terminal BulkResponse", err)
	}
	op := response.Operations[ordinal]
	var method, status string
	var failure struct {
		Schemas          []string
		Status, SCIMType string
	}
	if json.Unmarshal(op["method"], &method) != nil || json.Unmarshal(op["status"], &status) != nil ||
		json.Unmarshal(op["response"], &failure) != nil || method != "MOVE" || status != strconv.Itoa(code) ||
		failure.Status != status || failure.SCIMType != kind || len(failure.Schemas) != 1 ||
		failure.Schemas[0] != "urn:ietf:params:scim:api:messages:2.0:Error" || len(op) != 3 {
		t.Fatal("retain the original MOVE and typed failure without Location, version or fabricated bulkId")
	}
	for _, field := range []string{"location", "version", "bulkId"} {
		if _, exists := op[field]; exists {
			t.Fatal("unsupported MOVE must not disclose resource metadata", field)
		}
	}
	encoded, err := json.Marshal(op)
	if err != nil || hiddenID != "" && bytes.Contains(encoded, []byte(hiddenID)) {
		t.Fatal("the MOVE result must not reveal the target or predecessor allocation", err)
	}
}

func requireUnsupportedMoveAudit(t *testing.T, f *nativeFixture, parent BulkAdmission, original admittedBulkChild) {
	t.Helper()
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
		t.Fatal("retain one protected denial audit bound to the original aborted MOVE command", protectedFailures, err)
	}
}

func TestBulkUnsupportedMethodLiteralTargetsNeedOnlyBulkAuthority(t *testing.T) {
	f, _, _ := mixedUserMutationFixture(t)
	userID := createNativeNamed(t, f, "unsupported-move-user", "Unchanged User")
	user := readMixedMutationUser(t, f, userID)
	groups := groupsOnPool(t, f, f.pool)
	group, err := groups.Execute(f.ctx, groupRequest(f, scim.GroupCreate, "", "", "unsupported-move-group", `{"schemas":["urn:ietf:params:scim:schemas:core:2.0:Group"],"displayName":"Unchanged Group"}`))
	if err != nil {
		t.Fatal("seed the usable literal Group target", err)
	}
	groupResourceID := groupID(t, group)
	request := mixedUserMutationRequest(t, f, []map[string]any{
		{"method": "MOVE", "path": "/Users/" + userID, "version": user.ETag, "data": json.RawMessage(unsupportedMoveData)},
		{"method": "MOVE", "path": "/Groups/" + groupResourceID, "version": group.ETag, "data": json.RawMessage(unsupportedMoveData)},
	})
	for ordinal := range 2 {
		requireUnsupportedMovePlan(t, request, ordinal, false)
	}
	service, _, unexpected := unsupportedMoveService(t, f)
	parent, err := service.Admit(f.ctx, request)
	if err != nil || parent.ChildCount != 2 {
		t.Fatal("Bulk authority alone must admit both original unsupported declarations", err)
	}
	originals := []admittedBulkChild{originalStructuralBulkChild(t, f, parent, 0), originalStructuralBulkChild(t, f, parent, 1)}
	for _, original := range originals {
		if original.resource != "" {
			t.Fatal("unsupported MOVE must not allocate a result resource")
		}
	}
	want := scim.BulkChildResult{Status: scim.BulkChildFailed, Code: 400, SCIMType: "invalidValue"}
	for ordinal := range originals {
		if result, err := service.ExecuteChild(f.ctx, request, ordinal); err != nil || result != want {
			t.Fatal("Bulk authority alone must durably fail the original MOVE without a pseudo resource action", ordinal, result, err)
		}
	}
	wire, err := service.ExecuteBulk(f.ctx, request)
	if err != nil {
		t.Fatal("Bulk authority alone must disclose the retained resource-free failures", err)
	}
	for ordinal, id := range []string{userID, groupResourceID} {
		requireUnsupportedMoveWire(t, wire, 2, ordinal, 400, "invalidValue", id)
	}
	wantState := dependencyCutoffChild{status: "failed", reason: "none", code: 400, failed: 2, receipts: 1, audits: 1, applyAudits: 1, boundApplyAudits: 1}
	for range 2 {
		for ordinal, original := range originals {
			if result, err := service.ExecuteChild(f.ctx, request, ordinal); err != nil || result != want {
				t.Fatal("replay the identical unsupported-method checkpoint", ordinal, result, err)
			}
			if originalStructuralBulkChild(t, f, parent, ordinal) != original || readDependencyCutoffChild(t, f, parent, ordinal) != wantState {
				t.Fatal("retain the original command and one denial without resource or outbox effects", ordinal)
			}
			requireUnsupportedMoveAudit(t, f, parent, original)
		}
		if replay, err := service.ReadResult(f.ctx, request); err != nil || !bytes.Equal(replay, wire) {
			t.Fatal("Bulk-only ReadResult must replay exact terminal bytes", err)
		}
		if replay, err := service.ExecuteBulk(f.ctx, request); err != nil || !bytes.Equal(replay, wire) {
			t.Fatal("Bulk-only synchronous replay must preserve exact terminal bytes", err)
		}
	}
	currentUser := readMixedMutationUser(t, f, userID)
	currentGroup, err := groups.Execute(f.ctx, groupRequest(f, scim.GroupGet, groupResourceID, "", "", ""))
	if err != nil || !bytes.Equal(currentUser.Body, user.Body) || currentUser.ETag != user.ETag ||
		!bytes.Equal(currentGroup.Body, group.Body) || currentGroup.ETag != group.ETag {
		t.Fatal("unsupported MOVE and replay must preserve both usable projections and versions", err)
	}
	if unexpected.Load() != 0 {
		t.Fatal("unsupported MOVE requested a resource or pseudo-target permission", unexpected.Load())
	}

	patchRequest := mixedUserMutationRequest(t, f, []map[string]any{{
		"method": "PATCH", "path": "/Groups/" + groupResourceID, "version": group.ETag, "data": json.RawMessage(unsupportedMoveData),
	}})
	patchParent, err := service.Admit(f.ctx, patchRequest)
	if err != nil || patchParent.ChildCount != 1 {
		t.Fatal("Bulk authority must still admit an ordinary declared PATCH", err)
	}
	if result, err := service.ExecuteChild(f.ctx, patchRequest, 0); protocolStatus(err) != 403 || result != (scim.BulkChildResult{}) {
		t.Fatal("recognizable PATCH must retain its current resource-authority requirement", result, err)
	}
	if wire, err := service.ExecuteBulk(f.ctx, patchRequest); protocolStatus(err) != 403 || len(wire) != 0 {
		t.Fatal("Bulk authority must not execute or disclose an ordinary denied PATCH", err)
	}
	if state := readDependencyCutoffChild(t, f, patchParent, 0); state != (dependencyCutoffChild{status: "admitted", reason: "none"}) || unexpected.Load() == 0 {
		t.Fatal("ordinary PATCH denial must request target authority and leave its child unsettled without effects", state)
	}
}

func TestBulkUnsupportedMethodSymbolicTargetRetainsDependencyAndCutoff(t *testing.T) {
	for _, scenario := range []struct {
		name             string
		predecessorFails bool
		separateCutoff   bool
		code, failures   int
		kind             string
	}{
		{name: "successful predecessor", code: 400, failures: 1, kind: "invalidValue"},
		{name: "failed predecessor after cutoff", predecessorFails: true, code: 424, failures: 2},
		{name: "successful predecessor after separate cutoff", separateCutoff: true, failures: 1},
	} {
		t.Run(scenario.name, func(t *testing.T) {
			f, _, _ := nativeBulkExecutionFixture(t)
			installBulkGroupMutationSchema(t, f)
			data := `{"schemas":["urn:ietf:params:scim:schemas:core:2.0:Group"],"displayName":"Unchanged target"}`
			if scenario.predecessorFails {
				data = `{"schemas":["urn:ietf:params:scim:schemas:core:2.0:Group"]}`
			}
			operations := []map[string]any{{"method": "POST", "path": "/Groups", "bulkId": "target", "data": json.RawMessage(data)}}
			if scenario.separateCutoff {
				operations = append(operations, map[string]any{"method": "POST", "path": "/Groups", "bulkId": "cutoff", "data": json.RawMessage(`{"schemas":["urn:ietf:params:scim:schemas:core:2.0:Group"]}`)})
			}
			moveOrdinal := len(operations)
			operations = append(operations, map[string]any{"method": "MOVE", "path": "/Groups/bulkId:target", "data": json.RawMessage(unsupportedMoveData)})
			cutoff := scenario.predecessorFails || scenario.separateCutoff
			threshold := 0
			if cutoff {
				threshold = 1
			}
			body, err := json.Marshal(map[string]any{"schemas": []string{"urn:ietf:params:scim:api:messages:2.0:BulkRequest"}, "failOnErrors": threshold, "Operations": operations})
			if err != nil {
				t.Fatal("encode the original symbolic MOVE and real predecessor", err)
			}
			request := BulkAdmissionRequest{Credential: f.bearer, Body: body}
			requireUnsupportedMovePlan(t, request, moveOrdinal, true)
			service, allowCreate, unexpected := unsupportedMoveService(t, f)
			parent, err := service.Admit(f.ctx, request)
			if err != nil || parent.ChildCount != len(operations) {
				t.Fatal("admit the complete graph without granting any resource action", err)
			}
			predecessor := originalBulkChild(t, f, parent, 0)
			move := originalStructuralBulkChild(t, f, parent, moveOrdinal)
			if move.resource != "" || move.command == predecessor.command {
				t.Fatal("retain an independent MOVE command without a resource allocation")
			}
			if result, err := service.ExecuteChild(f.ctx, request, moveOrdinal); protocolStatus(err) != 409 || result != (scim.BulkChildResult{}) {
				t.Fatal("Bulk-only symbolic MOVE must block before its real predecessor completes", result, err)
			}
			if state := readDependencyCutoffChild(t, f, parent, moveOrdinal); state != (dependencyCutoffChild{status: "dependency-blocked", reason: "none"}) {
				t.Fatal("blocking must not allocate a result or produce failure, audit or outbox effects", state)
			}
			if state := readDependencyCutoffChild(t, f, parent, 0); state != (dependencyCutoffChild{status: "admitted", reason: "none"}) {
				t.Fatal("selecting MOVE must not execute its predecessor", state)
			}
			if wire, err := service.ReadResult(f.ctx, request); !errors.Is(err, scim.ErrBulkIncomplete) || len(wire) != 0 {
				t.Fatal("the blocked graph must withhold any terminal response", err)
			}
			if result, err := service.ExecuteChild(f.ctx, request, 0); protocolStatus(err) != 403 || result != (scim.BulkChildResult{}) {
				t.Fatal("Bulk authority must not implicitly authorize the ordinary predecessor create", result, err)
			}
			allowCreate.Store(true)
			first, err := service.ExecuteChild(f.ctx, request, 0)
			if err != nil {
				t.Fatal("execute the real predecessor under separately granted Group-create authority", err)
			}
			if scenario.predecessorFails {
				if first != (scim.BulkChildResult{Status: scim.BulkChildFailed, Code: 400, SCIMType: "invalidValue"}) {
					t.Fatal("the real predecessor must fail typed Group validation", first)
				}
			} else {
				requireCommittedBulkChild(t, f, parent, 0, predecessor, first)
			}
			if scenario.separateCutoff {
				if result, err := service.ExecuteChild(f.ctx, request, 1); err != nil || result != (scim.BulkChildResult{Status: scim.BulkChildFailed, Code: 400, SCIMType: "invalidValue"}) {
					t.Fatal("activate cutoff with the independent typed Group failure", result, err)
				}
			}
			allowCreate.Store(false)
			want := scim.BulkChildResult{Status: scim.BulkChildFailed, Code: scenario.code, SCIMType: scenario.kind}
			wantState := dependencyCutoffChild{status: "failed", reason: "none", code: scenario.code, failed: scenario.failures, cutoff: cutoff, receipts: 1, audits: 1, applyAudits: 1, boundApplyAudits: 1}
			if scenario.separateCutoff {
				want = scim.BulkChildResult{Status: scim.BulkChildSkipped, SkipReason: scim.BulkSkipFailOnErrors}
				wantState = dependencyCutoffChild{status: "skipped", reason: "fail-on-errors", failed: 1, cutoff: true, audits: 1, skipAudits: 1, protectedSkipAudits: 1}
			}
			if result, err := service.ExecuteChild(f.ctx, request, moveOrdinal); err != nil || result != want {
				t.Fatal("Bulk-only MOVE must retain dependency failure, structural failure or cutoff skip without a target permission", result, err)
			}
			allowCreate.Store(true)
			wire, err := service.ExecuteBulk(f.ctx, request)
			if err != nil {
				t.Fatal("return the terminal graph under Bulk and separately granted predecessor authority", err)
			}
			if scenario.separateCutoff {
				var response struct{ Operations []map[string]json.RawMessage }
				if err := json.Unmarshal(wire, &response); err != nil || len(response.Operations) != 2 || bytes.Contains(wire, []byte(`"MOVE"`)) {
					t.Fatal("omit the unprocessed MOVE entirely after cutoff", err)
				}
			} else {
				requireUnsupportedMoveWire(t, wire, 2, moveOrdinal, scenario.code, scenario.kind, predecessor.resource)
			}
			for range 2 {
				allowCreate.Store(false)
				if result, err := service.ExecuteChild(f.ctx, request, moveOrdinal); err != nil || result != want {
					t.Fatal("Bulk authority alone must replay the original MOVE checkpoint", result, err)
				}
				allowCreate.Store(true)
				if replay, err := service.ReadResult(f.ctx, request); err != nil || !bytes.Equal(replay, wire) {
					t.Fatal("ReadResult must replay the exact retained graph bytes", err)
				}
				if replay, err := service.ExecuteBulk(f.ctx, request); err != nil || !bytes.Equal(replay, wire) {
					t.Fatal("synchronous replay must preserve exact graph bytes", err)
				}
				if originalBulkChild(t, f, parent, 0) != predecessor || originalStructuralBulkChild(t, f, parent, moveOrdinal) != move || readDependencyCutoffChild(t, f, parent, moveOrdinal) != wantState {
					t.Fatal("retain original allocations and exactly one MOVE outcome without resource or outbox effects")
				}
				if !scenario.separateCutoff {
					requireUnsupportedMoveAudit(t, f, parent, move)
				}
				if !scenario.predecessorFails {
					projection := requireCommittedBulkChild(t, f, parent, 0, predecessor, first)
					if projection.Attributes["displayName"] != "Unchanged target" {
						t.Fatal("MOVE and replay must not change the committed predecessor projection")
					}
				} else if state := readDependencyCutoffChild(t, f, parent, 0); state.groups != 0 || state.outbox != 0 || state.committed != 0 {
					t.Fatal("a failed predecessor and MOVE must not project an allocated Group", state)
				}
			}
			if unexpected.Load() != 0 {
				t.Fatal("symbolic MOVE requested a resource or pseudo-target permission", unexpected.Load())
			}
		})
	}
}
