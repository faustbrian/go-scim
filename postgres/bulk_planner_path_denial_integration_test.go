//go:build integration

package scimpostgres

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"strconv"
	"testing"

	"github.com/faustbrian/go-authorization/v3"
	scim "github.com/faustbrian/go-scim"
)

const plannerInvalidPathPatch = `{"schemas":["urn:ietf:params:scim:api:messages:2.0:PatchOp"],"Operations":[{"op":"replace","path":"m29UnknownAttribute","value":"Must not apply"}]}`

func requirePlannerInvalidPath(t *testing.T, request BulkAdmissionRequest, ordinal int) {
	t.Helper()
	plan, err := scim.ParseBulk(request.Body, nil, scim.DefaultBulkPolicy(), scim.DefaultLimits())
	if err != nil {
		t.Fatal("the unknown declared PATCH path must remain a child planning error", err)
	}
	operations := plan.Operations()
	if ordinal >= len(operations) || operations[ordinal].Error == nil ||
		operations[ordinal].Error.StatusCode() != 400 || operations[ordinal].Error.SCIMType() != "invalidPath" {
		t.Fatal("the fixture must exercise planner-level 400 invalidPath", operations)
	}
}

func requirePlannerPathFailureWire(t *testing.T, wire []byte, count, ordinal, code int, kind, location string) {
	t.Helper()
	var response struct {
		Schemas    []string
		Operations []map[string]json.RawMessage
	}
	if err := json.Unmarshal(wire, &response); err != nil || len(response.Schemas) != 1 ||
		response.Schemas[0] != "urn:ietf:params:scim:api:messages:2.0:BulkResponse" || len(response.Operations) != count {
		t.Fatal("return the complete ordered SCIM BulkResponse", err)
	}
	operation := response.Operations[ordinal]
	var method, status, actualLocation string
	var denial struct {
		Schemas          []string
		Status, SCIMType string
	}
	if json.Unmarshal(operation["method"], &method) != nil || json.Unmarshal(operation["status"], &status) != nil ||
		json.Unmarshal(operation["location"], &actualLocation) != nil || json.Unmarshal(operation["response"], &denial) != nil ||
		method != "PATCH" || status != strconv.Itoa(code) || actualLocation != location ||
		denial.Status != status || denial.SCIMType != kind || len(denial.Schemas) != 1 ||
		denial.Schemas[0] != "urn:ietf:params:scim:api:messages:2.0:Error" || len(operation) != 4 {
		t.Fatal("retain the exact PATCH failure type and authorized Location without a result version")
	}
}

func TestNativeBulkPlannerPathDenialRequiresCurrentTargetAuthority(t *testing.T) {
	for _, resourceType := range []string{"User", "Group"} {
		t.Run(resourceType, func(t *testing.T) {
			f, _, _ := mixedUserMutationFixture(t)
			expandBulkTypedValidation(t, f, BulkGroupMutationMigrationSource{Base: bulkTypedValidationTestBase(), Version: 45})
			groups := groupsOnPool(t, f, f.pool)
			var seed scim.Response
			var id, path, targetType string
			action := scim.UserPatch
			if resourceType == "User" {
				id = createNativeNamed(t, f, "planner-path-user", "Unchanged target")
				seed = readMixedMutationUser(t, f, id)
				path, targetType = "/Users/"+id, "identity.scim.user"
			} else {
				var err error
				seed, err = groups.Execute(f.ctx, groupRequest(f, scim.GroupCreate, "", "", "planner-path-group", `{"schemas":["urn:ietf:params:scim:schemas:core:2.0:Group"],"displayName":"Unchanged target"}`))
				if err != nil {
					t.Fatal("seed the literal Group PATCH target", err)
				}
				id = groupID(t, seed)
				path, targetType, action = "/Groups/"+id, "identity.scim.group", scim.GroupPatch
			}
			request := mixedUserMutationRequest(t, f, []map[string]any{{
				"method": "PATCH", "path": path, "version": seed.ETag, "data": json.RawMessage(plannerInvalidPathPatch),
			}})
			requirePlannerInvalidPath(t, request, 0)
			denyPatch := true
			restricted := *f
			restricted.config.Authorization = configuredPolicy(func(ctx context.Context, decision authorization.DecisionContext) (authorization.Decision, error) {
				if denyPatch && decision.Request.Action == authorization.Action(action) &&
					decision.Request.Resource.Type == authorization.ResourceType(targetType) && string(decision.Request.Resource.ID) == id {
					return authorization.Decision{Outcome: authorization.Deny, Revision: decision.PolicyRevision}, nil
				}
				return f.config.Authorization.Decide(ctx, decision)
			})
			service, err := NewBulkService(groupsOnPool(t, &restricted, f.pool), scim.DefaultBulkPolicy(), scim.DefaultBulkResponsePolicy())
			if err != nil {
				t.Fatal("retain Bulk authority while denying the exact PATCH target", err)
			}
			service = service.WithTypedValidation()
			parent, err := service.Admit(f.ctx, request)
			if err != nil || parent.ChildCount != 1 {
				t.Fatal("admit the planner-invalid literal PATCH without settling it", err)
			}
			original := originalStructuralBulkChild(t, f, parent, 0)
			if result, err := service.ExecuteChild(f.ctx, request, 0); protocolStatus(err) != 403 || result != (scim.BulkChildResult{}) {
				t.Fatal("planner invalidPath must not bypass current exact-target PATCH authority", result, err)
			}
			if wire, err := service.ExecuteBulk(f.ctx, request); protocolStatus(err) != 403 || len(wire) != 0 {
				t.Fatal("unauthorized execution must withhold the whole Bulk response", err)
			}
			if state := readDependencyCutoffChild(t, f, parent, 0); state != (dependencyCutoffChild{status: "admitted", reason: "none"}) {
				t.Fatal("denial must not settle the child or create journal, audit or outbox effects", state)
			}

			denyPatch = false
			wire, err := service.ExecuteBulk(f.ctx, request)
			if err != nil {
				t.Fatal("authorized native execution must retain planner invalidPath, not reject the parent", err)
			}
			requirePlannerPathFailureWire(t, wire, 1, 0, 400, "invalidPath", f.config.BaseURL+path)
			want := scim.BulkChildResult{Status: scim.BulkChildFailed, Code: 400, SCIMType: "invalidPath"}
			if result, err := service.ExecuteChild(f.ctx, request, 0); err != nil || result != want {
				t.Fatal("replay the retained planner failure exactly", result, err)
			}
			for range 2 {
				if replay, err := service.ExecuteBulk(f.ctx, request); err != nil || !bytes.Equal(replay, wire) {
					t.Fatal("synchronous replay must retain the original whole-response bytes", err)
				}
				if replay, err := service.ReadResult(f.ctx, request); err != nil || !bytes.Equal(replay, wire) {
					t.Fatal("result replay must retain the original whole-response bytes", err)
				}
			}
			wantSettled := dependencyCutoffChild{status: "failed", reason: "none", code: 400, failed: 1, hasResource: true, receipts: 1,
				audits: 1, applyAudits: 1, boundApplyAudits: 1}
			requireUnchanged := func() {
				t.Helper()
				if originalStructuralBulkChild(t, f, parent, 0) != original || readDependencyCutoffChild(t, f, parent, 0) != wantSettled {
					t.Fatal("retain the original child and exactly one failure without mutation effects")
				}
				var actual scim.Response
				if resourceType == "User" {
					actual = readMixedMutationUser(t, f, id)
				} else {
					var err error
					actual, err = groups.Execute(f.ctx, groupRequest(f, scim.GroupGet, id, "", "", ""))
					if err != nil {
						t.Fatal("read the original Group after denied PATCH", err)
					}
				}
				if actual.ETag != seed.ETag || !bytes.Equal(actual.Body, seed.Body) {
					t.Fatal("planner denial must preserve the target body and version")
				}
			}
			requireUnchanged()
			denyPatch = true
			if result, err := service.ExecuteChild(f.ctx, request, 0); protocolStatus(err) != 403 || result != (scim.BulkChildResult{}) {
				t.Fatal("revoked target permission must withhold the retained child", result, err)
			}
			if replay, err := service.ReadResult(f.ctx, request); protocolStatus(err) != 403 || len(replay) != 0 {
				t.Fatal("revoked target permission must withhold retained whole-response bytes", err)
			}
			if replay, err := service.ExecuteBulk(f.ctx, request); protocolStatus(err) != 403 || len(replay) != 0 {
				t.Fatal("revoked target permission must withhold synchronous whole-response replay", err)
			}
			requireUnchanged()
		})
	}
}

func TestNativeBulkSymbolicPlannerPathDenialWaitsForDependency(t *testing.T) {
	for _, scenario := range []struct {
		name, predecessor, kind string
		code, failures, cutoff  int
	}{
		{"successful predecessor", `{"schemas":["urn:ietf:params:scim:schemas:core:2.0:Group"],"displayName":"Unchanged target"}`, "invalidPath", 400, 1, 0},
		{"failed predecessor with cutoff", `{"schemas":["urn:ietf:params:scim:schemas:core:2.0:Group"]}`, "", 424, 2, 1},
	} {
		t.Run(scenario.name, func(t *testing.T) {
			f, legacy, _ := mixedUserMutationFixture(t)
			expandBulkTypedValidation(t, f, BulkGroupMutationMigrationSource{Base: bulkTypedValidationTestBase(), Version: 45})
			service := legacy.WithTypedValidation()
			body, err := json.Marshal(map[string]any{
				"schemas":      []string{"urn:ietf:params:scim:api:messages:2.0:BulkRequest"},
				"failOnErrors": scenario.cutoff,
				"Operations": []map[string]any{
					{"method": "POST", "path": "/Groups", "bulkId": "target", "data": json.RawMessage(scenario.predecessor)},
					{"method": "PATCH", "path": "/Groups/bulkId:target", "data": json.RawMessage(plannerInvalidPathPatch)},
				},
			})
			if err != nil {
				t.Fatal("encode the invalidPath child with its real Group predecessor and cutoff", err)
			}
			request := BulkAdmissionRequest{Credential: f.bearer, Body: body}
			requirePlannerInvalidPath(t, request, 1)
			parent, err := service.Admit(f.ctx, request)
			if err != nil || parent.ChildCount != 2 {
				t.Fatal("admit the invalidPath child and its Group predecessor", err)
			}
			predecessor := originalBulkChild(t, f, parent, 0)
			dependent := originalStructuralBulkChild(t, f, parent, 1)
			if result, err := service.ExecuteChild(f.ctx, request, 1); protocolStatus(err) != 409 || result != (scim.BulkChildResult{}) {
				t.Fatal("planner invalidPath must wait for its symbolic target predecessor", result, err)
			}
			if state := readDependencyCutoffChild(t, f, parent, 1); state != (dependencyCutoffChild{status: "dependency-blocked", reason: "none"}) {
				t.Fatal("pending dependency must have no result, journal, audit or mutation effects", state)
			}
			if wire, err := service.ReadResult(f.ctx, request); !errors.Is(err, scim.ErrBulkIncomplete) || len(wire) != 0 {
				t.Fatal("the pending symbolic target must withhold a partial Bulk response", err)
			}
			first, err := service.ExecuteChild(f.ctx, request, 0)
			if err != nil {
				t.Fatal("execute the real Group predecessor", err)
			}
			if scenario.code == 400 {
				requireCommittedBulkChild(t, f, parent, 0, predecessor, first)
			} else if first != (scim.BulkChildResult{Status: scim.BulkChildFailed, Code: 400, SCIMType: "invalidValue"}) {
				t.Fatal("missing required displayName must be a real predecessor validation failure", first)
			}
			want := scim.BulkChildResult{Status: scim.BulkChildFailed, Code: scenario.code, SCIMType: scenario.kind}
			if result, err := service.ExecuteChild(f.ctx, request, 1); err != nil || result != want {
				t.Fatal("retain invalidPath after success, but preserve failed-dependency precedence after cutoff", result, err)
			}
			wire, err := service.ExecuteBulk(f.ctx, request)
			if err != nil {
				t.Fatal("complete the original symbolic Bulk response", err)
			}
			requirePlannerPathFailureWire(t, wire, 2, 1, scenario.code, scenario.kind, f.config.BaseURL+"/Groups/"+predecessor.resource)
			wantSettled := dependencyCutoffChild{status: "failed", reason: "none", code: scenario.code, failed: scenario.failures, hasResource: scenario.code == 400,
				cutoff: scenario.cutoff > 0, receipts: 1, audits: 1, applyAudits: 1, boundApplyAudits: 1}
			for range 2 {
				if result, err := service.ExecuteChild(f.ctx, request, 1); err != nil || result != want {
					t.Fatal("replay the original symbolic failure", result, err)
				}
				if replay, err := service.ExecuteBulk(f.ctx, request); err != nil || !bytes.Equal(replay, wire) {
					t.Fatal("symbolic replay must retain the exact complete response bytes", err)
				}
				if originalBulkChild(t, f, parent, 0) != predecessor || originalStructuralBulkChild(t, f, parent, 1) != dependent ||
					readDependencyCutoffChild(t, f, parent, 1) != wantSettled {
					t.Fatal("retain original allocations and exactly one dependent failure without mutation effects")
				}
				if scenario.code == 400 {
					projection := requireCommittedBulkChild(t, f, parent, 0, predecessor, first)
					if projection.Attributes["displayName"] != "Unchanged target" {
						t.Fatal("the invalid PATCH must not change its resolved Group target")
					}
				} else if state := readDependencyCutoffChild(t, f, parent, 0); state.groups != 0 || state.outbox != 0 || state.committed != 0 {
					t.Fatal("the failed predecessor must not create a Group or outbox effect", state)
				}
			}
		})
	}
}
