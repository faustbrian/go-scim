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

func TestBulkSymbolicStructuralDenialWaitsForDependency(t *testing.T) {
	for _, scenario := range []struct {
		name        string
		predecessor string
		code        int
		scimType    string
		failures    int
		cutoff      int
	}{
		{
			name:        "successful predecessor retains structural denial",
			predecessor: `{"schemas":["urn:ietf:params:scim:schemas:core:2.0:Group"],"displayName":"Unchanged target"}`,
			code:        400,
			scimType:    "invalidValue",
			failures:    1,
		},
		{
			name:        "failed predecessor retains dependency failure",
			predecessor: `{"schemas":["urn:ietf:params:scim:schemas:core:2.0:Group"]}`,
			code:        424,
			failures:    2,
			cutoff:      1,
		},
	} {
		t.Run(scenario.name, func(t *testing.T) {
			f, service, runner := nativeBulkExecutionFixture(t)
			installBulkGroupMutationSchema(t, f)
			body, err := json.Marshal(map[string]any{
				"schemas":      []string{"urn:ietf:params:scim:api:messages:2.0:BulkRequest"},
				"failOnErrors": scenario.cutoff,
				"Operations": []map[string]any{
					{"method": "POST", "path": "/Groups", "bulkId": "target", "data": json.RawMessage(scenario.predecessor)},
					{"method": "PATCH", "path": "/Groups/bulkId:target"},
				},
			})
			if err != nil {
				t.Fatal("encode the symbolic PATCH without data and its typed Group predecessor", err)
			}
			request := BulkAdmissionRequest{Credential: f.bearer, Body: body}
			parent, err := service.Admit(f.ctx, request)
			if err != nil || parent.ChildCount != 2 {
				t.Fatal("admit both declarations without settling the structurally invalid dependent", err)
			}
			predecessor := originalBulkChild(t, f, parent, 0)
			dependent := originalStructuralBulkChild(t, f, parent, 1)
			if dependent.resource != "" || dependent.command == predecessor.command {
				t.Fatal("the symbolic PATCH must have its own command and no resource allocation")
			}

			if result, err := service.ExecuteChild(f.ctx, request, 1); protocolStatus(err) != 409 || result != (scim.BulkChildResult{}) {
				t.Fatal("missing data must not settle a symbolic PATCH before its admitted predecessor", result, err)
			}
			wantBlocked := dependencyCutoffChild{status: "dependency-blocked", reason: "none"}
			if state := readDependencyCutoffChild(t, f, parent, 1); state != wantBlocked {
				t.Fatal("persist only the dependency block without a result, failure count, journal, audit or outbox effects", state)
			}
			if state := readDependencyCutoffChild(t, f, parent, 0); state != (dependencyCutoffChild{status: "admitted", reason: "none"}) {
				t.Fatal("premature selection must not execute or change the predecessor", state)
			}
			if wire, err := service.ReadResult(f.ctx, request); !errors.Is(err, scim.ErrBulkIncomplete) || len(wire) != 0 {
				t.Fatal("a blocked structural denial must not disclose a partial terminal Bulk response", err)
			}

			first, err := service.ExecuteChild(f.ctx, request, 0)
			if err != nil {
				t.Fatal("settle the original Group predecessor", err)
			}
			if scenario.code == 400 {
				projection := requireCommittedBulkChild(t, f, parent, 0, predecessor, first)
				if projection.Attributes["displayName"] != "Unchanged target" {
					t.Fatal("create the intended symbolic PATCH target")
				}
			} else if first != (scim.BulkChildResult{Status: scim.BulkChildFailed, Code: 400, SCIMType: "invalidValue"}) {
				t.Fatal("the typed Group missing displayName must fail schema validation, not Bulk admission", first)
			}
			want := scim.BulkChildResult{Status: scim.BulkChildFailed, Code: scenario.code, SCIMType: scenario.scimType}
			if result, err := service.ExecuteChild(f.ctx, request, 1); err != nil || result != want {
				t.Fatal("the predecessor outcome must determine structural denial or failed dependency", result, err)
			}
			wantSettled := dependencyCutoffChild{
				status: "failed", reason: "none", code: scenario.code, failed: scenario.failures, cutoff: scenario.cutoff > 0, receipts: 1,
				audits: 1, applyAudits: 1, boundApplyAudits: 1,
			}
			if state := readDependencyCutoffChild(t, f, parent, 1); state != wantSettled {
				t.Fatal("settle exactly one protected dependent failure without a Group projection or outbox effect", state)
			}

			wire, err := runner.ExecuteBulk(f.ctx, request)
			if err != nil {
				t.Fatal("return both retained results as a complete synchronous Bulk response", err)
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
				t.Fatal("return exactly the original predecessor and dependent in a SCIM BulkResponse", err)
			}
			created, denied := response.Operations[0], response.Operations[1]
			if created.Method != "POST" || created.BulkID != "target" || created.Status != strconv.Itoa(first.Code) ||
				denied.Method != "PATCH" || denied.BulkID != "" || denied.Status != strconv.Itoa(scenario.code) ||
				denied.Location != f.config.BaseURL+"/Groups/"+predecessor.resource || denied.Version != "" ||
				denied.Response.Status != denied.Status || denied.Response.SCIMType != scenario.scimType ||
				len(denied.Response.Schemas) != 1 || denied.Response.Schemas[0] != "urn:ietf:params:scim:api:messages:2.0:Error" {
				t.Fatal("retain declaration order, typed dependent failure and the exact resolved Group Location without a version")
			}
			for range 2 {
				if result, err := service.ExecuteChild(f.ctx, request, 1); err != nil || result != want {
					t.Fatal("replay the original dependent failure without executing the PATCH", result, err)
				}
				if replay, err := runner.ExecuteBulk(f.ctx, request); err != nil || !bytes.Equal(replay, wire) {
					t.Fatal("synchronous replay must preserve the complete original response bytes", err)
				}
				if replay, err := service.ReadResult(f.ctx, request); err != nil || !bytes.Equal(replay, wire) {
					t.Fatal("result replay must preserve the complete original response bytes", err)
				}
				if originalBulkChild(t, f, parent, 0) != predecessor || originalStructuralBulkChild(t, f, parent, 1) != dependent ||
					readDependencyCutoffChild(t, f, parent, 1) != wantSettled {
					t.Fatal("replay must preserve both original allocations and exactly one dependent failure")
				}
				if scenario.code == 400 {
					projection := requireCommittedBulkChild(t, f, parent, 0, predecessor, first)
					if projection.Attributes["displayName"] != "Unchanged target" {
						t.Fatal("structural denial and replay must leave the created Group unchanged")
					}
				} else if state := readDependencyCutoffChild(t, f, parent, 0); state.groups != 0 || state.outbox != 0 || state.committed != 0 {
					t.Fatal("a failed predecessor and its dependency failure must not create a Group or outbox effect", state)
				}
			}
			restricted := *f
			restricted.config.Authorization = configuredPolicy(func(ctx context.Context, decision authorization.DecisionContext) (authorization.Decision, error) {
				if decision.Request.Action == authorization.Action(scim.GroupPatch) && decision.Request.Resource.Type == "identity.scim.group" &&
					string(decision.Request.Resource.ID) == predecessor.resource {
					return authorization.Decision{Outcome: authorization.Deny, Revision: decision.PolicyRevision}, nil
				}
				return f.config.Authorization.Decide(ctx, decision)
			})
			deniedService, err := NewBulkService(groupsOnPool(t, &restricted, f.pool), scim.DefaultBulkPolicy(), scim.DefaultBulkResponsePolicy())
			if err != nil {
				t.Fatal("retain Bulk access while revoking the resolved Group PATCH permission", err)
			}
			if replay, err := deniedService.ReadResult(f.ctx, request); protocolStatus(err) != 403 || len(replay) != 0 {
				t.Fatal("stored symbolic results must not disclose Location without current target permission", err)
			}
			if replay, err := deniedService.ExecuteBulk(f.ctx, request); protocolStatus(err) != 403 || len(replay) != 0 {
				t.Fatal("synchronous replay must not disclose Location without current target permission", err)
			}
		})
	}
}
