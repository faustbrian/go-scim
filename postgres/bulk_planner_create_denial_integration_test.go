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

func TestNativeBulkPlannerDenialRetainsMalformedCreateAndForwardDependency(t *testing.T) {
	f, _ := bulkChildExecutionFixture(t)
	expandBulkTypedValidation(t, f, bulkTypedValidationTestBase())
	for _, kind := range []string{"User", "Group"} {
		t.Run(kind, func(t *testing.T) {
			action := scim.UserCreate
			invalidCreate := map[string]any{"method": "POST", "path": "/" + kind + "s", "bulkId": "malformed"}
			if kind == "Group" {
				action = scim.GroupCreate
				invalidCreate["data"] = []string{"not a resource object"}
			} else {
				invalidCreate["version"] = `"not-a-create-precondition"`
			}
			denyCreate := false
			restricted := *f
			restricted.config.Authorization = configuredPolicy(func(ctx context.Context, decision authorization.DecisionContext) (authorization.Decision, error) {
				if denyCreate && decision.Request.Action == authorization.Action(action) && decision.Request.Resource.ID == "" {
					return authorization.Decision{Outcome: authorization.Deny, Revision: decision.PolicyRevision}, nil
				}
				return f.config.Authorization.Decide(ctx, decision)
			})
			legacy, err := NewBulkService(groupsOnPool(t, &restricted, f.pool), scim.DefaultBulkPolicy(), scim.DefaultBulkResponsePolicy())
			if err != nil {
				t.Fatal("select the configured mixed Bulk service", err)
			}
			service := legacy.WithTypedValidation()
			request := mixedUserMutationRequest(t, f, []map[string]any{
				{"method": "POST", "path": "/Groups", "bulkId": "dependent", "data": map[string]any{
					"schemas": []string{"urn:ietf:params:scim:schemas:core:2.0:Group"}, "displayName": "Do not create dependent",
					"members": []map[string]any{{"type": kind, "value": "bulkId:malformed"}},
				}},
				invalidCreate,
				{"method": "POST", "path": "/Groups", "bulkId": "independent", "data": map[string]any{
					"schemas": []string{"urn:ietf:params:scim:schemas:core:2.0:Group"}, "displayName": "Independent " + kind,
				}},
			})
			parent, err := service.Admit(f.ctx, request)
			if err != nil {
				t.Fatal("admit the entire malformed-create graph", err)
			}
			original := originalBulkChild(t, f, parent, 1)
			if result, err := service.ExecuteChild(f.ctx, request, 0); protocolStatus(err) != 409 || result != (scim.BulkChildResult{}) {
				t.Fatalf("dependent must wait on the original create, got %+v (%v)", result, err)
			}
			denyCreate = true
			if result, err := service.ExecuteChild(f.ctx, request, 1); protocolStatus(err) != 403 || result != (scim.BulkChildResult{}) {
				t.Fatalf("Bulk permission alone must not settle a known create: %+v (%v)", result, err)
			}
			if got := readDependencyCutoffChild(t, f, parent, 1); got != (dependencyCutoffChild{status: "admitted", reason: "none"}) {
				t.Fatalf("unauthorized settlement must leave the exact child untouched: %+v", got)
			}
			denyCreate = false
			want := scim.BulkChildResult{Status: scim.BulkChildFailed, Code: 400, SCIMType: "invalidValue"}
			if result, err := service.ExecuteChild(f.ctx, request, 1); err != nil || result != want {
				t.Fatalf("malformed create must retain a child 400 without exposing its allocation: %+v (%v)", result, err)
			}
			wire, err := service.ExecuteBulk(f.ctx, request)
			if err != nil {
				t.Fatal("retained create denial must not abort the remaining graph", err)
			}
			var response struct {
				Operations []struct {
					BulkID, Status, Location, Version string
					Response                          struct{ SCIMType string }
				}
			}
			if err := json.Unmarshal(wire, &response); err != nil || len(response.Operations) != 3 {
				t.Fatal("return all three results in declaration order", err)
			}
			dependent, denied, independent := response.Operations[0], response.Operations[1], response.Operations[2]
			if dependent.BulkID != "dependent" || dependent.Status != "424" || dependent.Location != "" || dependent.Version != "" ||
				denied.BulkID != "malformed" || denied.Status != "400" || denied.Location != "" || denied.Version != "" || denied.Response.SCIMType != "invalidValue" ||
				independent.BulkID != "independent" || independent.Status != "201" || independent.Location == "" || independent.Version == "" {
				t.Fatalf("unexpected original terminal operations: %+v", response.Operations)
			}
			if retained, err := service.ReadResult(f.ctx, request); err != nil || !bytes.Equal(retained, wire) {
				t.Fatal("terminal replay must keep the same error types, ordering and allocation visibility", err)
			}
			if got := readDependencyCutoffChild(t, f, parent, 1); got != (dependencyCutoffChild{status: "failed", reason: "none", code: 400, failed: 2, hasResource: true,
				receipts: 1, audits: 1, applyAudits: 1, boundApplyAudits: 1}) {
				t.Fatalf("retain one original protected denial with no projection or outbox effect: %+v", got)
			}
			if again := originalBulkChild(t, f, parent, 1); again != original {
				t.Fatal("retry must not reallocate the malformed create")
			}
			if bytes.Contains(wire, []byte(original.resource)) {
				t.Fatal("failed create and failed dependent operation must not expose a create allocation")
			}
		})
	}
}
