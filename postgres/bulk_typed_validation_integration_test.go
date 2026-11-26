//go:build integration

package scimpostgres

import (
	"bytes"
	"encoding/json"
	"fmt"
	"testing"

	migrations "github.com/faustbrian/go-migrations/v3"
	scim "github.com/faustbrian/go-scim"
)

func expandBulkTypedValidation(t *testing.T, f *nativeFixture, base migrations.Source) {
	t.Helper()
	history, err := (BulkTypedValidationMigrationSource{Base: base, Version: 46, ValidationVersion: 47}).Load(f.ctx)
	if err != nil {
		t.Fatal("load typed validation expansion", err)
	}
	if _, err := f.pool.Raw().Exec(f.ctx, history[len(history)-2].UpSQL()); err != nil {
		t.Fatal("expand Bulk before enabling typed validation", err)
	}
}

func TestNativeBulkExecuteRetainsTypedPrePrepareValidation(t *testing.T) {
	f, legacy, _ := nativeBulkExecutionFixture(t)
	oldRequest := BulkAdmissionRequest{Credential: f.bearer, Body: []byte(`{"schemas":["urn:ietf:params:scim:api:messages:2.0:BulkRequest"],"Operations":[` +
		`{"method":"POST","path":"/Groups","bulkId":"legacy","data":{"schemas":["urn:ietf:params:scim:schemas:core:2.0:Group"]}}]}`)}
	oldWire, err := legacy.ExecuteBulk(f.ctx, oldRequest)
	if err != nil {
		t.Fatal("retain a legacy Group validation result before schema expansion", err)
	}
	expandBulkTypedValidation(t, f, bulkTypedValidationTestBase())
	service := legacy.WithTypedValidation()
	if replay, err := service.ReadResult(f.ctx, oldRequest); err != nil || !bytes.Equal(replay, oldWire) {
		t.Fatal("the typed runtime must replay the untouched legacy receipt", err)
	}
	const next = `{"method":"POST","path":"/Groups","bulkId":"later","data":{"schemas":["urn:ietf:params:scim:schemas:core:2.0:Group"],"displayName":"Must not be created"}}`
	for _, tc := range []struct{ name, path, data, kind string }{
		{"User missing required name", "/Users", `{"schemas":["urn:ietf:params:scim:schemas:core:2.0:User"]}`, "invalidValue"},
		{"User supplies read-only ID", "/Users", `{"schemas":["urn:ietf:params:scim:schemas:core:2.0:User"],"userName":"rejected-user","id":"supplied"}`, "mutability"},
		{"Group supplies read-only ID", "/Groups", `{"schemas":["urn:ietf:params:scim:schemas:core:2.0:Group"],"displayName":"Rejected Group","id":"supplied"}`, "mutability"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			body := fmt.Sprintf(`{"schemas":["urn:ietf:params:scim:api:messages:2.0:BulkRequest"],"failOnErrors":1,"Operations":[{"method":"POST","path":%q,"bulkId":"typed","data":%s},%s]}`, tc.path, tc.data, next)
			request := BulkAdmissionRequest{Credential: f.bearer, Body: []byte(body)}
			want := scim.BulkChildResult{Status: scim.BulkChildFailed, Code: 400, SCIMType: tc.kind}
			result, err := service.ExecuteChild(f.ctx, request, 0)
			if err != nil || result != want {
				t.Fatalf("settle the original child with its exact SCIM type: got %+v, error status %d, err %v", result, protocolStatus(err), err)
			}
			wire, err := service.ExecuteBulk(f.ctx, request)
			if err != nil {
				t.Fatal("complete the original graph after the audited cutoff", err)
			}
			var response struct {
				Operations []struct {
					BulkID, Status, Location, Version string
					Response                          struct{ Status, SCIMType string }
				}
			}
			if err := json.Unmarshal(wire, &response); err != nil || len(response.Operations) != 1 {
				t.Fatal("return one failed child and omit the skipped successor", err)
			}
			op := response.Operations[0]
			if op.BulkID != "typed" || op.Status != "400" || op.Response.Status != "400" || op.Response.SCIMType != tc.kind || op.Location != "" || op.Version != "" {
				t.Fatalf("unexpected failed create response: %+v", op)
			}
			if replay, err := service.ReadResult(f.ctx, request); err != nil || !bytes.Equal(wire, replay) {
				t.Fatal("retained result must be identical to synchronous completion", err)
			}
			if replay, err := service.ExecuteChild(f.ctx, request, 0); err != nil || replay != want {
				t.Fatal("replay the exact typed child", replay, err)
			}
			if wire, err := legacy.ReadResult(f.ctx, request); protocolStatus(err) != 503 || len(wire) != 0 {
				t.Fatal("a legacy reader must not silently relabel a typed result", err)
			}
			parent, err := service.Admit(f.ctx, request)
			if err != nil {
				t.Fatal("observe the original graph", err)
			}
			wantFailed := dependencyCutoffChild{status: "failed", reason: "none", code: 400, failed: 1, cutoff: true, hasResource: true,
				receipts: 1, audits: 1, applyAudits: 1, boundApplyAudits: 1}
			wantSkipped := dependencyCutoffChild{status: "skipped", reason: "fail-on-errors", failed: 1, cutoff: true,
				audits: 1, skipAudits: 1, protectedSkipAudits: 1}
			if got := readDependencyCutoffChild(t, f, parent, 0); got != wantFailed {
				t.Fatalf("failure must be atomic with one audit and no write effects: %+v", got)
			}
			if got := readDependencyCutoffChild(t, f, parent, 1); got != wantSkipped {
				t.Fatalf("the skipped operation must leave only its protected skip audit: %+v", got)
			}
		})
	}
}

func TestNativeBulkExecuteRetainsTypedPrePrepareMutations(t *testing.T) {
	f, legacy, _ := mixedUserMutationFixture(t)
	expandBulkTypedValidation(t, f, BulkGroupMutationMigrationSource{Base: bulkTypedValidationTestBase(), Version: 45})
	service := legacy.WithTypedValidation()
	userID := createNativeNamed(t, f, "typed-validation-user", "Unchanged")
	user := readMixedMutationUser(t, f, userID)
	groups := groupsOnPool(t, f, f.pool)
	group, err := groups.Execute(f.ctx, groupRequest(f, scim.GroupCreate, "", "", "typed-validation-group", `{"schemas":["urn:ietf:params:scim:schemas:core:2.0:Group"],"displayName":"Unchanged"}`))
	if err != nil {
		t.Fatal("seed an unchanged Group target", err)
	}
	groupResourceID := groupID(t, group)
	userPath, groupPath := "/Users/"+userID, "/Groups/"+groupResourceID
	request := mixedUserMutationRequest(t, f, []map[string]any{
		{"method": "PUT", "path": userPath, "version": user.ETag, "data": map[string]any{
			"schemas": []string{"urn:ietf:params:scim:schemas:core:2.0:User"}, "userName": "typed-validation-user", "id": userID,
		}},
		{"method": "PATCH", "path": groupPath, "version": group.ETag, "data": map[string]any{
			"schemas":    []string{"urn:ietf:params:scim:api:messages:2.0:PatchOp"},
			"Operations": []map[string]any{{"op": "remove", "path": "displayName", "value": "not allowed on remove"}},
		}},
	})
	wire, err := service.ExecuteBulk(f.ctx, request)
	if err != nil {
		t.Fatal("settle the original PUT and PATCH errors as child results", protocolStatus(err), err)
	}
	var response struct {
		Operations []struct {
			Status, Location, Version string
			Response                  struct{ SCIMType string }
		}
	}
	if err := json.Unmarshal(wire, &response); err != nil || len(response.Operations) != 2 {
		t.Fatal("decode both ordered validation denials", err)
	}
	for i, kind := range []string{"mutability", "invalidValue"} {
		result := response.Operations[i]
		if result.Status != "400" || result.Location != f.config.BaseURL+[]string{userPath, groupPath}[i] || result.Version != "" || result.Response.SCIMType != kind {
			t.Fatalf("unexpected mutation denial at ordinal %d: %+v", i, result)
		}
	}
	if retained, err := service.ReadResult(f.ctx, request); err != nil || !bytes.Equal(wire, retained) {
		t.Fatal("replay retains the exact mutation types and authorized locations", err)
	}
	currentUser := readMixedMutationUser(t, f, userID)
	currentGroup, err := groups.Execute(f.ctx, groupRequest(f, scim.GroupGet, groupResourceID, "", "", ""))
	if err != nil || currentUser.ETag != user.ETag || currentGroup.ETag != group.ETag ||
		!bytes.Equal(currentUser.Body, user.Body) || !bytes.Equal(currentGroup.Body, group.Body) {
		t.Fatal("pre-Prepare denials must leave both resources unchanged", err)
	}
}
