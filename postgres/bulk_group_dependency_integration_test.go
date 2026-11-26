//go:build integration

package scimpostgres

import (
	"bytes"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	identity "github.com/faustbrian/go-identity"
	scim "github.com/faustbrian/go-scim"
)

func TestNativeGroupBulkDependencyResumesVersionedPatch(t *testing.T) {
	f, service := bulkChildExecutionFixture(t)
	installBulkGroupMutationSchema(t, f)
	groups := groupsOnPool(t, f, f.pool)
	seed, err := groups.Execute(f.ctx, groupRequest(f, scim.GroupCreate, "", "", "bulk-dependency-patch-target",
		`{"schemas":["urn:ietf:params:scim:schemas:core:2.0:Group"],"displayName":"Existing"}`))
	if err != nil {
		t.Fatal("create the versioned PATCH target", err)
	}
	target := groupID(t, seed)
	body, err := json.Marshal(map[string]any{
		"schemas": []string{"urn:ietf:params:scim:api:messages:2.0:BulkRequest"},
		"Operations": []map[string]any{
			{"method": "POST", "path": "/Groups", "bulkId": "new-member", "data": json.RawMessage(`{"schemas":["urn:ietf:params:scim:schemas:core:2.0:Group"],"displayName":"New member"}`)},
			{"method": "PATCH", "path": "/Groups/" + target, "version": seed.ETag, "data": json.RawMessage(`{"schemas":["urn:ietf:params:scim:api:messages:2.0:PatchOp"],"Operations":[{"op":"add","path":"members","value":[{"type":"Group","value":"bulkId:new-member"}]}]}`)},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	request := BulkAdmissionRequest{Credential: f.bearer, Body: body}
	parent, err := service.Admit(f.ctx, request)
	if err != nil {
		t.Fatal("admit a versioned dependent PATCH", err)
	}
	_, _ = service.ExecuteChild(f.ctx, request, 1)
	var state string
	var input []byte
	if err := f.pool.Raw().QueryRow(f.ctx, `SELECT status,group_mutation_input FROM scim.bulk_children WHERE parent_id=$1 AND ordinal=1`, string(parent.CommandID)).Scan(&state, &input); err != nil || state != "dependency-blocked" || input != nil {
		t.Fatal("a blocked PATCH must not prepare a resource snapshot", state, err)
	}
	if _, err := service.ExecuteChild(f.ctx, request, 0); err != nil {
		t.Fatal("create the predecessor Group", err)
	}
	patched, err := service.ExecuteChild(f.ctx, request, 1)
	if err != nil || patched.Status != scim.BulkChildSucceeded || patched.Code != 200 || patched.ResourceID != target || patched.Version == seed.ETag {
		t.Fatal("resume the original versioned PATCH after the dependency succeeds", patched, err)
	}
	if replay, err := service.ExecuteChild(f.ctx, request, 1); err != nil || replay != patched {
		t.Fatal("retain the versioned PATCH's original result on retry", replay, err)
	}
}

func TestNativeGroupBulkDependencyFailureCannotSkipEarlierIndependentComponent(t *testing.T) {
	f, service := bulkChildExecutionFixture(t)
	missing, err := identity.NewSubjectID()
	if err != nil {
		t.Fatal(err)
	}
	body := strings.Replace(dependentGroupBulkFixture, `"Operations":[`, `"failOnErrors":2,"Operations":[`, 1)
	body = strings.Replace(body, `"displayName":"First"}}`,
		`"displayName":"First","members":[{"type":"User","value":"`+string(missing)+`"}]}},
 {"method":"POST","path":"/Groups","bulkId":"independent","data":{"schemas":["urn:ietf:params:scim:schemas:core:2.0:Group"],"displayName":"Independent"}}`, 1)
	request := BulkAdmissionRequest{Credential: f.bearer, Body: []byte(body)}
	parent, err := service.Admit(f.ctx, request)
	if err != nil || parent.ChildCount != 3 {
		t.Fatal("admit failed predecessor, earlier independent component, and dependent", err)
	}
	if first, err := service.ExecuteChild(f.ctx, request, 0); err != nil || first.Code != 400 {
		t.Fatal("settle the first actual failure", first, err)
	}
	// The later dependent is known to fail, but counting it before its plan
	// position would incorrectly use the cutoff to skip the independent Group.
	if premature, err := service.ExecuteChild(f.ctx, request, 2); premature.Status == scim.BulkChildFailed || err == nil {
		t.Fatal("a known dependency failure must not count out of plan order", premature, err)
	}
	if independent, err := service.ExecuteChild(f.ctx, request, 1); err != nil || independent.Code != 201 {
		t.Fatal("the earlier independent component must still run", independent, err)
	}
	if dependent, err := service.ExecuteChild(f.ctx, request, 2); err != nil || dependent.Code != 424 || dependent.Status != scim.BulkChildFailed {
		t.Fatal("settle the dependency failure in its original plan position", dependent, err)
	}
	wire, err := service.ReadResult(f.ctx, request)
	if err != nil || !bytes.Contains(wire, []byte(`"bulkId":"independent"`)) {
		t.Fatal("terminal replay must include the earlier independent success", err)
	}
}

func TestNativeGroupBulkDependencyRetainsFailureAfterDefinitivePredecessorDenial(t *testing.T) {
	f, service := bulkChildExecutionFixture(t)
	missing, err := identity.NewSubjectID()
	if err != nil {
		t.Fatal(err)
	}
	body := strings.Replace(dependentGroupBulkFixture, `"displayName":"First"`,
		`"displayName":"First","members":[{"type":"User","value":"`+string(missing)+`"}]`, 1)
	request := BulkAdmissionRequest{Credential: f.bearer, Body: []byte(body)}
	parent, err := service.Admit(f.ctx, request)
	if err != nil || parent.ChildCount != 2 {
		t.Fatal("admit the predecessor and dependent Group", err)
	}
	if first, err := service.ExecuteChild(f.ctx, request, 0); err != nil || first.Status != scim.BulkChildFailed || first.Code != 400 {
		t.Fatal("predecessor must first be definitively denied", first, err)
	}
	want := scim.BulkChildResult{Status: scim.BulkChildFailed, Code: 424}
	for range 2 {
		if dependent, err := service.ExecuteChild(f.ctx, request, 1); err != nil || dependent != want {
			t.Fatal("dependent must retain its own 424 without executing a Group projection", dependent, err)
		}
	}
	wire, err := service.ReadResult(f.ctx, request)
	if err != nil || !bytes.Contains(wire, []byte(`"status":"424"`)) {
		t.Fatal("a known predecessor failure must eventually yield terminal wire results", err)
	}
	var failed, groups int
	if err := f.pool.Raw().QueryRow(f.ctx, `SELECT failed_count,(SELECT count(*) FROM scim.groups)
 FROM scim.bulk_requests WHERE parent_id=$1 AND NOT cutoff_active`, string(parent.CommandID)).Scan(&failed, &groups); err != nil || failed != 2 || groups != 0 {
		t.Fatal("count both processed failures once without committing a Group", failed, groups, err)
	}
}

func TestNativeGroupBulkDependencyBlocksWithoutCountingAndResumesAfterPredecessorSuccess(t *testing.T) {
	f, service := bulkChildExecutionFixture(t)
	request := BulkAdmissionRequest{Credential: f.bearer, Body: []byte(dependentGroupBulkFixture)}
	parent, err := service.Admit(f.ctx, request)
	if err != nil {
		t.Fatal("admit the graph before either child runs", err)
	}
	_, _ = service.ExecuteChild(f.ctx, request, 1)
	var state string
	var failed, groups int
	err = f.pool.Raw().QueryRow(f.ctx, `SELECT child.status,parent.failed_count,(SELECT count(*) FROM scim.groups)
 FROM scim.bulk_children child JOIN scim.bulk_requests parent USING(parent_id)
 WHERE parent.parent_id=$1 AND child.ordinal=1`, string(parent.CommandID)).Scan(&state, &failed, &groups)
	if err != nil || state != "dependency-blocked" || failed != 0 || groups != 0 {
		t.Fatal("an unresolved predecessor must retain a blocked dependent without counting or mutation", state, failed, groups, err)
	}
	if wire, err := service.ReadResult(f.ctx, request); !errors.Is(err, scim.ErrBulkIncomplete) || len(wire) != 0 {
		t.Fatal("a blocked dependency cannot expose a partial terminal response", err)
	}
	for ordinal := range 2 {
		if result, err := service.ExecuteChild(f.ctx, request, ordinal); err != nil || result.Status != scim.BulkChildSucceeded {
			t.Fatal("commit the predecessor, then its originally blocked dependent", ordinal, result, err)
		}
	}
	if wire, err := service.ReadResult(f.ctx, request); err != nil || bytes.Count(wire, []byte(`"status":"201"`)) != 2 {
		t.Fatal("resolved dependency must yield both original successes", err)
	}
}
