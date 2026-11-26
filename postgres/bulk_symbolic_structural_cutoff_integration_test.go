//go:build integration

package scimpostgres

import (
	"bytes"
	"testing"

	scim "github.com/faustbrian/go-scim"
)

func TestBulkSymbolicStructuralDenialRespectsCutoff(t *testing.T) {
	f, service := bulkChildExecutionFixture(t)
	const body = `{"schemas":["urn:ietf:params:scim:api:messages:2.0:BulkRequest"],"failOnErrors":1,"Operations":[` +
		`{"method":"POST","path":"/Groups","bulkId":"target","data":{"schemas":["urn:ietf:params:scim:schemas:core:2.0:Group"],"displayName":"Predecessor"}},` +
		`{"method":"POST","path":"/Groups","bulkId":"unrelated","data":{"schemas":["urn:ietf:params:scim:schemas:core:2.0:Group"]}},` +
		`{"method":"PATCH","path":"/Groups/bulkId:target"}]}`
	request := BulkAdmissionRequest{Credential: f.bearer, Body: []byte(body)}
	parent, err := service.Admit(f.ctx, request)
	if err != nil || parent.ChildCount != 3 {
		t.Fatal("admit the original graph", err)
	}
	if result, err := service.ExecuteChild(f.ctx, request, 2); protocolStatus(err) != 409 || result != (scim.BulkChildResult{}) {
		t.Fatal("unresolved dependency must block before evaluating the malformed PATCH", result, err)
	}
	requireDependencyCutoffBlocked(t, f, service, request, parent, 2, 0, false)
	if result, err := service.ExecuteChild(f.ctx, request, 0); err != nil || result.Status != scim.BulkChildSucceeded {
		t.Fatal("commit the original predecessor independently", result, err)
	}
	if result, err := service.ExecuteChild(f.ctx, request, 1); err != nil || result.Code != 400 {
		t.Fatal("activate the cutoff with a separate child failure", result, err)
	}
	want := scim.BulkChildResult{Status: scim.BulkChildSkipped, SkipReason: scim.BulkSkipFailOnErrors}
	if result, err := service.ExecuteChild(f.ctx, request, 2); err != nil || result != want {
		t.Fatal("an already-blocked child must skip after predecessor success and cutoff", result, err)
	}
	state := readDependencyCutoffChild(t, f, parent, 2)
	if state.status != "skipped" || state.reason != "fail-on-errors" || state.protectedSkipAudits != 1 ||
		state.applyAudits != 0 || state.committed != 0 || state.failed != 1 || !state.cutoff {
		t.Fatal("the original child must retain only its audited skip, not a denial or mutation", state)
	}
	wire, err := service.ReadResult(f.ctx, request)
	if err != nil || bytes.Contains(wire, []byte(`"method":"PATCH"`)) {
		t.Fatal("omit the unprocessed malformed child from the terminal response", err)
	}
}
