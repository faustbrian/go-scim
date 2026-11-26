//go:build integration

package scimpostgres

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	scim "github.com/faustbrian/go-scim"
)

const groupCycleDependencyCutoffFixture = `{"schemas":["urn:ietf:params:scim:api:messages:2.0:BulkRequest"],"failOnErrors":1,"Operations":[` +
	`{"method":"POST","path":"/Groups","bulkId":"prior","data":{"schemas":["urn:ietf:params:scim:schemas:core:2.0:Group"],"displayName":"Prior"}},` +
	`{"method":"POST","path":"/Groups","bulkId":"first","data":{"schemas":["urn:ietf:params:scim:schemas:core:2.0:Group"],"displayName":"First","members":[{"type":"Group","value":"bulkId:second"},{"type":"Group","value":"bulkId:prior"}]}},` +
	`{"method":"POST","path":"/Groups","bulkId":"second","data":{"schemas":["urn:ietf:params:scim:schemas:core:2.0:Group"],"displayName":"Second","members":[{"type":"Group","value":"bulkId:first"}]}}]}`

func TestNativeGroupBulkCycleDependencyCutoffSkipsBlockedComponentAfterPredecessorSuccess(t *testing.T) {
	for _, selected := range []int{2, 3} {
		t.Run(fmt.Sprintf("selected-ordinal-%d", selected), func(t *testing.T) {
			f, service := bulkChildExecutionFixture(t)
			const firstCycleOperation = `{"method":"POST","path":"/Groups","bulkId":"first"`
			const independentDenial = `{"method":"POST","path":"/Groups","bulkId":"unrelated-denial","data":{"schemas":["urn:ietf:params:scim:schemas:core:2.0:Group"],"displayName":"Denied","members":[{"type":"Group","value":"missing-group"}]}},`
			body := strings.Replace(groupCycleDependencyCutoffFixture, firstCycleOperation, independentDenial+firstCycleOperation, 1)
			request := BulkAdmissionRequest{Credential: f.bearer, Body: []byte(body)}
			parent, err := service.Admit(f.ctx, request)
			if err != nil || parent.ChildCount != 4 {
				t.Fatal("admit the predecessor, earlier independent denial and dependent two-Group cycle", err)
			}
			originals := [4]admittedBulkChild{
				originalBulkChild(t, f, parent, 0), originalBulkChild(t, f, parent, 1),
				originalBulkChild(t, f, parent, 2), originalBulkChild(t, f, parent, 3),
			}

			_, _ = service.ExecuteChild(f.ctx, request, selected)
			for _, ordinal := range []int{2, 3} {
				requireDependencyCutoffBlocked(t, f, service, request, parent, ordinal, 0, false)
			}
			created, err := service.ExecuteChild(f.ctx, request, 0)
			if err != nil {
				t.Fatal("commit the external predecessor before activating cutoff", err)
			}
			requireCommittedBulkChild(t, f, parent, 0, originals[0], created)
			for _, ordinal := range []int{2, 3} {
				requireDependencyCutoffBlocked(t, f, service, request, parent, ordinal, 0, false)
			}

			wantFailed := scim.BulkChildResult{Status: scim.BulkChildFailed, Code: 400, SCIMType: "invalidValue"}
			if result, err := service.ExecuteChild(f.ctx, request, 1); err != nil || result != wantFailed {
				t.Fatal("the earlier independent denial must activate cutoff", result, err)
			}
			for _, ordinal := range []int{2, 3} {
				requireDependencyCutoffBlocked(t, f, service, request, parent, ordinal, 1, true)
			}
			wantSkipped := scim.BulkChildResult{Status: scim.BulkChildSkipped, SkipReason: scim.BulkSkipFailOnErrors}
			if result, err := service.ExecuteChild(f.ctx, request, selected); err != nil || result != wantSkipped {
				t.Fatal("selecting either blocked cycle member after predecessor success must skip the component", result, err)
			}
			for _, ordinal := range []int{2, 3} {
				state := readDependencyCutoffChild(t, f, parent, ordinal)
				if state.status != "skipped" || state.reason != "fail-on-errors" || state.code != 0 || state.hasResource || state.hasVersion ||
					state.failed != 1 || !state.cutoff || state.groups != 0 || state.outbox != 0 || state.committed != 0 ||
					state.applyAudits != 0 || state.skipAudits != 1 || state.protectedSkipAudits != 1 || state.audits != 1 {
					t.Fatal("each skipped member must retain exactly its protected skip without wire or Group effects", ordinal, state)
				}
			}
			wire, err := service.ReadResult(f.ctx, request)
			if err != nil {
				t.Fatal("one selected member must settle both skips and make the response terminal", err)
			}
			var response struct {
				Operations []struct{ Method, BulkID, Status, Location, Version string }
			}
			if err := json.Unmarshal(wire, &response); err != nil || len(response.Operations) != 2 ||
				response.Operations[0].Method != "POST" || response.Operations[0].BulkID != "prior" || response.Operations[0].Status != "201" ||
				response.Operations[0].Location != f.config.BaseURL+"/Groups/"+originals[0].resource || response.Operations[0].Version != string(created.Version) ||
				response.Operations[1].Method != "POST" || response.Operations[1].BulkID != "unrelated-denial" || response.Operations[1].Status != "400" ||
				response.Operations[1].Location != "" || response.Operations[1].Version != "" {
				t.Fatal("terminal response must omit both unprocessed cycle members and preserve the earlier results", err)
			}
			for ordinal, original := range originals {
				if originalBulkChild(t, f, parent, ordinal) != original {
					t.Fatal("cutoff changed an original child command or resource allocation", ordinal)
				}
			}
			requireDependencyCutoffReplay(t, f, service, request, parent, wire, []scim.BulkChildResult{created, wantFailed, wantSkipped, wantSkipped})
			requireCommittedBulkChild(t, f, parent, 0, originals[0], created)
		})
	}
}

func TestNativeGroupBulkCycleDependencyCutoffRetainsBlockedComponentAfterPredecessorFailure(t *testing.T) {
	for _, selected := range []int{1, 2} {
		t.Run(fmt.Sprintf("selected-ordinal-%d", selected), func(t *testing.T) {
			f, service := bulkChildExecutionFixture(t)
			body := strings.Replace(groupCycleDependencyCutoffFixture, `"displayName":"Prior"`,
				`"displayName":"Prior","members":[{"type":"Group","value":"missing-group"}]`, 1)
			request := BulkAdmissionRequest{Credential: f.bearer, Body: []byte(body)}
			parent, err := service.Admit(f.ctx, request)
			if err != nil || parent.ChildCount != 3 {
				t.Fatal("admit the failing external predecessor and dependent two-Group cycle", err)
			}
			originals := [3]admittedBulkChild{
				originalBulkChild(t, f, parent, 0), originalBulkChild(t, f, parent, 1), originalBulkChild(t, f, parent, 2),
			}
			_, _ = service.ExecuteChild(f.ctx, request, selected)
			for _, ordinal := range []int{1, 2} {
				requireDependencyCutoffBlocked(t, f, service, request, parent, ordinal, 0, false)
			}
			wantFailed := scim.BulkChildResult{Status: scim.BulkChildFailed, Code: 400, SCIMType: "invalidValue"}
			if result, err := service.ExecuteChild(f.ctx, request, 0); err != nil || result != wantFailed {
				t.Fatal("the predecessor denial must activate cutoff without rewriting the blocked component", result, err)
			}
			for _, ordinal := range []int{1, 2} {
				requireDependencyCutoffBlocked(t, f, service, request, parent, ordinal, 1, true)
			}
			wantDependencyFailure := scim.BulkChildResult{Status: scim.BulkChildFailed, Code: 424}
			if result, err := service.ExecuteChild(f.ctx, request, selected); err != nil || result != wantDependencyFailure {
				t.Fatal("a failed predecessor must settle both blocked cycle members as failures despite cutoff", result, err)
			}
			for ordinal := range originals {
				wantCode := 424
				if ordinal == 0 {
					wantCode = 400
				}
				state := readDependencyCutoffChild(t, f, parent, ordinal)
				if state.status != "failed" || state.reason != "none" || state.code != wantCode || state.hasResource || state.hasVersion ||
					state.failed != 3 || !state.cutoff || state.groups != 0 || state.outbox != 0 || state.receipts != 1 || state.committed != 0 ||
					state.applyAudits != 1 || state.boundApplyAudits != 1 || state.skipAudits != 0 || state.audits != 1 {
					t.Fatal("each denial must be counted once with its original bound audit and without skip or Group effects", ordinal, state)
				}
			}
			wire, err := service.ReadResult(f.ctx, request)
			if err != nil {
				t.Fatal("one selected cycle member must retain both dependency failures and make the parent terminal", err)
			}
			var response struct {
				Operations []struct {
					Method, BulkID, Status, Location, Version string
					Response                                  struct{ Status, SCIMType, Detail string }
				}
			}
			if err := json.Unmarshal(wire, &response); err != nil || len(response.Operations) != 3 {
				t.Fatal("decode the predecessor denial and both processed cycle failures", err)
			}
			for ordinal, operation := range response.Operations {
				wantCode := []string{"400", "424", "424"}[ordinal]
				if operation.Method != "POST" || operation.BulkID != []string{"prior", "first", "second"}[ordinal] ||
					operation.Status != wantCode || operation.Response.Status != wantCode || operation.Location != "" || operation.Version != "" {
					t.Fatal("retained failures must preserve request order without provisional locations or versions", ordinal)
				}
				if ordinal == 0 && operation.Response.SCIMType != "invalidValue" ||
					ordinal != 0 && (operation.Response.SCIMType != "" || operation.Response.Detail != "Dependency failed") {
					t.Fatal("terminal response changed the original typed predecessor or cycle dependency denial", ordinal)
				}
				if originalBulkChild(t, f, parent, ordinal) != originals[ordinal] {
					t.Fatal("dependency failure changed an original command or resource allocation", ordinal)
				}
			}
			requireDependencyCutoffReplay(t, f, service, request, parent, wire, []scim.BulkChildResult{wantFailed, wantDependencyFailure, wantDependencyFailure})
			var aborted int
			err = f.pool.Raw().QueryRow(f.ctx, `SELECT count(*) FROM identity.commands c
 JOIN scim.bulk_children b ON c.command_id=decode(translate(b.command_id,'-_','+/')||'==','base64')
 WHERE b.parent_id=$1 AND c.state='aborted'`, string(parent.CommandID)).Scan(&aborted)
			if err != nil || aborted != 3 {
				t.Fatal("retries must retain exactly the three original denied child journals", aborted, err)
			}
		})
	}
}
