//go:build integration

package scimpostgres

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/faustbrian/go-audit"
	identity "github.com/faustbrian/go-identity"
	scim "github.com/faustbrian/go-scim"
)

const externallyDependentGroupCycleFixture = `{"schemas":["urn:ietf:params:scim:api:messages:2.0:BulkRequest"],"Operations":[` +
	`{"method":"POST","path":"/Groups","bulkId":"prior","data":{"schemas":["urn:ietf:params:scim:schemas:core:2.0:Group"],"displayName":"Prior"}},` +
	`{"method":"POST","path":"/Groups","bulkId":"first","data":{"schemas":["urn:ietf:params:scim:schemas:core:2.0:Group"],"displayName":"First","members":[{"type":"Group","value":"bulkId:second"},{"type":"Group","value":"bulkId:prior"}]}},` +
	`{"method":"POST","path":"/Groups","bulkId":"second","data":{"schemas":["urn:ietf:params:scim:schemas:core:2.0:Group"],"displayName":"Second","members":[{"type":"Group","value":"bulkId:first"}]}}]}`

func TestNativeGroupBulkCycleExternalDependencyBlocksWholeComponentAndResumes(t *testing.T) {
	for _, selected := range []int{1, 2} {
		t.Run(fmt.Sprintf("selected-ordinal-%d", selected), func(t *testing.T) {
			f, service := bulkChildExecutionFixture(t)
			request := BulkAdmissionRequest{Credential: f.bearer, Body: []byte(externallyDependentGroupCycleFixture)}
			parent, err := service.Admit(f.ctx, request)
			if err != nil || parent.ChildCount != 3 {
				t.Fatal("admit the external predecessor and complete two-Group cycle", err)
			}
			originals := [3]admittedBulkChild{
				originalBulkChild(t, f, parent, 0),
				originalBulkChild(t, f, parent, 1),
				originalBulkChild(t, f, parent, 2),
			}

			_, _ = service.ExecuteChild(f.ctx, request, selected)
			requireExternallyBlockedGroupCycle(t, f, service, request, parent)
			_, _ = service.ExecuteChild(f.ctx, request, 3-selected)
			requireExternallyBlockedGroupCycle(t, f, service, request, parent)

			var results [3]scim.BulkChildResult
			results[0], err = service.ExecuteChild(f.ctx, request, 0)
			if err != nil {
				t.Fatal("settle the original external predecessor", err)
			}
			requireCommittedBulkChild(t, f, parent, 0, originals[0], results[0])
			if wire, err := service.ReadResult(f.ctx, request); !errors.Is(err, scim.ErrBulkIncomplete) || len(wire) != 0 {
				t.Fatal("the predecessor alone must not expose a terminal cycle response", err)
			}

			results[selected], err = service.ExecuteChild(f.ctx, request, selected)
			if err != nil || results[selected].Status != scim.BulkChildSucceeded {
				t.Fatal("selecting either originally blocked member must commit the complete cycle", results[selected], err)
			}
			var groups, completed, failed int
			err = f.pool.Raw().QueryRow(f.ctx, `SELECT
 (SELECT count(*) FROM scim.groups),
 (SELECT count(*) FROM scim.bulk_children WHERE parent_id=$1 AND status='succeeded'
  AND result_code=201 AND result_resource_id=resource_id AND result_version IS NOT NULL),
 (SELECT failed_count FROM scim.bulk_requests WHERE parent_id=$1 AND NOT cutoff_active)`, string(parent.CommandID)).Scan(&groups, &completed, &failed)
			if err != nil || groups != 3 || completed != 3 || failed != 0 {
				t.Fatal("one member selection must commit both original cycle projections and checkpoints without failures", groups, completed, failed, err)
			}
			wire, err := service.ReadResult(f.ctx, request)
			if err != nil {
				t.Fatal("the complete cycle must be terminal before its other member is selected", err)
			}
			other := 3 - selected
			results[other], err = service.ExecuteChild(f.ctx, request, other)
			if err != nil {
				t.Fatal("recover the other member's original successful checkpoint", err)
			}
			for ordinal, original := range originals {
				projection := requireCommittedBulkChild(t, f, parent, ordinal, original, results[ordinal])
				if projection.Attributes["displayName"] != []string{"Prior", "First", "Second"}[ordinal] {
					t.Fatal("resumed execution changed an original Group name", ordinal)
				}
				if ordinal == 1 {
					requireCycleGroupMembers(t, projection, originals[2].resource, originals[0].resource)
				} else if ordinal == 2 {
					requireCycleGroupMembers(t, projection, originals[1].resource)
				}
				if replay, err := service.ExecuteChild(f.ctx, request, ordinal); err != nil || replay != results[ordinal] {
					t.Fatal("replay changed an original child result after the cycle resumed", ordinal, err)
				}
				requireCommittedBulkChild(t, f, parent, ordinal, original, results[ordinal])
			}
			var response struct {
				Operations []struct{ Method, BulkID, Status, Location, Version string }
			}
			if err := json.Unmarshal(wire, &response); err != nil || len(response.Operations) != 3 {
				t.Fatal("decode the complete predecessor and cycle response", err)
			}
			for ordinal, operation := range response.Operations {
				if operation.Method != "POST" || operation.BulkID != []string{"prior", "first", "second"}[ordinal] || operation.Status != "201" ||
					operation.Location != f.config.BaseURL+"/Groups/"+originals[ordinal].resource || operation.Version != string(results[ordinal].Version) {
					t.Fatal("terminal response changed request order or an original location and version", ordinal)
				}
			}
			if replay, err := service.ReadResult(f.ctx, request); err != nil || !bytes.Equal(wire, replay) {
				t.Fatal("child replay changed the exact terminal response", err)
			}
			if err := f.pool.Raw().QueryRow(f.ctx, `SELECT count(*) FROM scim.groups`).Scan(&groups); err != nil || groups != 3 {
				t.Fatal("replaying the predecessor or either cycle member duplicated a Group projection", groups, err)
			}
		})
	}
}

func TestNativeGroupBulkCycleExternalDependencyFailureSettlesWholeComponent(t *testing.T) {
	for _, test := range []struct {
		name      string
		selected  int
		malformed bool
	}{
		{"selected-ordinal-1", 1, false},
		{"selected-ordinal-2", 2, false},
		{"malformed-sibling", 2, true},
	} {
		t.Run(test.name, func(t *testing.T) {
			selected := test.selected
			f, service := bulkChildExecutionFixture(t)
			missing, err := identity.NewSubjectID()
			if err != nil {
				t.Fatal(err)
			}
			body := strings.Replace(externallyDependentGroupCycleFixture, `"displayName":"Prior"`,
				`"displayName":"Prior","members":[{"type":"User","value":"`+string(missing)+`"}]`, 1)
			if test.malformed {
				body = strings.Replace(body, `"displayName":"First",`, "", 1)
			}
			request := BulkAdmissionRequest{Credential: f.bearer, Body: []byte(body)}
			parent, err := service.Admit(f.ctx, request)
			if err != nil || parent.ChildCount != 3 {
				t.Fatal("admit the invalid-member predecessor and complete dependent cycle", err)
			}
			originals := [3]admittedBulkChild{
				originalBulkChild(t, f, parent, 0),
				originalBulkChild(t, f, parent, 1),
				originalBulkChild(t, f, parent, 2),
			}
			_, _ = service.ExecuteChild(f.ctx, request, selected)
			requireExternallyBlockedGroupCycle(t, f, service, request, parent)
			wantPredecessor := scim.BulkChildResult{Status: scim.BulkChildFailed, Code: 400, SCIMType: "invalidValue"}
			if predecessor, err := service.ExecuteChild(f.ctx, request, 0); err != nil || predecessor != wantPredecessor {
				t.Fatal("first confirm and retain the predecessor's invalid-member denial", predecessor, err)
			}
			wantDependent := scim.BulkChildResult{Status: scim.BulkChildFailed, Code: 424}
			if dependent, err := service.ExecuteChild(f.ctx, request, selected); err != nil || dependent != wantDependent {
				t.Fatal("the confirmed external denial must settle either selected cycle member as a dependency failure", dependent, err)
			}
			wire, err := service.ReadResult(f.ctx, request)
			if err != nil {
				t.Fatal("settling either member must retain both failures and make the parent terminal", err)
			}
			for range 2 {
				for _, ordinal := range []int{3 - selected, selected, 0} {
					want := wantDependent
					if ordinal == 0 {
						want = wantPredecessor
					}
					if replay, err := service.ExecuteChild(f.ctx, request, ordinal); err != nil || replay != want {
						t.Fatal("replay must return the original typed predecessor or cycle failure", ordinal, replay, err)
					}
				}
			}
			var failed, settled, groups, committed, aborted, outbox, denialAudits int
			err = f.pool.Raw().QueryRow(f.ctx, `SELECT
 (SELECT failed_count FROM scim.bulk_requests WHERE parent_id=$1 AND NOT cutoff_active),
 (SELECT count(*) FROM scim.bulk_children WHERE parent_id=$1 AND status='failed' AND skip_reason='none'
  AND result_resource_id IS NULL AND result_version IS NULL
  AND (ordinal=0 AND result_code=400 OR ordinal IN (1,2) AND result_code=424)),
 (SELECT count(*) FROM scim.groups),
 (SELECT count(*) FROM identity.commands c JOIN scim.bulk_children b ON c.command_id=decode(translate(b.command_id,'-_','+/')||'==','base64') WHERE b.parent_id=$1 AND c.state='committed'),
 (SELECT count(*) FROM identity.commands c JOIN scim.bulk_children b ON c.command_id=decode(translate(b.command_id,'-_','+/')||'==','base64') WHERE b.parent_id=$1 AND c.state='aborted'),
 (SELECT count(*) FROM public.identity_outbox_bindings o JOIN scim.bulk_children b ON o.command_id=decode(translate(b.command_id,'-_','+/')||'==','base64') WHERE b.parent_id=$1),
 (SELECT count(*) FROM audit.identity_command_bindings a JOIN audit.records r ON r.record_id=a.event_id
  JOIN scim.bulk_children b ON a.command_id=decode(translate(b.command_id,'-_','+/')||'==','base64')
  WHERE b.parent_id=$1 AND r.action='identity.scim.bulk_apply_child' AND r.outcome<>$2)`, string(parent.CommandID), int16(audit.OutcomeSucceeded)).Scan(&failed, &settled, &groups, &committed, &aborted, &outbox, &denialAudits)
			if err != nil || failed != 3 || settled != 3 || groups != 0 || committed != 0 || aborted != 3 || outbox != 0 || denialAudits != 3 {
				t.Fatal("the predecessor and both cycle failures must count once without provisional results or successful effects", failed, settled, groups, committed, aborted, outbox, denialAudits, err)
			}
			for ordinal, original := range originals {
				if retained := originalBulkChild(t, f, parent, ordinal); retained != original {
					t.Fatal("external dependency failure changed an original child command or resource allocation", ordinal)
				}
			}
			var response struct {
				Operations []struct {
					Method, BulkID, Status, Location, Version string
					Response                                  struct{ Status, SCIMType, Detail string }
				}
			}
			if err := json.Unmarshal(wire, &response); err != nil || len(response.Operations) != 3 {
				t.Fatal("decode all three retained failure results", err)
			}
			for ordinal, operation := range response.Operations {
				wantCode := []string{"400", "424", "424"}[ordinal]
				if operation.Method != "POST" || operation.BulkID != []string{"prior", "first", "second"}[ordinal] || operation.Status != wantCode ||
					operation.Location != "" || operation.Version != "" || operation.Response.Status != wantCode {
					t.Fatal("terminal failures must preserve request order without provisional locations or versions", ordinal)
				}
				if ordinal == 0 {
					if operation.Response.SCIMType != "invalidValue" {
						t.Fatal("terminal response changed the typed predecessor denial")
					}
				} else if operation.Response.SCIMType != "" || operation.Response.Detail != "Dependency failed" {
					t.Fatal("terminal response changed a retained cycle dependency error", ordinal)
				}
			}
			if replay, err := service.ReadResult(f.ctx, request); err != nil || !bytes.Equal(wire, replay) {
				t.Fatal("failure replay must preserve the exact terminal response", err)
			}
		})
	}
}

func requireExternallyBlockedGroupCycle(t *testing.T, f *nativeFixture, service *GroupBulkService, request BulkAdmissionRequest, parent BulkAdmission) {
	t.Helper()
	var blocked, predecessor, failed, groups, committed, outbox, applied int
	err := f.pool.Raw().QueryRow(f.ctx, `SELECT
 (SELECT count(*) FROM scim.bulk_children WHERE parent_id=$1 AND ordinal IN (1,2)
  AND status='dependency-blocked' AND skip_reason='none' AND result_code IS NULL AND result_resource_id IS NULL AND result_version IS NULL),
 (SELECT count(*) FROM scim.bulk_children WHERE parent_id=$1 AND ordinal=0 AND status='admitted'),
 (SELECT failed_count FROM scim.bulk_requests WHERE parent_id=$1 AND NOT cutoff_active),
 (SELECT count(*) FROM scim.groups),
 (SELECT count(*) FROM identity.commands c JOIN scim.bulk_children b ON c.command_id=decode(translate(b.command_id,'-_','+/')||'==','base64') WHERE b.parent_id=$1 AND c.state='committed'),
 (SELECT count(*) FROM public.identity_outbox_bindings o JOIN scim.bulk_children b ON o.command_id=decode(translate(b.command_id,'-_','+/')||'==','base64') WHERE b.parent_id=$1),
 (SELECT count(*) FROM audit.identity_command_bindings a JOIN audit.records r ON r.record_id=a.event_id
  JOIN scim.bulk_children b ON a.command_id=decode(translate(b.command_id,'-_','+/')||'==','base64')
  WHERE b.parent_id=$1 AND r.action='identity.scim.bulk_apply_child')`, string(parent.CommandID)).Scan(&blocked, &predecessor, &failed, &groups, &committed, &outbox, &applied)
	if err != nil || blocked != 2 || predecessor != 1 || failed != 0 || groups != 0 || committed != 0 || outbox != 0 || applied != 0 {
		t.Fatal("an unresolved external predecessor must durably block both cycle members without failure, projection or child effects", blocked, predecessor, failed, groups, committed, outbox, applied, err)
	}
	if wire, err := service.ReadResult(f.ctx, request); !errors.Is(err, scim.ErrBulkIncomplete) || len(wire) != 0 {
		t.Fatal("a blocked cycle must withhold every terminal response byte", err)
	}
}

func requireCycleGroupMembers(t *testing.T, projection scim.Resource, expected ...string) {
	t.Helper()
	members, ok := projection.Attributes["members"].([]any)
	if !ok || len(members) != len(expected) {
		t.Fatal("resumed cycle Group lost an admitted member")
	}
	remaining := make(map[string]struct{}, len(expected))
	for _, resource := range expected {
		remaining[resource] = struct{}{}
	}
	for _, value := range members {
		member, ok := value.(map[string]any)
		if !ok || member["type"] != "Group" {
			t.Fatal("resumed cycle member changed its admitted type")
		}
		resource, ok := member["value"].(string)
		if _, exists := remaining[resource]; !ok || !exists {
			t.Fatal("resumed cycle member did not resolve to an original final Group ID")
		}
		delete(remaining, resource)
	}
}
