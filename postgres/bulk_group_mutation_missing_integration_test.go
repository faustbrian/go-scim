//go:build integration

package scimpostgres

import (
	"bytes"
	"encoding/json"
	"strconv"
	"testing"

	identity "github.com/faustbrian/go-identity"
	scim "github.com/faustbrian/go-scim"
)

func TestNativeGroupBulkRetainsMissingTargetAndRequiredVersionDenials(t *testing.T) {
	for _, want := range []int{404, 428} {
		t.Run(strconv.Itoa(want), func(t *testing.T) {
			f, service := bulkChildExecutionFixture(t)
			installBulkGroupMutationSchema(t, f)
			absent, err := identity.NewSubjectID()
			if err != nil {
				t.Fatal(err)
			}
			id := string(absent)
			child := map[string]string{"method": "DELETE", "path": "/Groups/" + id}
			if want == 404 {
				version, err := identity.NewCommandID()
				if err != nil {
					t.Fatal(err)
				}
				child["version"] = string(bulkChildVersion(string(version)))
			}
			body, err := json.Marshal(map[string]any{
				"schemas":      []string{"urn:ietf:params:scim:api:messages:2.0:BulkRequest"},
				"failOnErrors": 1,
				"Operations": []any{child, map[string]any{"method": "POST", "path": "/Groups", "bulkId": "skipped",
					"data": map[string]any{"schemas": []string{"urn:ietf:params:scim:schemas:core:2.0:Group"}, "displayName": "cutoff sibling"}}},
			})
			if err != nil {
				t.Fatal(err)
			}
			request := BulkAdmissionRequest{Credential: f.bearer, Body: body}
			admitted, err := service.Admit(f.ctx, request)
			if err != nil || admitted.ChildCount != 2 {
				t.Fatal("admit the exact Group mutation", err)
			}
			for range 2 {
				result, err := service.ExecuteChild(f.ctx, request, 0)
				if err != nil || result.Status != scim.BulkChildFailed || result.Code != want || result.Version != "" {
					t.Fatal("retain the authorized no-effect denial and replay it", result, err)
				}
			}
			sibling, err := service.ExecuteChild(f.ctx, request, 1)
			if err != nil || sibling.Status != scim.BulkChildSkipped || sibling.SkipReason != scim.BulkSkipFailOnErrors {
				t.Fatal("terminal denial atomically skips the sibling at the configured threshold", sibling, err)
			}
			wire, err := service.ReadResult(f.ctx, request)
			replay, replayErr := service.ReadResult(f.ctx, request)
			if err != nil || replayErr != nil || !bytes.Equal(wire, replay) || !bytes.Contains(wire, []byte(`"status":"`+strconv.Itoa(want)+`"`)) || bytes.Contains(wire, []byte(`"skipped"`)) {
				t.Fatal("expose the original typed terminal outcome on exact authorized replay", err, replayErr)
			}
			var failed, auditRows, skipAudits, outboxRows, projectionRows int
			var prepared bool
			if err := f.pool.Raw().QueryRow(f.ctx, `SELECT p.failed_count,b.group_mutation_input IS NOT NULL,
 (SELECT count(*) FROM audit.records a WHERE a.subject_id=b.command_id AND a.correlation_id=b.parent_id AND a.action='identity.scim.bulk_apply_child'),
 (SELECT count(*) FROM audit.records a WHERE a.correlation_id=b.parent_id AND a.action='identity.scim.bulk_skip_child'),
 (SELECT count(*) FROM public.identity_outbox_bindings o WHERE o.command_id=decode(translate(b.command_id,'-_','+/')||'==','base64')),
 (SELECT count(*) FROM scim.groups g WHERE g.resource_id=$2)
 FROM scim.bulk_children b JOIN scim.bulk_requests p USING(parent_id) WHERE b.parent_id=$1 AND b.ordinal=0`, string(admitted.CommandID), id).Scan(&failed, &prepared, &auditRows, &skipAudits, &outboxRows, &projectionRows); err != nil ||
				failed != 1 || prepared != (want == 404) || auditRows != 1 || skipAudits != 1 || outboxRows != 0 || projectionRows != 0 {
				t.Fatal("retain one denial audit and no success effects; only 404 prepares a projection", err)
			}
		})
	}
}
