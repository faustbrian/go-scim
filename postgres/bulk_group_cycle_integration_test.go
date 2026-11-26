//go:build integration

package scimpostgres

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/faustbrian/go-audit"
	identity "github.com/faustbrian/go-identity"
	database "github.com/faustbrian/go-postgres"
	scim "github.com/faustbrian/go-scim"
	"github.com/jackc/pgx/v5/pgconn"
)

func TestNativeGroupBulkCycleKnownMemberFailureSettlesWholeComponent(t *testing.T) {
	f, service := bulkChildExecutionFixture(t)
	missing, err := identity.NewSubjectID()
	if err != nil {
		t.Fatal(err)
	}
	body := strings.Replace(cyclicGroupBulkFixture, `"Operations":[`, `"failOnErrors":1,"Operations":[`, 1)
	body = strings.Replace(body, `"value":"bulkId:first"}`, `"value":"bulkId:first"},{"type":"User","value":"`+string(missing)+`"}`, 1)
	body = strings.TrimSuffix(body, `]}`) +
		`,{"method":"POST","path":"/Groups","bulkId":"later","data":{"schemas":["urn:ietf:params:scim:schemas:core:2.0:Group"],"displayName":"Later"}}]}`
	request := BulkAdmissionRequest{Credential: f.bearer, Body: []byte(body)}
	parent, err := service.Admit(f.ctx, request)
	if err != nil || parent.ChildCount != 3 {
		t.Fatal("admit the cyclic component and independent sibling", err)
	}
	for _, ordinal := range []int{1, 0, 1} {
		result, err := service.ExecuteChild(f.ctx, request, ordinal)
		if err != nil || result.Status != scim.BulkChildFailed || result.Code != 424 || result.ResourceID != "" || result.Version != "" {
			t.Fatalf("member %d did not return the retained dependency failure: %+v, %v", ordinal, result, err)
		}
	}
	skipped, err := service.ExecuteChild(f.ctx, request, 2)
	if err != nil || skipped.Status != scim.BulkChildSkipped || skipped.SkipReason != scim.BulkSkipFailOnErrors {
		t.Fatal("threshold must skip the disjoint sibling, not the failed cycle's second member", skipped, err)
	}
	wire, err := service.ReadResult(f.ctx, request)
	if err != nil || bytes.Count(wire, []byte(`"detail":"Dependency failed"`)) != 2 || bytes.Contains(wire, []byte(`"bulkId":"later"`)) {
		t.Fatal("terminal reply must retain both processed dependency failures only", err)
	}
	var failed, groups, committed, outbox, failureAudits, skipAudits int
	err = f.pool.Raw().QueryRow(f.ctx, `SELECT
 (SELECT failed_count FROM scim.bulk_requests WHERE parent_id=$1 AND cutoff_active),
 (SELECT count(*) FROM scim.groups),
 (SELECT count(*) FROM identity.commands c JOIN scim.bulk_children b ON c.command_id=decode(translate(b.command_id,'-_','+/')||'==','base64') WHERE b.parent_id=$1 AND c.state='committed'),
 (SELECT count(*) FROM public.identity_outbox_bindings o JOIN scim.bulk_children b ON o.command_id=decode(translate(b.command_id,'-_','+/')||'==','base64') WHERE b.parent_id=$1),
 (SELECT count(*) FROM audit.identity_command_bindings a JOIN audit.records r ON r.record_id=a.event_id JOIN scim.bulk_children b ON a.command_id=decode(translate(b.command_id,'-_','+/')||'==','base64') WHERE b.parent_id=$1 AND r.action='identity.scim.bulk_apply_child' AND r.outcome<>$2),
 (SELECT count(*) FROM audit.identity_command_bindings a JOIN audit.records r ON r.record_id=a.event_id JOIN scim.bulk_children b ON a.command_id=decode(translate(b.command_id,'-_','+/')||'==','base64') WHERE b.parent_id=$1 AND r.action='identity.scim.bulk_skip_child')`, string(parent.CommandID), int16(audit.OutcomeSucceeded)).Scan(&failed, &groups, &committed, &outbox, &failureAudits, &skipAudits)
	if err != nil || failed != 2 || groups != 0 || committed != 0 || outbox != 0 || failureAudits != 2 || skipAudits != 1 {
		t.Fatal("the whole cycle must fail once without projections or success effects", failed, groups, committed, outbox, failureAudits, skipAudits, err)
	}
}

func TestNativeGroupBulkCycleCommitsTogetherAndReplaysOriginalResults(t *testing.T) {
	for _, selected := range []int{0, 1} {
		t.Run(fmt.Sprintf("selected-ordinal-%d", selected), func(t *testing.T) {
			f, service := bulkChildExecutionFixture(t)
			request := BulkAdmissionRequest{Credential: f.bearer, Body: []byte(cyclicGroupBulkFixture)}
			parent, err := service.Admit(f.ctx, request)
			if err != nil || parent.ChildCount != 2 {
				t.Fatal("admit the complete two-Group cycle", err)
			}
			originals := [2]admittedBulkChild{
				originalBulkChild(t, f, parent, 0),
				originalBulkChild(t, f, parent, 1),
			}
			if originals[0].command == originals[1].command || originals[0].resource == originals[1].resource {
				t.Fatal("cyclic children must retain distinct original commands and final resource IDs")
			}
			if wire, err := service.ReadResult(f.ctx, request); !errors.Is(err, scim.ErrBulkIncomplete) || len(wire) != 0 {
				t.Fatal("admission must not expose a terminal cycle result", err)
			}

			var results [2]scim.BulkChildResult
			results[selected], err = service.ExecuteChild(f.ctx, request, selected)
			if err != nil || results[selected].Status != scim.BulkChildSucceeded {
				t.Fatal("selecting either member must execute its complete retained Group-create SCC", err)
			}
			var groups, completed int
			if err := f.pool.Raw().QueryRow(f.ctx, `SELECT
 (SELECT count(*) FROM scim.groups),
 (SELECT count(*) FROM scim.bulk_children b JOIN scim.groups g
  ON g.resource_id=b.resource_id AND g.command_id=b.command_id
  WHERE b.parent_id=$1 AND b.status='succeeded' AND b.result_code=201
   AND b.result_resource_id=b.resource_id AND b.result_version IS NOT NULL)`, string(parent.CommandID)).Scan(&groups, &completed); err != nil || groups != 2 || completed != 2 {
				t.Fatal("one member invocation must expose both original projections and successful checkpoints together", groups, completed, err)
			}
			wire, err := service.ReadResult(f.ctx, request)
			if err != nil {
				t.Fatal("the SCC must be terminal before the other member is invoked", err)
			}

			other := 1 - selected
			results[other], err = service.ExecuteChild(f.ctx, request, other)
			if err != nil {
				t.Fatal("recover the other member's original SCC result", err)
			}
			for ordinal, original := range originals {
				projection := requireCommittedBulkChild(t, f, parent, ordinal, original, results[ordinal])
				wantName := []string{"First", "Second"}[ordinal]
				members, ok := projection.Attributes["members"].([]any)
				if !ok || len(members) != 1 || projection.Attributes["displayName"] != wantName {
					t.Fatal("cyclic Group projection lost its original display name or member", ordinal)
				}
				member, ok := members[0].(map[string]any)
				if !ok || member["type"] != "Group" || member["value"] != originals[1-ordinal].resource {
					t.Fatal("cyclic bulkId must resolve to the other member's original final ID", ordinal)
				}
				if replayed, err := service.ExecuteChild(f.ctx, request, ordinal); err != nil || replayed != results[ordinal] {
					t.Fatal("exact member replay changed the original SCC result", ordinal, err)
				}
			}
			for ordinal, original := range originals {
				requireCommittedBulkChild(t, f, parent, ordinal, original, results[ordinal])
			}
			if err := f.pool.Raw().QueryRow(f.ctx, `SELECT count(*) FROM scim.groups`).Scan(&groups); err != nil || groups != 2 {
				t.Fatal("replaying either member must not duplicate Group projections", groups, err)
			}

			var response struct {
				Operations []struct{ Method, BulkID, Status, Location, Version string }
			}
			if err := json.Unmarshal(wire, &response); err != nil || len(response.Operations) != 2 {
				t.Fatal("decode the complete retained cycle response", err)
			}
			for ordinal, operation := range response.Operations {
				if operation.Method != "POST" || operation.BulkID != []string{"first", "second"}[ordinal] || operation.Status != "201" ||
					operation.Location != f.config.BaseURL+"/Groups/"+originals[ordinal].resource || operation.Version != string(results[ordinal].Version) {
					t.Fatal("terminal cycle response must preserve request order, original location and version", ordinal)
				}
			}
			if replayed, err := service.ReadResult(f.ctx, request); err != nil || !bytes.Equal(wire, replayed) {
				t.Fatal("member replay must preserve the exact original terminal response", err)
			}
		})
	}
}

func TestNativeGroupBulkCycleProjectionFailureRollsBackEveryMember(t *testing.T) {
	f, service := bulkChildExecutionFixture(t)
	request := BulkAdmissionRequest{Credential: f.bearer, Body: []byte(cyclicGroupBulkFixture)}
	parent, err := service.Admit(f.ctx, request)
	if err != nil || parent.ChildCount != 2 {
		t.Fatal("admit the complete cycle before injecting the projection failure", err)
	}
	originals := [2]admittedBulkChild{
		originalBulkChild(t, f, parent, 0),
		originalBulkChild(t, f, parent, 1),
	}
	reached := new(atomic.Bool)
	faulted := bulkOnFixturePool(t, f, func(c *database.PoolConfig) {
		c.ConnConfig.RuntimeParams["client_min_messages"] = "notice"
		c.ConnConfig.OnNotice = func(_ *pgconn.PgConn, notice *pgconn.Notice) {
			if notice.Code == "PZ006" {
				reached.Store(true)
			}
		}
	})
	if _, err := f.pool.Raw().Exec(f.ctx, `CREATE FUNCTION scim.fixture_cycle_projection_failure() RETURNS trigger LANGUAGE plpgsql AS $f$
BEGIN
 IF EXISTS (
  SELECT 1 FROM scim.bulk_children selected
  JOIN scim.bulk_children sibling ON sibling.parent_id=selected.parent_id
   AND sibling.component_id=selected.component_id AND sibling.ordinal<>selected.ordinal
  JOIN scim.groups staged ON staged.resource_id=sibling.resource_id AND staged.command_id=sibling.command_id
  WHERE selected.command_id=NEW.command_id AND selected.cyclic
 ) THEN
  RAISE NOTICE USING ERRCODE='PZ006',MESSAGE='owned earlier cyclic Group projection reached later insert';
  RAISE EXCEPTION 'owned later cyclic Group projection failure';
 END IF;
 RETURN NEW;
END $f$;
CREATE TRIGGER fixture_cycle_projection_failure BEFORE INSERT ON scim.groups
FOR EACH ROW EXECUTE FUNCTION scim.fixture_cycle_projection_failure()`); err != nil {
		t.Fatal("install the owned second-projection failure", err)
	}
	if result, err := faulted.ExecuteChild(f.ctx, request, 0); err == nil || result != (scim.BulkChildResult{}) || !reached.Load() {
		t.Fatal("a definite later projection failure must follow an actual earlier staged SCC write without returning success", reached.Load(), err)
	}

	var groups, successes, committed, audits, outbox int
	err = f.pool.Raw().QueryRow(f.ctx, `SELECT
 (SELECT count(*) FROM scim.groups),
 (SELECT count(*) FROM scim.bulk_children b WHERE b.parent_id=$1
  AND (b.status='succeeded' OR b.result_resource_id IS NOT NULL OR b.result_version IS NOT NULL)),
 (SELECT count(*) FROM identity.commands c JOIN scim.bulk_children b
  ON c.command_id=decode(translate(b.command_id,'-_','+/')||'==','base64')
  WHERE b.parent_id=$1 AND c.state='committed'),
 (SELECT count(*) FROM audit.identity_command_bindings a JOIN audit.records r ON r.record_id=a.event_id
  JOIN scim.bulk_children b ON a.command_id=decode(translate(b.command_id,'-_','+/')||'==','base64')
  WHERE b.parent_id=$1 AND r.outcome=$2),
 (SELECT count(*) FROM public.identity_outbox_bindings o JOIN scim.bulk_children b
  ON o.command_id=decode(translate(b.command_id,'-_','+/')||'==','base64')
  WHERE b.parent_id=$1)`, string(parent.CommandID), int16(audit.OutcomeSucceeded)).Scan(&groups, &successes, &committed, &audits, &outbox)
	if err != nil || groups != 0 || successes != 0 || committed != 0 || audits != 0 || outbox != 0 {
		t.Fatal("later SCC failure leaked a half-cycle, successful checkpoint, committed child, success audit or outbox", groups, successes, committed, audits, outbox, err)
	}
	for ordinal, original := range originals {
		if retained := originalBulkChild(t, f, parent, ordinal); retained != original {
			t.Fatal("SCC rollback changed an original child command or final resource allocation", ordinal)
		}
	}
}

func TestNativeGroupBulkCycleLostRootCommitRecoversBothOriginals(t *testing.T) {
	f, service := bulkChildExecutionFixture(t)
	request := BulkAdmissionRequest{Credential: f.bearer, Body: []byte(cyclicGroupBulkFixture)}
	parent, err := service.Admit(f.ctx, request)
	if err != nil {
		t.Fatal("admit cycle before the root commit fault", err)
	}
	fault := new(nativeCommitFault)
	uncertain := bulkOnFixturePool(t, f, func(c *database.PoolConfig) { c.ConnConfig.DialFunc = fault.dial })
	if result, err := uncertain.ExecuteChild(f.ctx, request, 1); protocolStatus(err) != 503 || result != (scim.BulkChildResult{}) || !fault.hit.Load() {
		t.Fatal("lost root COMMIT acknowledgment must not publish a provisional result", fault.hit.Load(), err)
	}
	wire, err := service.ReadResult(f.ctx, request)
	if err != nil || bytes.Count(wire, []byte(`"status":"201"`)) != 2 {
		t.Fatal("the exact retained graph must recover both committed results directly", err)
	}
	for ordinal := range 2 {
		original := originalBulkChild(t, f, parent, ordinal)
		result, err := service.ExecuteChild(f.ctx, request, ordinal)
		if err != nil {
			t.Fatal("recover the original child without new work", ordinal, err)
		}
		requireCommittedBulkChild(t, f, parent, ordinal, original, result)
	}
}
