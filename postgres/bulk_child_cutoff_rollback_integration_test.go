//go:build integration

package scimpostgres

import (
	"fmt"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/faustbrian/go-audit"
	database "github.com/faustbrian/go-postgres"
	scim "github.com/faustbrian/go-scim"
	"github.com/jackc/pgx/v5/pgconn"
)

func TestNativeGroupBulkChildCutoffSecondSkipAuditFailureRollsBackAndRetries(t *testing.T) {
	f, service := bulkChildExecutionFixture(t)
	const body = `{"schemas":["urn:ietf:params:scim:api:messages:2.0:BulkRequest"],"failOnErrors":1,"Operations":[` +
		`{"method":"POST","path":"/Groups","bulkId":"missing-member","data":{"schemas":["urn:ietf:params:scim:schemas:core:2.0:Group"],"displayName":"Denied","members":[{"type":"Group","value":"missing-group"}]}},` +
		`{"method":"POST","path":"/Groups","bulkId":"first-skipped","data":{"schemas":["urn:ietf:params:scim:schemas:core:2.0:Group"],"displayName":"First independent"}},` +
		`{"method":"POST","path":"/Groups","bulkId":"second-skipped","data":{"schemas":["urn:ietf:params:scim:schemas:core:2.0:Group"],"displayName":"Second independent"}}]}`
	request := BulkAdmissionRequest{Credential: f.bearer, Body: []byte(body)}
	parent, err := service.Admit(f.ctx, request)
	if err != nil || parent.ChildCount != 3 {
		t.Fatal("admit the denied child and two ordinary independent successors", err)
	}
	children := [3]admittedBulkChild{
		originalBulkChild(t, f, parent, 0),
		originalBulkChild(t, f, parent, 1),
		originalBulkChild(t, f, parent, 2),
	}
	requireBulkCutoffRollbackState(t, f, parent, children, false)

	// Fail whichever exact successor is appended second, without making audit
	// emission order part of the contract. xmin proves that the first skip and
	// original denial are provisional records in this same terminal transaction.
	quote := func(value string) string { return "'" + strings.ReplaceAll(value, "'", "''") + "'" }
	faultSQL := `CREATE FUNCTION scim.fixture_bulk_second_skip_fault() RETURNS trigger LANGUAGE plpgsql AS $f$
BEGIN
 IF NEW.action='identity.scim.bulk_skip_child' AND NEW.subject_type='scim_bulk_child'
  AND NEW.correlation_id=TG_ARGV[0] AND NEW.subject_id IN (TG_ARGV[1],TG_ARGV[2])
  AND EXISTS (SELECT 1 FROM audit.records r WHERE r.correlation_id=TG_ARGV[0]
   AND r.action='identity.scim.bulk_skip_child' AND r.subject_type='scim_bulk_child'
   AND r.subject_id IN (TG_ARGV[1],TG_ARGV[2]) AND r.subject_id<>NEW.subject_id
   AND r.xmin=pg_current_xact_id()::text::xid) THEN
  IF EXISTS (SELECT 1 FROM audit.records r WHERE r.correlation_id=TG_ARGV[0]
   AND r.action='identity.scim.bulk_apply_child' AND r.subject_type='scim_bulk_child'
   AND r.subject_id=TG_ARGV[3] AND r.outcome=` + fmt.Sprint(int16(audit.OutcomeDenied)) + `
   AND r.xmin=pg_current_xact_id()::text::xid) THEN
   RAISE NOTICE USING ERRCODE='PZ005',MESSAGE=NEW.subject_id;
  END IF;
  RAISE EXCEPTION 'owned second cutoff skip audit failure';
 END IF;
 RETURN NEW;
END $f$;
CREATE TRIGGER fixture_bulk_second_skip_fault BEFORE INSERT ON audit.records
FOR EACH ROW EXECUTE FUNCTION scim.fixture_bulk_second_skip_fault(` +
		quote(string(parent.CommandID)) + "," + quote(children[1].command) + "," + quote(children[2].command) + "," + quote(children[0].command) + ")"
	if _, err := f.pool.Raw().Exec(f.ctx, faultSQL); err != nil {
		t.Fatal("install the owned second-skip audit fault", err)
	}
	reached := new(atomic.Bool)
	f.config.Coordinator.LeaseDuration = time.Second
	faulted := bulkOnFixturePool(t, f, func(c *database.PoolConfig) {
		c.ConnConfig.RuntimeParams["client_min_messages"] = "notice"
		c.ConnConfig.OnNotice = func(_ *pgconn.PgConn, n *pgconn.Notice) {
			if n.Code == "PZ005" && (n.Message == children[1].command || n.Message == children[2].command) {
				reached.Store(true)
			}
		}
	})
	if result, err := faulted.ExecuteChild(f.ctx, request, 0); protocolStatus(err) != 503 || result != (scim.BulkChildResult{}) || !reached.Load() {
		t.Fatal("second skip audit fault must follow a provisional skip and denial, and return no finite result", reached.Load(), err)
	}
	requireBulkCutoffRollbackState(t, f, parent, children, false)

	if _, err := f.pool.Raw().Exec(f.ctx, `DROP TRIGGER fixture_bulk_second_skip_fault ON audit.records;
DROP FUNCTION scim.fixture_bulk_second_skip_fault()`); err != nil {
		t.Fatal("remove only the owned audit fault before exact retry", err)
	}
	// The failure terminalization rolled back, not the earlier reservation.
	// Retry must respect that original pending journal lease until it expires.
	var remainingMicros int64
	err = f.pool.Raw().QueryRow(f.ctx, `SELECT greatest(0,ceil(extract(epoch from (lease_until-clock_timestamp()))*1000000))::bigint
 FROM identity.commands WHERE state='pending' AND command_id=decode(translate($1::text,'-_','+/')||'==','base64')`, children[0].command).Scan(&remainingMicros)
	if err != nil || remainingMicros > time.Second.Microseconds() {
		t.Fatal("retain only the original bounded pending reservation", remainingMicros, err)
	}
	untilExpired := time.NewTimer(time.Duration(remainingMicros+1000) * time.Microsecond)
	defer untilExpired.Stop()
	select {
	case <-untilExpired.C:
	case <-f.ctx.Done():
		t.Fatal("original lease did not expire in the owned fixture")
	}
	wantFailed := scim.BulkChildResult{Status: scim.BulkChildFailed, Code: 400, SCIMType: "invalidValue"}
	wantSkipped := scim.BulkChildResult{Status: scim.BulkChildSkipped, SkipReason: scim.BulkSkipFailOnErrors}
	if result, err := service.ExecuteChild(f.ctx, request, 0); err != nil || result != wantFailed {
		t.Fatal("retry the exact request after rollback and retain its original typed denial", result, err)
	}
	requireBulkCutoffRollbackState(t, f, parent, children, true)
	for range 2 {
		for ordinal, want := range []scim.BulkChildResult{wantFailed, wantSkipped, wantSkipped} {
			if result, err := service.ExecuteChild(f.ctx, request, ordinal); err != nil || result != want {
				t.Fatal("exact replay must retain the denial or skip without a new operation result", ordinal, result, err)
			}
		}
		requireBulkCutoffRollbackState(t, f, parent, children, true)
	}
}

func requireBulkCutoffRollbackState(t *testing.T, f *nativeFixture, parent BulkAdmission, children [3]admittedBulkChild, completed bool) {
	t.Helper()
	wantFailures := 0
	if completed {
		wantFailures = 1
	}
	var failures, childCount int
	var cutoff bool
	err := f.pool.Raw().QueryRow(f.ctx, `SELECT failed_count,cutoff_active,
 (SELECT count(*) FROM scim.bulk_children WHERE parent_id=$1)
 FROM scim.bulk_requests WHERE parent_id=$1`, string(parent.CommandID)).Scan(&failures, &cutoff, &childCount)
	if err != nil || failures != wantFailures || cutoff != completed || childCount != len(children) {
		t.Fatal("cutoff and failure count must commit once or roll back with every child", failures, cutoff, childCount, err)
	}
	for ordinal, original := range children {
		var command, resource, status, skipReason string
		var code *int16
		var resultResource, resultVersion *string
		var receipts, aborted, audits, bindings, boundAudits, groups, events int
		err := f.pool.Raw().QueryRow(f.ctx, `SELECT b.command_id,b.resource_id,b.status,b.skip_reason,
 b.result_code,b.result_resource_id,b.result_version,
 (SELECT count(*) FROM identity.commands c
  WHERE c.command_id=decode(translate(b.command_id,'-_','+/')||'==','base64') AND c.state IN ('committed','aborted')),
 (SELECT count(*) FROM identity.commands c
  WHERE c.command_id=decode(translate(b.command_id,'-_','+/')||'==','base64') AND c.state='aborted'),
 (SELECT count(*) FROM audit.records r WHERE r.correlation_id=b.parent_id AND r.subject_id=b.command_id),
 (SELECT count(*) FROM audit.identity_command_bindings a
  WHERE a.command_id=decode(translate(b.command_id,'-_','+/')||'==','base64')),
 (SELECT count(*) FROM audit.records r JOIN audit.identity_command_bindings a ON a.event_id=r.record_id
  WHERE r.correlation_id=b.parent_id AND r.subject_type='scim_bulk_child' AND r.subject_id=b.command_id
   AND a.command_id=decode(translate(b.command_id,'-_','+/')||'==','base64') AND a.event_index=0 AND r.outcome=$4
   AND ((b.ordinal=0 AND r.action='identity.scim.bulk_apply_child')
    OR (b.ordinal<>0 AND r.action='identity.scim.bulk_skip_child'
     AND convert_from(r.canonical_record,'UTF8')::jsonb->>'reason_code'='identity.scim.fail_on_errors_cutoff'
     AND convert_from(r.canonical_record,'UTF8')::jsonb#>>'{context,causation_id}'=$3
     AND convert_from(r.canonical_record,'UTF8')::jsonb#>>'{attributes,retention.class}'='protected'))),
 (SELECT count(*) FROM scim.groups g WHERE g.command_id=b.command_id),
 (SELECT count(*) FROM public.identity_outbox_bindings o
  WHERE o.command_id=decode(translate(b.command_id,'-_','+/')||'==','base64'))
 FROM scim.bulk_children b WHERE b.parent_id=$1 AND b.ordinal=$2`, string(parent.CommandID), ordinal, children[0].command, int16(audit.OutcomeDenied)).Scan(
			&command, &resource, &status, &skipReason, &code, &resultResource, &resultVersion,
			&receipts, &aborted, &audits, &bindings, &boundAudits, &groups, &events)
		if err != nil {
			t.Fatal("read exact original child effects", ordinal, err)
		}
		wantStatus, wantReason := "admitted", "none"
		wantReceipts, wantAudits := 0, 0
		if completed {
			wantAudits = 1
			if ordinal == 0 {
				wantStatus, wantReceipts = "failed", 1
			} else {
				wantStatus, wantReason = "skipped", "fail-on-errors"
			}
		}
		if command != original.command || resource != original.resource || status != wantStatus || skipReason != wantReason ||
			receipts != wantReceipts || aborted != wantReceipts || audits != wantAudits || bindings != wantAudits || boundAudits != wantAudits || groups != 0 || events != 0 {
			t.Fatal("child allocation, checkpoint, receipt and protected audit must be atomic and replay-stable", ordinal,
				status, skipReason, receipts, aborted, audits, bindings, boundAudits, groups, events)
		}
		if completed && ordinal == 0 {
			if code == nil || *code != 400 {
				t.Fatal("only the original denial may retain its 400 result", ordinal)
			}
		} else if code != nil {
			t.Fatal("admitted or skipped child retained an operation status", ordinal)
		}
		if resultResource != nil || resultVersion != nil {
			t.Fatal("denied or unprocessed child retained a successful resource result", ordinal)
		}
	}
}
