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

const failedThenIndependentGroupBulk = `{"schemas":["urn:ietf:params:scim:api:messages:2.0:BulkRequest"],"failOnErrors":0,"Operations":[` +
	`{"method":"POST","path":"/Groups","bulkId":"missing-member","data":{"schemas":["urn:ietf:params:scim:schemas:core:2.0:Group"],"displayName":"Denied","members":[{"type":"Group","value":"missing-group"}]}},` +
	`{"method":"POST","path":"/Groups","bulkId":"independent","data":{"schemas":["urn:ietf:params:scim:schemas:core:2.0:Group"],"displayName":"Independent"}}]}`

func TestNativeGroupBulkChildRetainsTypedDenialAndContinuesWithoutCutoff(t *testing.T) {
	f, service := bulkChildExecutionFixture(t)
	request := BulkAdmissionRequest{Credential: f.bearer, Body: []byte(failedThenIndependentGroupBulk)}
	parent, err := service.Admit(f.ctx, request)
	if err != nil || parent.ChildCount != 2 {
		t.Fatal("admit both independent children", err)
	}
	first := originalBulkChild(t, f, parent, 0)
	second := originalBulkChild(t, f, parent, 1)

	result, executeErr := service.ExecuteChild(f.ctx, request, 0)
	var status string
	var code *int
	var failed, journal, auditCount, projection, outbox int
	var cutoff bool
	err = f.pool.Raw().QueryRow(f.ctx, `SELECT b.status,b.result_code,p.failed_count,p.cutoff_active,
 (SELECT count(*) FROM identity.commands WHERE command_id=decode(translate(b.command_id,'-_','+/')||'==','base64') AND state='aborted'),
 (SELECT count(*) FROM audit.identity_command_bindings a JOIN audit.records r ON r.record_id=a.event_id
  WHERE a.command_id=decode(translate(b.command_id,'-_','+/')||'==','base64')
  AND r.action='identity.scim.bulk_apply_child' AND r.subject_type='scim_bulk_child'
  AND r.subject_id=b.command_id AND r.correlation_id=b.parent_id AND r.outcome=$3),
 (SELECT count(*) FROM scim.groups WHERE command_id=b.command_id),
 (SELECT count(*) FROM public.identity_outbox_bindings WHERE command_id=decode(translate(b.command_id,'-_','+/')||'==','base64'))
 FROM scim.bulk_children b JOIN scim.bulk_requests p USING(parent_id)
 WHERE b.parent_id=$1 AND b.command_id=$2`, string(parent.CommandID), first.command, int16(audit.OutcomeDenied)).Scan(&status, &code, &failed, &cutoff, &journal, &auditCount, &projection, &outbox)
	if err != nil || journal != 1 || auditCount != 1 || projection != 0 || outbox != 0 {
		t.Fatal("original denial must exist once, without a Group projection or success outbox", journal, auditCount, projection, outbox, err)
	}
	want := scim.BulkChildResult{Status: scim.BulkChildFailed, Code: 400, SCIMType: "invalidValue"}
	if executeErr != nil || result != want || status != "failed" || code == nil || *code != 400 || failed != 1 || cutoff {
		t.Fatal("definitive denial was not retained and counted exactly once", status, code != nil, failed, cutoff, executeErr)
	}

	replayed, err := service.ExecuteChild(f.ctx, request, 0)
	if err != nil || replayed != want {
		t.Fatal("exact retry did not return the retained typed denial", err)
	}
	f.deny.Store(true)
	if denied, err := service.ExecuteChild(f.ctx, request, 0); protocolStatus(err) != 403 || denied != (scim.BulkChildResult{}) {
		t.Fatal("retained denial was disclosed without current authority", err)
	}
	f.deny.Store(false)
	result, err = service.ExecuteChild(f.ctx, request, 1)
	if err != nil {
		t.Fatal("an independent successor was blocked after a completed failure with cutoff disabled", err)
	}
	requireCommittedBulkChild(t, f, parent, 1, second, result)
	if err := f.pool.Raw().QueryRow(f.ctx, `SELECT failed_count FROM scim.bulk_requests WHERE parent_id=$1`, string(parent.CommandID)).Scan(&failed); err != nil || failed != 1 {
		t.Fatal("replay or successor changed the original failure count", failed, err)
	}
}

func TestNativeGroupBulkChildFailureRecoversAfterLostTerminalAcknowledgement(t *testing.T) {
	f, service := bulkChildExecutionFixture(t)
	request := BulkAdmissionRequest{Credential: f.bearer, Body: []byte(failedThenIndependentGroupBulk)}
	parent, err := service.Admit(f.ctx, request)
	if err != nil {
		t.Fatal(err)
	}
	fault := &nativeCommitFault{terminalBulkFailure: true}
	uncertain := bulkOnFixturePool(t, f, func(c *database.PoolConfig) { c.ConnConfig.DialFunc = fault.dial })
	if result, err := uncertain.ExecuteChild(f.ctx, request, 0); protocolStatus(err) != 503 || result != (scim.BulkChildResult{}) || !fault.hit.Load() {
		t.Fatal("the lost failure COMMIT acknowledgment disclosed or did not reach the terminal transaction", fault.hit.Load(), err)
	}
	requireBulkFailureEffects(t, f, parent, "failed", 1)
	want := scim.BulkChildResult{Status: scim.BulkChildFailed, Code: 400, SCIMType: "invalidValue"}
	for range 2 {
		if result, err := service.ExecuteChild(f.ctx, request, 0); err != nil || result != want {
			t.Fatal("uncertain failure retry did not recover the original typed result", err)
		}
	}
	requireBulkFailureEffects(t, f, parent, "failed", 1)
}

func TestNativeGroupBulkChildCutoffRecordsUnprocessedSiblingAndAudit(t *testing.T) {
	f, service := bulkChildExecutionFixture(t)
	body := strings.Replace(failedThenIndependentGroupBulk, `"failOnErrors":0`, `"failOnErrors":1`, 1)
	request := BulkAdmissionRequest{Credential: f.bearer, Body: []byte(body)}
	parent, err := service.Admit(f.ctx, request)
	if err != nil || parent.ChildCount != 2 {
		t.Fatal("admit both independent children", err)
	}
	second := originalBulkChild(t, f, parent, 1)
	wantFailed := scim.BulkChildResult{Status: scim.BulkChildFailed, Code: 400, SCIMType: "invalidValue"}
	wantSkipped := scim.BulkChildResult{Status: scim.BulkChildSkipped, SkipReason: scim.BulkSkipFailOnErrors}
	for range 2 {
		if failed, err := service.ExecuteChild(f.ctx, request, 0); err != nil || failed != wantFailed {
			t.Fatal("retain and replay the cutoff-triggering denial", failed, err)
		}
		if skipped, err := service.ExecuteChild(f.ctx, request, 1); err != nil || skipped != wantSkipped {
			t.Fatal("the skipped sibling must have no operation result", skipped, err)
		}
	}
	var status, skipReason string
	var cutoff, hasWireResult bool
	var failures, skipAudits, applied, groups int
	err = f.pool.Raw().QueryRow(f.ctx, `SELECT b.status,b.skip_reason,p.cutoff_active,p.failed_count,
 b.result_code IS NOT NULL OR b.result_resource_id IS NOT NULL OR b.result_version IS NOT NULL,
 (SELECT count(*) FROM audit.records r JOIN audit.identity_command_bindings a ON a.event_id=r.record_id
  WHERE a.command_id=decode(translate(b.command_id,'-_','+/')||'==','base64') AND a.event_index=0
   AND r.subject_id=b.command_id AND r.subject_type='scim_bulk_child'
   AND r.correlation_id=b.parent_id AND r.action='identity.scim.bulk_skip_child' AND r.outcome=$3
   AND convert_from(r.canonical_record,'UTF8')::jsonb->>'reason_code'='identity.scim.fail_on_errors_cutoff'),
 (SELECT count(*) FROM audit.records WHERE subject_id=b.command_id AND correlation_id=b.parent_id
   AND action='identity.scim.bulk_apply_child'),
 (SELECT count(*) FROM scim.groups WHERE command_id=b.command_id)
 FROM scim.bulk_children b JOIN scim.bulk_requests p USING(parent_id)
 WHERE b.parent_id=$1 AND b.command_id=$2`, string(parent.CommandID), second.command, int16(audit.OutcomeDenied)).Scan(
		&status, &skipReason, &cutoff, &failures, &hasWireResult, &skipAudits, &applied, &groups)
	if err != nil || status != "skipped" || skipReason != "fail-on-errors" || !cutoff || failures != 1 || hasWireResult || skipAudits != 1 || applied != 0 || groups != 0 {
		t.Fatal("cutoff must persist exactly one skip audit and no skipped operation effects", status, skipReason, cutoff, failures, hasWireResult, skipAudits, applied, groups, err)
	}
}

func TestNativeGroupBulkChildCutoffRecoversAfterLostAcknowledgement(t *testing.T) {
	f, service := bulkChildExecutionFixture(t)
	request := BulkAdmissionRequest{Credential: f.bearer, Body: []byte(strings.Replace(failedThenIndependentGroupBulk, `"failOnErrors":0`, `"failOnErrors":1`, 1))}
	parent, err := service.Admit(f.ctx, request)
	if err != nil {
		t.Fatal("admit the cutoff fixture", err)
	}
	fault := &nativeCommitFault{terminalBulkFailure: true}
	uncertain := bulkOnFixturePool(t, f, func(c *database.PoolConfig) { c.ConnConfig.DialFunc = fault.dial })
	if result, err := uncertain.ExecuteChild(f.ctx, request, 0); protocolStatus(err) != 503 || result != (scim.BulkChildResult{}) || !fault.hit.Load() {
		t.Fatal("lost cutoff acknowledgement must not disclose an outcome", fault.hit.Load(), err)
	}
	want := []scim.BulkChildResult{
		{Status: scim.BulkChildFailed, Code: 400, SCIMType: "invalidValue"},
		{Status: scim.BulkChildSkipped, SkipReason: scim.BulkSkipFailOnErrors},
	}
	for ordinal, expected := range want {
		if actual, err := service.ExecuteChild(f.ctx, request, ordinal); err != nil || actual != expected {
			t.Fatal("recover the original definitive result or skip after lost acknowledgement", ordinal, actual, err)
		}
	}
	var skips int
	if err := f.pool.Raw().QueryRow(f.ctx, `SELECT count(*) FROM audit.records WHERE correlation_id=$1 AND action='identity.scim.bulk_skip_child'`, string(parent.CommandID)).Scan(&skips); err != nil || skips != 1 {
		t.Fatal("replaying the retained cutoff must not append another skip audit", skips, err)
	}
}

func TestNativeGroupBulkChildCutoffSkipsDeclaredInvalidSibling(t *testing.T) {
	f, service := bulkChildExecutionFixture(t)
	body := strings.Replace(failedThenIndependentGroupBulk, `"failOnErrors":0`, `"failOnErrors":1`, 1)
	body = strings.Replace(body, `"bulkId":"independent","data"`, `"bulkId":"independent","unknown":true,"data"`, 1)
	request := BulkAdmissionRequest{Credential: f.bearer, Body: []byte(body)}
	if parent, err := service.Admit(f.ctx, request); err != nil || parent.ChildCount != 2 {
		t.Fatal("admit and retain the parser-invalid declaration", err)
	}
	if result, err := service.ExecuteChild(f.ctx, request, 1); protocolStatus(err) != 400 || result != (scim.BulkChildResult{}) {
		t.Fatal("before cutoff the unprocessed declaration still reports its validation error", result, err)
	}
	if result, err := service.ExecuteChild(f.ctx, request, 0); err != nil || result.Status != scim.BulkChildFailed || result.Code != 400 {
		t.Fatal("commit the original Group denial and its cutoff", result, err)
	}
	want := scim.BulkChildResult{Status: scim.BulkChildSkipped, SkipReason: scim.BulkSkipFailOnErrors}
	if result, err := service.ExecuteChild(f.ctx, request, 1); err != nil || result != want {
		t.Fatal("the retained skip must take precedence over the unprocessed validation error", result, err)
	}
}

func TestNativeGroupBulkChildContinuesBelowPositiveCutoff(t *testing.T) {
	f, service := bulkChildExecutionFixture(t)
	body := strings.Replace(failedThenIndependentGroupBulk, `"failOnErrors":0`, `"failOnErrors":2`, 1)
	request := BulkAdmissionRequest{Credential: f.bearer, Body: []byte(body)}
	parent, err := service.Admit(f.ctx, request)
	if err != nil || parent.ChildCount != 2 {
		t.Fatal("admit both independent children", err)
	}
	wantFailed := scim.BulkChildResult{Status: scim.BulkChildFailed, Code: 400, SCIMType: "invalidValue"}
	if result, err := service.ExecuteChild(f.ctx, request, 0); err != nil || result != wantFailed {
		t.Fatal("retain a failure even if the cutoff has not been reached", result, err)
	}
	second := originalBulkChild(t, f, parent, 1)
	result, err := service.ExecuteChild(f.ctx, request, 1)
	if err != nil {
		t.Fatal("the independent sibling is still eligible below the cutoff", err)
	}
	requireCommittedBulkChild(t, f, parent, 1, second, result)
	var count int
	var cutoff bool
	if err := f.pool.Raw().QueryRow(f.ctx, `SELECT failed_count,cutoff_active FROM scim.bulk_requests WHERE parent_id=$1`, string(parent.CommandID)).Scan(&count, &cutoff); err != nil || count != 1 || cutoff {
		t.Fatal("one completed failure must not reach the threshold of two", count, cutoff, err)
	}
}

func TestNativeGroupBulkChildCutoffAtMaximumAdmittedSize(t *testing.T) {
	response := scim.DefaultBulkResponsePolicy()
	response.MaxBytes = 4 << 20
	f, service := bulkChildExecutionFixtureWithResponse(t, response)
	const split = `,{"method":"POST","path":"/Groups","bulkId":"independent"`
	first, _, ok := strings.Cut(failedThenIndependentGroupBulk, split)
	if !ok {
		t.Fatal("missing first failure fixture")
	}
	var body strings.Builder
	body.WriteString(strings.Replace(first, `"failOnErrors":0`, `"failOnErrors":1`, 1))
	for i := 1; i < 1000; i++ {
		fmt.Fprintf(&body, `,{"method":"POST","path":"/Groups","bulkId":"independent-%d","data":{"schemas":["urn:ietf:params:scim:schemas:core:2.0:Group"],"displayName":"Independent"}}`, i)
	}
	body.WriteString(`]}`)
	request := BulkAdmissionRequest{Credential: f.bearer, Body: []byte(body.String())}
	parent, err := service.Admit(f.ctx, request)
	if err != nil || parent.ChildCount != 1000 {
		t.Fatal("admit the maximum number of children", parent.ChildCount, err)
	}
	start := time.Now()
	want := scim.BulkChildResult{Status: scim.BulkChildFailed, Code: 400, SCIMType: "invalidValue"}
	if result, err := service.ExecuteChild(f.ctx, request, 0); err != nil || result != want {
		t.Fatal("complete all 999 skips before the native authority deadline", result, time.Since(start), err)
	}
	t.Logf("PostgreSQL-backed maximum cutoff completed in %s including all 999 protected audits", time.Since(start))
	var skipped, audited int
	err = f.pool.Raw().QueryRow(f.ctx, `SELECT
 (SELECT count(*) FROM scim.bulk_children WHERE parent_id=$1 AND status='skipped' AND skip_reason='fail-on-errors'),
 (SELECT count(*) FROM scim.bulk_children b JOIN audit.records r ON r.subject_id=b.command_id AND r.correlation_id=b.parent_id
  JOIN audit.identity_command_bindings a ON a.event_id=r.record_id
  WHERE b.parent_id=$1 AND b.status='skipped' AND r.action='identity.scim.bulk_skip_child' AND a.event_index=0
  AND a.command_id=decode(translate(b.command_id,'-_','+/')||'==','base64'))`, string(parent.CommandID)).Scan(&skipped, &audited)
	if err != nil || skipped != 999 || audited != skipped {
		t.Fatal("each skipped child must have one exact bound record", skipped, audited, err)
	}
}

func TestNativeGroupBulkChildFailureCheckpointFaultRollsBackAuditAndReceipt(t *testing.T) {
	f, service := bulkChildExecutionFixture(t)
	request := BulkAdmissionRequest{Credential: f.bearer, Body: []byte(failedThenIndependentGroupBulk)}
	parent, err := service.Admit(f.ctx, request)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.pool.Raw().Exec(f.ctx, `CREATE FUNCTION scim.fixture_bulk_failure_counter_fault() RETURNS trigger LANGUAGE plpgsql AS $f$
BEGIN
 IF EXISTS (SELECT 1 FROM audit.records WHERE correlation_id=NEW.parent_id AND action='identity.scim.bulk_apply_child') THEN
  RAISE NOTICE USING ERRCODE='PZ004',MESSAGE='owned failure audit reached the counter checkpoint';
 END IF;
 RAISE EXCEPTION 'owned failure checkpoint fault';
END $f$;
CREATE TRIGGER fixture_bulk_failure_counter_fault BEFORE UPDATE ON scim.bulk_requests
FOR EACH ROW WHEN(NEW.failed_count<>OLD.failed_count) EXECUTE FUNCTION scim.fixture_bulk_failure_counter_fault()`); err != nil {
		t.Fatal(err)
	}
	atAudit := new(atomic.Bool)
	faulted := bulkOnFixturePool(t, f, func(c *database.PoolConfig) {
		c.ConnConfig.RuntimeParams["client_min_messages"] = "notice"
		c.ConnConfig.OnNotice = func(_ *pgconn.PgConn, n *pgconn.Notice) {
			if n.Code == "PZ004" {
				atAudit.Store(true)
			}
		}
	})
	if result, err := faulted.ExecuteChild(f.ctx, request, 0); protocolStatus(err) != 503 || result != (scim.BulkChildResult{}) || !atAudit.Load() {
		t.Fatal("checkpoint fault did not follow the provisional audit or returned a finite result", atAudit.Load(), err)
	}
	requireBulkFailureEffects(t, f, parent, "admitted", 0)
}

func requireBulkFailureEffects(t *testing.T, f *nativeFixture, parent BulkAdmission, wantStatus string, wantCount int) {
	t.Helper()
	var status string
	var count, audits, receipts, groups, lifecycle int
	var cutoff bool
	err := f.pool.Raw().QueryRow(f.ctx, `SELECT b.status,p.failed_count,p.cutoff_active,
 (SELECT count(*) FROM audit.records WHERE correlation_id=p.parent_id AND action='identity.scim.bulk_apply_child'),
 (SELECT count(*) FROM identity.commands WHERE command_id=decode(translate(b.command_id,'-_','+/')||'==','base64') AND state='aborted'),
 (SELECT count(*) FROM scim.groups WHERE command_id=b.command_id),
 (SELECT count(*) FROM public.identity_outbox_bindings WHERE command_id=decode(translate(b.command_id,'-_','+/')||'==','base64'))
 FROM scim.bulk_children b JOIN scim.bulk_requests p USING(parent_id) WHERE b.parent_id=$1 AND b.ordinal=0`, string(parent.CommandID)).Scan(&status, &count, &cutoff, &audits, &receipts, &groups, &lifecycle)
	if err != nil || status != wantStatus || count != wantCount || cutoff || audits != wantCount || receipts != wantCount || groups != 0 || lifecycle != 0 {
		t.Fatal("denial effects were not atomic or were repeated", status, count, cutoff, audits, receipts, groups, lifecycle, err)
	}
}
