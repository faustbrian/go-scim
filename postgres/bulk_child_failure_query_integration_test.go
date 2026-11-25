//go:build integration

package scimpostgres

import (
	"context"
	"encoding/json"
	"slices"
	"strings"
	"testing"
	"time"

	identity "github.com/faustbrian/go-identity"
	"github.com/jackc/pgx/v5"
)

// Retained singleton histories exercise the exact failure checkpoint's selected
// row, immediate predecessor and parent-counter work without Group execution.
func TestNativeGroupBulkChildBoundedFailureCheckpointQueryPlans(t *testing.T) {
	f, service := bulkChildExecutionFixture(t)
	ctx, cancel := context.WithTimeout(f.ctx, 30*time.Second)
	defer cancel()
	parent, err := service.Admit(ctx, BulkAdmissionRequest{Credential: f.bearer, Body: []byte(failedThenIndependentGroupBulk)})
	if err != nil {
		t.Fatal("admit native parent before seeding retained history", err)
	}
	connection, err := f.pool.Raw().Acquire(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer connection.Release()
	if _, err := connection.Exec(ctx, `INSERT INTO scim.bulk_requests
 (tenant_id,organization_id,provider_id,connection_id,parent_id,intent_digest,configuration_digest,response_bytes,child_count,fail_on_errors,created_at)
 SELECT tenant_id,organization_id,provider_id,connection_id,
 translate(rtrim(encode(decode(md5('bulk-child-failure-plan-parent-'||n),'hex'),'base64'),'='),'+/','-_'),
 intent_digest,configuration_digest,response_bytes,1000,fail_on_errors,created_at
 FROM scim.bulk_requests CROSS JOIN generate_series(1,10000) n WHERE parent_id=$1`, string(parent.CommandID)); err != nil {
		t.Fatal("seed bounded same-scope retained parents", err)
	}
	if _, err := connection.Exec(ctx, `INSERT INTO scim.bulk_children
 (parent_id,ordinal,command_id,bulk_id,request_fingerprint,resource_id,component_id,component_order,cyclic,dependency_ids,
  status,result_code,result_resource_id,result_version)
 SELECT p.parent_id,c.ordinal,c.command_id,''::bytea,c.fingerprint,c.resource_id,c.ordinal,c.ordinal,false,ARRAY[]::text[],
 'succeeded',201,c.resource_id,'"'||c.command_id||'"'
 FROM generate_series(1,10) n
 JOIN scim.bulk_requests p ON p.parent_id=translate(rtrim(encode(decode(md5('bulk-child-failure-plan-parent-'||n),'hex'),'base64'),'='),'+/','-_')
 CROSS JOIN LATERAL (
  SELECT ordinal,
   translate(rtrim(encode(decode(md5('bulk-child-failure-plan-command-'||n||'-'||ordinal),'hex'),'base64'),'='),'+/','-_') command_id,
   sha256(convert_to('bulk-child-failure-plan-fingerprint-'||n||'-'||ordinal,'UTF8')) fingerprint,
   translate(rtrim(encode(decode(md5('bulk-child-failure-plan-resource-'||n||'-'||ordinal),'hex'),'base64'),'='),'+/','-_') resource_id
  FROM generate_series(0,999) ordinal
 ) c`); err != nil {
		t.Fatal("seed bounded maximum retained child histories", err)
	}
	if _, err := connection.Exec(ctx, `ANALYZE scim.bulk_requests; ANALYZE scim.bulk_children`); err != nil {
		t.Fatal(err)
	}
	var version string
	if err := connection.QueryRow(ctx, `SHOW server_version`).Scan(&version); err != nil {
		t.Fatal(err)
	}
	// Work encodes every Go int as a binary int8, including the smallint result.
	failureOIDs := []uint32{25, 20, 25, 17, 25, 20, 20}
	t.Logf("PostgreSQL %s; synthetic same-scope parents=10001 children=10002; 10 parents retain 1000 singleton children each; warm cache; sequential client; no concurrent writer", version)
	t.Logf("failure SQL=%s; actual Work binary parameter OIDs=%v; Go binding types=string,int,string,[]byte,string,int,int", bulkChildFail, failureOIDs)

	for _, test := range []struct {
		name                string
		ordinal             int
		missingOrdinal      bool
		mismatchFingerprint bool
		terminal            bool
	}{
		{name: "first selected failure", ordinal: 0},
		{name: "late selected failure", ordinal: 999},
		{name: "no matching ordinal", ordinal: 999, missingOrdinal: true},
		{name: "mismatched fingerprint", ordinal: 999, mismatchFingerprint: true},
		{name: "repeated terminal checkpoint", ordinal: 999, terminal: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			var phase bulkChildExecution
			var parentID string
			err := connection.QueryRow(ctx, `SELECT parent_id,ordinal,command_id,request_fingerprint,resource_id,component_order
 FROM scim.bulk_children
 WHERE parent_id=translate(rtrim(encode(decode(md5('bulk-child-failure-plan-parent-1'),'hex'),'base64'),'='),'+/','-_')
 AND ordinal=$1`, test.ordinal).Scan(&parentID, &phase.row.Ordinal, &phase.row.Command, &phase.row.Fingerprint, &phase.row.Resource, &phase.row.ComponentOrder)
			if err != nil {
				t.Fatal("select actual retained failure bindings", err)
			}
			phase.parent = identity.CommandID(parentID)
			var elapsed, duplicateElapsed [3]time.Duration
			var executionMS, duplicateExecutionMS [3]float64
			for sample := range elapsed {
				tx, err := connection.Begin(ctx)
				if err != nil {
					t.Fatal(err)
				}
				func() {
					defer func() {
						cleanup, cancel := context.WithTimeout(context.Background(), 3*time.Second)
						defer cancel()
						if err := tx.Rollback(cleanup); err != nil {
							t.Error("rollback measured failure checkpoint", err)
						}
					}()
					if _, err := tx.Exec(ctx, `UPDATE scim.bulk_children
 SET status='admitted',result_code=NULL,result_resource_id=NULL,result_version=NULL
 WHERE parent_id=$1 AND ordinal=$2`, parentID, test.ordinal); err != nil {
						t.Fatal(err)
					}
					if test.terminal {
						if _, err := tx.Exec(ctx, `UPDATE scim.bulk_children SET status='failed',result_code=400
 WHERE parent_id=$1 AND ordinal=$2`, parentID, test.ordinal); err != nil {
							t.Fatal(err)
						}
						if _, err := tx.Exec(ctx, `UPDATE scim.bulk_requests SET failed_count=1 WHERE parent_id=$1`, parentID); err != nil {
							t.Fatal(err)
						}
					}
					args := phase.args()
					if test.missingOrdinal {
						args[1] = 1000
					}
					if test.mismatchFingerprint {
						fingerprint := append([]byte(nil), phase.row.Fingerprint...)
						fingerprint[0] ^= 1
						args[3] = fingerprint
					}
					args = append(args, 400)
					started := time.Now()
					plan := explainBulkWorkInsert(t, ctx, tx, bulkChildFail, failureOIDs, args)
					elapsed[sample] = time.Since(started)
					var measured bulkQueryPlan
					if err := json.Unmarshal(plan, &measured); err != nil {
						t.Fatal("decode measured failure timing", err)
					}
					executionMS[sample] = measured.ExecutionMS
					if sample == 0 {
						requireBoundedBulkChildQueryPlan(t, plan)
					}
					wantStatus, wantCount := "failed", 1
					if test.missingOrdinal || test.mismatchFingerprint {
						wantStatus, wantCount = "admitted", 0
					}
					requireBulkFailureQueryEffects(t, ctx, tx, parentID, test.ordinal, wantStatus, wantCount)
					// A second exact checkpoint must not count an already failed row,
					// and a second non-match must not create a terminal checkpoint.
					started = time.Now()
					duplicatePlan := explainBulkWorkInsert(t, ctx, tx, bulkChildFail, failureOIDs, args)
					duplicateElapsed[sample] = time.Since(started)
					if err := json.Unmarshal(duplicatePlan, &measured); err != nil {
						t.Fatal("decode duplicate failure timing", err)
					}
					duplicateExecutionMS[sample] = measured.ExecutionMS
					if sample == 0 {
						requireBoundedBulkChildQueryPlan(t, duplicatePlan)
					}
					requireBulkFailureQueryEffects(t, ctx, tx, parentID, test.ordinal, wantStatus, wantCount)
				}()
			}
			t.Logf("instrumented Work failure client samples=%v server execution ms=%v; duplicate checkpoint client samples=%v server execution ms=%v; each transaction rolled back", elapsed, executionMS, duplicateElapsed, duplicateExecutionMS)
		})
	}
	t.Logf("cutoff SQL=%s; actual Work binary parameter OID=25; Go binding type=string", bulkCutoffSkip)
	for _, test := range []struct {
		name          string
		failureAt     int
		missingParent bool
		wantSkipped   int
	}{
		{name: "cutoff dense 999 siblings", failureAt: 0, wantSkipped: 999},
		{name: "cutoff sparse after completed prefix", failureAt: 998, wantSkipped: 1},
		{name: "cutoff no remaining admitted siblings", failureAt: 999},
		{name: "cutoff no matching parent", failureAt: 0, missingParent: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			var phase bulkChildExecution
			var parentID string
			if err := connection.QueryRow(ctx, `SELECT parent_id,ordinal,command_id,request_fingerprint,resource_id,component_order
 FROM scim.bulk_children
 WHERE parent_id=translate(rtrim(encode(decode(md5('bulk-child-failure-plan-parent-1'),'hex'),'base64'),'='),'+/','-_')
 AND ordinal=$1`, test.failureAt).Scan(&parentID, &phase.row.Ordinal, &phase.row.Command, &phase.row.Fingerprint, &phase.row.Resource, &phase.row.ComponentOrder); err != nil {
				t.Fatal("select actual cutoff failure bindings", err)
			}
			phase.parent = identity.CommandID(parentID)
			var elapsed, duplicateElapsed [3]time.Duration
			var executionMS, duplicateExecutionMS [3]float64
			for sample := range elapsed {
				tx, err := connection.Begin(ctx)
				if err != nil {
					t.Fatal(err)
				}
				func() {
					defer func() {
						cleanup, cancel := context.WithTimeout(context.Background(), 3*time.Second)
						defer cancel()
						if err := tx.Rollback(cleanup); err != nil {
							t.Error("rollback measured cutoff checkpoints", err)
						}
					}()
					if _, err := tx.Exec(ctx, `UPDATE scim.bulk_requests SET fail_on_errors=1 WHERE parent_id=$1`, parentID); err != nil {
						t.Fatal(err)
					}
					if _, err := tx.Exec(ctx, `UPDATE scim.bulk_children
 SET status='admitted',result_code=NULL,result_resource_id=NULL,result_version=NULL
 WHERE parent_id=$1 AND ordinal>=$2`, parentID, test.failureAt); err != nil {
						t.Fatal(err)
					}
					// Execute the actual failure CTE with Work's bindings: cutoff is
					// reached by its counter transition, not simulated fixture flags.
					explainBulkWorkInsert(t, ctx, tx, bulkChildFail, failureOIDs, append(phase.args(), 400))
					var cutoff bool
					if err := tx.QueryRow(ctx, `SELECT cutoff_active FROM scim.bulk_requests WHERE parent_id=$1`, parentID).Scan(&cutoff); err != nil || !cutoff {
						t.Fatal("original typed failure did not activate cutoff", cutoff, err)
					}
					requireBulkFailureQueryEffects(t, ctx, tx, parentID, test.failureAt, "failed", 1)
					selectedParent := parentID
					if test.missingParent {
						selectedParent = strings.Repeat("x", 22)
					}
					want := make([]bulkCutoffQueryChild, 0, test.wantSkipped)
					rows, err := tx.Query(ctx, `SELECT command_id,ordinal FROM scim.bulk_children
 WHERE parent_id=$1 AND status='admitted' ORDER BY ordinal`, selectedParent)
					if err != nil {
						t.Fatal(err)
					}
					for rows.Next() {
						var child bulkCutoffQueryChild
						if err := rows.Scan(&child.Command, &child.Ordinal); err != nil {
							rows.Close()
							t.Fatal(err)
						}
						want = append(want, child)
					}
					rows.Close()
					if err := rows.Err(); err != nil || len(want) != test.wantSkipped {
						t.Fatal("cutoff fixture did not retain the expected pending siblings", len(want), err)
					}
					// Roll back only the instrumented execution, then obtain the
					// real aggregate from the same warm input and exact native SQL.
					if _, err := tx.Exec(ctx, `SAVEPOINT cutoff_plan`); err != nil {
						t.Fatal(err)
					}
					plan := explainBulkWorkInsert(t, ctx, tx, bulkCutoffSkip, []uint32{25}, []any{selectedParent})
					executionMS[sample] = requireBoundedBulkCutoffQueryPlan(t, plan)
					if _, err := tx.Exec(ctx, `ROLLBACK TO SAVEPOINT cutoff_plan; RELEASE SAVEPOINT cutoff_plan`); err != nil {
						t.Fatal(err)
					}
					started := time.Now()
					got := queryBulkCutoffWork(t, ctx, tx, selectedParent)
					elapsed[sample] = time.Since(started)
					if !slices.Equal(got, want) {
						t.Fatal("cutoff aggregate did not contain exactly the selected server-owned siblings", len(got), len(want))
					}
					duplicatePlan := explainBulkWorkInsert(t, ctx, tx, bulkCutoffSkip, []uint32{25}, []any{selectedParent})
					duplicateExecutionMS[sample] = requireBoundedBulkCutoffQueryPlan(t, duplicatePlan)
					started = time.Now()
					duplicate := queryBulkCutoffWork(t, ctx, tx, selectedParent)
					duplicateElapsed[sample] = time.Since(started)
					if len(duplicate) != 0 {
						t.Fatal("repeated cutoff returned already-skipped identities", len(duplicate))
					}
					var skipped, admitted int
					if err := tx.QueryRow(ctx, `SELECT count(*) FILTER (WHERE status='skipped' AND skip_reason='fail-on-errors'),
 count(*) FILTER (WHERE status='admitted') FROM scim.bulk_children WHERE parent_id=$1`, parentID).Scan(&skipped, &admitted); err != nil || skipped != test.wantSkipped || admitted != 999-test.failureAt-test.wantSkipped {
						t.Fatal("cutoff or duplicate changed the wrong sibling set", skipped, admitted, err)
					}
					requireBulkFailureQueryEffects(t, ctx, tx, parentID, test.failureAt, "failed", 1)
				}()
			}
			t.Logf("cutoff aggregate rows=%d; actual Work client samples=%v EXPLAIN server execution ms=%v; duplicate aggregate rows=0 client samples=%v EXPLAIN server execution ms=%v; each transaction rolled back", test.wantSkipped, elapsed, executionMS, duplicateElapsed, duplicateExecutionMS)
		})
	}
	var parents, children, succeeded, failed, skipped, failureCount, cutoffParents, positiveCutoffs, groups int
	if err := connection.QueryRow(ctx, `SELECT
 (SELECT count(*) FROM scim.bulk_requests),(SELECT count(*) FROM scim.bulk_children),
 (SELECT count(*) FROM scim.bulk_children WHERE status='succeeded'),
 (SELECT count(*) FROM scim.bulk_children WHERE status='failed'),
 (SELECT count(*) FROM scim.bulk_children WHERE status='skipped'),
 (SELECT sum(failed_count) FROM scim.bulk_requests),
 (SELECT count(*) FROM scim.bulk_requests WHERE cutoff_active),
 (SELECT count(*) FROM scim.bulk_requests WHERE fail_on_errors>0),
 (SELECT count(*) FROM scim.groups)`).Scan(&parents, &children, &succeeded, &failed, &skipped, &failureCount, &cutoffParents, &positiveCutoffs, &groups); err != nil || parents != 10001 || children != 10002 || succeeded != 10000 || failed != 0 || skipped != 0 || failureCount != 0 || cutoffParents != 0 || positiveCutoffs != 0 || groups != 0 {
		t.Fatal("failure or cutoff measurement escaped rollback or changed retained history", parents, children, succeeded, failed, skipped, failureCount, cutoffParents, positiveCutoffs, groups, err)
	}
}

func requireBulkFailureQueryEffects(t *testing.T, ctx context.Context, tx pgx.Tx, parentID string, ordinal int, wantStatus string, wantCount int) {
	t.Helper()
	var status string
	var code *int16
	var resource, version *string
	var count int
	err := tx.QueryRow(ctx, `SELECT child.status,child.result_code,child.result_resource_id,child.result_version,parent.failed_count
 FROM scim.bulk_children child JOIN scim.bulk_requests parent USING(parent_id)
 WHERE child.parent_id=$1 AND child.ordinal=$2`, parentID, ordinal).Scan(&status, &code, &resource, &version, &count)
	if err != nil || status != wantStatus || count != wantCount || resource != nil || version != nil {
		t.Fatal("selected failure and parent counter did not change together exactly once", status, count, resource != nil, version != nil, err)
	}
	if wantStatus == "failed" {
		if code == nil || *code != 400 {
			t.Fatal("failure checkpoint did not retain the selected typed denial")
		}
	} else if code != nil {
		t.Fatal("nonmatching checkpoint retained a result code")
	}
}

type bulkCutoffQueryChild struct {
	Command string `json:"command_id"`
	Ordinal int    `json:"ordinal"`
}

func queryBulkCutoffWork(t *testing.T, ctx context.Context, tx pgx.Tx, parentID string) []bulkCutoffQueryChild {
	t.Helper()
	result := tx.Conn().PgConn().ExecParams(ctx, bulkCutoffSkip, [][]byte{[]byte(parentID)}, []uint32{25}, []int16{1}, nil).Read()
	if result.Err != nil || len(result.Rows) != 1 || len(result.Rows[0]) != 1 {
		t.Fatal("execute exact cutoff SQL with Work binary text binding", result.Err)
	}
	var skipped []bulkCutoffQueryChild
	if err := json.Unmarshal(result.Rows[0][0], &skipped); err != nil || skipped == nil {
		t.Fatal("cutoff did not return one JSON array aggregate", err)
	}
	return skipped
}

func requireBoundedBulkCutoffQueryPlan(t *testing.T, sanitized []byte) float64 {
	t.Helper()
	var plan bulkQueryPlan
	if err := json.Unmarshal(sanitized, &plan); err != nil {
		t.Fatal("decode measured cutoff plan", err)
	}
	var childRows, parentRows float64
	var childIndexed bool
	var visit func(bulkQueryPlanNode)
	visit = func(node bulkQueryPlanNode) {
		if node.Loops > 0 && strings.HasPrefix(node.Index, "bulk_children_") {
			childIndexed = true
		}
		if node.Loops > 0 && strings.Contains(node.NodeType, "Scan") && (node.Relation == "bulk_children" || node.Relation == "bulk_requests") {
			if node.NodeType == "Seq Scan" {
				t.Fatal("cutoff scanned unrelated retained history", string(sanitized))
			}
			examined := (node.Rows + node.Filtered) * node.Loops
			if node.Relation == "bulk_children" {
				childRows += examined
			} else {
				parentRows += examined
				if node.Index != "bulk_requests_pkey" {
					t.Fatal("cutoff did not use the exact parent key", string(sanitized))
				}
			}
		}
		for _, child := range node.Plans {
			visit(child)
		}
	}
	visit(plan.Plan)
	// Status is filtered after a parent-scoped index lookup. A sparse or empty
	// aggregate can therefore examine all 1,000 siblings, but not other parents.
	if (childRows > 0 && !childIndexed) || childRows > 1000 || parentRows > 1000 {
		t.Fatal("cutoff work exceeded one bounded parent graph", childRows, parentRows, string(sanitized))
	}
	t.Logf("indexed cutoff work children=%.0f parent probes=%.0f; sanitized plan=%s", childRows, parentRows, sanitized)
	return plan.ExecutionMS
}
