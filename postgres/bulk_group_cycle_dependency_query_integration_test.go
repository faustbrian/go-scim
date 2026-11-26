//go:build integration

package scimpostgres

import (
	"context"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
)

// These five statements add dependency reconciliation to the cycle checkpoints.
// They have no predecessor SQL; measure their incremental work separately from
// the owning lifecycle tests, without treating synthetic timings as production.
func TestNativeGroupBulkCycleDependencyBoundedCheckpointQueryPlans(t *testing.T) {
	f, service := bulkChildExecutionFixture(t)
	ctx, cancel := context.WithTimeout(f.ctx, 60*time.Second)
	defer cancel()
	parent, err := service.Admit(ctx, BulkAdmissionRequest{Credential: f.bearer, Body: []byte(dependentGroupBulkFixture)})
	if err != nil {
		t.Fatal("admit parent before seeding retained cycle dependency history", err)
	}
	connection, err := f.pool.Raw().Acquire(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer connection.Release()
	if _, err := connection.Exec(ctx, `INSERT INTO scim.bulk_requests
 (tenant_id,organization_id,provider_id,connection_id,parent_id,intent_digest,configuration_digest,response_bytes,child_count,fail_on_errors,created_at)
 SELECT tenant_id,organization_id,provider_id,connection_id,
 translate(rtrim(encode(decode(md5('bulk-cycle-dependency-plan-parent-'||n),'hex'),'base64'),'='),'+/','-_'),
 intent_digest,configuration_digest,response_bytes,1000,fail_on_errors,created_at
 FROM scim.bulk_requests CROSS JOIN generate_series(1,4096) n WHERE parent_id=$1`, string(parent.CommandID)); err != nil {
		t.Fatal("seed bounded same-scope retained parents", err)
	}
	if _, err := connection.Exec(ctx, `INSERT INTO scim.bulk_children
 (parent_id,ordinal,command_id,bulk_id,request_fingerprint,resource_id,component_id,component_order,cyclic,dependency_ids,
  status,result_code,result_resource_id,result_version)
 SELECT p.parent_id,c.ordinal,c.command_id,''::bytea,c.fingerprint,c.resource_id,c.ordinal,c.ordinal,false,ARRAY[]::text[],
 'succeeded',201,c.resource_id,'"'||c.command_id||'"'
 FROM generate_series(1,10) n
 JOIN scim.bulk_requests p ON p.parent_id=translate(rtrim(encode(decode(md5('bulk-cycle-dependency-plan-parent-'||n),'hex'),'base64'),'='),'+/','-_')
 CROSS JOIN LATERAL (
  SELECT ordinal,
   translate(rtrim(encode(decode(md5('bulk-cycle-dependency-plan-command-'||n||'-'||ordinal),'hex'),'base64'),'='),'+/','-_') command_id,
   sha256(convert_to('bulk-cycle-dependency-plan-fingerprint-'||n||'-'||ordinal,'UTF8')) fingerprint,
   translate(rtrim(encode(decode(md5('bulk-cycle-dependency-plan-resource-'||n||'-'||ordinal),'hex'),'base64'),'='),'+/','-_') resource_id
  FROM generate_series(0,999) ordinal
 ) c`); err != nil {
		t.Fatal("seed ten bounded maximum histories", err)
	}
	if _, err := connection.Exec(ctx, `ANALYZE scim.bulk_requests; ANALYZE scim.bulk_children`); err != nil {
		t.Fatal(err)
	}
	var parentID, version, columns, indexes string
	if err := connection.QueryRow(ctx, `SELECT parent_id FROM scim.bulk_requests
 WHERE parent_id=translate(rtrim(encode(decode(md5('bulk-cycle-dependency-plan-parent-1'),'hex'),'base64'),'='),'+/','-_')`).Scan(&parentID); err != nil {
		t.Fatal(err)
	}
	if err := connection.QueryRow(ctx, `SHOW server_version`).Scan(&version); err != nil {
		t.Fatal(err)
	}
	if err := connection.QueryRow(ctx, `SELECT string_agg(table_name||'.'||column_name||'='||data_type,', ' ORDER BY table_name,column_name)
 FROM information_schema.columns WHERE table_schema='scim' AND table_name IN ('bulk_requests','bulk_children')
 AND column_name IN ('parent_id','ordinal','command_id','request_fingerprint','resource_id','component_order','component_id',
 'dependency_ids','cyclic','status','skip_reason','result_code','failed_count','fail_on_errors','cutoff_active')`).Scan(&columns); err != nil {
		t.Fatal(err)
	}
	if err := connection.QueryRow(ctx, `SELECT string_agg(indexdef,'; ' ORDER BY indexname)
 FROM pg_indexes WHERE schemaname='scim' AND tablename IN ('bulk_requests','bulk_children')`).Scan(&indexes); err != nil {
		t.Fatal(err)
	}
	t.Logf("PostgreSQL %s; synthetic same-scope parents=4097 children=10002; ten 1000-child histories; warm cache; sequential client; no concurrent writer; not a production latency estimate", version)
	t.Logf("actual migrated columns=%s; usable indexes=%s", columns, indexes)
	t.Log("statistics collected before rollback samples; client timings include binary encoding and round trip, exclude setup and rollback; instrumented server execution is separate")

	type checkpointCase struct {
		name, sql, initial, predecessor, mismatch string
		size, edges, threshold                    int
		cutoff, priorPending, change              bool
	}
	tests := []checkpointCase{
		{name: "read sparse succeeded external", sql: bulkCycleDependencyRead, size: 2, edges: 1},
		{name: "read sparse known failure", sql: bulkCycleDependencyRead, size: 2, edges: 1, predecessor: "failed"},
		{name: "read sparse pending external", sql: bulkCycleDependencyRead, size: 2, edges: 1, predecessor: "admitted"},
		{name: "read sparse missing external", sql: bulkCycleDependencyRead, size: 2, edges: 1, predecessor: "missing"},
		{name: "read skipped external at cutoff", sql: bulkCycleDependencyRead, size: 2, edges: 1, predecessor: "skipped", cutoff: true},
		{name: "read known failure cannot overtake pending component", sql: bulkCycleDependencyRead, size: 2, edges: 1, predecessor: "failed", priorPending: true},
		{name: "read many external edges maximum total", sql: bulkCycleDependencyRead, size: 2, edges: 998},
		{name: "read many external edges late missing at cutoff", sql: bulkCycleDependencyRead, size: 2, edges: 998, predecessor: "missing", cutoff: true},
		{name: "read many external edges late pending", sql: bulkCycleDependencyRead, size: 2, edges: 998, predecessor: "admitted"},
		{name: "read many component members maximum total", sql: bulkCycleDependencyRead, size: 998, edges: 2, predecessor: "failed"},
		{name: "read maximum internal component", sql: bulkCycleDependencyRead, size: 1000},
		{name: "block sparse pending", sql: bulkCycleDependencyBlock, size: 2, edges: 1, predecessor: "admitted", change: true},
		{name: "block maximum component", sql: bulkCycleDependencyBlock, size: 1000, change: true},
		{name: "block admitted rejected after cutoff", sql: bulkCycleDependencyBlock, size: 2, cutoff: true},
		{name: "block repeated checkpoint", sql: bulkCycleDependencyBlock, size: 2, initial: "dependency-blocked"},
		{name: "skip sparse blocked after cutoff", sql: bulkCycleDependencySkip, size: 2, initial: "dependency-blocked", cutoff: true, change: true},
		{name: "skip maximum blocked component", sql: bulkCycleDependencySkip, size: 1000, initial: "dependency-blocked", cutoff: true, change: true},
		{name: "skip blocked before cutoff", sql: bulkCycleDependencySkip, size: 2, initial: "dependency-blocked"},
		{name: "skip admitted rejected", sql: bulkCycleDependencySkip, size: 2, cutoff: true},
		{name: "external fail admitted before cutoff", sql: bulkCycleExternalFail, size: 2, edges: 1, predecessor: "failed", change: true},
		{name: "external fail blocked after cutoff", sql: bulkCycleExternalFail, size: 2, edges: 998, predecessor: "failed", initial: "dependency-blocked", cutoff: true, change: true},
		{name: "external fail many members", sql: bulkCycleExternalFail, size: 998, edges: 2, predecessor: "failed", initial: "dependency-blocked", change: true},
		{name: "external fail admitted rejected after cutoff", sql: bulkCycleExternalFail, size: 2, cutoff: true},
		{name: "external fail prior pending rejected", sql: bulkCycleExternalFail, size: 2, priorPending: true},
		{name: "external parent sparse failure before cutoff", sql: bulkCycleExternalParentFail, size: 2, initial: "failed", change: true},
		{name: "external parent reaches cutoff", sql: bulkCycleExternalParentFail, size: 998, edges: 2, initial: "failed", threshold: 100, change: true},
		{name: "external parent maximum total failure after cutoff", sql: bulkCycleExternalParentFail, size: 999, edges: 1, predecessor: "failed", initial: "failed", cutoff: true, change: true},
		{name: "external parent incomplete component", sql: bulkCycleExternalParentFail, size: 2},
		{name: "external parent wrong failed member count", sql: bulkCycleExternalParentFail, size: 2, initial: "failed", mismatch: "count"},
	}
	for _, statement := range []struct{ name, sql string }{
		{"read", bulkCycleDependencyRead}, {"block", bulkCycleDependencyBlock}, {"skip", bulkCycleDependencySkip},
		{"external fail", bulkCycleExternalFail}, {"external parent", bulkCycleExternalParentFail},
	} {
		for _, mismatch := range []string{"parent", "component", "order"} {
			tests = append(tests, checkpointCase{name: statement.name + " mismatched " + mismatch, sql: statement.sql, size: 2, edges: 998, initial: "dependency-blocked", cutoff: true, mismatch: mismatch})
		}
		if statement.sql == bulkCycleExternalFail {
			for _, mismatch := range []string{"ordinal", "fingerprint", "command", "resource"} {
				tests = append(tests, checkpointCase{name: statement.name + " mismatched " + mismatch, sql: statement.sql, size: 2, initial: "dependency-blocked", cutoff: true, mismatch: mismatch})
			}
		}
		tests = append(tests, checkpointCase{name: statement.name + " terminal component", sql: statement.sql, size: 2, initial: "succeeded"})
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if test.size+test.edges > 1000 {
				t.Fatal("fixture exceeds the supported operation limit")
			}
			var elapsed [3]time.Duration
			var executionMS [3]float64
			for sample := range elapsed {
				withBulkMutationPlanTransaction(t, ctx, connection.Conn(), func(tx pgx.Tx) {
					phase := prepareBulkCycleQueryComponent(t, ctx, tx, parentID, test.size)
					initial := test.initial
					if initial == "" {
						initial = "admitted"
					}
					if _, err := tx.Exec(ctx, `UPDATE scim.bulk_children SET status=$3,
 result_code=CASE WHEN $3='failed' THEN 424::smallint WHEN $3='succeeded' THEN 201::smallint END,
 result_resource_id=CASE WHEN $3='succeeded' THEN resource_id END,
 result_version=CASE WHEN $3='succeeded' THEN '"'||command_id||'"' END
 WHERE parent_id=$1 AND component_id=$2 AND cyclic`, parentID, phase.row.ComponentID, initial); err != nil {
						t.Fatal(err)
					}
					var external string
					if err := tx.QueryRow(ctx, `SELECT coalesce(jsonb_agg(
 CASE WHEN ordinal=$2::integer-1 AND $3='missing' THEN repeat('x',22) ELSE command_id END
 ORDER BY ordinal),'[]'::jsonb)::text FROM scim.bulk_children WHERE parent_id=$1 AND ordinal<$2::integer`, parentID, test.edges, test.predecessor).Scan(&external); err != nil {
						t.Fatal(err)
					}
					if _, err := tx.Exec(ctx, `UPDATE scim.bulk_children SET dependency_ids=dependency_ids || ARRAY(
 SELECT jsonb_array_elements_text($2::jsonb)) WHERE parent_id=$1 AND ordinal=999`, parentID, external); err != nil {
						t.Fatal(err)
					}
					if test.edges > 0 && test.predecessor != "" && test.predecessor != "missing" {
						if _, err := tx.Exec(ctx, `UPDATE scim.bulk_children SET status=$3,
 result_code=CASE WHEN $3='failed' THEN 400::smallint END,result_resource_id=NULL,result_version=NULL,
 skip_reason=CASE WHEN $3='skipped' THEN 'fail-on-errors' ELSE 'none' END
 WHERE parent_id=$1 AND ordinal=$2`, parentID, test.edges-1, test.predecessor); err != nil {
							t.Fatal(err)
						}
					}
					if test.priorPending {
						if _, err := tx.Exec(ctx, `UPDATE scim.bulk_children SET status='admitted',result_code=NULL,
 result_resource_id=NULL,result_version=NULL WHERE parent_id=$1 AND ordinal=$2`, parentID, phase.row.ComponentOrder-1); err != nil {
							t.Fatal(err)
						}
					}
					initialCount, threshold := 0, test.threshold
					if test.predecessor == "failed" || test.cutoff {
						initialCount = 1
					}
					if test.cutoff {
						threshold = 1
					}
					if _, err := tx.Exec(ctx, `UPDATE scim.bulk_requests SET failed_count=$2,fail_on_errors=$3,cutoff_active=$4 WHERE parent_id=$1`, parentID, initialCount, threshold, test.cutoff); err != nil {
						t.Fatal(err)
					}
					args := []any{parentID, phase.row.ComponentOrder, phase.row.ComponentID}
					oids := []uint32{25, 20, 20}
					switch test.sql {
					case bulkCycleDependencyRead:
						args, oids = append(args, external), []uint32{25, 20, 20, 25}
					case bulkCycleExternalFail:
						args, oids = append(phase.args(), phase.row.ComponentID), []uint32{25, 20, 25, 17, 25, 20, 20}
					case bulkCycleExternalParentFail:
						args, oids = append(args, test.size), []uint32{25, 20, 20, 20}
					}
					orderIndex, componentIndex := 1, 2
					if test.sql == bulkCycleExternalFail {
						orderIndex, componentIndex = 5, 6
					}
					switch test.mismatch {
					case "parent":
						args[0] = strings.Repeat("x", 22)
					case "component":
						args[componentIndex] = phase.row.ComponentID - 1
					case "order":
						args[orderIndex] = 1000
					case "ordinal":
						args[1] = 1000
					case "fingerprint":
						fingerprint := append([]byte(nil), phase.row.Fingerprint...)
						fingerprint[0] ^= 1
						args[3] = fingerprint
					case "command":
						args[2] = strings.Repeat("x", 22)
					case "resource":
						args[4] = strings.Repeat("x", 22)
					case "count":
						args[3] = test.size + 1
					}
					if sample == 0 {
						t.Logf("exact SQL=%s; actual Work binary parameter OIDs=%v; bindings=text IDs(22 bytes), int8 orders/IDs/counts, bytea fingerprint(32 bytes) or text JSON external IDs(count=%d); mismatches preserve types", test.sql, oids, test.edges)
					}
					if _, err := tx.Exec(ctx, `SAVEPOINT cycle_dependency_plan`); err != nil {
						t.Fatal(err)
					}
					plan := explainBulkWorkInsert(t, ctx, tx, test.sql, oids, args)
					executionMS[sample] = requireBoundedBulkCycleQueryPlan(t, plan, float64(2*test.size+2*test.edges+8), sample == 0)
					if _, err := tx.Exec(ctx, `ROLLBACK TO SAVEPOINT cycle_dependency_plan; RELEASE SAVEPOINT cycle_dependency_plan`); err != nil {
						t.Fatal(err)
					}
					started := time.Now()
					result := executeBulkCycleQueryWork(t, ctx, tx, test.sql, oids, args)
					elapsed[sample] = time.Since(started)
					wantRows := int64(0)
					wantStatus, wantCount, wantCutoff := initial, initialCount, test.cutoff
					if test.sql == bulkCycleDependencyRead {
						if test.mismatch != "parent" {
							wantRows = 1
							members := test.size
							if test.mismatch != "" {
								members = 0
							}
							pendingPrior := test.priorPending || test.edges == phase.row.ComponentOrder && (test.predecessor == "admitted" || test.predecessor == "skipped")
							ordered := !test.cutoff && !pendingPrior && test.mismatch != "order"
							want := []string{bulkDependencyQueryBool(test.cutoff), bulkDependencyQueryBool(ordered), strconv.Itoa(members), initial, initial,
								bulkDependencyQueryBool(test.predecessor == "failed"), bulkDependencyQueryBool(test.predecessor == "admitted" || test.predecessor == "missing"), bulkDependencyQueryBool(test.predecessor == "skipped")}
							if len(result.Rows) != 1 || len(result.Rows[0]) != len(want) {
								t.Fatal("cycle dependency read did not return one complete state")
							}
							for index, value := range want {
								if members == 0 && (index == 3 || index == 4) {
									if result.Rows[0][index] != nil {
										t.Fatal("empty component reported a member status")
									}
								} else if string(result.Rows[0][index]) != value {
									t.Fatal("cycle dependency read returned the wrong state field", index, string(result.Rows[0][index]), value)
								}
							}
						}
					} else if test.change {
						wantRows = 1
						switch test.sql {
						case bulkCycleDependencyBlock:
							wantRows, wantStatus = int64(test.size), "dependency-blocked"
						case bulkCycleDependencySkip:
							wantRows, wantStatus = int64(test.size), "skipped"
						case bulkCycleExternalFail:
							wantStatus = "failed"
						case bulkCycleExternalParentFail:
							wantCount += test.size
							wantCutoff = test.cutoff || threshold > 0 && wantCount >= threshold
							if len(result.Rows) != 1 || len(result.Rows[0]) != 1 || string(result.Rows[0][0]) != bulkDependencyQueryBool(wantCutoff) {
								t.Fatal("external parent failure returned the wrong cutoff")
							}
						}
					}
					if result.CommandTag.RowsAffected() != wantRows || wantRows == 0 && len(result.Rows) != 0 {
						t.Fatal("cycle dependency checkpoint selected the wrong row set", result.CommandTag.RowsAffected(), wantRows)
					}
					if test.change && test.sql != bulkCycleExternalParentFail {
						if replay := executeBulkCycleQueryWork(t, ctx, tx, test.sql, oids, args); replay.CommandTag.RowsAffected() != 0 {
							t.Fatal("cycle dependency mutation replay changed a checkpointed child")
						}
					}
					var status, skip string
					var code *int16
					var count, changedMembers int
					var cutoff bool
					if err := tx.QueryRow(ctx, `SELECT child.status,child.skip_reason,child.result_code,parent.failed_count,parent.cutoff_active,
 (SELECT count(*) FROM scim.bulk_children member WHERE member.parent_id=parent.parent_id AND member.cyclic AND member.status=$2)
 FROM scim.bulk_children child JOIN scim.bulk_requests parent USING(parent_id)
 WHERE child.parent_id=$1 AND child.ordinal=999`, parentID, wantStatus).Scan(&status, &skip, &code, &count, &cutoff, &changedMembers); err != nil || status != wantStatus || count != wantCount || cutoff != wantCutoff {
						t.Fatal("cycle dependency checkpoint changed the wrong child or parent state", status, count, cutoff, err)
					}
					wantMembers := test.size
					if test.sql == bulkCycleExternalFail && test.change {
						wantMembers = 1
					}
					if changedMembers != wantMembers {
						t.Fatal("cycle checkpoint changed the wrong component membership", changedMembers, wantMembers)
					}
					wantSkip := "none"
					if wantStatus == "skipped" {
						wantSkip = "fail-on-errors"
					}
					if skip != wantSkip || wantStatus == "failed" && (code == nil || *code != 424) || wantStatus == "succeeded" && (code == nil || *code != 201) || wantStatus != "failed" && wantStatus != "succeeded" && code != nil {
						t.Fatal("cycle checkpoint retained the wrong result code or skip reason")
					}
				})
			}
			t.Logf("component members=%d external IDs=%d; actual Work client samples=%v; instrumented server execution ms=%v; all samples rolled back", test.size, test.edges, elapsed, executionMS)
		})
	}
	var parents, children, succeeded, cyclic, failedCount, cutoffParents int
	if err := connection.QueryRow(ctx, `SELECT (SELECT count(*) FROM scim.bulk_requests),(SELECT count(*) FROM scim.bulk_children),
 (SELECT count(*) FROM scim.bulk_children WHERE status='succeeded'),(SELECT count(*) FROM scim.bulk_children WHERE cyclic),
 (SELECT sum(failed_count) FROM scim.bulk_requests),(SELECT count(*) FROM scim.bulk_requests WHERE cutoff_active)`).Scan(&parents, &children, &succeeded, &cyclic, &failedCount, &cutoffParents); err != nil || parents != 4097 || children != 10002 || succeeded != 10000 || cyclic != 0 || failedCount != 0 || cutoffParents != 0 {
		t.Fatal("cycle dependency measurements escaped rollback or changed retained history", parents, children, succeeded, cyclic, failedCount, cutoffParents, err)
	}
}
