//go:build integration

package scimpostgres

import (
	"context"
	"testing"
	"time"

	identity "github.com/faustbrian/go-identity"
	"github.com/jackc/pgx/v5"
)

// Dependency reconciliation has no predecessor SQL. These are its incremental
// selected-child costs; the dependency execution tests cover the owning flow.
func TestNativeGroupBulkDependencyBoundedCheckpointQueryPlans(t *testing.T) {
	f, service := bulkChildExecutionFixture(t)
	ctx, cancel := context.WithTimeout(f.ctx, 45*time.Second)
	defer cancel()
	parent, err := service.Admit(ctx, BulkAdmissionRequest{Credential: f.bearer, Body: []byte(dependentGroupBulkFixture)})
	if err != nil {
		t.Fatal("admit parent before seeding retained dependency history", err)
	}
	connection, err := f.pool.Raw().Acquire(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer connection.Release()
	if _, err := connection.Exec(ctx, `INSERT INTO scim.bulk_requests
 (tenant_id,organization_id,provider_id,connection_id,parent_id,intent_digest,configuration_digest,response_bytes,child_count,fail_on_errors,created_at)
 SELECT tenant_id,organization_id,provider_id,connection_id,
 translate(rtrim(encode(decode(md5('bulk-dependency-plan-parent-'||n),'hex'),'base64'),'='),'+/','-_'),
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
 JOIN scim.bulk_requests p ON p.parent_id=translate(rtrim(encode(decode(md5('bulk-dependency-plan-parent-'||n),'hex'),'base64'),'='),'+/','-_')
 CROSS JOIN LATERAL (
  SELECT ordinal,
   translate(rtrim(encode(decode(md5('bulk-dependency-plan-command-'||n||'-'||ordinal),'hex'),'base64'),'='),'+/','-_') command_id,
   sha256(convert_to('bulk-dependency-plan-fingerprint-'||n||'-'||ordinal,'UTF8')) fingerprint,
   translate(rtrim(encode(decode(md5('bulk-dependency-plan-resource-'||n||'-'||ordinal),'hex'),'base64'),'='),'+/','-_') resource_id
  FROM generate_series(0,999) ordinal
 ) c`); err != nil {
		t.Fatal("seed bounded maximum retained child histories", err)
	}
	if _, err := connection.Exec(ctx, `ANALYZE scim.bulk_requests; ANALYZE scim.bulk_children`); err != nil {
		t.Fatal(err)
	}
	var parentID, version, columns, indexes string
	if err := connection.QueryRow(ctx, `SELECT parent_id FROM scim.bulk_requests
 WHERE parent_id=translate(rtrim(encode(decode(md5('bulk-dependency-plan-parent-1'),'hex'),'base64'),'='),'+/','-_')`).Scan(&parentID); err != nil {
		t.Fatal(err)
	}
	if err := connection.QueryRow(ctx, `SHOW server_version`).Scan(&version); err != nil {
		t.Fatal(err)
	}
	if err := connection.QueryRow(ctx, `SELECT string_agg(table_name||'.'||column_name||'='||data_type,', ' ORDER BY table_name,column_name)
 FROM information_schema.columns WHERE table_schema='scim' AND table_name IN ('bulk_requests','bulk_children')
 AND column_name IN ('parent_id','ordinal','command_id','request_fingerprint','resource_id','component_order',
 'dependency_ids','cyclic','status','result_code','failed_count','fail_on_errors','cutoff_active')`).Scan(&columns); err != nil {
		t.Fatal(err)
	}
	if err := connection.QueryRow(ctx, `SELECT string_agg(indexdef,'; ' ORDER BY indexname)
 FROM pg_indexes WHERE schemaname='scim' AND tablename IN ('bulk_requests','bulk_children')`).Scan(&indexes); err != nil {
		t.Fatal(err)
	}
	oids := []uint32{25, 20, 25, 17, 25, 20}
	t.Logf("PostgreSQL %s; synthetic same-scope parents=4097 children=10002; ten 1000-child histories; warm cache; sequential client; no concurrent writer; not a production latency estimate", version)
	t.Logf("actual migrated columns=%s; usable indexes=%s", columns, indexes)
	t.Logf("exact dependency SQL: read=%s; block=%s; cutoff skip=%s; fail=%s", bulkDependencyRead, bulkDependencyBlock, bulkDependencyCutoffSkip, bulkDependencyFail)
	t.Logf("actual Work binary OIDs=%v; binding representations=string(text parent,22 bytes),int(int8 ordinal,999),string(text command,22 bytes),[]byte(bytea fingerprint,32 bytes),string(text resource,22 bytes),int(int8 component order,999); mismatches preserve type", oids)
	t.Log("client samples include binary encoding and round trip, exclude fixture preparation and rollback; instrumented server timings are separate; each mutation sample rolls back")

	type dependencyCase struct {
		name, sql, initial, predecessor, wantStatus string
		fanIn, threshold                            int
		cutoff, change, outOfOrder                  bool
		mismatch                                    string
	}
	tests := []dependencyCase{
		{name: "read no dependencies", sql: bulkDependencyRead, initial: "admitted"},
		{name: "read sparse success", sql: bulkDependencyRead, initial: "admitted", fanIn: 1},
		{name: "read sparse failed", sql: bulkDependencyRead, initial: "admitted", fanIn: 1, predecessor: "failed"},
		{name: "read known failure behind earlier pending component", sql: bulkDependencyRead, initial: "admitted", fanIn: 1, predecessor: "failed", outOfOrder: true},
		{name: "read sparse pending", sql: bulkDependencyRead, initial: "admitted", fanIn: 1, predecessor: "admitted"},
		{name: "read missing predecessor", sql: bulkDependencyRead, initial: "dependency-blocked", fanIn: 1, predecessor: "missing"},
		{name: "read maximum success", sql: bulkDependencyRead, initial: "admitted", fanIn: 999},
		{name: "read maximum late failed", sql: bulkDependencyRead, initial: "admitted", fanIn: 999, predecessor: "failed"},
		{name: "read maximum late pending", sql: bulkDependencyRead, initial: "dependency-blocked", fanIn: 999, predecessor: "admitted"},
		{name: "read maximum missing predecessor at cutoff", sql: bulkDependencyRead, initial: "dependency-blocked", fanIn: 999, predecessor: "missing", cutoff: true},
		{name: "block sparse pending", sql: bulkDependencyBlock, initial: "admitted", fanIn: 1, predecessor: "admitted", wantStatus: "dependency-blocked", change: true},
		{name: "block maximum pending", sql: bulkDependencyBlock, initial: "admitted", fanIn: 999, predecessor: "admitted", wantStatus: "dependency-blocked", change: true},
		{name: "block cutoff rejects admitted", sql: bulkDependencyBlock, initial: "admitted", fanIn: 1, cutoff: true},
		{name: "block repeated checkpoint", sql: bulkDependencyBlock, initial: "dependency-blocked", fanIn: 1},
		{name: "skip sparse blocked at cutoff", sql: bulkDependencyCutoffSkip, initial: "dependency-blocked", fanIn: 1, cutoff: true, wantStatus: "skipped", change: true},
		{name: "skip maximum blocked at cutoff", sql: bulkDependencyCutoffSkip, initial: "dependency-blocked", fanIn: 999, cutoff: true, wantStatus: "skipped", change: true},
		{name: "skip without cutoff", sql: bulkDependencyCutoffSkip, initial: "dependency-blocked", fanIn: 1},
		{name: "skip rejects admitted", sql: bulkDependencyCutoffSkip, initial: "admitted", fanIn: 1, cutoff: true},
		{name: "fail sparse admitted", sql: bulkDependencyFail, initial: "admitted", fanIn: 1, predecessor: "failed", wantStatus: "failed", change: true},
		{name: "fail known dependency cannot overtake earlier pending component", sql: bulkDependencyFail, initial: "admitted", fanIn: 1, predecessor: "failed", outOfOrder: true},
		{name: "fail maximum blocked late failure reaches cutoff", sql: bulkDependencyFail, initial: "dependency-blocked", fanIn: 999, predecessor: "failed", threshold: 2, wantStatus: "failed", change: true},
		{name: "fail blocked survives cutoff", sql: bulkDependencyFail, initial: "dependency-blocked", fanIn: 1, predecessor: "failed", cutoff: true, wantStatus: "failed", change: true},
		{name: "fail admitted rejects cutoff", sql: bulkDependencyFail, initial: "admitted", fanIn: 1, predecessor: "failed", cutoff: true},
		{name: "fail maximum successful predecessors", sql: bulkDependencyFail, initial: "dependency-blocked", fanIn: 999},
		{name: "fail pending predecessor", sql: bulkDependencyFail, initial: "dependency-blocked", fanIn: 1, predecessor: "admitted"},
		{name: "fail missing predecessor", sql: bulkDependencyFail, initial: "dependency-blocked", fanIn: 1, predecessor: "missing"},
	}
	for _, statement := range []struct{ name, sql string }{{"read", bulkDependencyRead}, {"block", bulkDependencyBlock}, {"skip", bulkDependencyCutoffSkip}, {"fail", bulkDependencyFail}} {
		for _, mismatch := range []string{"ordinal", "fingerprint", "component", "parent"} {
			tests = append(tests, dependencyCase{name: statement.name + " mismatched " + mismatch, sql: statement.sql, initial: "dependency-blocked", fanIn: 999, predecessor: "failed", cutoff: true, mismatch: mismatch})
		}
		tests = append(tests, dependencyCase{name: statement.name + " terminal child", sql: statement.sql, initial: "succeeded", fanIn: 1, predecessor: "failed"})
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var elapsed [3]time.Duration
			var executionMS [3]float64
			for sample := range elapsed {
				withBulkMutationPlanTransaction(t, ctx, connection.Conn(), func(tx pgx.Tx) {
					if _, err := tx.Exec(ctx, `UPDATE scim.bulk_children SET status=$2,
 result_code=CASE WHEN $2='succeeded' THEN 201::smallint END,
 result_resource_id=CASE WHEN $2='succeeded' THEN resource_id END,
 result_version=CASE WHEN $2='succeeded' THEN '"'||command_id||'"' END,
 dependency_ids=ARRAY(SELECT CASE WHEN ordinal=998 AND $4='missing' THEN repeat('x',22) ELSE command_id END
 FROM scim.bulk_children WHERE parent_id=$1 AND ordinal>=999-$3::integer AND ordinal<999 ORDER BY ordinal)
 WHERE parent_id=$1 AND ordinal=999`, parentID, test.initial, test.fanIn, test.predecessor); err != nil {
						t.Fatal("prepare selected dependency checkpoint", err)
					}
					if test.outOfOrder {
						if _, err := tx.Exec(ctx, `UPDATE scim.bulk_children SET dependency_ids=ARRAY(
 SELECT command_id FROM scim.bulk_children WHERE parent_id=$1 AND ordinal=997)
 WHERE parent_id=$1 AND ordinal=999`, parentID); err != nil {
							t.Fatal(err)
						}
						if _, err := tx.Exec(ctx, `UPDATE scim.bulk_children SET
 status=CASE WHEN ordinal=997 THEN 'failed' ELSE 'admitted' END,
 result_code=CASE WHEN ordinal=997 THEN 400::smallint END,result_resource_id=NULL,result_version=NULL
 WHERE parent_id=$1 AND ordinal IN (997,998)`, parentID); err != nil {
							t.Fatal(err)
						}
					} else if test.predecessor == "failed" || test.predecessor == "admitted" {
						if _, err := tx.Exec(ctx, `UPDATE scim.bulk_children SET status=$2,
 result_code=CASE WHEN $2='failed' THEN 400::smallint END,result_resource_id=NULL,result_version=NULL
 WHERE parent_id=$1 AND ordinal=998`, parentID, test.predecessor); err != nil {
							t.Fatal(err)
						}
					}
					initialCount := 0
					if test.cutoff || test.predecessor == "failed" {
						initialCount = 1
					}
					threshold := test.threshold
					if test.cutoff {
						threshold = 1
					}
					if _, err := tx.Exec(ctx, `UPDATE scim.bulk_requests SET fail_on_errors=$4,failed_count=$2,cutoff_active=$3 WHERE parent_id=$1`, parentID, initialCount, test.cutoff, threshold); err != nil {
						t.Fatal(err)
					}
					var phase bulkChildExecution
					phase.parent = identity.CommandID(parentID)
					if err := tx.QueryRow(ctx, `SELECT ordinal,command_id,request_fingerprint,resource_id,component_order FROM scim.bulk_children
 WHERE parent_id=$1 AND ordinal=999`, parentID).Scan(&phase.row.Ordinal, &phase.row.Command, &phase.row.Fingerprint, &phase.row.Resource, &phase.row.ComponentOrder); err != nil {
						t.Fatal(err)
					}
					args := phase.args()
					switch test.mismatch {
					case "ordinal":
						args[1] = 1000
					case "fingerprint":
						fingerprint := append([]byte(nil), phase.row.Fingerprint...)
						fingerprint[0] ^= 1
						args[3] = fingerprint
					case "component":
						args[5] = 998
					case "parent":
						args[0] = "xxxxxxxxxxxxxxxxxxxxxx"
					}
					if _, err := tx.Exec(ctx, `SAVEPOINT dependency_plan`); err != nil {
						t.Fatal(err)
					}
					plan := explainBulkWorkInsert(t, ctx, tx, test.sql, oids, args)
					executionMS[sample] = requireBoundedBulkCycleQueryPlan(t, plan, float64(2*test.fanIn+4), sample == 0)
					if _, err := tx.Exec(ctx, `ROLLBACK TO SAVEPOINT dependency_plan; RELEASE SAVEPOINT dependency_plan`); err != nil {
						t.Fatal(err)
					}
					started := time.Now()
					result := executeBulkCycleQueryWork(t, ctx, tx, test.sql, oids, args)
					elapsed[sample] = time.Since(started)
					wantRows := int64(0)
					if test.change || test.sql == bulkDependencyRead && test.mismatch == "" {
						wantRows = 1
					}
					if result.CommandTag.RowsAffected() != wantRows {
						t.Fatal("dependency checkpoint selected the wrong row set", result.CommandTag.RowsAffected(), wantRows)
					}
					if test.sql == bulkDependencyRead && wantRows == 1 {
						want := []string{test.initial, bulkDependencyQueryBool(test.cutoff), bulkDependencyQueryBool(test.predecessor == "failed" && !test.outOfOrder), bulkDependencyQueryBool(test.predecessor == "admitted" || test.predecessor == "missing")}
						if len(result.Rows) != 1 || len(result.Rows[0]) != len(want) {
							t.Fatal("dependency read did not return exactly one typed state")
						}
						for index := range want {
							if string(result.Rows[0][index]) != want[index] {
								t.Fatal("dependency read returned the wrong selected state", index)
							}
						}
					}
					wantStatus, wantCount, wantCutoff := test.initial, initialCount, test.cutoff
					if test.change {
						wantStatus = test.wantStatus
						if test.sql == bulkDependencyFail {
							wantCount++
							wantCutoff = test.cutoff || threshold > 0 && wantCount >= threshold
							if len(result.Rows) != 1 || len(result.Rows[0]) != 1 || string(result.Rows[0][0]) != bulkDependencyQueryBool(wantCutoff) {
								t.Fatal("dependency failure did not return its exact cutoff state")
							}
						}
						if duplicate := executeBulkCycleQueryWork(t, ctx, tx, test.sql, oids, args); duplicate.CommandTag.RowsAffected() != 0 {
							t.Fatal("dependency mutation replay changed an already checkpointed child")
						}
					}
					var status string
					var code *int16
					var skip string
					var count int
					var cutoff bool
					if err := tx.QueryRow(ctx, `SELECT child.status,child.result_code,child.skip_reason,parent.failed_count,parent.cutoff_active
 FROM scim.bulk_children child JOIN scim.bulk_requests parent USING(parent_id)
 WHERE child.parent_id=$1 AND child.ordinal=999`, parentID).Scan(&status, &code, &skip, &count, &cutoff); err != nil || status != wantStatus || count != wantCount || cutoff != wantCutoff {
						t.Fatal("dependency checkpoint or replay changed the wrong status, counter or cutoff", status, count, cutoff, err)
					}
					wantSkip := "none"
					if status == "skipped" {
						wantSkip = "fail-on-errors"
					}
					if skip != wantSkip {
						t.Fatal("dependency checkpoint retained the wrong skip reason", skip)
					}
					switch status {
					case "failed", "succeeded":
						wantCode := int16(424)
						if status == "succeeded" {
							wantCode = 201
						}
						if code == nil || *code != wantCode {
							t.Fatal("dependency checkpoint retained the wrong typed terminal result")
						}
					default:
						if code != nil {
							t.Fatal("nonterminal dependency checkpoint retained a result code")
						}
					}
				})
			}
			t.Logf("fan-in=%d; actual Work client samples=%v; instrumented server execution ms=%v; all samples rolled back", test.fanIn, elapsed, executionMS)
		})
	}
	var parents, children, succeeded, failedCount, cutoffParents, groups int
	if err := connection.QueryRow(ctx, `SELECT (SELECT count(*) FROM scim.bulk_requests),(SELECT count(*) FROM scim.bulk_children),
 (SELECT count(*) FROM scim.bulk_children WHERE status='succeeded'),(SELECT sum(failed_count) FROM scim.bulk_requests),
 (SELECT count(*) FROM scim.bulk_requests WHERE cutoff_active),(SELECT count(*) FROM scim.groups)`).Scan(&parents, &children, &succeeded, &failedCount, &cutoffParents, &groups); err != nil || parents != 4097 || children != 10002 || succeeded != 10000 || failedCount != 0 || cutoffParents != 0 || groups != 0 {
		t.Fatal("dependency measurements escaped rollback or changed retained history", parents, children, succeeded, failedCount, cutoffParents, groups, err)
	}
}

func bulkDependencyQueryBool(value bool) string {
	if value {
		return "t"
	}
	return "f"
}
