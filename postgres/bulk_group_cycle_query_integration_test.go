//go:build integration

package scimpostgres

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	identity "github.com/faustbrian/go-identity"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgtype"
)

// The cycle operation has no predecessor SQL. These samples measure its three
// incremental checkpoints; the cycle execution tests prove the owning operation.
func TestNativeGroupBulkCycleBoundedCheckpointQueryPlans(t *testing.T) {
	f, service := bulkChildExecutionFixture(t)
	ctx, cancel := context.WithTimeout(f.ctx, 45*time.Second)
	defer cancel()
	parent, err := service.Admit(ctx, BulkAdmissionRequest{Credential: f.bearer, Body: []byte(dependentGroupBulkFixture)})
	if err != nil {
		t.Fatal("admit native parent before seeding retained cycle history", err)
	}
	connection, err := f.pool.Raw().Acquire(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer connection.Release()
	if _, err := connection.Exec(ctx, `INSERT INTO scim.bulk_requests
 (tenant_id,organization_id,provider_id,connection_id,parent_id,intent_digest,configuration_digest,response_bytes,child_count,fail_on_errors,created_at)
 SELECT tenant_id,organization_id,provider_id,connection_id,
 translate(rtrim(encode(decode(md5('bulk-cycle-plan-parent-'||n),'hex'),'base64'),'='),'+/','-_'),
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
 JOIN scim.bulk_requests p ON p.parent_id=translate(rtrim(encode(decode(md5('bulk-cycle-plan-parent-'||n),'hex'),'base64'),'='),'+/','-_')
 CROSS JOIN LATERAL (
  SELECT ordinal,
   translate(rtrim(encode(decode(md5('bulk-cycle-plan-command-'||n||'-'||ordinal),'hex'),'base64'),'='),'+/','-_') command_id,
   sha256(convert_to('bulk-cycle-plan-fingerprint-'||n||'-'||ordinal,'UTF8')) fingerprint,
   translate(rtrim(encode(decode(md5('bulk-cycle-plan-resource-'||n||'-'||ordinal),'hex'),'base64'),'='),'+/','-_') resource_id
  FROM generate_series(0,999) ordinal
 ) c`); err != nil {
		t.Fatal("seed bounded maximum retained child histories", err)
	}
	if _, err := connection.Exec(ctx, `ANALYZE scim.bulk_requests; ANALYZE scim.bulk_children`); err != nil {
		t.Fatal(err)
	}
	var parentID, version, columns, indexes string
	if err := connection.QueryRow(ctx, `SELECT parent_id FROM scim.bulk_requests
 WHERE parent_id=translate(rtrim(encode(decode(md5('bulk-cycle-plan-parent-1'),'hex'),'base64'),'='),'+/','-_')`).Scan(&parentID); err != nil {
		t.Fatal(err)
	}
	if err := connection.QueryRow(ctx, `SHOW server_version`).Scan(&version); err != nil {
		t.Fatal(err)
	}
	if err := connection.QueryRow(ctx, `SELECT string_agg(table_name||'.'||column_name||'='||data_type,', ' ORDER BY table_name,column_name)
 FROM information_schema.columns WHERE table_schema='scim' AND table_name IN ('bulk_requests','bulk_children')
 AND column_name IN ('parent_id','ordinal','command_id','request_fingerprint','resource_id','component_order','component_id',
 'dependency_ids','cyclic','status','result_code','failed_count','fail_on_errors','cutoff_active')`).Scan(&columns); err != nil {
		t.Fatal(err)
	}
	if err := connection.QueryRow(ctx, `SELECT string_agg(indexdef,'; ' ORDER BY indexname)
 FROM pg_indexes WHERE schemaname='scim' AND tablename IN ('bulk_requests','bulk_children')`).Scan(&indexes); err != nil {
		t.Fatal(err)
	}
	childOIDs := []uint32{25, 20, 25, 17, 25, 20, 20}
	parentOIDs := []uint32{25, 20, 20, 20}
	t.Logf("PostgreSQL %s; synthetic same-scope parents=4097 children=10002; ten maximum 1000-child histories; warm cache; sequential client; no concurrent writer; not a production latency estimate", version)
	t.Log("statistics collected from retained terminal histories before rollback samples; client samples include binary encoding and round trip, exclude setup and rollback; EXPLAIN server execution is separate")
	t.Logf("actual migrated columns=%s; usable indexes=%s", columns, indexes)
	t.Logf("cycle start SQL=%s; cycle child failure SQL=%s; actual Work binary OIDs=%v; Go bindings=string,int,string,[]byte,string,int,int", bulkCycleChildStart, bulkCycleChildFail, childOIDs)
	t.Logf("cycle parent failure SQL=%s; actual Work binary OIDs=%v; Go bindings=string,int,int,int; explicit integer cast narrows the final int8 parameter", bulkCycleParentFail, parentOIDs)

	for _, statement := range []struct {
		name, sql, status, peerStatus string
	}{
		{name: "child start", sql: bulkCycleChildStart, status: "running", peerStatus: "running"},
		{name: "child failure", sql: bulkCycleChildFail, status: "failed", peerStatus: "failed"},
	} {
		t.Run(statement.name, func(t *testing.T) {
			for _, test := range []struct {
				name, external, mismatch string
				size                     int
				peerProgress, priorOpen  bool
				terminal, wantChange     bool
			}{
				{name: "sparse late two-member cycle", size: 2, wantChange: true},
				{name: "dense maximum cycle and dependency fan-in", size: 1000, wantChange: true},
				{name: "in-cycle peer already progressed", size: 2, peerProgress: true, wantChange: true},
				{name: "external dependency succeeded", size: 2, external: "succeeded", wantChange: true},
				{name: "external dependency missing", size: 2, external: "missing"},
				{name: "external dependency admitted", size: 2, external: "admitted"},
				{name: "immediate prior component admitted", size: 2, priorOpen: true},
				{name: "selected fingerprint mismatch", size: 2, mismatch: "fingerprint"},
				{name: "selected ordinal missing", size: 2, mismatch: "ordinal"},
				{name: "selected component mismatch", size: 2, mismatch: "component"},
				{name: "selected terminal checkpoint", size: 2, terminal: true},
			} {
				t.Run(test.name, func(t *testing.T) {
					var elapsed [3]time.Duration
					var executionMS [3]float64
					for sample := range elapsed {
						withBulkMutationPlanTransaction(t, ctx, connection.Conn(), func(tx pgx.Tx) {
							phase := prepareBulkCycleQueryComponent(t, ctx, tx, parentID, test.size)
							if test.peerProgress {
								if _, err := tx.Exec(ctx, `UPDATE scim.bulk_children SET status=$3,result_code=CASE WHEN $3='failed' THEN 424::smallint END
 WHERE parent_id=$1 AND ordinal=$2`, parentID, phase.row.ComponentOrder, statement.peerStatus); err != nil {
									t.Fatal(err)
								}
							}
							if test.external != "" {
								if _, err := tx.Exec(ctx, `UPDATE scim.bulk_children SET dependency_ids=array_append(dependency_ids,
 CASE WHEN $2 THEN repeat('x',22) ELSE (SELECT command_id FROM scim.bulk_children WHERE parent_id=$1 AND ordinal=0) END)
 WHERE parent_id=$1 AND ordinal=999`, parentID, test.external == "missing"); err != nil {
									t.Fatal(err)
								}
							}
							if test.external == "admitted" || test.priorOpen {
								ordinal := 0
								if test.priorOpen {
									ordinal = phase.row.ComponentOrder - 1
								}
								if _, err := tx.Exec(ctx, `UPDATE scim.bulk_children SET status='admitted',result_code=NULL,result_resource_id=NULL,result_version=NULL
 WHERE parent_id=$1 AND ordinal=$2`, parentID, ordinal); err != nil {
									t.Fatal(err)
								}
							}
							if test.terminal {
								if _, err := tx.Exec(ctx, `UPDATE scim.bulk_children SET status='succeeded',result_code=201,result_resource_id=resource_id,result_version='"'||command_id||'"'
 WHERE parent_id=$1 AND ordinal=999`, parentID); err != nil {
									t.Fatal(err)
								}
							}
							args := append(phase.args(), phase.row.ComponentID)
							switch test.mismatch {
							case "fingerprint":
								fingerprint := append([]byte(nil), phase.row.Fingerprint...)
								fingerprint[0] ^= 1
								args[3] = fingerprint
							case "ordinal":
								args[1] = 1000
							case "component":
								args[6] = phase.row.ComponentID - 1
							}
							if _, err := tx.Exec(ctx, `SAVEPOINT cycle_plan`); err != nil {
								t.Fatal(err)
							}
							plan := explainBulkWorkInsert(t, ctx, tx, statement.sql, childOIDs, args)
							executionMS[sample] = requireBoundedBulkCycleQueryPlan(t, plan, float64(2*test.size+8), sample == 0)
							if _, err := tx.Exec(ctx, `ROLLBACK TO SAVEPOINT cycle_plan; RELEASE SAVEPOINT cycle_plan`); err != nil {
								t.Fatal(err)
							}
							started := time.Now()
							result := executeBulkCycleQueryWork(t, ctx, tx, statement.sql, childOIDs, args)
							elapsed[sample] = time.Since(started)
							wantRows, wantStatus := int64(0), "admitted"
							if test.wantChange {
								wantRows, wantStatus = 1, statement.status
							} else if test.terminal {
								wantStatus = "succeeded"
							}
							if result.CommandTag.RowsAffected() != wantRows {
								t.Fatal("cycle checkpoint changed the wrong selected row set", result.CommandTag.RowsAffected(), wantRows)
							}
							var status string
							var code *int16
							var count int
							if err := tx.QueryRow(ctx, `SELECT child.status,child.result_code,parent.failed_count
 FROM scim.bulk_children child JOIN scim.bulk_requests parent USING(parent_id)
 WHERE child.parent_id=$1 AND child.ordinal=999`, parentID).Scan(&status, &code, &count); err != nil || status != wantStatus || count != 0 {
								t.Fatal("cycle child checkpoint changed status or counted the parent prematurely", status, count, err)
							}
							if (status == "failed" && (code == nil || *code != 424)) ||
								(status == "succeeded" && (code == nil || *code != 201)) ||
								((status == "admitted" || status == "running") && code != nil) {
								t.Fatal("cycle child checkpoint retained the wrong typed result")
							}
						})
					}
					t.Logf("actual Work client samples=%v; instrumented server execution ms=%v; each sample rolled back", elapsed, executionMS)
				})
			}
		})
	}

	t.Run("parent failure", func(t *testing.T) {
		for _, test := range []struct {
			name, mismatch            string
			size, threshold           int
			incomplete, alreadyCutoff bool
			wantChange, wantCutoff    bool
		}{
			{name: "sparse complete component without cutoff", size: 2, wantChange: true},
			{name: "sparse complete component reaches cutoff", size: 2, threshold: 1, wantChange: true, wantCutoff: true},
			{name: "dense maximum component reaches cutoff", size: 1000, threshold: 100, wantChange: true, wantCutoff: true},
			{name: "component not completely failed", size: 2, incomplete: true},
			{name: "failed member count mismatch", size: 2, mismatch: "count"},
			{name: "selected component missing", size: 2, mismatch: "component"},
			{name: "selected parent missing", size: 2, mismatch: "parent"},
			{name: "parent cutoff already active", size: 2, threshold: 1, alreadyCutoff: true, wantCutoff: true},
		} {
			t.Run(test.name, func(t *testing.T) {
				var elapsed [3]time.Duration
				var executionMS [3]float64
				for sample := range elapsed {
					withBulkMutationPlanTransaction(t, ctx, connection.Conn(), func(tx pgx.Tx) {
						phase := prepareBulkCycleQueryComponent(t, ctx, tx, parentID, test.size)
						if _, err := tx.Exec(ctx, `UPDATE scim.bulk_children SET status='failed',result_code=424
 WHERE parent_id=$1 AND cyclic AND component_id=$2`, parentID, phase.row.ComponentID); err != nil {
							t.Fatal(err)
						}
						if test.incomplete {
							if _, err := tx.Exec(ctx, `UPDATE scim.bulk_children SET status='admitted',result_code=NULL WHERE parent_id=$1 AND ordinal=999`, parentID); err != nil {
								t.Fatal(err)
							}
						}
						initialCount := 0
						if test.alreadyCutoff {
							initialCount = 1
						}
						if _, err := tx.Exec(ctx, `UPDATE scim.bulk_requests SET fail_on_errors=$2,failed_count=$3,cutoff_active=$4 WHERE parent_id=$1`, parentID, test.threshold, initialCount, test.alreadyCutoff); err != nil {
							t.Fatal(err)
						}
						args := []any{parentID, phase.row.ComponentOrder, phase.row.ComponentID, test.size}
						switch test.mismatch {
						case "count":
							args[3] = test.size + 1
						case "component":
							args[2] = phase.row.ComponentID - 1
						case "parent":
							args[0] = strings.Repeat("x", 22)
						}
						if _, err := tx.Exec(ctx, `SAVEPOINT cycle_plan`); err != nil {
							t.Fatal(err)
						}
						plan := explainBulkWorkInsert(t, ctx, tx, bulkCycleParentFail, parentOIDs, args)
						executionMS[sample] = requireBoundedBulkCycleQueryPlan(t, plan, 1000, sample == 0)
						if _, err := tx.Exec(ctx, `ROLLBACK TO SAVEPOINT cycle_plan; RELEASE SAVEPOINT cycle_plan`); err != nil {
							t.Fatal(err)
						}
						started := time.Now()
						result := executeBulkCycleQueryWork(t, ctx, tx, bulkCycleParentFail, parentOIDs, args)
						elapsed[sample] = time.Since(started)
						wantRows, wantCount := int64(0), initialCount
						if test.wantChange {
							wantRows, wantCount = 1, test.size
							wantReturned := "f"
							if test.wantCutoff {
								wantReturned = "t"
							}
							if len(result.Rows) != 1 || len(result.Rows[0]) != 1 || string(result.Rows[0][0]) != wantReturned {
								t.Fatal("cycle parent did not return the exact cutoff checkpoint")
							}
						} else if len(result.Rows) != 0 {
							t.Fatal("nonmatching cycle parent returned a checkpoint")
						}
						var count int
						var cutoff bool
						if err := tx.QueryRow(ctx, `SELECT failed_count,cutoff_active FROM scim.bulk_requests WHERE parent_id=$1`, parentID).Scan(&count, &cutoff); err != nil || count != wantCount || cutoff != test.wantCutoff || result.CommandTag.RowsAffected() != wantRows {
							t.Fatal("cycle parent count or cutoff bypassed the complete-component guard", count, cutoff, result.CommandTag.RowsAffected(), err)
						}
					})
				}
				t.Logf("actual Work client samples=%v; instrumented server execution ms=%v; each sample rolled back", elapsed, executionMS)
			})
		}
	})
	var parents, children, succeeded, cyclic, failedCount, cutoffParents int
	if err := connection.QueryRow(ctx, `SELECT (SELECT count(*) FROM scim.bulk_requests),(SELECT count(*) FROM scim.bulk_children),
 (SELECT count(*) FROM scim.bulk_children WHERE status='succeeded'),(SELECT count(*) FROM scim.bulk_children WHERE cyclic),
 (SELECT sum(failed_count) FROM scim.bulk_requests),(SELECT count(*) FROM scim.bulk_requests WHERE cutoff_active)`).Scan(&parents, &children, &succeeded, &cyclic, &failedCount, &cutoffParents); err != nil || parents != 4097 || children != 10002 || succeeded != 10000 || cyclic != 0 || failedCount != 0 || cutoffParents != 0 {
		t.Fatal("cycle measurements escaped rollback or changed retained history", parents, children, succeeded, cyclic, failedCount, cutoffParents, err)
	}
}

func prepareBulkCycleQueryComponent(t *testing.T, ctx context.Context, tx pgx.Tx, parentID string, size int) bulkChildExecution {
	t.Helper()
	start := 1000 - size
	if _, err := tx.Exec(ctx, `UPDATE scim.bulk_children child SET component_id=$2::integer,component_order=$2::integer,cyclic=true,
 status='admitted',result_code=NULL,result_resource_id=NULL,result_version=NULL,
 dependency_ids=ARRAY[(SELECT command_id FROM scim.bulk_children peer WHERE peer.parent_id=child.parent_id
 AND peer.ordinal=CASE WHEN child.ordinal=999 THEN $2::integer ELSE child.ordinal+1 END)]
 WHERE child.parent_id=$1 AND child.ordinal>=$2::integer`, parentID, start); err != nil {
		t.Fatal("prepare retained cyclic component", err)
	}
	// Only the selected member has dense fan-in, avoiding a redundant million-
	// edge fixture while exercising the maximum 999 dependency probes.
	if size == 1000 {
		if _, err := tx.Exec(ctx, `UPDATE scim.bulk_children SET dependency_ids=ARRAY(
 SELECT command_id FROM scim.bulk_children WHERE parent_id=$1 AND ordinal<999 ORDER BY ordinal)
 WHERE parent_id=$1 AND ordinal=999`, parentID); err != nil {
			t.Fatal(err)
		}
	}
	var phase bulkChildExecution
	phase.parent = identity.CommandID(parentID)
	if err := tx.QueryRow(ctx, `SELECT ordinal,command_id,request_fingerprint,resource_id,component_order,component_id
 FROM scim.bulk_children WHERE parent_id=$1 AND ordinal=999`, parentID).Scan(&phase.row.Ordinal, &phase.row.Command, &phase.row.Fingerprint, &phase.row.Resource, &phase.row.ComponentOrder, &phase.row.ComponentID); err != nil {
		t.Fatal("select actual retained cycle bindings", err)
	}
	return phase
}

func executeBulkCycleQueryWork(t *testing.T, ctx context.Context, tx pgx.Tx, sql string, oids []uint32, args []any) *pgconn.Result {
	t.Helper()
	codecs := pgtype.NewMap()
	values, formats := make([][]byte, len(args)), make([]int16, len(args))
	for index, value := range args {
		if number, ok := value.(int); ok {
			value = int64(number)
		}
		formats[index] = pgtype.BinaryFormatCode
		var err error
		values[index], err = codecs.Encode(oids[index], formats[index], value, nil)
		if err != nil {
			t.Fatal("encode actual Work cycle binding", index, err)
		}
	}
	result := tx.Conn().PgConn().ExecParams(ctx, sql, values, oids, formats, nil).Read()
	if result.Err != nil {
		t.Fatal("execute exact cycle SQL with native Work bindings", result.Err)
	}
	return result
}

func requireBoundedBulkCycleQueryPlan(t *testing.T, sanitized []byte, childBound float64, logPlan bool) float64 {
	t.Helper()
	var plan bulkQueryPlan
	if err := json.Unmarshal(sanitized, &plan); err != nil {
		t.Fatal("decode sanitized cycle checkpoint plan", err)
	}
	var childRows, parentRows float64
	var visit func(bulkQueryPlanNode)
	visit = func(node bulkQueryPlanNode) {
		if node.Loops > 0 && strings.Contains(node.NodeType, "Scan") && (node.Relation == "bulk_children" || node.Relation == "bulk_requests") {
			if node.NodeType == "Seq Scan" {
				t.Fatal("cycle checkpoint scanned unrelated retained history", string(sanitized))
			}
			examined := (node.Rows + node.Filtered) * node.Loops
			if node.Relation == "bulk_children" {
				childRows += examined
			} else {
				parentRows += examined
				if node.Index != "bulk_requests_pkey" {
					t.Fatal("cycle checkpoint did not use the exact parent key", string(sanitized))
				}
			}
		}
		for _, child := range node.Plans {
			visit(child)
		}
	}
	visit(plan.Plan)
	if childRows > childBound || parentRows > 2 {
		t.Fatal("cycle checkpoint work exceeded the selected graph or explicit dependency bound", childRows, parentRows, string(sanitized))
	}
	if logPlan {
		t.Logf("indexed cycle work children=%.0f parents=%.0f; sanitized plan=%s", childRows, parentRows, sanitized)
	}
	return plan.ExecutionMS
}
