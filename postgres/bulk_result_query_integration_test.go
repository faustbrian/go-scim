//go:build integration

package scimpostgres

import (
	"context"
	"encoding/json"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

	identity "github.com/faustbrian/go-identity"
	scim "github.com/faustbrian/go-scim"
	"github.com/jackc/pgx/v5"
)

// Synthetic terminal checkpoints isolate the exact retained-result query; the
// result integration tests separately prove authorization and response writing.
func TestNativeGroupBulkReadResultBoundedTerminalCheckpointQueryPlans(t *testing.T) {
	f, service := bulkChildExecutionFixture(t)
	ctx, cancel := context.WithTimeout(f.ctx, 30*time.Second)
	defer cancel()
	parent, err := service.Admit(ctx, BulkAdmissionRequest{Credential: f.bearer, Body: []byte(dependentGroupBulkFixture)})
	if err != nil {
		t.Fatal("admit native small graph before seeding retained history", err)
	}
	connection, err := f.pool.Raw().Acquire(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer connection.Release()
	if _, err := connection.Exec(ctx, `INSERT INTO scim.bulk_requests
 (tenant_id,organization_id,provider_id,connection_id,parent_id,intent_digest,configuration_digest,response_bytes,child_count,fail_on_errors,created_at)
 SELECT tenant_id,organization_id,provider_id,connection_id,
 translate(rtrim(encode(decode(md5('bulk-result-plan-parent-'||n),'hex'),'base64'),'='),'+/','-_'),
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
 JOIN scim.bulk_requests p ON p.parent_id=translate(rtrim(encode(decode(md5('bulk-result-plan-parent-'||n),'hex'),'base64'),'='),'+/','-_')
 CROSS JOIN LATERAL (
  SELECT ordinal,
   translate(rtrim(encode(decode(md5('bulk-result-plan-command-'||n||'-'||ordinal),'hex'),'base64'),'='),'+/','-_') command_id,
   sha256(convert_to('bulk-result-plan-fingerprint-'||n||'-'||ordinal,'UTF8')) fingerprint,
   translate(rtrim(encode(decode(md5('bulk-result-plan-resource-'||n||'-'||ordinal),'hex'),'base64'),'='),'+/','-_') resource_id
  FROM generate_series(0,999) ordinal
 ) c`); err != nil {
		t.Fatal("seed bounded maximum retained child histories", err)
	}
	if _, err := connection.Exec(ctx, `UPDATE scim.bulk_children
 SET status='succeeded',result_code=201,result_resource_id=resource_id,result_version='"'||command_id||'"'
 WHERE parent_id=$1`, string(parent.CommandID)); err != nil {
		t.Fatal("retain synthetic terminal checkpoints for the small graph", err)
	}
	if _, err := connection.Exec(ctx, `ANALYZE scim.bulk_requests; ANALYZE scim.bulk_children`); err != nil {
		t.Fatal(err)
	}
	var version, denseParent string
	if err := connection.QueryRow(ctx, `SHOW server_version`).Scan(&version); err != nil {
		t.Fatal(err)
	}
	if err := connection.QueryRow(ctx, `SELECT parent_id FROM scim.bulk_requests
 WHERE parent_id=translate(rtrim(encode(decode(md5('bulk-result-plan-parent-1'),'hex'),'base64'),'='),'+/','-_')`).Scan(&denseParent); err != nil {
		t.Fatal(err)
	}
	readDescription, err := connection.Conn().Prepare(ctx, "bulk-terminal-checkpoints-read", bulkTerminalCheckpoints)
	if err != nil {
		t.Fatal("prepare exact production terminal checkpoint query", err)
	}
	explainDescription, err := connection.Conn().Prepare(ctx, "bulk-terminal-checkpoints-explain", `EXPLAIN (ANALYZE, BUFFERS, FORMAT JSON) `+bulkTerminalCheckpoints)
	if err != nil {
		t.Fatal("prepare exact terminal checkpoint measurement", err)
	}
	if len(readDescription.ParamOIDs) != 11 || readDescription.ParamOIDs[10] != 1184 || !slices.Equal(readDescription.ParamOIDs, explainDescription.ParamOIDs) {
		t.Fatal("measurement did not preserve the raw pgx eleven-parameter profile", readDescription.ParamOIDs, explainDescription.ParamOIDs)
	}
	t.Logf("PostgreSQL %s; synthetic same-scope parents=10001 children=10002; native small graph has 2 children, ten retained graphs have 1000 children each; warm cache; sequential client; no concurrent writer", version)
	t.Logf("terminal checkpoint SQL=%s; actual raw pgx prepared parameter OIDs=%v; bulkParentArgs Go binding types=string,string,string,string,string,[]byte,[]byte,int,int,int,time.Time", bulkTerminalCheckpoints, readDescription.ParamOIDs)
	for _, test := range []struct {
		name           string
		parent         string
		children       int
		mismatchDigest bool
		missingParent  bool
	}{
		{name: "exact small terminal graph", parent: string(parent.CommandID), children: 2},
		{name: "exact maximum terminal graph", parent: denseParent, children: 1000},
		{name: "mismatched intent digest", parent: denseParent, children: 1000, mismatchDigest: true},
		{name: "missing parent", parent: denseParent, children: 1000, missingParent: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			var intent, profile []byte
			var maximum, count, cutoff int
			var created time.Time
			if err := connection.QueryRow(ctx, `SELECT intent_digest,configuration_digest,response_bytes,child_count,fail_on_errors,created_at
 FROM scim.bulk_requests WHERE parent_id=$1`, test.parent).Scan(&intent, &profile, &maximum, &count, &cutoff, &created); err != nil || count != test.children {
				t.Fatal("read retained parent's exact match inputs", count, err)
			}
			phase := nativePhase{service: f.service, original: originalInput{Command: identity.CommandID(test.parent), At: created},
				bulk: &bulkAdmissionPhase{children: make([]scim.BulkOperation, count), maximum: maximum, cutoff: cutoff}}
			copy(phase.bulk.intent[:], intent)
			copy(phase.bulk.profile[:], profile)
			args := phase.bulkParentArgs()
			if test.mismatchDigest {
				wrongDigest := append([]byte(nil), intent...)
				wrongDigest[0] ^= 1
				args[5] = wrongDigest
			}
			if test.missingParent {
				args[4] = strings.Repeat("x", 22)
			}
			var elapsed [3]time.Duration
			var executionMS [3]float64
			for sample := range elapsed {
				tx, err := connection.BeginTx(ctx, pgx.TxOptions{AccessMode: pgx.ReadOnly})
				if err != nil {
					t.Fatal(err)
				}
				func() {
					defer func() {
						cleanup, cancel := context.WithTimeout(context.Background(), 3*time.Second)
						defer cancel()
						if err := tx.Rollback(cleanup); err != nil {
							t.Error("rollback measured terminal checkpoint read", err)
						}
					}()
					want := queryBulkTerminalPlanRows(t, ctx, tx, `SELECT
 child.ordinal,child.command_id,child.request_fingerprint,child.resource_id,child.component_order,child.cyclic,
 child.status,child.skip_reason,child.result_code,child.result_resource_id,child.result_version,parent.failed_count,parent.cutoff_active
 FROM scim.bulk_children child JOIN scim.bulk_requests parent USING(parent_id)
 WHERE child.parent_id=$1 ORDER BY child.ordinal`, test.parent)
					if len(want) != test.children {
						t.Fatal("fixture lost the selected retained checkpoint set", len(want))
					}
					for ordinal, row := range want {
						r := row.checkpoint
						if r.ordinal != ordinal || r.status != "succeeded" || r.code == nil || *r.code != 201 || r.resource == nil || *r.resource != r.allocation || r.version == nil || *r.version != `"`+r.command+`"` || row.failed != 0 || row.cutoff {
							t.Fatal("fixture did not retain a complete ordered successful graph", ordinal)
						}
					}
					if test.mismatchDigest || test.missingParent {
						want = want[:0]
					}
					started := time.Now()
					got := queryBulkTerminalPlanRows(t, ctx, tx, "bulk-terminal-checkpoints-read", args...)
					elapsed[sample] = time.Since(started)
					if !reflect.DeepEqual(got, want) {
						t.Fatal("terminal read changed the selected ordered checkpoints or accepted a nonmatching parent", len(got), len(want))
					}
					var wire []byte
					if err := tx.QueryRow(ctx, "bulk-terminal-checkpoints-explain", args...).Scan(&wire); err != nil {
						t.Fatal("measure exact production terminal query with raw pgx bindings", err)
					}
					plan := parseBulkQueryPlan(t, wire)
					executionMS[sample] = plan.ExecutionMS
					requireBoundedBulkTerminalQueryPlan(t, plan.sanitized(t), test.children, len(want))
				}()
			}
			t.Logf("terminal read graph children=%d; actual raw pgx client samples=%v; EXPLAIN server execution ms=%v; read-only transactions rolled back", test.children, elapsed, executionMS)
		})
	}
	var parents, children, terminal, groups int
	if err := connection.QueryRow(ctx, `SELECT (SELECT count(*) FROM scim.bulk_requests),
 (SELECT count(*) FROM scim.bulk_children),(SELECT count(*) FROM scim.bulk_children WHERE status='succeeded'),
 (SELECT count(*) FROM scim.groups)`).Scan(&parents, &children, &terminal, &groups); err != nil || parents != 10001 || children != 10002 || terminal != 10002 || groups != 0 {
		t.Fatal("terminal query measurements changed retained history or Group projections", parents, children, terminal, groups, err)
	}
}

type bulkTerminalQueryRow struct {
	checkpoint bulkTerminalCheckpoint
	failed     int
	cutoff     bool
}

func queryBulkTerminalPlanRows(t *testing.T, ctx context.Context, tx pgx.Tx, statement string, args ...any) []bulkTerminalQueryRow {
	t.Helper()
	rows, err := tx.Query(ctx, statement, args...)
	if err != nil {
		t.Fatal("execute terminal checkpoint query", err)
	}
	defer rows.Close()
	result := make([]bulkTerminalQueryRow, 0)
	for rows.Next() {
		var row bulkTerminalQueryRow
		r := &row.checkpoint
		if err := rows.Scan(&r.ordinal, &r.command, &r.fingerprint, &r.allocation, &r.componentOrder, &r.cyclic,
			&r.status, &r.skipReason, &r.code, &r.resource, &r.version, &row.failed, &row.cutoff); err != nil {
			t.Fatal("scan actual retained terminal checkpoint", err)
		}
		result = append(result, row)
	}
	if err := rows.Err(); err != nil {
		t.Fatal("read complete terminal checkpoint set", err)
	}
	return result
}

func requireBoundedBulkTerminalQueryPlan(t *testing.T, sanitized []byte, maximumChildren, returned int) {
	t.Helper()
	var plan bulkQueryPlan
	if err := json.Unmarshal(sanitized, &plan); err != nil {
		t.Fatal("decode measured terminal checkpoint plan", err)
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
				t.Fatal("terminal read scanned unrelated retained history", string(sanitized))
			}
			examined := (node.Rows + node.Filtered) * node.Loops
			if node.Relation == "bulk_children" {
				childRows += examined
			} else {
				parentRows += examined
				if node.Index != "bulk_requests_pkey" {
					t.Fatal("terminal read did not use the exact parent key", string(sanitized))
				}
			}
		}
		for _, child := range node.Plans {
			visit(child)
		}
	}
	visit(plan.Plan)
	if plan.Plan.Rows != float64(returned) || parentRows > 1 || childRows > float64(maximumChildren) || (returned > 0 && !childIndexed) {
		t.Fatal("terminal checkpoint work exceeded one selected bounded graph", returned, childRows, parentRows, string(sanitized))
	}
	t.Logf("terminal read returned=%d examined children=%.0f parents=%.0f; sanitized plan=%s", returned, childRows, parentRows, sanitized)
}
