//go:build integration

package scimpostgres

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	identity "github.com/faustbrian/go-identity"
)

// Synthetic retained rows isolate the owner's exact predicates and index work;
// the execution integration tests separately prove Group/Work composition.
// Ten populated parents each retain the maximum 1,000 singleton components.
func TestNativeGroupBulkChildBoundedCheckpointQueryPlans(t *testing.T) {
	f, service := bulkChildExecutionFixture(t)
	parent, err := service.Admit(f.ctx, BulkAdmissionRequest{Credential: f.bearer, Body: []byte(dependentGroupBulkFixture)})
	if err != nil {
		t.Fatal("admit native parent before seeding retained history", err)
	}
	connection, err := f.pool.Raw().Acquire(f.ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer connection.Release()
	if _, err := connection.Exec(f.ctx, `INSERT INTO scim.bulk_requests
 (tenant_id,organization_id,provider_id,connection_id,parent_id,intent_digest,configuration_digest,response_bytes,child_count,fail_on_errors,created_at)
 SELECT tenant_id,organization_id,provider_id,connection_id,
 translate(rtrim(encode(decode(md5('bulk-child-plan-parent-'||n),'hex'),'base64'),'='),'+/','-_'),
 intent_digest,configuration_digest,response_bytes,1000,fail_on_errors,created_at
 FROM scim.bulk_requests CROSS JOIN generate_series(1,10000) n WHERE parent_id=$1`, string(parent.CommandID)); err != nil {
		t.Fatal("seed bounded same-scope retained parents", err)
	}
	if _, err := connection.Exec(f.ctx, `INSERT INTO scim.bulk_children
 (parent_id,ordinal,command_id,bulk_id,request_fingerprint,resource_id,component_id,component_order,cyclic,dependency_ids,
  status,result_code,result_resource_id,result_version)
 SELECT p.parent_id,c.ordinal,c.command_id,''::bytea,c.fingerprint,c.resource_id,c.ordinal,c.ordinal,false,ARRAY[]::text[],
 'succeeded',201,c.resource_id,'"'||c.command_id||'"'
 FROM generate_series(1,10) n
 JOIN scim.bulk_requests p ON p.parent_id=translate(rtrim(encode(decode(md5('bulk-child-plan-parent-'||n),'hex'),'base64'),'='),'+/','-_')
 CROSS JOIN LATERAL (
  SELECT ordinal,
   translate(rtrim(encode(decode(md5('bulk-child-plan-command-'||n||'-'||ordinal),'hex'),'base64'),'='),'+/','-_') command_id,
   sha256(convert_to('bulk-child-plan-fingerprint-'||n||'-'||ordinal,'UTF8')) fingerprint,
   translate(rtrim(encode(decode(md5('bulk-child-plan-resource-'||n||'-'||ordinal),'hex'),'base64'),'='),'+/','-_') resource_id
  FROM generate_series(0,999) ordinal
 ) c`); err != nil {
		t.Fatal("seed bounded maximum retained child histories", err)
	}
	if _, err := connection.Exec(f.ctx, `ANALYZE scim.bulk_requests; ANALYZE scim.bulk_children`); err != nil {
		t.Fatal(err)
	}
	var version string
	if err := connection.QueryRow(f.ctx, `SHOW server_version`).Scan(&version); err != nil {
		t.Fatal(err)
	}
	description, err := connection.Conn().Prepare(f.ctx, "bulk-child-read-plan", bulkChildCheckpointRead)
	if err != nil {
		t.Fatal("prepare production checkpoint read", err)
	}
	t.Logf("PostgreSQL %s; synthetic same-scope parents=10001 children=10002; 10 parents retain 1000 children each; warm cache; sequential client; no concurrent writer", version)
	t.Logf("checkpoint SQL=%s; actual pgx prepared parameter OIDs=%v; Go binding types=string,int,string,[]byte,string,int", bulkChildCheckpointRead, description.ParamOIDs)
	startOIDs := []uint32{25, 20, 25, 17, 25, 20}
	successOIDs := []uint32{25, 20, 25, 17, 25, 20, 25}
	t.Logf("start SQL=%s; Work binary parameter OIDs=%v", bulkChildStart, startOIDs)
	t.Logf("success SQL=%s; Work binary parameter OIDs=%v", bulkChildSucceed, successOIDs)

	for _, test := range []struct {
		name       string
		ordinal    int
		dependency bool
		blocked    int
		terminal   bool
	}{
		{name: "first ready", ordinal: 0, blocked: -1},
		{name: "late ready", ordinal: 999, blocked: -1},
		{name: "late previous not ready", ordinal: 999, blocked: 998},
		{name: "late explicit dependency ready", ordinal: 999, dependency: true, blocked: -1},
		{name: "late explicit dependency not ready", ordinal: 999, dependency: true, blocked: 0},
		{name: "late terminal replay", ordinal: 999, blocked: -1, terminal: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			var phase bulkChildExecution
			var parentID string
			err := connection.QueryRow(f.ctx, `SELECT parent_id,ordinal,command_id,request_fingerprint,resource_id,component_order
 FROM scim.bulk_children
 WHERE parent_id=translate(rtrim(encode(decode(md5('bulk-child-plan-parent-1'),'hex'),'base64'),'='),'+/','-_')
 AND ordinal=$1`, test.ordinal).Scan(&parentID, &phase.row.Ordinal, &phase.row.Command, &phase.row.Fingerprint, &phase.row.Resource, &phase.row.ComponentOrder)
			if err != nil {
				t.Fatal("select actual retained child bindings", err)
			}
			phase.parent = identity.CommandID(parentID)
			version := `"` + phase.row.Command + `"`
			var readElapsed, startElapsed, successElapsed [3]time.Duration
			for sample := range readElapsed {
				tx, err := connection.Begin(f.ctx)
				if err != nil {
					t.Fatal(err)
				}
				func() {
					defer func() {
						cleanup, cancel := context.WithTimeout(context.Background(), 3*time.Second)
						defer cancel()
						if err := tx.Rollback(cleanup); err != nil {
							t.Error("rollback measured child checkpoints", err)
						}
					}()
					const reset = `UPDATE scim.bulk_children SET status='admitted',result_code=NULL,result_resource_id=NULL,result_version=NULL WHERE parent_id=$1 AND ordinal=$2`
					if !test.terminal {
						if _, err := tx.Exec(f.ctx, reset, parentID, test.ordinal); err != nil {
							t.Fatal(err)
						}
					}
					if test.blocked >= 0 {
						if _, err := tx.Exec(f.ctx, reset, parentID, test.blocked); err != nil {
							t.Fatal(err)
						}
					}
					if test.dependency {
						if _, err := tx.Exec(f.ctx, `UPDATE scim.bulk_children SET dependency_ids=ARRAY[
 (SELECT command_id FROM scim.bulk_children WHERE parent_id=$1 AND ordinal=0)]
 WHERE parent_id=$1 AND ordinal=$2`, parentID, test.ordinal); err != nil {
							t.Fatal(err)
						}
					}
					args := phase.args()
					wantReady := test.blocked < 0
					var status string
					var code *int16
					var resource, resultVersion *string
					var ready bool
					started := time.Now()
					err := tx.QueryRow(f.ctx, "bulk-child-read-plan", args...).Scan(&status, &code, &resource, &resultVersion, &ready)
					readElapsed[sample] = time.Since(started)
					if err != nil || ready != wantReady {
						t.Fatal("production checkpoint read changed readiness", ready, err)
					}
					if test.terminal {
						if status != "succeeded" || code == nil || *code != 201 || resource == nil || *resource != phase.row.Resource || resultVersion == nil || *resultVersion != version {
							t.Fatal("terminal read did not recover the exact checkpoint")
						}
					} else if status != "admitted" || code != nil || resource != nil || resultVersion != nil {
						t.Fatal("admitted checkpoint acquired a terminal result")
					}
					if sample == 0 {
						var wire []byte
						if err := tx.QueryRow(f.ctx, `EXPLAIN (ANALYZE, BUFFERS, FORMAT JSON) `+bulkChildCheckpointRead, args...).Scan(&wire); err != nil {
							t.Fatal("measure exact checkpoint read", err)
						}
						requireBoundedBulkChildQueryPlan(t, parseBulkQueryPlan(t, wire).sanitized(t))
					}
					started = time.Now()
					startPlan := explainBulkWorkInsert(t, f.ctx, tx, bulkChildStart, startOIDs, args)
					startElapsed[sample] = time.Since(started)
					if sample == 0 {
						requireBoundedBulkChildQueryPlan(t, startPlan)
					}
					if err := tx.QueryRow(f.ctx, `SELECT status FROM scim.bulk_children WHERE parent_id=$1 AND ordinal=$2`, parentID, test.ordinal).Scan(&status); err != nil {
						t.Fatal(err)
					}
					wantStatus := "admitted"
					if test.terminal {
						wantStatus = "succeeded"
					} else if wantReady {
						wantStatus = "running"
					}
					if status != wantStatus {
						t.Fatal("production start changed a blocked or terminal child", status, wantStatus)
					}
					started = time.Now()
					successPlan := explainBulkWorkInsert(t, f.ctx, tx, bulkChildSucceed, successOIDs, append(args, version))
					successElapsed[sample] = time.Since(started)
					if sample == 0 {
						requireBoundedBulkChildQueryPlan(t, successPlan)
					}
					if err := tx.QueryRow(f.ctx, "bulk-child-read-plan", args...).Scan(&status, &code, &resource, &resultVersion, &ready); err != nil {
						t.Fatal(err)
					}
					if test.terminal || wantReady {
						if status != "succeeded" || code == nil || *code != 201 || resource == nil || *resource != phase.row.Resource || resultVersion == nil || *resultVersion != version {
							t.Fatal("production success did not retain the original typed checkpoint")
						}
					} else if status != "admitted" || code != nil || resource != nil || resultVersion != nil {
						t.Fatal("success checkpoint bypassed the production start guard")
					}
				}()
			}
			t.Logf("checkpoint read client samples=%v; instrumented Work start samples=%v; instrumented Work success samples=%v; each transaction rolled back", readElapsed, startElapsed, successElapsed)
		})
	}
	var succeeded, groups int
	if err := connection.QueryRow(f.ctx, `SELECT (SELECT count(*) FROM scim.bulk_children WHERE status='succeeded'),(SELECT count(*) FROM scim.groups)`).Scan(&succeeded, &groups); err != nil || succeeded != 10000 || groups != 0 {
		t.Fatal("measurement escaped rollback or changed Group projections", succeeded, groups, err)
	}
}

func requireBoundedBulkChildQueryPlan(t *testing.T, sanitized []byte) {
	t.Helper()
	var plan bulkQueryPlan
	if err := json.Unmarshal(sanitized, &plan); err != nil {
		t.Fatal("decode sanitized checkpoint plan", err)
	}
	var childRows, parentRows float64
	var childIndexed bool
	var visit func(bulkQueryPlanNode)
	visit = func(node bulkQueryPlanNode) {
		if node.Loops > 0 && (node.Relation == "bulk_children" || node.Relation == "bulk_requests") {
			if node.NodeType == "Seq Scan" {
				t.Fatal("checkpoint scanned retained history instead of an exact index", string(sanitized))
			}
			if strings.Contains(node.NodeType, "Scan") {
				examined := (node.Rows + node.Filtered) * node.Loops
				if node.Relation == "bulk_children" {
					childRows += examined
					childIndexed = childIndexed || node.Index != ""
				} else {
					parentRows += examined
					if node.Index != "bulk_requests_pkey" {
						t.Fatal("checkpoint did not use the exact parent key", string(sanitized))
					}
				}
			}
		}
		for _, child := range node.Plans {
			visit(child)
		}
	}
	visit(plan.Plan)
	// A singleton needs one selected-child lookup, at most two immediate-prior
	// probes and one explicit-dependency lookup, not the 999-row succeeded prefix.
	if !childIndexed || childRows > 8 || parentRows > 2 {
		t.Fatal("checkpoint work grew with the completed prefix", childRows, parentRows, string(sanitized))
	}
	t.Logf("indexed checkpoint work children=%.0f parents=%.0f; sanitized plan=%s", childRows, parentRows, sanitized)
}
