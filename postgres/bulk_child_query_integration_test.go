//go:build integration

package scimpostgres

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	identity "github.com/faustbrian/go-identity"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
)

// Synthetic retained rows isolate the owner's exact predicates and index work;
// the execution integration tests separately prove Group/Work composition.
// Ten populated parents each retain the maximum 1,000 singleton components.
func TestNativeGroupBulkChildBoundedCheckpointQueryPlans(t *testing.T) {
	f, service := bulkChildExecutionFixture(t)
	installBulkGroupMutationSchema(t, f)
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
	t.Logf("reconciliation checkpoint uses the same SQL with Work binary parameter OIDs=%v", startOIDs)
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
			var readElapsed, reconciliationElapsed, startElapsed, successElapsed [3]time.Duration
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
					reconciliationPlan := explainBulkWorkInsert(t, f.ctx, tx, bulkChildCheckpointRead, startOIDs, args)
					reconciliationElapsed[sample] = time.Since(started)
					if sample == 0 {
						requireBoundedBulkChildQueryPlan(t, reconciliationPlan)
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
			t.Logf("checkpoint read client samples=%v; instrumented Work reconciliation read=%v; instrumented Work start=%v; instrumented Work success=%v; each transaction rolled back", readElapsed, reconciliationElapsed, startElapsed, successElapsed)
		})
	}
	t.Run("Group mutation input and success", func(t *testing.T) {
		measureBulkGroupMutationQueries(t, f.ctx, connection.Conn())
	})
	var succeeded, groups, retainedInputs int
	if err := connection.QueryRow(f.ctx, `SELECT (SELECT count(*) FROM scim.bulk_children WHERE status='succeeded'),
 (SELECT count(*) FROM scim.groups),(SELECT count(*) FROM scim.bulk_children WHERE group_mutation_input IS NOT NULL)`).Scan(&succeeded, &groups, &retainedInputs); err != nil || succeeded != 10000 || groups != 0 || retainedInputs != 0 {
		t.Fatal("measurement escaped rollback or changed Group projections", succeeded, groups, retainedInputs, err)
	}
}

func measureBulkGroupMutationQueries(t *testing.T, ctx context.Context, connection *pgx.Conn) {
	t.Helper()
	readDescription, err := connection.Prepare(ctx, "bulk-mutation-input-read-plan", readBulkMutationInput)
	if err != nil {
		t.Fatal("prepare production mutation input read", err)
	}
	retainDescription, err := connection.Prepare(ctx, "bulk-mutation-input-retain-plan", retainBulkMutationInput)
	if err != nil {
		t.Fatal("prepare production mutation input retention", err)
	}
	t.Logf("mutation input read SQL=%s; actual pgx parameter OIDs=%v; Go binding types=string,int,string,[]byte,string,int", readBulkMutationInput, readDescription.ParamOIDs)
	t.Logf("mutation input retention SQL=%s; actual pgx parameter OIDs=%v; Go binding types=string,int,string,[]byte,string,int,[]byte,time.Time", retainBulkMutationInput, retainDescription.ParamOIDs)
	successOIDs := []uint32{25, 20, 25, 17, 25, 20, 20, 25, 25}
	t.Logf("mutation success SQL=%s; Work binary parameter OIDs=%v", bulkGroupMutationSucceed, successOIDs)

	// Use the real encrypted representation, not compressible zero padding, so
	// returning and writing the pre-image exercise PostgreSQL's bytea/TOAST work.
	codec, input, originalParent := bulkMutationInputCodec(t)
	input.Current.Attributes["displayName"] = strings.Repeat("group projection ", 4096)
	ciphertext, err := codec.sealBulkMutationInput(ctx, input, originalParent)
	if err != nil || len(ciphertext) < 64*1024 {
		t.Fatal("seal representative enlarged Group pre-image", err)
	}
	defer clear(ciphertext)
	t.Logf("synthetic sealed Group pre-image bytes=%d; same 10000-child history and 1000-child graph; 3 warm sequential samples; no concurrent writer", len(ciphertext))
	childArgs := func(ordinal int) []any {
		var parent, command, resource string
		var fingerprint []byte
		var component int
		if err := connection.QueryRow(ctx, `SELECT parent_id,command_id,request_fingerprint,resource_id,component_order
 FROM scim.bulk_children WHERE parent_id=translate(rtrim(encode(decode(md5('bulk-child-plan-parent-1'),'hex'),'base64'),'='),'+/','-_')
 AND ordinal=$1`, ordinal).Scan(&parent, &command, &fingerprint, &resource, &component); err != nil {
			t.Fatal("select actual mutation checkpoint bindings", err)
		}
		return []any{parent, ordinal, command, fingerprint, resource, component}
	}
	for _, test := range []struct {
		name     string
		retained bool
		missing  bool
	}{
		{name: "unprepared read"},
		{name: "retained enlarged input read", retained: true},
		{name: "binding miss read", retained: true, missing: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			args := childArgs(999)
			returned := 1
			if test.missing {
				returned = 0
			}
			var elapsed [3]time.Duration
			for sample := range elapsed {
				withBulkMutationPlanTransaction(t, ctx, connection, func(tx pgx.Tx) {
					if test.retained {
						if _, err := tx.Exec(ctx, `UPDATE scim.bulk_children SET group_mutation_input=$3 WHERE parent_id=$1 AND ordinal=$2`, args[0], args[1], ciphertext); err != nil {
							t.Fatal(err)
						}
					}
					queryArgs := append([]any(nil), args...)
					if test.missing {
						queryArgs[2] = "another-command"
					}
					var retained []byte
					started := time.Now()
					err := tx.QueryRow(ctx, "bulk-mutation-input-read-plan", queryArgs...).Scan(&retained)
					elapsed[sample] = time.Since(started)
					defer clear(retained)
					if test.missing {
						if !errors.Is(err, pgx.ErrNoRows) {
							t.Fatal("binding miss returned a retained input", err)
						}
					} else if err != nil || test.retained && !bytes.Equal(retained, ciphertext) || !test.retained && retained != nil {
						t.Fatal("mutation read changed the exact retained input", err)
					}
					if sample == 0 {
						var wire []byte
						if err := tx.QueryRow(ctx, `EXPLAIN (ANALYZE, BUFFERS, FORMAT JSON) `+readBulkMutationInput, queryArgs...).Scan(&wire); err != nil {
							t.Fatal("measure exact mutation read", err)
						}
						requireBoundedBulkChildQueryPlan(t, parseBulkQueryPlan(t, wire).sanitized(t))
					}
				})
			}
			t.Logf("mutation read client samples=%v; returned rows=%d; each transaction rolled back", elapsed, returned)
		})
	}
	for _, test := range []struct {
		name     string
		ordinal  int
		blocked  bool
		resumed  bool
		retained bool
		expired  bool
	}{
		{name: "first input ready", ordinal: 0},
		{name: "late input ready", ordinal: 999},
		{name: "previously blocked input now ready", ordinal: 999, resumed: true},
		{name: "late input blocked", ordinal: 999, blocked: true},
		{name: "input already retained", ordinal: 999, retained: true},
		{name: "input admission expired", ordinal: 999, expired: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			args := childArgs(test.ordinal)
			var elapsed [3]time.Duration
			for sample := range elapsed {
				withBulkMutationPlanTransaction(t, ctx, connection, func(tx pgx.Tx) {
					status := "admitted"
					if test.resumed {
						status = "dependency-blocked"
					}
					if _, err := tx.Exec(ctx, `UPDATE scim.bulk_children SET status=$3,result_code=NULL,result_resource_id=NULL,result_version=NULL WHERE parent_id=$1 AND ordinal=$2`, args[0], args[1], status); err != nil {
						t.Fatal(err)
					}
					if test.blocked {
						if _, err := tx.Exec(ctx, `UPDATE scim.bulk_children SET status='admitted',result_code=NULL,result_resource_id=NULL,result_version=NULL WHERE parent_id=$1 AND ordinal=998`, args[0]); err != nil {
							t.Fatal(err)
						}
					}
					if test.retained {
						if _, err := tx.Exec(ctx, `UPDATE scim.bulk_children SET group_mutation_input=$3 WHERE parent_id=$1 AND ordinal=$2`, args[0], args[1], ciphertext); err != nil {
							t.Fatal(err)
						}
					}
					deadline := time.Now().UTC().Add(time.Hour)
					if test.expired {
						deadline = time.Now().UTC().Add(-time.Hour)
					}
					retainArgs := append(append([]any(nil), args...), ciphertext, deadline)
					if sample == 0 {
						if _, err := tx.Exec(ctx, "SAVEPOINT mutation_retention_plan"); err != nil {
							t.Fatal(err)
						}
						var wire []byte
						if err := tx.QueryRow(ctx, `EXPLAIN (ANALYZE, BUFFERS, FORMAT JSON) `+retainBulkMutationInput, retainArgs...).Scan(&wire); err != nil {
							t.Fatal("measure exact mutation retention", err)
						}
						requireBoundedBulkChildQueryPlan(t, parseBulkQueryPlan(t, wire).sanitized(t))
						if _, err := tx.Exec(ctx, "ROLLBACK TO SAVEPOINT mutation_retention_plan"); err != nil {
							t.Fatal(err)
						}
					}
					started := time.Now()
					result, err := tx.Exec(ctx, "bulk-mutation-input-retain-plan", retainArgs...)
					elapsed[sample] = time.Since(started)
					wantRows := int64(1)
					if test.blocked || test.retained || test.expired {
						wantRows = 0
					}
					if err != nil || result.RowsAffected() != wantRows {
						t.Fatal("retention did not update exactly one eligible child", result.RowsAffected(), wantRows, err)
					}
					var retained []byte
					if err := tx.QueryRow(ctx, "bulk-mutation-input-read-plan", args...).Scan(&retained); err != nil {
						t.Fatal(err)
					}
					defer clear(retained)
					if wantRows == 1 || test.retained {
						if !bytes.Equal(retained, ciphertext) {
							t.Fatal("retention changed the exact encrypted pre-image")
						}
					} else if retained != nil {
						t.Fatal("blocked retention acquired input")
					}
				})
			}
			t.Logf("mutation retention client samples=%v; each transaction rolled back", elapsed)
		})
	}
	measureBulkGroupMutationSuccess(t, ctx, connection, childArgs(999), ciphertext, successOIDs)
}

func measureBulkGroupMutationSuccess(t *testing.T, ctx context.Context, connection *pgx.Conn, args []any, ciphertext []byte, oids []uint32) {
	t.Helper()
	for _, test := range []struct {
		name     string
		status   string
		retained bool
		code     int
		version  string
	}{
		{name: "replace or patch success", status: "running", retained: true, code: 200, version: `"original-child-version"`},
		{name: "delete success", status: "running", retained: true, code: 204},
		{name: "unstarted success blocked", status: "admitted", retained: true, code: 200, version: `"original-child-version"`},
		{name: "unprepared success blocked", status: "running", code: 200, version: `"original-child-version"`},
	} {
		t.Run(test.name, func(t *testing.T) {
			var elapsed [3]time.Duration
			for sample := range elapsed {
				withBulkMutationPlanTransaction(t, ctx, connection, func(tx pgx.Tx) {
					var retained []byte
					if test.retained {
						retained = ciphertext
					}
					if _, err := tx.Exec(ctx, `UPDATE scim.bulk_children SET status=$3,result_code=NULL,result_resource_id=NULL,result_version=NULL,group_mutation_input=$4 WHERE parent_id=$1 AND ordinal=$2`, args[0], args[1], test.status, retained); err != nil {
						t.Fatal(err)
					}
					successArgs := append(append([]any(nil), args...), test.code, args[4], test.version)
					if sample == 0 {
						if _, err := tx.Exec(ctx, "SAVEPOINT mutation_success_plan"); err != nil {
							t.Fatal(err)
						}
						requireBoundedBulkChildQueryPlan(t, explainBulkWorkInsert(t, ctx, tx, bulkGroupMutationSucceed, oids, successArgs))
						if _, err := tx.Exec(ctx, "ROLLBACK TO SAVEPOINT mutation_success_plan"); err != nil {
							t.Fatal(err)
						}
					}
					values, formats := make([][]byte, len(successArgs)), make([]int16, len(successArgs))
					for index, value := range successArgs {
						if number, ok := value.(int); ok {
							value = int64(number)
						}
						formats[index] = pgtype.BinaryFormatCode
						var err error
						values[index], err = tx.Conn().TypeMap().Encode(oids[index], formats[index], value, nil)
						if err != nil {
							t.Fatal("encode Work mutation success binding", index, err)
						}
					}
					started := time.Now()
					result := tx.Conn().PgConn().ExecParams(ctx, bulkGroupMutationSucceed, values, oids, formats, nil).Read()
					elapsed[sample] = time.Since(started)
					wantRows := int64(0)
					if test.status == "running" && test.retained {
						wantRows = 1
					}
					if result.Err != nil || result.CommandTag.RowsAffected() != wantRows {
						t.Fatal("mutation success did not update exactly one prepared running child", result.CommandTag.RowsAffected(), wantRows, result.Err)
					}
					var status string
					var code *int16
					var resource, version *string
					if err := tx.QueryRow(ctx, `SELECT status,result_code,result_resource_id,result_version FROM scim.bulk_children WHERE parent_id=$1 AND ordinal=$2`, args[0], args[1]).Scan(&status, &code, &resource, &version); err != nil {
						t.Fatal(err)
					}
					if wantRows == 1 {
						versionMatches := version == nil
						if test.version != "" {
							versionMatches = version != nil && *version == test.version
						}
						if status != "succeeded" || code == nil || int(*code) != test.code || resource == nil || *resource != args[4] || !versionMatches {
							t.Fatal("mutation success changed the exact typed terminal result")
						}
					} else if status != test.status || code != nil || resource != nil || version != nil {
						t.Fatal("mutation success bypassed its prepared-running guard")
					}
				})
			}
			t.Logf("Work binary mutation success client samples=%v; each transaction rolled back", elapsed)
		})
	}
}

func withBulkMutationPlanTransaction(t *testing.T, ctx context.Context, connection *pgx.Conn, measure func(pgx.Tx)) {
	t.Helper()
	tx, err := connection.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		cleanup, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		if err := tx.Rollback(cleanup); err != nil {
			t.Error("rollback measured mutation queries", err)
		}
	}()
	measure(tx)
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
