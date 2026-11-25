//go:build integration

package scimpostgres

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"

	scim "github.com/faustbrian/go-scim"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
)

// This is a bounded, warm-cache, single-client synthetic measurement, not a
// production latency claim. Distinct literal targets keep all 1,000 DELETEs
// shallow; admission must retain them without executing any Group operation.
func TestNativeGroupBulkAdmissionMaximumAndOwnerQueryPlans(t *testing.T) {
	policy := scim.DefaultBulkResponsePolicy()
	policy.ErrorDetailBytes = 0
	f, service := bulkAdmissionFixture(t, policy)
	var selected BulkAdmission
	for _, size := range []int{1, 1000} {
		var admitElapsed, replayElapsed [3]time.Duration
		for sample := range admitElapsed {
			operations := make([]string, size)
			for ordinal := range operations {
				digest := sha256.Sum256(fmt.Appendf(nil, "bulk-plan-%d-%d-%d", size, sample, ordinal))
				id := base64.RawURLEncoding.EncodeToString(digest[:16])
				operations[ordinal] = `{"method":"DELETE","path":"/Groups/` + id + `"}`
			}
			request := BulkAdmissionRequest{Credential: f.bearer, Body: []byte(`{"schemas":["urn:ietf:params:scim:api:messages:2.0:BulkRequest"],"Operations":[` + strings.Join(operations, ",") + `]}`)}
			started := time.Now()
			admitted, err := service.Admit(f.ctx, request)
			admitElapsed[sample] = time.Since(started)
			if err != nil || admitted.CommandID == "" || admitted.ChildCount != size || admitted.ResponseMaximumBytes <= 0 {
				t.Fatalf("native admission size=%d sample=%d failed: %v", size, sample, err)
			}
			started = time.Now()
			replayed, err := service.Admit(f.ctx, request)
			replayElapsed[sample] = time.Since(started)
			if err != nil || replayed != admitted {
				t.Fatalf("native replay size=%d sample=%d changed admission: %v", size, sample, err)
			}
			var children, commands, shallow int
			err = f.pool.Raw().QueryRow(f.ctx, `SELECT count(*),count(DISTINCT command_id),
 count(*) FILTER (WHERE status='admitted' AND resource_id='' AND NOT cyclic AND cardinality(dependency_ids)=0)
 FROM scim.bulk_children WHERE parent_id=$1`, string(admitted.CommandID)).Scan(&children, &commands, &shallow)
			if err != nil || children != size || commands != size || shallow != size {
				t.Fatal("maximum admission lost distinct, unexecuted shallow children", children, commands, shallow, err)
			}
			selected = admitted
		}
		t.Logf("native Bulk children=%d; distinct-request admission samples=%v; exact replay samples=%v", size, admitElapsed, replayElapsed)
	}
	var parents, children, groups, commands int
	err := f.pool.Raw().QueryRow(f.ctx, `SELECT
 (SELECT count(*) FROM scim.bulk_requests), (SELECT count(*) FROM scim.bulk_children),
 (SELECT count(*) FROM scim.groups),
 (SELECT count(*) FROM identity.commands WHERE purpose=$1 AND state='committed')`, string(scim.Bulk)).Scan(&parents, &children, &groups, &commands)
	if err != nil || parents != 6 || children != 3003 || groups != 0 || commands != 6 {
		t.Fatal("replay duplicated admission or admission executed a Group mutation", parents, children, groups, commands, err)
	}

	connection, err := f.pool.Raw().Acquire(f.ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer connection.Release()
	var intent, profile []byte
	var maximum, count, cutoff int
	var created time.Time
	err = connection.QueryRow(f.ctx, `SELECT intent_digest,configuration_digest,response_bytes,child_count,fail_on_errors,created_at
 FROM scim.bulk_requests WHERE parent_id=$1`, string(selected.CommandID)).Scan(&intent, &profile, &maximum, &count, &cutoff, &created)
	if err != nil {
		t.Fatal("read the native parent's retained replay values", err)
	}
	// These are bulkParentArgs' actual primitive types, including Go int, not
	// manually narrowed int16 values inferred from the destination columns.
	args := append(scopeArgs(f.config.Scope), string(selected.CommandID), intent, profile, maximum, count, cutoff, created)
	// Preserve the retained-row width and selected-scope skew. These synthetic
	// historical parents need no fake journal or children for the exact-key
	// replay read or parent/child insert index and FK measurements.
	if _, err := connection.Exec(f.ctx, `INSERT INTO scim.bulk_requests
 (tenant_id,organization_id,provider_id,connection_id,parent_id,intent_digest,configuration_digest,response_bytes,child_count,fail_on_errors,created_at)
 SELECT tenant_id,organization_id,provider_id,connection_id,
 translate(rtrim(encode(decode(md5('bulk-retained-'||n),'hex'),'base64'),'='),'+/','-_'),
 intent_digest,configuration_digest,response_bytes,child_count,fail_on_errors,created_at
 FROM scim.bulk_requests CROSS JOIN generate_series(1,10000) n WHERE parent_id=$1`, string(selected.CommandID)); err != nil {
		t.Fatal("seed bounded same-scope retained parents", err)
	}
	if _, err := connection.Exec(f.ctx, `ANALYZE scim.bulk_requests; ANALYZE scim.bulk_children`); err != nil {
		t.Fatal(err)
	}
	var version string
	if err := connection.QueryRow(f.ctx, `SHOW server_version`).Scan(&version); err != nil {
		t.Fatal(err)
	}
	t.Logf("PostgreSQL %s; synthetic retained parents=10006 in one scope; warm cache; sequential client; no concurrent writer", version)

	// Work.encodeWorkParameters uses binary Text=25, Bytea=17, Go int=Int8=20,
	// and time.Time=Timestamptz=1184, even for smallint destination columns.
	parentOIDs := []uint32{25, 25, 25, 25, 25, 17, 17, 20, 20, 20, 1184}
	t.Logf("parent SQL=%s; Work parameter OIDs=%v", bulkParentInsert, parentOIDs)
	t.Logf("child SQL=%s; Work parameter OIDs=[25 17]", bulkChildrenInsert)
	for _, size := range []int{1, 1000} {
		var parentElapsed, childElapsed [3]time.Duration
		for sample := range parentElapsed {
			tx, err := connection.Begin(f.ctx)
			if err != nil {
				t.Fatal(err)
			}
			func() {
				defer func() {
					cleanup, cancel := context.WithTimeout(context.Background(), 3*time.Second)
					defer cancel()
					if err := tx.Rollback(cleanup); err != nil {
						t.Error("rollback measured owner inserts", err)
					}
				}()
				parentDigest := sha256.Sum256(fmt.Appendf(nil, "bulk-insert-%d-%d", size, sample))
				parentID := base64.RawURLEncoding.EncodeToString(parentDigest[:16])
				parentArgs := append([]any(nil), args...)
				parentArgs[4], parentArgs[8] = parentID, size
				rows := make([]bulkChildRow, size)
				for ordinal := range rows {
					digest := sha256.Sum256(fmt.Appendf(nil, "bulk-insert-child-%d-%d-%d", size, sample, ordinal))
					rows[ordinal] = bulkChildRow{Ordinal: ordinal, Command: base64.RawURLEncoding.EncodeToString(digest[:16]),
						BulkID: []byte{}, Fingerprint: bulkChildFingerprint(parentDigest, ordinal), ComponentID: ordinal, ComponentOrder: ordinal, Dependencies: []string{}}
				}
				wire, err := json.Marshal(rows)
				if err != nil || len(wire) > bulkChildBatchBytes {
					t.Fatal("maximum shallow rows must fit the actual JSON batch", len(wire), err)
				}
				started := time.Now()
				parentPlan := explainBulkWorkInsert(t, f.ctx, tx, bulkParentInsert, parentOIDs, parentArgs)
				parentElapsed[sample] = time.Since(started)
				started = time.Now()
				childPlan := explainBulkWorkInsert(t, f.ctx, tx, bulkChildrenInsert, []uint32{25, 17}, []any{parentID, wire})
				childElapsed[sample] = time.Since(started)
				var stored int
				if err := tx.QueryRow(f.ctx, `SELECT count(*) FROM scim.bulk_children WHERE parent_id=$1`, parentID).Scan(&stored); err != nil || stored != size {
					t.Fatal("EXPLAIN ANALYZE did not execute the complete actual child insert", stored, err)
				}
				if sample == 0 {
					t.Logf("insert children=%d JSON bytes=%d; sanitized parent plan=%s; sanitized child plan=%s", size, len(wire), parentPlan, childPlan)
				}
			}()
		}
		t.Logf("children=%d instrumented parent client samples=%v; instrumented child client samples=%v; each transaction rolled back", size, parentElapsed, childElapsed)
	}

	// requireCommittedBulkAdmission uses ordinary pgx QueryRow, not Work's
	// explicit OIDs. Capture that statement's real server-inferred binding OIDs.
	description, err := connection.Conn().Prepare(f.ctx, "bulk-replay-plan", bulkCommittedSelect)
	if err != nil {
		t.Fatal("prepare actual replay predicate", err)
	}
	t.Logf("replay SQL=%s; actual pgx prepared parameter OIDs=%v; Go types=string*5,[]byte*2,int*3,time.Time", bulkCommittedSelect, description.ParamOIDs)
	for _, mode := range []string{"exact hit", "missing parent", "foreign scope", "changed digest"} {
		replayArgs := append([]any(nil), args...)
		want := mode == "exact hit"
		switch mode {
		case "missing parent":
			replayArgs[4] = "AAAAAAAAAAAAAAAAAAAAAQ"
		case "foreign scope":
			replayArgs[3] = "absent-connection"
		case "changed digest":
			replayArgs[6] = make([]byte, 32)
		}
		var wire []byte
		if err := connection.QueryRow(f.ctx, `EXPLAIN (ANALYZE, BUFFERS, FORMAT JSON) `+bulkCommittedSelect, replayArgs...).Scan(&wire); err != nil {
			t.Fatal("measure exact replay SELECT", err)
		}
		plan := parseBulkQueryPlan(t, wire)
		examined, indexed := plan.Plan.parentAccess()
		if !indexed || examined > 1 {
			t.Fatalf("replay %s examined unrelated retained parents: %s", mode, plan.sanitized(t))
		}
		var elapsed [3]time.Duration
		for sample := range elapsed {
			started := time.Now()
			var exists bool
			if err := connection.QueryRow(f.ctx, "bulk-replay-plan", replayArgs...).Scan(&exists); err != nil || exists != want {
				t.Fatal("actual replay predicate returned the wrong commitment result", mode, exists, err)
			}
			elapsed[sample] = time.Since(started)
		}
		t.Logf("replay %s; client samples=%v; examined=%.0f; sanitized plan=%s", mode, elapsed, examined, plan.sanitized(t))
	}
	// RecoveryWork delegates to Work.Query and sends binary Text (25).
	// Check the actual projection as well as the ordinary scoped replay read.
	for _, id := range []string{string(selected.CommandID), "AAAAAAAAAAAAAAAAAAAAAQ"} {
		want := 0
		if id == string(selected.CommandID) {
			want = 1
		}
		const explain = `EXPLAIN (ANALYZE, BUFFERS, FORMAT JSON) `
		pg := connection.Conn().PgConn()
		param := [][]byte{[]byte(id)}
		oids, formats := []uint32{pgtype.TextOID}, []int16{pgtype.BinaryFormatCode}
		record := pg.ExecParams(f.ctx, explain+bulkRecoverySelect, param, oids, formats, nil).Read()
		if record.Err != nil || len(record.Rows) != 1 || len(record.Rows[0]) != 1 {
			t.Fatal("measure actual RecoveryWork SELECT with binary Text binding", record.Err)
		}
		plan := parseBulkQueryPlan(t, record.Rows[0][0])
		examined, indexed := plan.Plan.parentAccess()
		if !indexed || examined != float64(want) {
			t.Fatal("recovery read examined unrelated parents", plan.sanitized(t))
		}
		var elapsed [3]time.Duration
		for sample := range elapsed {
			started := time.Now()
			result := pg.ExecParams(f.ctx, bulkRecoverySelect, param, oids, formats, []int16{pgtype.BinaryFormatCode}).Read()
			elapsed[sample] = time.Since(started)
			if result.Err != nil || len(result.Rows) != want || want == 1 && (len(result.Rows[0]) != 1 || !bytes.Equal(result.Rows[0][0], intent)) {
				t.Fatal("actual recovery projection differed", result.Err)
			}
		}
		t.Logf("recovery SQL=%s; RecoveryWork parameter OID=25 (binary); examined=%.0f; client samples=%v; sanitized plan=%s", bulkRecoverySelect, examined, elapsed, plan.sanitized(t))
	}
	if err := connection.QueryRow(f.ctx, `SELECT count(*) FROM scim.bulk_requests`).Scan(&parents); err != nil || parents != 10006 {
		t.Fatal("measured inserts escaped rollback", parents, err)
	}
}

// ExecParams preserves the actual Work binary scalar profile. pgx's normal
// inferred parameter types would instead narrow the INSERT's integer inputs.
func explainBulkWorkInsert(t *testing.T, ctx context.Context, tx pgx.Tx, sql string, oids []uint32, args []any) []byte {
	t.Helper()
	codecs := pgtype.NewMap()
	values, formats := make([][]byte, len(args)), make([]int16, len(args))
	for index, value := range args {
		if number, ok := value.(int); ok {
			value = int64(number)
		}
		formats[index] = pgtype.BinaryFormatCode
		var err error
		values[index], err = codecs.Encode(oids[index], formats[index], value, make([]byte, 0))
		if err != nil {
			t.Fatal("encode actual Work primitive binding", index, err)
		}
	}
	result := tx.Conn().PgConn().ExecParams(ctx, `EXPLAIN (ANALYZE, BUFFERS, FORMAT JSON) `+sql, values, oids, formats, nil).Read()
	if result.Err != nil || len(result.Rows) != 1 || len(result.Rows[0]) != 1 {
		t.Fatal("execute exact Work SQL with native binding OIDs", result.Err)
	}
	return parseBulkQueryPlan(t, result.Rows[0][0]).sanitized(t)
}

// Do not log predicates or literal bindings from EXPLAIN. Only structural work
// and timings survive decoding, so retained commitment values stay private.
type bulkQueryPlanNode struct {
	NodeType   string              `json:"Node Type"`
	Relation   string              `json:"Relation Name,omitempty"`
	Index      string              `json:"Index Name,omitempty"`
	Rows       float64             `json:"Actual Rows"`
	Loops      float64             `json:"Actual Loops"`
	Filtered   float64             `json:"Rows Removed by Filter,omitempty"`
	SharedHits int                 `json:"Shared Hit Blocks"`
	SharedRead int                 `json:"Shared Read Blocks"`
	Plans      []bulkQueryPlanNode `json:"Plans,omitempty"`
}

type bulkQueryPlan struct {
	Plan        bulkQueryPlanNode
	ExecutionMS float64 `json:"Execution Time"`
	PlanningMS  float64 `json:"Planning Time"`
}

func parseBulkQueryPlan(t *testing.T, wire []byte) bulkQueryPlan {
	t.Helper()
	var plans []bulkQueryPlan
	if err := json.Unmarshal(wire, &plans); err != nil || len(plans) != 1 {
		t.Fatal("invalid exact owner query plan", err)
	}
	return plans[0]
}

func (p bulkQueryPlan) sanitized(t *testing.T) []byte {
	t.Helper()
	wire, err := json.Marshal(p)
	if err != nil {
		t.Fatal(err)
	}
	return wire
}

func (p bulkQueryPlanNode) parentAccess() (float64, bool) {
	var examined float64
	var indexed bool
	if p.Relation == "bulk_requests" {
		examined = (p.Rows + p.Filtered) * p.Loops
		indexed = p.Index == "bulk_requests_pkey"
	}
	for _, child := range p.Plans {
		rows, index := child.parentAccess()
		examined += rows
		indexed = indexed || index
	}
	return examined, indexed
}
