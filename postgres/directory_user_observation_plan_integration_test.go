//go:build integration

package scimpostgres

import (
	"bytes"
	"fmt"
	"reflect"
	"strings"
	"testing"
	"time"

	identity "github.com/faustbrian/go-identity"
	"github.com/jackc/pgx/v5"
)

// This measures the new read's incremental SQL cost, not a predecessor public
// operation: repeated deprovision point SELECTs are only an isolated comparison.
// The public read also performs one existing recheckRead call after the batch;
// its three owner reads and one connection read are outside these timings.
func TestDirectoryUserObservationRepresentativeQueryPlans(t *testing.T) {
	f, groups := nativeGroupsFixture(t)
	user := createNativeNamed(t, f, "ObservationPlanUser", "Synthetic observation")
	if _, err := f.pool.Raw().Exec(f.ctx, `INSERT INTO identity.users(tenant_id,user_id,status,version)
 SELECT 'tenant-a',translate(rtrim(encode(decode(md5('observation-plan-user-'||n),'hex'),'base64'),'='),'+/','-_'),'active',1
 FROM generate_series(1,10000) n`); err != nil {
		t.Fatal("seed synthetic identity cardinality", err)
	}
	if _, err := f.pool.Raw().Exec(f.ctx, `INSERT INTO scim.users(tenant_id,organization_id,provider_id,connection_id,resource_id,user_id,username_key,username_digest,external_id,resource,command_id,effect_digest)
 SELECT s.tenant_id,s.organization_id,s.provider_id,s.connection_id,
 translate(rtrim(encode(decode(md5('observation-plan-user-'||n),'hex'),'base64'),'='),'+/','-_'),
 translate(rtrim(encode(decode(md5('observation-plan-user-'||n),'hex'),'base64'),'='),'+/','-_'),
 'observation-plan-name-'||n,sha256(convert_to('observation-plan-name-'||n,'UTF8')),'',s.resource,
 translate(rtrim(encode(decode(md5('observation-plan-command-'||n),'hex'),'base64'),'='),'+/','-_'),s.effect_digest
 FROM scim.users s CROSS JOIN generate_series(1,10000) n WHERE s.resource_id=$1`, user); err != nil {
		t.Fatal("seed synthetic User projection cardinality", err)
	}
	if _, err := f.pool.Raw().Exec(f.ctx, `ANALYZE scim.users; ANALYZE scim.connections`); err != nil {
		t.Fatal(err)
	}
	connection, err := f.pool.Raw().Acquire(f.ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer connection.Release()
	if _, err := connection.Exec(f.ctx, `SET statement_timeout='3s'; SET lock_timeout='1s'`); err != nil {
		t.Fatal("bound synthetic statements", err)
	}
	var version string
	if err := connection.QueryRow(f.ctx, `SHOW server_version`).Scan(&version); err != nil {
		t.Fatal(err)
	}
	logDirectoryUserObservationSchema(t, f, connection.Conn())

	rows, err := connection.Query(f.ctx, `SELECT resource_id FROM scim.users
 WHERE tenant_id=$1 AND organization_id=$2 AND provider_id=$3 AND connection_id=$4
 ORDER BY resource_id DESC LIMIT 128`, scopeArgs(f.config.Scope)...)
	if err != nil {
		t.Fatal(err)
	}
	var dense []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			rows.Close()
			t.Fatal(err)
		}
		dense = append(dense, id)
	}
	rows.Close()
	if rows.Err() != nil || len(dense) != 128 {
		t.Fatal("maximum distinct synthetic batch unavailable", rows.Err())
	}
	missing := make([]string, len(dense))
	for i := range missing {
		id, err := identity.NewSubjectID()
		if err != nil {
			t.Fatal(err)
		}
		missing[i] = string(id)
	}
	sparse := append([]string(nil), missing...)
	sparse[len(sparse)/2] = dense[0]

	for _, query := range []struct{ name, sql string }{
		{"candidate", directoryUserStatesSQL},
		{"isolated-point-comparison", directoryUserDeprovisionSQL},
	} {
		description, err := connection.Conn().Prepare(f.ctx, "observation-plan-"+query.name, query.sql)
		if err != nil {
			t.Fatal("prepare actual native parameterized SQL", err)
		}
		if query.name == "candidate" && (len(description.ParamOIDs) != 13 || description.ParamOIDs[12] != 1009) {
			t.Fatal("resource batch did not bind as native PostgreSQL text[]", description.ParamOIDs)
		}
		t.Logf("%s SQL=%s; PostgreSQL parameter OIDs=%v", query.name, query.sql, description.ParamOIDs)
	}
	t.Logf("PostgreSQL %s; synthetic users=10001 in one selected scope, one source connection; normal planner, warm cache, sequential client, no concurrent writer; copied retained payloads exercise SQL only, not resource classification; no production-scale or contention claim", version)

	for _, test := range []struct {
		name     string
		ids      []string
		wantHits int
		wide     bool
	}{
		{"one-hit", dense[:1], 1, false},
		{"one-miss", missing[:1], 0, false},
		{"maximum-dense", dense, 128, false},
		{"maximum-sparse", sparse, 1, false},
		{"maximum-miss", missing, 0, false},
		{"maximum-payload-one-hit", dense[:1], 1, true},
	} {
		t.Run(test.name, func(t *testing.T) {
			if test.wide {
				if _, err := connection.Exec(f.ctx, `UPDATE scim.users SET resource=$2 WHERE resource_id=$1`, test.ids[0], bytes.Repeat([]byte("x"), 131072)); err != nil {
					t.Fatal("seed maximum retained payload width", err)
				}
			}
			observed, err := groups.ObserveDirectorySource(f.ctx, f.config.Scope)
			if err != nil {
				t.Fatal(err)
			}
			bindings, err := observed.Bindings()
			if err != nil {
				t.Fatal(err)
			}
			args := directorySourceReadArguments(groups.native, bindings, observed.admission, test.ids)
			types := make([]string, len(args))
			for i, arg := range args {
				types[i] = fmt.Sprintf("%T", arg)
			}
			t.Logf("native candidate Go binding types=%s; isolated comparison binding types=string,string,string,string,string", strings.Join(types, ","))

			baseline := readDirectoryUserObservationPoints(t, f, connection.Conn(), test.ids)
			candidate := readDirectoryUserObservationBatch(t, f, connection.Conn(), args, len(test.ids))
			if !reflect.DeepEqual(candidate, baseline) {
				t.Fatal("batched SQL changed ordered exact mapping, revision, tombstone or payload results")
			}
			hits, payloadBytes := 0, 0
			for _, row := range baseline {
				if row.Found {
					hits++
				}
				payloadBytes += len(row.Wire)
			}
			if hits != test.wantHits || test.wide && payloadBytes != 131072 {
				t.Fatal("synthetic case lost its intended match density or payload width", hits, payloadBytes)
			}
			var wire []byte
			if err := connection.QueryRow(f.ctx, `EXPLAIN (ANALYZE,BUFFERS,FORMAT JSON) `+directoryUserStatesSQL, args...).Scan(&wire); err != nil {
				t.Fatal("measure exact candidate SQL and native bindings", err)
			}
			plan := parseBulkQueryPlan(t, wire)
			requireDirectoryUserObservationPlan(t, plan, len(test.ids))
			t.Logf("candidate returned=%d hits=%d payload bytes=%d; sanitized plan=%s", len(candidate), hits, payloadBytes, plan.sanitized(t))

			// One retained hit and one miss suffice for the baseline's two
			// exact-key shapes; all repeated reads below still use actual IDs.
			measured := map[bool]bool{}
			for i, row := range baseline {
				if measured[row.Found] {
					continue
				}
				measured[row.Found] = true
				pointArgs := append(scopeArgs(f.config.Scope), test.ids[i])
				if err := connection.QueryRow(f.ctx, `EXPLAIN (ANALYZE,BUFFERS,FORMAT JSON) `+directoryUserDeprovisionSQL, pointArgs...).Scan(&wire); err != nil {
					t.Fatal("measure exact isolated comparison SQL", err)
				}
				pointPlan := parseBulkQueryPlan(t, wire)
				requireDirectoryUserObservationPlan(t, pointPlan, int(pointPlan.Plan.Rows))
				t.Logf("isolated point hit=%t; sanitized plan=%s", row.Found, pointPlan.sanitized(t))
			}

			var batchElapsed, pointElapsed [3]time.Duration
			for sample := range batchElapsed {
				measureBatch := func() {
					start := time.Now()
					got := readDirectoryUserObservationBatch(t, f, connection.Conn(), args, len(test.ids))
					batchElapsed[sample] = time.Since(start)
					if !reflect.DeepEqual(got, baseline) {
						t.Fatal("measured candidate changed ordered results")
					}
				}
				measurePoints := func() {
					start := time.Now()
					got := readDirectoryUserObservationPoints(t, f, connection.Conn(), test.ids)
					pointElapsed[sample] = time.Since(start)
					if !reflect.DeepEqual(got, baseline) {
						t.Fatal("measured isolated comparison changed ordered results")
					}
				}
				if sample%2 == 0 {
					measureBatch()
					measurePoints()
				} else {
					measurePoints()
					measureBatch()
				}
			}
			t.Logf("targets=%d candidate statements=1 isolated comparison statements=%d; complete raw pgx client samples candidate=%v comparison=%v; includes result transfer, excludes connection acquisition, setup, EXPLAIN and final authority recheck", len(test.ids), len(test.ids), batchElapsed, pointElapsed)
		})
	}
}

type directoryUserObservationPlanResult struct {
	Found, Deleted bool
	User, Command  string
	Wire           []byte
}

func readDirectoryUserObservationPoints(t *testing.T, f *nativeFixture, connection *pgx.Conn, ids []string) []directoryUserObservationPlanResult {
	t.Helper()
	results := make([]directoryUserObservationPlanResult, len(ids))
	for i, id := range ids {
		row := &results[i]
		err := connection.QueryRow(f.ctx, directoryUserDeprovisionSQL, append(scopeArgs(f.config.Scope), id)...).Scan(&row.User, &row.Wire, &row.Deleted, &row.Command)
		if err == pgx.ErrNoRows {
			continue
		}
		if err != nil {
			t.Fatal("execute isolated native point comparison", err)
		}
		row.Found = true
	}
	return results
}

func readDirectoryUserObservationBatch(t *testing.T, f *nativeFixture, connection *pgx.Conn, args []any, size int) []directoryUserObservationPlanResult {
	t.Helper()
	rows, err := connection.Query(f.ctx, directoryUserStatesSQL, args...)
	if err != nil {
		t.Fatal("execute actual native observation SQL", err)
	}
	defer rows.Close()
	results := make([]directoryUserObservationPlanResult, 0, size)
	for rows.Next() {
		var ordinal int64
		var row directoryUserObservationPlanResult
		if err := rows.Scan(&ordinal, &row.Found, &row.Deleted, &row.User, &row.Command, &row.Wire); err != nil {
			t.Fatal(err)
		}
		if ordinal != int64(len(results)+1) || len(row.Wire) > 131072 {
			t.Fatal("observation SQL lost ordered bounded output")
		}
		results = append(results, row)
	}
	if rows.Err() != nil || len(results) != size {
		t.Fatal("observation SQL lost admitted target cardinality", rows.Err(), len(results), size)
	}
	return results
}

func requireDirectoryUserObservationPlan(t *testing.T, plan bulkQueryPlan, returned int) {
	t.Helper()
	var userRows float64
	var indexed bool
	var visit func(bulkQueryPlanNode)
	visit = func(node bulkQueryPlanNode) {
		if node.Relation == "users" && node.Loops > 0 {
			if node.Index != "users_pkey" {
				t.Fatal("observation traversed unrelated User projections", string(plan.sanitized(t)))
			}
			indexed = true
			userRows += (node.Rows + node.Filtered) * node.Loops
		}
		for _, child := range node.Plans {
			visit(child)
		}
	}
	visit(plan.Plan)
	if !indexed || plan.Plan.Rows != float64(returned) || userRows > float64(max(returned, 1)) {
		t.Fatal("observation lost indexed, bounded target work", string(plan.sanitized(t)))
	}
}

func logDirectoryUserObservationSchema(t *testing.T, f *nativeFixture, connection *pgx.Conn) {
	t.Helper()
	rows, err := connection.Query(f.ctx, `SELECT a.attname,format_type(a.atttypid,a.atttypmod)
 FROM pg_attribute a WHERE a.attrelid='scim.users'::regclass AND a.attnum>0 AND NOT a.attisdropped ORDER BY a.attnum`)
	if err != nil {
		t.Fatal(err)
	}
	for rows.Next() {
		var column, columnType string
		if err := rows.Scan(&column, &columnType); err != nil {
			rows.Close()
			t.Fatal(err)
		}
		t.Logf("actual scim.users column=%s type=%s", column, columnType)
	}
	rows.Close()
	if rows.Err() != nil {
		t.Fatal(rows.Err())
	}
	rows, err = connection.Query(f.ctx, `SELECT i.relname,pg_get_indexdef(i.oid)
 FROM pg_index x JOIN pg_class i ON i.oid=x.indexrelid
 WHERE x.indrelid='scim.users'::regclass AND x.indisvalid AND x.indisready ORDER BY i.relname`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	for rows.Next() {
		var name, definition string
		if err := rows.Scan(&name, &definition); err != nil {
			t.Fatal(err)
		}
		t.Logf("actual usable User index=%s definition=%s", name, definition)
	}
	if rows.Err() != nil {
		t.Fatal(rows.Err())
	}
}
