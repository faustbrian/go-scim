//go:build integration

package scimpostgres

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

	identity "github.com/faustbrian/go-identity"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
)

func measureManagedCreatePlans(t *testing.T, f *nativeFixture, connection *pgx.Conn, tenant, denseOrg, sparseOrg string, mapping []byte) {
	t.Helper()
	bindingOIDs := []uint32{25, 25, 25, 25, 25, 17, 17, 1184, 25, 25, 25, 17}
	projectionOIDs := []uint32{25, 25, 25, 25, 17}
	for _, selected := range []struct {
		name, query string
		oids        []uint32
	}{
		{"binding", managedCreateBindingSQL, bindingOIDs},
		{"projection", managedCreateProjectionSQL, projectionOIDs},
	} {
		// Work sends explicit primitive OIDs, including text for the two
		// numeric casts. Inferred pgx parameters would not preserve that wire.
		for _, prefix := range []string{"", "EXPLAIN (ANALYZE,BUFFERS,FORMAT JSON) "} {
			description, err := connection.PgConn().Prepare(f.ctx, "", prefix+selected.query, selected.oids)
			if err != nil || !slices.Equal(description.ParamOIDs, selected.oids) {
				t.Fatal("prepare exact create Work parameter types", selected.name, err)
			}
		}
		t.Logf("create %s exact SQL=%s; explicit native Work parameter OIDs=%v", selected.name, selected.query, selected.oids)
	}
	for _, org := range []string{denseOrg, sparseOrg} {
		id, err := identity.NewSubjectID()
		if err != nil {
			t.Fatal(err)
		}
		keys := []any{tenant, org, "managed-plan-provider", string(id)}
		digest := sha256.Sum256([]byte("synthetic create plan"))
		bindingArgs := append(slices.Clone(keys), string(id), digest[:], digest[:], time.Now().UTC().Truncate(time.Microsecond).Add(time.Hour), "1", "1", string(id), digest[:])
		projectionArgs := append(slices.Clone(keys), mapping)
		withBulkMutationPlanTransaction(t, f.ctx, connection, func(tx pgx.Tx) {
			// Each EXPLAIN/sample gets a rollback savepoint: an insert always
			// sees absence and its following duplicate sees exactly that insert.
			for sample := range 4 {
				savepoint, err := tx.Begin(f.ctx)
				if err != nil {
					t.Fatal(err)
				}
				for _, duplicate := range []bool{false, true} {
					for _, selected := range []struct {
						name, query string
						oids        []uint32
						args        []any
					}{
						{"binding", managedCreateBindingSQL, bindingOIDs, bindingArgs},
						{"projection", managedCreateProjectionSQL, projectionOIDs, projectionArgs},
					} {
						codecs := pgtype.NewMap()
						values, formats := make([][]byte, len(selected.args)), make([]int16, len(selected.args))
						for index, value := range selected.args {
							formats[index] = pgtype.BinaryFormatCode
							values[index], err = codecs.Encode(selected.oids[index], formats[index], value, nil)
							if err != nil {
								t.Fatal("encode actual managed create Work binding", index, err)
							}
						}
						query := selected.query
						if sample == 0 {
							query = "EXPLAIN (ANALYZE,BUFFERS,FORMAT JSON) " + query
						}
						start := time.Now()
						result := connection.PgConn().ExecParams(f.ctx, query, values, selected.oids, formats, nil).Read()
						elapsed := time.Since(start)
						if result.Err != nil {
							t.Fatal("execute exact managed create Work SQL", result.Err)
						}
						inserted, conflicts := 1, 0
						if duplicate {
							inserted, conflicts = 0, 1
						}
						if sample == 0 {
							if len(result.Rows) != 1 || len(result.Rows[0]) != 1 {
								t.Fatal("missing managed create plan")
							}
							var plans []struct {
								Plan struct {
									Operation string
									Inserted  int `json:"Tuples Inserted"`
									Conflicts int `json:"Conflicting Tuples"`
								}
							}
							wire := result.Rows[0][0]
							if json.Unmarshal(wire, &plans) != nil || len(plans) != 1 || plans[0].Plan.Operation != "Insert" || plans[0].Plan.Inserted != inserted || plans[0].Plan.Conflicts != conflicts {
								t.Fatal("managed create lost one-row insert/conflict bound")
							}
							t.Logf("create %s duplicate=%t inserted=%d conflicts=%d sanitized plan=%s", selected.name, duplicate, inserted, conflicts, parseBulkQueryPlan(t, wire).sanitized(t))
						} else {
							if result.CommandTag.String() != fmt.Sprintf("INSERT 0 %d", inserted) {
								t.Fatal("managed create returned unexpected exact command tag", result.CommandTag)
							}
							t.Logf("create %s duplicate=%t sample=%d native Work command=%s client elapsed=%s; one statement, excludes encoding/savepoint/admission; populated warm sequential fixture, no production or contention claim", selected.name, duplicate, sample, result.CommandTag, elapsed)
						}
					}
				}
				if err := savepoint.Rollback(f.ctx); err != nil {
					t.Fatal("rollback measured managed create pair", err)
				}
			}
		})
		var retained bool
		if err := connection.QueryRow(f.ctx, `SELECT EXISTS(SELECT 1 FROM scim.connections WHERE tenant_id=$1 AND connection_id=$2) OR EXISTS(SELECT 1 FROM scim.managed_connections WHERE tenant_id=$1 AND connection_id=$2)`, tenant, string(id)).Scan(&retained); err != nil || retained {
			t.Fatal("managed create measurements retained seeded state", err)
		}
	}
}

func measureManagedProvisioningPlans(t *testing.T, f *nativeFixture, connection *pgx.Conn, tenant, foreignTenant, denseOrg, sparseOrg, denseID, sparseID, deletedID string, mapping []byte) {
	t.Helper()
	prepareManagedPointQuery(t, f, connection, "provisioning", managedProvisioningSQL, []uint32{25, 25, 25})
	prepareManagedPointQuery(t, f, connection, "withdrawal-profile", managedWithdrawalProfileSQL, []uint32{25, 25, 25, 25})
	digest := sha256.Sum256([]byte("synthetic credential"))
	configuration := sha256.Sum256([]byte("synthetic configuration"))
	for _, test := range []struct {
		name, tenant, org, provider, id, credential string
		provisioningRows, profileRows               int
	}{
		{"dense-hit", tenant, denseOrg, "managed-plan-provider", denseID, "managed-plan-credential", 1, 1},
		{"sparse-hit", tenant, sparseOrg, "managed-plan-provider", sparseID, "managed-plan-credential", 1, 1},
		{"missing-key", tenant, denseOrg, "managed-plan-provider", "AAAAAAAAAAAAAAAAAAAABQ", "managed-plan-credential", 0, 0},
		{"foreign-tenant", foreignTenant, denseOrg, "managed-plan-provider", denseID, "managed-plan-credential", 0, 0},
		{"foreign-organization", tenant, sparseOrg, "managed-plan-provider", denseID, "managed-plan-credential", 1, 0},
		{"foreign-provider", tenant, denseOrg, "absent-provider", denseID, "managed-plan-credential", 1, 0},
		{"wrong-credential", tenant, denseOrg, "managed-plan-provider", denseID, "absent-credential", 0, 1},
		{"deleted-binding", tenant, denseOrg, "managed-plan-provider", deletedID, "managed-plan-credential", 0, 1},
	} {
		t.Run("provisioning/"+test.name, func(t *testing.T) {
			expectedOrg := denseOrg
			if test.id == sparseID {
				expectedOrg = sparseOrg
			}
			measureManagedPointQuery(t, f, connection, "provisioning", managedProvisioningSQL,
				[]any{test.tenant, test.id, test.credential}, test.provisioningRows, 1, []string{"managed_connections", "connections"}, func(row []any) bool {
					if len(row) != 10 {
						return false
					}
					expiry, expiryOK := row[8].(time.Time)
					now, nowOK := row[9].(time.Time)
					return reflect.DeepEqual(row[:8], []any{expectedOrg, "managed-plan-provider", mapping, "remove-membership", "1", "managed-plan-credential", digest[:], configuration[:]}) && expiryOK && nowOK && now.Before(expiry)
				})
		})
		t.Run("withdrawal-profile/"+test.name, func(t *testing.T) {
			measureManagedPointQuery(t, f, connection, "withdrawal-profile", managedWithdrawalProfileSQL,
				[]any{test.tenant, test.org, test.provider, test.id}, test.profileRows, 1, []string{"managed_connections"}, func(row []any) bool {
					return reflect.DeepEqual(row, []any{mapping, "remove-membership"})
				})
		})
	}
}

// This extends the existing managed read fixture, so all new exact production
// queries share its real migrations, 10,003 bindings and normal-planner setup.
// Payloads below are synthetic SQL inputs, not valid public SCIM resources.
func measureManagedWithdrawalPlans(t *testing.T, f *nativeFixture, connection *pgx.Conn) {
	t.Helper()
	if _, err := connection.Exec(f.ctx, `CREATE TEMP TABLE managed_withdrawal_plan_fixture AS
 SELECT sample.n,s.tenant_id,s.organization_id,s.connection_id,
 translate(rtrim(encode(decode(md5('managed-withdrawal-user-'||sample.n),'hex'),'base64'),'='),'+/','-_') AS user_id,
 translate(rtrim(encode(decode(md5('managed-withdrawal-resource-'||sample.n),'hex'),'base64'),'='),'+/','-_') AS resource_id,
 convert_to('synthetic retained resource','UTF8') AS resource
 FROM generate_series(1,10003) AS sample(n) JOIN managed_read_plan_fixture s
 ON s.n=CASE WHEN sample.n<=8000 THEN 1 WHEN sample.n<=8003 THEN 8001 ELSE sample.n END`); err != nil {
		t.Fatal("seed dense, sparse and unrelated User scopes", err)
	}
	if _, err := connection.Exec(f.ctx, `INSERT INTO identity.users(tenant_id,user_id,status,version)
 SELECT tenant_id,user_id,'active',1 FROM managed_withdrawal_plan_fixture`); err != nil {
		t.Fatal("seed synthetic canonical User owners", err)
	}
	if _, err := connection.Exec(f.ctx, `INSERT INTO scim.users
 (tenant_id,organization_id,provider_id,connection_id,resource_id,user_id,username_key,username_digest,external_id,resource,command_id,effect_digest)
 SELECT tenant_id,organization_id,'managed-plan-provider',connection_id,resource_id,user_id,
 'withdrawal-plan-'||n,sha256(convert_to('withdrawal-plan-'||n,'UTF8')),'',resource,resource_id,sha256('synthetic effect')
 FROM managed_withdrawal_plan_fixture`); err != nil {
		t.Fatal("seed representative withdrawal User projections", err)
	}
	if _, err := connection.Exec(f.ctx, `ANALYZE scim.users`); err != nil {
		t.Fatal(err)
	}
	logDirectoryUserObservationSchema(t, f, connection)
	prepareManagedPointQuery(t, f, connection, "withdrawal-prepare", managedWithdrawalPrepareSQL, []uint32{25, 25, 25, 25, 25, 17})
	prepareManagedPointQuery(t, f, connection, "withdrawal-lock", managedWithdrawalLockSQL, []uint32{25, 25, 25, 25, 25, 25})
	t.Log("withdrawal synthetic users=10003; dense selected connection=8000, sparse selected connection=3, unrelated=2000; new incremental reads have no predecessor; preparation adds one User SELECT, feature Work adds one locked User SELECT and one locked profile SELECT; owning lifecycle and contention are covered separately")
	for _, selected := range []struct {
		name             string
		n, examinedBound int
	}{
		{"dense", 1, 1},
		// The normal planner may use a scope-prefix index for all three
		// fixture rows; this stays bounded without forcing a specific index.
		{"sparse", 8001, 3},
	} {
		var tenant, org, id, user, resourceID string
		var resource []byte
		if err := connection.QueryRow(f.ctx, `SELECT tenant_id,organization_id,connection_id,user_id,resource_id,resource
 FROM managed_withdrawal_plan_fixture WHERE n=$1`, selected.n).Scan(&tenant, &org, &id, &user, &resourceID, &resource); err != nil {
			t.Fatal(err)
		}
		for _, mode := range []string{"live-hit", "missing-key", "foreign-tenant", "foreign-organization", "foreign-provider", "foreign-connection", "wrong-resource", "wrong-user", "wide-hit", "tombstone"} {
			t.Run("withdrawal-user/"+selected.name+"/"+mode, func(t *testing.T) {
				prepareArgs := []any{tenant, org, "managed-plan-provider", id, resourceID, resource}
				lockArgs := []any{tenant, org, "managed-plan-provider", id, resourceID, user}
				prepareRows, lockRows := 1, 1
				retained := resource
				var deleted any
				switch mode {
				case "missing-key", "foreign-tenant", "foreign-organization", "foreign-provider", "foreign-connection":
					position := map[string]int{"missing-key": 4, "foreign-tenant": 0, "foreign-organization": 1, "foreign-provider": 2, "foreign-connection": 3}[mode]
					prepareArgs[position], lockArgs[position] = "AAAAAAAAAAAAAAAAAAAABQ", "AAAAAAAAAAAAAAAAAAAABQ"
					prepareRows, lockRows = 0, 0
				case "wrong-resource":
					prepareArgs[5], prepareRows = []byte("not the retained payload"), 0
				case "wrong-user":
					lockArgs[5], lockRows = "AAAAAAAAAAAAAAAAAAAABQ", 0
				case "wide-hit":
					retained = bytes.Repeat([]byte("x"), 131072)
					prepareArgs[5] = retained
				case "tombstone":
					deleted, prepareRows = time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC), 0
				}
				if _, err := connection.Exec(f.ctx, `UPDATE scim.users SET resource=$6,deleted_at=$7
 WHERE tenant_id=$1 AND organization_id=$2 AND provider_id=$3 AND connection_id=$4 AND resource_id=$5`, tenant, org, "managed-plan-provider", id, resourceID, retained, deleted); err != nil {
					t.Fatal("set retained payload/tombstone class", err)
				}
				measureManagedPointQuery(t, f, connection, "withdrawal-prepare", managedWithdrawalPrepareSQL, prepareArgs, prepareRows, selected.examinedBound, []string{"users"}, func(row []any) bool {
					return reflect.DeepEqual(row, []any{int64(1), user})
				})
				measureManagedPointQuery(t, f, connection, "withdrawal-lock", managedWithdrawalLockSQL, lockArgs, lockRows, selected.examinedBound, []string{"users"}, func(row []any) bool {
					if len(row) != 3 || !reflect.DeepEqual(row[:2], []any{int64(1), retained}) {
						return false
					}
					if deleted == nil {
						return row[2] == nil
					}
					actual, ok := row[2].(time.Time)
					return ok && actual.Equal(deleted.(time.Time))
				})
			})
		}
	}
}

func prepareManagedPointQuery(t *testing.T, f *nativeFixture, connection *pgx.Conn, name, query string, expectedOIDs []uint32) {
	t.Helper()
	description, err := connection.Prepare(f.ctx, "managed-point-"+name, query)
	if err != nil {
		t.Fatal("prepare exact managed point SQL", err)
	}
	explained, err := connection.Prepare(f.ctx, "managed-point-explain-"+name, `EXPLAIN (ANALYZE,BUFFERS,FORMAT JSON) `+query)
	if err != nil || !slices.Equal(description.ParamOIDs, expectedOIDs) || !slices.Equal(description.ParamOIDs, explained.ParamOIDs) {
		t.Fatal("measurement did not preserve production binding types", err, description.ParamOIDs)
	}
	t.Logf("%s exact SQL=%s; actual PostgreSQL parameter OIDs=%v", name, query, description.ParamOIDs)
}

func measureManagedPointQuery(t *testing.T, f *nativeFixture, connection *pgx.Conn, name, query string, args []any, wantRows, examinedBound int, relations []string, valid func([]any) bool) {
	t.Helper()
	var wire []byte
	if err := connection.QueryRow(f.ctx, `EXPLAIN (ANALYZE,BUFFERS,FORMAT JSON) `+query, args...).Scan(&wire); err != nil {
		t.Fatal("measure exact managed point SQL", err)
	}
	plan := parseBulkQueryPlan(t, wire)
	work := make(map[string]float64)
	var visit func(bulkQueryPlanNode)
	visit = func(node bulkQueryPlanNode) {
		if slices.Contains(relations, node.Relation) {
			work[node.Relation] += (node.Rows + node.Filtered) * node.Loops
			if node.Loops > 0 && (!strings.Contains(node.NodeType, "Index") || node.Index == "") {
				t.Fatalf("%s lost indexed point access: %s", name, plan.sanitized(t))
			}
		}
		for _, child := range node.Plans {
			visit(child)
		}
	}
	visit(plan.Plan)
	for _, relation := range relations {
		if examined, found := work[relation]; !found || examined > float64(examinedBound) {
			t.Fatalf("%s lost examined-row bound <=%d on %s: %s", name, examinedBound, relation, plan.sanitized(t))
		}
	}
	if plan.Plan.Rows != float64(wantRows) {
		t.Fatalf("%s returned unexpected rows: %s", name, plan.sanitized(t))
	}
	var samples [3]time.Duration
	for sample := range samples {
		start := time.Now()
		rows, err := connection.Query(f.ctx, query, args...)
		if err != nil {
			t.Fatal(err)
		}
		count := 0
		for rows.Next() {
			values, err := rows.Values()
			if err != nil || !valid(values) {
				rows.Close()
				t.Fatal("exact managed point read changed retained output", err)
			}
			count++
		}
		rows.Close()
		samples[sample] = time.Since(start)
		if rows.Err() != nil || count != wantRows {
			t.Fatal("exact managed point read changed hit/miss outcome", rows.Err(), count)
		}
	}
	types := make([]string, len(args))
	for i, arg := range args {
		types[i] = fmt.Sprintf("%T", arg)
	}
	t.Logf("%s Go bindings=%s; returned=%d examined=%v bound=%d; sanitized plan=%s; complete pgx client samples=%v; one SQL/sample, includes transfer, excludes pool acquisition, setup and domain Work/admission; warm sequential isolated fixture, no concurrent writer or production-load claim", name, strings.Join(types, ","), wantRows, work, examinedBound, plan.sanitized(t), samples)
}
