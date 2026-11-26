//go:build integration

package scimpostgres

import (
	"crypto/sha256"
	"fmt"
	"slices"
	"strings"
	"testing"
	"time"

	identity "github.com/faustbrian/go-identity"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
)

func TestManagedConnectionRotateRepresentativePlans(t *testing.T) {
	const tenant = "AAAAAAAAAAAAAAAAAAAACA"
	const foreign = "AAAAAAAAAAAAAAAAAAAADA"
	const dense = "AAAAAAAAAAAAAAAAAAAACQ"
	const sparse = "AAAAAAAAAAAAAAAAAAAACg"
	f := newNativeFixture(t, identity.TenantID(tenant), identity.TenantID(foreign))
	installManagedConnectionFixtureMigration(t, f)
	acquired, err := f.pool.Raw().Acquire(f.ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer acquired.Release()
	connection := acquired.Conn()
	if _, err := connection.Exec(f.ctx, `SET statement_timeout='5s'; SET lock_timeout='1s'`); err != nil {
		t.Fatal("bound isolated rotation measurement", err)
	}
	if _, err := connection.Exec(f.ctx, `CREATE TEMP TABLE rotation_plan_fixture AS
 SELECT n,CASE WHEN n<=8003 THEN $1 ELSE $2 END::text tenant_id,
 CASE WHEN n<=8000 THEN $3 WHEN n<=8003 THEN $4 ELSE translate(rtrim(encode(decode(md5('rotation-org-'||(n%40)),'hex'),'base64'),'='),'+/','-_') END::text organization_id,
 translate(rtrim(encode(decode(md5('rotation-connection-'||n),'hex'),'base64'),'='),'+/','-_') connection_id,
 translate(rtrim(encode(decode(md5('rotation-command-'||n),'hex'),'base64'),'='),'+/','-_') command_id
 FROM generate_series(1,10003) n`, tenant, foreign, dense, sparse); err != nil {
		t.Fatal("seed isolated representative rotation keys", err)
	}
	if _, err := connection.Exec(f.ctx, `INSERT INTO organization.organizations(tenant_id,organization_id,slug,name,state,version,member_count,owner_count,credential_version)
 SELECT DISTINCT tenant_id,organization_id,'rotation-'||md5(organization_id),'Rotation plan','active',1,1,1,1 FROM rotation_plan_fixture`); err != nil {
		t.Fatal(err)
	}
	expiry := time.Now().UTC().Truncate(time.Microsecond).Add(time.Hour)
	if _, err := connection.Exec(f.ctx, `INSERT INTO scim.connections(tenant_id,organization_id,provider_id,connection_id,credential_id,credential_digest,configuration_digest,version,state,expires_at,authority_version,organization_credential_version,command_id,effect_digest)
 SELECT tenant_id,organization_id,'rotation-plan-provider',connection_id,'rotation-plan-credential',sha256('rotation credential'),sha256('rotation profile'),1,'active',$1,1,1,command_id,sha256('rotation effect') FROM rotation_plan_fixture`, expiry); err != nil {
		t.Fatal(err)
	}
	mappings := []byte(`[{"source":"userName","target":"scim_user_name","writable":true}]`)
	if _, err := connection.Exec(f.ctx, `INSERT INTO scim.managed_connections(tenant_id,organization_id,provider_id,connection_id,mappings,deprovision_policy)
 SELECT tenant_id,organization_id,'rotation-plan-provider',connection_id,$1,'remove-membership' FROM rotation_plan_fixture`, mappings); err != nil {
		t.Fatal(err)
	}
	if _, err := connection.Exec(f.ctx, `ANALYZE scim.connections; ANALYZE scim.managed_connections`); err != nil {
		t.Fatal(err)
	}
	var engine string
	if err := connection.QueryRow(f.ctx, `SHOW server_version`).Scan(&engine); err != nil {
		t.Fatal(err)
	}
	t.Logf("PostgreSQL %s; 10003 managed bindings plus existing configured v1; dense organization=8000, sparse=3, unrelated tenant=2000; fresh statistics; warm sequential normal planner; point-key operation, no new index; no production or concurrent load claim", engine)
	schema, err := connection.Query(f.ctx, `SELECT c.relname,a.attname,format_type(a.atttypid,a.atttypmod) FROM pg_attribute a JOIN pg_class c ON c.oid=a.attrelid WHERE a.attrelid IN('scim.connections'::regclass,'scim.managed_connections'::regclass) AND a.attnum>0 AND NOT a.attisdropped ORDER BY c.relname,a.attnum`)
	if err != nil {
		t.Fatal(err)
	}
	for schema.Next() {
		var table, column, kind string
		if err := schema.Scan(&table, &column, &kind); err != nil {
			t.Fatal(err)
		}
		t.Logf("actual column %s.%s %s", table, column, kind)
	}
	schema.Close()
	if schema.Err() != nil {
		t.Fatal(schema.Err())
	}
	indexes, err := connection.Query(f.ctx, `SELECT indexdef FROM pg_indexes WHERE schemaname='scim' AND tablename IN('connections','managed_connections') ORDER BY indexname`)
	if err != nil {
		t.Fatal(err)
	}
	for indexes.Next() {
		var definition string
		if err := indexes.Scan(&definition); err != nil {
			t.Fatal(err)
		}
		t.Log("actual index", definition)
	}
	indexes.Close()
	if indexes.Err() != nil {
		t.Fatal(indexes.Err())
	}
	prepareManagedPointQuery(t, f, connection, "rotation-preparation", managedRotatePreparationSQL, []uint32{25, 25, 25, 1700})
	prepareManagedPointQuery(t, f, connection, "rotation-fence", managedRotateFenceSQL, []uint32{25, 25, 25, 25})
	prepareManagedPointQuery(t, f, connection, "rotation-recovery", managedRotateRecoverySQL, []uint32{25, 25, 25, 25})
	for _, selected := range []struct {
		name, org string
		n         int
	}{{"dense", dense, 1}, {"sparse", sparse, 8001}} {
		var id string
		if err := connection.QueryRow(f.ctx, `SELECT connection_id FROM rotation_plan_fixture WHERE n=$1`, selected.n).Scan(&id); err != nil {
			t.Fatal(err)
		}
		for _, mode := range []string{"hit", "missing", "foreign-tenant", "foreign-organization", "stale-version"} {
			t.Run(selected.name+"/"+mode, func(t *testing.T) {
				prepare := []any{tenant, selected.org, id, "1"}
				fence := []any{tenant, selected.org, "rotation-plan-provider", id}
				want := 1
				switch mode {
				case "missing":
					prepare[2], fence[3] = "AAAAAAAAAAAAAAAAAAAABQ", "AAAAAAAAAAAAAAAAAAAABQ"
					want = 0
				case "foreign-tenant":
					prepare[0], fence[0] = foreign, foreign
					want = 0
				case "foreign-organization":
					prepare[1], fence[1] = "AAAAAAAAAAAAAAAAAAAACw", "AAAAAAAAAAAAAAAAAAAACw"
					want = 0
				case "stale-version":
					prepare[3] = "2"
					want = 0
				}
				measureManagedPointQuery(t, f, connection, "rotation-preparation", managedRotatePreparationSQL, prepare, want, 1, []string{"managed_connections", "connections"}, func(row []any) bool {
					return len(row) == 11 && row[0] == "rotation-plan-provider" && row[2] == managedRemoveMembership && row[3] == "rotation-plan-credential"
				})
				fenceWant := want
				if mode == "stale-version" {
					fenceWant = 1
				}
				measureManagedPointQuery(t, f, connection, "rotation-fence", managedRotateFenceSQL, fence, fenceWant, 1, []string{"managed_connections", "connections"}, func(row []any) bool {
					return len(row) == 11 && row[0] == "1" && row[1] == "rotation-plan-credential" && row[10] == managedRemoveMembership
				})
				measureManagedPointQuery(t, f, connection, "rotation-recovery", managedRotateRecoverySQL, fence, fenceWant, 1, []string{"connections"}, func(row []any) bool { return len(row) == 3 && row[0] == "1" })
				measureManagedRotationUpdate(t, f, connection, fence, mode)
			})
		}
	}
	t.Log("incremental owning operation: preparation resolves organization plus one predecessor SELECT; execution resolves organization and reads canonical custody, then one native reservation/Work, two exact authority+connection checks and one credential UPDATE; replay reads no resource content and emits no bearer; adapter SQL samples exclude shared kernel/session owner queries and contention")
}

func measureManagedRotationUpdate(t *testing.T, f *nativeFixture, connection *pgx.Conn, keys []any, mode string) {
	t.Helper()
	oids := []uint32{25, 25, 25, 25, 25, 17, 17, 1184, 25, 25, 25, 25, 17, 25, 25, 17, 17}
	for _, prefix := range []string{"", "EXPLAIN (ANALYZE,BUFFERS,FORMAT JSON) "} {
		description, err := connection.PgConn().Prepare(f.ctx, "", prefix+managedRotateUpdateSQL, oids)
		if err != nil || !slices.Equal(description.ParamOIDs, oids) {
			t.Fatal("prepare exact rotation Work bindings", err)
		}
	}
	digest := sha256.Sum256([]byte("rotation credential"))
	profile := sha256.Sum256([]byte("rotation profile"))
	successor := sha256.Sum256([]byte("rotation successor"))
	command, err := identity.NewCommandID()
	if err != nil {
		t.Fatal(err)
	}
	args := append(slices.Clone(keys), "rotation-successor-credential", successor[:], successor[:], time.Now().UTC().Truncate(time.Microsecond).Add(time.Hour), "2", "1", "1", string(command), successor[:], "1", "rotation-plan-credential", digest[:], profile[:])
	if mode == "stale-version" {
		args[13] = "2"
	}
	want := int64(0)
	if mode == "hit" {
		want = 1
	}
	codecs := pgtype.NewMap()
	values, formats := make([][]byte, len(args)), make([]int16, len(args))
	for i, value := range args {
		formats[i] = pgtype.BinaryFormatCode
		values[i], err = codecs.Encode(oids[i], formats[i], value, nil)
		if err != nil {
			t.Fatal("encode actual Work primitive", i, err)
		}
	}
	withBulkMutationPlanTransaction(t, f.ctx, connection, func(tx pgx.Tx) {
		for sample := range 4 {
			savepoint, err := tx.Begin(f.ctx)
			if err != nil {
				t.Fatal(err)
			}
			query := managedRotateUpdateSQL
			if sample == 0 {
				query = "EXPLAIN (ANALYZE,BUFFERS,FORMAT JSON) " + query
			}
			start := time.Now()
			result := connection.PgConn().ExecParams(f.ctx, query, values, oids, formats, nil).Read()
			elapsed := time.Since(start)
			if result.Err != nil {
				t.Fatal("execute exact rotation Work UPDATE", result.Err)
			}
			if sample == 0 {
				if len(result.Rows) != 1 || len(result.Rows[0]) != 1 {
					t.Fatal("missing exact UPDATE plan")
				}
				plan := parseBulkQueryPlan(t, result.Rows[0][0])
				examined := float64(0)
				var visit func(bulkQueryPlanNode)
				visit = func(node bulkQueryPlanNode) {
					if node.Relation == "connections" && node.NodeType != "ModifyTable" {
						if !strings.Contains(node.NodeType, "Index") {
							t.Fatal("rotation UPDATE lost indexed exact predecessor", plan.sanitized(t))
						}
						examined += (node.Rows + node.Filtered) * node.Loops
					}
					for _, child := range node.Plans {
						visit(child)
					}
				}
				visit(plan.Plan)
				if examined > 1 {
					t.Fatal("rotation UPDATE exceeded one exact predecessor", plan.sanitized(t))
				}
				t.Logf("rotation UPDATE mode=%s native Work OIDs=%v examined<=1 sanitized plan=%s", mode, oids, plan.sanitized(t))
			} else {
				if result.CommandTag.RowsAffected() != want {
					t.Fatal("rotation UPDATE changed unexpected row count", result.CommandTag)
				}
				t.Logf("rotation UPDATE mode=%s sample=%d affected=%d client elapsed=%s", mode, sample, want, elapsed)
			}
			if err := savepoint.Rollback(f.ctx); err != nil {
				t.Fatal("rollback rotation sample", err)
			}
		}
	})
	types := make([]string, len(args))
	for i, arg := range args {
		types[i] = fmt.Sprintf("%T", arg)
	}
	t.Logf("exact rotation UPDATE SQL=%s; native Go bindings=%s; no retained writes", managedRotateUpdateSQL, strings.Join(types, ","))
}
