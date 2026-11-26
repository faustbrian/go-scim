//go:build integration

package scimpostgres

import (
	"bytes"
	"reflect"
	"strings"
	"testing"
	"time"

	identity "github.com/faustbrian/go-identity"
	"github.com/jackc/pgx/v5"
)

// These are incremental SQL measurements, not end-to-end administrator timings:
// session, organization/policy admission and the final authority recheck remain
// covered by TestManagedConnectionGetAndListRequireCurrentAdministrator. The
// normal-planner fixture is warm, sequential and isolated, not production load.
func TestManagedConnectionRepresentativeReadPlans(t *testing.T) {
	const tenant = "AAAAAAAAAAAAAAAAAAAACA"
	const foreignTenant = "AAAAAAAAAAAAAAAAAAAADA"
	const denseOrg = "AAAAAAAAAAAAAAAAAAAACQ"
	const sparseOrg = "AAAAAAAAAAAAAAAAAAAACg"
	const missingOrg = "AAAAAAAAAAAAAAAAAAAACw"
	f := newNativeFixture(t, identity.TenantID(tenant), identity.TenantID(foreignTenant))
	installManagedConnectionFixtureMigration(t, f)
	connection, err := f.pool.Raw().Acquire(f.ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer connection.Release()
	if _, err := connection.Exec(f.ctx, `SET statement_timeout='5s'; SET lock_timeout='1s'`); err != nil {
		t.Fatal("bound isolated measurement statements", err)
	}
	// Canonical synthetic IDs preserve the actual key width and bytewise
	// ordering. A dense organization has 8,000 rows (800 deleted), a selective
	// organization has three, and 2,000 unrelated rows span 40 tenant/org pairs.
	if _, err := connection.Exec(f.ctx, `CREATE TEMP TABLE managed_read_plan_fixture AS
 SELECT n,CASE WHEN n<=9003 THEN $1 ELSE $2 END::text AS tenant_id,
 CASE WHEN n<=8000 THEN $3 WHEN n<=8003 THEN $4 ELSE
 translate(rtrim(encode(decode(md5('managed-plan-org-'||(n%20)),'hex'),'base64'),'='),'+/','-_') END::text AS organization_id,
 translate(rtrim(encode(decode(md5('managed-plan-connection-'||n),'hex'),'base64'),'='),'+/','-_') AS connection_id,
 translate(rtrim(encode(decode(md5('managed-plan-command-'||n),'hex'),'base64'),'='),'+/','-_') AS command_id,
 CASE WHEN n<=8000 AND n%10=0 THEN 'deleted' ELSE 'active' END::text AS state
 FROM generate_series(1,10003) n`, tenant, foreignTenant, denseOrg, sparseOrg); err != nil {
		t.Fatal("seed isolated representative key distribution", err)
	}
	if _, err := connection.Exec(f.ctx, `INSERT INTO organization.organizations
 (tenant_id,organization_id,slug,name,state,version,member_count,owner_count,credential_version)
 SELECT DISTINCT tenant_id,organization_id,'plan-'||md5(organization_id),'Synthetic read plan','active',1,1,1,1
 FROM managed_read_plan_fixture`); err != nil {
		t.Fatal("seed synthetic organization owners", err)
	}
	if _, err := connection.Exec(f.ctx, `INSERT INTO scim.connections
 (tenant_id,organization_id,provider_id,connection_id,credential_id,credential_digest,configuration_digest,version,state,expires_at,authority_version,organization_credential_version,command_id,effect_digest)
 SELECT tenant_id,organization_id,'managed-plan-provider',connection_id,'managed-plan-credential',sha256('synthetic credential'),sha256('synthetic configuration'),1,state,clock_timestamp()+interval '1 hour',1,1,command_id,sha256('synthetic effect')
 FROM managed_read_plan_fixture`); err != nil {
		t.Fatal("seed representative native binding rows", err)
	}
	mapping := []byte(`[{"source":"userName","target":"scim_user_name","writable":true}]`)
	if _, err := connection.Exec(f.ctx, `INSERT INTO scim.managed_connections
 (tenant_id,organization_id,provider_id,connection_id,mappings,deprovision_policy)
 SELECT tenant_id,organization_id,'managed-plan-provider',connection_id,$1,'remove-membership'
 FROM managed_read_plan_fixture`, mapping); err != nil {
		t.Fatal("seed representative administrative projections", err)
	}
	if _, err := connection.Exec(f.ctx, `ANALYZE scim.managed_connections; ANALYZE scim.connections`); err != nil {
		t.Fatal(err)
	}
	var version string
	if err := connection.QueryRow(f.ctx, `SHOW server_version`).Scan(&version); err != nil {
		t.Fatal(err)
	}
	t.Logf("PostgreSQL %s; managed=10003 bindings=10004; selected tenant=9003 foreign=1000; dense org=8000 (800 deleted), sparse org=3; fresh statistics; normal planner; warm cache; sequential client; no concurrent writer", version)
	rows, err := connection.Query(f.ctx, `SELECT c.relname,a.attname,format_type(a.atttypid,a.atttypmod)
 FROM pg_attribute a JOIN pg_class c ON c.oid=a.attrelid
 WHERE a.attrelid IN ('scim.managed_connections'::regclass,'scim.connections'::regclass)
 AND a.attnum>0 AND NOT a.attisdropped ORDER BY c.relname,a.attnum`)
	if err != nil {
		t.Fatal(err)
	}
	for rows.Next() {
		var table, column, kind string
		if err := rows.Scan(&table, &column, &kind); err != nil {
			rows.Close()
			t.Fatal(err)
		}
		t.Logf("actual column %s.%s=%s", table, column, kind)
	}
	rows.Close()
	if rows.Err() != nil {
		t.Fatal(rows.Err())
	}
	rows, err = connection.Query(f.ctx, `SELECT pg_get_indexdef(indexrelid) FROM pg_index
 WHERE indrelid IN ('scim.managed_connections'::regclass,'scim.connections'::regclass)
 AND indisvalid AND indisready ORDER BY indexrelid`)
	if err != nil {
		t.Fatal(err)
	}
	for rows.Next() {
		var definition string
		if err := rows.Scan(&definition); err != nil {
			rows.Close()
			t.Fatal(err)
		}
		t.Logf("actual usable index=%s", definition)
	}
	rows.Close()
	if rows.Err() != nil {
		t.Fatal(rows.Err())
	}
	for _, query := range []struct{ name, sql, bindings string }{
		{"organization", managedConnectionOrganizationSQL, "string,string"},
		{"get", managedConnectionGetSQL, "string,string,string"},
		{"list", managedConnectionListSQL, "string,string,string,int (requested limit+1)"},
	} {
		description, err := connection.Conn().Prepare(f.ctx, "managed-read-plan-"+query.name, query.sql)
		if err != nil {
			t.Fatal("prepare exact managed reader SQL", err)
		}
		t.Logf("%s SQL=%s; actual pgx parameter OIDs=%v; Go bindings=%s", query.name, query.sql, description.ParamOIDs, query.bindings)
	}
	idAt := func(n int) string {
		t.Helper()
		var id string
		if err := connection.QueryRow(f.ctx, `SELECT connection_id FROM managed_read_plan_fixture WHERE n=$1`, n).Scan(&id); err != nil {
			t.Fatal(err)
		}
		return id
	}
	for _, test := range []struct {
		name, tenant, org, id     string
		organizationRows, getRows int
	}{
		{"dense-hit", tenant, denseOrg, idAt(1), 1, 1},
		{"sparse-hit", tenant, sparseOrg, idAt(8001), 1, 1},
		{"deleted-binding", tenant, denseOrg, idAt(10), 1, 0},
		{"missing-key", tenant, denseOrg, "AAAAAAAAAAAAAAAAAAAABQ", 0, 0},
		{"foreign-tenant", foreignTenant, denseOrg, idAt(1), 0, 0},
		{"foreign-organization", tenant, sparseOrg, idAt(1), 1, 0},
	} {
		t.Run(test.name, func(t *testing.T) {
			var expectedOrganizations []string
			if test.organizationRows == 1 {
				var organization string
				if err := connection.QueryRow(f.ctx, `SELECT organization_id FROM managed_read_plan_fixture WHERE tenant_id=$1 AND connection_id=$2`, test.tenant, test.id).Scan(&organization); err != nil {
					t.Fatal(err)
				}
				expectedOrganizations = []string{organization}
			}
			measureManagedConnectionRead(t, f, connection.Conn(), "organization", managedConnectionOrganizationSQL, []any{test.tenant, test.id}, test.organizationRows, 1, expectedOrganizations, "")
			var expected []string
			if test.getRows == 1 {
				expected = []string{test.id}
			}
			measureManagedConnectionRead(t, f, connection.Conn(), "get", managedConnectionGetSQL, []any{test.tenant, test.org, test.id}, test.getRows, 1, expected, "")
		})
	}
	afterOffset := func(offset int) string {
		t.Helper()
		var id string
		if err := connection.QueryRow(f.ctx, `SELECT connection_id FROM managed_read_plan_fixture
 WHERE tenant_id=$1 AND organization_id=$2 AND state<>'deleted' ORDER BY connection_id OFFSET $3 LIMIT 1`, tenant, denseOrg, offset).Scan(&id); err != nil {
			t.Fatal(err)
		}
		return id
	}
	for _, test := range []struct {
		name, tenant, org, after string
		limit                    int
	}{
		{"dense-first-minimum", tenant, denseOrg, "", 1},
		{"dense-first-maximum", tenant, denseOrg, "", 200},
		{"dense-middle-maximum", tenant, denseOrg, afterOffset(3600), 200},
		{"dense-deep-final-page", tenant, denseOrg, afterOffset(7100), 200},
		{"dense-exhausted", tenant, denseOrg, afterOffset(7199), 200},
		{"selective-organization", tenant, sparseOrg, "", 200},
		{"missing-organization", tenant, missingOrg, "", 200},
		{"foreign-tenant", foreignTenant, denseOrg, "", 200},
	} {
		t.Run(test.name, func(t *testing.T) {
			rows, err := connection.Query(f.ctx, `SELECT connection_id FROM managed_read_plan_fixture
 WHERE tenant_id=$1 AND organization_id=$2 AND state<>'deleted' AND connection_id>$3 ORDER BY connection_id LIMIT $4`, test.tenant, test.org, test.after, test.limit+1)
			if err != nil {
				t.Fatal(err)
			}
			var expected []string
			for rows.Next() {
				var id string
				if err := rows.Scan(&id); err != nil {
					rows.Close()
					t.Fatal(err)
				}
				expected = append(expected, id)
			}
			rows.Close()
			if rows.Err() != nil {
				t.Fatal(rows.Err())
			}
			var candidates, deleted int
			if err := connection.QueryRow(f.ctx, `SELECT count(*),count(*) FILTER (WHERE state='deleted')
 FROM managed_read_plan_fixture WHERE tenant_id=$1 AND organization_id=$2 AND connection_id>$3`, test.tenant, test.org, test.after).Scan(&candidates, &deleted); err != nil {
				t.Fatal(err)
			}
			// LIMIT alone does not bound examined rows: deleted bindings are
			// retained metadata and can require extra indexed join probes.
			bound := min(candidates, test.limit+1+deleted)
			measureManagedConnectionRead(t, f, connection.Conn(), "list", managedConnectionListSQL, []any{test.tenant, test.org, test.after, test.limit + 1}, len(expected), bound, expected, "managed_connections_organization_page")
		})
	}
	measureManagedProvisioningPlans(t, f, connection.Conn(), tenant, foreignTenant, denseOrg, sparseOrg, idAt(1), idAt(8001), idAt(10), mapping)
	measureManagedWithdrawalPlans(t, f, connection.Conn())
	measureManagedCreatePlans(t, f, connection.Conn(), tenant, denseOrg, sparseOrg, mapping)
}

func measureManagedConnectionRead(t *testing.T, f *nativeFixture, connection *pgx.Conn, name, sql string, args []any, wantRows, examinedBound int, expected []string, requiredIndex string) {
	t.Helper()
	var wire []byte
	if err := connection.QueryRow(f.ctx, `EXPLAIN (ANALYZE,BUFFERS,FORMAT JSON) `+sql, args...).Scan(&wire); err != nil {
		t.Fatal("measure exact managed SQL and native bindings", err)
	}
	plan := parseBulkQueryPlan(t, wire)
	var managedRows, bindingRows float64
	var foundRequiredIndex bool
	var visit func(bulkQueryPlanNode)
	visit = func(node bulkQueryPlanNode) {
		if node.Index == requiredIndex {
			foundRequiredIndex = true
		}
		if node.Loops > 0 && (node.Relation == "managed_connections" || node.Relation == "connections") {
			if !strings.Contains(node.NodeType, "Index") || node.Index == "" {
				t.Fatalf("%s traversed projections without an indexed boundary: %s", name, plan.sanitized(t))
			}
			work := (node.Rows + node.Filtered) * node.Loops
			if node.Relation == "managed_connections" {
				managedRows += work
			} else {
				bindingRows += work
			}
		}
		for _, child := range node.Plans {
			visit(child)
		}
	}
	visit(plan.Plan)
	if plan.Plan.Rows != float64(wantRows) || managedRows > float64(examinedBound) || bindingRows > float64(examinedBound) || requiredIndex != "" && !foundRequiredIndex {
		t.Fatalf("%s lost scoped output/work bound rows=%d examined<=%d: %s", name, wantRows, examinedBound, plan.sanitized(t))
	}
	var samples [3]time.Duration
	for sample := range samples {
		start := time.Now()
		rows, err := connection.Query(f.ctx, sql, args...)
		if err != nil {
			t.Fatal(err)
		}
		var ids []string
		for rows.Next() {
			var id string
			if name == "organization" {
				if err := rows.Scan(&id); err != nil {
					rows.Close()
					t.Fatal(err)
				}
			} else {
				var provider, policy, version string
				var mapping []byte
				if err := rows.Scan(&provider, &id, &mapping, &policy, &version); err != nil {
					rows.Close()
					t.Fatal(err)
				}
				if provider != "managed-plan-provider" || policy != "remove-membership" || version != "1" || !bytes.Equal(mapping, []byte(`[{"source":"userName","target":"scim_user_name","writable":true}]`)) {
					rows.Close()
					t.Fatal("actual managed SQL changed the retained projection")
				}
			}
			ids = append(ids, id)
		}
		rows.Close()
		samples[sample] = time.Since(start)
		if rows.Err() != nil || len(ids) != wantRows || !reflect.DeepEqual(ids, expected) {
			t.Fatal("actual managed driver execution changed ordered exact results", rows.Err(), ids, expected)
		}
	}
	t.Logf("%s returned=%d examined managed=%.0f binding=%.0f bound=%d; sanitized plan=%s; complete pgx client samples=%v; one SQL statement/sample, includes transfer, excludes acquisition, setup and authority admission/recheck", name, wantRows, managedRows, bindingRows, examinedBound, plan.sanitized(t), samples)
}
