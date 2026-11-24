//go:build integration

package scimpostgres

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	scim "github.com/faustbrian/go-scim"
)

// This synthetic context measures the two new exact-key reads, not production
// scale or contention. Native Work and this pgx hook use the same SQL and string
// bindings. The lifecycle regression separately exercises the owning operation.
func TestDirectoryGroupEdgeRepresentativePointLookupPlans(t *testing.T) {
	f, groups := nativeGroupsFixture(t)
	user := createNativeNamed(t, f, "PlanUser", "Plan identity")
	var originalUser []byte
	if err := f.pool.Raw().QueryRow(f.ctx, `SELECT resource FROM scim.users WHERE resource_id=$1`, user).Scan(&originalUser); err != nil {
		t.Fatal("retain original synthetic User payload", err)
	}
	groupResponse, err := groups.Execute(f.ctx, groupRequest(f, scim.GroupCreate, "", "", "plan-group", `{"schemas":["urn:ietf:params:scim:schemas:core:2.0:Group"],"displayName":"Plan group"}`))
	if err != nil {
		t.Fatal(err)
	}
	group := groupID(t, groupResponse)
	// 10,000 irrelevant keys in each table make an accidental connection-wide
	// scan visible. Most keys share the selected scope; the full PK still admits
	// at most one row independently of member density and tenant selectivity.
	if _, err := f.pool.Raw().Exec(f.ctx, `INSERT INTO identity.users(tenant_id,user_id,status,version)
 SELECT 'tenant-a',translate(rtrim(encode(decode(md5('edge-plan-user-'||n),'hex'),'base64'),'='),'+/','-_'),'active',1
 FROM generate_series(1,10000) n`); err != nil {
		t.Fatal("seed representative identity cardinality", err)
	}
	if _, err := f.pool.Raw().Exec(f.ctx, `INSERT INTO scim.users(tenant_id,organization_id,provider_id,connection_id,resource_id,user_id,username_key,username_digest,external_id,resource,command_id,effect_digest)
 SELECT s.tenant_id,s.organization_id,s.provider_id,s.connection_id,
 translate(rtrim(encode(decode(md5('edge-plan-user-'||n),'hex'),'base64'),'='),'+/','-_'),
 translate(rtrim(encode(decode(md5('edge-plan-user-'||n),'hex'),'base64'),'='),'+/','-_'),
 'edge-plan-name-'||n,sha256(convert_to('edge-plan-name-'||n,'UTF8')),'',s.resource,
 translate(rtrim(encode(decode(md5('edge-plan-user-command-'||n),'hex'),'base64'),'='),'+/','-_'),s.effect_digest
 FROM scim.users s CROSS JOIN generate_series(1,10000) n WHERE s.resource_id=$1`, user); err != nil {
		t.Fatal("seed representative User projection cardinality", err)
	}
	if _, err := f.pool.Raw().Exec(f.ctx, `INSERT INTO scim.groups(tenant_id,organization_id,provider_id,connection_id,resource_id,resource,command_id,effect_digest)
 SELECT s.tenant_id,s.organization_id,s.provider_id,s.connection_id,
 translate(rtrim(encode(decode(md5('edge-plan-group-'||n),'hex'),'base64'),'='),'+/','-_'),s.resource,
 translate(rtrim(encode(decode(md5('edge-plan-group-command-'||n),'hex'),'base64'),'='),'+/','-_'),s.effect_digest
 FROM scim.groups s CROSS JOIN generate_series(1,10000) n WHERE s.resource_id=$1`, group); err != nil {
		t.Fatal("seed representative Group projection cardinality", err)
	}
	if _, err := f.pool.Raw().Exec(f.ctx, `ANALYZE scim.groups; ANALYZE scim.users`); err != nil {
		t.Fatal(err)
	}
	connection, err := f.pool.Raw().Acquire(f.ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer connection.Release()
	var version string
	if err := connection.QueryRow(f.ctx, `SHOW server_version`).Scan(&version); err != nil {
		t.Fatal(err)
	}
	t.Logf("PostgreSQL %s; synthetic groups=10001 users=10001; same-scope density; warm cache; sequential client; no concurrent writer", version)
	for _, query := range []struct {
		name, sql, id, table string
	}{
		{"Group", directoryGroupEdgeGroupSQL, group, "scim.groups"},
		{"GroupUser", directoryGroupEdgeUserSQL, user, "scim.users"},
		{"DeprovisionUser", directoryUserDeprovisionSQL, user, "scim.users"},
	} {
		if query.table == "scim.users" {
			// Give both User reads the same live-to-tombstone workload.
			if _, err := connection.Exec(f.ctx, `UPDATE scim.users SET resource=$2,deleted_at=NULL WHERE resource_id=$1`, user, originalUser); err != nil {
				t.Fatal("restore identical benchmark User", err)
			}
		}
		description, err := connection.Conn().Prepare(f.ctx, "edge-plan-"+query.name, query.sql)
		if err != nil {
			t.Fatal("prepare actual parameterized query", err)
		}
		t.Logf("%s SQL=%s; native Go binding types=string,string,string,string,string; PostgreSQL parameter OIDs=%v", query.name, query.sql, description.ParamOIDs)
		for _, mode := range []string{"live hit", "missing key", "foreign scope", "wide hit", "tombstone hit"} {
			args := append(scopeArgs(f.config.Scope), query.id)
			wantRows := 1
			switch mode {
			case "missing key":
				args[4], wantRows = "AAAAAAAAAAAAAAAAAAAAAQ", 0
			case "foreign scope":
				args[3], wantRows = "absent-connection", 0
			case "wide hit":
				if _, err := connection.Exec(f.ctx, `UPDATE `+query.table+` SET resource=convert_to($2,'UTF8') WHERE resource_id=$1`, query.id, strings.Repeat("x", 131072)); err != nil {
					t.Fatal(err)
				}
			case "tombstone hit":
				if _, err := connection.Exec(f.ctx, `UPDATE `+query.table+` SET resource=convert_to('null','UTF8'),deleted_at=clock_timestamp() WHERE resource_id=$1`, query.id); err != nil {
					t.Fatal(err)
				}
			}
			var plan []byte
			if err := connection.QueryRow(f.ctx, `EXPLAIN (ANALYZE,BUFFERS,FORMAT JSON) `+query.sql, args...).Scan(&plan); err != nil {
				t.Fatal("measure exact query plan and bindings", err)
			}
			var document []struct {
				Plan struct {
					NodeType       string  `json:"Node Type"`
					IndexName      string  `json:"Index Name"`
					ActualRows     float64 `json:"Actual Rows"`
					Loops          float64 `json:"Actual Loops"`
					FilteredRows   float64 `json:"Rows Removed by Filter"`
					IndexCondition string  `json:"Index Cond"`
				} `json:"Plan"`
			}
			if json.Unmarshal(plan, &document) != nil || len(document) != 1 {
				t.Fatalf("%s/%s returned an invalid query plan", query.name, mode)
			}
			scan := document[0].Plan
			// PostgreSQL may cost an empty connection prefix lower on a
			// different local index. It must not scan or filter any rows
			// for that foreign scope; retained live/tombstone hits use the PK.
			indexedScope := strings.HasSuffix(scan.IndexName, "_pkey") ||
				mode == "foreign scope" && scan.IndexName != "" && strings.Contains(scan.IndexCondition, "connection_id") && scan.FilteredRows == 0
			if scan.NodeType != "Index Scan" || !indexedScope || scan.ActualRows != float64(wantRows) || scan.Loops != 1 {
				t.Fatalf("%s/%s lost exact one-key access plan: %s", query.name, mode, plan)
			}
			elapsed := make([]time.Duration, 3)
			for sample := range elapsed {
				start := time.Now()
				rows, err := connection.Query(f.ctx, query.sql, args...)
				if err != nil {
					t.Fatal(err)
				}
				count := 0
				for rows.Next() {
					if _, err := rows.Values(); err != nil {
						t.Fatal(err)
					}
					count++
				}
				rows.Close()
				if rows.Err() != nil || count != wantRows {
					t.Fatal("actual driver execution returned unexpected rows", rows.Err(), count)
				}
				elapsed[sample] = time.Since(start)
			}
			t.Logf("%s/%s client samples=%v; exact plan=%s", query.name, mode, elapsed, plan)
		}
	}
}
