//go:build integration

package scimpostgres

import (
	"context"
	"fmt"
	"os"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	identity "github.com/faustbrian/go-identity"
	kernel "github.com/faustbrian/go-identity/postgres"
	database "github.com/faustbrian/go-postgres"
	scim "github.com/faustbrian/go-scim"
	"github.com/jackc/pgx/v5/pgconn"
)

const cyclicGroupBulkFixture = `{"schemas":["urn:ietf:params:scim:api:messages:2.0:BulkRequest"],"Operations":[` +
	`{"method":"POST","path":"/Groups","bulkId":"first","data":{"schemas":["urn:ietf:params:scim:schemas:core:2.0:Group"],"displayName":"First","members":[{"type":"Group","value":"bulkId:second"}]}},` +
	`{"method":"POST","path":"/Groups","bulkId":"second","data":{"schemas":["urn:ietf:params:scim:schemas:core:2.0:Group"],"displayName":"Second","members":[{"type":"Group","value":"bulkId:first"}]}}]}`

func bulkAdmissionFixture(t *testing.T, responsePolicy scim.BulkResponsePolicy) (*nativeFixture, *GroupBulkService) {
	t.Helper()
	f, groups := nativeGroupsFixture(t)
	saml := kernel.CanonicalSAMLStartRequestMigrationSource{Base: nativeCanonicalFixtureHistory(), Version: 15}
	aliases := kernel.CanonicalSCIMBulkRequestMigrationSource{Base: saml, Version: 17}
	steps, err := aliases.Load(f.ctx)
	if err != nil {
		t.Fatal(err)
	}
	for _, step := range steps {
		if step.Version() <= 14 {
			continue
		}
		if _, err := f.pool.Raw().Exec(f.ctx, step.UpSQL()); err != nil {
			t.Fatal("kernel aliases", step.Version(), err)
		}
	}
	groupHistory := GroupsMigrationSource{Base: UsersMigrationSource{Base: MigrationSource{Version: 40}, Version: 41}, Version: 42}
	steps, err = (BulkAdmissionMigrationSource{Base: groupHistory, Version: 43}).Load(f.ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.pool.Raw().Exec(f.ctx, steps[len(steps)-1].UpSQL()); err != nil {
		t.Fatal("native Bulk admission schema", err)
	}
	service, err := NewGroupBulkService(groups, scim.DefaultBulkPolicy(), responsePolicy)
	if err != nil {
		t.Fatal(err)
	}
	return f, service
}

func TestNativeGroupBulkAdmissionRetainsExactCyclicGraphWithoutExecuting(t *testing.T) {
	f, service := bulkAdmissionFixture(t, scim.DefaultBulkResponsePolicy())
	const body = cyclicGroupBulkFixture
	request := BulkAdmissionRequest{Credential: f.bearer, Body: []byte(body)}
	first, err := service.Admit(f.ctx, request)
	if err != nil || first.CommandID == "" || first.ChildCount != 2 || first.ResponseMaximumBytes <= 0 {
		t.Fatal("did not admit the complete graph", err)
	}
	key, err := identity.NewIdempotencyKey([]byte("retry-the-same-native-bulk-graph"))
	if err != nil {
		t.Fatal(err)
	}
	request.IdempotencyKey = &key
	again, err := service.Admit(f.ctx, request)
	if err != nil || again != first {
		t.Fatal("late alias did not recover the original parent", err)
	}
	request.Body = []byte(strings.Replace(body, `"Second"`, `"Changed"`, 1))
	if changed, err := service.Admit(f.ctx, request); protocolStatus(err) != 409 || changed != (BulkAdmission{}) {
		t.Fatal("changed request acquired original graph custody", err)
	}
	request.Body, request.IdempotencyKey = []byte(body), nil
	groupsOtherLimit, err := NewGroupsService(f.service, 1)
	if err != nil {
		t.Fatal(err)
	}
	other, err := NewGroupBulkService(groupsOtherLimit, scim.DefaultBulkPolicy(), scim.DefaultBulkResponsePolicy())
	if err != nil {
		t.Fatal(err)
	}
	if changed, err := other.Admit(f.ctx, request); protocolStatus(err) != 409 || changed != (BulkAdmission{}) {
		t.Fatal("changed Group membership policy acquired original graph custody", err)
	}
	rows, err := f.pool.Raw().Query(f.ctx, `SELECT ordinal,command_id,resource_id,bulk_id,component_id,component_order,cyclic,status,dependency_ids FROM scim.bulk_children WHERE parent_id=$1 ORDER BY ordinal`, string(first.CommandID))
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	type child struct {
		command, resource string
		dependencies      []string
	}
	var admitted [2]child
	for index, expectedBulkID := range []string{"first", "second"} {
		if !rows.Next() {
			t.Fatal("missing original child", index, rows.Err())
		}
		stored := &admitted[index]
		var ordinal, componentID, componentOrder int
		var bulkID []byte
		var status string
		var cyclic bool
		if err := rows.Scan(&ordinal, &stored.command, &stored.resource, &bulkID, &componentID, &componentOrder, &cyclic, &status, &stored.dependencies); err != nil {
			t.Fatal(err)
		}
		if ordinal != index || string(bulkID) != expectedBulkID || componentID != 0 || componentOrder != 0 || !cyclic || status != "admitted" || stored.resource == "" {
			t.Fatal("lost original order, allocation, SCC or initial checkpoint", index)
		}
		if _, err := identity.ParseCommandID(stored.command); err != nil || stored.command == string(first.CommandID) {
			t.Fatal("child must retain its own server command", index, err)
		}
	}
	if rows.Next() || rows.Err() != nil || admitted[0].command == admitted[1].command || admitted[0].resource == admitted[1].resource ||
		len(admitted[0].dependencies) != 1 || admitted[0].dependencies[0] != admitted[1].command || len(admitted[1].dependencies) != 1 || admitted[1].dependencies[0] != admitted[0].command {
		t.Fatal("retained cyclic dependencies or independent allocations differ")
	}
	var parents, projections int
	if err := f.pool.Raw().QueryRow(f.ctx, `SELECT (SELECT count(*) FROM scim.bulk_requests),(SELECT count(*) FROM scim.groups)`).Scan(&parents, &projections); err != nil || parents != 1 || projections != 0 {
		t.Fatal("admission or replay executed a child or duplicated the parent", parents, projections, err)
	}
}

func TestNativeGroupBulkRequiredEffectFailureRollsBackTheWholeGraph(t *testing.T) {
	f, _ := bulkAdmissionFixture(t, scim.DefaultBulkResponsePolicy())
	reached := new(atomic.Bool)
	service := bulkOnFixturePool(t, f, func(c *database.PoolConfig) {
		c.ConnConfig.RuntimeParams["client_min_messages"] = "notice"
		c.ConnConfig.OnNotice = func(_ *pgconn.PgConn, n *pgconn.Notice) {
			if n.Code == "PZ002" {
				reached.Store(true)
			}
		}
	})
	// The real outbox owner runs inside the protected Work, after both graph
	// inserts. The notice proves the provisional graph existed at the fault.
	if _, err := f.pool.Raw().Exec(f.ctx, `CREATE FUNCTION scim.fixture_bulk_outbox_failure() RETURNS trigger LANGUAGE plpgsql AS $f$
BEGIN
 IF (SELECT count(*) FROM scim.bulk_requests) = 1 AND (SELECT count(*) FROM scim.bulk_children) = 2 THEN
  RAISE NOTICE USING ERRCODE='PZ002',MESSAGE='owned graph reached outbox';
 END IF;
 RAISE EXCEPTION 'owned outbox failure';
END $f$;
CREATE TRIGGER fixture_bulk_outbox_failure BEFORE INSERT ON public.outbox_messages FOR EACH ROW EXECUTE FUNCTION scim.fixture_bulk_outbox_failure()`); err != nil {
		t.Fatal(err)
	}
	admitted, err := service.Admit(f.ctx, BulkAdmissionRequest{Credential: f.bearer, Body: []byte(cyclicGroupBulkFixture)})
	if protocolStatus(err) != 503 || admitted != (BulkAdmission{}) || !reached.Load() {
		t.Fatal("did not reach the required effect failure after provisional graph", reached.Load(), err)
	}
	requireNativeBulkCounts(t, f, [5]int{})
}

func TestNativeGroupBulkRecoversExactGraphAfterLostCommitAcknowledgement(t *testing.T) {
	f, service := bulkAdmissionFixture(t, scim.DefaultBulkResponsePolicy())
	fault := new(nativeCommitFault)
	uncertain := bulkOnFixturePool(t, f, func(c *database.PoolConfig) { c.ConnConfig.DialFunc = fault.dial })
	request := BulkAdmissionRequest{Credential: f.bearer, Body: []byte(cyclicGroupBulkFixture)}
	if result, err := uncertain.Admit(f.ctx, request); protocolStatus(err) != 503 || result != (BulkAdmission{}) || !fault.hit.Load() {
		t.Fatal("did not lose the real admission commit acknowledgement", fault.hit.Load(), err)
	}
	var parent string
	if err := f.pool.Raw().QueryRow(f.ctx, `SELECT parent_id FROM scim.bulk_requests`).Scan(&parent); err != nil {
		t.Fatal("original committed graph absent", err)
	}
	requireNativeBulkCounts(t, f, [5]int{1, 2, 1, 1, 1})
	f.deny.Store(true)
	if denied, err := service.Admit(f.ctx, request); protocolStatus(err) != 403 || denied != (BulkAdmission{}) {
		t.Fatal("replay disclosed graph while current authority denied", err)
	}
	f.deny.Store(false)
	if result, err := service.Admit(f.ctx, request); err != nil || string(result.CommandID) != parent || result.ChildCount != 2 {
		t.Fatal("retry did not recover the original admitted graph", err)
	}
	requireNativeBulkCounts(t, f, [5]int{1, 2, 1, 1, 1})
}

func TestNativeGroupBulkReusesOriginalAfterLostReservationAcknowledgement(t *testing.T) {
	f, service := bulkAdmissionFixture(t, scim.DefaultBulkResponsePolicy())
	f.config.Coordinator.LeaseDuration = 100 * time.Millisecond
	fault := &nativeCommitFault{reservation: true}
	uncertain := bulkOnFixturePool(t, f, func(c *database.PoolConfig) { c.ConnConfig.DialFunc = fault.dial })
	request := BulkAdmissionRequest{Credential: f.bearer, Body: []byte(cyclicGroupBulkFixture)}
	if result, err := uncertain.Admit(f.ctx, request); protocolStatus(err) != 503 || result != (BulkAdmission{}) || !fault.hit.Load() {
		t.Fatal("did not lose the real reservation acknowledgement", fault.hit.Load(), err)
	}
	requireNativeBulkCounts(t, f, [5]int{})
	var pending string
	var remainingMicros int64
	err := f.pool.Raw().QueryRow(f.ctx, `SELECT encode(command_id,'hex'), greatest(0,ceil(extract(epoch from (lease_until-clock_timestamp()))*1000000))::bigint
FROM identity.commands WHERE purpose=$1 AND state='pending'`, string(scim.Bulk)).Scan(&pending, &remainingMicros)
	if err != nil || pending == "" || remainingMicros > 100000 {
		t.Fatal("missing original pending parent and bounded lease", err)
	}
	untilExpired := time.NewTimer(time.Duration(remainingMicros+1000) * time.Microsecond)
	defer untilExpired.Stop()
	select {
	case <-untilExpired.C:
	case <-f.ctx.Done():
		t.Fatal("actual parent lease did not expire in the owned fixture")
	}
	result, err := service.Admit(f.ctx, request)
	if err != nil || result.ChildCount != 2 {
		t.Fatal("expired pending parent did not recover original admission", err)
	}
	var recovered string
	err = f.pool.Raw().QueryRow(f.ctx, `SELECT encode(command_id,'hex') FROM identity.commands WHERE purpose=$1 AND state='committed'`, string(scim.Bulk)).Scan(&recovered)
	if err != nil || recovered != pending {
		t.Fatal("pending retry allocated another command", err)
	}
	requireNativeBulkCounts(t, f, [5]int{1, 2, 1, 1, 1})
}

func bulkOnFixturePool(t *testing.T, f *nativeFixture, configure func(*database.PoolConfig)) *GroupBulkService {
	t.Helper()
	pool, err := database.Connect(f.ctx, database.Config{DSN: os.Getenv("SCIM_POSTGRES_TEST_DSN"), MaxConns: 3, Configure: func(c *database.PoolConfig) error {
		c.ConnConfig.Database = f.pool.Raw().Config().ConnConfig.Database
		configure(c)
		return nil
	}})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		if err := pool.Close(ctx); err != nil {
			t.Error("owned fault pool cleanup", err)
		}
	})
	service, err := NewGroupBulkService(groupsOnPool(t, f, pool), scim.DefaultBulkPolicy(), scim.DefaultBulkResponsePolicy())
	if err != nil {
		t.Fatal(err)
	}
	return service
}

func requireNativeBulkCounts(t *testing.T, f *nativeFixture, want [5]int) {
	t.Helper()
	var counts [5]int
	var projections int
	err := f.pool.Raw().QueryRow(f.ctx, `SELECT (SELECT count(*) FROM scim.bulk_requests), (SELECT count(*) FROM scim.bulk_children),
 (SELECT count(*) FROM identity.commands WHERE purpose=$1 AND state='committed'),
 (SELECT count(*) FROM audit.identity_command_bindings a JOIN identity.commands c USING(command_id) WHERE c.purpose=$1 AND c.state='committed'),
 (SELECT count(*) FROM public.identity_outbox_bindings o JOIN identity.commands c USING(command_id) WHERE c.purpose=$1 AND c.state='committed'),
 (SELECT count(*) FROM scim.groups)`, string(scim.Bulk)).Scan(&counts[0], &counts[1], &counts[2], &counts[3], &counts[4], &projections)
	if err != nil || counts != want || projections != 0 {
		t.Fatalf("graph, journal, audit, outbox or projection mismatch: %v, %d, %v", counts, projections, err)
	}
}

func TestNativeGroupBulkRejectsOversizeBeforeAnyCustody(t *testing.T) {
	policy := scim.DefaultBulkResponsePolicy()
	policy.MaxBytes = 16 * 1024
	f, service := bulkAdmissionFixture(t, policy)
	var ops []string
	for i := range 12 {
		ops = append(ops, fmt.Sprintf(`{"method":"POST","path":"/Groups","bulkId":"group-%d","data":{"displayName":"Small input"}}`, i))
	}
	body := `{"schemas":["urn:ietf:params:scim:api:messages:2.0:BulkRequest"],"Operations":[` + strings.Join(ops, ",") + `]}`
	result, err := service.Admit(f.ctx, BulkAdmissionRequest{Credential: f.bearer, Body: []byte(body)})
	if protocolStatus(err) != 413 || result != (BulkAdmission{}) {
		t.Fatal("expected a whole-request response-budget failure", err)
	}
	var mappings, parents, children, groups int
	err = f.pool.Raw().QueryRow(f.ctx, `SELECT
		(SELECT count(*) FROM identity.request_key_mappings WHERE route_id=$1),
		(SELECT count(*) FROM scim.bulk_requests), (SELECT count(*) FROM scim.bulk_children),
		(SELECT count(*) FROM scim.groups)`, string(scim.Bulk)).Scan(&mappings, &parents, &children, &groups)
	if err != nil || mappings != 0 || parents != 0 || children != 0 || groups != 0 {
		t.Fatal("response-budget rejection left custody or effects", mappings, parents, children, groups, err)
	}
}

func TestNativeGroupBulkDenseCycleSpansStatementBatches(t *testing.T) {
	f, service := bulkAdmissionFixture(t, scim.DefaultBulkResponsePolicy())
	const children, dependencies = 210, 110
	// Each dependency contributes a quoted 22-byte command ID and a comma to
	// the stored JSON. Edges alone put this graph beyond one statement batch.
	if children*dependencies*25 <= bulkChildBatchBytes {
		t.Fatal("fixture no longer reaches a batch boundary")
	}
	var body strings.Builder
	body.WriteString(`{"schemas":["urn:ietf:params:scim:api:messages:2.0:BulkRequest"],"Operations":[`)
	for i := range children {
		if i != 0 {
			body.WriteByte(',')
		}
		fmt.Fprintf(&body, `{"method":"POST","path":"/Groups","bulkId":"g%03d","data":{"schemas":["urn:ietf:params:scim:schemas:core:2.0:Group"],"displayName":"Group %03d","members":[`, i, i)
		for offset := range dependencies {
			if offset != 0 {
				body.WriteByte(',')
			}
			fmt.Fprintf(&body, `{"type":"Group","value":"bulkId:g%03d"}`, (i+offset+1)%children)
		}
		body.WriteString(`]}}`)
	}
	body.WriteString(`]}`)
	start := time.Now()
	admission, err := service.Admit(f.ctx, BulkAdmissionRequest{Credential: f.bearer, Body: []byte(body.String())})
	if err != nil || admission.ChildCount != children {
		t.Fatal("dense single SCC admission failed", body.Len(), err)
	}
	t.Logf("dense native admission: parsed request bytes=%d, children=%d, edges=%d, elapsed=%s", body.Len(), children, children*dependencies, time.Since(start))
	var kept int
	err = f.pool.Raw().QueryRow(f.ctx, `SELECT count(*) FROM scim.bulk_children WHERE parent_id=$1
AND component_id=0 AND component_order=0 AND cyclic AND status='admitted' AND cardinality(dependency_ids)=$2`, string(admission.CommandID), dependencies).Scan(&kept)
	if err != nil || kept != children {
		t.Fatal("dense cyclic plan was partially retained", kept, err)
	}
	requireNativeBulkCounts(t, f, [5]int{1, children, 1, 1, 1})
}
