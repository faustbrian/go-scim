//go:build integration

package scimpostgres

import (
	"bytes"
	"encoding/json"
	"sync/atomic"
	"testing"

	database "github.com/faustbrian/go-postgres"
	scim "github.com/faustbrian/go-scim"
	"github.com/jackc/pgx/v5/pgconn"
)

const dependentGroupBulkFixture = `{"schemas":["urn:ietf:params:scim:api:messages:2.0:BulkRequest"],"Operations":[` +
	`{"method":"POST","path":"/Groups","bulkId":"first","data":{"schemas":["urn:ietf:params:scim:schemas:core:2.0:Group"],"displayName":"First"}},` +
	`{"method":"POST","path":"/Groups","bulkId":"second","data":{"schemas":["urn:ietf:params:scim:schemas:core:2.0:Group"],"displayName":"Second","members":[{"type":"Group","value":"bulkId:first"}]}}]}`

func bulkChildExecutionFixture(t *testing.T) (*nativeFixture, *GroupBulkService) {
	t.Helper()
	return bulkChildExecutionFixtureWithResponse(t, scim.DefaultBulkResponsePolicy())
}

func bulkChildExecutionFixtureWithResponse(t *testing.T, response scim.BulkResponsePolicy) (*nativeFixture, *GroupBulkService) {
	t.Helper()
	f, service := bulkAdmissionFixture(t, response)
	history, err := (BulkChildExecutionMigrationSource{
		Base: BulkAdmissionMigrationSource{
			Base: GroupsMigrationSource{
				Base:    UsersMigrationSource{Base: MigrationSource{Version: 40}, Version: 41},
				Version: 42,
			},
			Version: 43,
		},
		Version: 44,
	}).Load(f.ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.pool.Raw().Exec(f.ctx, history[len(history)-1].UpSQL()); err != nil {
		t.Fatal("additive Bulk child execution migration", err)
	}
	return f, service
}

type admittedBulkChild struct {
	command  string
	resource string
}

func originalBulkChild(t *testing.T, f *nativeFixture, parent BulkAdmission, ordinal int) admittedBulkChild {
	t.Helper()
	var child admittedBulkChild
	if err := f.pool.Raw().QueryRow(f.ctx, `SELECT command_id,resource_id FROM scim.bulk_children WHERE parent_id=$1 AND ordinal=$2`, string(parent.CommandID), ordinal).Scan(&child.command, &child.resource); err != nil {
		t.Fatal("original admitted child allocation", err)
	}
	if child.command == "" || child.resource == "" || child.command == string(parent.CommandID) {
		t.Fatal("child lacks independent original command and resource allocation")
	}
	return child
}

func requireCommittedBulkChild(t *testing.T, f *nativeFixture, parent BulkAdmission, ordinal int, original admittedBulkChild, result scim.BulkChildResult) scim.Resource {
	t.Helper()
	if result.Status != scim.BulkChildSucceeded || result.Code != 201 || result.ResourceID != original.resource || !nativeVersion(result.Version) || result.SkipReason != scim.BulkSkipNone || result.SCIMType != "" {
		t.Fatal("child did not return the original typed successful creation result")
	}
	var command, status, version, resourceID string
	var code, committed, audits, events int
	var wire []byte
	err := f.pool.Raw().QueryRow(f.ctx, `SELECT g.command_id,g.resource,b.status,b.result_code,b.result_resource_id,b.result_version,
 (SELECT count(*) FROM identity.commands c WHERE c.command_id=decode(translate(b.command_id,'-_','+/')||'==','base64') AND c.state='committed'),
 (SELECT count(*) FROM audit.identity_command_bindings a JOIN audit.records r ON r.record_id=a.event_id
  WHERE a.command_id=decode(translate(b.command_id,'-_','+/')||'==','base64')
  AND r.action='identity.scim.bulk_apply_child' AND r.subject_type='scim_bulk_child'
  AND r.subject_id=b.command_id AND r.correlation_id=b.parent_id),
 (SELECT count(*) FROM public.identity_outbox_bindings o WHERE o.command_id=decode(translate(b.command_id,'-_','+/')||'==','base64'))
 FROM scim.bulk_children b JOIN scim.groups g ON g.resource_id=b.resource_id AND g.command_id=b.command_id
 WHERE b.parent_id=$1 AND b.ordinal=$2`, string(parent.CommandID), ordinal).Scan(&command, &wire, &status, &code, &resourceID, &version, &committed, &audits, &events)
	if err != nil || command != original.command || status != "succeeded" || code != 201 || resourceID != original.resource || scim.Version(version) != result.Version || committed != 1 || audits != 1 || events != 1 {
		t.Fatal("original projection, terminal checkpoint, journal, audit and outbox did not commit together", err)
	}
	var projection scim.Resource
	if err := json.Unmarshal(wire, &projection); err != nil || projection.ID != original.resource || projection.Version != result.Version {
		t.Fatal("stored Group does not match the retained child result", err)
	}
	return projection
}

func TestNativeGroupBulkChildExecutionCommitsInPlanOrderAndReplaysOriginal(t *testing.T) {
	f, service := bulkChildExecutionFixture(t)
	request := BulkAdmissionRequest{Credential: f.bearer, Body: []byte(dependentGroupBulkFixture)}
	parent, err := service.Admit(f.ctx, request)
	if err != nil || parent.ChildCount != 2 {
		t.Fatal("admit ordered dependent children", err)
	}
	first := originalBulkChild(t, f, parent, 0)
	second := originalBulkChild(t, f, parent, 1)
	if first.command == second.command || first.resource == second.resource {
		t.Fatal("admitted children share command or resource allocation")
	}

	if result, err := service.ExecuteChild(f.ctx, request, 1); protocolStatus(err) != 409 || result != (scim.BulkChildResult{}) {
		t.Fatal("caller executed a dependent child before its persisted predecessor", err)
	}
	var projections, advanced int
	if err := f.pool.Raw().QueryRow(f.ctx, `SELECT (SELECT count(*) FROM scim.groups),
 (SELECT count(*) FROM scim.bulk_children WHERE NOT (ordinal=1 AND status='dependency-blocked' OR ordinal=0 AND status='admitted'))`).Scan(&projections, &advanced); err != nil || projections != 0 || advanced != 0 {
		t.Fatal("premature selection must retain only the exact dependency block", err)
	}

	created, err := service.ExecuteChild(f.ctx, request, 0)
	if err != nil {
		t.Fatal("execute first independently committable child", err)
	}
	projection := requireCommittedBulkChild(t, f, parent, 0, first, created)
	if projection.Attributes["displayName"] != "First" {
		t.Fatal("first child projected a different admitted request")
	}
	var secondStatus string
	if err := f.pool.Raw().QueryRow(f.ctx, `SELECT (SELECT count(*) FROM scim.groups),status FROM scim.bulk_children WHERE parent_id=$1 AND ordinal=1`, string(parent.CommandID)).Scan(&projections, &secondStatus); err != nil || projections != 1 || secondStatus != "dependency-blocked" {
		t.Fatal("first child execution also executed its successor", err)
	}
	if replayed, err := service.ExecuteChild(f.ctx, request, 0); err != nil || replayed != created {
		t.Fatal("exact retry changed first child result", err)
	}
	f.deny.Store(true)
	if denied, err := service.ExecuteChild(f.ctx, request, 0); protocolStatus(err) != 403 || denied != (scim.BulkChildResult{}) {
		t.Fatal("committed child replay disclosed its result after current authority denied", err)
	}
	f.deny.Store(false)

	nested, err := service.ExecuteChild(f.ctx, request, 1)
	if err != nil {
		t.Fatal("execute dependent child after predecessor success", err)
	}
	projection = requireCommittedBulkChild(t, f, parent, 1, second, nested)
	members, ok := projection.Attributes["members"].([]any)
	if !ok || len(members) != 1 {
		t.Fatal("dependent Group lost its admitted member")
	}
	member, ok := members[0].(map[string]any)
	if !ok || member["type"] != "Group" || member["value"] != first.resource || projection.Attributes["displayName"] != "Second" {
		t.Fatal("dependent Group did not normalize bulkId to the original committed Group")
	}
	if replayed, err := service.ExecuteChild(f.ctx, request, 1); err != nil || replayed != nested {
		t.Fatal("exact retry changed dependent child result", err)
	}
	if replayed, err := service.ExecuteChild(f.ctx, request, 0); err != nil || replayed != created {
		t.Fatal("later child execution changed original first child replay", err)
	}
	requireCommittedBulkChild(t, f, parent, 0, first, created)
	requireCommittedBulkChild(t, f, parent, 1, second, nested)
	if err := f.pool.Raw().QueryRow(f.ctx, `SELECT count(*) FROM scim.groups`).Scan(&projections); err != nil || projections != 2 {
		t.Fatal("execution or replay created extra Group projections", err)
	}
	groups := groupsOnPool(t, f, f.pool)
	update := groupRequest(f, scim.GroupReplace, first.resource, created.Version, "after-bulk", `{"schemas":["urn:ietf:params:scim:schemas:core:2.0:Group"],"displayName":"Changed after Bulk"}`)
	if changed, err := groups.Execute(f.ctx, update); err != nil || changed.ETag == created.Version {
		t.Fatal("ordinary Group projection did not advance", err)
	}
	if replayed, err := service.ExecuteChild(f.ctx, request, 0); err != nil || replayed != created {
		t.Fatal("later projection version replaced the original Bulk result", err)
	}
}

func TestNativeGroupBulkChildRecoversOriginalAfterLostCommitAcknowledgement(t *testing.T) {
	f, service := bulkChildExecutionFixture(t)
	request := BulkAdmissionRequest{Credential: f.bearer, Body: []byte(dependentGroupBulkFixture)}
	parent, err := service.Admit(f.ctx, request)
	if err != nil {
		t.Fatal("admit before selecting the child commit fault", err)
	}
	first := originalBulkChild(t, f, parent, 0)
	fault := new(nativeCommitFault)
	uncertain := bulkOnFixturePool(t, f, func(c *database.PoolConfig) { c.ConnConfig.DialFunc = fault.dial })
	if result, err := uncertain.ExecuteChild(f.ctx, request, 0); protocolStatus(err) != 503 || result != (scim.BulkChildResult{}) || !fault.hit.Load() {
		t.Fatal("did not lose the actual child projection COMMIT acknowledgement", fault.hit.Load(), err)
	}
	var retainedVersion string
	if err := f.pool.Raw().QueryRow(f.ctx, `SELECT result_version FROM scim.bulk_children WHERE parent_id=$1 AND ordinal=0 AND status='succeeded'`, string(parent.CommandID)).Scan(&retainedVersion); err != nil || !nativeVersion(scim.Version(retainedVersion)) {
		t.Fatal("lost acknowledgement did not retain a committed typed child checkpoint", err)
	}
	recovered, err := service.ExecuteChild(f.ctx, request, 0)
	if err != nil || recovered.Version != scim.Version(retainedVersion) {
		t.Fatal("exact retry did not recover the original committed child version", err)
	}
	requireCommittedBulkChild(t, f, parent, 0, first, recovered)
	if replayed, err := service.ExecuteChild(f.ctx, request, 0); err != nil || replayed != recovered {
		t.Fatal("recovered child did not remain exactly replayable", err)
	}
	var projections int
	var secondStatus string
	if err := f.pool.Raw().QueryRow(f.ctx, `SELECT (SELECT count(*) FROM scim.groups),status FROM scim.bulk_children WHERE parent_id=$1 AND ordinal=1`, string(parent.CommandID)).Scan(&projections, &secondStatus); err != nil || projections != 1 || secondStatus != "admitted" {
		t.Fatal("ambiguous child retry duplicated its projection or executed the next child", err)
	}
}

func TestNativeGroupBulkChildCheckpointFaultRollsBackProjection(t *testing.T) {
	f, service := bulkChildExecutionFixture(t)
	request := BulkAdmissionRequest{Credential: f.bearer, Body: []byte(dependentGroupBulkFixture)}
	parent, err := service.Admit(f.ctx, request)
	if err != nil {
		t.Fatal(err)
	}
	first := originalBulkChild(t, f, parent, 0)
	second := originalBulkChild(t, f, parent, 1)
	reached := new(atomic.Bool)
	faulted := bulkOnFixturePool(t, f, func(c *database.PoolConfig) {
		c.ConnConfig.RuntimeParams["client_min_messages"] = "notice"
		c.ConnConfig.OnNotice = func(_ *pgconn.PgConn, n *pgconn.Notice) {
			if n.Code == "PZ003" {
				reached.Store(true)
			}
		}
	})
	if _, err := f.pool.Raw().Exec(f.ctx, `CREATE FUNCTION scim.fixture_child_checkpoint_failure() RETURNS trigger LANGUAGE plpgsql AS $f$
BEGIN
 IF EXISTS (SELECT 1 FROM scim.groups WHERE command_id=NEW.command_id AND resource_id=NEW.resource_id) THEN
  RAISE NOTICE USING ERRCODE='PZ003',MESSAGE='owned provisional projection reached checkpoint';
 END IF;
 RAISE EXCEPTION 'owned checkpoint failure';
END $f$;
CREATE TRIGGER fixture_child_checkpoint_failure BEFORE UPDATE ON scim.bulk_children
FOR EACH ROW WHEN (NEW.status='succeeded') EXECUTE FUNCTION scim.fixture_child_checkpoint_failure()`); err != nil {
		t.Fatal(err)
	}
	wantFailed := scim.BulkChildResult{Status: scim.BulkChildFailed, Code: 503}
	if result, err := faulted.ExecuteChild(f.ctx, request, 0); err != nil || result != wantFailed || !reached.Load() {
		t.Fatal("confirmed rollback must return the retained failure after reaching the provisional Group", result, reached.Load(), err)
	}
	var retained, aborted, projections, committed, outbox, audits, failures int
	err = f.pool.Raw().QueryRow(f.ctx, `SELECT
 (SELECT count(*) FROM scim.bulk_children WHERE parent_id=$1 AND command_id=$2 AND resource_id=$3
  AND ordinal=0 AND status='failed' AND result_code=503 AND result_resource_id IS NULL AND result_version IS NULL),
 (SELECT count(*) FROM identity.commands WHERE command_id=decode(translate($2,'-_','+/')||'==','base64')
  AND purpose=$4 AND state='aborted' AND terminal_class='dependency-failure'),
 (SELECT count(*) FROM scim.groups),
 (SELECT count(*) FROM identity.commands WHERE purpose=$4 AND state='committed'),
 (SELECT count(*) FROM public.identity_outbox_bindings o JOIN scim.bulk_children b
  ON o.command_id=decode(translate(b.command_id,'-_','+/')||'==','base64') WHERE b.parent_id=$1),
 (SELECT count(*) FROM audit.records WHERE correlation_id=$1 AND action='identity.scim.bulk_apply_child'),
 failed_count FROM scim.bulk_requests WHERE parent_id=$1 AND NOT cutoff_active`, string(parent.CommandID), first.command, first.resource, string(scim.GroupCreate)).Scan(&retained, &aborted, &projections, &committed, &outbox, &audits, &failures)
	if err != nil || retained != 1 || aborted != 1 || projections != 0 || committed != 0 || outbox != 0 || audits != 1 || failures != 1 {
		t.Fatal("confirmed rollback must atomically retain the original aborted failure without provisional Group or success effects", retained, aborted, projections, committed, outbox, audits, failures, err)
	}
	if _, err := f.pool.Raw().Exec(f.ctx, `DROP TRIGGER fixture_child_checkpoint_failure ON scim.bulk_children`); err != nil {
		t.Fatal("remove only the owned checkpoint fault before exact replay", err)
	}
	if replayed, err := service.ExecuteChild(f.ctx, request, 0); err != nil || replayed != wantFailed {
		t.Fatal("exact retry must replay the original retained 503 without executing the Group", replayed, err)
	}
	var pending int
	err = f.pool.Raw().QueryRow(f.ctx, `SELECT
 (SELECT count(*) FROM scim.groups),
 (SELECT count(*) FROM audit.records WHERE correlation_id=$1 AND action='identity.scim.bulk_apply_child'),
 (SELECT count(*) FROM scim.bulk_children WHERE parent_id=$1 AND command_id=$2 AND resource_id=$3
  AND ordinal=1 AND status='admitted' AND result_code IS NULL),
 failed_count FROM scim.bulk_requests WHERE parent_id=$1`, string(parent.CommandID), second.command, second.resource).Scan(&projections, &audits, &pending, &failures)
	if err != nil || projections != 0 || audits != 1 || pending != 1 || failures != 1 {
		t.Fatal("replay must not create a Group, repeat the failure or execute its dependent", projections, audits, pending, failures, err)
	}
	wantDependent := scim.BulkChildResult{Status: scim.BulkChildFailed, Code: 424}
	if result, err := service.ExecuteChild(f.ctx, request, 1); err != nil || result != wantDependent {
		t.Fatal("the dependent Group must settle its own failed-dependency result", result, err)
	}
	wire, err := service.ReadResult(f.ctx, request)
	if err != nil {
		t.Fatal("read the terminal parent after both original failures settle", err)
	}
	var response struct {
		Operations []struct {
			BulkID, Status, Location, Version string
			Response                          struct{ Status string }
		}
	}
	if err := json.Unmarshal(wire, &response); err != nil || len(response.Operations) != 2 ||
		response.Operations[0].BulkID != "first" || response.Operations[0].Status != "503" || response.Operations[0].Response.Status != "503" ||
		response.Operations[1].BulkID != "second" || response.Operations[1].Status != "424" || response.Operations[1].Response.Status != "424" {
		t.Fatal("the terminal parent must retain both original failed results in request order", err)
	}
	for _, operation := range response.Operations {
		if operation.Location != "" || operation.Version != "" {
			t.Fatal("failed Group creates must not disclose provisional resource results")
		}
	}
	if replayed, err := service.ReadResult(f.ctx, request); err != nil || !bytes.Equal(replayed, wire) {
		t.Fatal("exact parent replay must preserve the original terminal response bytes", err)
	}
	err = f.pool.Raw().QueryRow(f.ctx, `SELECT
 (SELECT count(*) FROM scim.groups),
 (SELECT count(*) FROM public.identity_outbox_bindings o JOIN scim.bulk_children b
  ON o.command_id=decode(translate(b.command_id,'-_','+/')||'==','base64') WHERE b.parent_id=$1),
 (SELECT count(*) FROM audit.records WHERE correlation_id=$1 AND action='identity.scim.bulk_apply_child'),
 failed_count FROM scim.bulk_requests WHERE parent_id=$1`, string(parent.CommandID)).Scan(&projections, &outbox, &audits, &failures)
	if err != nil || projections != 0 || outbox != 0 || audits != 2 || failures != 2 {
		t.Fatal("settling and reading both failures must not leak a partial Group or success outbox", projections, outbox, audits, failures, err)
	}
	if originalBulkChild(t, f, parent, 0) != first || originalBulkChild(t, f, parent, 1) != second {
		t.Fatal("failure settlement or replay replaced the original admitted child allocations")
	}
}

func TestNativeGroupBulkChildUnavailableCheckpointFaultLeavesOriginalPending(t *testing.T) {
	f, service := bulkChildExecutionFixture(t)
	request := BulkAdmissionRequest{Credential: f.bearer, Body: []byte(dependentGroupBulkFixture)}
	parent, err := service.Admit(f.ctx, request)
	if err != nil {
		t.Fatal(err)
	}
	first := originalBulkChild(t, f, parent, 0)
	second := originalBulkChild(t, f, parent, 1)
	projectionReached, settlementReached := new(atomic.Bool), new(atomic.Bool)
	faulted := bulkOnFixturePool(t, f, func(c *database.PoolConfig) {
		c.ConnConfig.RuntimeParams["client_min_messages"] = "notice"
		c.ConnConfig.OnNotice = func(_ *pgconn.PgConn, n *pgconn.Notice) {
			switch n.Code {
			case "PZ011":
				projectionReached.Store(true)
			case "PZ012":
				settlementReached.Store(true)
			}
		}
	})
	if _, err := f.pool.Raw().Exec(f.ctx, `CREATE FUNCTION scim.fixture_child_unavailable_checkpoint_failure() RETURNS trigger LANGUAGE plpgsql AS $f$
BEGIN
 IF NEW.status='succeeded' THEN
  IF EXISTS (SELECT 1 FROM scim.groups WHERE command_id=NEW.command_id AND resource_id=NEW.resource_id) THEN
   RAISE NOTICE USING ERRCODE='PZ011',MESSAGE='owned provisional Group reached success checkpoint';
  END IF;
  RAISE EXCEPTION 'owned provisional Group checkpoint failure';
 END IF;
 RAISE NOTICE USING ERRCODE='PZ012',MESSAGE='owned retained 503 reached terminal checkpoint';
 RAISE EXCEPTION 'owned retained unavailable checkpoint failure';
END $f$;
CREATE TRIGGER fixture_child_unavailable_checkpoint_failure BEFORE UPDATE ON scim.bulk_children
FOR EACH ROW WHEN (NEW.status='succeeded' OR NEW.status='failed' AND NEW.result_code=503)
EXECUTE FUNCTION scim.fixture_child_unavailable_checkpoint_failure()`); err != nil {
		t.Fatal(err)
	}
	if result, err := faulted.ExecuteChild(f.ctx, request, 0); protocolStatus(err) != 503 || result != (scim.BulkChildResult{}) || !projectionReached.Load() || !settlementReached.Load() {
		t.Fatal("a faulted terminal settlement must return only raw unavailable after both real checkpoint attempts", result, projectionReached.Load(), settlementReached.Load(), err)
	}
	var pending, admitted, projections, audits, outbox, failures int
	var cutoff bool
	err = f.pool.Raw().QueryRow(f.ctx, `SELECT
 (SELECT count(*) FROM identity.commands WHERE command_id=decode(translate($2,'-_','+/')||'==','base64')
  AND purpose=$3 AND state='pending' AND terminal_class IS NULL AND result IS NULL),
 (SELECT count(*) FROM scim.bulk_children WHERE parent_id=$1 AND status='admitted'
  AND result_code IS NULL AND result_resource_id IS NULL AND result_version IS NULL),
 (SELECT count(*) FROM scim.groups),
 (SELECT count(*) FROM audit.records WHERE correlation_id=$1 AND action='identity.scim.bulk_apply_child'),
 (SELECT count(*) FROM public.identity_outbox_bindings o JOIN scim.bulk_children b
  ON o.command_id=decode(translate(b.command_id,'-_','+/')||'==','base64') WHERE b.parent_id=$1),
 failed_count,cutoff_active FROM scim.bulk_requests WHERE parent_id=$1`, string(parent.CommandID), first.command, string(scim.GroupCreate)).Scan(&pending, &admitted, &projections, &audits, &outbox, &failures, &cutoff)
	if err != nil || pending != 1 || admitted != 2 || projections != 0 || audits != 0 || outbox != 0 || failures != 0 || cutoff {
		t.Fatal("a failed terminal transaction must leave the original pending and graph admitted without counting or leaking child effects", pending, admitted, projections, audits, outbox, failures, cutoff, err)
	}
	if originalBulkChild(t, f, parent, 0) != first || originalBulkChild(t, f, parent, 1) != second {
		t.Fatal("a failed terminal transaction replaced the original admitted child allocations")
	}
}
