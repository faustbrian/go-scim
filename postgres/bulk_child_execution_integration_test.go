//go:build integration

package scimpostgres

import (
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
	if err := f.pool.Raw().QueryRow(f.ctx, `SELECT (SELECT count(*) FROM scim.groups),(SELECT count(*) FROM scim.bulk_children WHERE status<>'admitted')`).Scan(&projections, &advanced); err != nil || projections != 0 || advanced != 0 {
		t.Fatal("premature child execution changed projection or checkpoint", err)
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
	if err := f.pool.Raw().QueryRow(f.ctx, `SELECT (SELECT count(*) FROM scim.groups),status FROM scim.bulk_children WHERE parent_id=$1 AND ordinal=1`, string(parent.CommandID)).Scan(&projections, &secondStatus); err != nil || projections != 1 || secondStatus != "admitted" {
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
	if result, err := faulted.ExecuteChild(f.ctx, request, 0); protocolStatus(err) != 503 || result != (scim.BulkChildResult{}) || !reached.Load() {
		t.Fatal("checkpoint fault did not follow the actual provisional projection", reached.Load(), err)
	}
	var projections, progressed, committed int
	err = f.pool.Raw().QueryRow(f.ctx, `SELECT (SELECT count(*) FROM scim.groups),
 (SELECT count(*) FROM scim.bulk_children WHERE parent_id=$1 AND (status<>'admitted' OR result_code IS NOT NULL)),
 (SELECT count(*) FROM identity.commands WHERE purpose=$2 AND state='committed')`, string(parent.CommandID), string(scim.GroupCreate)).Scan(&projections, &progressed, &committed)
	if err != nil || projections != 0 || progressed != 0 || committed != 0 {
		t.Fatal("checkpoint failure leaked provisional Group, child state or committed receipt", projections, progressed, committed, err)
	}
}
