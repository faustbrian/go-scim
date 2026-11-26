//go:build integration

package scimpostgres

import (
	"bytes"
	"encoding/json"
	"errors"
	"sync/atomic"
	"testing"

	"github.com/faustbrian/go-audit"
	database "github.com/faustbrian/go-postgres"
	scim "github.com/faustbrian/go-scim"
	"github.com/jackc/pgx/v5/pgconn"
)

const mixedCreateBulkFixture = `{"schemas":["urn:ietf:params:scim:api:messages:2.0:BulkRequest"],"Operations":[` +
	`{"method":"POST","path":"/Groups","bulkId":"new-group","data":{"schemas":["urn:ietf:params:scim:schemas:core:2.0:Group"],"displayName":"Forward user member","members":[{"type":"User","value":"bulkId:new-user"}]}},` +
	`{"method":"POST","path":"/Users","bulkId":"new-user","data":{"schemas":["urn:ietf:params:scim:schemas:core:2.0:User"],"userName":"MixedBulkUser","displayName":"Original mixed User","active":true}}]}`

func TestNativeBulkMixedCreateForwardUserReferenceCommitsAndReplays(t *testing.T) {
	f, groupOnly := bulkChildExecutionFixture(t)
	request := BulkAdmissionRequest{Credential: f.bearer, Body: []byte(mixedCreateBulkFixture)}
	if rejected, err := groupOnly.Admit(f.ctx, request); protocolStatus(err) != 501 || rejected != (BulkAdmission{}) {
		t.Fatal("the existing Group-only adapter must not opt into User execution", rejected, err)
	}
	requireMixedBulkCounts(t, f, [8]int{})
	groups, err := NewGroupsService(f.service, scim.DefaultGroupMembers)
	if err != nil {
		t.Fatal(err)
	}
	service, err := NewBulkService(groups, scim.DefaultBulkPolicy(), scim.DefaultBulkResponsePolicy())
	if err != nil {
		t.Fatal("explicitly select mixed native Bulk creation", err)
	}
	parent, err := service.Admit(f.ctx, request)
	if err != nil || parent.ChildCount != 2 {
		t.Fatal("admit the forward User reference without running either child", parent, err)
	}
	group := originalBulkChild(t, f, parent, 0)
	user := originalBulkChild(t, f, parent, 1)
	if group.command == user.command || group.resource == user.resource {
		t.Fatal("mixed children must retain distinct original command and resource allocations")
	}
	if replay, err := service.Admit(f.ctx, request); err != nil || replay != parent {
		t.Fatal("exact admission replay must retain the original mixed graph", replay, err)
	}
	requireMixedBulkCounts(t, f, [8]int{0, 0, 0, 1, 1, 1, 1, 2})

	if premature, err := service.ExecuteChild(f.ctx, request, 0); protocolStatus(err) != 409 || premature != (scim.BulkChildResult{}) {
		t.Fatal("selecting the Group cannot create its uncommitted User member", premature, err)
	}
	var blocked, admitted string
	var failures int
	if err := f.pool.Raw().QueryRow(f.ctx, `SELECT
 (SELECT status FROM scim.bulk_children WHERE parent_id=$1 AND ordinal=0),
 (SELECT status FROM scim.bulk_children WHERE parent_id=$1 AND ordinal=1),failed_count
 FROM scim.bulk_requests WHERE parent_id=$1`, string(parent.CommandID)).Scan(&blocked, &admitted, &failures); err != nil || blocked != "dependency-blocked" || admitted != "admitted" || failures != 0 {
		t.Fatal("unresolved typed dependency must remain nonterminal without counting a failure", blocked, admitted, failures, err)
	}
	if wire, err := service.ReadResult(f.ctx, request); !errors.Is(err, scim.ErrBulkIncomplete) || len(wire) != 0 {
		t.Fatal("an unresolved mixed graph must withhold the terminal response", err)
	}
	requireMixedBulkCounts(t, f, [8]int{0, 0, 0, 1, 1, 1, 1, 2})

	createdUser, err := service.ExecuteChild(f.ctx, request, 1)
	if err != nil {
		t.Fatal("execute the declared-later User before its dependent Group", err)
	}
	requireCommittedMixedBulkUser(t, f, parent, user, createdUser)
	requireMixedBulkCounts(t, f, [8]int{1, 1, 0, 2, 2, 2, 1, 2})
	if wire, err := service.ReadResult(f.ctx, request); !errors.Is(err, scim.ErrBulkIncomplete) || len(wire) != 0 {
		t.Fatal("one committed User must not expose a partial mixed response", err)
	}
	createdGroup, err := service.ExecuteChild(f.ctx, request, 0)
	if err != nil {
		t.Fatal("resume the Group against its originally committed User member", err)
	}
	projection := requireCommittedBulkChild(t, f, parent, 0, group, createdGroup)
	members, ok := projection.Attributes["members"].([]any)
	if !ok || len(members) != 1 {
		t.Fatal("committed Group must retain exactly its original typed User member")
	}
	member, ok := members[0].(map[string]any)
	if !ok || member["type"] != "User" || member["value"] != user.resource || projection.Attributes["displayName"] != "Forward user member" {
		t.Fatal("Group member must resolve to the original committed User, not another allocation")
	}
	wire, err := service.ReadResult(f.ctx, request)
	if err != nil {
		t.Fatal("read the complete mixed result", err)
	}
	var response struct {
		Operations []struct{ Method, BulkID, Status, Location, Version string }
	}
	if json.Unmarshal(wire, &response) != nil || len(response.Operations) != 2 {
		t.Fatal("terminal mixed result must contain both declared operations")
	}
	for ordinal, want := range []struct {
		bulkID, location string
		result           scim.BulkChildResult
	}{
		{"new-group", f.config.BaseURL + "/Groups/" + group.resource, createdGroup},
		{"new-user", f.config.BaseURL + "/Users/" + user.resource, createdUser},
	} {
		got := response.Operations[ordinal]
		if got.Method != "POST" || got.BulkID != want.bulkID || got.Status != "201" || got.Location != want.location || got.Version != string(want.result.Version) {
			t.Fatal("wire result must preserve declaration order, resource type and original version", ordinal)
		}
	}
	for range 2 {
		for ordinal, want := range []scim.BulkChildResult{createdGroup, createdUser} {
			if replay, err := service.ExecuteChild(f.ctx, request, ordinal); err != nil || replay != want {
				t.Fatal("exact retry changed an original mixed child result", ordinal, replay, err)
			}
		}
		if replay, err := service.ReadResult(f.ctx, request); err != nil || !bytes.Equal(replay, wire) {
			t.Fatal("exact mixed replay must retain the original terminal bytes", err)
		}
	}
	requireCommittedMixedBulkUser(t, f, parent, user, createdUser)
	requireCommittedBulkChild(t, f, parent, 0, group, createdGroup)
	requireMixedBulkCounts(t, f, [8]int{1, 1, 1, 3, 3, 3, 1, 2})
}

func TestNativeBulkMixedCreateRetainsUsernameConflictAndFailedDependency(t *testing.T) {
	f, _ := bulkChildExecutionFixture(t)
	existing := createNativeNamed(t, f, "MixedBulkUser", "Detached ordinary User")
	var original []byte
	if err := f.pool.Raw().QueryRow(f.ctx, `SELECT resource FROM scim.users WHERE resource_id=$1`, existing).Scan(&original); err != nil {
		t.Fatal(err)
	}
	groups, err := NewGroupsService(f.service, scim.DefaultGroupMembers)
	if err != nil {
		t.Fatal(err)
	}
	service, err := NewBulkService(groups, scim.DefaultBulkPolicy(), scim.DefaultBulkResponsePolicy())
	if err != nil {
		t.Fatal(err)
	}
	request := BulkAdmissionRequest{Credential: f.bearer, Body: []byte(mixedCreateBulkFixture)}
	parent, err := service.Admit(f.ctx, request)
	if err != nil || parent.ChildCount != 2 {
		t.Fatal("admit the original mixed request independently of the ordinary username owner", err)
	}
	user := originalBulkChild(t, f, parent, 1)
	if user.resource == existing {
		t.Fatal("Bulk admission must not link its new User to an ordinary username owner")
	}
	if result, err := service.ExecuteChild(f.ctx, request, 0); protocolStatus(err) != 409 || result != (scim.BulkChildResult{}) {
		t.Fatal("the Group must first wait for its exact uncommitted dependency", result, err)
	}
	wantUser := scim.BulkChildResult{Status: scim.BulkChildFailed, Code: 409, SCIMType: "uniqueness"}
	for range 2 {
		if result, err := service.ExecuteChild(f.ctx, request, 1); err != nil || result != wantUser {
			t.Fatal("the original User must retain its typed username conflict", result, err)
		}
	}
	if wire, err := service.ReadResult(f.ctx, request); !errors.Is(err, scim.ErrBulkIncomplete) || len(wire) != 0 {
		t.Fatal("a settled User denial cannot expose the still-blocked Group as partial wire", err)
	}
	requireMixedBulkCounts(t, f, [8]int{1, 1, 0, 2, 3, 2, 1, 2})
	wantGroup := scim.BulkChildResult{Status: scim.BulkChildFailed, Code: 424}
	for range 2 {
		if result, err := service.ExecuteChild(f.ctx, request, 0); err != nil || result != wantGroup {
			t.Fatal("the blocked Group must retain its own confirmed failed dependency", result, err)
		}
	}
	wire, err := service.ReadResult(f.ctx, request)
	if err != nil {
		t.Fatal("read both retained mixed denials", err)
	}
	var response struct {
		Operations []struct {
			BulkID, Status, Location, Version string
			Response                          struct{ SCIMType string }
		}
	}
	if json.Unmarshal(wire, &response) != nil || len(response.Operations) != 2 ||
		response.Operations[0].BulkID != "new-group" || response.Operations[0].Status != "424" ||
		response.Operations[1].BulkID != "new-user" || response.Operations[1].Status != "409" || response.Operations[1].Response.SCIMType != "uniqueness" {
		t.Fatal("terminal wire must preserve the original ordered dependency and uniqueness denials")
	}
	for _, operation := range response.Operations {
		if operation.Location != "" || operation.Version != "" {
			t.Fatal("failed creates must not disclose allocated IDs or successful versions")
		}
	}
	if replay, err := service.ReadResult(f.ctx, request); err != nil || !bytes.Equal(replay, wire) {
		t.Fatal("exact mixed denial replay changed terminal bytes", err)
	}
	var retained []byte
	var failed, denied int
	err = f.pool.Raw().QueryRow(f.ctx, `SELECT
 (SELECT resource FROM scim.users WHERE resource_id=$2),failed_count,
 (SELECT count(*) FROM scim.bulk_children b JOIN identity.commands c
  ON c.command_id=decode(translate(b.command_id,'-_','+/')||'==','base64')
  JOIN audit.identity_command_bindings a ON a.command_id=c.command_id JOIN audit.records r ON r.record_id=a.event_id
  WHERE b.parent_id=$1 AND b.status='failed' AND c.state='aborted'
  AND r.action='identity.scim.bulk_apply_child' AND r.subject_type='scim_bulk_child'
  AND r.subject_id=b.command_id AND r.correlation_id=b.parent_id AND r.outcome=$3)
 FROM scim.bulk_requests WHERE parent_id=$1 AND NOT cutoff_active`, string(parent.CommandID), existing, int16(audit.OutcomeDenied)).Scan(&retained, &failed, &denied)
	if err != nil || !bytes.Equal(retained, original) || failed != 2 || denied != 2 {
		t.Fatal("retain both original protected denials without changing the ordinary username owner", failed, denied, err)
	}
	requireMixedBulkCounts(t, f, [8]int{1, 1, 0, 2, 4, 2, 1, 2})
}

func TestNativeBulkMixedUserCheckpointFaultRollsBackAndSettlesOriginal(t *testing.T) {
	f, _ := bulkChildExecutionFixture(t)
	groups, err := NewGroupsService(f.service, scim.DefaultGroupMembers)
	if err != nil {
		t.Fatal(err)
	}
	service, err := NewBulkService(groups, scim.DefaultBulkPolicy(), scim.DefaultBulkResponsePolicy())
	if err != nil {
		t.Fatal(err)
	}
	request := BulkAdmissionRequest{Credential: f.bearer, Body: []byte(mixedCreateBulkFixture)}
	parent, err := service.Admit(f.ctx, request)
	if err != nil {
		t.Fatal(err)
	}
	user := originalBulkChild(t, f, parent, 1)
	reached := new(atomic.Bool)
	faultPool := bulkOnFixturePool(t, f, func(c *database.PoolConfig) {
		c.ConnConfig.RuntimeParams["client_min_messages"] = "notice"
		c.ConnConfig.OnNotice = func(_ *pgconn.PgConn, n *pgconn.Notice) {
			if n.Code == "PZ009" {
				reached.Store(true)
			}
		}
	})
	faultGroups, err := NewGroupsService(faultPool.native, scim.DefaultGroupMembers)
	if err != nil {
		t.Fatal(err)
	}
	faulted, err := NewBulkService(faultGroups, scim.DefaultBulkPolicy(), scim.DefaultBulkResponsePolicy())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.pool.Raw().Exec(f.ctx, `CREATE FUNCTION scim.fixture_user_checkpoint_failure() RETURNS trigger LANGUAGE plpgsql AS $f$
BEGIN
 IF EXISTS (SELECT 1 FROM scim.users s JOIN identity.users i USING(tenant_id,user_id)
  WHERE s.command_id=NEW.command_id AND s.resource_id=NEW.resource_id AND i.user_id=NEW.resource_id) THEN
  RAISE NOTICE USING ERRCODE='PZ009',MESSAGE='owned provisional User reached checkpoint';
 END IF;
 RAISE EXCEPTION 'owned User checkpoint failure';
END $f$;
CREATE TRIGGER fixture_user_checkpoint_failure BEFORE UPDATE ON scim.bulk_children
FOR EACH ROW WHEN (NEW.status='succeeded' AND NEW.ordinal=1) EXECUTE FUNCTION scim.fixture_user_checkpoint_failure()`); err != nil {
		t.Fatal(err)
	}
	first, firstErr := faulted.ExecuteChild(f.ctx, request, 1)
	if !reached.Load() {
		t.Fatal("checkpoint fault must follow the real provisional kernel User and projection", first, firstErr)
	}
	var protectedFailures, attributes, reservations, committed int
	err = f.pool.Raw().QueryRow(f.ctx, `SELECT
 (SELECT count(*) FROM scim.bulk_children WHERE parent_id=$1 AND ordinal=1
  AND status='failed' AND result_code=503 AND result_resource_id IS NULL AND result_version IS NULL),
 (SELECT count(*) FROM identity.user_attributes),
 (SELECT count(*) FROM identity.commands WHERE command_id=decode(translate($2,'-_','+/')||'==','base64') AND purpose=$3 AND state='aborted' AND terminal_class='dependency-failure'),
 (SELECT count(*) FROM identity.commands WHERE command_id=decode(translate($2,'-_','+/')||'==','base64') AND state='committed')`, string(parent.CommandID), user.command, string(scim.UserCreate)).Scan(&protectedFailures, &attributes, &reservations, &committed)
	if err != nil || protectedFailures != 1 || attributes != 0 || reservations != 1 || committed != 0 {
		t.Fatal("a confirmed rollback must settle the original User checkpoint as 503, not leave it admitted or leak provisional effects", protectedFailures, attributes, reservations, committed, err)
	}
	want := scim.BulkChildResult{Status: scim.BulkChildFailed, Code: 503}
	if firstErr != nil || first != want {
		t.Fatal("return only the exact acknowledged terminal User failure", first, firstErr)
	}
	if _, err := f.pool.Raw().Exec(f.ctx, `DROP TRIGGER fixture_user_checkpoint_failure ON scim.bulk_children`); err != nil {
		t.Fatal("remove only the owned checkpoint fault before exact retry", err)
	}
	if replay, err := service.ExecuteChild(f.ctx, request, 1); err != nil || replay != want {
		t.Fatal("retry must replay the aborted child without executing it", replay, err)
	}
	requireMixedBulkCounts(t, f, [8]int{0, 0, 0, 1, 2, 1, 1, 2})
	if dependent, err := service.ExecuteChild(f.ctx, request, 0); err != nil || dependent != (scim.BulkChildResult{Status: scim.BulkChildFailed, Code: 424}) {
		t.Fatal("confirmed User noncommit must settle the dependency without writing a Group", dependent, err)
	}
	if wire, err := service.ReadResult(f.ctx, request); err != nil || len(wire) == 0 {
		t.Fatal("read the exact completed mixed request after both original failures settle", err)
	}
}

func requireCommittedMixedBulkUser(t *testing.T, f *nativeFixture, parent BulkAdmission, original admittedBulkChild, result scim.BulkChildResult) {
	t.Helper()
	if result != (scim.BulkChildResult{Status: scim.BulkChildSucceeded, Code: 201, ResourceID: original.resource, Version: bulkChildVersion(original.command)}) {
		t.Fatal("User creation must return its original allocated identity and successful checkpoint", result)
	}
	var command, status, resource, version string
	var code, authoritative, journal, audits, events int
	var wire []byte
	err := f.pool.Raw().QueryRow(f.ctx, `SELECT u.command_id,u.resource,b.status,b.result_code,b.result_resource_id,b.result_version,
 (SELECT count(*) FROM identity.users i WHERE i.tenant_id=u.tenant_id AND i.user_id=u.user_id AND i.user_id=u.resource_id),
 (SELECT count(*) FROM identity.commands c WHERE c.command_id=decode(translate(b.command_id,'-_','+/')||'==','base64') AND c.purpose=$3 AND c.state='committed'),
 (SELECT count(*) FROM audit.identity_command_bindings a JOIN audit.records r ON r.record_id=a.event_id
  WHERE a.command_id=decode(translate(b.command_id,'-_','+/')||'==','base64')
  AND r.action='identity.scim.bulk_apply_child' AND r.subject_type='scim_bulk_child'
  AND r.subject_id=b.command_id AND r.correlation_id=b.parent_id),
 (SELECT count(*) FROM public.identity_outbox_bindings o WHERE o.command_id=decode(translate(b.command_id,'-_','+/')||'==','base64'))
 FROM scim.bulk_children b JOIN scim.users u ON u.resource_id=b.resource_id AND u.command_id=b.command_id
 WHERE b.parent_id=$1 AND b.ordinal=$2`, string(parent.CommandID), 1, string(scim.UserCreate)).Scan(&command, &wire, &status, &code, &resource, &version, &authoritative, &journal, &audits, &events)
	if err != nil || command != original.command || status != "succeeded" || code != 201 || resource != original.resource || scim.Version(version) != result.Version || authoritative != 1 || journal != 1 || audits != 1 || events != 1 {
		t.Fatal("original authoritative User, projection, checkpoint, protected audit and lifecycle event must commit together", err)
	}
	var projection scim.Resource
	if json.Unmarshal(wire, &projection) != nil || projection.ID != original.resource || projection.Version != result.Version || projection.Attributes["userName"] != "MixedBulkUser" || projection.Attributes["displayName"] != "Original mixed User" || projection.Attributes["active"] != true {
		t.Fatal("User projection differs from the original normal User fixture")
	}
	f.assertAtomicCreation(t, original.resource, 1)
}

func requireMixedBulkCounts(t *testing.T, f *nativeFixture, want [8]int) {
	t.Helper()
	var got [8]int
	err := f.pool.Raw().QueryRow(f.ctx, `SELECT
 (SELECT count(*) FROM identity.users),(SELECT count(*) FROM scim.users),(SELECT count(*) FROM scim.groups),
 (SELECT count(*) FROM identity.commands WHERE purpose IN ($1,$2,$3) AND state='committed'),
 (SELECT count(*) FROM audit.identity_command_bindings a JOIN identity.commands c USING(command_id) WHERE c.purpose IN ($1,$2,$3)),
 (SELECT count(*) FROM public.identity_outbox_bindings o JOIN identity.commands c USING(command_id) WHERE c.purpose IN ($1,$2,$3)),
 (SELECT count(*) FROM scim.bulk_requests),(SELECT count(*) FROM scim.bulk_children)`, string(scim.Bulk), string(scim.UserCreate), string(scim.GroupCreate)).Scan(&got[0], &got[1], &got[2], &got[3], &got[4], &got[5], &got[6], &got[7])
	if err != nil || got != want {
		t.Fatal("mixed admission, execution or replay created unexpected durable effects", got, want, err)
	}
}
