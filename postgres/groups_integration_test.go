//go:build integration

package scimpostgres

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	scim "github.com/faustbrian/go-scim"
)

func nativeGroupsFixture(t *testing.T) (*nativeFixture, *GroupsService) {
	t.Helper()
	f := newNativeFixture(t)
	history, err := (GroupsMigrationSource{Base: UsersMigrationSource{Base: MigrationSource{Version: 40}, Version: 41}, Version: 42}).Load(f.ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.pool.Raw().Exec(f.ctx, history[len(history)-1].UpSQL()); err != nil {
		t.Fatal("additive Groups migration", err)
	}
	s, err := NewGroupsService(f.service, scim.DefaultGroupMembers)
	if err != nil {
		t.Fatal("explicit native Groups selection", err)
	}
	return f, s
}

func TestNativeGroupsExactTypedMembersAndConnectionIsolation(t *testing.T) {
	f, groups := nativeGroupsFixture(t)
	user := createNativeNamed(t, f, "SameConnectionUser", "User")
	child, err := groups.Execute(f.ctx, groupRequest(f, scim.GroupCreate, "", "", "existing-group", `{"schemas":["urn:ietf:params:scim:schemas:core:2.0:Group"],"displayName":"Nested"}`))
	if err != nil {
		t.Fatal(err)
	}
	childID := groupID(t, child)
	otherConfig := f.config
	otherConfig.Scope.ConnectionID = "connection-b"
	otherService, err := NewService(f.pool, otherConfig, f.keys)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := otherService.InitializeConfiguredConnection(f.ctx); err != nil {
		t.Fatal(err)
	}
	other, err := NewGroupsService(otherService, scim.DefaultGroupMembers)
	if err != nil {
		t.Fatal(err)
	}
	for index, test := range []struct {
		service  *GroupsService
		id, kind string
	}{{groups, user, "Group"}, {groups, childID, "User"}, {groups, "missing-opaque-id", "User"}, {other, user, "User"}, {other, childID, "Group"}} {
		key := "invalid-member-" + strings.Repeat("x", index+1)
		request := groupRequest(f, scim.GroupCreate, "", "", key, `{"schemas":["urn:ietf:params:scim:schemas:core:2.0:Group"],"displayName":"Denied","members":[{"value":"`+test.id+`","type":"`+test.kind+`"}]}`)
		for range 2 {
			response, err := test.service.Execute(f.ctx, request)
			if protocolStatus(err) != 400 || len(response.Body) != 0 {
				t.Fatal("missing/wrong-type/cross-connection member did not retain redacted no-commit denial", index, err)
			}
		}
	}
	for _, request := range []scim.Request{groupRequest(f, scim.GroupGet, childID, "", "", ""), {Operation: scim.GroupList, Credential: f.bearer, Query: scim.Query{Filter: `id eq "` + childID + `"`}}} {
		response, err := other.Execute(f.ctx, request)
		if request.Operation == scim.GroupGet {
			if protocolStatus(err) != 404 {
				t.Fatal("Group read crossed connection", err)
			}
		} else if err != nil || bytes.Contains(response.Body, []byte(childID)) {
			t.Fatal("Group list crossed connection", err)
		}
	}
	var projections, committed int
	if err := f.pool.Raw().QueryRow(f.ctx, `SELECT (SELECT count(*) FROM scim.groups),(SELECT count(*) FROM identity.commands WHERE purpose=$1 AND state='committed')`, string(scim.GroupCreate)).Scan(&projections, &committed); err != nil || projections != 1 || committed != 1 {
		t.Fatal("invalid members left committed effects", projections, committed, err)
	}
	emptyOnly, err := NewGroupsService(f.service, 0)
	if err != nil {
		t.Fatal(err)
	}
	request := groupRequest(f, scim.GroupCreate, "", "", "zero-member-budget", `{"schemas":["urn:ietf:params:scim:schemas:core:2.0:Group"],"displayName":"Denied","members":[{"value":"`+user+`","type":"User"}]}`)
	if response, err := emptyOnly.Execute(f.ctx, request); protocolStatus(err) != 400 || len(response.Body) != 0 {
		t.Fatal("explicit zero member ceiling ignored", err)
	}
}

func TestNativeGroupsReplacePatchListDeleteAndOriginalReplay(t *testing.T) {
	f, groups := nativeGroupsFixture(t)
	user := createNativeNamed(t, f, "TypedMember", "User remains")
	childRequest := groupRequest(f, scim.GroupCreate, "", "", "child-group", `{"schemas":["urn:ietf:params:scim:schemas:core:2.0:Group"],"displayName":"Child"}`)
	child, err := groups.Execute(f.ctx, childRequest)
	if err != nil {
		t.Fatal(err)
	}
	childID := groupID(t, child)
	create := groupRequest(f, scim.GroupCreate, "", "", "parent-group", `{"schemas":["urn:ietf:params:scim:schemas:core:2.0:Group"],"displayName":"Original","members":[{"value":"`+user+`","type":"User"},{"value":"`+childID+`","type":"Group"}]}`)
	created, err := groups.Execute(f.ctx, create)
	if err != nil {
		t.Fatal("typed nested references", err)
	}
	id := groupID(t, created)
	childCycle, err := groups.Execute(f.ctx, groupRequest(f, scim.GroupPatch, childID, child.ETag, "nested-directory-cycle", `{"schemas":["urn:ietf:params:scim:api:messages:2.0:PatchOp"],"Operations":[{"op":"add","path":"members","value":[{"value":"`+id+`","type":"Group"}]}]}`))
	if err != nil {
		t.Fatal("nested Groups incorrectly traversed/rejected a directory reference cycle", err)
	}
	replace := groupRequest(f, scim.GroupReplace, id, created.ETag, "replace-group", `{"schemas":["urn:ietf:params:scim:schemas:core:2.0:Group"],"displayName":"Renamed","members":[{"value":"`+user+`","type":"User"},{"value":"`+childID+`","type":"Group"}]}`)
	replaced, err := groups.Execute(f.ctx, replace)
	if err != nil || replaced.Status != 200 || replaced.ETag == created.ETag || groupID(t, replaced) != id {
		t.Fatal("Group replacement", err)
	}
	patch := groupRequest(f, scim.GroupPatch, id, replaced.ETag, "patch-group", `{"schemas":["urn:ietf:params:scim:api:messages:2.0:PatchOp"],"Operations":[{"op":"remove","path":"members[value eq \"`+user+`\"]"},{"op":"replace","path":"displayName","value":"Patched"}]}`)
	patched, err := groups.Execute(f.ctx, patch)
	if err != nil || patched.Status != 200 || patched.ETag == replaced.ETag || bytes.Contains(patched.Body, []byte(user)) || !bytes.Contains(patched.Body, []byte(childID)) {
		t.Fatal("atomic Group PATCH", err)
	}
	noop := groupRequest(f, scim.GroupPatch, id, patched.ETag, "noop-group", `{"schemas":["urn:ietf:params:scim:api:messages:2.0:PatchOp"],"Operations":[{"op":"replace","path":"displayName","value":"Patched"}]}`)
	var generationBefore, generationAfter int64
	if err := f.pool.Raw().QueryRow(f.ctx, `SELECT generation FROM scim.groups WHERE resource_id=$1`, id).Scan(&generationBefore); err != nil {
		t.Fatal(err)
	}
	if got, err := groups.Execute(f.ctx, noop); err != nil || got.ETag != patched.ETag || !bytes.Equal(got.Body, patched.Body) {
		t.Fatal("no-op changed Group metadata", err)
	}
	if err := f.pool.Raw().QueryRow(f.ctx, `SELECT generation FROM scim.groups WHERE resource_id=$1`, id).Scan(&generationAfter); err != nil || generationAfter != generationBefore {
		t.Fatal("no-op advanced private generation", err)
	}
	invalid := noop
	invalid.IdempotencyKey = "atomic-invalid-group-patch"
	invalid.Body = []byte(`{"schemas":["urn:ietf:params:scim:api:messages:2.0:PatchOp"],"Operations":[{"op":"replace","path":"displayName","value":"Must not persist"},{"op":"remove","path":"displayName"}]}`)
	if response, err := groups.Execute(f.ctx, invalid); protocolStatus(err) != 400 || len(response.Body) != 0 {
		t.Fatal("invalid later Group PATCH operation committed", err)
	}
	count := 1
	for _, request := range []scim.Request{
		{Operation: scim.GroupList, Credential: f.bearer, Query: scim.Query{Filter: `members[type eq "Group" and value eq "` + childID + `"]`, SortBy: "displayName", StartIndex: 1, Count: &count}},
		{Operation: scim.GroupSearch, Credential: f.bearer, ContentType: "application/scim+json", Body: []byte(`{"schemas":["urn:ietf:params:scim:api:messages:2.0:SearchRequest"],"filter":"displayName eq \"Patched\"","count":1}`)},
	} {
		response, err := groups.Execute(f.ctx, request)
		var page struct {
			Total     int               `json:"totalResults"`
			Resources []json.RawMessage `json:"Resources"`
		}
		if err != nil || json.Unmarshal(response.Body, &page) != nil || page.Total != 1 || len(page.Resources) != 1 || !bytes.Contains(page.Resources[0], []byte(id)) {
			t.Fatal("complete filtered/sorted Group page", err)
		}
	}
	stale := replace
	stale.IdempotencyKey = "stale-group-replace"
	if _, err := groups.Execute(f.ctx, stale); protocolStatus(err) != 412 {
		t.Fatal("stale Group If-Match admitted", err)
	}
	remove := groupRequest(f, scim.GroupDelete, id, patched.ETag, "", "")
	removed, err := groups.Execute(f.ctx, remove)
	if err != nil || removed.Status != 204 || len(removed.Body) != 0 || removed.ETag != "" {
		t.Fatal("canonical headerless Group DELETE", err)
	}
	if _, err := groups.Execute(f.ctx, groupRequest(f, scim.GroupGet, id, "", "", "")); protocolStatus(err) != 404 {
		t.Fatal("deleted Group disclosed", err)
	}
	if response, err := groups.Execute(f.ctx, groupRequest(f, scim.GroupGet, childID, "", "", "")); err != nil || response.ETag != childCycle.ETag || !bytes.Equal(response.Body, childCycle.Body) {
		t.Fatal("Group delete affected/traversed nested member", err)
	}
	if _, err := f.service.Execute(f.ctx, scim.Request{Operation: scim.UserGet, Credential: f.bearer, ResourceID: user}); err != nil {
		t.Fatal("Group delete affected User member", err)
	}
	if _, err := f.pool.Raw().Exec(f.ctx, `DELETE FROM scim.groups WHERE resource_id=$1 AND deleted_at IS NOT NULL`, id); err != nil {
		t.Fatal("owned terminal tombstone expiry", err)
	}
	for _, request := range []scim.Request{create, replace, patch, noop, remove} {
		response, err := groups.Execute(f.ctx, request)
		if err != nil {
			t.Fatal("original Group result after later changes/tombstone expiry", request.Operation, err)
		}
		if request.Operation == scim.GroupDelete {
			if response.Status != 204 || len(response.Body) != 0 {
				t.Fatal("original empty DELETE response changed")
			}
		} else if groupID(t, response) != id {
			t.Fatal("Group retry created another resource")
		}
	}
	remove.IdempotencyKey = "late-group-delete-alias"
	if response, err := groups.Execute(f.ctx, remove); err != nil || response.Status != 204 {
		t.Fatal("late DELETE key lost original command", err)
	}
	f.deny.Store(true)
	if response, err := groups.Execute(f.ctx, remove); protocolStatus(err) != 403 || len(response.Body) != 0 {
		t.Fatal("historical Group result bypassed current policy", err)
	}
}

func groupRequest(f *nativeFixture, operation scim.Operation, id string, version scim.Version, key, body string) scim.Request {
	return scim.Request{Operation: operation, Credential: f.bearer, ResourceID: id, IfMatch: version, IdempotencyKey: key, ContentType: "application/scim+json", Body: []byte(body)}
}

func groupID(t *testing.T, response scim.Response) string {
	t.Helper()
	var resource struct {
		ID string `json:"id"`
	}
	if json.Unmarshal(response.Body, &resource) != nil || resource.ID == "" || response.ETag == "" {
		t.Fatal("invalid Group response", response.Status)
	}
	return resource.ID
}

func TestNativeGroupsCreateReadAndProfileIsolation(t *testing.T) {
	f, groups := nativeGroupsFixture(t)
	user := createNativeNamed(t, f, "GroupMember", "Member")
	request := groupRequest(f, scim.GroupCreate, "", "", "original-group", `{"schemas":["urn:ietf:params:scim:schemas:core:2.0:Group"],"displayName":"Directory group","externalId":"nonunique-correlation","members":[{"value":"`+user+`","type":"User"}]}`)
	created, err := groups.Execute(f.ctx, request)
	if err != nil || created.Status != 201 {
		t.Fatal("native Group create", created.Status, err)
	}
	id := groupID(t, created)
	if got, err := groups.Execute(f.ctx, groupRequest(f, scim.GroupGet, id, "", "", "")); err != nil || got.Status != 200 || got.ETag != created.ETag || !bytes.Equal(got.Body, created.Body) {
		t.Fatal("exact Group read", err)
	}
	if got, err := groups.Execute(f.ctx, request); err != nil || got.ETag != created.ETag || !bytes.Equal(got.Body, created.Body) {
		t.Fatal("original Group replay", err)
	}
	duplicate := request
	duplicate.IdempotencyKey = "duplicate-group-name-external-id"
	if got, err := groups.Execute(f.ctx, duplicate); err != nil || got.Status != 201 || groupID(t, got) == id {
		t.Fatal("Group displayName/externalId became unique", err)
	}
	var users, groupsCount, committed, audits, events int
	if err := f.pool.Raw().QueryRow(f.ctx, `SELECT
 (SELECT count(*) FROM identity.users),
 (SELECT count(*) FROM scim.groups),
 (SELECT count(*) FROM identity.commands c JOIN scim.groups g ON c.command_id=decode(translate(g.command_id,'-_','+/')||'==','base64') WHERE c.state='committed'),
 (SELECT count(*) FROM audit.records WHERE action='identity.scim.group-create'),
 (SELECT count(*) FROM public.outbox_messages)`).Scan(&users, &groupsCount, &committed, &audits, &events); err != nil {
		t.Fatal("actual Group owner effects", err)
	}
	if users != 1 || groupsCount != 2 || committed != 2 || audits != 2 || events != 4 {
		t.Fatal("Group creation changed foreign owners or missed atomic effects", users, groupsCount, committed, audits, events)
	}
	if _, err := f.service.Execute(f.ctx, request); protocolStatus(err) != 501 {
		t.Fatal("Users implicitly enabled Groups", err)
	}
	if _, err := groups.Execute(f.ctx, scim.Request{Operation: scim.UserGet, ResourceID: user, Credential: f.bearer}); protocolStatus(err) != 501 {
		t.Fatal("Groups implicitly enabled Users", err)
	}
	for _, selected := range []struct {
		group bool
		want  string
		omit  string
	}{{true, "Group", "User"}, {false, "User", "Group"}} {
		req := scim.Request{Operation: scim.ResourceTypesList, Credential: f.bearer}
		response, err := f.service.Execute(f.ctx, req)
		if selected.group {
			response, err = groups.Execute(f.ctx, req)
		}
		if err != nil || !bytes.Contains(response.Body, []byte(`"name":"`+selected.want+`"`)) || bytes.Contains(response.Body, []byte(`"name":"`+selected.omit+`"`)) {
			t.Fatal("profile-specific discovery", err)
		}
	}
}
