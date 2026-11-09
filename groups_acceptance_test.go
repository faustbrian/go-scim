package scim_test

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	authentication "github.com/faustbrian/go-authentication/v2"
	scim "github.com/faustbrian/go-scim"
)

func TestGroupsPublicLifecycleAndDiscovery(t *testing.T) {
	f := newGroupFixture(t, nil)
	f.addUser("user-a", "fixture-connection")
	created := f.call(t, scim.GroupCreate, "", "", groupBody("Tour Guides", `,"externalId":"non-unique","members":[{"value":"user-a","display":"Babs Jensen"}]`))
	doc := object(t, created.Body)
	id := doc["id"].(string)
	if created.Status != 201 || created.ETag == "" || created.Location != "https://scim.example.test/v2/Groups/"+id || doc["meta"].(map[string]any)["resourceType"] != "Group" {
		t.Fatalf("wrong group create response: %#v %s", created, created.Body)
	}
	member := doc["members"].([]any)[0].(map[string]any)
	if member["value"] != "user-a" || member["type"] != "User" || member["$ref"] != "https://scim.example.test/v2/Users/user-a" || member["display"] != "Babs Jensen" {
		t.Fatalf("member identity/defaults lost: %#v", member)
	}
	if read := f.call(t, scim.GroupGet, id, "", ""); string(read.Body) != string(created.Body) || read.ETag != created.ETag {
		t.Fatal("GET changed the persisted group")
	}
	f.call(t, scim.GroupCreate, "", "", groupBody("Tour Guides", `,"externalId":"non-unique"`))
	replaced := f.call(t, scim.GroupReplace, id, created.ETag, groupBody("Replaced", ""))
	replacedMembers, _ := object(t, replaced.Body)["members"].([]any)
	if replaced.ETag == created.ETag || object(t, replaced.Body)["externalId"] != nil || len(replacedMembers) != 0 {
		t.Fatal("replacement did not remove omitted writable fields")
	}
	deleted := f.call(t, scim.GroupDelete, id, replaced.ETag, "")
	if deleted.Status != 204 || len(deleted.Body) != 0 {
		t.Fatalf("wrong deletion response: %#v", deleted)
	}
	f.deny(t, scim.Request{Operation: scim.GroupGet, ResourceID: id}, 404, "")
	for _, operation := range []scim.Operation{scim.SchemasList, scim.ResourceTypesList} {
		list := object(t, f.call(t, operation, "", "", "").Body)
		if list["totalResults"] != float64(1) || list["itemsPerPage"] != float64(1) {
			t.Fatalf("discovery advertised another profile: %#v", list)
		}
	}
	schema := object(t, f.call(t, scim.SchemaGet, groupURN, "", "").Body)
	attrs := schema["attributes"].([]any)
	if attrs[0].(map[string]any)["required"] != true || attrs[1].(map[string]any)["name"] != "members" {
		t.Fatalf("wrong Group schema: %#v", schema)
	}
	for _, raw := range attrs[1].(map[string]any)["subAttributes"].([]any) {
		if raw.(map[string]any)["mutability"] != "immutable" {
			t.Fatalf("member child is not immutable: %#v", raw)
		}
	}
	typ := object(t, f.call(t, scim.ResourceTypeGet, "Group", "", "").Body)
	if typ["endpoint"] != "/Groups" || typ["schema"] != groupURN {
		t.Fatalf("wrong Group resource type: %#v", typ)
	}
	f.deny(t, scim.Request{Operation: scim.ResourceTypeGet, ResourceID: "User"}, 404, "")
	f.deny(t, scim.Request{Operation: scim.UserCreate, Body: []byte(userBody("not-a-group", ""))}, 501, "")
	f.deny(t, scim.Request{Operation: scim.Search, Body: []byte(`{"schemas":["urn:ietf:params:scim:api:messages:2.0:SearchRequest"]}`)}, 501, "")
	newProtocolFixture(t).deny(t, scim.Request{Operation: scim.GroupCreate, Body: []byte(groupBody("not-a-user", ""))}, 501, "")
}

func TestGroupsListFilterSortPageSearchAndProjection(t *testing.T) {
	f := newGroupFixture(t, nil)
	f.addUser("user-a", "fixture-connection")
	first := f.call(t, scim.GroupCreate, "", "", groupBody("Zulu", `,"members":[{"value":"user-a"}]`))
	second := f.call(t, scim.GroupCreate, "", "", groupBody("alpha", `,"members":[{"value":"user-a"}]`))
	f.call(t, scim.GroupCreate, "", "", groupBody("Other", ""))
	count := 1
	query := scim.Query{Filter: `members[value eq "user-a" and type eq "user"]`, SortBy: groupURN + ":displayName", StartIndex: 2, Count: &count, Attributes: "displayName"}
	list := object(t, f.execute(t, scim.Request{Operation: scim.GroupList, Query: query}).Body)
	if list["totalResults"] != float64(2) || list["startIndex"] != float64(2) || list["itemsPerPage"] != float64(1) {
		t.Fatalf("incorrect exact page: %#v", list)
	}
	resource := list["Resources"].([]any)[0].(map[string]any)
	if resource["id"] != object(t, first.Body)["id"] || resource["members"] != nil || resource["meta"].(map[string]any)["version"] != string(first.ETag) {
		t.Fatalf("incorrect projection/sort: %#v", resource)
	}
	search := `{"schemas":["urn:ietf:params:scim:api:messages:2.0:SearchRequest"],"filter":"displayName eq \"ALPHA\"","sortBy":"displayName","attributes":["displayName"],"startIndex":-1,"count":100}`
	result := object(t, f.call(t, scim.GroupSearch, "", "", search).Body)
	if result["totalResults"] != float64(1) || result["Resources"].([]any)[0].(map[string]any)["id"] != object(t, second.Body)["id"] || result["startIndex"] != float64(1) {
		t.Fatalf("search differs from list: %#v", result)
	}
	for _, value := range []int{0, -1} {
		result := object(t, f.execute(t, scim.Request{Operation: scim.GroupList, Query: scim.Query{Count: &value}}).Body)
		if result["totalResults"] != float64(3) || result["itemsPerPage"] != float64(0) || len(result["Resources"].([]any)) != 0 {
			t.Fatalf("count zero lost exact total: %#v", result)
		}
	}
	f.store.incomplete = true
	f.deny(t, scim.Request{Operation: scim.GroupList, Query: scim.Query{Count: &count}}, 400, "tooMany")
}

func TestGroupsRejectMalformedAndMemberBoundariesBeforeMapping(t *testing.T) {
	for name, body := range map[string]string{
		"missing required name":      `{"schemas":["` + groupURN + `"]}`,
		"wrong resource schema":      userBody("user", ""),
		"server ID":                  groupBody("group", `,"id":"chosen"`),
		"duplicate JSON aliases":     groupBody("group", `,"DISPLAYNAME":"other"`),
		"member duplicate aliases":   groupBody("group", `,"members":[{"value":"a","VALUE":"b"}]`),
		"member scalar":              groupBody("group", `,"members":["a"]`),
		"missing member value":       groupBody("group", `,"members":[{"type":"User"}]`),
		"dot member ID":              groupBody("group", `,"members":[{"value":".."}]`),
		"invalid member type":        groupBody("group", `,"members":[{"value":"a","type":"Device"}]`),
		"external member ref":        groupBody("group", `,"members":[{"value":"a","$ref":"https://other.example.test/v2/Users/a"}]`),
		"mismatched member ref":      groupBody("group", `,"members":[{"value":"a","$ref":"Users/b"}]`),
		"mismatched member type":     groupBody("group", `,"members":[{"value":"a","type":"Group","$ref":"Users/a"}]`),
		"query-bearing ref":          groupBody("group", `,"members":[{"value":"a","$ref":"Users/a?scope=b"}]`),
		"empty fragment ref":         groupBody("group", `,"members":[{"value":"a","$ref":"Users/a#"}]`),
		"dot-segment ref":            groupBody("group", `,"members":[{"value":"a","$ref":"Users/../Users/a"}]`),
		"encoded dot-segment ref":    groupBody("group", `,"members":[{"value":"a","$ref":"Users/%2e%2e/Users/a"}]`),
		"encoded path separator ref": groupBody("group", `,"members":[{"value":"a","$ref":"Users/a%2fb"}]`),
		"duplicate member identity":  groupBody("group", `,"members":[{"value":"a"},{"value":"a","type":"user","display":"different"}]`),
		"password unsupported":       groupBody("group", `,"password":"never-store"`),
	} {
		t.Run(name, func(t *testing.T) {
			f := newGroupFixture(t, nil)
			response, err := f.raw(scim.Request{Operation: scim.GroupCreate, Body: []byte(body)})
			if err == nil || response.Status != 0 || f.mapper.calls != 0 || f.store.prepares != 0 || len(f.store.resources) != 0 {
				t.Fatalf("invalid group reached mapping/admission: response=%#v err=%v", response, err)
			}
		})
	}
	f := newGroupFixture(t, func(c *scim.GroupsConfig) { c.GroupMembers = 1 })
	f.deny(t, scim.Request{Operation: scim.GroupCreate, Body: []byte(groupBody("bounded", `,"members":[{"value":"a"},{"value":"b"}]`))}, 400, "invalidValue")
	if f.mapper.calls != 0 || f.store.prepares != 0 {
		t.Fatal("member limit checked after effects")
	}
	zero := newGroupFixture(t, func(c *scim.GroupsConfig) { c.GroupMembers = 0 })
	zero.call(t, scim.GroupCreate, "", "", groupBody("empty members allowed", ""))
	zero.deny(t, scim.Request{Operation: scim.GroupCreate, Body: []byte(groupBody("no members allowed", `,"members":[{"value":"a"}]`))}, 400, "invalidValue")
}

func TestGroupsAtomicPatchMemberImmutabilityAndVersions(t *testing.T) {
	f := newGroupFixture(t, nil)
	f.addUser("a", "fixture-connection")
	f.addUser("b", "fixture-connection")
	created := f.call(t, scim.GroupCreate, "", "", groupBody("before", `,"members":[{"value":"a","display":"Alice"}]`))
	id := object(t, created.Body)["id"].(string)
	for name, operation := range map[string]string{
		"member value":            `{"op":"replace","path":"members[value eq \"a\"].value","value":"b"}`,
		"member ref":              `{"op":"replace","path":"members[value eq \"a\"].$ref","value":"Users/b"}`,
		"member type":             `{"op":"replace","path":"members[value eq \"a\"].type","value":"Group"}`,
		"member display":          `{"op":"replace","path":"members[value eq \"a\"].display","value":"Changed"}`,
		"unselected member child": `{"op":"replace","path":"members.value","value":"b"}`,
		"whole existing member":   `{"op":"replace","path":"members[value eq \"a\"]","value":{"value":"a","display":"Changed"}}`,
	} {
		t.Run(name, func(t *testing.T) {
			f.deny(t, scim.Request{Operation: scim.GroupPatch, ResourceID: id, IfMatch: created.ETag, Body: []byte(patchBody(`{"op":"replace","path":"displayName","value":"must roll back"},` + operation))}, 400, "mutability")
			if read := f.call(t, scim.GroupGet, id, "", ""); read.ETag != created.ETag || string(read.Body) != string(created.Body) {
				t.Fatal("failed PATCH partially mutated group")
			}
		})
	}
	for _, version := range []scim.Version{"", `W/"weak"`, `"stale"`} {
		status, kind := 412, ""
		if version == "" {
			status = 428
		}
		if strings.HasPrefix(string(version), "W/") {
			status, kind = 400, "invalidValue"
		}
		f.deny(t, scim.Request{Operation: scim.GroupPatch, ResourceID: id, IfMatch: version, Body: []byte(patchBody(`{"op":"replace","path":"displayName","value":"after"}`))}, status, kind)
	}
	patched := f.call(t, scim.GroupPatch, id, created.ETag, patchBody(`{"op":"remove","path":"members[value eq \"a\"]"},{"op":"add","path":"members","value":[{"value":"b"}]},{"op":"replace","path":"displayName","value":"after"}`))
	if patched.ETag == created.ETag || object(t, patched.Body)["members"].([]any)[0].(map[string]any)["value"] != "b" {
		t.Fatal("member add/remove failed")
	}
	noop := f.call(t, scim.GroupPatch, id, patched.ETag, patchBody(`{"op":"add","path":"members","value":[{"value":"b"}]}`))
	if noop.ETag != patched.ETag || string(noop.Body) != string(patched.Body) {
		t.Fatal("adding existing member did not preserve no-op")
	}
}

func TestGroupsIsolationUnknownMembersAndReplay(t *testing.T) {
	f := newGroupFixture(t, nil)
	f.addUser("private-user", "fixture-other-connection")
	f.deny(t, scim.Request{Operation: scim.GroupCreate, Body: []byte(groupBody("unknown", `,"members":[{"value":"unknown"}]`))}, 400, "invalidValue")
	f.deny(t, scim.Request{Operation: scim.GroupCreate, Body: []byte(groupBody("cross connection", `,"members":[{"value":"private-user"}]`))}, 400, "invalidValue")
	f.addUser("same-id", "fixture-connection")
	f.deny(t, scim.Request{Operation: scim.GroupGet, ResourceID: "same-id"}, 404, "")
	f.deny(t, scim.Request{Operation: scim.GroupCreate, Body: []byte(groupBody("wrong member type", `,"members":[{"value":"same-id","type":"Group"}]`))}, 400, "invalidValue")
	request := scim.Request{Operation: scim.GroupCreate, IdempotencyKey: "group-create", Body: []byte(groupBody("replay", `,"members":[{"value":"same-id"}]`))}
	created := f.execute(t, request)
	id := object(t, created.Body)["id"].(string)
	if replay := f.execute(t, request); replay.ETag != created.ETag || string(replay.Body) != string(created.Body) || len(f.store.resources) != 1 {
		t.Fatal("create retry allocated another resource")
	}
	request.Body = []byte(groupBody("changed fingerprint", ""))
	f.deny(t, request, 409, "")
	f.deny(t, scim.Request{Operation: scim.GroupGet, Credential: authentication.NewBearerCredential("fixture-other-connection"), ResourceID: id}, 404, "")
	deleteRequest := scim.Request{Operation: scim.GroupDelete, ResourceID: id, IfMatch: created.ETag}
	f.execute(t, deleteRequest)
	if replay := f.execute(t, deleteRequest); replay.Status != 204 {
		t.Fatal("headerless deletion did not recover original result")
	}
	deleteRequest.IdempotencyKey = "later-key"
	if replay := f.execute(t, deleteRequest); replay.Status != 204 {
		t.Fatal("later optional deletion key lost canonical recovery")
	}

	unknown := newGroupFixture(t, nil)
	unknown.store.unknown = true
	request = scim.Request{Operation: scim.GroupCreate, IdempotencyKey: "unknown", Body: []byte(groupBody("uncertain", ""))}
	unknown.deny(t, request, 503, "")
	unknown.store.unknown = false
	unknown.deny(t, request, 503, "")
	if unknown.mapper.calls != 1 || len(unknown.store.pending) != 1 || len(unknown.store.resources) != 0 {
		t.Fatal("unknown outcome released authority for another attempt")
	}
}

func TestGroupsOriginalAuthorityDeadline(t *testing.T) {
	clock := fixtureNow
	auth := &groupClockAuthenticator{now: &clock}
	f := newGroupFixture(t, func(c *scim.GroupsConfig) { c.Now = func() time.Time { return clock }; c.Authenticator = auth })
	created := f.call(t, scim.GroupCreate, "", "", groupBody("authority", ""))
	id := object(t, created.Body)["id"].(string)
	clock = clock.Add(20 * time.Second)
	f.deny(t, scim.Request{Operation: scim.GroupGet, ResourceID: id}, 401, "")
	if len(f.store.resources) != 1 {
		t.Fatal("authority expiry mutated state")
	}
	auth.readAt = clock.Add(-time.Second)
	auth.expiresAt = clock.Add(21 * time.Second)
	f.deny(t, scim.Request{Operation: scim.GroupList}, 401, "")
}

type groupClockAuthenticator struct {
	now               *time.Time
	readAt, expiresAt time.Time
}

func (a *groupClockAuthenticator) Authenticate(ctx context.Context, credential authentication.BearerCredential) (scim.Connection, error) {
	c, err := (protocolAuthenticator{}).Authenticate(ctx, credential)
	if !a.readAt.IsZero() {
		c.AuthorityReadBeganAt = a.readAt
	}
	if !a.expiresAt.IsZero() {
		c.AuthorityValidUntil = a.expiresAt
	}
	return c, err
}

func TestGroupsErrorRedaction(t *testing.T) {
	f := newGroupFixture(t, nil)
	response, err := f.raw(scim.Request{Operation: scim.GroupCreate, Body: []byte(groupBody("sensitive-name", `,"members":[{"value":"sensitive-unknown"}]`))})
	assertProtocolError(t, response, err, 400, "invalidValue")
	encoded, _ := json.Marshal(err)
	if strings.Contains(string(encoded), "sensitive") || !strings.Contains(string(encoded), `"status":"400"`) {
		t.Fatalf("unstable or revealing error: %s", encoded)
	}
}
