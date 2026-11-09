package scim_test

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	scim "github.com/faustbrian/go-scim"
)

type primaryDescriptorCase struct {
	label, name string
	core        bool
}

func primaryDescriptorCases() []primaryDescriptorCase {
	return []primaryDescriptorCase{
		{label: "extension-primary", name: "primary"},
		{label: "extension-Primary", name: "Primary"},
		{label: "extension-PRIMARY", name: "PRIMARY"},
		{label: "core-primary", name: "primary", core: true},
	}
}

func (d primaryDescriptorCase) configure(c *scim.Config) {
	if d.core {
		return
	}
	items := reviewAttribute("items", "complex")
	items.MultiValued = true
	items.SubAttributes = []scim.Attribute{reviewAttribute("value", "string"), reviewAttribute(d.name, "boolean")}
	reviewSchema(items)(c)
}

func (d primaryDescriptorCase) path() string {
	if d.core {
		return "emails"
	}
	return extensionURN + ":items"
}

func (d primaryDescriptorCase) user(name, members string) string {
	if d.core {
		return userBody(name, `,"emails":`+members)
	}
	return reviewUser(name, `{"items":`+members+`}`)
}

func (d primaryDescriptorCase) members(t *testing.T, doc map[string]any) []any {
	t.Helper()
	field := "emails"
	if !d.core {
		var ok bool
		doc, ok = doc[extensionURN].(map[string]any)
		if !ok {
			t.Fatal("missing configured extension representation")
		}
		field = "items"
	}
	members, ok := doc[field].([]any)
	if !ok {
		t.Fatal("missing multi-valued member representation")
	}
	for _, member := range members {
		obj, ok := member.(map[string]any)
		if !ok {
			t.Fatal("non-object member representation")
		}
		for key := range obj {
			if strings.EqualFold(key, "primary") && key != d.name {
				t.Fatalf("created primary alias %q instead of canonical descriptor %q", key, d.name)
			}
		}
	}
	return members
}

func TestUsersReviewF2PrimaryDescriptorRejectsMultipleTrue(t *testing.T) {
	for _, descriptor := range primaryDescriptorCases() {
		for _, operation := range []string{"create", "replace", "patch-add", "patch-replace", "patch-selected-all"} {
			t.Run(descriptor.label+"/"+operation, func(t *testing.T) {
				fixture := configuredProtocolFixture(t, descriptor.configure)
				created := fixture.call(t, scim.UserCreate, "", "", descriptor.user("descriptor-multiple", `[{"value":"a"},{"value":"b"}]`))
				id := object(t, created.Body)["id"].(string)
				values := `[{"value":"a","` + descriptor.name + `":true},{"value":"b","` + descriptor.name + `":true}]`
				request := scim.Request{ResourceID: id, IfMatch: created.ETag}
				switch operation {
				case "create":
					request.Operation, request.ResourceID, request.IfMatch = scim.UserCreate, "", ""
					request.Body = []byte(descriptor.user("descriptor-multiple-new", values))
				case "replace":
					request.Operation = scim.UserReplace
					request.Body = []byte(descriptor.user("descriptor-multiple", values))
				case "patch-add", "patch-replace":
					request.Operation = scim.UserPatch
					verb := strings.TrimPrefix(operation, "patch-")
					request.Body = []byte(patchBody(`{"op":"` + verb + `","path":"` + descriptor.path() + `","value":` + values + `}`))
				case "patch-selected-all":
					request.Operation = scim.UserPatch
					request.Body = []byte(patchBody(`{"op":"replace","path":"` + descriptor.path() + `[value pr].primary","value":true}`))
				}
				calls := fixture.mapper.calls
				fixture.deny(t, request, 400, "invalidValue")
				if fixture.mapper.calls != calls {
					t.Fatal("multiple true-primary members crossed validation into mapping")
				}
				if read := fixture.call(t, scim.UserGet, id, "", ""); read.ETag != created.ETag || string(read.Body) != string(created.Body) || len(fixture.store.resources) != 1 {
					t.Fatal("rejected multiple-primary write changed persisted state")
				}
			})
		}
	}
}

func TestUsersReviewF2PrimaryDescriptorOmittedFalseQueries(t *testing.T) {
	for _, descriptor := range primaryDescriptorCases() {
		for _, operation := range []scim.Operation{scim.UserList, scim.UserSearch, scim.Search} {
			for _, suffix := range []string{`.primary eq false`, `[primary eq false]`, `[primary ne true]`} {
				t.Run(descriptor.label+"/"+string(operation)+"/"+suffix, func(t *testing.T) {
					fixture := configuredProtocolFixture(t, descriptor.configure)
					created := fixture.call(t, scim.UserCreate, "", "", descriptor.user("descriptor-query", `[{"value":"a"},{"value":"b","`+descriptor.name+`":true}]`))
					id := object(t, created.Body)["id"].(string)
					response := fixture.execute(t, followupQueryRequest(t, operation, descriptor.path()+suffix))
					doc := object(t, response.Body)
					resources := doc["Resources"].([]any)
					if doc["totalResults"] != float64(1) || len(resources) != 1 || resources[0].(map[string]any)["id"] != id {
						t.Fatalf("configured omitted-primary default lost its resource: %s", response.Body)
					}
					if _, supplied := descriptor.members(t, resources[0].(map[string]any))[0].(map[string]any)[descriptor.name]; supplied {
						t.Fatal("query materialized an omitted primary default")
					}
					if read := fixture.call(t, scim.UserGet, id, "", ""); read.ETag != created.ETag || string(read.Body) != string(created.Body) {
						t.Fatal("configured-primary query changed stored representation")
					}
				})
			}
		}
	}
}

func TestUsersReviewF2PrimaryDescriptorPreferredMemberSorting(t *testing.T) {
	for _, descriptor := range primaryDescriptorCases() {
		for _, operation := range []scim.Operation{scim.UserList, scim.UserSearch, scim.Search} {
			for _, order := range []string{"ascending", "descending"} {
				t.Run(descriptor.label+"/"+string(operation)+"/"+order, func(t *testing.T) {
					fixture := configuredProtocolFixture(t, descriptor.configure)
					first := fixture.call(t, scim.UserCreate, "", "", descriptor.user("descriptor-sort-a", `[{"value":"z"},{"value":"a","`+descriptor.name+`":true}]`))
					second := fixture.call(t, scim.UserCreate, "", "", descriptor.user("descriptor-sort-b", `[{"value":"m"}]`))
					request := scim.Request{Operation: operation}
					if operation == scim.UserList {
						request.Query = scim.Query{SortBy: descriptor.path() + ".value", SortOrder: order}
					} else {
						body, err := json.Marshal(map[string]any{"schemas": []string{searchURN}, "sortBy": descriptor.path() + ".value", "sortOrder": order})
						if err != nil {
							t.Fatal(err)
						}
						request.Body = body
					}
					response := fixture.execute(t, request)
					doc := object(t, response.Body)
					resources := doc["Resources"].([]any)
					want := []any{object(t, first.Body)["id"], object(t, second.Body)["id"]}
					if order == "descending" {
						want[0], want[1] = want[1], want[0]
					}
					if doc["totalResults"] != float64(2) || len(resources) != 2 || resources[0].(map[string]any)["id"] != want[0] || resources[1].(map[string]any)["id"] != want[1] {
						t.Fatalf("sort did not use the schema-named preferred member: %s", response.Body)
					}
					for _, resource := range resources {
						descriptor.members(t, resource.(map[string]any))
					}
				})
			}
		}
	}
}

func TestUsersReviewF2PrimaryDescriptorOmittedFalseSorting(t *testing.T) {
	for _, descriptor := range primaryDescriptorCases() {
		t.Run(descriptor.label, func(t *testing.T) {
			fixture := configuredProtocolFixture(t, descriptor.configure)
			omitted := fixture.call(t, scim.UserCreate, "", "", descriptor.user("descriptor-sort-false", `[{"value":"a"}]`))
			preferred := fixture.call(t, scim.UserCreate, "", "", descriptor.user("descriptor-sort-true", `[{"value":"b","`+descriptor.name+`":true}]`))
			response := fixture.execute(t, scim.Request{Operation: scim.UserList, Query: scim.Query{SortBy: descriptor.path() + ".primary"}})
			resources := object(t, response.Body)["Resources"].([]any)
			if len(resources) != 2 || resources[0].(map[string]any)["id"] != object(t, omitted.Body)["id"] || resources[1].(map[string]any)["id"] != object(t, preferred.Body)["id"] {
				t.Fatal("sort treated omitted configured primary as unassigned instead of false")
			}
			if _, supplied := descriptor.members(t, resources[0].(map[string]any))[0].(map[string]any)[descriptor.name]; supplied {
				t.Fatal("sort materialized an omitted primary default")
			}
		})
	}
}

func TestUsersReviewF2PrimaryDescriptorAtomicReassignment(t *testing.T) {
	for _, descriptor := range primaryDescriptorCases() {
		for _, target := range []string{"collection-add", "collection-replace", "selected-add", "selected-replace", "selected-record-add", "selected-record-replace", "omitted-selector-add", "omitted-selector-replace"} {
			t.Run(descriptor.label+"/"+target, func(t *testing.T) {
				now := fixtureNow
				fixture := configuredProtocolFixture(t, func(c *scim.Config) {
					descriptor.configure(c)
					c.Now = func() time.Time { return now }
				})
				values := `[{"value":"a","` + descriptor.name + `":true},{"value":"b","` + descriptor.name + `":false}]`
				if strings.HasPrefix(target, "omitted-selector-") {
					values = `[{"value":"a","` + descriptor.name + `":true},{"value":"b"}]`
				}
				created := fixture.call(t, scim.UserCreate, "", "", descriptor.user("descriptor-reassign", values))
				id := object(t, created.Body)["id"].(string)
				// Client aliases are legal; internal writes must retain the schema spelling.
				verb, path, value := "replace", descriptor.path()+`[value eq \"b\"].primary`, `true`
				count := 2
				switch target {
				case "collection-add":
					verb, path, value, count = "add", descriptor.path(), `[{"value":"c","primary":true}]`, 3
				case "collection-replace":
					path, value = descriptor.path(), `[{"value":"a","primary":false},{"value":"b","primary":true}]`
				case "selected-add":
					verb = "add"
				case "selected-record-add", "selected-record-replace":
					verb = strings.TrimPrefix(target, "selected-record-")
					path, value = descriptor.path()+`[value eq \"b\"]`, `{"value":"b","primary":true}`
				case "omitted-selector-add", "omitted-selector-replace":
					verb = strings.TrimPrefix(target, "omitted-selector-")
					path = descriptor.path() + `[primary eq false].primary`
				}
				now = now.Add(time.Second)
				request := scim.Request{Operation: scim.UserPatch, ResourceID: id, IfMatch: created.ETag, IdempotencyKey: "descriptor-reassign", Body: []byte(patchBody(`{"op":"` + verb + `","path":"` + path + `","value":` + value + `}`))}
				updated := fixture.execute(t, request)
				members := descriptor.members(t, object(t, updated.Body))
				if len(members) != count {
					t.Fatal("atomic reassignment lost or duplicated a member")
				}
				for index, member := range members {
					if member.(map[string]any)[descriptor.name] != (index == count-1) {
						t.Fatalf("primary was not reassigned atomically with canonical keys: %s", updated.Body)
					}
				}
				if updated.ETag == created.ETag || object(t, updated.Body)["meta"].(map[string]any)["lastModified"] == object(t, created.Body)["meta"].(map[string]any)["lastModified"] {
					t.Fatal("real primary reassignment did not advance version and modification time")
				}
				for _, stored := range fixture.store.resources {
					descriptor.members(t, stored.Attributes)
				}
				if read := fixture.call(t, scim.UserGet, id, "", ""); read.ETag != updated.ETag || string(read.Body) != string(updated.Body) {
					t.Fatal("atomic primary result differs from stored representation")
				}
				now = now.Add(time.Second)
				calls := fixture.mapper.calls
				if replay := fixture.execute(t, request); replay.ETag != updated.ETag || string(replay.Body) != string(updated.Body) || fixture.mapper.calls != calls {
					t.Fatal("primary reassignment replay changed its result or repeated mapping")
				}
			})
		}
	}
}

func TestUsersReviewF2PrimaryDescriptorReassignmentRetainsOmittedSiblings(t *testing.T) {
	for _, descriptor := range primaryDescriptorCases() {
		for _, target := range []string{"collection-add", "selected-field", "selected-record"} {
			t.Run(descriptor.label+"/"+target, func(t *testing.T) {
				fixture := configuredProtocolFixture(t, descriptor.configure)
				created := fixture.call(t, scim.UserCreate, "", "", descriptor.user("descriptor-preserve-omission", `[{"value":"a","`+descriptor.name+`":true},{"value":"b","`+descriptor.name+`":false},{"value":"c"},{"value":"d","`+descriptor.name+`":false}]`))
				id := object(t, created.Body)["id"].(string)
				verb, path, value := "replace", descriptor.path()+`[value eq \"d\"].primary`, `true`
				if target == "collection-add" {
					verb, path, value = "add", descriptor.path(), `[{"value":"e","primary":true}]`
				} else if target == "selected-record" {
					path, value = descriptor.path()+`[value eq \"d\"]`, `{"value":"d","primary":true}`
				}
				updated := fixture.call(t, scim.UserPatch, id, created.ETag, patchBody(`{"op":"`+verb+`","path":"`+path+`","value":`+value+`}`))
				members := descriptor.members(t, object(t, updated.Body))
				if members[0].(map[string]any)[descriptor.name] != false || members[1].(map[string]any)[descriptor.name] != false || members[len(members)-1].(map[string]any)[descriptor.name] != true {
					t.Fatal("reassignment did not demote the old primary and promote the new one")
				}
				if _, supplied := members[2].(map[string]any)[descriptor.name]; supplied {
					t.Fatal("demotion materialized false on an already omitted non-primary sibling")
				}
				for _, stored := range fixture.store.resources {
					if _, supplied := descriptor.members(t, stored.Attributes)[2].(map[string]any)[descriptor.name]; supplied {
						t.Fatal("demotion persisted a synthetic default on an omitted sibling")
					}
				}
			})
		}
	}
}

func TestUsersReviewF2PrimaryDescriptorNoOpRetainsRepresentationAndReplay(t *testing.T) {
	for _, descriptor := range primaryDescriptorCases() {
		for _, direction := range []struct{ label, stored, incoming string }{
			{label: "omitted-to-false", incoming: `,"primary":false`},
			{label: "false-to-omitted", stored: `,"` + descriptor.name + `":false`},
		} {
			t.Run(descriptor.label+"/"+direction.label, func(t *testing.T) {
				now := fixtureNow
				fixture := configuredProtocolFixture(t, func(c *scim.Config) {
					descriptor.configure(c)
					c.Now = func() time.Time { return now }
				})
				created := fixture.call(t, scim.UserCreate, "", "", descriptor.user("descriptor-noop", `[{"value":"a"`+direction.stored+`}]`))
				id := object(t, created.Body)["id"].(string)
				original := descriptor.members(t, object(t, created.Body))[0].(map[string]any)
				if _, supplied := original[descriptor.name]; supplied != (direction.stored != "") {
					t.Fatal("create synthesized or discarded supplied primary representation")
				}
				now = now.Add(time.Second)
				request := scim.Request{Operation: scim.UserPatch, ResourceID: id, IfMatch: created.ETag, IdempotencyKey: "descriptor-noop", Body: []byte(patchBody(`{"op":"add","path":"` + descriptor.path() + `","value":[{"value":"a"` + direction.incoming + `}]}`))}
				updated := fixture.execute(t, request)
				if updated.ETag != created.ETag || string(updated.Body) != string(created.Body) {
					t.Fatal("configured-primary no-op changed representation, ID, version or timestamp")
				}
				now = now.Add(time.Second)
				if replay := fixture.execute(t, request); replay.ETag != created.ETag || string(replay.Body) != string(created.Body) {
					t.Fatal("configured-primary no-op replay changed the original result")
				}
				for _, stored := range fixture.store.resources {
					member := descriptor.members(t, stored.Attributes)[0].(map[string]any)
					if _, supplied := member[descriptor.name]; supplied != (direction.stored != "") {
						t.Fatal("comparison-only default or primary alias escaped into Store")
					}
				}
			})
		}
	}
}

func TestUsersReviewF2PrimaryDescriptorSingularAndTypeControls(t *testing.T) {
	for _, name := range []string{"primary", "Primary", "PRIMARY"} {
		t.Run(name, func(t *testing.T) {
			parent := reviewAttribute("parent", "complex")
			parent.SubAttributes = []scim.Attribute{reviewAttribute(name, "boolean")}
			items := reviewAttribute("items", "complex")
			items.MultiValued = true
			items.SubAttributes = []scim.Attribute{reviewAttribute("value", "string"), reviewAttribute(name, "string"), reviewAttribute("flag", "boolean")}
			fixture := configuredProtocolFixture(t, reviewSchema(parent, items))
			created := fixture.call(t, scim.UserCreate, "", "", reviewUser("descriptor-boundary", `{"parent":{},"items":[{"value":"a","`+name+`":"true"},{"value":"b","`+name+`":"true"}]}`))
			id := object(t, created.Body)["id"].(string)
			for _, filter := range []string{extensionURN + `:parent.primary eq false`, extensionURN + `:items[flag eq false]`, `active eq false`} {
				response := fixture.execute(t, followupQueryRequest(t, scim.UserList, filter))
				if object(t, response.Body)["totalResults"] != float64(0) {
					t.Fatal("primary policy defaulted a singular or unrelated Boolean")
				}
			}
			updated := fixture.call(t, scim.UserPatch, id, created.ETag, patchBody(`{"op":"add","path":"`+extensionURN+`:parent.primary","value":false}`))
			if updated.ETag == created.ETag || object(t, updated.Body)[extensionURN].(map[string]any)["parent"].(map[string]any)[name] != false {
				t.Fatal("singular absent/false transition was incorrectly treated as defaulted")
			}
			fixture.deny(t, scim.Request{Operation: scim.UserPatch, ResourceID: id, IfMatch: updated.ETag, Body: []byte(patchBody(`{"op":"add","path":"` + extensionURN + `:items","value":[{"value":"c","primary":true}]}`))}, 400, "invalidValue")
		})
	}
}

func TestUsersReviewF2PrimaryDescriptorMultiValuedBooleanIsNotPrimary(t *testing.T) {
	for _, name := range []string{"primary", "Primary", "PRIMARY"} {
		t.Run(name, func(t *testing.T) {
			primary := reviewAttribute(name, "boolean")
			primary.MultiValued = true
			items := reviewAttribute("items", "complex")
			items.MultiValued = true
			items.SubAttributes = []scim.Attribute{reviewAttribute("value", "string"), primary}
			fixture := configuredProtocolFixture(t, reviewSchema(items))
			created := fixture.call(t, scim.UserCreate, "", "", reviewUser("descriptor-not-singular", `{"items":[{"value":"a","`+name+`":[true]},{"value":"b","`+name+`":[true]}]}`))
			id := object(t, created.Body)["id"].(string)
			updated := fixture.call(t, scim.UserPatch, id, created.ETag, patchBody(`{"op":"add","path":"`+extensionURN+`:items","value":[{"value":"c","primary":[true]}]}`))
			descriptor := primaryDescriptorCase{name: name}
			members := descriptor.members(t, object(t, updated.Body))
			if len(members) != 3 {
				t.Fatal("non-singular Boolean descriptor incorrectly acquired primary set constraints")
			}
			for _, member := range members {
				values, ok := member.(map[string]any)[name].([]any)
				if !ok || len(values) != 1 || values[0] != true {
					t.Fatal("primary reassignment policy rewrote a multi-valued Boolean descriptor")
				}
			}
		})
	}
}

func TestUsersReviewF2PrimaryDescriptorReturnedAndImmutableControls(t *testing.T) {
	for _, name := range []string{"primary", "Primary", "PRIMARY"} {
		t.Run(name, func(t *testing.T) {
			primary := reviewAttribute(name, "boolean")
			primary.Returned = "request"
			items := reviewAttribute("items", "complex")
			items.MultiValued = true
			items.SubAttributes = []scim.Attribute{reviewAttribute("value", "string"), primary}
			immutable := reviewAttribute(name, "boolean")
			immutable.Mutability = "immutable"
			parent := reviewAttribute("parent", "complex")
			parent.SubAttributes = []scim.Attribute{immutable}
			fixture := configuredProtocolFixture(t, reviewSchema(items, parent))
			created := fixture.call(t, scim.UserCreate, "", "", reviewUser("descriptor-policy", `{"parent":{"`+name+`":true},"items":[{"value":"a","`+name+`":true}]}`))
			id := object(t, created.Body)["id"].(string)
			if object(t, created.Body)[extensionURN].(map[string]any)["items"].([]any)[0].(map[string]any)[name] != true {
				t.Fatal("write response lost supplied request-only primary")
			}
			read := fixture.call(t, scim.UserGet, id, "", "")
			if _, disclosed := object(t, read.Body)[extensionURN].(map[string]any)["items"].([]any)[0].(map[string]any)[name]; disclosed {
				t.Fatal("ordinary GET disclosed request-only primary")
			}
			fixture.deny(t, scim.Request{Operation: scim.UserPatch, ResourceID: id, IfMatch: created.ETag, Body: []byte(patchBody(`{"op":"replace","path":"` + extensionURN + `:parent.primary","value":false}`))}, 400, "mutability")
			if after := fixture.call(t, scim.UserGet, id, "", ""); after.ETag != read.ETag || string(after.Body) != string(read.Body) {
				t.Fatal("rejected immutable primary write changed the resource")
			}
		})
	}
}
