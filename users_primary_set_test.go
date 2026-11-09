package scim_test

import (
	"testing"
	"time"

	scim "github.com/faustbrian/go-scim"
)

func TestUsersReviewF1PrimarySetSuppliedDuplicatesRejected(t *testing.T) {
	for _, operation := range []scim.Operation{scim.UserCreate, scim.UserReplace} {
		for _, target := range []string{"emails", "extension-items"} {
			for _, pair := range []struct{ name, first, second string }{
				{"omitted-before-false", "", `,"primary":false`},
				{"false-before-omitted", `,"primary":false`, ""},
				{"null-before-false", `,"primary":null`, `,"primary":false`},
				{"false-before-null", `,"primary":false`, `,"primary":null`},
				{"omitted-before-null-control", "", `,"primary":null`},
				{"null-before-omitted-control", `,"primary":null`, ""},
			} {
				t.Run(string(operation)+"/"+target+"/"+pair.name, func(t *testing.T) {
					items := reviewAttribute("items", "complex")
					items.MultiValued = true
					items.SubAttributes = []scim.Attribute{reviewAttribute("value", "string"), reviewAttribute("primary", "boolean")}
					fixture := configuredProtocolFixture(t, reviewSchema(items))
					created := fixture.call(t, scim.UserCreate, "", "", userBody("primary-duplicate-existing", `,"displayName":"retain"`))
					id := object(t, created.Body)["id"].(string)
					values := `[{"value":"a@example.test"` + pair.first + `},{"value":"a@example.test"` + pair.second + `}]`
					name := "primary-duplicate-new"
					request := scim.Request{Operation: operation}
					if operation == scim.UserReplace {
						name, request.ResourceID, request.IfMatch = "primary-duplicate-existing", id, created.ETag
					}
					body := userBody(name, `,"emails":`+values)
					if target == "extension-items" {
						body = reviewUser(name, `{"items":`+values+`}`)
					}
					request.Body = []byte(body)
					calls, prepares := fixture.mapper.calls, fixture.store.prepares
					fixture.deny(t, request, 400, "invalidValue")
					if fixture.mapper.calls != calls || fixture.store.prepares != prepares {
						t.Fatal("canonical-equivalent supplied members crossed resource admission")
					}
					read := fixture.call(t, scim.UserGet, id, "", "")
					if read.ETag != created.ETag || string(read.Body) != string(created.Body) || len(fixture.store.resources) != 1 {
						t.Fatal("rejected duplicate set changed persisted resources")
					}
				})
			}
		}
	}
}

func TestUsersReviewF1PrimarySetExistingMemberAddNoOp(t *testing.T) {
	for _, target := range []string{"emails", "extension-items"} {
		for _, direction := range []struct{ name, stored, incoming string }{
			{"omitted-to-false", "", `,"primary":false`},
			{"false-to-omitted", `,"primary":false`, ""},
		} {
			for _, withOther := range []bool{false, true} {
				label := "singleton"
				if withOther {
					label = "with-other-member"
				}
				t.Run(target+"/"+direction.name+"/"+label, func(t *testing.T) {
					now := fixtureNow
					items := reviewAttribute("items", "complex")
					items.MultiValued = true
					items.SubAttributes = []scim.Attribute{reviewAttribute("value", "string"), reviewAttribute("primary", "boolean")}
					fixture := configuredProtocolFixture(t, func(c *scim.Config) {
						reviewSchema(items)(c)
						c.Now = func() time.Time { return now }
					})
					values := `[{"value":"a@example.test"` + direction.stored + `}`
					if withOther {
						values += `,{"value":"other@example.test","primary":true}`
					}
					values += `]`
					body, path := userBody("primary-member-noop", `,"emails":`+values), "emails"
					if target == "extension-items" {
						body, path = reviewUser("primary-member-noop", `{"items":`+values+`}`), extensionURN+":items"
					}
					created := fixture.call(t, scim.UserCreate, "", "", body)
					original := object(t, created.Body)
					id := original["id"].(string)
					for _, stored := range fixture.store.resources {
						attributes := stored.Attributes
						field := "emails"
						if target == "extension-items" {
							attributes, field = attributes[extensionURN].(map[string]any), "items"
						}
						first := attributes[field].([]any)[0].(map[string]any)
						primary, supplied := first["primary"]
						if direction.stored == "" && supplied || direction.stored != "" && (!supplied || primary != false) {
							t.Fatal("create synthesized or discarded the source primary representation in Store")
						}
					}
					now = now.Add(time.Second)
					request := scim.Request{Operation: scim.UserPatch, ResourceID: id, IfMatch: created.ETag, IdempotencyKey: "primary-member-noop", Body: []byte(patchBody(`{"op":"add","path":"` + path + `","value":[{"value":"a@example.test"` + direction.incoming + `}]}`))}
					updated := fixture.execute(t, request)
					if updated.ETag != created.ETag {
						t.Error("existing effective-primary=false member changed the ETag")
					}
					if object(t, updated.Body)["meta"].(map[string]any)["lastModified"] != original["meta"].(map[string]any)["lastModified"] {
						t.Error("existing member advanced modification time after clock advance")
					}
					if string(updated.Body) != string(created.Body) {
						t.Error("existing-member add changed original member representation or resource ID")
					}
					read := fixture.call(t, scim.UserGet, id, "", "")
					if read.ETag != created.ETag || string(read.Body) != string(created.Body) {
						t.Error("existing-member add persisted a duplicate or a synthetic primary default")
					}
					now = now.Add(time.Second)
					changed := fixture.call(t, scim.UserPatch, id, read.ETag, patchBody(`{"op":"replace","path":"displayName","value":"later-change"}`))
					if changed.ETag == read.ETag {
						t.Fatal("real intervening update did not change resource version")
					}
					now = now.Add(time.Second)
					calls := fixture.mapper.calls
					replayed := fixture.execute(t, request)
					if replayed.ETag != created.ETag || string(replayed.Body) != string(created.Body) {
						t.Error("no-op replay did not retain the original representation, version and timestamps")
					}
					latest := fixture.call(t, scim.UserGet, id, "", "")
					if fixture.mapper.calls != calls || latest.ETag != changed.ETag || string(latest.Body) != string(changed.Body) {
						t.Fatal("no-op replay remapped or overwrote the intervening resource update")
					}
				})
			}
		}
	}
}

func TestUsersReviewF1PrimarySetEquivalentPatchReplaceNoOp(t *testing.T) {
	for _, direction := range []struct{ name, stored, incoming string }{
		{"omitted-to-false", "", `,"primary":false`},
		{"false-to-omitted", `,"primary":false`, ""},
	} {
		t.Run(direction.name, func(t *testing.T) {
			now := fixtureNow
			fixture := configuredProtocolFixture(t, func(c *scim.Config) { c.Now = func() time.Time { return now } })
			created := fixture.call(t, scim.UserCreate, "", "", userBody("primary-replace-noop", `,"emails":[{"value":"a@example.test"`+direction.stored+`}]`))
			id := object(t, created.Body)["id"].(string)
			now = now.Add(time.Second)
			request := scim.Request{Operation: scim.UserPatch, ResourceID: id, IfMatch: created.ETag, IdempotencyKey: "primary-replace-noop", Body: []byte(patchBody(`{"op":"replace","path":"emails","value":[{"value":"a@example.test"` + direction.incoming + `}]}`))}
			updated := fixture.execute(t, request)
			if updated.ETag != created.ETag || string(updated.Body) != string(created.Body) {
				t.Error("whole-array effective-primary equality changed original representation, version or modification time")
			}
			now = now.Add(time.Second)
			if replayed := fixture.execute(t, request); replayed.ETag != created.ETag || string(replayed.Body) != string(created.Body) {
				t.Error("equivalent whole-array PATCH replay changed the original result")
			}
			if read := fixture.call(t, scim.UserGet, id, "", ""); read.ETag != created.ETag || string(read.Body) != string(created.Body) {
				t.Fatal("equivalent whole-array PATCH persisted a changed representation")
			}
		})
	}
}

func TestUsersReviewF1PrimarySetNestedElementKeysAndEquality(t *testing.T) {
	for _, operation := range []string{"supplied-duplicates", "add", "replace"} {
		t.Run(operation, func(t *testing.T) {
			now := fixtureNow
			members := reviewAttribute("members", "complex")
			members.MultiValued = true
			members.SubAttributes = []scim.Attribute{reviewAttribute("value", "string"), reviewAttribute("primary", "boolean")}
			records := reviewAttribute("records", "complex")
			records.MultiValued = true
			records.SubAttributes = []scim.Attribute{reviewAttribute("value", "string"), members}
			fixture := configuredProtocolFixture(t, func(c *scim.Config) {
				reviewSchema(records)(c)
				c.Now = func() time.Time { return now }
			})
			omitted := `{"value":"outer","members":[{"value":"inner"}]}`
			explicit := `{"value":"outer","members":[{"value":"inner","primary":false}]}`
			other := `{"value":"other"}`
			if operation == "supplied-duplicates" {
				fixture.deny(t, scim.Request{Operation: scim.UserCreate, Body: []byte(reviewUser("primary-nested", `{"records":[`+omitted+`,`+explicit+`]}`))}, 400, "invalidValue")
				return
			}
			created := fixture.call(t, scim.UserCreate, "", "", reviewUser("primary-nested", `{"records":[`+omitted+`,`+other+`]}`))
			id := object(t, created.Body)["id"].(string)
			values := explicit
			if operation == "replace" {
				values += `,` + other
			}
			now = now.Add(time.Second)
			updated := fixture.call(t, scim.UserPatch, id, created.ETag, patchBody(`{"op":"`+operation+`","path":"`+extensionURN+`:records","value":[`+values+`]}`))
			if updated.ETag != created.ETag || string(updated.Body) != string(created.Body) {
				t.Fatal("nested actual-element comparison lost its primary default or changed the stored representation")
			}
			if read := fixture.call(t, scim.UserGet, id, "", ""); read.ETag != created.ETag || string(read.Body) != string(created.Body) {
				t.Fatal("nested comparison view escaped into persisted data")
			}
		})
	}
}

func TestUsersReviewF1PrimarySetTrueAndFalseRemainDistinct(t *testing.T) {
	for _, pair := range []struct{ name, first, second string }{
		{"false-before-true", "false", "true"},
		{"true-before-false", "true", "false"},
	} {
		for _, operation := range []scim.Operation{scim.UserCreate, scim.UserPatch} {
			t.Run(pair.name+"/"+string(operation), func(t *testing.T) {
				now := fixtureNow
				fixture := configuredProtocolFixture(t, func(c *scim.Config) { c.Now = func() time.Time { return now } })
				first := `{"value":"a@example.test","primary":` + pair.first + `}`
				second := `{"value":"a@example.test","primary":` + pair.second + `}`
				response := scim.Response{}
				if operation == scim.UserCreate {
					response = fixture.call(t, scim.UserCreate, "", "", userBody("primary-distinct", `,"emails":[`+first+`,`+second+`]`))
				} else {
					created := fixture.call(t, scim.UserCreate, "", "", userBody("primary-distinct", `,"emails":[`+first+`]`))
					id := object(t, created.Body)["id"].(string)
					now = now.Add(time.Second)
					response = fixture.call(t, scim.UserPatch, id, created.ETag, patchBody(`{"op":"add","path":"emails","value":[`+second+`]}`))
					if response.ETag == created.ETag || object(t, response.Body)["meta"].(map[string]any)["lastModified"] == object(t, created.Body)["meta"].(map[string]any)["lastModified"] {
						t.Fatal("distinct true/false member was incorrectly treated as a no-op")
					}
				}
				emails := object(t, response.Body)["emails"].([]any)
				if len(emails) != 2 || emails[0].(map[string]any)["primary"] != (pair.first == "true") || emails[1].(map[string]any)["primary"] != (pair.second == "true") {
					t.Fatalf("true/false primary members were collapsed or reassigned incorrectly: %s", response.Body)
				}
			})
		}
	}
}

func TestUsersReviewF1PrimarySetDoesNotInventMissingElements(t *testing.T) {
	for _, collection := range []struct{ name, suffix string }{
		{"absent", ""},
		{"null", `,"emails":null`},
		{"empty", `,"emails":[]`},
	} {
		t.Run(collection.name, func(t *testing.T) {
			now := fixtureNow
			fixture := configuredProtocolFixture(t, func(c *scim.Config) { c.Now = func() time.Time { return now } })
			created := fixture.call(t, scim.UserCreate, "", "", userBody("primary-no-element", collection.suffix))
			id := object(t, created.Body)["id"].(string)
			for _, filter := range []string{`emails.primary eq false`, `emails[primary eq false]`} {
				if response := fixture.execute(t, followupQueryRequest(t, scim.UserList, filter)); object(t, response.Body)["totalResults"] != float64(0) {
					t.Fatal("effective default invented an element in a missing/null/empty collection")
				}
			}
			now = now.Add(time.Second)
			updated := fixture.call(t, scim.UserPatch, id, created.ETag, patchBody(`{"op":"add","path":"emails","value":[{"value":"a@example.test","primary":false}]}`))
			emails := object(t, updated.Body)["emails"].([]any)
			if updated.ETag == created.ETag || len(emails) != 1 || emails[0].(map[string]any)["primary"] != false {
				t.Fatal("adding the first actual false-primary element was incorrectly treated as a no-op")
			}
		})
	}
}

func TestUsersReviewF1PrimarySetOtherBooleanMembersRemainDistinct(t *testing.T) {
	for _, field := range []string{"flag", "nested-singular-primary"} {
		for _, operation := range []scim.Operation{scim.UserCreate, scim.UserPatch} {
			t.Run(field+"/"+string(operation), func(t *testing.T) {
				items := reviewAttribute("items", "complex")
				items.MultiValued = true
				items.SubAttributes = []scim.Attribute{reviewAttribute("value", "string"), reviewAttribute("flag", "boolean")}
				first, second := `{"value":"same"}`, `{"value":"same","flag":false}`
				if field == "nested-singular-primary" {
					parent := reviewAttribute("parent", "complex")
					parent.SubAttributes = []scim.Attribute{reviewAttribute("primary", "boolean")}
					items.SubAttributes = []scim.Attribute{reviewAttribute("value", "string"), parent}
					first, second = `{"value":"same","parent":{}}`, `{"value":"same","parent":{"primary":false}}`
				}
				fixture := configuredProtocolFixture(t, reviewSchema(items))
				body := reviewUser("primary-unrelated-set", `{"items":[`+first+`,`+second+`]}`)
				var response scim.Response
				if operation == scim.UserCreate {
					response = fixture.call(t, operation, "", "", body)
				} else {
					created := fixture.call(t, scim.UserCreate, "", "", reviewUser("primary-unrelated-set", `{"items":[`+first+`]}`))
					id := object(t, created.Body)["id"].(string)
					response = fixture.call(t, operation, id, created.ETag, patchBody(`{"op":"add","path":"`+extensionURN+`:items","value":[`+second+`]}`))
					if response.ETag == created.ETag {
						t.Fatal("unrelated omitted/false Boolean member was incorrectly treated as a no-op")
					}
				}
				members := object(t, response.Body)[extensionURN].(map[string]any)["items"].([]any)
				if len(members) != 2 {
					t.Fatal("unrelated omitted/false Boolean members were collapsed")
				}
				if field == "flag" {
					if _, exists := members[0].(map[string]any)["flag"]; exists || members[1].(map[string]any)["flag"] != false {
						t.Fatal("unrelated Boolean representation was defaulted or lost")
					}
				} else {
					parent, _ := members[0].(map[string]any)["parent"].(map[string]any)
					if _, exists := parent["primary"]; exists || members[1].(map[string]any)["parent"].(map[string]any)["primary"] != false {
						t.Fatal("outer multi-valued context leaked into a singular nested primary")
					}
				}
			})
		}
	}
}

func TestUsersReviewF1PrimarySetSingularBooleansDoNotDefault(t *testing.T) {
	for _, target := range []string{"active", "singular-primary"} {
		t.Run(target, func(t *testing.T) {
			now := fixtureNow
			parent := reviewAttribute("parent", "complex")
			parent.SubAttributes = []scim.Attribute{reviewAttribute("primary", "boolean")}
			fixture := configuredProtocolFixture(t, func(c *scim.Config) {
				reviewSchema(parent)(c)
				c.Now = func() time.Time { return now }
			})
			created := fixture.call(t, scim.UserCreate, "", "", reviewUser("primary-singular-control", `{"parent":{}}`))
			id := object(t, created.Body)["id"].(string)
			path := "active"
			if target == "singular-primary" {
				path = extensionURN + ":parent.primary"
			}
			previous := created
			for _, value := range []string{"false", "null"} {
				now = now.Add(time.Second)
				updated := fixture.call(t, scim.UserPatch, id, previous.ETag, patchBody(`{"op":"replace","path":"`+path+`","value":`+value+`}`))
				if updated.ETag == previous.ETag || object(t, updated.Body)["meta"].(map[string]any)["lastModified"] == object(t, previous.Body)["meta"].(map[string]any)["lastModified"] {
					t.Fatal("singular absent/false/null transition was incorrectly treated as a no-op")
				}
				doc := object(t, updated.Body)
				var actual any
				var exists bool
				if target == "active" {
					actual, exists = doc["active"]
				} else {
					extension, _ := doc[extensionURN].(map[string]any)
					storedParent, _ := extension["parent"].(map[string]any)
					actual, exists = storedParent["primary"]
				}
				if value == "false" && (!exists || actual != false) || value == "null" && exists {
					t.Fatal("singular Boolean supplied false or explicit unassignment was not preserved")
				}
				previous = updated
			}
		})
	}
}
