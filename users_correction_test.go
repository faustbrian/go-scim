package scim_test

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"runtime"
	"strings"
	"testing"

	scim "github.com/faustbrian/go-scim"
)

func TestUsersCorrectionF1NumericOperandsValidatedBeforeEquality(t *testing.T) {
	for _, kind := range []string{"decimal", "integer"} {
		for _, operand := range []struct{ name, value string }{
			{"positive-exponent", "0e309"},
			{"negative-exponent", "0e-309"},
			{"representation-length", "0." + strings.Repeat("0", 127)},
			{"wrong-type", "false"},
		} {
			for _, target := range []string{"scalar", "nested-scalar", "set", "nested-set"} {
				t.Run(kind+"/"+operand.name+"/"+target, func(t *testing.T) {
					value := reviewAttribute("value", kind)
					attribute := value
					initial, incoming, path := `{"value":0}`, operand.value, extensionURN+":value"
					switch target {
					case "nested-scalar":
						attribute = reviewAttribute("parent", "complex")
						attribute.SubAttributes = []scim.Attribute{value}
						initial, incoming, path = `{"parent":{"value":0}}`, `{"Value":`+operand.value+`}`, extensionURN+":parent"
					case "set":
						attribute.MultiValued = true
						initial, incoming = `{"value":[0]}`, `[`+operand.value+`,1]`
					case "nested-set":
						attribute = reviewAttribute("items", "complex")
						attribute.MultiValued = true
						attribute.SubAttributes = []scim.Attribute{value}
						initial, incoming, path = `{"items":[{"value":0}]}`, `[{"Value":`+operand.value+`},{"value":1}]`, extensionURN+":items"
					}
					f := configuredProtocolFixture(t, reviewSchema(attribute))
					created := f.call(t, scim.UserCreate, "", "", reviewUser("numeric-admission", initial))
					id := object(t, created.Body)["id"].(string)
					calls := f.mapper.calls
					f.deny(t, scim.Request{Operation: scim.UserPatch, ResourceID: id, IfMatch: created.ETag, Body: []byte(patchBody(`{"op":"add","path":"` + path + `","value":` + incoming + `}`))}, 400, "invalidValue")
					if f.mapper.calls != calls {
						t.Fatal("invalid numeric operand reached Mapper after equality or set-key comparison")
					}
					after := f.call(t, scim.UserGet, id, "", "")
					if after.ETag != created.ETag || string(after.Body) != string(created.Body) {
						t.Fatal("invalid numeric operand changed the resource")
					}
				})
			}
		}
	}
}

func TestUsersCorrectionF1NumericSetKeysBoundAllocation(t *testing.T) {
	for _, nested := range []bool{false, true} {
		t.Run(fmt.Sprintf("nested=%t", nested), func(t *testing.T) {
			value := reviewAttribute("values", "decimal")
			value.MultiValued = true
			initial, path := `{"values":[0]}`, extensionURN+":values"
			if nested {
				value = reviewAttribute("items", "complex")
				value.MultiValued = true
				value.SubAttributes = []scim.Attribute{reviewAttribute("value", "decimal")}
				initial, path = `{"items":[{"value":0}]}`, extensionURN+":items"
			}
			f := configuredProtocolFixture(t, reviewSchema(value))
			created := f.call(t, scim.UserCreate, "", "", reviewUser("numeric-key-budget", initial))
			id := object(t, created.Body)["id"].(string)
			// Twenty-four small tokens exercise key amplification without the
			// original million-scale exponents or gigabyte-sized retained keys.
			values := make([]string, 24)
			for i := range values {
				values[i] = fmt.Sprintf("1e%d", 32768+i)
				if nested {
					values[i] = `{"value":` + values[i] + `}`
				}
			}
			request := freshnessRequest(scim.UserPatch, id, created.ETag)
			request.Body = []byte(patchBody(`{"op":"add","path":"` + path + `","value":[` + strings.Join(values, ",") + `]}`))
			if len(request.Body) > 1024 {
				t.Fatal("hostile numeric fixture must remain below one KiB")
			}
			calls := f.mapper.calls
			var before, after runtime.MemStats
			runtime.ReadMemStats(&before)
			response, err := f.service.Execute(context.Background(), request)
			runtime.ReadMemStats(&after)
			assertProtocolError(t, response, err, 400, "invalidValue")
			// Admission should cost well below this generous two-MiB ceiling for
			// a sub-KiB request; expanding decimal keys violates that boundary.
			if allocated := after.TotalAlloc - before.TotalAlloc; allocated > 2<<20 {
				t.Errorf("invalid numeric set allocated %d bytes before rejection; budget is %d", allocated, 2<<20)
			}
			if f.mapper.calls != calls || f.call(t, scim.UserGet, id, "", "").ETag != created.ETag {
				t.Fatal("invalid numeric set crossed mapping or changed the resource")
			}
		})
	}
}

func TestUsersCorrectionF2BooleanAddRejectsWrongType(t *testing.T) {
	for _, target := range []string{"path", "pathless", "nested"} {
		t.Run(target, func(t *testing.T) {
			flag := reviewAttribute("flag", "boolean")
			parent := reviewAttribute("parent", "complex")
			parent.SubAttributes = []scim.Attribute{flag}
			f := configuredProtocolFixture(t, reviewSchema(parent))
			created := f.call(t, scim.UserCreate, "", "", `{"schemas":["`+userURN+`","`+extensionURN+`"],"userName":"boolean-add","active":false,"`+extensionURN+`":{"parent":{"flag":false}}}`)
			id := object(t, created.Body)["id"].(string)
			operation := `{"op":"add","path":"active","value":"not-a-boolean"}`
			if target == "pathless" {
				operation = `{"op":"add","value":{"active":"not-a-boolean"}}`
			} else if target == "nested" {
				operation = `{"op":"add","path":"` + extensionURN + `:parent","value":{"Flag":"not-a-boolean"}}`
			}
			calls := f.mapper.calls
			f.deny(t, scim.Request{Operation: scim.UserPatch, ResourceID: id, IfMatch: created.ETag, Body: []byte(patchBody(operation))}, 400, "invalidValue")
			if f.mapper.calls != calls || f.call(t, scim.UserGet, id, "", "").ETag != created.ETag {
				t.Fatal("wrong Boolean type crossed mapping or changed the resource")
			}
		})
	}
}

func TestUsersCorrectionF2ImmutableComplexAliasesAndPartialPatch(t *testing.T) {
	for _, verb := range []string{"add", "replace"} {
		for _, partial := range []bool{false, true} {
			for _, pathless := range []bool{false, true} {
				t.Run(fmt.Sprintf("%s/partial=%t/pathless=%t", verb, partial, pathless), func(t *testing.T) {
					parent := reviewAttribute("parent", "complex")
					parent.Mutability = "immutable"
					code := reviewAttribute("code", "string")
					code.CaseExact = true
					parent.SubAttributes = []scim.Attribute{code, reviewAttribute("note", "string")}
					f := configuredProtocolFixture(t, reviewSchema(parent))
					initial := `{"parent":{"code":"A"}}`
					if partial {
						initial = `{"parent":{"code":"A","note":"keep"}}`
					}
					created := f.call(t, scim.UserCreate, "", "", reviewUser("immutable-alias", initial))
					id := object(t, created.Body)["id"].(string)
					operation := `{"op":"` + verb + `","path":"` + extensionURN + `:parent","value":{"Code":"A"}}`
					if pathless {
						operation = `{"op":"` + verb + `","value":{"` + extensionURN + `":{"parent":{"Code":"A"}}}}`
					}
					updated := f.call(t, scim.UserPatch, id, created.ETag, patchBody(operation))
					if updated.ETag != created.ETag || string(updated.Body) != string(created.Body) {
						t.Fatal("equivalent immutable complex PATCH did not retain canonical values and unspecified siblings")
					}
					f.deny(t, scim.Request{Operation: scim.UserPatch, ResourceID: id, IfMatch: updated.ETag, Body: []byte(patchBody(`{"op":"replace","path":"` + extensionURN + `:parent","value":{"Code":"B"}}`))}, 400, "mutability")
				})
			}
		}
	}
}

func TestUsersCorrectionF3ImmutableComplexRetainsReadOnlyDescendant(t *testing.T) {
	for _, operation := range []scim.Operation{scim.UserPatch, scim.UserReplace} {
		t.Run(string(operation), func(t *testing.T) {
			parent := reviewAttribute("parent", "complex")
			parent.Mutability = "immutable"
			origin := reviewAttribute("origin", "string")
			origin.Mutability = "readOnly"
			parent.SubAttributes = []scim.Attribute{reviewAttribute("code", "string"), origin}
			f := configuredProtocolFixture(t, reviewSchema(parent))
			created := f.call(t, scim.UserCreate, "", "", reviewUser("immutable-server-child", `{"parent":{"code":"A"}}`))
			id := object(t, created.Body)["id"].(string)
			for key, resource := range f.store.resources {
				resource.Attributes[extensionURN].(map[string]any)["parent"].(map[string]any)["origin"] = "trusted-source"
				f.store.resources[key] = resource
			}
			body := patchBody(`{"op":"replace","path":"displayName","value":"changed"}`)
			if operation == scim.UserReplace {
				body = `{"schemas":["` + userURN + `","` + extensionURN + `"],"userName":"immutable-server-child","displayName":"changed","` + extensionURN + `":{"parent":{"code":"A"}}}`
			}
			updated := f.call(t, operation, id, created.ETag, body)
			doc := object(t, updated.Body)
			stored := doc[extensionURN].(map[string]any)["parent"].(map[string]any)
			if doc["displayName"] != "changed" || stored["code"] != "A" || stored["origin"] != "trusted-source" {
				t.Fatalf("unrelated write changed immutable server-owned representation: %s", updated.Body)
			}
			if read := f.call(t, scim.UserGet, id, "", ""); string(read.Body) != string(updated.Body) {
				t.Fatal("read-only descendant was not preserved in stored state")
			}
		})
	}
}

func TestUsersCorrectionF3ClientsCannotEchoReadOnlyDescendant(t *testing.T) {
	parent := reviewAttribute("parent", "complex")
	parent.Mutability = "immutable"
	origin := reviewAttribute("origin", "string")
	origin.Mutability = "readOnly"
	parent.SubAttributes = []scim.Attribute{reviewAttribute("code", "string"), origin}
	f := configuredProtocolFixture(t, reviewSchema(parent))
	created := f.call(t, scim.UserCreate, "", "", reviewUser("readonly-echo", `{"parent":{"code":"A"}}`))
	id := object(t, created.Body)["id"].(string)
	for key, resource := range f.store.resources {
		resource.Attributes[extensionURN].(map[string]any)["parent"].(map[string]any)["origin"] = "trusted-source"
		f.store.resources[key] = resource
	}
	for _, operation := range []scim.Operation{scim.UserPatch, scim.UserReplace} {
		body := reviewUser("readonly-echo", `{"parent":{"code":"A","origin":"trusted-source"}}`)
		if operation == scim.UserPatch {
			body = patchBody(`{"op":"add","path":"` + extensionURN + `:parent","value":{"code":"A","origin":"trusted-source"}}`)
		}
		calls, prepares := f.mapper.calls, f.store.prepares
		f.deny(t, scim.Request{Operation: operation, ResourceID: id, IfMatch: created.ETag, Body: []byte(body)}, 400, "mutability")
		if f.mapper.calls != calls || f.store.prepares != prepares || f.call(t, scim.UserGet, id, "", "").ETag != created.ETag {
			t.Fatal("client-supplied read-only descendant crossed admission")
		}
	}
}

func TestUsersCorrectionF4SuppliedRequestAttributesOnWriteAndReplay(t *testing.T) {
	for _, target := range []string{"create", "replace", "patch-path", "patch-pathless", "patch-parent", "patch-unrelated"} {
		t.Run(target, func(t *testing.T) {
			note := reviewAttribute("note", "string")
			note.Returned = "request"
			parent := reviewAttribute("parent", "complex")
			parent.SubAttributes = []scim.Attribute{note, reviewAttribute("label", "string")}
			f := configuredProtocolFixture(t, reviewSchema(note, parent))
			request := scim.Request{Operation: scim.UserCreate, IdempotencyKey: "write-supplied-context", Body: []byte(reviewUser("request-returned", `{"note":"supplied","parent":{"note":"nested-supplied","label":"keep"}}`))}
			if target != "create" {
				created := f.call(t, scim.UserCreate, "", "", reviewUser("request-returned", `{"note":"before","parent":{"note":"nested-before","label":"keep"}}`))
				request.ResourceID, request.IfMatch = object(t, created.Body)["id"].(string), created.ETag
				request.Operation = scim.UserReplace
				if strings.HasPrefix(target, "patch-") {
					request.Operation = scim.UserPatch
					operations := `{"op":"replace","path":"` + extensionURN + `:note","value":"supplied"},{"op":"replace","path":"` + extensionURN + `:parent.note","value":"nested-supplied"}`
					if target == "patch-pathless" {
						operations = `{"op":"replace","value":{"` + extensionURN + `":{"note":"supplied","parent":{"note":"nested-supplied"}}}}`
					} else if target == "patch-parent" {
						operations = `{"op":"replace","path":"` + extensionURN + `:note","value":"supplied"},{"op":"replace","path":"` + extensionURN + `:parent","value":{"note":"nested-supplied"}}`
					} else if target == "patch-unrelated" {
						operations = `{"op":"replace","path":"displayName","value":"changed"}`
					}
					request.Body = []byte(patchBody(operations))
				}
			}
			written := f.execute(t, request)
			doc := object(t, written.Body)
			id := doc["id"].(string)
			extension := doc[extensionURN].(map[string]any)
			nested := extension["parent"].(map[string]any)
			if target == "patch-unrelated" {
				if extension["note"] != nil || nested["note"] != nil {
					t.Error("unrelated PATCH disclosed unsupplied request-only attributes")
				}
			} else if extension["note"] != "supplied" || nested["note"] != "nested-supplied" {
				t.Errorf("write omitted supplied request-only attributes: %s", written.Body)
			}
			if nested["label"] != "keep" {
				t.Error("partial complex PATCH lost an unspecified sibling")
			}
			if replay := f.execute(t, request); string(replay.Body) != string(written.Body) || replay.ETag != written.ETag || replay.Status != written.Status {
				t.Error("replay lost the write's supplied-attribute context")
			}
			ordinary := object(t, f.call(t, scim.UserGet, id, "", "").Body)[extensionURN].(map[string]any)
			if ordinary["note"] != nil || ordinary["parent"].(map[string]any)["note"] != nil {
				t.Error("ordinary GET disclosed unrequested attributes after a write or replay")
			}
			requested := f.execute(t, scim.Request{Operation: scim.UserGet, ResourceID: id, Query: scim.Query{Attributes: extensionURN + ":note," + extensionURN + ":parent.note"}})
			selected := object(t, requested.Body)[extensionURN].(map[string]any)
			want, nestedWant := "supplied", "nested-supplied"
			if target == "patch-unrelated" {
				want, nestedWant = "before", "nested-before"
			}
			if selected["note"] != want || selected["parent"].(map[string]any)["note"] != nestedWant {
				t.Error("explicit GET projection did not return the retained request-only values")
			}
		})
	}
}

func TestUsersCorrectionF5AlwaysDescendantsKeepMinimumAncestors(t *testing.T) {
	for _, shape := range []string{"singular", "multi-valued", "nested"} {
		for _, projection := range []string{"include-other", "exclude-parent", "exclude-child"} {
			t.Run(shape+"/"+projection, func(t *testing.T) {
				code := reviewAttribute("code", "string")
				code.Returned = "always"
				parent := reviewAttribute("parent", "complex")
				parent.SubAttributes = []scim.Attribute{code, reviewAttribute("label", "string")}
				initial, leafPath := `{"parent":{"code":"A","label":"ordinary"}}`, ":parent.code"
				if shape == "multi-valued" {
					parent.MultiValued = true
					initial = `{"parent":[{"code":"A","label":"ordinary"},{"code":"B","label":"ordinary"}]}`
				} else if shape == "nested" {
					inner := parent
					inner.Name = "inner"
					parent.SubAttributes = []scim.Attribute{inner, reviewAttribute("label", "string")}
					initial, leafPath = `{"parent":{"inner":{"code":"A","label":"ordinary"},"label":"ordinary"}}`, ":parent.inner.code"
				}
				f := configuredProtocolFixture(t, reviewSchema(parent))
				created := f.call(t, scim.UserCreate, "", "", reviewUser("always-descendant", initial))
				id := object(t, created.Body)["id"].(string)
				query := scim.Query{Attributes: "userName"}
				if projection == "exclude-parent" {
					query = scim.Query{ExcludedAttributes: extensionURN + ":parent"}
				} else if projection == "exclude-child" {
					query = scim.Query{ExcludedAttributes: extensionURN + leafPath}
				}
				for _, operation := range []scim.Operation{scim.UserGet, scim.UserList} {
					response := f.execute(t, scim.Request{Operation: operation, ResourceID: id, Query: query})
					doc := object(t, response.Body)
					if operation == scim.UserList {
						doc = doc["Resources"].([]any)[0].(map[string]any)
					}
					extension, ok := doc[extensionURN].(map[string]any)
					if !ok {
						t.Errorf("%s dropped extension ancestor of returned=always child", operation)
						continue
					}
					var elements []any
					if shape == "multi-valued" {
						elements, ok = extension["parent"].([]any)
					} else {
						var obj map[string]any
						obj, ok = extension["parent"].(map[string]any)
						if shape == "nested" {
							if projection != "exclude-child" && obj["label"] != nil {
								t.Error("minimum outer ancestor retained an unselected sibling")
							}
							obj, ok = obj["inner"].(map[string]any)
						}
						elements = []any{obj}
					}
					wantCount := 1
					if shape == "multi-valued" {
						wantCount = 2
					}
					if !ok || len(elements) != wantCount {
						t.Errorf("%s lost minimum complex ancestor or multi-valued records", operation)
						continue
					}
					for i, element := range elements {
						obj, ok := element.(map[string]any)
						if !ok || obj["code"] != []string{"A", "B"}[i] {
							t.Errorf("%s dropped returned=always child at index %d", operation, i)
						}
						if projection != "exclude-child" && obj["label"] != nil {
							t.Error("minimum ancestor retained an unselected ordinary sibling")
						}
					}
				}
			})
		}
	}
}

func TestUsersCorrectionF6BinaryOrderingIsInvalidFilter(t *testing.T) {
	value := reviewAttribute("value", "binary")
	value.CaseExact = true
	for _, operator := range []string{"gt", "ge", "lt", "le"} {
		t.Run(operator, func(t *testing.T) {
			f := configuredProtocolFixture(t, reviewSchema(value))
			f.call(t, scim.UserCreate, "", "", reviewUser("binary-filter", `{"value":"YQ=="}`))
			filter := extensionURN + `:value ` + operator + ` "YQ=="`
			for _, operation := range []scim.Operation{scim.UserList, scim.UserSearch, scim.Search} {
				request := scim.Request{Operation: operation, Query: scim.Query{Filter: filter}}
				if operation != scim.UserList {
					body, err := json.Marshal(map[string]any{"schemas": []string{searchURN}, "filter": filter})
					if err != nil {
						t.Fatal(err)
					}
					request.Body = body
				}
				f.deny(t, request, 400, "invalidFilter")
			}
		})
	}
}

func TestUsersCorrectionF5RequestOnlyAncestorDoesNotExposeDefaultSiblings(t *testing.T) {
	code := reviewAttribute("code", "string")
	code.Returned = "always"
	parent := reviewAttribute("parent", "complex")
	parent.Returned = "request"
	parent.SubAttributes = []scim.Attribute{code, reviewAttribute("label", "string")}
	f := configuredProtocolFixture(t, reviewSchema(parent))
	created := f.call(t, scim.UserCreate, "", "", reviewUser("request-ancestor", `{"parent":{"code":"A","label":"only-with-parent"}}`))
	id := object(t, created.Body)["id"].(string)
	read := f.call(t, scim.UserGet, id, "", "")
	extension, ok := object(t, read.Body)[extensionURN].(map[string]any)
	if !ok {
		t.Fatal("GET omitted the ancestor of an always-returned child")
	}
	returned, ok := extension["parent"].(map[string]any)
	if !ok || returned["code"] != "A" || returned["label"] != nil {
		t.Fatalf("GET did not restrict the request-only ancestor to its always-returned child: %s", read.Body)
	}
	requested := f.execute(t, scim.Request{Operation: scim.UserGet, ResourceID: id, Query: scim.Query{Attributes: extensionURN + ":parent"}})
	if object(t, requested.Body)[extensionURN].(map[string]any)["parent"].(map[string]any)["label"] != "only-with-parent" {
		t.Fatal("explicitly requested parent lost its default-returned child")
	}
}

func TestUsersCorrectionF6BinaryEqualityPresenceAndRepresentationRemainSupported(t *testing.T) {
	value := reviewAttribute("value", "binary")
	value.CaseExact = true
	f := configuredProtocolFixture(t, reviewSchema(value))
	created := f.call(t, scim.UserCreate, "", "", reviewUser("binary-supported", `{"value":"YQ=="}`))
	if object(t, created.Body)[extensionURN].(map[string]any)["value"] != "YQ==" {
		t.Fatal("binary representation was rewritten")
	}
	for _, comparison := range []struct {
		expression string
		count      float64
	}{{`eq "YQ=="`, 1}, {`ne "Yg=="`, 1}, {`eq "Yg=="`, 0}, {`pr`, 1}} {
		response := f.execute(t, scim.Request{Operation: scim.UserList, Query: scim.Query{Filter: extensionURN + ":value " + comparison.expression}})
		if object(t, response.Body)["totalResults"] != comparison.count {
			t.Errorf("binary comparison %s changed semantics", comparison.expression)
		}
	}
}

func TestUsersCorrectionF7ExactDecimalBoundariesAcrossResourceAndFilter(t *testing.T) {
	for _, number := range []struct{ value, equivalent string }{
		{"9e308", "90e307"},
		{"-9e308", "-90e307"},
		{"9e-308", "9.0e-308"},
		{"-9e-308", "-9.0e-308"},
		{"0." + strings.Repeat("0", 126), "0"},
	} {
		t.Run(number.value, func(t *testing.T) {
			value := reviewAttribute("value", "decimal")
			f := configuredProtocolFixture(t, reviewSchema(value))
			created := f.call(t, scim.UserCreate, "", "", reviewUser("exact-decimal", `{"value":`+number.value+`}`))
			// UseNumber is essential: the contract is exact bounded JSON, not
			// the smaller finite float64 domain used by generic JSON helpers.
			var doc map[string]any
			decoder := json.NewDecoder(strings.NewReader(string(created.Body)))
			decoder.UseNumber()
			if err := decoder.Decode(&doc); err != nil {
				t.Fatal(err)
			}
			if doc[extensionURN].(map[string]any)["value"] != json.Number(number.value) {
				t.Fatal("decimal representation lost precision or range")
			}
			id := doc["id"].(string)
			if read := f.call(t, scim.UserGet, id, "", ""); string(read.Body) != string(created.Body) {
				t.Error("GET changed the exact decimal representation")
			}
			patched := f.call(t, scim.UserPatch, id, created.ETag, patchBody(`{"op":"add","path":"`+extensionURN+`:value","value":`+number.equivalent+`}`))
			if patched.ETag != created.ETag {
				t.Error("equal bounded decimal changed the resource version")
			}
			replaced := f.call(t, scim.UserReplace, id, patched.ETag, reviewUser("exact-decimal", `{"value":`+number.value+`}`))
			if replaced.ETag == "" {
				t.Fatal("bounded decimal PUT did not expose its version")
			}
			for _, comparison := range []struct {
				operator string
				count    float64
			}{{"eq", 1}, {"ne", 0}, {"gt", 0}, {"ge", 1}, {"lt", 0}, {"le", 1}} {
				filter := extensionURN + ":value " + comparison.operator + " " + number.equivalent
				response := f.execute(t, scim.Request{Operation: scim.UserList, Query: scim.Query{Filter: filter, Attributes: "userName"}})
				if object(t, response.Body)["totalResults"] != comparison.count {
					t.Errorf("resource/filter exact-number domains diverged for %s", filter)
				}
			}
		})
	}
}

func TestUsersCorrectionF7RejectsOutsideDecimalDomain(t *testing.T) {
	for _, value := range []string{"9e309", "-9e309", "9e-309", "-9e-309"} {
		t.Run(value, func(t *testing.T) {
			f := configuredProtocolFixture(t, reviewSchema(reviewAttribute("value", "decimal")))
			f.deny(t, scim.Request{Operation: scim.UserCreate, Body: []byte(reviewUser("outside-domain", `{"value":`+value+`}`))}, 400, "invalidValue")
			f.deny(t, scim.Request{Operation: scim.UserList, Query: scim.Query{Filter: extensionURN + ":value eq " + value}}, 400, "invalidFilter")
		})
	}
}

func TestUsersCorrectionProjectionPathCountBeforeAllocation(t *testing.T) {
	for _, excluded := range []bool{false, true} {
		t.Run(fmt.Sprintf("excluded=%t", excluded), func(t *testing.T) {
			f := newProtocolFixture(t)
			request := freshnessRequest(scim.UserList, "", "")
			// A 64-KiB raw list is within BodyBytes, but its separator count is
			// far beyond 1,000 paths. It must not materialize all split slots.
			if excluded {
				request.Query.ExcludedAttributes = strings.Repeat(",", 65536)
			} else {
				request.Query.Attributes = strings.Repeat(",", 65536)
			}
			var before, after runtime.MemStats
			runtime.ReadMemStats(&before)
			response, err := f.service.Execute(context.Background(), request)
			runtime.ReadMemStats(&after)
			assertProtocolError(t, response, err, 400, "invalidValue")
			if allocated := after.TotalAlloc - before.TotalAlloc; allocated > 256<<10 {
				t.Errorf("over-limit projection allocated %d bytes before rejection; budget is %d", allocated, 256<<10)
			}
		})
	}
}

func TestUsersCorrectionLogicalFilterRequiresSpaces(t *testing.T) {
	for _, filter := range []string{
		`userName eq "Alice"or userName eq "Bob"`,
		`userName eq "Alice"and active eq true`,
		`(userName eq "Alice")or userName eq "Bob"`,
		`userName eq "Alice" or(userName eq "Bob")`,
		`emails[type eq "work"]and active eq true`,
		`emails[type eq "work"and value co "example.test"]`,
	} {
		t.Run(filter, func(t *testing.T) {
			f := newProtocolFixture(t)
			f.deny(t, scim.Request{Operation: scim.UserList, Query: scim.Query{Filter: filter}}, 400, "invalidFilter")
		})
	}
}

func TestUsersCorrectionLogicalFilterSpacedGrammarRemainsSupported(t *testing.T) {
	f := newProtocolFixture(t)
	f.call(t, scim.UserCreate, "", "", userBody("Alice", `,"active":true,"emails":[{"type":"work","value":"alice@example.test"}]`))
	for _, filter := range []string{
		`userName eq "Alice" or userName eq "Bob"`,
		`userName eq "Alice" and active eq true`,
		`(userName eq "Alice") or userName eq "Bob"`,
		`userName eq "Alice" or (userName eq "Bob")`,
		`emails[type eq "work"] and active eq true`,
		`emails[type eq "work" and value co "example.test"]`,
	} {
		response := f.execute(t, scim.Request{Operation: scim.UserList, Query: scim.Query{Filter: filter}})
		if object(t, response.Body)["totalResults"] != float64(1) {
			t.Errorf("spaced filter lost its match: %s", filter)
		}
	}
}

func FuzzUsersCorrectionOperands(f *testing.F) {
	for _, operation := range []string{
		`{"op":"add","path":"active","value":"not-a-boolean"}`,
		`{"op":"add","path":"` + extensionURN + `:values","value":[0e309,1]}`,
		`{"op":"add","path":"` + extensionURN + `:values","value":[1e32768,1e32769]}`,
		`{"op":"add","path":"` + extensionURN + `:values","value":[9e308,-9e308]}`,
		`{"op":"replace","path":"` + extensionURN + `:parent","value":{"Code":"A"}}`,
		`{"op":"replace","path":"displayName","value":"changed"}`,
		`{"op":"replace","path":"` + extensionURN + `:note","value":"supplied"}`,
		`{"op":"add","path":"emails","value":[{"value":"a@example.test","primary":false}]}`,
		`{"op":"add","path":"emails","value":[{"value":"b@example.test"}]}`,
		`{"op":"replace","path":"emails","value":[{"value":"a@example.test","primary":false},{"value":"b@example.test"}]}`,
		`{"op":"add","path":"emails","value":[{"value":"same@example.test"},{"value":"same@example.test","primary":false}]}`,
		`{"op":"add","path":"emails","value":[{"value":"same@example.test","primary":null},{"value":"same@example.test","primary":false}]}`,
		`{"op":"add","path":"` + extensionURN + `:items","value":[{"value":"c","primary":true}]}`,
		`{"op":"replace","path":"` + extensionURN + `:items[value eq \"a\"].primary","value":true}`,
		`{"op":"add","path":"` + extensionURN + `:items[value eq \"a\"]","value":{"primary":true}}`,
		`{"op":"add","path":"` + extensionURN + `:items","value":[{"value":"a","primary":false}]}`,
		`{"op":"replace","path":"` + extensionURN + `:items","value":[{"value":"a","Primary":true},{"value":"b","PRIMARY":true}]}`,
	} {
		f.Add(patchBody(operation))
	}
	f.Fuzz(func(t *testing.T, body string) {
		if len(body) > 2048 {
			return
		}
		values := reviewAttribute("values", "decimal")
		values.MultiValued = true
		parent := reviewAttribute("parent", "complex")
		parent.Mutability = "immutable"
		origin := reviewAttribute("origin", "string")
		origin.Mutability = "readOnly"
		parent.SubAttributes = []scim.Attribute{reviewAttribute("code", "string"), origin}
		note := reviewAttribute("note", "string")
		note.Returned = "request"
		items := reviewAttribute("items", "complex")
		items.MultiValued = true
		items.SubAttributes = []scim.Attribute{reviewAttribute("value", "string"), reviewAttribute("PRIMARY", "boolean")}
		fixture := configuredProtocolFixture(t, func(c *scim.Config) {
			reviewSchema(values, parent, note, items)(c)
			c.Limits.BodyBytes, c.Limits.ResponseBytes = 2048, 8192
		})
		created := fixture.call(t, scim.UserCreate, "", "", `{"schemas":["`+userURN+`","`+extensionURN+`"],"userName":"operand-fuzz","active":false,"emails":[{"value":"a@example.test"},{"value":"b@example.test","primary":false}],"`+extensionURN+`":{"values":[0],"parent":{"code":"A"},"note":"before","items":[{"value":"a"},{"value":"b","PRIMARY":true}]}}`)
		id := object(t, created.Body)["id"].(string)
		for key, resource := range fixture.store.resources {
			resource.Attributes[extensionURN].(map[string]any)["parent"].(map[string]any)["origin"] = "trusted-source"
			fixture.store.resources[key] = resource
		}
		before := fixture.call(t, scim.UserGet, id, "", "")
		request := freshnessRequest(scim.UserPatch, id, created.ETag)
		request.Body = []byte(body)
		response, err := fixture.service.Execute(context.Background(), request)
		if err != nil {
			var protocol *scim.Error
			if !errors.As(err, &protocol) || protocol.StatusCode() >= 500 || len(response.Body) != 0 {
				t.Fatalf("unexpected bounded operand failure: %v", err)
			}
			after := fixture.call(t, scim.UserGet, id, "", "")
			if after.ETag != before.ETag || string(after.Body) != string(before.Body) {
				t.Fatal("rejected operand changed the stored resource")
			}
			return
		}
		if response.Status != 200 || response.ETag == "" || !json.Valid(response.Body) || len(response.Body) > 8192 {
			t.Fatal("invalid successful bounded operand response")
		}
		stored := fixture.call(t, scim.UserGet, id, "", "")
		var doc map[string]any
		decoder := json.NewDecoder(strings.NewReader(string(stored.Body)))
		decoder.UseNumber()
		if err := decoder.Decode(&doc); err != nil {
			t.Fatal(err)
		}
		immutable := doc[extensionURN].(map[string]any)["parent"].(map[string]any)
		if immutable["code"] != "A" || immutable["origin"] != "trusted-source" {
			t.Fatal("successful PATCH changed immutable or server-owned data")
		}
		for _, resource := range fixture.store.resources {
			extension := resource.Attributes[extensionURN].(map[string]any)
			members, _ := extension["items"].([]any)
			trueMembers := 0
			for _, member := range members {
				obj := member.(map[string]any)
				for key := range obj {
					if strings.EqualFold(key, "primary") && key != "PRIMARY" {
						t.Fatal("successful PATCH persisted a noncanonical primary alias")
					}
				}
				if obj["PRIMARY"] == true {
					trueMembers++
				}
			}
			if trueMembers > 1 {
				t.Fatal("successful PATCH persisted multiple true-primary members")
			}
		}
	})
}

func FuzzUsersCorrectionQuery(f *testing.F) {
	for _, seed := range [][3]string{
		{`userName eq "query-fuzz"or userName eq "other"`, "", ""},
		{`userName eq "Jose\u0301"`, "", ""},
		{`userName eq "aא"`, "", ""},
		{`userName co "·"`, "", ""},
		{`userName sw "l·"`, "", ""},
		{`userName ew "·l"`, "", ""},
		{`userName co ""`, "", ""},
		{`userName sw ""`, "", ""},
		{`userName ew ""`, "", ""},
		{`displayName gt "A"`, "", ""},
		{`displayName le ""`, "", ""},
		{`emails[primary eq false]`, "", ""},
		{`emails[primary eq null]`, "", ""},
		{`emails.primary ne false`, "", ""},
		{extensionURN + `:items[primary eq false]`, "", ""},
		{extensionURN + `:items.PRIMARY eq false`, "", ""},
		{extensionURN + `:items[Primary eq true]`, "", ""},
		{extensionURN + `:binary gt "YQ=="`, "", ""},
		{extensionURN + `:decimal eq 9e308`, "userName", ""},
		{extensionURN + `:decimal eq 9e309`, "", ""},
		{"", "userName", ""},
		{"", "", extensionURN + ":parent"},
		{"", strings.Repeat(",", 1001), ""},
	} {
		f.Add(seed[0], seed[1], seed[2])
	}
	f.Fuzz(func(t *testing.T, filter, attributes, excluded string) {
		if len(filter) > 4096 || len(attributes) > 4096 || len(excluded) > 4096 {
			return
		}
		code := reviewAttribute("code", "string")
		code.Returned = "always"
		parent := reviewAttribute("parent", "complex")
		parent.SubAttributes = []scim.Attribute{code, reviewAttribute("label", "string")}
		binary := reviewAttribute("binary", "binary")
		binary.CaseExact = true
		items := reviewAttribute("items", "complex")
		items.MultiValued = true
		items.SubAttributes = []scim.Attribute{reviewAttribute("value", "string"), reviewAttribute("Primary", "boolean")}
		fixture := configuredProtocolFixture(t, reviewSchema(parent, binary, reviewAttribute("decimal", "decimal"), items))
		fixture.call(t, scim.UserCreate, "", "", `{"schemas":["`+userURN+`","`+extensionURN+`"],"userName":"query-fuzz","displayName":"","emails":[{"value":"a@example.test"}],"`+extensionURN+`":{"parent":{"code":"A","label":"ordinary"},"binary":"YQ==","decimal":9e308,"items":[{"value":"a"},{"value":"b","Primary":true}]}}`)
		request := freshnessRequest(scim.UserList, "", "")
		request.Query = scim.Query{Filter: filter, Attributes: attributes, ExcludedAttributes: excluded}
		response, err := fixture.service.Execute(context.Background(), request)
		if err != nil {
			var protocol *scim.Error
			if !errors.As(err, &protocol) || protocol.StatusCode() != 400 || len(response.Body) != 0 {
				t.Fatalf("unexpected bounded query failure: %v", err)
			}
			return
		}
		if response.Status != 200 || !json.Valid(response.Body) {
			t.Fatal("invalid successful bounded query response")
		}
	})
}
