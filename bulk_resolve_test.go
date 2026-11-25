package scim

import (
	"bytes"
	"reflect"
	"strings"
	"testing"
)

func resolveTestPlan(t *testing.T, operations string, extensions ...Schema) BulkPlan {
	t.Helper()
	body := []byte(`{"schemas":["` + bulkRequestSchema + `"],"Operations":[` + operations + `]}`)
	plan, err := ParseBulk(body, extensions, DefaultBulkPolicy(), DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}
	return plan
}

func resolvedDocument(t *testing.T, operation BulkOperation) map[string]any {
	t.Helper()
	doc, err := decodeObject(operation.Data, DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}
	return doc
}

func TestBulkResolveForwardAndCyclicGroupReferencesPassNormalization(t *testing.T) {
	plan := resolveTestPlan(t, `
		{"method":"POST","bulkId":"a","path":"/Groups","data":{"schemas":["`+groupSchema+`"],"displayName":"bulkId:b","members":[{"value":"bulkId:b","$ref":"/Groups/bulkId:b","type":"Group","display":"bulkId:b"}]}},
		{"method":"POST","bulkId":"b","path":"/Groups","data":{"schemas":["`+groupSchema+`"],"displayName":"B","members":[{"value":"bulkId:a","type":"Group"}]}}`)
	before := plan.CanonicalRequest()
	allocations := map[int]string{0: "Group.A", 1: "Group.B"}
	service := protocolService{profile: groupProfile(), config: Config{BaseURL: "https://example.test/scim/v2", Limits: DefaultLimits()}, groups: groupDependencies{members: DefaultGroupMembers}}
	for index, expectedID := range []string{"Group.B", "Group.A"} {
		operation, err := plan.ResolveOperation(index, allocations)
		if err != nil {
			t.Fatal(err)
		}
		doc := resolvedDocument(t, operation)
		member := doc["members"].([]any)[0].(map[string]any)
		if member["value"] != expectedID {
			t.Fatalf("member value is not the retained resource ID: %#v", member)
		}
		if index == 0 && (member["$ref"] != "Groups/Group.B" || member["display"] != "bulkId:b" || doc["displayName"] != "bulkId:b") {
			t.Fatalf("reference URI or unrelated strings changed: %#v", doc)
		}
		writable, err := service.normalize(doc, nil)
		if err != nil {
			t.Fatalf("resolved member rejected by actual Group normalization: %v", err)
		}
		canonical := writable.Attributes["members"].([]any)[0].(map[string]any)
		if canonical["$ref"] != "https://example.test/scim/v2/Groups/"+expectedID {
			t.Fatalf("reference escaped configured service root: %#v", canonical)
		}
		operation.Data[0] = 'x'
		operation.Dependencies[0] = 99
	}
	allocations[1] = "changed"
	if !bytes.Equal(before, plan.CanonicalRequest()) || plan.Operations()[0].Dependencies[0] != 1 {
		t.Fatal("resolution mutated retained request or dependency graph")
	}
}

func TestBulkResolveLiteralTargetAndSparseOriginalCreateIndexes(t *testing.T) {
	plan := resolveTestPlan(t, `
		{"method":"DELETE","path":"/Users/unrelated"},
		{"method":"PATCH","path":"/Users/bulkId:later","version":"\"v1\"","data":{"schemas":["`+patchSchema+`"],"Operations":[{"op":"replace","path":"displayName","value":"bulkId:later"}]}},
		{"method":"POST","bulkId":"later","path":"/Users","data":{"userName":"later"}}`)
	operation, err := plan.ResolveOperation(1, map[int]string{2: "Exact:ID"})
	if err != nil {
		t.Fatal(err)
	}
	if operation.Target != (BulkTarget{ResourceType: "User", ResourceID: "Exact:ID"}) || operation.Path != "/Users/Exact:ID" || operation.Index != 1 || operation.Version != `"v1"` || !reflect.DeepEqual(operation.Dependencies, []int{2}) {
		t.Fatalf("original child metadata or literal target lost: %#v", operation)
	}
	if !bytes.Contains(operation.Data, []byte(`"value":"bulkId:later"`)) {
		t.Fatal("non-reference PATCH string was substituted")
	}
	if plan.Operations()[1].Target.BulkID != "later" {
		t.Fatal("symbolic source target mutated")
	}
}

func TestBulkResolveSchemaSlotsAndQualifiedPathlessPatch(t *testing.T) {
	extension := Schema{ID: "urn:example:bulk:refs", Name: "Refs", Attributes: []Attribute{
		scalar("supervisor", "reference"), scalar("literal", "string"),
		{Name: "links", Type: "complex", MultiValued: true, Mutability: "readWrite", Returned: "default", Uniqueness: "none", SubAttributes: []Attribute{scalar("target", "reference"), scalar("label", "string")}},
	}}
	for name, data := range map[string]string{
		"document":        `{"schemas":["` + userSchema + `","` + extension.ID + `"],"userName":"follower","` + extension.ID + `":{"supervisor":"bulkId:person","literal":"bulkId:person","links":[{"target":"/Users/bulkId:person","label":"bulkId:person"}]}}`,
		"qualified PATCH": `{"schemas":["` + patchSchema + `"],"Operations":[{"op":"replace","path":"` + extension.ID + `:supervisor","value":"bulkId:person"},{"op":"add","path":"` + extension.ID + `:links","value":[{"target":"bulkId:person","label":"bulkId:person"}]}]}`,
		"pathless PATCH":  `{"schemas":["` + patchSchema + `"],"Operations":[{"op":"replace","value":{"` + extension.ID + `:supervisor":"bulkId:person","` + extension.ID + `":{"links":[{"target":"bulkId:person","label":"bulkId:person"}]}}}]}`,
	} {
		t.Run(name, func(t *testing.T) {
			method := "PATCH"
			if name == "document" {
				method = "PUT"
			}
			plan := resolveTestPlan(t, `{"method":"`+method+`","path":"/Users/follower","data":`+data+`},{"method":"POST","bulkId":"person","path":"/Users","data":{"userName":"person"}}`, extension)
			operation, err := plan.ResolveOperation(0, map[int]string{1: "Person.ID"})
			if err != nil {
				t.Fatal(err)
			}
			if bytes.Count(operation.Data, []byte(`"Users/Person.ID"`)) != 2 || !reflect.DeepEqual(plan.Operations()[0].Dependencies, []int{1}) {
				t.Fatalf("declared references not resolved: %s", operation.Data)
			}
			if !bytes.Contains(operation.Data, []byte(`"label":"bulkId:person"`)) {
				t.Fatal("unrelated string was rewritten")
			}
			if method == "PUT" {
				service := protocolService{profile: userProfile(), config: Config{Extensions: []Schema{extension}}}
				if _, err := service.normalize(resolvedDocument(t, operation), nil); err != nil {
					t.Fatalf("declared reference rejected by schema owner: %v", err)
				}
			} else if _, err := ParsePatch(operation.Data, []Schema{extension}, DefaultLimits()); err != nil {
				t.Fatalf("resolved PATCH rejected: %v", err)
			}
		})
	}
}

func TestBulkResolvePathlessSelectedExtensionReferenceTail(t *testing.T) {
	extension := Schema{ID: "urn:example:refs", Name: "Refs", Attributes: []Attribute{
		{Name: "links", Type: "complex", MultiValued: true, Mutability: "readWrite", Returned: "default", Uniqueness: "none", SubAttributes: []Attribute{scalar("target", "reference"), scalar("label", "string")}},
	}}
	patch := `{"schemas":["` + patchSchema + `"],"Operations":[{"op":"replace","value":{"urn:example:refs:links[label eq \"bulkId:literal\"].target":"bulkId:u"}}]}`
	if _, err := ParsePatch([]byte(patch), []Schema{extension}, DefaultLimits()); err != nil {
		t.Fatalf("selected pathless reference tail is not accepted by the actual PATCH parser: %v", err)
	}
	plan := resolveTestPlan(t, `{"method":"PATCH","path":"/Users/follower","data":`+patch+`},{"method":"POST","bulkId":"u","path":"/Users","data":{"userName":"u"}}`, extension)
	if got := plan.Operations()[0].Dependencies; !reflect.DeepEqual(got, []int{1}) {
		t.Errorf("selected reference tail missing from dependency graph: got %v, want [1]", got)
	}
	operation, err := plan.ResolveOperation(0, map[int]string{1: "User.ID"})
	if err != nil {
		t.Fatal(err)
	}
	doc := resolvedDocument(t, operation)
	values := doc["Operations"].([]any)[0].(map[string]any)["value"].(map[string]any)
	path := `urn:example:refs:links[label eq "bulkId:literal"].target`
	if len(values) != 1 || values[path] != "Users/User.ID" {
		t.Errorf("selected tail not resolved or quoted selector changed: %#v", values)
	}
	if _, err := ParsePatch(operation.Data, []Schema{extension}, DefaultLimits()); err != nil {
		t.Fatalf("resolved selected pathless reference tail rejected by PATCH parser: %v", err)
	}
}

func TestBulkResolveInfersCreatedGroupKindWhenMemberTypeIsOmitted(t *testing.T) {
	for name, typeField := range map[string]string{
		"omitted": "",
		"null":    `,"type":null`,
		"empty":   `,"type":""`,
		"cased":   `,"type":"gRoUp"`,
	} {
		t.Run(name, func(t *testing.T) {
			plan := resolveTestPlan(t, `{"method":"POST","bulkId":"g","path":"/Groups","data":{"schemas":["`+groupSchema+`"],"displayName":"g","members":[{"value":"bulkId:g"`+typeField+`}]}}`)
			operation, err := plan.ResolveOperation(0, map[int]string{0: "Group.ID"})
			if err != nil {
				t.Fatal(err)
			}
			doc := resolvedDocument(t, operation)
			if name == "cased" && doc["members"].([]any)[0].(map[string]any)["type"] != "gRoUp" {
				t.Fatal("valid supplied type casing changed")
			}
			service := protocolService{profile: groupProfile(), config: Config{BaseURL: "https://example.test/scim/v2", Limits: DefaultLimits()}, groups: groupDependencies{members: DefaultGroupMembers}}
			writable, err := service.normalize(doc, nil)
			if err != nil {
				t.Fatal(err)
			}
			member := writable.Attributes["members"].([]any)[0].(map[string]any)
			if member["type"] != "Group" || member["$ref"] != "https://example.test/scim/v2/Groups/Group.ID" {
				t.Fatalf("created Group identity silently became a User: %#v", member)
			}
		})
	}
}

func TestBulkResolveQualifiedGroupPatchUsesIDAndReferenceURI(t *testing.T) {
	for name, patch := range map[string]string{
		"qualified collection": `{"op":"add","path":"` + groupSchema + `:members","value":[{"value":"bulkId:u","$ref":"bulkId:u","type":"User"}]}`,
		"pathless collection":  `{"op":"add","value":{"` + groupSchema + `:members":[{"value":"bulkId:u","$ref":"bulkId:u","type":"User"}]}}`,
		"selected value":       `{"op":"replace","path":"members[value eq \"old\"].value","value":"bulkId:u"}`,
		"selected ref":         `{"op":"replace","path":"members[value eq \"old\"].$ref","value":"bulkId:u"}`,
	} {
		t.Run(name, func(t *testing.T) {
			plan := resolveTestPlan(t, `{"method":"PATCH","path":"/Groups/g","data":{"schemas":["`+patchSchema+`"],"Operations":[`+patch+`]}},{"method":"POST","bulkId":"u","path":"/Users","data":{"userName":"u"}}`)
			operation, err := plan.ResolveOperation(0, map[int]string{1: "User.ID"})
			if err != nil {
				t.Fatal(err)
			}
			if _, err := ParseGroupPatch(operation.Data, nil, DefaultLimits()); err != nil {
				t.Fatal(err)
			}
			want := `"value":"User.ID"`
			if name == "selected ref" {
				want = `"value":"Users/User.ID"`
			}
			if !bytes.Contains(operation.Data, []byte(want)) {
				t.Fatalf("wrong typed PATCH substitution: %s", operation.Data)
			}
		})
	}
}

func TestBulkResolveSnapshotsSchemasAndResolvesComplexAndMultiReferenceSlots(t *testing.T) {
	links := scalar("links", "reference")
	links.MultiValued = true
	complex := scalar("manager", "complex")
	complex.SubAttributes = []Attribute{scalar("target", "reference"), scalar("label", "string")}
	extensions := []Schema{{ID: "urn:example:bulk:shape", Name: "Shape", Attributes: []Attribute{links, complex}}}
	plan := resolveTestPlan(t, `{"method":"PUT","path":"/Users/follower","data":{"schemas":["`+userSchema+`","`+extensions[0].ID+`"],"userName":"follower","`+extensions[0].ID+`":{"links":["bulkId:u","/Groups/bulkId:g"],"manager":{"target":"bulkId:u","label":"bulkId:u"}}}},{"method":"POST","bulkId":"u","path":"/Users","data":{}},{"method":"POST","bulkId":"g","path":"/Groups","data":{}}`, extensions...)
	extensions[0].Attributes[0].Type = "string"
	extensions[0].Attributes[1].SubAttributes[0].Type = "string"
	operation, err := plan.ResolveOperation(0, map[int]string{1: "U %ID", 2: "G"})
	if err == nil {
		t.Fatal("unsafe allocation accepted")
	}
	operation, err = plan.ResolveOperation(0, map[int]string{1: "U%ID", 2: "G"})
	if err != nil {
		t.Fatal(err)
	}
	doc := resolvedDocument(t, operation)["urn:example:bulk:shape"].(map[string]any)
	if !reflect.DeepEqual(doc["links"], []any{"Users/U%25ID", "Groups/G"}) || doc["manager"].(map[string]any)["target"] != "Users/U%25ID" || doc["manager"].(map[string]any)["label"] != "bulkId:u" {
		t.Fatalf("declared slot shape, escaping or source schema custody lost: %#v", doc)
	}
}

func TestBulkResolveMissingLaterAllocationHasNoPartialOutput(t *testing.T) {
	plan := resolveTestPlan(t, `{"method":"POST","bulkId":"g","path":"/Groups","data":{"members":[{"value":"bulkId:a","type":"User"},{"value":"bulkId:b","type":"User"}]}},{"method":"POST","bulkId":"a","path":"/Users","data":{}},{"method":"POST","bulkId":"b","path":"/Users","data":{}}`)
	before := plan.Operations()
	got, err := plan.ResolveOperation(0, map[int]string{1: "A"})
	if err == nil || !reflect.DeepEqual(got, BulkOperation{}) || !reflect.DeepEqual(plan.Operations(), before) {
		t.Fatalf("missing later allocation leaked partial resolution: %#v, %v", got, err)
	}
	got, err = plan.ResolveOperation(0, map[int]string{1: "same", 2: "same"})
	if err == nil || !reflect.DeepEqual(got, BulkOperation{}) {
		t.Fatal("two creates aliased the same retained resource")
	}
}

func TestBulkResolveRejectsExpandedTargetBeyondRetainedPathLimit(t *testing.T) {
	limits := DefaultLimits()
	limits.PathBytes = 64
	body := []byte(`{"schemas":["` + bulkRequestSchema + `"],"Operations":[{"method":"DELETE","path":"/Users/bulkId:u"},{"method":"POST","bulkId":"u","path":"/Users","data":{}}]}`)
	plan, err := ParseBulk(body, nil, DefaultBulkPolicy(), limits)
	if err != nil {
		t.Fatal(err)
	}
	got, err := plan.ResolveOperation(0, map[int]string{1: strings.Repeat("u", 128)})
	if err == nil || !reflect.DeepEqual(got, BulkOperation{}) {
		t.Fatalf("expanded target exceeded retained path limit: %#v, %v", got, err)
	}
}

func TestBulkResolveRetainsInvalidPathlessPatchAsUnexecutableChild(t *testing.T) {
	plan := resolveTestPlan(t, `{"method":"PATCH","path":"/Users/u","data":{"schemas":["`+patchSchema+`"],"Operations":[{"op":"replace","value":{"unknown":"bulkId:literal"}}]}},{"method":"DELETE","path":"/Users/other"}`)
	if plan.Operations()[0].Error == nil || plan.Operations()[1].Error != nil {
		t.Fatal("invalid pathless PATCH was not retained as an individual child failure")
	}
	got, err := plan.ResolveOperation(0, nil)
	if err == nil || !reflect.DeepEqual(got, BulkOperation{}) {
		t.Fatal("invalid pathless PATCH exposed executable output")
	}
}

func TestBulkResolveRejectsInvalidAllocationAtomically(t *testing.T) {
	plan := resolveTestPlan(t, `{"method":"DELETE","path":"/Users/bulkId:user"},{"method":"POST","bulkId":"user","path":"/Users","data":{"userName":"u"}},{"method":"GET","path":"/Users/id"}`)
	for name, test := range map[string]struct {
		index int
		ids   map[int]string
	}{
		"missing allocation": {0, nil},
		"foreign index":      {0, map[int]string{1: "U", 9: "foreign"}},
		"non-create index":   {0, map[int]string{0: "U", 1: "U"}},
		"invalid ID":         {0, map[int]string{1: "../escape"}},
		"dot ID":             {0, map[int]string{1: ".."}},
		"unresolved ID":      {0, map[int]string{1: "bulkId:foreign"}},
		"invalid child":      {2, map[int]string{1: "U"}},
		"negative index":     {-1, map[int]string{1: "U"}},
		"past end":           {3, map[int]string{1: "U"}},
	} {
		t.Run(name, func(t *testing.T) {
			got, err := plan.ResolveOperation(test.index, test.ids)
			if err == nil || !reflect.DeepEqual(got, BulkOperation{}) {
				t.Fatalf("invalid allocation exposed executable output: %#v, %v", got, err)
			}
		})
	}
	if got, err := (BulkPlan{}).ResolveOperation(0, nil); err == nil || !reflect.DeepEqual(got, BulkOperation{}) {
		t.Fatal("zero plan produced executable operation")
	}
}

func TestBulkResolveRejectsWrongKindAndAmbiguousReferencesBeforeOutput(t *testing.T) {
	for _, member := range []string{
		`{"value":"bulkId:user","type":"Group"}`,
		`{"value":"bulkId:user","$ref":"bulkId:other"}`,
		`{"value":"bulkId:user","$ref":"https://foreign.test/Users/bulkId:user"}`,
		`{"value":42,"$ref":"bulkId:user"}`,
	} {
		body := []byte(`{"schemas":["` + bulkRequestSchema + `"],"Operations":[{"method":"POST","bulkId":"user","path":"/Users","data":{}},{"method":"POST","bulkId":"g","path":"/Groups","data":{"members":[` + member + `]}}]}`)
		plan, err := ParseBulk(body, nil, DefaultBulkPolicy(), DefaultLimits())
		if err == nil {
			got, resolveErr := plan.ResolveOperation(1, map[int]string{0: "U"})
			if resolveErr == nil || !reflect.DeepEqual(got, BulkOperation{}) {
				t.Fatalf("wrong/ambiguous member exposed executable output: %s, %#v", member, got)
			}
		}
	}
}

func TestBulkResolveRejectsUnrecognizedPlaceholderReferencePaths(t *testing.T) {
	extension := Schema{ID: "urn:example:bulk:reference", Name: "Reference", Attributes: []Attribute{scalar("target", "reference")}}
	for _, reference := range []string{"/Other/bulkId:u", "../Users/bulkId:u", "Users/bulkId:u", "/Users/%62ulkId:u", "https://foreign.test/Users/bulkId:u"} {
		body := []byte(`{"schemas":["` + bulkRequestSchema + `"],"Operations":[{"method":"PUT","path":"/Users/follower","data":{"` + extension.ID + `":{"target":"` + reference + `"}}},{"method":"POST","bulkId":"u","path":"/Users","data":{}}]}`)
		plan, err := ParseBulk(body, []Schema{extension}, DefaultBulkPolicy(), DefaultLimits())
		if err == nil {
			got, resolveErr := plan.ResolveOperation(0, map[int]string{1: "U"})
			if resolveErr == nil || !reflect.DeepEqual(got, BulkOperation{}) {
				t.Fatalf("unrecognized placeholder URI reached execution: %q", reference)
			}
		}
	}
}

func TestBulkResolveReturnsDetachedLiteralChildWithoutAllocations(t *testing.T) {
	plan := resolveTestPlan(t, `{"method":"DELETE","path":"/Users/al%69ce"}`)
	got, err := plan.ResolveOperation(0, nil)
	if err != nil || got.Path != "/Users/al%69ce" || got.Target.ResourceID != "alice" {
		t.Fatalf("literal child changed: %#v, %v", got, err)
	}
	if !reflect.DeepEqual(got, plan.Operations()[0]) {
		t.Fatal("literal child metadata changed")
	}
}
