package scim_test

import (
	"bytes"
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"testing"

	scim "github.com/faustbrian/go-scim"
)

const bulkRequestURN = "urn:ietf:params:scim:api:messages:2.0:BulkRequest"

func bulkEnvelope(operations string, extra string) []byte {
	return []byte(`{"schemas":["` + bulkRequestURN + `"],"Operations":[` + operations + `]` + extra + `}`)
}

func parseBulkPlan(t *testing.T, body []byte) scim.BulkPlan {
	t.Helper()
	plan, err := scim.ParseBulk(body, nil, scim.DefaultBulkPolicy(), scim.DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}
	return plan
}

func TestBulkPlanPreservesOrderedIntentAndDetachedSnapshots(t *testing.T) {
	body := bulkEnvelope(`{"method":"POST","bulkId":"new-user","path":"/Users","data":{"schemas":["`+userURN+`"],"userName":"Alice","displayName":"bulkId:literal"}},
		{"method":"PATCH","path":"/Users/bulkId:new-user","version":"\"v1\"","data":{"schemas":["`+patchURN+`"],"Operations":[{"op":"replace","path":"displayName","value":"Alice Updated"}]}}`, `,"failOnErrors":2`)
	plan := parseBulkPlan(t, body)
	ops := plan.Operations()
	if plan.FailOnErrors() != 2 || len(ops) != 2 || ops[0].Index != 0 || ops[0].Method != "POST" || ops[0].BulkID != "new-user" || ops[0].Path != "/Users" || ops[0].Target.ResourceType != "User" || ops[0].Error != nil {
		t.Fatalf("lost create intent: %#v", ops)
	}
	if ops[1].Method != "PATCH" || ops[1].Version != `"v1"` || ops[1].Target.BulkID != "new-user" || !reflect.DeepEqual(ops[1].Dependencies, []int{0}) || ops[1].Error != nil {
		t.Fatalf("lost update intent: %#v", ops[1])
	}
	canonical := plan.CanonicalRequest()
	ops[0].Data[0] = 'x'
	ops[1].Dependencies[0] = 42
	ops[0].Method = "DELETE"
	canonical[0] = 'x'
	components := plan.Components()
	components[0].Operations[0] = 42
	if !bytes.Equal(plan.CanonicalRequest(), parseBulkPlan(t, body).CanonicalRequest()) || plan.Operations()[0].Method != "POST" || plan.Operations()[1].Dependencies[0] != 0 || plan.Components()[0].Operations[0] != 0 {
		t.Fatal("caller changed retained request or execution plan")
	}
}

func TestBulkPlanDependencyFirstSCCAndOriginalIndexTies(t *testing.T) {
	plan := parseBulkPlan(t, bulkEnvelope(`
		{"method":"POST","bulkId":"a","path":"/Groups","data":{"members":[{"value":"bulkId:b","type":"Group"}]}},
		{"method":"POST","bulkId":"independent","path":"/Users","data":{"userName":"independent"}},
		{"method":"POST","bulkId":"b","path":"/Groups","data":{"members":[{"value":"bulkId:a","type":"Group"}]}},
		{"method":"POST","bulkId":"forward","path":"/Groups","data":{"members":[{"value":"bulkId:later","type":"User"}]}},
		{"method":"POST","bulkId":"later","path":"/Users","data":{"userName":"later"}},
		{"method":"POST","bulkId":"self","path":"/Groups","data":{"members":[{"value":"bulkId:self","type":"Group"}]}}`, ""))
	components := plan.Components()
	want := []scim.BulkComponent{{Operations: []int{0, 2}, Cyclic: true}, {Operations: []int{1}}, {Operations: []int{4}}, {Operations: []int{3}}, {Operations: []int{5}, Cyclic: true}}
	if !reflect.DeepEqual(components, want) {
		t.Fatalf("dependency-first SCC plan: got %#v; want %#v", components, want)
	}
	if !reflect.DeepEqual(plan.Operations()[0].Dependencies, []int{2}) || !reflect.DeepEqual(plan.Operations()[3].Dependencies, []int{4}) {
		t.Fatal("lost forward or circular dependency")
	}
}

func TestBulkPlanRejectsMalformedParentBeforeAdmission(t *testing.T) {
	valid := `{"method":"POST","bulkId":"a","path":"/Users","data":{"userName":"Alice"}}`
	for name, body := range map[string][]byte{
		"wrong schema":                []byte(`{"schemas":["wrong"],"Operations":[]}`),
		"unknown envelope field":      bulkEnvelope(valid, `,"unknown":true`),
		"duplicate alias":             bulkEnvelope(valid, `,"operations":[]`),
		"nested duplicate alias":      bulkEnvelope(`{"method":"POST","bulkId":"a","path":"/Users","data":{"userName":"a","USERNAME":"b"}}`, ""),
		"empty operations":            bulkEnvelope("", ""),
		"non-array operations":        []byte(`{"schemas":["` + bulkRequestURN + `"],"Operations":{}}`),
		"duplicate bulk id":           bulkEnvelope(valid+","+valid, ""),
		"unknown reference":           bulkEnvelope(`{"method":"DELETE","path":"/Users/bulkId:other"}`, ""),
		"reference to non-create":     bulkEnvelope(`{"method":"DELETE","bulkId":"a","path":"/Users/existing"},{"method":"DELETE","path":"/Users/bulkId:a"}`, ""),
		"wrong reference type":        bulkEnvelope(valid+`,{"method":"DELETE","path":"/Groups/bulkId:a"}`, ""),
		"ambiguous member references": bulkEnvelope(valid+`,{"method":"POST","bulkId":"g","path":"/Groups","data":{"members":[{"value":"bulkId:a","$ref":"bulkId:other"}]}}`, ""),
		"negative cutoff":             bulkEnvelope(valid, `,"failOnErrors":-1`),
		"fractional cutoff":           bulkEnvelope(valid, `,"failOnErrors":1.5`),
		"null cutoff":                 bulkEnvelope(valid, `,"failOnErrors":null`),
		"over maximum cutoff":         bulkEnvelope(valid, `,"failOnErrors":101`),
		"trailing JSON":               append(bulkEnvelope(valid, ""), []byte(` {}`)...),
	} {
		t.Run(name, func(t *testing.T) {
			_, err := scim.ParseBulk(body, nil, scim.DefaultBulkPolicy(), scim.DefaultLimits())
			var protocol *scim.Error
			if !errors.As(err, &protocol) || protocol.StatusCode() != 400 {
				t.Fatalf("malformed parent admitted: %v", err)
			}
		})
	}
}

func TestBulkPlanRetainsPerOperationFailures(t *testing.T) {
	for name, operation := range map[string]string{
		"unsupported method":     `{"method":"GET","path":"/Users/existing"}`,
		"unknown child field":    `{"method":"DELETE","path":"/Users/existing","unknown":true}`,
		"missing create bulk id": `{"method":"POST","path":"/Users","data":{}}`,
		"missing body":           `{"method":"PUT","path":"/Users/existing"}`,
		"delete body":            `{"method":"DELETE","path":"/Users/existing","data":{}}`,
		"absolute path":          `{"method":"DELETE","path":"https://other.test/Users/id"}`,
		"query path":             `{"method":"DELETE","path":"/Users/id?x=y"}`,
		"encoded separator":      `{"method":"DELETE","path":"/Users/a%2Fb"}`,
		"missing resource":       `{"method":"DELETE","path":"/Users"}`,
		"invalid precondition":   `{"method":"DELETE","path":"/Users/id","version":"not-an-etag"}`,
	} {
		t.Run(name, func(t *testing.T) {
			plan := parseBulkPlan(t, bulkEnvelope(operation+`,{"method":"DELETE","path":"/Groups/valid"}`, ""))
			ops := plan.Operations()
			if len(ops) != 2 || ops[0].Error == nil || ops[0].Error.StatusCode() != 400 || ops[1].Error != nil || ops[1].Index != 1 {
				t.Fatalf("invalid child discarded or converted to parent failure: %#v", ops)
			}
		})
	}
}

func TestBulkPlanCanonicalFingerprintPreservesEveryReplayInput(t *testing.T) {
	operation := `{"method":"PUT","bulkId":"update","path":"/Users/id","version":"\"v1\"","data":{"userName":"Alice","displayName":"A"}}`
	body := bulkEnvelope(operation+`,{"method":"DELETE","path":"/Groups/group"}`, `,"failOnErrors":1`)
	canonical := parseBulkPlan(t, body).CanonicalRequest()
	for name, changed := range map[string][]byte{
		"order":   bulkEnvelope(`{"method":"DELETE","path":"/Groups/group"},`+operation, `,"failOnErrors":1`),
		"cutoff":  bytes.Replace(body, []byte(`"failOnErrors":1`), []byte(`"failOnErrors":2`), 1),
		"target":  bytes.Replace(body, []byte(`/Users/id`), []byte(`/Users/other`), 1),
		"version": bytes.Replace(body, []byte(`v1`), []byte(`v2`), 1),
		"body":    bytes.Replace(body, []byte(`Alice`), []byte(`Bob`), 1),
		"bulk id": bytes.Replace(body, []byte(`update`), []byte(`changed`), 1),
	} {
		t.Run(name, func(t *testing.T) {
			if bytes.Equal(canonical, parseBulkPlan(t, changed).CanonicalRequest()) {
				t.Fatal("changed canonical intent reused prior fingerprint input")
			}
		})
	}
	equivalent := []byte(" \n" + strings.ReplaceAll(string(body), `"userName":"Alice","displayName":"A"`, `"displayName":"A","userName":"Alice"`))
	if !bytes.Equal(canonical, parseBulkPlan(t, equivalent).CanonicalRequest()) {
		t.Fatal("insignificant whitespace or JSON member order changed canonical input")
	}
	var decoded any
	if err := json.Unmarshal(canonical, &decoded); err != nil {
		t.Fatal("canonical request is not independently consumable JSON", err)
	}
	if parseBulkPlan(t, bulkEnvelope(`{"method":"DELETE","path":"/Users/id"}`, "")).FailOnErrors() != 0 || parseBulkPlan(t, bulkEnvelope(`{"method":"DELETE","path":"/Users/id"}`, `,"failOnErrors":0`)).FailOnErrors() != 0 {
		t.Fatal("zero or omitted cutoff became positive")
	}
}

func TestBulkPlanAppliesIndependentResourceBudgets(t *testing.T) {
	operation := `{"method":"POST","bulkId":"a","path":"/Users","data":{"userName":"` + strings.Repeat("a", 1100) + `"}}`
	for name, policy := range map[string]scim.BulkPolicy{
		"operation bytes": {MaxOperations: 1000, MaxPayloadBytes: 1048576, MaxOperationBytes: 1024},
		"operation count": {MaxOperations: 1, MaxPayloadBytes: 1048576, MaxOperationBytes: 262144},
	} {
		t.Run(name, func(t *testing.T) {
			body := bulkEnvelope(operation+`,{"method":"DELETE","path":"/Users/id"}`, "")
			_, err := scim.ParseBulk(body, nil, policy, scim.DefaultLimits())
			var protocol *scim.Error
			if !errors.As(err, &protocol) || protocol.StatusCode() != 413 {
				t.Fatalf("exceeded %s admitted: %v", name, err)
			}
		})
	}
	limits := scim.DefaultLimits()
	limits.ResourceAttributes = 8
	plan, err := scim.ParseBulk(bulkEnvelope(`{"method":"POST","bulkId":"a","path":"/Users","data":{"userName":"a"}},{"method":"POST","bulkId":"b","path":"/Users","data":{"userName":"b"}}`, ""), nil, scim.DefaultBulkPolicy(), limits)
	if err != nil || len(plan.Operations()) != 2 {
		t.Fatalf("aggregate envelope consumed independent per-child attribute budget: %v", err)
	}
}

func TestBulkPlanResolvesSchemaReferencesAndQualifiedPatchPaths(t *testing.T) {
	extension := scim.Schema{ID: "urn:example:scim:custom", Name: "Custom", Attributes: []scim.Attribute{{Name: "supervisor", Type: "reference", Mutability: "readWrite", Returned: "default", Uniqueness: "none"}}}
	body := bulkEnvelope(`{"method":"PATCH","path":"/Groups/existing","data":{"Operations":[{"op":"add","path":"`+groupURN+`:members","value":[{"value":"bulkId:new:person","type":"User"}]}]}},
		{"method":"POST","bulkId":"new:person","path":"/Users","data":{"userName":"new"}},
		{"method":"POST","bulkId":"follower","path":"/Users","data":{"userName":"follower","`+extension.ID+`":{"supervisor":"bulkId:new:person"}}}`, "")
	plan, err := scim.ParseBulk(body, []scim.Schema{extension}, scim.DefaultBulkPolicy(), scim.DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}
	for _, index := range []int{0, 2} {
		op := plan.Operations()[index]
		if op.Error != nil || !reflect.DeepEqual(op.Dependencies, []int{1}) {
			t.Fatalf("schema-owned reference was lost: %#v", op)
		}
	}
}

func TestBulkPlanRetainsEscapedTargetWithoutRejectingUnreservedCharacters(t *testing.T) {
	plan := parseBulkPlan(t, bulkEnvelope(`{"method":"DELETE","path":"/Users/al%69ce"}`, ""))
	op := plan.Operations()[0]
	if op.Error != nil || op.Path != "/Users/al%69ce" || op.Target.ResourceID != "alice" {
		t.Fatalf("safe encoded target did not retain wire intent and exact resource identity: %#v", op)
	}
}

func TestBulkPlanExtensionMembersUsesDeclaredReferenceAttributes(t *testing.T) {
	ordinaryValue := scim.Attribute{Name: "value", Type: "string", Mutability: "readWrite", Returned: "default", Uniqueness: "none"}
	supervisor := scim.Attribute{Name: "supervisor", Type: "reference", Mutability: "readWrite", Returned: "default", Uniqueness: "none"}
	members := scim.Attribute{Name: "members", Type: "complex", Mutability: "readWrite", Returned: "default", Uniqueness: "none", SubAttributes: []scim.Attribute{ordinaryValue, supervisor}}
	nested := scim.Attribute{Name: "container", Type: "complex", Mutability: "readWrite", Returned: "default", Uniqueness: "none", SubAttributes: []scim.Attribute{members}}
	for _, fixture := range []struct {
		name      string
		attribute scim.Attribute
		data      string
	}{
		{name: "extension members", attribute: members, data: `{"members":{"value":"bulkId:unrelated","supervisor":"bulkId:leader"}}`},
		{name: "nested members", attribute: nested, data: `{"container":{"members":{"value":"bulkId:unrelated","supervisor":"bulkId:leader"}}}`},
	} {
		t.Run(fixture.name, func(t *testing.T) {
			extension := scim.Schema{ID: "urn:example:scim:custom", Name: "Custom", Attributes: []scim.Attribute{fixture.attribute}}
			body := bulkEnvelope(`{"method":"POST","bulkId":"follower","path":"/Users","data":{"userName":"follower","`+extension.ID+`":`+fixture.data+`}},
				{"method":"POST","bulkId":"leader","path":"/Users","data":{"userName":"leader"}}`, "")
			plan, err := scim.ParseBulk(body, []scim.Schema{extension}, scim.DefaultBulkPolicy(), scim.DefaultLimits())
			if err != nil {
				t.Fatalf("ordinary extension string was misclassified as a Group member reference: %v", err)
			}
			op := plan.Operations()[0]
			if op.Error != nil || !reflect.DeepEqual(op.Dependencies, []int{1}) {
				t.Fatalf("extension reference attribute did not supply its exact dependency: %#v", op)
			}
			want := []scim.BulkComponent{{Operations: []int{1}}, {Operations: []int{0}}}
			if !reflect.DeepEqual(plan.Components(), want) {
				t.Fatalf("extension reference did not order its predecessor first: %#v", plan.Components())
			}
			unknown := bytes.Replace(body, []byte(`"supervisor":"bulkId:leader"`), []byte(`"supervisor":"bulkId:unknown"`), 1)
			_, err = scim.ParseBulk(unknown, []scim.Schema{extension}, scim.DefaultBulkPolicy(), scim.DefaultLimits())
			var protocol *scim.Error
			if !errors.As(err, &protocol) || protocol.StatusCode() != 400 {
				t.Fatalf("unknown schema-declared extension reference crossed parent admission: %v", err)
			}
		})
	}
}

func FuzzBulkPlanAdmission(f *testing.F) {
	f.Add(bulkEnvelope(`{"method":"DELETE","path":"/Users/existing"}`, ""))
	f.Add(bulkEnvelope(`{"method":"POST","bulkId":"self","path":"/Groups","data":{"members":[{"value":"bulkId:self","type":"Group"}]}}`, ""))
	f.Add([]byte(`{"schemas":null,"Operations":[null]}`))
	f.Fuzz(func(t *testing.T, body []byte) {
		plan, err := scim.ParseBulk(body, nil, scim.DefaultBulkPolicy(), scim.DefaultLimits())
		if err != nil {
			var protocol *scim.Error
			if !errors.As(err, &protocol) {
				t.Fatal("untyped parser failure")
			}
			return
		}
		ops := plan.Operations()
		visited := make([]bool, len(ops))
		for _, component := range plan.Components() {
			if len(component.Operations) == 0 {
				t.Fatal("empty SCC")
			}
			for _, index := range component.Operations {
				if index < 0 || index >= len(ops) || visited[index] {
					t.Fatal("SCC plan lost original operation identity")
				}
				visited[index] = true
			}
		}
		for _, found := range visited {
			if !found {
				t.Fatal("SCC plan omitted a declared operation")
			}
		}
		replayed, err := scim.ParseBulk(plan.CanonicalRequest(), nil, scim.DefaultBulkPolicy(), scim.DefaultLimits())
		if err != nil || !bytes.Equal(plan.CanonicalRequest(), replayed.CanonicalRequest()) || !reflect.DeepEqual(plan.Components(), replayed.Components()) {
			t.Fatalf("canonical round trip changed retained intent or graph: %v", err)
		}
	})
}
