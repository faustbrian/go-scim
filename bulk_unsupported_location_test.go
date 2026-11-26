package scim_test

import (
	"bytes"
	"encoding/json"
	"strconv"
	"testing"

	scim "github.com/faustbrian/go-scim"
)

func unsupportedMethodResponsePlan(t *testing.T, method, path string) scim.BulkResponsePlan {
	t.Helper()
	body := []byte(`{"schemas":["urn:ietf:params:scim:api:messages:2.0:BulkRequest"],"Operations":[` +
		`{"method":"POST","path":"/Groups","bulkId":"new","data":{"schemas":["urn:ietf:params:scim:schemas:core:2.0:Group"],"displayName":"New group"}},` +
		`{"method":"` + method + `","path":"` + path + `","version":"\"original\"","data":{"schemas":["urn:ietf:params:scim:api:messages:2.0:PatchOp"],"Operations":[{"op":"replace","path":"displayName","value":"Changed"}]}}]}`)
	plan, err := scim.ParseBulk(body, nil, scim.DefaultBulkPolicy(), scim.DefaultLimits())
	if err != nil {
		t.Fatal("parse the Bulk envelope", err)
	}
	operations := plan.Operations()
	if len(operations) != 2 || operations[0].Error != nil {
		t.Fatal("fixture must retain a valid Group create and its following declaration")
	}
	if method == "MOVE" {
		failure := operations[1].Error
		if failure == nil || failure.StatusCode() != 400 || failure.SCIMType() != "invalidValue" {
			t.Fatal("unrecognized method must retain its malformed-declaration result", failure)
		}
	} else if operations[1].Error != nil {
		t.Fatal("recognized PATCH fixture must remain valid", operations[1].Error)
	}
	response, err := scim.PreflightBulkResponse(plan, "https://directory.example/v2", scim.DefaultBulkResponsePolicy())
	if err != nil {
		t.Fatal("preflight malformed and recognized child responses", err)
	}
	return response
}

func TestBulkResponseUnsupportedMethodDoesNotDiscloseTargetLocation(t *testing.T) {
	for _, scenario := range []struct {
		name, method, path, resultID, location string
		code                                   int
	}{
		{name: "literal MOVE", method: "MOVE", path: "/Groups/existing", code: 400},
		{name: "symbolic MOVE", method: "MOVE", path: "/Groups/bulkId:new", code: 400},
		{name: "symbolic MOVE dependency failure", method: "MOVE", path: "/Groups/bulkId:new", code: 424},
		{name: "literal PATCH", method: "PATCH", path: "/Groups/existing", code: 400, location: "https://directory.example/v2/Groups/existing"},
		{name: "symbolic PATCH", method: "PATCH", path: "/Groups/bulkId:new", code: 400, resultID: "created-group", location: "https://directory.example/v2/Groups/created-group"},
	} {
		t.Run(scenario.name, func(t *testing.T) {
			response := unsupportedMethodResponsePlan(t, scenario.method, scenario.path)
			prerequisite := scim.BulkChildResult{Status: scim.BulkChildSucceeded, Code: 201, ResourceID: "created-group", Version: `"created"`}
			kind := "invalidValue"
			if scenario.code == 424 {
				prerequisite = scim.BulkChildResult{Status: scim.BulkChildFailed, Code: 409}
				kind = ""
			}
			var out bytes.Buffer
			if err := response.Write(&out, []scim.BulkChildResult{
				prerequisite,
				{Status: scim.BulkChildFailed, Code: scenario.code, SCIMType: kind, ResourceID: scenario.resultID},
			}); err != nil {
				t.Fatal("encode the terminal result without requiring an unauthorized Location", err)
			}
			var wire struct {
				Operations []map[string]json.RawMessage
			}
			if err := json.Unmarshal(out.Bytes(), &wire); err != nil || len(wire.Operations) != 2 {
				t.Fatal("decode both terminal results", err)
			}
			child := wire.Operations[1]
			var method, status string
			var failure struct{ Status, SCIMType string }
			wantStatus := strconv.Itoa(scenario.code)
			if json.Unmarshal(child["method"], &method) != nil || json.Unmarshal(child["status"], &status) != nil ||
				json.Unmarshal(child["response"], &failure) != nil || method != scenario.method || status != wantStatus ||
				failure.Status != wantStatus || failure.SCIMType != kind {
				t.Fatalf("wrong terminal error response: %s", out.Bytes())
			}
			location, present := child["location"]
			if scenario.location == "" {
				if present {
					t.Fatalf("unrecognized method disclosed a target Location: %s", location)
				}
			} else {
				var got string
				if !present || json.Unmarshal(location, &got) != nil || got != scenario.location {
					t.Fatalf("recognized PATCH lost its target Location: %s", out.Bytes())
				}
			}
		})
	}
}

func TestBulkResponseUnsupportedMethodRejectsFabricatedResourceIDBeforeWriting(t *testing.T) {
	for _, path := range []string{"/Groups/existing", "/Groups/bulkId:new"} {
		for _, code := range []int{400, 424} {
			t.Run(path+"/"+strconv.Itoa(code), func(t *testing.T) {
				response := unsupportedMethodResponsePlan(t, "MOVE", path)
				prerequisite := scim.BulkChildResult{Status: scim.BulkChildSucceeded, Code: 201, ResourceID: "created-group", Version: `"created"`}
				kind := "invalidValue"
				if code == 424 {
					prerequisite = scim.BulkChildResult{Status: scim.BulkChildFailed, Code: 409}
					kind = ""
				}
				var out bytes.Buffer
				err := response.Write(&out, []scim.BulkChildResult{
					prerequisite,
					{Status: scim.BulkChildFailed, Code: code, SCIMType: kind, ResourceID: "existing"},
				})
				if err == nil || out.Len() != 0 {
					t.Fatalf("contradictory resource metadata produced output: %v %q", err, out.String())
				}
			})
		}
	}
}
