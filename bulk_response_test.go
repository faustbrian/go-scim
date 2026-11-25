package scim_test

import (
	"bytes"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	scim "github.com/faustbrian/go-scim"
)

func TestBulkResponseProjectsTerminalResultsInOriginalOrder(t *testing.T) {
	plan := parseBulkPlan(t, bulkEnvelope(`
		{"method":"PATCH","path":"/Groups/bulkId:later","version":"\"before\"","data":{"Operations":[{"op":"replace","path":"displayName","value":"renamed"}]}},
		{"method":"POST","path":"/Groups","bulkId":"later","data":{"displayName":"new"}},
		{"method":"DELETE","path":"/Groups/one"},
		{"method":"DELETE","path":"/Groups/two","bulkId":"omitted"}`, `,"failOnErrors":1`))
	response, err := scim.PreflightBulkResponse(plan, "https://directory.example/v2/", scim.DefaultBulkResponsePolicy())
	if err != nil {
		t.Fatal(err)
	}
	results := []scim.BulkChildResult{
		{Status: scim.BulkChildSucceeded, Code: 200, ResourceID: "new&group", Version: `"after"`},
		{Status: scim.BulkChildSucceeded, Code: 201, ResourceID: "new&group", Version: `"before"`},
		{Status: scim.BulkChildFailed, Code: 424, SCIMType: "private-reason"},
		{Status: scim.BulkChildSkipped, SkipReason: scim.BulkSkipFailOnErrors},
	}
	var out bytes.Buffer
	if err := response.Write(&out, results); err != nil {
		t.Fatal(err)
	}
	want := `{"schemas":["urn:ietf:params:scim:api:messages:2.0:BulkResponse"],"Operations":[` +
		`{"method":"PATCH","location":"https://directory.example/v2/Groups/new\u0026group","version":"\"after\"","status":"200"},` +
		`{"method":"POST","bulkId":"later","location":"https://directory.example/v2/Groups/new\u0026group","version":"\"before\"","status":"201"},` +
		`{"method":"DELETE","location":"https://directory.example/v2/Groups/one","status":"424","response":{"schemas":["urn:ietf:params:scim:api:messages:2.0:Error"],"status":"424","detail":"Dependency failed"}}]}`
	if out.String() != want || out.Len() > response.MaximumBytes() {
		t.Fatalf("wrong terminal response or underestimated bound: %s (maximum %d)", out.String(), response.MaximumBytes())
	}
}

func TestBulkResponseRejectsIncompleteOrCorruptResultsBeforeWriting(t *testing.T) {
	plan := parseBulkPlan(t, bulkEnvelope(`{"method":"DELETE","path":"/Groups/one"},{"method":"DELETE","path":"/Groups/two"}`, ""))
	response, err := scim.PreflightBulkResponse(plan, "https://directory.example/v2", scim.DefaultBulkResponsePolicy())
	if err != nil {
		t.Fatal(err)
	}
	valid := scim.BulkChildResult{Status: scim.BulkChildSucceeded, Code: 204, ResourceID: "one"}
	for _, state := range []scim.BulkChildStatus{scim.BulkChildAdmitted, scim.BulkChildRunning, scim.BulkChildDependencyBlocked} {
		var out bytes.Buffer
		if err := response.Write(&out, []scim.BulkChildResult{valid, {Status: state}}); !errors.Is(err, scim.ErrBulkIncomplete) || out.Len() != 0 {
			t.Fatalf("unresolved child produced terminal output: %v, %q", err, out.String())
		}
	}
	for _, result := range []scim.BulkChildResult{
		{Status: scim.BulkChildSkipped},
		{Status: scim.BulkChildSkipped, SkipReason: scim.BulkSkipFailOnErrors, Code: 204},
		{Status: scim.BulkChildSucceeded, Code: 204, ResourceID: "wrong"},
		{Status: scim.BulkChildFailed, Code: 201},
	} {
		var out bytes.Buffer
		if err := response.Write(&out, []scim.BulkChildResult{valid, result}); err == nil || out.Len() != 0 {
			t.Fatalf("malformed checkpoint produced output: %v, %q", err, out.String())
		}
	}
}

func TestBulkResponsePreflightBoundsEscapedFieldsAndAllChildren(t *testing.T) {
	var operations []string
	for i := range 20 {
		id, _ := json.Marshal(strings.Repeat("<", 120) + string(rune('a'+i)))
		operations = append(operations, `{"method":"POST","bulkId":`+string(id)+`,"path":"/Groups","data":{"displayName":"new"}}`)
	}
	plan := parseBulkPlan(t, bulkEnvelope(strings.Join(operations, ","), ",\"failOnErrors\":1"))
	policy := scim.DefaultBulkResponsePolicy()
	policy.MaxBytes = 16 * 1024
	if _, err := scim.PreflightBulkResponse(plan, "https://directory.example", policy); err == nil {
		t.Fatal("preflight relied on the cutoff or underestimated escaping")
	}
	policy = scim.DefaultBulkResponsePolicy()
	response, err := scim.PreflightBulkResponse(plan, "https://directory.example", policy)
	if err != nil {
		t.Fatal(err)
	}
	policy.MaxBytes = response.MaximumBytes()
	if _, err := scim.PreflightBulkResponse(plan, "https://directory.example", policy); err != nil {
		t.Fatal("exact conservative limit rejected", err)
	}
	policy.MaxBytes--
	if _, err := scim.PreflightBulkResponse(plan, "https://directory.example", policy); err == nil {
		t.Fatal("accepted a response one byte beyond the configured limit")
	}
	results := make([]scim.BulkChildResult, len(operations))
	for i := range results {
		results[i] = scim.BulkChildResult{Status: scim.BulkChildSucceeded, Code: 201,
			ResourceID: strings.Repeat("&", 128), Version: scim.Version(`"` + strings.Repeat("<", 254) + `"`)}
	}
	var out bytes.Buffer
	if err := response.Write(&out, results); err != nil || !json.Valid(out.Bytes()) || out.Len() > response.MaximumBytes() {
		t.Fatal("maximally escaped output exceeded the preflight bound", out.Len(), response.MaximumBytes(), err)
	}
}

func TestBulkResponsePreservesEmptySuppliedIDAndRejectsFragmentRoots(t *testing.T) {
	plan := parseBulkPlan(t, bulkEnvelope(`{"method":"DELETE","path":"/Groups/one","bulkId":""},{"method":"DELETE","path":"/Groups/two"}`, ""))
	policy := scim.DefaultBulkResponsePolicy()
	if _, err := scim.PreflightBulkResponse(plan, "https://directory.example/v2#", policy); err == nil {
		t.Fatal("fragment marker accepted in a service root")
	}
	response, err := scim.PreflightBulkResponse(plan, "https://directory.example/a b/", policy)
	if err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	if err := response.Write(&out, []scim.BulkChildResult{
		{Status: scim.BulkChildFailed, Code: 400, SCIMType: "invalidValue"},
		{Status: scim.BulkChildSucceeded, Code: 204, ResourceID: "two"},
	}); err != nil {
		t.Fatal(err)
	}
	if strings.Count(out.String(), `"bulkId":""`) != 1 || !strings.Contains(out.String(), `https://directory.example/a%20b/Groups/two`) {
		t.Fatalf("wrong ID presence or service location: %s", out.String())
	}
}

func TestBulkResponseRequiresResolvedLocationForFailedSymbolicTarget(t *testing.T) {
	plan := parseBulkPlan(t, bulkEnvelope(`{"method":"DELETE","path":"/Groups/bulkId:new"},{"method":"POST","path":"/Groups","bulkId":"new","data":{"displayName":"new"}}`, ""))
	response, err := scim.PreflightBulkResponse(plan, "https://directory.example/v2", scim.DefaultBulkResponsePolicy())
	if err != nil {
		t.Fatal(err)
	}
	results := []scim.BulkChildResult{{Status: scim.BulkChildFailed, Code: 424}, {Status: scim.BulkChildFailed, Code: 409}}
	var out bytes.Buffer
	if err := response.Write(&out, results); err == nil || out.Len() != 0 {
		t.Fatalf("missing resolved endpoint produced a response: %v %q", err, out.String())
	}
	results[0].ResourceID = "preallocated-group"
	if err := response.Write(&out, results); err != nil {
		t.Fatal(err)
	}
	if strings.Count(out.String(), `"location":`) != 1 || !strings.Contains(out.String(), `"location":"https://directory.example/v2/Groups/preallocated-group","status":"424"`) {
		t.Fatalf("wrong failed symbolic target or failed POST location: %s", out.String())
	}
}

func TestBulkResponseRejectsSkipBeforeDurableCutoff(t *testing.T) {
	for _, cutoff := range []string{"", `,"failOnErrors":2`} {
		plan := parseBulkPlan(t, bulkEnvelope(`{"method":"DELETE","path":"/Groups/one"},{"method":"DELETE","path":"/Groups/two"}`, cutoff))
		response, err := scim.PreflightBulkResponse(plan, "https://directory.example/v2", scim.DefaultBulkResponsePolicy())
		if err != nil {
			t.Fatal(err)
		}
		var out bytes.Buffer
		err = response.Write(&out, []scim.BulkChildResult{
			{Status: scim.BulkChildFailed, Code: 404},
			{Status: scim.BulkChildSkipped, SkipReason: scim.BulkSkipFailOnErrors},
		})
		if err == nil || out.Len() != 0 {
			t.Fatalf("skip accepted without an activated cutoff (%q): %v %q", cutoff, err, out.String())
		}
	}
}
