package scim_test

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strconv"
	"testing"

	scim "github.com/faustbrian/go-scim"
)

func TestBulkResponsePreflightBoundsEveryEncodedError(t *testing.T) {
	cases := []struct {
		code         int
		kind, detail string
	}{
		{400, "", "Invalid request"},
		{400, "invalidFilter", "Invalid request"},
		{400, "tooMany", "Invalid request"},
		{400, "mutability", "Invalid request"},
		{400, "invalidSyntax", "Invalid request"},
		{400, "invalidPath", "Invalid request"},
		{400, "noTarget", "Invalid request"},
		{400, "invalidValue", "Invalid request"},
		{400, "invalidVers", "Invalid request"},
		{401, "", "Authentication required"},
		{403, "", "Access denied"},
		{404, "", "Resource not found"},
		{409, "", "Request conflict"},
		{409, "uniqueness", "Request conflict"},
		{412, "", "Resource version mismatch"},
		{413, "", "Request too large"},
		{415, "", "Unsupported representation"},
		{424, "", "Dependency failed"},
		{428, "", "Resource version required"},
		{500, "", "Request failed"},
		{501, "", "Operation unsupported"},
		{503, "", "Authority or outcome unavailable"},
	}
	// DELETE has no success-version reservation to hide an underestimated error.
	// These are the encoder's accepted status/type pairs, not execution outcomes.
	plan := parseBulkPlan(t, bulkEnvelope(`{"method":"DELETE","path":"/Users/existing"}`, ""))
	cutoffs := make([]int, 34)
	for i := range cutoffs {
		cutoffs[i] = i
	}
	cutoffs = append(cutoffs, scim.DefaultLimits().ErrorDetailBytes)
	for _, cutoff := range cutoffs {
		t.Run(fmt.Sprintf("detail_%d", cutoff), func(t *testing.T) {
			policy := scim.DefaultBulkResponsePolicy()
			policy.ErrorDetailBytes = cutoff
			response, err := scim.PreflightBulkResponse(plan, "https://directory.example/v2", policy)
			if err != nil {
				t.Fatal(err)
			}
			for _, tc := range cases {
				t.Run(strconv.Itoa(tc.code)+"_"+tc.kind, func(t *testing.T) {
					var out bytes.Buffer
					result := scim.BulkChildResult{Status: scim.BulkChildFailed, Code: tc.code, SCIMType: tc.kind}
					if err := response.Write(&out, []scim.BulkChildResult{result}); err != nil {
						t.Fatalf("preflighted error could not be encoded (maximum %d): %v", response.MaximumBytes(), err)
					}
					if out.Len() > response.MaximumBytes() {
						t.Fatalf("encoded error uses %d bytes, exceeding preflight maximum %d", out.Len(), response.MaximumBytes())
					}
					var wire struct {
						Operations []struct {
							Method, Location, Status string
							Response                 struct {
								Schemas []string `json:"schemas"`
								Status  string   `json:"status"`
								Type    string   `json:"scimType"`
								Detail  string   `json:"detail"`
							}
						}
					}
					if err := json.Unmarshal(out.Bytes(), &wire); err != nil {
						t.Fatal(err)
					}
					if len(wire.Operations) != 1 {
						t.Fatalf("encoded %d operations, want 1", len(wire.Operations))
					}
					got := wire.Operations[0]
					wantStatus := strconv.Itoa(tc.code)
					wantDetail := tc.detail[:min(len(tc.detail), cutoff)]
					if got.Method != "DELETE" || got.Location != "https://directory.example/v2/Users/existing" ||
						got.Status != wantStatus || got.Response.Status != wantStatus || got.Response.Type != tc.kind || got.Response.Detail != wantDetail ||
						len(got.Response.Schemas) != 1 || got.Response.Schemas[0] != "urn:ietf:params:scim:api:messages:2.0:Error" {
						t.Fatalf("wrong public error response: %s", out.Bytes())
					}
				})
			}
		})
	}
}
