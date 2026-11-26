//go:build integration

package scimpostgres

import (
	"bytes"
	"encoding/json"
	"strconv"
	"testing"

	scim "github.com/faustbrian/go-scim"
)

func TestNativeGroupBulkReplacePatchAndNoOpRetainOriginalResults(t *testing.T) {
	f, service := bulkChildExecutionFixture(t)
	installBulkGroupMutationSchema(t, f)
	groups := groupsOnPool(t, f, f.pool)
	user := createNativeNamed(t, f, "BulkUpdateMember", "Existing member")
	seedBodies := []string{
		`{"schemas":["urn:ietf:params:scim:schemas:core:2.0:Group"],"displayName":"Before replacement","externalId":"remove-on-replace","members":[{"type":"User","value":"` + user + `"}]}`,
		`{"schemas":["urn:ietf:params:scim:schemas:core:2.0:Group"],"displayName":"Before patch","externalId":"keep-on-patch","members":[{"type":"User","value":"` + user + `"}]}`,
		`{"schemas":["urn:ietf:params:scim:schemas:core:2.0:Group"],"displayName":"Unchanged"}`,
	}
	seeds := make([]scim.Response, len(seedBodies))
	ids := make([]string, len(seedBodies))
	for i, body := range seedBodies {
		created, err := groups.Execute(f.ctx, groupRequest(f, scim.GroupCreate, "", "", "bulk-update-seed-"+strconv.Itoa(i), body))
		if err != nil || created.Status != 201 {
			t.Fatal("seed existing Group for Bulk update", i, err)
		}
		seeds[i], ids[i] = created, groupID(t, created)
	}
	var generationBefore int64
	if err := f.pool.Raw().QueryRow(f.ctx, `SELECT generation FROM scim.groups WHERE resource_id=$1`, ids[2]).Scan(&generationBefore); err != nil {
		t.Fatal("observe no-op target generation before Bulk", err)
	}

	body, err := json.Marshal(map[string]any{
		"schemas": []string{"urn:ietf:params:scim:api:messages:2.0:BulkRequest"},
		"Operations": []map[string]any{
			{"method": "POST", "path": "/Groups", "bulkId": "new-member", "data": json.RawMessage(`{"schemas":["urn:ietf:params:scim:schemas:core:2.0:Group"],"displayName":"Created in Bulk"}`)},
			{"method": "PUT", "path": "/Groups/" + ids[0], "version": seeds[0].ETag, "bulkId": "replacement", "data": json.RawMessage(`{"schemas":["urn:ietf:params:scim:schemas:core:2.0:Group"],"displayName":"Replacement"}`)},
			{"method": "PATCH", "path": "/Groups/" + ids[1], "version": seeds[1].ETag, "bulkId": "changed-patch", "data": json.RawMessage(`{"schemas":["urn:ietf:params:scim:api:messages:2.0:PatchOp"],"Operations":[{"op":"replace","path":"displayName","value":"Patched"},{"op":"add","path":"members","value":[{"type":"Group","value":"bulkId:new-member"}]}]}`)},
			{"method": "PATCH", "path": "/Groups/" + ids[2], "version": seeds[2].ETag, "data": json.RawMessage(`{"schemas":["urn:ietf:params:scim:api:messages:2.0:PatchOp"],"Operations":[{"op":"replace","path":"displayName","value":"Unchanged"}]}`)},
		},
	})
	if err != nil {
		t.Fatal("encode exact versioned Bulk request", err)
	}
	request := BulkAdmissionRequest{Credential: f.bearer, Body: body}
	parent, err := service.Admit(f.ctx, request)
	if err != nil || parent.ChildCount != 4 {
		t.Fatal("admit Group create, replacement, changed PATCH and no-op PATCH", err)
	}
	results := make([]scim.BulkChildResult, parent.ChildCount)
	for ordinal := range results {
		result, err := service.ExecuteChild(f.ctx, request, ordinal)
		wantCode := 200
		if ordinal == 0 {
			wantCode = 201
		}
		if err != nil || result.Status != scim.BulkChildSucceeded || result.Code != wantCode || result.ResourceID == "" ||
			!nativeVersion(result.Version) || result.SkipReason != scim.BulkSkipNone || result.SCIMType != "" {
			t.Fatal("execute independently committed Group Bulk operation", ordinal, result, err)
		}
		if ordinal > 0 && result.ResourceID != ids[ordinal-1] {
			t.Fatal("Bulk update changed the exact target Group ID", ordinal)
		}
		results[ordinal] = result
	}
	if results[1].Version == seeds[0].ETag || results[2].Version == seeds[1].ETag || results[3].Version != seeds[2].ETag {
		t.Fatal("replacement and changed PATCH must advance ETags, while no-op PATCH must retain its ETag")
	}
	if results[0].ResourceID == ids[0] || results[0].ResourceID == ids[1] || results[0].ResourceID == ids[2] {
		t.Fatal("Bulk create reused an existing Group ID")
	}

	observed := make([]scim.Response, len(results))
	documents := make([]map[string]json.RawMessage, len(results))
	for ordinal, result := range results {
		got, err := groups.Execute(f.ctx, groupRequest(f, scim.GroupGet, result.ResourceID, "", "", ""))
		if err != nil || got.Status != 200 || got.ETag != result.Version || groupID(t, got) != result.ResourceID {
			t.Fatal("public Group read does not match committed Bulk result", ordinal, err)
		}
		if err := json.Unmarshal(got.Body, &documents[ordinal]); err != nil {
			t.Fatal("decode public Group representation", ordinal, err)
		}
		observed[ordinal] = got
	}
	var replacementName string
	if err := json.Unmarshal(documents[1]["displayName"], &replacementName); err != nil || replacementName != "Replacement" {
		t.Fatal("PUT did not replace the Group display name", err)
	}
	if _, retained := documents[1]["externalId"]; retained {
		t.Fatal("PUT retained omitted externalId")
	}
	var replacedMembers []json.RawMessage
	if raw, present := documents[1]["members"]; present {
		if err := json.Unmarshal(raw, &replacedMembers); err != nil || len(replacedMembers) != 0 {
			t.Fatal("PUT retained omitted members", err)
		}
	}
	var patched struct {
		DisplayName string `json:"displayName"`
		ExternalID  string `json:"externalId"`
		Members     []struct {
			Type, Value string
		} `json:"members"`
	}
	if err := json.Unmarshal(observed[2].Body, &patched); err != nil || patched.DisplayName != "Patched" || patched.ExternalID != "keep-on-patch" || len(patched.Members) != 2 {
		t.Fatal("PATCH did not atomically change the name while preserving unaffected attributes", err)
	}
	wantMembers := map[string]string{user: "User", results[0].ResourceID: "Group"}
	for _, member := range patched.Members {
		wantType, exists := wantMembers[member.Value]
		if !exists || wantType != member.Type {
			t.Fatal("PATCH did not resolve the prior-create symbolic member to its exact Group ID and type")
		}
		delete(wantMembers, member.Value)
	}
	if len(wantMembers) != 0 {
		t.Fatal("PATCH dropped an existing or prior-create member")
	}
	var generationAfter int64
	if err := f.pool.Raw().QueryRow(f.ctx, `SELECT generation FROM scim.groups WHERE resource_id=$1`, ids[2]).Scan(&generationAfter); err != nil || generationAfter != generationBefore || !bytes.Equal(observed[3].Body, seeds[2].Body) {
		t.Fatal("no-op PATCH changed Group generation or representation metadata", err)
	}

	wire, err := service.ReadResult(f.ctx, request)
	if err != nil {
		t.Fatal("read terminal mixed-method Bulk result", err)
	}
	var response struct {
		Schemas    []string `json:"schemas"`
		Operations []struct {
			Method, Status, Location, Version string
			BulkID                            *string `json:"bulkId"`
			Response                          json.RawMessage
		} `json:"Operations"`
	}
	if err := json.Unmarshal(wire, &response); err != nil || len(response.Schemas) != 1 || response.Schemas[0] != "urn:ietf:params:scim:api:messages:2.0:BulkResponse" || len(response.Operations) != len(results) {
		t.Fatal("invalid terminal mixed-method Bulk response", err)
	}
	methods := []string{"POST", "PUT", "PATCH", "PATCH"}
	bulkIDs := []string{"new-member", "replacement", "changed-patch", ""}
	for ordinal, operation := range response.Operations {
		result := results[ordinal]
		if operation.Method != methods[ordinal] || operation.Status != strconv.Itoa(result.Code) || operation.Version != string(result.Version) ||
			operation.Location != f.config.BaseURL+"/Groups/"+result.ResourceID || len(operation.Response) != 0 {
			t.Fatal("terminal Bulk response lost original request order or exact successful result", ordinal)
		}
		if bulkIDs[ordinal] == "" {
			if operation.BulkID != nil {
				t.Fatal("terminal Bulk response invented an omitted bulkId", ordinal)
			}
		} else if operation.BulkID == nil || *operation.BulkID != bulkIDs[ordinal] {
			t.Fatal("terminal Bulk response changed a supplied bulkId", ordinal)
		}
	}

	later := make([]scim.Response, len(results))
	for ordinal, result := range results {
		update := groupRequest(f, scim.GroupReplace, result.ResourceID, result.Version, "after-mixed-bulk-"+strconv.Itoa(ordinal), `{"schemas":["urn:ietf:params:scim:schemas:core:2.0:Group"],"displayName":"Changed after Bulk"}`)
		changed, err := groups.Execute(f.ctx, update)
		if err != nil || changed.Status != 200 || changed.ETag == result.Version || groupID(t, changed) != result.ResourceID {
			t.Fatal("ordinary mutation did not advance the same Group after Bulk", ordinal, err)
		}
		later[ordinal] = changed
	}
	if replayed, err := service.Admit(f.ctx, request); err != nil || replayed != parent {
		t.Fatal("retry admitted a different mixed-method Bulk parent", err)
	}
	for ordinal, original := range results {
		if replayed, err := service.ExecuteChild(f.ctx, request, ordinal); err != nil || replayed != original {
			t.Fatal("later ordinary mutation replaced an original Bulk child result", ordinal, err)
		}
		current, err := groups.Execute(f.ctx, groupRequest(f, scim.GroupGet, original.ResourceID, "", "", ""))
		if err != nil || current.ETag != later[ordinal].ETag || !bytes.Equal(current.Body, later[ordinal].Body) {
			t.Fatal("Bulk replay reapplied an old update over the later Group state", ordinal, err)
		}
	}
	if replayed, err := service.ReadResult(f.ctx, request); err != nil || !bytes.Equal(replayed, wire) {
		t.Fatal("later Group versions changed retained terminal Bulk bytes or request order", err)
	}
}
