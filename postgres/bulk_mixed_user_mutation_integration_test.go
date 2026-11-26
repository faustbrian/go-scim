//go:build integration

package scimpostgres

import (
	"bytes"
	"encoding/json"
	"strconv"
	"testing"

	identity "github.com/faustbrian/go-identity"
	scim "github.com/faustbrian/go-scim"
)

func mixedUserMutationFixture(t *testing.T) (*nativeFixture, *BulkService, *GroupBulkService) {
	t.Helper()
	f, groupOnly := bulkChildExecutionFixture(t)
	installBulkGroupMutationSchema(t, f)
	groups := groupsOnPool(t, f, f.pool)
	service, err := NewBulkService(groups, scim.DefaultBulkPolicy(), scim.DefaultBulkResponsePolicy())
	if err != nil {
		t.Fatal("select native mixed Bulk explicitly", err)
	}
	return f, service, groupOnly
}

func mixedUserMutationRequest(t *testing.T, f *nativeFixture, operations []map[string]any) BulkAdmissionRequest {
	t.Helper()
	body, err := json.Marshal(map[string]any{
		"schemas":    []string{"urn:ietf:params:scim:api:messages:2.0:BulkRequest"},
		"Operations": operations,
	})
	if err != nil {
		t.Fatal("encode exact original User mutations", err)
	}
	return BulkAdmissionRequest{Credential: f.bearer, Body: body}
}

func readMixedMutationUser(t *testing.T, f *nativeFixture, id string) scim.Response {
	t.Helper()
	response, err := f.service.Execute(f.ctx, scim.Request{Operation: scim.UserGet, Credential: f.bearer, ResourceID: id})
	if err != nil || response.Status != 200 || parseNativeUser(t, response).ID != id {
		t.Fatal("read the exact native User target", err)
	}
	return response
}

func requireMixedUserMutationEffects(t *testing.T, f *nativeFixture, parent BulkAdmission, results []scim.BulkChildResult) {
	t.Helper()
	for ordinal, result := range results {
		var state, status string
		var code, commands, audits, events int
		var resource, version *string
		err := f.pool.Raw().QueryRow(f.ctx, `SELECT b.status,b.result_code,b.result_resource_id,b.result_version,c.state,
 (SELECT count(*) FROM identity.commands j WHERE j.command_id=c.command_id),
 (SELECT count(*) FROM audit.identity_command_bindings a JOIN audit.records r ON r.record_id=a.event_id
  WHERE a.command_id=c.command_id AND r.action='identity.scim.bulk_apply_child'
  AND r.subject_type='scim_bulk_child' AND r.subject_id=b.command_id AND r.correlation_id=b.parent_id),
 (SELECT count(*) FROM public.identity_outbox_bindings o WHERE o.command_id=c.command_id)
 FROM scim.bulk_children b JOIN identity.commands c
 ON c.command_id=decode(translate(b.command_id,'-_','+/')||'==','base64')
 WHERE b.parent_id=$1 AND b.ordinal=$2`, string(parent.CommandID), ordinal).Scan(
			&status, &code, &resource, &version, &state, &commands, &audits, &events)
		wantStatus, wantState, wantEvents := "succeeded", "committed", 1
		if result.Status == scim.BulkChildFailed {
			wantStatus, wantState, wantEvents = "failed", "aborted", 0
		}
		if err != nil || status != wantStatus || code != result.Code || state != wantState || commands != 1 || audits != 1 || events != wantEvents {
			t.Fatal("retain one original child checkpoint, journal, audit and appropriate outbox effect", ordinal, status, code, state, commands, audits, events, err)
		}
		if result.ResourceID == "" {
			if resource != nil {
				t.Fatal("failed User mutation retained a successful resource ID", ordinal)
			}
		} else if resource == nil || *resource != result.ResourceID {
			t.Fatal("checkpoint changed the exact original User target", ordinal)
		}
		if result.Version == "" {
			if version != nil {
				t.Fatal("empty-version result acquired a checkpoint version", ordinal)
			}
		} else if version == nil || scim.Version(*version) != result.Version {
			t.Fatal("checkpoint lost the exact original result ETag", ordinal)
		}
	}
}

func TestNativeBulkMixedUserMutationsCommitAndRetainOriginalResults(t *testing.T) {
	f, service, groupOnly := mixedUserMutationFixture(t)
	ids := make([]string, 4)
	seeds := make([]scim.Response, len(ids))
	for i := range ids {
		ids[i] = createNativeNamed(t, f, "MixedMutationUser"+strconv.Itoa(i), "Original display")
		seeds[i] = readMixedMutationUser(t, f, ids[i])
	}
	operations := []map[string]any{
		{"method": "POST", "path": "/Groups", "bulkId": "mixed-group", "data": json.RawMessage(`{"schemas":["urn:ietf:params:scim:schemas:core:2.0:Group"],"displayName":"Mixed operation sibling"}`)},
		{"method": "PUT", "path": "/Users/" + ids[0], "version": seeds[0].ETag, "bulkId": "replacement", "data": json.RawMessage(`{"schemas":["urn:ietf:params:scim:schemas:core:2.0:User"],"userName":"MixedReplacedUser","displayName":"Replacement display"}`)},
		{"method": "PATCH", "path": "/Users/" + ids[1], "version": seeds[1].ETag, "data": json.RawMessage(`{"schemas":["urn:ietf:params:scim:api:messages:2.0:PatchOp"],"Operations":[{"op":"replace","path":"displayName","value":"Patched display"}]}`)},
		{"method": "PATCH", "path": "/Users/" + ids[2], "version": seeds[2].ETag, "data": json.RawMessage(`{"schemas":["urn:ietf:params:scim:api:messages:2.0:PatchOp"],"Operations":[{"op":"replace","path":"displayName","value":"Original display"}]}`)},
		{"method": "DELETE", "path": "/Users/" + ids[3], "version": seeds[3].ETag},
	}
	request := mixedUserMutationRequest(t, f, operations)
	if rejected, err := groupOnly.Admit(f.ctx, request); protocolStatus(err) != 501 || rejected != (BulkAdmission{}) {
		t.Fatal("the Group-only adapter must not opt into native User mutations", err)
	}
	parent, err := service.Admit(f.ctx, request)
	if err != nil || parent.ChildCount != len(operations) {
		t.Fatal("admit the explicitly selected mixed Group create and conditional User mutations", err)
	}
	for i, id := range ids {
		current := readMixedMutationUser(t, f, id)
		if current.ETag != seeds[i].ETag || !bytes.Equal(current.Body, seeds[i].Body) {
			t.Fatal("admission executed a User mutation", i)
		}
	}
	results := make([]scim.BulkChildResult, len(operations))
	for ordinal := range results {
		result, err := service.ExecuteChild(f.ctx, request, ordinal)
		wantCode := 200
		if ordinal == 0 {
			wantCode = 201
		} else if ordinal == 4 {
			wantCode = 204
		}
		if err != nil || result.Status != scim.BulkChildSucceeded || result.Code != wantCode || result.ResourceID == "" || result.SCIMType != "" || result.SkipReason != scim.BulkSkipNone {
			t.Fatal("commit exactly the selected original mixed child", ordinal, result, err)
		}
		if ordinal > 0 && result.ResourceID != ids[ordinal-1] {
			t.Fatal("User mutation changed the admitted target", ordinal)
		}
		if ordinal == 4 {
			if result.Version != "" {
				t.Fatal("DELETE invented a result ETag")
			}
		} else if !nativeVersion(result.Version) {
			t.Fatal("successful create or update lost its strong result ETag", ordinal)
		}
		results[ordinal] = result
	}
	if results[1].Version == seeds[0].ETag || results[2].Version == seeds[1].ETag || results[3].Version != seeds[2].ETag {
		t.Fatal("changed PUT/PATCH must advance ETags and no-op PATCH must retain its original ETag")
	}
	replaced := readMixedMutationUser(t, f, ids[0])
	patched := readMixedMutationUser(t, f, ids[1])
	if replaced.ETag != results[1].Version || patched.ETag != results[2].Version {
		t.Fatal("ordinary User reads do not expose the committed Bulk versions")
	}
	assertNativeMappedFields(t, f, ids[0], "MixedReplacedUser", "Replacement display")
	assertNativeMappedFields(t, f, ids[1], "MixedMutationUser1", "Patched display")
	var replacedDoc, patchedDoc map[string]json.RawMessage
	if json.Unmarshal(replaced.Body, &replacedDoc) != nil || json.Unmarshal(patched.Body, &patchedDoc) != nil || replacedDoc["externalId"] != nil || !bytes.Equal(patchedDoc["externalId"], []byte(`"shared-correlation"`)) {
		t.Fatal("PUT must remove omitted attributes while PATCH preserves unaffected attributes")
	}
	unchanged := readMixedMutationUser(t, f, ids[2])
	var generation int64
	if err := f.pool.Raw().QueryRow(f.ctx, `SELECT generation FROM scim.users WHERE resource_id=$1`, ids[2]).Scan(&generation); err != nil || generation != 1 || !bytes.Equal(unchanged.Body, seeds[2].Body) {
		t.Fatal("no-op PATCH changed generation or original representation metadata", err)
	}
	if _, err := f.service.Execute(f.ctx, scim.Request{Operation: scim.UserGet, Credential: f.bearer, ResourceID: ids[3]}); protocolStatus(err) != 404 {
		t.Fatal("Bulk-deleted User remains readable", err)
	}
	var tombstone, emptyProjection bool
	if err := f.pool.Raw().QueryRow(f.ctx, `SELECT generation,deleted_at IS NOT NULL,resource=convert_to('null','UTF8') FROM scim.users WHERE resource_id=$1`, ids[3]).Scan(&generation, &tombstone, &emptyProjection); err != nil || generation != 2 || !tombstone || !emptyProjection {
		t.Fatal("Bulk DELETE did not tombstone its exact native User once", err)
	}
	if _, err := f.service.directory.Get(f.ctx, identity.GetUserQuery{TenantID: f.config.Scope.TenantID, UserID: identity.UserID(ids[3])}); err != nil {
		t.Fatal("Bulk DELETE removed the kernel identity instead of its SCIM projection", err)
	}
	wire, err := service.ReadResult(f.ctx, request)
	if err != nil {
		t.Fatal("read terminal mixed User mutation results", err)
	}
	var response struct {
		Operations []struct {
			Method, Status, Location, Version string
			BulkID                            *string `json:"bulkId"`
			Response                          json.RawMessage
		}
	}
	if err := json.Unmarshal(wire, &response); err != nil || len(response.Operations) != len(results) {
		t.Fatal("decode complete ordered mixed User mutation response", err)
	}
	for ordinal, operation := range response.Operations {
		result := results[ordinal]
		path := "/Users/"
		if ordinal == 0 {
			path = "/Groups/"
		}
		if operation.Method != operations[ordinal]["method"] || operation.Status != strconv.Itoa(result.Code) || operation.Location != f.config.BaseURL+path+result.ResourceID || operation.Version != string(result.Version) || len(operation.Response) != 0 {
			t.Fatal("terminal response changed operation order, resource type or exact original version", ordinal)
		}
		bulkID, supplied := operations[ordinal]["bulkId"]
		if supplied && (operation.BulkID == nil || *operation.BulkID != bulkID) || !supplied && operation.BulkID != nil {
			t.Fatal("terminal response changed an original optional bulkId", ordinal)
		}
	}
	later := make([]scim.Response, 3)
	for i := range later {
		changed, err := f.service.Execute(f.ctx, scim.Request{Operation: scim.UserPatch, Credential: f.bearer, ResourceID: ids[i], IfMatch: results[i+1].Version,
			ContentType: "application/scim+json", Body: []byte(`{"schemas":["urn:ietf:params:scim:api:messages:2.0:PatchOp"],"Operations":[{"op":"replace","path":"displayName","value":"Changed after Bulk"}]}`)})
		if err != nil || changed.Status != 200 || changed.ETag == results[i+1].Version {
			t.Fatal("advance the native User through its ordinary service after Bulk", i, err)
		}
		later[i] = changed
	}
	for range 2 {
		if replay, err := service.Admit(f.ctx, request); err != nil || replay != parent {
			t.Fatal("exact retry replaced the original mixed parent", err)
		}
		for ordinal, original := range results {
			if replay, err := service.ExecuteChild(f.ctx, request, ordinal); err != nil || replay != original {
				t.Fatal("later native state replaced an original retained child result", ordinal, err)
			}
		}
		if replay, err := service.ReadResult(f.ctx, request); err != nil || !bytes.Equal(replay, wire) {
			t.Fatal("later native versions changed the exact terminal response bytes", err)
		}
	}
	for i, expected := range later {
		current := readMixedMutationUser(t, f, ids[i])
		if current.ETag != expected.ETag || !bytes.Equal(current.Body, expected.Body) {
			t.Fatal("replay reapplied an old User mutation over later ordinary state", i)
		}
	}
	requireMixedUserMutationEffects(t, f, parent, results)
}

func TestNativeBulkMixedUserMutationsRetainPreconditionAndTargetDenials(t *testing.T) {
	for _, scenario := range []struct {
		name string
		code int
	}{
		{"missing-version", 428}, {"wrong-version", 412}, {"stale-after-admission", 412}, {"missing-target", 404}, {"Group-is-not-a-User", 404},
	} {
		t.Run(scenario.name, func(t *testing.T) {
			f, service, _ := mixedUserMutationFixture(t)
			methods := []string{"PUT", "PATCH", "DELETE"}
			ids := make([]string, len(methods))
			preserved := make([]scim.Response, len(methods))
			operations := make([]map[string]any, len(methods))
			for ordinal, method := range methods {
				ids[ordinal] = createNativeNamed(t, f, "MixedDeniedUser"+strconv.Itoa(ordinal), "Preserved display")
				preserved[ordinal] = readMixedMutationUser(t, f, ids[ordinal])
				target, version := ids[ordinal], preserved[ordinal].ETag
				switch scenario.name {
				case "missing-version":
					version = ""
				case "wrong-version":
					version = `"valid-but-unknown"`
				case "missing-target":
					missing, err := identity.NewSubjectID()
					if err != nil {
						t.Fatal(err)
					}
					target = string(missing)
				case "Group-is-not-a-User":
					groups := groupsOnPool(t, f, f.pool)
					group, err := groups.Execute(f.ctx, groupRequest(f, scim.GroupCreate, "", "", "wrong-user-target-"+strconv.Itoa(ordinal), `{"schemas":["urn:ietf:params:scim:schemas:core:2.0:Group"],"displayName":"Not a User"}`))
					if err != nil {
						t.Fatal("seed a valid resource with the wrong target type", err)
					}
					target, version = groupID(t, group), group.ETag
				}
				operation := map[string]any{"method": method, "path": "/Users/" + target}
				if version != "" {
					operation["version"] = version
				}
				switch method {
				case "PUT":
					operation["data"] = json.RawMessage(`{"schemas":["urn:ietf:params:scim:schemas:core:2.0:User"],"userName":"MustNotReplace","displayName":"Must not apply"}`)
				case "PATCH":
					operation["data"] = json.RawMessage(`{"schemas":["urn:ietf:params:scim:api:messages:2.0:PatchOp"],"Operations":[{"op":"replace","path":"displayName","value":"Must not apply"}]}`)
				}
				operations[ordinal] = operation
			}
			request := mixedUserMutationRequest(t, f, operations)
			parent, err := service.Admit(f.ctx, request)
			if err != nil || parent.ChildCount != len(methods) {
				t.Fatal("admit exact User mutations before independently settling native denials", err)
			}
			if scenario.name == "stale-after-admission" {
				for ordinal, id := range ids {
					changed, err := f.service.Execute(f.ctx, scim.Request{Operation: scim.UserPatch, Credential: f.bearer, ResourceID: id, IfMatch: preserved[ordinal].ETag,
						ContentType: "application/scim+json", Body: []byte(`{"schemas":["urn:ietf:params:scim:api:messages:2.0:PatchOp"],"Operations":[{"op":"replace","path":"displayName","value":"Winning ordinary update"}]}`)})
					if err != nil || changed.ETag == preserved[ordinal].ETag {
						t.Fatal("advance the exact target after Bulk admission", err)
					}
					preserved[ordinal] = changed
				}
			}
			results := make([]scim.BulkChildResult, len(methods))
			for ordinal := range results {
				results[ordinal] = scim.BulkChildResult{Status: scim.BulkChildFailed, Code: scenario.code}
				for range 2 {
					if result, err := service.ExecuteChild(f.ctx, request, ordinal); err != nil || result != results[ordinal] {
						t.Fatal("retain the exact original native no-effect denial", methods[ordinal], result, err)
					}
				}
				current := readMixedMutationUser(t, f, ids[ordinal])
				if current.ETag != preserved[ordinal].ETag || !bytes.Equal(current.Body, preserved[ordinal].Body) {
					t.Fatal("a denied Bulk mutation changed its native User", methods[ordinal])
				}
			}
			wire, err := service.ReadResult(f.ctx, request)
			if err != nil {
				t.Fatal("read terminal native User denials", err)
			}
			var response struct {
				Operations []struct {
					Method, Status, Location, Version string
					Response                          struct {
						Schemas  []string
						Status   string
						SCIMType string `json:"scimType"`
					}
				}
			}
			if json.Unmarshal(wire, &response) != nil || len(response.Operations) != len(methods) {
				t.Fatal("decode ordered original User denials")
			}
			for ordinal, result := range response.Operations {
				if result.Method != methods[ordinal] || result.Status != strconv.Itoa(scenario.code) || result.Location != f.config.BaseURL+operations[ordinal]["path"].(string) || result.Version != "" ||
					result.Response.Status != result.Status || result.Response.SCIMType != "" || len(result.Response.Schemas) != 1 || result.Response.Schemas[0] != "urn:ietf:params:scim:api:messages:2.0:Error" {
					t.Fatal("terminal denial lost its original target, order or SCIM error semantics", ordinal)
				}
			}
			if replay, err := service.ReadResult(f.ctx, request); err != nil || !bytes.Equal(replay, wire) {
				t.Fatal("exact native denial replay changed terminal bytes", err)
			}
			var failed int
			if err := f.pool.Raw().QueryRow(f.ctx, `SELECT failed_count FROM scim.bulk_requests WHERE parent_id=$1`, string(parent.CommandID)).Scan(&failed); err != nil || failed != len(methods) {
				t.Fatal("denial replay counted one failed child more than once", failed, err)
			}
			requireMixedUserMutationEffects(t, f, parent, results)
		})
	}
}

func TestNativeBulkMixedUserMutationRetainsFailedCreateTargetDependency(t *testing.T) {
	f, service, _ := mixedUserMutationFixture(t)
	existing := createNativeNamed(t, f, "MixedFailedTargetOwner", "Ordinary username owner")
	before := readMixedMutationUser(t, f, existing)
	request := mixedUserMutationRequest(t, f, []map[string]any{
		{"method": "POST", "path": "/Users", "bulkId": "failed-user", "data": json.RawMessage(`{"schemas":["urn:ietf:params:scim:schemas:core:2.0:User"],"userName":"MixedFailedTargetOwner","displayName":"Must not create"}`)},
		{"method": "PATCH", "path": "/Users/bulkId:failed-user", "version": before.ETag, "data": json.RawMessage(`{"schemas":["urn:ietf:params:scim:api:messages:2.0:PatchOp"],"Operations":[{"op":"replace","path":"displayName","value":"Must not patch"}]}`)},
	})
	parent, err := service.Admit(f.ctx, request)
	if err != nil || parent.ChildCount != 2 {
		t.Fatal("admit a User mutation targeting its declared User create", err)
	}
	original := originalBulkChild(t, f, parent, 0)
	if original.resource == existing {
		t.Fatal("the failed create must not resolve to the ordinary username owner")
	}
	if result, err := service.ExecuteChild(f.ctx, request, 1); protocolStatus(err) != 409 || result != (scim.BulkChildResult{}) {
		t.Fatal("the User mutation must wait for its exact uncommitted target", result, err)
	}
	want := []scim.BulkChildResult{
		{Status: scim.BulkChildFailed, Code: 409, SCIMType: "uniqueness"},
		{Status: scim.BulkChildFailed, Code: 424},
	}
	for ordinal, expected := range want {
		for range 2 {
			if result, err := service.ExecuteChild(f.ctx, request, ordinal); err != nil || result != expected {
				t.Fatal("retain the failed create and its dependent User mutation independently", ordinal, result, err)
			}
		}
	}
	current := readMixedMutationUser(t, f, existing)
	if current.ETag != before.ETag || !bytes.Equal(current.Body, before.Body) {
		t.Fatal("a failed symbolic target changed the ordinary username owner")
	}
	var projections, failed int
	if err := f.pool.Raw().QueryRow(f.ctx, `SELECT (SELECT count(*) FROM scim.users),failed_count FROM scim.bulk_requests WHERE parent_id=$1`, string(parent.CommandID)).Scan(&projections, &failed); err != nil || projections != 1 || failed != 2 {
		t.Fatal("failed create and dependent mutation must create no User projection or duplicate failure", projections, failed, err)
	}
	wire, err := service.ReadResult(f.ctx, request)
	if err != nil {
		t.Fatal("read retained failed User target dependency", err)
	}
	var response struct {
		Operations []struct {
			Method, Status, Location, Version string
			Response                          struct{ Status, SCIMType string }
		}
	}
	if json.Unmarshal(wire, &response) != nil || len(response.Operations) != 2 || response.Operations[0].Method != "POST" || response.Operations[0].Status != "409" || response.Operations[0].Response.SCIMType != "uniqueness" ||
		response.Operations[1].Method != "PATCH" || response.Operations[1].Status != "424" || response.Operations[1].Response.Status != "424" {
		t.Fatal("terminal wire must retain the original ordered uniqueness and failed-dependency results")
	}
	if response.Operations[0].Location != "" || response.Operations[0].Version != "" {
		t.Fatal("a failed create must not carry a resource location or version")
	}
	if response.Operations[1].Location != f.config.BaseURL+"/Users/"+original.resource || response.Operations[1].Version != "" {
		t.Fatal("the failed PATCH must identify its original resolved endpoint without a committed version")
	}
	if replay, err := service.ReadResult(f.ctx, request); err != nil || !bytes.Equal(replay, wire) {
		t.Fatal("failed User target dependency replay changed terminal bytes", err)
	}
	requireMixedUserMutationEffects(t, f, parent, want)
}

func TestNativeBulkMixedUserReplaceRetainsUsernameUniquenessDenial(t *testing.T) {
	f, service, _ := mixedUserMutationFixture(t)
	owner := createNativeNamed(t, f, "MixedReservedUsername", "Existing username owner")
	target := createNativeNamed(t, f, "MixedReplacementTarget", "Preserved target display")
	ownerBefore := readMixedMutationUser(t, f, owner)
	targetBefore := readMixedMutationUser(t, f, target)
	request := mixedUserMutationRequest(t, f, []map[string]any{
		{"method": "PUT", "path": "/Users/" + target, "version": targetBefore.ETag, "data": json.RawMessage(`{"schemas":["urn:ietf:params:scim:schemas:core:2.0:User"],"userName":"MixedReservedUsername","displayName":"Must not replace"}`)},
	})
	parent, err := service.Admit(f.ctx, request)
	if err != nil || parent.ChildCount != 1 {
		t.Fatal("admit a versioned replacement before settling native username uniqueness", err)
	}
	want := scim.BulkChildResult{Status: scim.BulkChildFailed, Code: 409, SCIMType: "uniqueness"}
	for range 2 {
		if result, err := service.ExecuteChild(f.ctx, request, 0); err != nil || result != want {
			t.Fatal("retain the real native replacement uniqueness denial", result, err)
		}
	}
	for id, before := range map[string]scim.Response{owner: ownerBefore, target: targetBefore} {
		current := readMixedMutationUser(t, f, id)
		if current.ETag != before.ETag || !bytes.Equal(current.Body, before.Body) {
			t.Fatal("a username uniqueness denial changed its owner or replacement target")
		}
	}
	assertNativeMappedFields(t, f, target, "MixedReplacementTarget", "Preserved target display")
	var projections, failed int
	if err := f.pool.Raw().QueryRow(f.ctx, `SELECT (SELECT count(*) FROM scim.users),failed_count FROM scim.bulk_requests WHERE parent_id=$1`, string(parent.CommandID)).Scan(&projections, &failed); err != nil || projections != 2 || failed != 1 {
		t.Fatal("a failed replacement created a projection or counted a repeated denial", projections, failed, err)
	}
	wire, err := service.ReadResult(f.ctx, request)
	if err != nil {
		t.Fatal("read the retained native uniqueness denial", err)
	}
	var response struct {
		Operations []struct {
			Method, Status, Location, Version string
			Response                          struct{ Status, SCIMType string }
		}
	}
	if json.Unmarshal(wire, &response) != nil || len(response.Operations) != 1 || response.Operations[0].Method != "PUT" || response.Operations[0].Status != "409" || response.Operations[0].Location != f.config.BaseURL+"/Users/"+target ||
		response.Operations[0].Version != "" || response.Operations[0].Response.Status != "409" || response.Operations[0].Response.SCIMType != "uniqueness" {
		t.Fatal("terminal replacement denial must preserve its exact target and SCIM uniqueness error")
	}
	if replay, err := service.ReadResult(f.ctx, request); err != nil || !bytes.Equal(replay, wire) {
		t.Fatal("native uniqueness denial replay changed terminal bytes", err)
	}
	requireMixedUserMutationEffects(t, f, parent, []scim.BulkChildResult{want})
}
