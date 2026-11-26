//go:build integration

package scimpostgres

import (
	"bytes"
	"context"
	"encoding/json"
	"testing"

	scim "github.com/faustbrian/go-scim"
)

type nativeBulkRunner interface {
	ExecuteBulk(context.Context, BulkAdmissionRequest) ([]byte, error)
}

func nativeBulkExecutionFixture(t *testing.T) (*nativeFixture, *BulkService, nativeBulkRunner) {
	t.Helper()
	if _, ok := any((*BulkService)(nil)).(nativeBulkRunner); !ok {
		t.Fatal("BulkService is missing synchronous ExecuteBulk execution")
	}
	f, _ := bulkChildExecutionFixture(t)
	groups := groupsOnPool(t, f, f.pool)
	service, err := NewBulkService(groups, scim.DefaultBulkPolicy(), scim.DefaultBulkResponsePolicy())
	if err != nil {
		t.Fatal("select native Bulk execution", err)
	}
	return f, service, any(service).(nativeBulkRunner)
}

func TestNativeBulkExecuteForwardUserDependencyRetainsOrderedResults(t *testing.T) {
	f, service, runner := nativeBulkExecutionFixture(t)
	request := BulkAdmissionRequest{Credential: f.bearer, Body: []byte(mixedCreateBulkFixture)}
	parent, err := service.Admit(f.ctx, request)
	if err != nil || parent.ChildCount != 2 {
		t.Fatal("retain the original forward-reference graph", err)
	}
	group := originalBulkChild(t, f, parent, 0)
	user := originalBulkChild(t, f, parent, 1)
	wire, err := runner.ExecuteBulk(f.ctx, request)
	if err != nil {
		t.Fatal("one synchronous invocation must settle the declared-later User before its Group", err)
	}
	createdGroup := scim.BulkChildResult{Status: scim.BulkChildSucceeded, Code: 201, ResourceID: group.resource, Version: bulkChildVersion(group.command)}
	createdUser := scim.BulkChildResult{Status: scim.BulkChildSucceeded, Code: 201, ResourceID: user.resource, Version: bulkChildVersion(user.command)}
	requireCommittedMixedBulkUser(t, f, parent, user, createdUser)
	projection := requireCommittedBulkChild(t, f, parent, 0, group, createdGroup)
	members, ok := projection.Attributes["members"].([]any)
	if !ok || len(members) != 1 {
		t.Fatal("the original Group must contain exactly its forward User member")
	}
	member, ok := members[0].(map[string]any)
	if !ok || member["type"] != "User" || member["value"] != user.resource {
		t.Fatal("the Group must resolve its member to the original User allocation")
	}
	var response struct {
		Operations []struct{ Method, BulkID, Status, Location, Version string }
	}
	if err := json.Unmarshal(wire, &response); err != nil || len(response.Operations) != 2 {
		t.Fatal("decode both original operation results", err)
	}
	for ordinal, want := range []struct{ bulkID, location, version string }{
		{"new-group", f.config.BaseURL + "/Groups/" + group.resource, string(createdGroup.Version)},
		{"new-user", f.config.BaseURL + "/Users/" + user.resource, string(createdUser.Version)},
	} {
		got := response.Operations[ordinal]
		if got.Method != "POST" || got.BulkID != want.bulkID || got.Status != "201" || got.Location != want.location || got.Version != want.version {
			t.Fatal("synchronous results must retain declaration order and original IDs and versions", ordinal)
		}
	}
	if retained, err := service.ReadResult(f.ctx, request); err != nil || !bytes.Equal(retained, wire) {
		t.Fatal("the synchronous body must equal the original retained terminal body", err)
	}
	for range 2 {
		replay := BulkAdmissionRequest{Credential: f.bearer, Body: []byte(mixedCreateBulkFixture)}
		if retained, err := runner.ExecuteBulk(f.ctx, replay); err != nil || !bytes.Equal(retained, wire) {
			t.Fatal("headerless exact replay must return identical terminal bytes", err)
		}
	}
	requireMixedBulkCounts(t, f, [8]int{1, 1, 1, 3, 3, 3, 1, 2})
}

func TestNativeBulkExecuteCommitsRetainedGroupCycleOnce(t *testing.T) {
	f, service, runner := nativeBulkExecutionFixture(t)
	request := BulkAdmissionRequest{Credential: f.bearer, Body: []byte(cyclicGroupBulkFixture)}
	parent, err := service.Admit(f.ctx, request)
	if err != nil || parent.ChildCount != 2 {
		t.Fatal("retain the complete Group-only strongly connected component", err)
	}
	originals := [2]admittedBulkChild{originalBulkChild(t, f, parent, 0), originalBulkChild(t, f, parent, 1)}
	wire, err := runner.ExecuteBulk(f.ctx, request)
	if err != nil {
		t.Fatal("one synchronous invocation must commit the complete Group-only cycle", err)
	}
	var response struct {
		Operations []struct{ Method, BulkID, Status, Location, Version string }
	}
	if err := json.Unmarshal(wire, &response); err != nil || len(response.Operations) != 2 {
		t.Fatal("decode both original SCC results", err)
	}
	for ordinal, original := range originals {
		result := scim.BulkChildResult{Status: scim.BulkChildSucceeded, Code: 201, ResourceID: original.resource, Version: bulkChildVersion(original.command)}
		projection := requireCommittedBulkChild(t, f, parent, ordinal, original, result)
		members, ok := projection.Attributes["members"].([]any)
		if !ok || len(members) != 1 {
			t.Fatal("each original cyclic Group must retain one member", ordinal)
		}
		member, ok := members[0].(map[string]any)
		if !ok || member["type"] != "Group" || member["value"] != originals[1-ordinal].resource {
			t.Fatal("the SCC must resolve both original allocations", ordinal)
		}
		got := response.Operations[ordinal]
		if got.Method != "POST" || got.BulkID != []string{"first", "second"}[ordinal] || got.Status != "201" || got.Location != f.config.BaseURL+"/Groups/"+original.resource || got.Version != string(result.Version) {
			t.Fatal("the SCC body must retain original declaration order, IDs and versions", ordinal)
		}
	}
	if replay, err := runner.ExecuteBulk(f.ctx, request); err != nil || !bytes.Equal(replay, wire) {
		t.Fatal("exact SCC replay must return identical bytes without another component commit", err)
	}
	requireMixedBulkCounts(t, f, [8]int{0, 0, 2, 3, 3, 3, 1, 2})
}
