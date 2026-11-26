//go:build integration

package scimpostgres

import (
	"encoding/json"
	"testing"

	scim "github.com/faustbrian/go-scim"
)

func TestNativeGroupBulkMutationPreparationKeepsFirstSnapshot(t *testing.T) {
	f, service := bulkChildExecutionFixture(t)
	installBulkGroupMutationSchema(t, f)
	groups := groupsOnPool(t, f, f.pool)
	const schema = `"schemas":["urn:ietf:params:scim:schemas:core:2.0:Group"]`
	seed, err := groups.Execute(f.ctx, groupRequest(f, scim.GroupCreate, "", "", "bulk-prepare-group",
		`{`+schema+`,"displayName":"Original"}`))
	if err != nil || seed.Status != 201 {
		t.Fatal("create Group for a conditional Bulk mutation", err)
	}
	target := groupID(t, seed)
	body, err := json.Marshal(map[string]any{
		"schemas": []string{"urn:ietf:params:scim:api:messages:2.0:BulkRequest"},
		"Operations": []map[string]any{
			{"method": "DELETE", "path": "/Groups/" + target, "version": seed.ETag},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	request := BulkAdmissionRequest{Credential: f.bearer, Body: body}
	parent, _, err := service.admitGraph(f.ctx, request, nil)
	if err != nil {
		t.Fatal("admit one exact child before preparation", err)
	}
	rows, err := parent.bulk.childRows()
	if err != nil || len(rows) != 1 {
		t.Fatal("read admitted child custody", err)
	}
	p := nativePhase{service: service.native, admission: parent.admission,
		intent:    scim.WriteIntent{Operation: scim.GroupDelete, Scope: f.config.Scope, ResourceID: target, IfMatch: seed.ETag},
		bulkChild: &bulkChildExecution{parent: parent.original.Command, row: rows[0]}}
	type preparation struct {
		input originalInput
		err   error
	}
	results := make(chan preparation, 2)
	start := make(chan struct{})
	for range 2 {
		go func() {
			<-start
			attempt := p
			input, err := attempt.prepareBulkMutationOriginal(f.ctx, parent.original)
			results <- preparation{input, err}
		}()
	}
	close(start)
	first, second := <-results, <-results
	if first.err != nil || second.err != nil || first.input.Current == nil || second.input.Current == nil ||
		first.input.Version != second.input.Version || !first.input.At.Equal(second.input.At) || first.input.Generation != second.input.Generation ||
		first.input.Generation < 1 || first.input.Current.Version != seed.ETag || second.input.Current.Version != seed.ETag ||
		string(first.input.Command) != rows[0].Command || first.input.Admission != parent.original.Admission {
		t.Fatal("concurrent preparation failed to select one exact old snapshot", first.err, second.err)
	}
	later, err := groups.Execute(f.ctx, groupRequest(f, scim.GroupReplace, target, seed.ETag, "bulk-prepare-other-writer",
		`{`+schema+`,"displayName":"Later"}`))
	if err != nil || later.Status != 200 || later.ETag == seed.ETag {
		t.Fatal("advance Group through the normal owner", err)
	}
	replay, err := p.prepareBulkMutationOriginal(f.ctx, parent.original)
	if err != nil || replay.Current == nil || replay.Current.Version != seed.ETag || replay.Generation != first.input.Generation ||
		replay.Version != first.input.Version || !replay.At.Equal(first.input.At) || replay.Admission != parent.original.Admission {
		t.Fatal("preparing again read the later Group or changed original custody", err)
	}
}
