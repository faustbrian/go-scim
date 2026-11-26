//go:build integration

package scimpostgres

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/faustbrian/go-authorization/v3"
	identity "github.com/faustbrian/go-identity"
	scim "github.com/faustbrian/go-scim"
)

func TestNativeGroupBulkReadResultDoesNotAdmitAndReplaysCutoff(t *testing.T) {
	f, service := bulkChildExecutionFixture(t)
	body := strings.Replace(failedThenIndependentGroupBulk, `"failOnErrors":0`, `"failOnErrors":1`, 1)
	request := BulkAdmissionRequest{Credential: f.bearer, Body: []byte(body)}
	for _, phase := range []string{"absent", "admitted"} {
		if phase == "admitted" {
			var parents int
			if err := f.pool.Raw().QueryRow(f.ctx, `SELECT count(*) FROM scim.bulk_requests`).Scan(&parents); err != nil || parents != 0 {
				t.Fatal("reading an absent result must not create a parent", parents, err)
			}
			if _, err := service.Admit(f.ctx, request); err != nil {
				t.Fatal("admit the request without processing children", err)
			}
		}
		if wire, err := service.ReadResult(f.ctx, request); !errors.Is(err, scim.ErrBulkIncomplete) || len(wire) != 0 {
			t.Fatal("read must withhold every byte before the request is terminal", phase, err)
		}
	}
	if failed, err := service.ExecuteChild(f.ctx, request, 0); err != nil || failed.Status != scim.BulkChildFailed {
		t.Fatal("execute the first denial and its cutoff", failed, err)
	}
	wire, err := service.ReadResult(f.ctx, request)
	if err != nil {
		t.Fatal("read the terminal cutoff result", err)
	}
	var response struct {
		Operations []struct{ BulkID, Status, Location, Version string }
	}
	if json.Unmarshal(wire, &response) != nil || len(response.Operations) != 1 ||
		response.Operations[0].BulkID != "missing-member" || response.Operations[0].Status != "400" ||
		response.Operations[0].Location != "" || response.Operations[0].Version != "" {
		t.Fatal("the terminal response contains only the processed denial, without a Group result")
	}
	if again, err := service.ReadResult(f.ctx, request); err != nil || !bytes.Equal(wire, again) {
		t.Fatal("an exact repeat must return the same terminal bytes", err)
	}
	f.deny.Store(true)
	if denied, err := service.ReadResult(f.ctx, request); protocolStatus(err) != 403 || len(denied) != 0 {
		t.Fatal("read must re-authorize before disclosing any retained results", err)
	}
}

func TestNativeGroupBulkReadResultKeepsOriginalOrderWithoutAttachingKey(t *testing.T) {
	f, service := bulkChildExecutionFixture(t)
	request := BulkAdmissionRequest{Credential: f.bearer, Body: []byte(failedThenIndependentGroupBulk)}
	if denied, err := service.ExecuteChild(f.ctx, request, 0); err != nil || denied.Status != scim.BulkChildFailed {
		t.Fatal("record the independent denial", err)
	}
	if wire, err := service.ReadResult(f.ctx, request); !errors.Is(err, scim.ErrBulkIncomplete) || len(wire) != 0 {
		t.Fatal("a processed error does not expose a partial response", err)
	}
	created, err := service.ExecuteChild(f.ctx, request, 1)
	if err != nil || created.Status != scim.BulkChildSucceeded {
		t.Fatal("process the independent successor", err)
	}
	wire, err := service.ReadResult(f.ctx, request)
	if err != nil {
		t.Fatal("read both original checkpoints", err)
	}
	var response struct {
		Operations []struct{ BulkID, Status, Location, Version string }
	}
	if json.Unmarshal(wire, &response) != nil || len(response.Operations) != 2 ||
		response.Operations[0].BulkID != "missing-member" || response.Operations[0].Status != "400" ||
		response.Operations[1].BulkID != "independent" || response.Operations[1].Status != "201" ||
		response.Operations[1].Version != string(created.Version) || response.Operations[1].Location != f.config.BaseURL+"/Groups/"+created.ResourceID {
		t.Fatal("wire result must preserve declaration order and exactly the stored success version and location")
	}
	// Bulk replay permission alone must not disclose a settled Group child.
	config := f.config
	originalPolicy := config.Authorization
	config.Authorization = configuredPolicy(func(ctx context.Context, d authorization.DecisionContext) (authorization.Decision, error) {
		if d.Request.Action == authorization.Action(scim.GroupCreate) {
			return authorization.Decision{Outcome: authorization.Deny, Revision: d.PolicyRevision}, nil
		}
		return originalPolicy.Decide(ctx, d)
	})
	native, err := NewService(f.pool, config, f.keys)
	if err != nil {
		t.Fatal("reopen the same configured connection with current child policy", err)
	}
	groups, err := NewGroupsService(native, scim.DefaultGroupMembers)
	if err != nil {
		t.Fatal(err)
	}
	limited, err := NewGroupBulkService(groups, scim.DefaultBulkPolicy(), scim.DefaultBulkResponsePolicy())
	if err != nil {
		t.Fatal(err)
	}
	if denied, err := limited.ReadResult(f.ctx, request); protocolStatus(err) != 403 || len(denied) != 0 {
		t.Fatal("Group permission is checked before releasing the entire terminal body", err)
	}

	key, err := identity.NewIdempotencyKey([]byte("synthetic-read-only-bulk-key"))
	if err != nil {
		t.Fatal(err)
	}
	request.IdempotencyKey = &key
	if keyed, err := service.ReadResult(f.ctx, request); err != nil || !bytes.Equal(wire, keyed) {
		t.Fatal("absence of an optional key must not hide the canonical result", err)
	}
	other := request
	other.Body = []byte(strings.Replace(string(request.Body), `"Independent"`, `"Other Group"`, 1))
	if _, err := service.Admit(f.ctx, other); err != nil {
		t.Fatal("read must not attach the supplied retry key", err)
	}
	if conflict, err := service.ReadResult(f.ctx, request); protocolStatus(err) != 409 || len(conflict) != 0 {
		t.Fatal("a retained retry-key conflict must withhold the terminal body", err)
	}
}
