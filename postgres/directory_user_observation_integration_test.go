//go:build integration

package scimpostgres

import (
	"context"
	"encoding/json"
	"reflect"
	"testing"
	"time"

	identity "github.com/faustbrian/go-identity"
	scim "github.com/faustbrian/go-scim"
)

func createDirectoryObservedUser(t *testing.T, f *nativeFixture, name string) (DirectoryUserTarget, scim.Response) {
	t.Helper()
	response, err := f.service.Execute(f.ctx, scim.Request{
		Operation: scim.UserCreate, Credential: f.bearer, ContentType: "application/scim+json",
		Body: []byte(`{"schemas":["urn:ietf:params:scim:schemas:core:2.0:User"],"userName":"` + name + `","displayName":"Directory observation","active":true}`),
	})
	if err != nil {
		t.Fatal("create native source User", err)
	}
	id := parseNativeUser(t, response).ID
	return DirectoryUserTarget{ResourceID: id, UserID: identity.UserID(id)}, response
}

func TestReadDirectoryUserStatesReturnsExactCurrentStatesInInputOrder(t *testing.T) {
	f, groups := nativeGroupsFixture(t)
	active, activeResponse := createDirectoryObservedUser(t, f, "ObservedActive")
	inactive, inactiveResponse := createDirectoryObservedUser(t, f, "ObservedInactive")
	deleted, deletedResponse := createDirectoryObservedUser(t, f, "ObservedDeleted")
	observed, err := groups.ObserveDirectorySource(f.ctx, f.config.Scope)
	if err != nil {
		t.Fatal(err)
	}
	bindings, err := observed.Bindings()
	if err != nil {
		t.Fatal(err)
	}
	inactiveResponse, err = f.service.Execute(f.ctx, scim.Request{
		Operation: scim.UserPatch, Credential: f.bearer, ResourceID: inactive.ResourceID, IfMatch: inactiveResponse.ETag,
		ContentType: "application/scim+json", Body: []byte(`{"schemas":["urn:ietf:params:scim:api:messages:2.0:PatchOp"],"Operations":[{"op":"replace","path":"active","value":false}]}`),
	})
	if err != nil {
		t.Fatal("deactivate native source User", err)
	}
	if _, err := f.service.Execute(f.ctx, scim.Request{Operation: scim.UserDelete, Credential: f.bearer, ResourceID: deleted.ResourceID, IfMatch: deletedResponse.ETag}); err != nil {
		t.Fatal("delete native source User", err)
	}
	var deleteCommand string
	if err := f.pool.Raw().QueryRow(f.ctx, `SELECT command_id FROM scim.users WHERE resource_id=$1 AND deleted_at IS NOT NULL`, deleted.ResourceID).Scan(&deleteCommand); err != nil {
		t.Fatal(err)
	}
	// Imported local identity mappings need not use the native resource ID's
	// canonical form. Preserve that retained mapping even after deletion.
	const canonicalUser = "01ARZ3NDEKTSV4RRFFQ69G5FAV"
	if _, err := f.pool.Raw().Exec(f.ctx, `INSERT INTO identity.users(tenant_id,user_id,status,version) VALUES($1,$2,'active',1)`, string(f.config.Scope.TenantID), canonicalUser); err != nil {
		t.Fatal(err)
	}
	if _, err := f.pool.Raw().Exec(f.ctx, `UPDATE scim.users SET user_id=$2 WHERE resource_id=$1`, deleted.ResourceID, canonicalUser); err != nil {
		t.Fatal(err)
	}
	oldDeletedMapping := deleted
	deleted.UserID = canonicalUser
	missingID, err := identity.NewSubjectID()
	if err != nil {
		t.Fatal(err)
	}
	missing := DirectoryUserTarget{ResourceID: string(missingID), UserID: identity.UserID(missingID)}
	wrongMapping := active
	wrongMapping.UserID = identity.UserID(missingID)
	omittedID := createNativeNamed(t, f, "ObservedWithoutActive", "Unproven activity")
	omitted := DirectoryUserTarget{ResourceID: omittedID, UserID: identity.UserID(omittedID)}
	activeState := DirectoryUserObservation{State: DirectoryMembershipUserActive, Revision: activeResponse.ETag}
	inactiveState := DirectoryUserObservation{State: DirectoryMembershipUserInactive, Revision: inactiveResponse.ETag}
	deletedState := DirectoryUserObservation{State: DirectoryMembershipUserDeleted, Revision: scim.Version(`"` + deleteCommand + `"`)}
	targets := []DirectoryUserTarget{inactive, missing, wrongMapping, active, deleted, oldDeletedMapping, omitted}
	want := []DirectoryUserObservation{inactiveState, {}, {}, activeState, deletedState, {}, {}}
	results, err := groups.ReadDirectoryUserStates(f.ctx, observed, targets)
	if err != nil || !reflect.DeepEqual(results, want) {
		t.Fatal("current native states, exact local mappings or native revisions changed", results, err)
	}
	results, err = groups.ReadDirectoryUserStates(f.ctx, observed, []DirectoryUserTarget{deleted, active, inactive})
	if err != nil || !reflect.DeepEqual(results, []DirectoryUserObservation{deletedState, activeState, inactiveState}) {
		t.Fatal("reordered targets lost input order", results, err)
	}
	if after, err := observed.Bindings(); err != nil || after != bindings {
		t.Fatal("reading current User states renewed the original observation", err)
	}
	var retainedCommand, retainedMapping string
	var retainedWire []byte
	if err := f.pool.Raw().QueryRow(f.ctx, `SELECT command_id,user_id,resource FROM scim.users WHERE resource_id=$1 AND deleted_at IS NOT NULL`, deleted.ResourceID).Scan(&retainedCommand, &retainedMapping, &retainedWire); err != nil || retainedCommand != deleteCommand || retainedMapping != canonicalUser || string(retainedWire) != "null" {
		t.Fatal("observation changed the retained native tombstone", err)
	}
}

func TestReadDirectoryUserStatesRejectsMalformedStorageWithoutPrefix(t *testing.T) {
	f, groups := nativeGroupsFixture(t)
	valid, _ := createDirectoryObservedUser(t, f, "ObservedValidPrefix")
	broken, response := createDirectoryObservedUser(t, f, "ObservedBroken")
	var originalWire []byte
	if err := f.pool.Raw().QueryRow(f.ctx, `SELECT resource FROM scim.users WHERE resource_id=$1`, broken.ResourceID).Scan(&originalWire); err != nil {
		t.Fatal(err)
	}
	var nonboolean scim.Resource
	if err := json.Unmarshal(originalWire, &nonboolean); err != nil {
		t.Fatal(err)
	}
	nonboolean.Attributes["active"] = "true"
	nonbooleanWire, err := json.Marshal(nonboolean)
	if err != nil {
		t.Fatal(err)
	}
	observed, err := groups.ObserveDirectorySource(f.ctx, f.config.Scope)
	if err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		name string
		wire []byte
	}{
		{"invalid envelope", []byte(`{}`)},
		{"nonboolean active", nonbooleanWire},
	} {
		t.Run(test.name, func(t *testing.T) {
			if _, err := f.pool.Raw().Exec(f.ctx, `UPDATE scim.users SET resource=$2 WHERE resource_id=$1`, broken.ResourceID, test.wire); err != nil {
				t.Fatal(err)
			}
			if results, err := groups.ReadDirectoryUserStates(f.ctx, observed, []DirectoryUserTarget{valid, broken}); err == nil || results != nil {
				t.Fatal("malformed stored User disclosed a usable prefix", results, err)
			}
		})
	}
	if _, err := f.pool.Raw().Exec(f.ctx, `UPDATE scim.users SET resource=$2 WHERE resource_id=$1`, broken.ResourceID, originalWire); err != nil {
		t.Fatal(err)
	}
	if _, err := f.service.Execute(f.ctx, scim.Request{Operation: scim.UserDelete, Credential: f.bearer, ResourceID: broken.ResourceID, IfMatch: response.ETag}); err != nil {
		t.Fatal(err)
	}
	if _, err := f.pool.Raw().Exec(f.ctx, `UPDATE scim.users SET resource=convert_to('{}','UTF8') WHERE resource_id=$1`, broken.ResourceID); err != nil {
		t.Fatal(err)
	}
	if results, err := groups.ReadDirectoryUserStates(f.ctx, observed, []DirectoryUserTarget{valid, broken}); err == nil || results != nil {
		t.Fatal("noncanonical tombstone disclosed a usable prefix", results, err)
	}
}

func TestReadDirectoryUserStatesEnforcesBatchAndOriginalAuthorityBounds(t *testing.T) {
	f, groups := nativeGroupsFixture(t)
	target, response := createDirectoryObservedUser(t, f, "ObservedBounded")
	observed, err := groups.ObserveDirectorySource(f.ctx, f.config.Scope)
	if err != nil {
		t.Fatal(err)
	}
	if results, err := groups.ReadDirectoryUserStates(f.ctx, observed, []DirectoryUserTarget{target}); err != nil || !reflect.DeepEqual(results, []DirectoryUserObservation{{State: DirectoryMembershipUserActive, Revision: response.ETag}}) {
		t.Fatal("minimum admitted batch lost its current state", results, err)
	}
	targets := make([]DirectoryUserTarget, 128)
	want := make([]DirectoryUserObservation, len(targets))
	for i := range targets {
		targets[i] = target
		want[i] = DirectoryUserObservation{State: DirectoryMembershipUserActive, Revision: response.ETag}
	}
	if results, err := groups.ReadDirectoryUserStates(f.ctx, observed, targets); err != nil || !reflect.DeepEqual(results, want) {
		t.Fatal("maximum admitted batch lost ordered current states", results, err)
	}
	for _, invalid := range [][]DirectoryUserTarget{
		nil,
		append(append([]DirectoryUserTarget(nil), targets...), target),
		{target, {}},
		{target, {ResourceID: target.ResourceID}},
		{target, {ResourceID: "not-a-subject-id", UserID: target.UserID}},
	} {
		if results, err := groups.ReadDirectoryUserStates(f.ctx, observed, invalid); err == nil || results != nil {
			t.Fatal("invalid target batch disclosed a usable prefix", results, err)
		}
	}
	canceled, cancel := context.WithCancel(f.ctx)
	cancel()
	if results, err := groups.ReadDirectoryUserStates(canceled, observed, []DirectoryUserTarget{target}); err == nil || results != nil {
		t.Fatal("canceled read disclosed usable source state", results, err)
	}
	if results, err := groups.ReadDirectoryUserStates(f.ctx, DirectorySourceObservation{}, []DirectoryUserTarget{target}); err == nil || results != nil {
		t.Fatal("unissued observation disclosed usable source state", results, err)
	}
	expired := observed
	expired.admission.connection.AuthorityValidUntil = time.Now().Add(-time.Second)
	if results, err := groups.ReadDirectoryUserStates(f.ctx, expired, []DirectoryUserTarget{target}); err == nil || results != nil {
		t.Fatal("expired original observation disclosed usable source state", results, err)
	}
	if _, err := f.pool.Raw().Exec(f.ctx, `UPDATE scim.connections SET version=version+1 WHERE tenant_id=$1 AND organization_id=$2 AND provider_id=$3 AND connection_id=$4`, scopeArgs(f.config.Scope)...); err != nil {
		t.Fatal(err)
	}
	if results, err := groups.ReadDirectoryUserStates(f.ctx, observed, []DirectoryUserTarget{target}); err == nil || results != nil {
		t.Fatal("changed original connection disclosed usable source state", results, err)
	}
}
