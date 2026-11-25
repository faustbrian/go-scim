//go:build integration

package scimpostgres

import (
	"context"
	"reflect"
	"testing"
	"time"

	identity "github.com/faustbrian/go-identity"
	scim "github.com/faustbrian/go-scim"
)

func TestReadDirectoryGroupEdgeStatesDistinguishesAbsenceFromUnprovenAndInactive(t *testing.T) {
	f, groups := nativeGroupsFixture(t)
	user := createNativeNamed(t, f, "EdgeStateMember", "Direct member")
	other := createNativeNamed(t, f, "EdgeStateNonmember", "Known nonmember")
	group, err := groups.Execute(f.ctx, groupRequest(f, scim.GroupCreate, "", "", "edge-state-group", `{"schemas":["urn:ietf:params:scim:schemas:core:2.0:Group"],"displayName":"Edge states","members":[{"value":"`+user+`","type":"User"}]}`))
	if err != nil {
		t.Fatal(err)
	}
	edge := DirectoryGroupRoleEdge{GroupID: groupID(t, group), MemberResourceID: user, UserID: identity.UserID(user)}
	absent := DirectoryGroupRoleEdge{GroupID: edge.GroupID, MemberResourceID: other, UserID: identity.UserID(other)}
	missingGroup, wrongMapping, missingUser := edge, edge, edge
	missingGroup.GroupID, wrongMapping.UserID, missingUser.MemberResourceID = other, identity.UserID(other), edge.GroupID
	observed, err := groups.ObserveDirectorySource(f.ctx, f.config.Scope)
	if err != nil {
		t.Fatal(err)
	}
	assertStates := func(edges []DirectoryGroupRoleEdge, want []DirectoryGroupEdgeState) {
		t.Helper()
		got, err := groups.ReadDirectoryGroupEdgeStates(f.ctx, observed, edges)
		if err != nil || !reflect.DeepEqual(got, want) {
			t.Fatal("source states did not retain exact evidence and input order", got, err)
		}
		roles, err := groups.ReadDirectoryGroupRoleEdges(f.ctx, observed, edges)
		if err != nil || len(roles) != len(want) {
			t.Fatal("role projection failed", err)
		}
		for i, state := range want {
			if roles[i] != (state == DirectoryGroupEdgePresent) {
				t.Fatal("non-present source state conferred role eligibility", i)
			}
		}
	}
	assertStates([]DirectoryGroupRoleEdge{absent, missingGroup, edge, wrongMapping, missingUser}, []DirectoryGroupEdgeState{
		DirectoryGroupEdgeAbsent, DirectoryGroupEdgeUnproven, DirectoryGroupEdgePresent, DirectoryGroupEdgeUnproven, DirectoryGroupEdgeUnproven,
	})
	current, err := f.service.Execute(f.ctx, scim.Request{Operation: scim.UserGet, Credential: f.bearer, ResourceID: user})
	if err != nil {
		t.Fatal(err)
	}
	inactive, err := f.service.Execute(f.ctx, scim.Request{Operation: scim.UserPatch, Credential: f.bearer, ResourceID: user, IfMatch: current.ETag,
		ContentType: "application/scim+json", Body: []byte(`{"schemas":["urn:ietf:params:scim:api:messages:2.0:PatchOp"],"Operations":[{"op":"replace","path":"active","value":false}]}`)})
	if err != nil {
		t.Fatal(err)
	}
	assertStates([]DirectoryGroupRoleEdge{edge, absent}, []DirectoryGroupEdgeState{DirectoryGroupEdgeInactiveUser, DirectoryGroupEdgeAbsent})
	if _, err := f.service.Execute(f.ctx, scim.Request{Operation: scim.UserDelete, Credential: f.bearer, ResourceID: user, IfMatch: inactive.ETag}); err != nil {
		t.Fatal(err)
	}
	assertStates([]DirectoryGroupRoleEdge{edge}, []DirectoryGroupEdgeState{DirectoryGroupEdgeInactiveUser})
	removed, err := groups.Execute(f.ctx, groupRequest(f, scim.GroupPatch, edge.GroupID, group.ETag, "remove-state-member", `{"schemas":["urn:ietf:params:scim:api:messages:2.0:PatchOp"],"Operations":[{"op":"remove","path":"members"}]}`))
	if err != nil {
		t.Fatal(err)
	}
	assertStates([]DirectoryGroupRoleEdge{edge}, []DirectoryGroupEdgeState{DirectoryGroupEdgeAbsent})
	if _, err := groups.Execute(f.ctx, groupRequest(f, scim.GroupDelete, edge.GroupID, removed.ETag, "", "")); err != nil {
		t.Fatal(err)
	}
	assertStates([]DirectoryGroupRoleEdge{edge, wrongMapping, missingGroup}, []DirectoryGroupEdgeState{DirectoryGroupEdgeAbsent, DirectoryGroupEdgeUnproven, DirectoryGroupEdgeUnproven})
	assertNoDecision := func(ctx context.Context, observation DirectorySourceObservation, edges []DirectoryGroupRoleEdge) {
		t.Helper()
		if got, err := groups.ReadDirectoryGroupEdgeStates(ctx, observation, edges); err == nil || got != nil {
			t.Fatal("unavailable source disclosed a usable decision", got, err)
		}
	}
	canceled, cancel := context.WithCancel(f.ctx)
	cancel()
	assertNoDecision(canceled, observed, []DirectoryGroupRoleEdge{edge})
	expired := observed
	expired.admission.connection.AuthorityValidUntil = time.Now().Add(-time.Second)
	assertNoDecision(f.ctx, expired, []DirectoryGroupRoleEdge{edge})
	args := append(scopeArgs(f.config.Scope), other)
	if _, err := f.pool.Raw().Exec(f.ctx, `UPDATE scim.users SET resource=convert_to('{}','UTF8') WHERE tenant_id=$1 AND organization_id=$2 AND provider_id=$3 AND connection_id=$4 AND resource_id=$5`, args...); err != nil {
		t.Fatal(err)
	}
	assertNoDecision(f.ctx, observed, []DirectoryGroupRoleEdge{edge, absent})
	if _, err := f.pool.Raw().Exec(f.ctx, `UPDATE scim.connections SET state='revoked',version=version+1 WHERE tenant_id=$1 AND organization_id=$2 AND provider_id=$3 AND connection_id=$4`, scopeArgs(f.config.Scope)...); err != nil {
		t.Fatal(err)
	}
	assertNoDecision(f.ctx, observed, []DirectoryGroupRoleEdge{edge})
}
