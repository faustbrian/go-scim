//go:build integration

package scimpostgres

import (
	"reflect"
	"testing"
	"time"

	identity "github.com/faustbrian/go-identity"
	scim "github.com/faustbrian/go-scim"
)

func TestReadDirectoryGroupRoleEdgesChecksExactCurrentProjection(t *testing.T) {
	f, groups := nativeGroupsFixture(t)
	user := createNativeNamed(t, f, "RoleSourceUser", "Role source")
	group, err := groups.Execute(f.ctx, groupRequest(f, scim.GroupCreate, "", "", "directory-role-group", `{"schemas":["urn:ietf:params:scim:schemas:core:2.0:Group"],"displayName":"Role source","members":[{"value":"`+user+`","type":"User"}]}`))
	if err != nil {
		t.Fatal(err)
	}
	edge := DirectoryGroupRoleEdge{GroupID: groupID(t, group), MemberResourceID: user, UserID: identity.UserID(user)}
	missing, err := identity.NewSubjectID()
	if err != nil {
		t.Fatal(err)
	}
	wrongTarget := edge
	wrongTarget.UserID = identity.UserID(missing)
	missingGroup := edge
	missingGroup.GroupID = string(missing)
	observed, err := groups.ObserveDirectorySource(f.ctx, f.config.Scope)
	if err != nil {
		t.Fatal(err)
	}
	matches, err := groups.ReadDirectoryGroupRoleEdges(f.ctx, observed, []DirectoryGroupRoleEdge{wrongTarget, edge, missingGroup})
	if err != nil || !reflect.DeepEqual(matches, []bool{false, true, false}) {
		t.Fatal("direct current edges were not proved in original order", matches, err)
	}
	// The imported local identity can use a different canonical form from the
	// native SCIM resource ID. Seed its retained mapping, not a computed alias.
	const adopted = "01ARZ3NDEKTSV4RRFFQ69G5FAV"
	if _, err := f.pool.Raw().Exec(f.ctx, `INSERT INTO identity.users(tenant_id,user_id,status,version) VALUES($1,$2,'active',1)`, string(f.config.Scope.TenantID), adopted); err != nil {
		t.Fatal(err)
	}
	setLocal := func(id string) {
		t.Helper()
		if _, err := f.pool.Raw().Exec(f.ctx, `UPDATE scim.users SET user_id=$2 WHERE resource_id=$1`, user, id); err != nil {
			t.Fatal(err)
		}
	}
	setLocal(adopted)
	imported := edge
	imported.UserID = adopted
	matches, err = groups.ReadDirectoryGroupRoleEdges(f.ctx, observed, []DirectoryGroupRoleEdge{edge, imported})
	if err != nil || !reflect.DeepEqual(matches, []bool{false, true}) {
		t.Fatal("canonical local identity was collapsed into the SCIM resource ID", matches, err)
	}
	setLocal(user)
	current, err := f.service.Execute(f.ctx, scim.Request{Operation: scim.UserGet, Credential: f.bearer, ResourceID: user})
	if err != nil {
		t.Fatal(err)
	}
	const activity = `{"schemas":["urn:ietf:params:scim:api:messages:2.0:PatchOp"],"Operations":[{"op":"replace","path":"active","value":`
	toggle := func(value string, version scim.Version) scim.Response {
		t.Helper()
		out, err := f.service.Execute(f.ctx, scim.Request{Operation: scim.UserPatch, Credential: f.bearer, ResourceID: user, IfMatch: version,
			ContentType: "application/scim+json", Body: []byte(activity + value + `}]}`)})
		if err != nil {
			t.Fatal("set current native User state", err)
		}
		return out
	}
	inactive := toggle("false", current.ETag)
	matches, err = groups.ReadDirectoryGroupRoleEdges(f.ctx, observed, []DirectoryGroupRoleEdge{edge})
	if err != nil || !reflect.DeepEqual(matches, []bool{false}) {
		t.Fatal("inactive source User retained role eligibility", matches, err)
	}
	toggle("true", inactive.ETag)
	matches, err = groups.ReadDirectoryGroupRoleEdges(f.ctx, observed, []DirectoryGroupRoleEdge{edge})
	if err != nil || !reflect.DeepEqual(matches, []bool{true}) {
		t.Fatal("current active source was not observed", matches, err)
	}
	broken := createNativeNamed(t, f, "BrokenRoleSource", "Malformed fixture")
	if _, err := f.pool.Raw().Exec(f.ctx, `UPDATE scim.users SET resource=convert_to('{}','UTF8') WHERE resource_id=$1`, broken); err != nil {
		t.Fatal(err)
	}
	corrupt := edge
	corrupt.MemberResourceID = broken
	corrupt.UserID = identity.UserID(broken)
	if results, err := groups.ReadDirectoryGroupRoleEdges(f.ctx, observed, []DirectoryGroupRoleEdge{edge, corrupt}); err == nil || results != nil {
		t.Fatal("malformed stored source disclosed a usable prefix")
	}
	_, err = groups.Execute(f.ctx, groupRequest(f, scim.GroupPatch, edge.GroupID, group.ETag, "remove-role-edge", `{"schemas":["urn:ietf:params:scim:api:messages:2.0:PatchOp"],"Operations":[{"op":"remove","path":"members"}]}`))
	if err != nil {
		t.Fatal(err)
	}
	matches, err = groups.ReadDirectoryGroupRoleEdges(f.ctx, observed, []DirectoryGroupRoleEdge{edge})
	if err != nil || !reflect.DeepEqual(matches, []bool{false}) {
		t.Fatal("reusing the original source observation retained removed access", matches, err)
	}
	expired := observed
	expired.admission.connection.AuthorityValidUntil = time.Now().Add(-time.Second)
	if matches, err := groups.ReadDirectoryGroupRoleEdges(f.ctx, expired, []DirectoryGroupRoleEdge{edge}); err == nil || matches != nil {
		t.Fatal("expired source produced a usable decision")
	}
	if _, err := f.pool.Raw().Exec(f.ctx, `UPDATE scim.connections SET state='revoked',version=version+1 WHERE tenant_id=$1 AND organization_id=$2 AND provider_id=$3 AND connection_id=$4`, scopeArgs(f.config.Scope)...); err != nil {
		t.Fatal(err)
	}
	if matches, err := groups.ReadDirectoryGroupRoleEdges(f.ctx, observed, []DirectoryGroupRoleEdge{edge}); err == nil || matches != nil {
		t.Fatal("changed connection produced a usable decision")
	}
}
