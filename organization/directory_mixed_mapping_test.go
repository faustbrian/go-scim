package scimorganization_test

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"

	identity "github.com/faustbrian/go-identity"
	scimorganization "github.com/faustbrian/go-scim/organization"
	"github.com/faustbrian/go-sso"
)

func TestDirectoryMixedMapperPreservesInterleavingAndExplicitTargets(t *testing.T) {
	mapper, err := scimorganization.NewDirectoryMixedMapper(directoryMixedConfig(t))
	if err != nil {
		t.Fatal(err)
	}
	batch := directoryMixedBatch(t)
	got, err := mapper.MapDirectoryMixedDelta(batch)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(got.Source, batch) {
		t.Fatal("mixed mapping changed original envelope, child order, commands or revisions")
	}
	assertDirectoryMixedChildren(t, got.Children, directoryMixedExpectedChildren())
}

func TestDirectoryMixedMapperAllowsHomogeneousBatchesAndOptionalGroupPolicies(t *testing.T) {
	for _, test := range []struct {
		name         string
		selectPolicy func(*scimorganization.DirectoryMixedMappingConfig)
		indexes      []int
	}{
		{"users with membership policy", func(c *scimorganization.DirectoryMixedMappingConfig) {
			c.Roles = scimorganization.DirectoryRoleMapper{}
		}, []int{0, 3, 6}},
		{"memberships only", func(c *scimorganization.DirectoryMixedMappingConfig) {
			c.Roles = scimorganization.DirectoryRoleMapper{}
		}, []int{1, 4}},
		{"users with role policy", func(c *scimorganization.DirectoryMixedMappingConfig) { c.Groups = scimorganization.DirectoryMapper{} }, []int{0, 3, 6}},
		{"roles only", func(c *scimorganization.DirectoryMixedMappingConfig) { c.Groups = scimorganization.DirectoryMapper{} }, []int{2, 5}},
		{"users and memberships", func(c *scimorganization.DirectoryMixedMappingConfig) {
			c.Roles = scimorganization.DirectoryRoleMapper{}
		}, []int{0, 1, 3, 4, 6}},
		{"users and roles", func(c *scimorganization.DirectoryMixedMappingConfig) { c.Groups = scimorganization.DirectoryMapper{} }, []int{0, 2, 3, 5, 6}},
	} {
		t.Run(test.name, func(t *testing.T) {
			config := directoryMixedConfig(t)
			test.selectPolicy(&config)
			mapper, err := scimorganization.NewDirectoryMixedMapper(config)
			if err != nil {
				t.Fatal(err)
			}
			original := directoryMixedBatch(t)
			batch := directoryBatch(t)
			batch.Deltas = nil
			var want []directoryMixedExpectedChild
			for _, index := range test.indexes {
				batch.Deltas = append(batch.Deltas, original.Deltas[index])
				want = append(want, directoryMixedExpectedChildren()[index])
			}
			got, err := mapper.MapDirectoryMixedDelta(batch)
			if err != nil || !reflect.DeepEqual(got.Source, batch) {
				t.Fatal("selected homogeneous or mixed subset was not preserved", err)
			}
			assertDirectoryMixedChildren(t, got.Children, want)
		})
	}
}

func TestDirectoryMixedMapperRejectsScopeVersionAndLateUnmappedChildrenAllOrZero(t *testing.T) {
	mapper, err := scimorganization.NewDirectoryMixedMapper(directoryMixedConfig(t))
	if err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		name string
		edit func(*sso.DirectoryDeltaBatch)
	}{
		{"tenant", func(b *sso.DirectoryDeltaBatch) { b.TenantID = "Tenant.Other" }},
		{"organization", func(b *sso.DirectoryDeltaBatch) { b.OrganizationID = "Org.Other" }},
		{"provider case", func(b *sso.DirectoryDeltaBatch) { b.ProviderID = "provider.A" }},
		{"connection", func(b *sso.DirectoryDeltaBatch) { b.ConnectionID = "Connection.Other" }},
		{"older version", func(b *sso.DirectoryDeltaBatch) { b.MappingVersion-- }},
		{"newer version", func(b *sso.DirectoryDeltaBatch) { b.MappingVersion++ }},
		{"user case", func(b *sso.DirectoryDeltaBatch) {
			b.Deltas[6] = directoryUserWithdrawal(t, directoryMixedCommand(7), "member.A", "Revision.C", sso.DirectoryUserDeleted)
		}},
		{"local user alias", func(b *sso.DirectoryDeltaBatch) {
			b.Deltas[6] = directoryUserWithdrawal(t, directoryMixedCommand(7), "User.A", "Revision.C", sso.DirectoryUserDeleted)
		}},
		{"membership member", func(b *sso.DirectoryDeltaBatch) {
			b.Deltas[4] = directoryDelta(t, directoryMixedCommand(5), "Group.A", "Member.Other", sso.DirectoryMembershipRemove)
		}},
		{"role member", func(b *sso.DirectoryDeltaBatch) {
			b.Deltas[5] = directoryDelta(t, directoryMixedCommand(6), "Group.Roles", "Member.Other", sso.DirectoryMembershipRemove)
		}},
		{"group case", func(b *sso.DirectoryDeltaBatch) {
			b.Deltas[5] = directoryDelta(t, directoryMixedCommand(6), "group.Roles", "Member.A", sso.DirectoryMembershipRemove)
		}},
		{"role-like group is not inferred", func(b *sso.DirectoryDeltaBatch) {
			b.Deltas[5] = directoryDelta(t, directoryMixedCommand(6), "Administrators", "Member.A", sso.DirectoryMembershipRemove)
		}},
		{"team alias", func(b *sso.DirectoryDeltaBatch) {
			b.Deltas[5] = directoryDelta(t, directoryMixedCommand(6), "Team.Roles", "Member.A", sso.DirectoryMembershipRemove)
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			batch := directoryMixedBatch(t)
			test.edit(&batch)
			got, err := mapper.MapDirectoryMixedDelta(batch)
			if !errors.Is(err, scimorganization.ErrMappingDenied) || !reflect.DeepEqual(got, scimorganization.DirectoryMixedBatch{}) {
				t.Fatal("denied child or scope returned partial mixed output", err)
			}
		})
	}
}

func TestDirectoryMixedMapperRejectsDisabledPoliciesWithoutPartialOutput(t *testing.T) {
	for _, test := range []struct {
		name string
		edit func(*scimorganization.DirectoryUserMappingConfig, *scimorganization.DirectoryMixedMappingConfig)
	}{
		{"admission", func(u *scimorganization.DirectoryUserMappingConfig, _ *scimorganization.DirectoryMixedMappingConfig) {
			u.AllowAdmission = false
		}},
		{"withdrawal", func(u *scimorganization.DirectoryUserMappingConfig, _ *scimorganization.DirectoryMixedMappingConfig) {
			u.AllowWithdrawal = false
		}},
		{"membership policy", func(_ *scimorganization.DirectoryUserMappingConfig, c *scimorganization.DirectoryMixedMappingConfig) {
			c.Groups = scimorganization.DirectoryMapper{}
		}},
		{"role policy", func(_ *scimorganization.DirectoryUserMappingConfig, c *scimorganization.DirectoryMixedMappingConfig) {
			c.Roles = scimorganization.DirectoryRoleMapper{}
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			users := directoryUserConfig()
			config := directoryMixedConfig(t)
			test.edit(&users, &config)
			var err error
			config.Users, err = scimorganization.NewDirectoryUserMapper(users)
			if err != nil {
				t.Fatal(err)
			}
			mapper, err := scimorganization.NewDirectoryMixedMapper(config)
			if err != nil {
				t.Fatal(err)
			}
			batch := directoryMixedBatch(t)
			if test.name == "admission" {
				batch.Deltas[0], batch.Deltas[6] = batch.Deltas[6], batch.Deltas[0]
			}
			got, err := mapper.MapDirectoryMixedDelta(batch)
			if !errors.Is(err, scimorganization.ErrMappingDenied) || !reflect.DeepEqual(got, scimorganization.DirectoryMixedBatch{}) {
				t.Fatal("disabled policy produced a mapped prefix", err)
			}
		})
	}
}

func TestDirectoryMixedMapperRejectsMalformedInputAndZeroValues(t *testing.T) {
	mapper, err := scimorganization.NewDirectoryMixedMapper(directoryMixedConfig(t))
	if err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		name string
		edit func(*sso.DirectoryDeltaBatch)
	}{
		{"zero batch", func(b *sso.DirectoryDeltaBatch) { *b = sso.DirectoryDeltaBatch{} }},
		{"empty children", func(b *sso.DirectoryDeltaBatch) { b.Deltas = nil }},
		{"late zero child", func(b *sso.DirectoryDeltaBatch) { b.Deltas[6] = sso.DirectoryDelta{} }},
		{"duplicate command across child kinds", func(b *sso.DirectoryDeltaBatch) {
			b.Deltas[5] = directoryDelta(t, directoryMixedCommand(1), "Group.Roles", "Member.A", sso.DirectoryMembershipRemove)
		}},
		{"oversized", func(b *sso.DirectoryDeltaBatch) { b.Deltas = make([]sso.DirectoryDelta, 1001) }},
		{"zero generation", func(b *sso.DirectoryDeltaBatch) { b.Generation = 0 }},
		{"zero version", func(b *sso.DirectoryDeltaBatch) { b.MappingVersion = 0 }},
		{"zero predecessor", func(b *sso.DirectoryDeltaBatch) { b.PredecessorCheckpoint = [32]byte{} }},
	} {
		t.Run(test.name, func(t *testing.T) {
			batch := directoryMixedBatch(t)
			test.edit(&batch)
			got, err := mapper.MapDirectoryMixedDelta(batch)
			if !errors.Is(err, scimorganization.ErrInvalidMappingInput) || !reflect.DeepEqual(got, scimorganization.DirectoryMixedBatch{}) {
				t.Fatal("malformed mixed batch produced output", err)
			}
		})
	}
	var zeroMapper scimorganization.DirectoryMixedMapper
	got, err := zeroMapper.MapDirectoryMixedDelta(directoryMixedBatch(t))
	if !errors.Is(err, scimorganization.ErrInvalidMappingInput) || !reflect.DeepEqual(got, scimorganization.DirectoryMixedBatch{}) {
		t.Fatal("zero mixed mapper accepted input", err)
	}
	var zeroIntent scimorganization.DirectoryMixedIntent
	if _, ok := zeroIntent.User(); ok {
		t.Fatal("zero mixed intent opened user accessor")
	}
	if _, ok := zeroIntent.Membership(); ok {
		t.Fatal("zero mixed intent opened membership accessor")
	}
	if _, ok := zeroIntent.Role(); ok {
		t.Fatal("zero mixed intent opened role accessor")
	}
}

func TestDirectoryMixedMapperRequiresUsersAndAtLeastOneUnambiguousGroupPolicy(t *testing.T) {
	for _, test := range []struct {
		name string
		edit func(*scimorganization.DirectoryMixedMappingConfig)
	}{
		{"zero config", func(c *scimorganization.DirectoryMixedMappingConfig) {
			*c = scimorganization.DirectoryMixedMappingConfig{}
		}},
		{"no users", func(c *scimorganization.DirectoryMixedMappingConfig) {
			c.Users = scimorganization.DirectoryUserMapper{}
		}},
		{"no group policy", func(c *scimorganization.DirectoryMixedMappingConfig) {
			c.Groups = scimorganization.DirectoryMapper{}
			c.Roles = scimorganization.DirectoryRoleMapper{}
		}},
		{"overlapping group IDs", func(c *scimorganization.DirectoryMixedMappingConfig) {
			var err error
			c.Roles, err = scimorganization.NewDirectoryRoleMapper(directoryRoleConfig())
			if err != nil {
				t.Fatal(err)
			}
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			config := directoryMixedConfig(t)
			test.edit(&config)
			got, err := scimorganization.NewDirectoryMixedMapper(config)
			if !errors.Is(err, scimorganization.ErrInvalidMappingInput) || !reflect.DeepEqual(got, scimorganization.DirectoryMixedMapper{}) {
				t.Fatal("missing or ambiguous policy constructed a mixed mapper", err)
			}
		})
	}
}

func TestDirectoryMixedMapperRequiresExactScopeAndVersionAcrossSelectedPolicies(t *testing.T) {
	for _, policy := range []string{"users", "groups", "roles"} {
		for _, field := range []string{"tenant", "organization", "provider case", "connection", "version"} {
			t.Run(policy+"/"+field, func(t *testing.T) {
				users, groups, roles := directoryMixedPolicyInputs()
				switch policy {
				case "users":
					switch field {
					case "tenant":
						users.TenantID = "Tenant.Other"
					case "organization":
						users.OrganizationID = "Org.Other"
					case "provider case":
						users.ProviderID = "provider.A"
					case "connection":
						users.ConnectionID = "Connection.Other"
					case "version":
						users.MappingVersion++
					}
				case "groups":
					changeDirectoryMixedScope(&groups, field)
				case "roles":
					changeDirectoryMixedScope(&roles.Directory, field)
				}
				config := directoryMixedConfigFrom(t, users, groups, roles)
				got, err := scimorganization.NewDirectoryMixedMapper(config)
				if !errors.Is(err, scimorganization.ErrInvalidMappingInput) || !reflect.DeepEqual(got, scimorganization.DirectoryMixedMapper{}) {
					t.Fatal("inconsistent selected policy scope constructed a mixed mapper", err)
				}
			})
		}
	}
}

func TestDirectoryMixedMapperRejectsConflictingMemberSelectionsBetweenEveryPolicyPair(t *testing.T) {
	for _, pair := range []string{"users and groups", "users and roles", "groups and roles"} {
		t.Run(pair, func(t *testing.T) {
			users, groups, roles := directoryMixedPolicyInputs()
			switch pair {
			case "users and groups":
				roles.Directory.Members[0].MemberID = "Role.Member"
				groups.Members[0].UserID = "User.Other"
			case "users and roles":
				groups.Members[0].MemberID = "Group.Member"
				roles.Directory.Members[0].UserID = "User.Other"
			case "groups and roles":
				users.Members[0].MemberID = "User.Member"
				roles.Directory.Members[0].UserID = "User.Other"
			}
			config := directoryMixedConfigFrom(t, users, groups, roles)
			got, err := scimorganization.NewDirectoryMixedMapper(config)
			if !errors.Is(err, scimorganization.ErrInvalidMappingInput) || !reflect.DeepEqual(got, scimorganization.DirectoryMixedMapper{}) {
				t.Fatal("one exact source member selected conflicting local users", err)
			}
		})
	}
}

func TestDirectoryMixedMapperKeepsCaseDistinctGroupPoliciesAndMemberSelections(t *testing.T) {
	users, groups, roles := directoryMixedPolicyInputs()
	roles.Directory.Groups[0].GroupID = "group.A"
	roles.Roles[0].GroupID = "group.A"
	roles.Directory.Members[0] = scimorganization.DirectoryMemberUserMapping{MemberID: "member.A", UserID: "User.Other"}
	mapper, err := scimorganization.NewDirectoryMixedMapper(directoryMixedConfigFrom(t, users, groups, roles))
	if err != nil {
		t.Fatal(err)
	}
	batch := directoryBatch(t)
	batch.Deltas = append(batch.Deltas, directoryDelta(t, directoryMixedCommand(2), "group.A", "member.A", sso.DirectoryMembershipAdd))
	got, err := mapper.MapDirectoryMixedDelta(batch)
	if err != nil {
		t.Fatal(err)
	}
	assertDirectoryMixedChildren(t, got.Children, []directoryMixedExpectedChild{
		{membership: &scimorganization.DirectoryMembershipIntent{CommandID: "AQEBAQEBAQEBAQEBAQEBAQ", GroupID: "Group.A", MemberID: "Member.A", TeamID: "Team.A", UserID: "User.A", Action: sso.DirectoryMembershipAdd}},
		{role: &scimorganization.DirectoryRoleIntent{Membership: scimorganization.DirectoryMembershipIntent{CommandID: directoryMixedCommand(2), GroupID: "group.A", MemberID: "member.A", TeamID: "Team.Roles", UserID: "User.Other", Action: sso.DirectoryMembershipAdd}, RoleID: "Role.ReadOnly"}},
	})
}

func TestDirectoryMixedMapperDetachesSourceChildrenAndAccessorValues(t *testing.T) {
	config := directoryMixedConfig(t)
	mapper, err := scimorganization.NewDirectoryMixedMapper(config)
	if err != nil {
		t.Fatal(err)
	}
	batch := directoryMixedBatch(t)
	original, err := batch.Snapshot()
	if err != nil {
		t.Fatal(err)
	}
	got, err := mapper.MapDirectoryMixedDelta(batch)
	if err != nil {
		t.Fatal(err)
	}
	user, _ := got.Children[0].User()
	user.UserID = "Changed.User"
	membership, _ := got.Children[1].Membership()
	membership.TeamID = "Changed.Team"
	role, _ := got.Children[2].Role()
	role.RoleID = "Changed.Role"
	role.Membership.UserID = "Changed.Role.User"
	assertDirectoryMixedChildren(t, got.Children, directoryMixedExpectedChildren())
	got.Source.Deltas[0] = sso.DirectoryDelta{}
	got.Children[0] = scimorganization.DirectoryMixedIntent{}
	if !reflect.DeepEqual(batch, original) {
		t.Fatal("mutating mixed output changed the caller's original input")
	}
	batch.Deltas[1] = sso.DirectoryDelta{}
	if !reflect.DeepEqual(got.Source.Deltas[1:], original.Deltas[1:]) {
		t.Fatal("mutating caller input changed the detached mixed source")
	}
	config.Users = scimorganization.DirectoryUserMapper{}
	config.Groups = scimorganization.DirectoryMapper{}
	config.Roles = scimorganization.DirectoryRoleMapper{}
	again, err := mapper.MapDirectoryMixedDelta(directoryMixedBatch(t))
	if err != nil {
		t.Fatal(err)
	}
	assertDirectoryMixedChildren(t, again.Children, directoryMixedExpectedChildren())
	if !reflect.DeepEqual(again.Source, original) {
		t.Fatal("mutating caller configuration or output changed later mapping")
	}
}

func TestDirectoryMixedMappingRedactsImplicitOutput(t *testing.T) {
	config := directoryMixedConfig(t)
	mapper, err := scimorganization.NewDirectoryMixedMapper(config)
	if err != nil {
		t.Fatal(err)
	}
	mapped, err := mapper.MapDirectoryMixedDelta(directoryMixedBatch(t))
	if err != nil {
		t.Fatal(err)
	}
	for _, value := range []any{config, mapper, mapped, mapped.Children[0], mapped.Children[1], mapped.Children[2]} {
		formatted := fmt.Sprintf("%v %+v %#v %s", value, value, value, value)
		for _, sensitive := range []string{"Tenant.A", "Org.A", "Provider.A", "Connection.A", "Member.A", "User.A", "Group.A", "Group.Roles", "Role.ReadOnly", "Revision.A"} {
			if strings.Contains(formatted, sensitive) {
				t.Fatal("implicit formatting exposed mixed mapping identifiers")
			}
		}
		if _, err := json.Marshal(value); !errors.Is(err, scimorganization.ErrSensitiveSerialization) {
			t.Fatal("implicit JSON exposed mixed mapping data", err)
		}
	}
}

type directoryMixedExpectedChild struct {
	user       *scimorganization.DirectoryUserIntent
	membership *scimorganization.DirectoryMembershipIntent
	role       *scimorganization.DirectoryRoleIntent
}

func assertDirectoryMixedChildren(t *testing.T, got []scimorganization.DirectoryMixedIntent, want []directoryMixedExpectedChild) {
	t.Helper()
	if len(got) != len(want) {
		t.Fatalf("got %d children, want %d", len(got), len(want))
	}
	for i, child := range got {
		user, userOK := child.User()
		membership, membershipOK := child.Membership()
		role, roleOK := child.Role()
		if userOK != (want[i].user != nil) || membershipOK != (want[i].membership != nil) || roleOK != (want[i].role != nil) {
			t.Fatalf("child %d opened the wrong accessors or more than one accessor", i)
		}
		if userOK && !reflect.DeepEqual(user, *want[i].user) {
			t.Fatalf("child %d changed user identity, revision or action", i)
		}
		if membershipOK && !reflect.DeepEqual(membership, *want[i].membership) {
			t.Fatalf("child %d changed explicit membership selection", i)
		}
		if roleOK && !reflect.DeepEqual(role, *want[i].role) {
			t.Fatalf("child %d changed explicit role selection", i)
		}
	}
}

func directoryMixedPolicyInputs() (scimorganization.DirectoryUserMappingConfig, scimorganization.DirectoryMappingConfig, scimorganization.DirectoryRoleMappingConfig) {
	roles := directoryRoleConfig()
	roles.Directory.Groups[0] = scimorganization.DirectoryGroupTeamMapping{GroupID: "Group.Roles", TeamID: "Team.Roles"}
	roles.Roles[0] = scimorganization.DirectoryGroupRoleMapping{GroupID: "Group.Roles", TeamID: "Team.Roles", RoleID: "Role.ReadOnly"}
	return directoryUserConfig(), directoryConfig(), roles
}

func directoryMixedConfig(t *testing.T) scimorganization.DirectoryMixedMappingConfig {
	t.Helper()
	users, groups, roles := directoryMixedPolicyInputs()
	return directoryMixedConfigFrom(t, users, groups, roles)
}

func directoryMixedConfigFrom(t *testing.T, users scimorganization.DirectoryUserMappingConfig, groups scimorganization.DirectoryMappingConfig, roles scimorganization.DirectoryRoleMappingConfig) scimorganization.DirectoryMixedMappingConfig {
	t.Helper()
	u, err := scimorganization.NewDirectoryUserMapper(users)
	if err != nil {
		t.Fatal(err)
	}
	g, err := scimorganization.NewDirectoryMapper(groups)
	if err != nil {
		t.Fatal(err)
	}
	r, err := scimorganization.NewDirectoryRoleMapper(roles)
	if err != nil {
		t.Fatal(err)
	}
	return scimorganization.DirectoryMixedMappingConfig{Users: u, Groups: g, Roles: r}
}

func changeDirectoryMixedScope(config *scimorganization.DirectoryMappingConfig, field string) {
	switch field {
	case "tenant":
		config.TenantID = "Tenant.Other"
	case "organization":
		config.OrganizationID = "Org.Other"
	case "provider case":
		config.ProviderID = "provider.A"
	case "connection":
		config.ConnectionID = "Connection.Other"
	case "version":
		config.MappingVersion++
	}
}

func directoryMixedCommand(index byte) identity.CommandID {
	var raw [16]byte
	raw[0] = index
	return identity.CommandID(base64.RawURLEncoding.EncodeToString(raw[:]))
}

func directoryMixedBatch(t *testing.T) sso.DirectoryDeltaBatch {
	t.Helper()
	batch := directoryBatch(t)
	batch.Deltas = []sso.DirectoryDelta{
		directoryUserAdmission(t, directoryMixedCommand(1), "Member.A", "Revision.A"),
		directoryDelta(t, directoryMixedCommand(2), "Group.A", "Member.A", sso.DirectoryMembershipAdd),
		directoryDelta(t, directoryMixedCommand(3), "Group.Roles", "Member.A", sso.DirectoryMembershipAdd),
		directoryUserWithdrawal(t, directoryMixedCommand(4), "Member.A", "Revision.B", sso.DirectoryUserInactive),
		directoryDelta(t, directoryMixedCommand(5), "Group.A", "Member.A", sso.DirectoryMembershipRemove),
		directoryDelta(t, directoryMixedCommand(6), "Group.Roles", "Member.A", sso.DirectoryMembershipRemove),
		directoryUserWithdrawal(t, directoryMixedCommand(7), "Member.A", "Revision.C", sso.DirectoryUserDeleted),
	}
	return batch
}

func directoryMixedExpectedChildren() []directoryMixedExpectedChild {
	return []directoryMixedExpectedChild{
		{user: &scimorganization.DirectoryUserIntent{CommandID: directoryMixedCommand(1), ResourceID: "Member.A", SourceRevision: "Revision.A", UserID: "User.A", Action: scimorganization.DirectoryUserAdmit}},
		{membership: &scimorganization.DirectoryMembershipIntent{CommandID: directoryMixedCommand(2), GroupID: "Group.A", MemberID: "Member.A", TeamID: "Team.A", UserID: "User.A", Action: sso.DirectoryMembershipAdd}},
		{role: &scimorganization.DirectoryRoleIntent{Membership: scimorganization.DirectoryMembershipIntent{CommandID: directoryMixedCommand(3), GroupID: "Group.Roles", MemberID: "Member.A", TeamID: "Team.Roles", UserID: "User.A", Action: sso.DirectoryMembershipAdd}, RoleID: "Role.ReadOnly"}},
		{user: &scimorganization.DirectoryUserIntent{CommandID: directoryMixedCommand(4), ResourceID: "Member.A", SourceRevision: "Revision.B", UserID: "User.A", Action: scimorganization.DirectoryUserWithdrawInactive}},
		{membership: &scimorganization.DirectoryMembershipIntent{CommandID: directoryMixedCommand(5), GroupID: "Group.A", MemberID: "Member.A", TeamID: "Team.A", UserID: "User.A", Action: sso.DirectoryMembershipRemove}},
		{role: &scimorganization.DirectoryRoleIntent{Membership: scimorganization.DirectoryMembershipIntent{CommandID: directoryMixedCommand(6), GroupID: "Group.Roles", MemberID: "Member.A", TeamID: "Team.Roles", UserID: "User.A", Action: sso.DirectoryMembershipRemove}, RoleID: "Role.ReadOnly"}},
		{user: &scimorganization.DirectoryUserIntent{CommandID: directoryMixedCommand(7), ResourceID: "Member.A", SourceRevision: "Revision.C", UserID: "User.A", Action: scimorganization.DirectoryUserWithdrawDeleted}},
	}
}
