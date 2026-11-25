package scimorganization_test

import (
	"encoding"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"reflect"
	"strings"
	"testing"

	organization "github.com/faustbrian/go-organization"
	scimorganization "github.com/faustbrian/go-scim/organization"
	"github.com/faustbrian/go-sso"
)

func TestDirectoryRoleMapperPreservesOriginalChildrenAndExplicitRole(t *testing.T) {
	config := directoryRoleConfig()
	mapper, err := scimorganization.NewDirectoryRoleMapper(config)
	if err != nil {
		t.Fatal(err)
	}
	batch := directoryBatch(t)
	batch.Deltas = append(batch.Deltas, directoryDelta(t, "AgICAgICAgICAgICAgICAg", "Group.A", "Member.A", sso.DirectoryMembershipRemove))
	got, err := mapper.MapDirectoryRoleDelta(batch)
	if err != nil {
		t.Fatal(err)
	}
	want := []scimorganization.DirectoryRoleIntent{
		{Membership: scimorganization.DirectoryMembershipIntent{CommandID: "AQEBAQEBAQEBAQEBAQEBAQ", GroupID: "Group.A", MemberID: "Member.A", TeamID: "Team.A", UserID: "User.A", Action: sso.DirectoryMembershipAdd}, RoleID: "Role.ReadOnly"},
		{Membership: scimorganization.DirectoryMembershipIntent{CommandID: "AgICAgICAgICAgICAgICAg", GroupID: "Group.A", MemberID: "Member.A", TeamID: "Team.A", UserID: "User.A", Action: sso.DirectoryMembershipRemove}, RoleID: "Role.ReadOnly"},
	}
	if !reflect.DeepEqual(got.Source, batch) || !reflect.DeepEqual(got.Roles, want) {
		t.Fatal("role mapping changed original child identity, order, direction or explicit target")
	}
	if !mapper.MatchesDirectoryRoleSource(directoryRoleScope(), directoryRoleTarget()) {
		t.Fatal("exact mapped target did not match the configured source")
	}

	config.Directory.Groups[0].TeamID = "Changed.Team"
	config.Directory.Members[0].UserID = "Changed.User"
	config.Roles[0].RoleID = "Changed.Role"
	got.Source.Deltas[0] = sso.DirectoryDelta{}
	got.Roles[0].Membership.TeamID = "Changed.Output.Team"
	got.Roles[0].RoleID = "Changed.Output.Role"
	batch.Deltas[1] = sso.DirectoryDelta{}
	again, err := mapper.MapDirectoryRoleDelta(directoryBatch(t))
	if err != nil || !reflect.DeepEqual(again.Roles, want[:1]) || !mapper.MatchesDirectoryRoleSource(directoryRoleScope(), directoryRoleTarget()) {
		t.Fatal("caller mutation changed the immutable role profile")
	}
	if _, err := batch.Deltas[0].GroupMembership(); err != nil {
		t.Fatal("role output source aliases the caller's child slice")
	}
}

func TestDirectoryRoleMapperRechecksEveryExactScopeAndTargetField(t *testing.T) {
	mapper, err := scimorganization.NewDirectoryRoleMapper(directoryRoleConfig())
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name string
		edit func(*scimorganization.DirectoryRoleScope, *scimorganization.DirectoryRoleTarget)
	}{
		{"tenant", func(s *scimorganization.DirectoryRoleScope, _ *scimorganization.DirectoryRoleTarget) {
			s.TenantID = "Other.Tenant"
		}},
		{"organization", func(s *scimorganization.DirectoryRoleScope, _ *scimorganization.DirectoryRoleTarget) {
			s.OrganizationID = "Other.Organization"
		}},
		{"provider", func(s *scimorganization.DirectoryRoleScope, _ *scimorganization.DirectoryRoleTarget) {
			s.ProviderID = "Other.Provider"
		}},
		{"connection", func(s *scimorganization.DirectoryRoleScope, _ *scimorganization.DirectoryRoleTarget) {
			s.ConnectionID = "Other.Connection"
		}},
		{"version", func(s *scimorganization.DirectoryRoleScope, _ *scimorganization.DirectoryRoleTarget) {
			s.MappingVersion++
		}},
		{"zero version", func(s *scimorganization.DirectoryRoleScope, _ *scimorganization.DirectoryRoleTarget) {
			s.MappingVersion = 0
		}},
		{"group case", func(_ *scimorganization.DirectoryRoleScope, v *scimorganization.DirectoryRoleTarget) {
			v.GroupID = "group.A"
		}},
		{"member case", func(_ *scimorganization.DirectoryRoleScope, v *scimorganization.DirectoryRoleTarget) {
			v.MemberID = "member.A"
		}},
		{"team", func(_ *scimorganization.DirectoryRoleScope, v *scimorganization.DirectoryRoleTarget) {
			v.TeamID = "Other.Team"
		}},
		{"user", func(_ *scimorganization.DirectoryRoleScope, v *scimorganization.DirectoryRoleTarget) {
			v.UserID = "Other.User"
		}},
		{"role", func(_ *scimorganization.DirectoryRoleScope, v *scimorganization.DirectoryRoleTarget) {
			v.RoleID = "Other.Role"
		}},
		{"static role", func(_ *scimorganization.DirectoryRoleScope, v *scimorganization.DirectoryRoleTarget) {
			v.RoleID = organization.ID(organization.RoleOwner)
		}},
		{"source alias", func(_ *scimorganization.DirectoryRoleScope, v *scimorganization.DirectoryRoleTarget) {
			v.GroupID = "Team.A"
		}},
		{"member alias", func(_ *scimorganization.DirectoryRoleScope, v *scimorganization.DirectoryRoleTarget) {
			v.MemberID = "User.A"
		}},
		{"empty target", func(_ *scimorganization.DirectoryRoleScope, v *scimorganization.DirectoryRoleTarget) {
			*v = scimorganization.DirectoryRoleTarget{}
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			scope, target := directoryRoleScope(), directoryRoleTarget()
			tt.edit(&scope, &target)
			if mapper.MatchesDirectoryRoleSource(scope, target) {
				t.Fatal("non-exact source or target matched the role policy")
			}
		})
	}
	var zero scimorganization.DirectoryRoleMapper
	if zero.MatchesDirectoryRoleSource(directoryRoleScope(), directoryRoleTarget()) {
		t.Fatal("zero role mapper matched a target")
	}
}

func TestDirectoryRoleMapperKeepsCaseDistinctGroupsAndSharedTeamsExplicit(t *testing.T) {
	config := directoryRoleConfig()
	config.Directory.Groups = append(config.Directory.Groups,
		scimorganization.DirectoryGroupTeamMapping{GroupID: "group.A", TeamID: "Team.A"},
		scimorganization.DirectoryGroupTeamMapping{GroupID: "Administrators", TeamID: "Team.A"},
	)
	config.Roles = append(config.Roles,
		scimorganization.DirectoryGroupRoleMapping{GroupID: "group.A", TeamID: "Team.A", RoleID: "Role.Support"},
		scimorganization.DirectoryGroupRoleMapping{GroupID: "Administrators", TeamID: "Team.A", RoleID: "Role.ReadOnly"},
	)
	mapper, err := scimorganization.NewDirectoryRoleMapper(config)
	if err != nil {
		t.Fatal(err)
	}
	batch := directoryBatch(t)
	batch.Deltas = append(batch.Deltas,
		directoryDelta(t, "AgICAgICAgICAgICAgICAg", "group.A", "Member.A", sso.DirectoryMembershipAdd),
		directoryDelta(t, "AwMDAwMDAwMDAwMDAwMDAw", "Administrators", "Member.A", sso.DirectoryMembershipAdd),
	)
	got, err := mapper.MapDirectoryRoleDelta(batch)
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Roles) != 3 || got.Roles[0].RoleID != "Role.ReadOnly" || got.Roles[1].RoleID != "Role.Support" || got.Roles[2].RoleID != "Role.ReadOnly" {
		t.Fatal("case-distinct or role-like Group IDs overrode their explicit roles")
	}
	for _, intent := range got.Roles {
		target := directoryRoleTarget()
		target.GroupID = intent.Membership.GroupID
		target.RoleID = intent.RoleID
		if !mapper.MatchesDirectoryRoleSource(directoryRoleScope(), target) {
			t.Fatal("explicit shared-team selection failed its exact lookup")
		}
	}
}

func TestDirectoryRoleMapperRejectsInvalidAndIncompleteProfiles(t *testing.T) {
	tests := []struct {
		name string
		edit func(*scimorganization.DirectoryRoleMappingConfig)
	}{
		{"invalid directory", func(c *scimorganization.DirectoryRoleMappingConfig) { c.Directory.MappingVersion = 0 }},
		{"no roles", func(c *scimorganization.DirectoryRoleMappingConfig) { c.Roles = nil }},
		{"partial roles", func(c *scimorganization.DirectoryRoleMappingConfig) {
			c.Directory.Groups = append(c.Directory.Groups, scimorganization.DirectoryGroupTeamMapping{GroupID: "Group.B", TeamID: "Team.B"})
		}},
		{"duplicate role", func(c *scimorganization.DirectoryRoleMappingConfig) { c.Roles = append(c.Roles, c.Roles[0]) }},
		{"duplicate hides missing group", func(c *scimorganization.DirectoryRoleMappingConfig) {
			c.Directory.Groups = append(c.Directory.Groups, scimorganization.DirectoryGroupTeamMapping{GroupID: "Group.B", TeamID: "Team.B"})
			c.Roles = append(c.Roles, c.Roles[0])
		}},
		{"group alias", func(c *scimorganization.DirectoryRoleMappingConfig) { c.Roles[0].GroupID = "Team.A" }},
		{"wrong group case", func(c *scimorganization.DirectoryRoleMappingConfig) { c.Roles[0].GroupID = "group.A" }},
		{"wrong team", func(c *scimorganization.DirectoryRoleMappingConfig) { c.Roles[0].TeamID = "Other.Team" }},
		{"empty role", func(c *scimorganization.DirectoryRoleMappingConfig) { c.Roles[0].RoleID = "" }},
		{"oversized role", func(c *scimorganization.DirectoryRoleMappingConfig) {
			c.Roles[0].RoleID = organization.ID(strings.Repeat("r", 129))
		}},
		{"role whitespace", func(c *scimorganization.DirectoryRoleMappingConfig) { c.Roles[0].RoleID = " Role.ReadOnly" }},
		{"role control", func(c *scimorganization.DirectoryRoleMappingConfig) { c.Roles[0].RoleID = "Role\x7f" }},
		{"invalid role UTF8", func(c *scimorganization.DirectoryRoleMappingConfig) {
			c.Roles[0].RoleID = organization.ID(string([]byte{0xff}))
		}},
		{"too many roles", func(c *scimorganization.DirectoryRoleMappingConfig) {
			c.Roles = make([]scimorganization.DirectoryGroupRoleMapping, 1001)
		}},
	}
	for _, role := range []organization.Role{organization.RoleOwner, organization.RoleAdministrator, organization.RoleMember} {
		tests = append(tests, struct {
			name string
			edit func(*scimorganization.DirectoryRoleMappingConfig)
		}{"static " + string(role), func(c *scimorganization.DirectoryRoleMappingConfig) { c.Roles[0].RoleID = organization.ID(role) }})
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			config := directoryRoleConfig()
			tt.edit(&config)
			got, err := scimorganization.NewDirectoryRoleMapper(config)
			if !errors.Is(err, scimorganization.ErrInvalidMappingInput) || !reflect.DeepEqual(got, scimorganization.DirectoryRoleMapper{}) {
				t.Fatal("invalid role profile constructed a mapper", err)
			}
		})
	}
}

func TestDirectoryRoleMapperPreservesBaseDenialAndAllOrZero(t *testing.T) {
	mapper, err := scimorganization.NewDirectoryRoleMapper(directoryRoleConfig())
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name string
		edit func(*sso.DirectoryDeltaBatch)
		want error
	}{
		{"wrong scope", func(b *sso.DirectoryDeltaBatch) { b.ConnectionID = "Other.Connection" }, scimorganization.ErrMappingDenied},
		{"stale version", func(b *sso.DirectoryDeltaBatch) { b.MappingVersion++ }, scimorganization.ErrMappingDenied},
		{"role-like alias after valid child", func(b *sso.DirectoryDeltaBatch) {
			b.Deltas = append(b.Deltas, directoryDelta(t, "AgICAgICAgICAgICAgICAg", "Owner", "Member.A", sso.DirectoryMembershipAdd))
		}, scimorganization.ErrMappingDenied},
		{"member alias after valid child", func(b *sso.DirectoryDeltaBatch) {
			b.Deltas = append(b.Deltas, directoryDelta(t, "AgICAgICAgICAgICAgICAg", "Group.A", "User.A", sso.DirectoryMembershipRemove))
		}, scimorganization.ErrMappingDenied},
		{"malformed child", func(b *sso.DirectoryDeltaBatch) { b.Deltas = append(b.Deltas, sso.DirectoryDelta{}) }, scimorganization.ErrInvalidMappingInput},
		{"duplicate child command", func(b *sso.DirectoryDeltaBatch) { b.Deltas = append(b.Deltas, b.Deltas[0]) }, scimorganization.ErrInvalidMappingInput},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			batch := directoryBatch(t)
			tt.edit(&batch)
			got, err := mapper.MapDirectoryRoleDelta(batch)
			if !errors.Is(err, tt.want) || !reflect.DeepEqual(got, scimorganization.DirectoryRoleBatch{}) {
				t.Fatal("denied or malformed batch returned role output", err)
			}
		})
	}
	var zero scimorganization.DirectoryRoleMapper
	got, err := zero.MapDirectoryRoleDelta(directoryBatch(t))
	if !errors.Is(err, scimorganization.ErrInvalidMappingInput) || !reflect.DeepEqual(got, scimorganization.DirectoryRoleBatch{}) {
		t.Fatal("zero mapper accepted a batch")
	}
}

func TestDirectoryRoleMappingRedactsImplicitOutput(t *testing.T) {
	config := directoryRoleConfig()
	mapper, err := scimorganization.NewDirectoryRoleMapper(config)
	if err != nil {
		t.Fatal(err)
	}
	mapped, err := mapper.MapDirectoryRoleDelta(directoryBatch(t))
	if err != nil {
		t.Fatal(err)
	}
	for _, value := range []any{config.Roles[0], config, mapper, mapped, mapped.Roles[0], directoryRoleScope(), directoryRoleTarget()} {
		for _, verb := range []string{"%+v", "%#v", "%s"} {
			if text := fmt.Sprintf(verb, value); strings.Contains(text, "Role.ReadOnly") || strings.Contains(text, "Tenant.A") || strings.Contains(text, "Group.A") || strings.Contains(text, "User.A") {
				t.Fatal("implicit formatting exposed role mapping identifiers")
			}
		}
		if _, err := json.Marshal(value); !errors.Is(err, scimorganization.ErrSensitiveSerialization) {
			t.Fatal("implicit JSON exposed role mapping identifiers")
		}
		text, ok := value.(encoding.TextMarshaler)
		if !ok {
			t.Fatal("role mapping value lacks text serialization protection")
		}
		if _, err := text.MarshalText(); !errors.Is(err, scimorganization.ErrSensitiveSerialization) {
			t.Fatal("implicit text exposed role mapping identifiers")
		}
		logger, ok := value.(slog.LogValuer)
		if !ok || !strings.Contains(logger.LogValue().String(), "redacted") {
			t.Fatal("structured logging lacks redaction")
		}
	}
}

func directoryRoleConfig() scimorganization.DirectoryRoleMappingConfig {
	return scimorganization.DirectoryRoleMappingConfig{
		Directory: directoryConfig(),
		Roles:     []scimorganization.DirectoryGroupRoleMapping{{GroupID: "Group.A", TeamID: "Team.A", RoleID: "Role.ReadOnly"}},
	}
}

func directoryRoleScope() scimorganization.DirectoryRoleScope {
	return scimorganization.DirectoryRoleScope{TenantID: "Tenant.A", OrganizationID: "Org.A", ProviderID: "Provider.A", ConnectionID: "Connection.A", MappingVersion: 7}
}

func directoryRoleTarget() scimorganization.DirectoryRoleTarget {
	return scimorganization.DirectoryRoleTarget{GroupID: "Group.A", MemberID: "Member.A", TeamID: "Team.A", RoleID: "Role.ReadOnly", UserID: "User.A"}
}
