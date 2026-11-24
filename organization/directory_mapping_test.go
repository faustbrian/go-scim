package scimorganization_test

import (
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"

	identity "github.com/faustbrian/go-identity"
	organization "github.com/faustbrian/go-organization"
	scimorganization "github.com/faustbrian/go-scim/organization"
	"github.com/faustbrian/go-sso"
)

func TestDirectoryMapperPreservesExactSourceAndDirection(t *testing.T) {
	config := directoryConfig()
	mapper, err := scimorganization.NewDirectoryMapper(config)
	if err != nil {
		t.Fatal(err)
	}
	batch := directoryBatch(t)
	batch.Deltas = append(batch.Deltas, directoryDelta(t, "AgICAgICAgICAgICAgICAg", "Group.A", "Member.A", sso.DirectoryMembershipRemove))
	got, err := mapper.MapDirectoryDelta(batch)
	if err != nil {
		t.Fatal(err)
	}
	want := []scimorganization.DirectoryMembershipIntent{
		{CommandID: "AQEBAQEBAQEBAQEBAQEBAQ", GroupID: "Group.A", MemberID: "Member.A", TeamID: "Team.A", UserID: "User.A", Action: sso.DirectoryMembershipAdd},
		{CommandID: "AgICAgICAgICAgICAgICAg", GroupID: "Group.A", MemberID: "Member.A", TeamID: "Team.A", UserID: "User.A", Action: sso.DirectoryMembershipRemove},
	}
	if !reflect.DeepEqual(got.Source, batch) || !reflect.DeepEqual(got.Memberships, want) {
		t.Fatal("mapping changed the admitted envelope, order, exact identities or direction")
	}
	got.Source.Deltas[0] = sso.DirectoryDelta{}
	got.Memberships[0].TeamID = "changed"
	batch.Deltas[1] = sso.DirectoryDelta{}
	again, err := mapper.MapDirectoryDelta(directoryBatch(t))
	if err != nil || !reflect.DeepEqual(again.Memberships, want[:1]) {
		t.Fatal("returned data or caller batch mutated the mapper")
	}
	if _, err := batch.Deltas[0].GroupMembership(); err != nil {
		t.Fatal("mapped source aliases the caller's delta slice")
	}
}

func TestDirectoryMapperSnapshotsConfiguration(t *testing.T) {
	config := directoryConfig()
	mapper, err := scimorganization.NewDirectoryMapper(config)
	if err != nil {
		t.Fatal(err)
	}
	config.Groups[0].TeamID = "OtherTeam"
	config.Groups[0].GroupID = "OtherGroup"
	config.Members[0].UserID = "OtherUser"
	config.Members[0].MemberID = "OtherMember"
	config.ConnectionID = "OtherConnection"
	got, err := mapper.MapDirectoryDelta(directoryBatch(t))
	if err != nil || len(got.Memberships) != 1 || got.Memberships[0].TeamID != "Team.A" || got.Memberships[0].UserID != "User.A" {
		t.Fatal("mapper retained mutable configuration")
	}
}

func TestDirectoryMapperRejectsWrongScopeAndUnknownEdges(t *testing.T) {
	mapper, err := scimorganization.NewDirectoryMapper(directoryConfig())
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name string
		edit func(*sso.DirectoryDeltaBatch)
	}{
		{"tenant", func(b *sso.DirectoryDeltaBatch) { b.TenantID = "Tenant.Other" }},
		{"organization", func(b *sso.DirectoryDeltaBatch) { b.OrganizationID = "Org.Other" }},
		{"provider", func(b *sso.DirectoryDeltaBatch) { b.ProviderID = "Provider.Other" }},
		{"connection", func(b *sso.DirectoryDeltaBatch) { b.ConnectionID = "Connection.Other" }},
		{"mapping version", func(b *sso.DirectoryDeltaBatch) { b.MappingVersion++ }},
		{"group case", func(b *sso.DirectoryDeltaBatch) {
			b.Deltas[0] = directoryDelta(t, "AQEBAQEBAQEBAQEBAQEBAQ", "group.A", "Member.A", sso.DirectoryMembershipAdd)
		}},
		{"member case", func(b *sso.DirectoryDeltaBatch) {
			b.Deltas[0] = directoryDelta(t, "AQEBAQEBAQEBAQEBAQEBAQ", "Group.A", "member.A", sso.DirectoryMembershipAdd)
		}},
		{"unknown group", func(b *sso.DirectoryDeltaBatch) {
			b.Deltas[0] = directoryDelta(t, "AQEBAQEBAQEBAQEBAQEBAQ", "Unknown", "Member.A", sso.DirectoryMembershipAdd)
		}},
		{"unknown member", func(b *sso.DirectoryDeltaBatch) {
			b.Deltas[0] = directoryDelta(t, "AQEBAQEBAQEBAQEBAQEBAQ", "Group.A", "Unknown", sso.DirectoryMembershipAdd)
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			batch := directoryBatch(t)
			tt.edit(&batch)
			got, err := mapper.MapDirectoryDelta(batch)
			if !errors.Is(err, scimorganization.ErrMappingDenied) || !reflect.DeepEqual(got, scimorganization.DirectoryMembershipBatch{}) {
				t.Fatal("out-of-policy source produced mapping intent")
			}
		})
	}
	batch := directoryBatch(t)
	batch.Deltas = append(batch.Deltas, directoryDelta(t, "AgICAgICAgICAgICAgICAg", "Unknown", "Member.A", sso.DirectoryMembershipRemove))
	got, err := mapper.MapDirectoryDelta(batch)
	if !errors.Is(err, scimorganization.ErrMappingDenied) || len(got.Memberships) != 0 {
		t.Fatal("partially mapped batch escaped after later denial")
	}
}

func TestDirectoryMapperRejectsMalformedBatchAndZeroMapper(t *testing.T) {
	mapper, err := scimorganization.NewDirectoryMapper(directoryConfig())
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name string
		edit func(*sso.DirectoryDeltaBatch)
	}{
		{"zero generation", func(b *sso.DirectoryDeltaBatch) { b.Generation = 0 }},
		{"zero predecessor", func(b *sso.DirectoryDeltaBatch) { b.PredecessorCheckpoint = [32]byte{} }},
		{"no deltas", func(b *sso.DirectoryDeltaBatch) { b.Deltas = nil }},
		{"invalid delta", func(b *sso.DirectoryDeltaBatch) { b.Deltas[0] = sso.DirectoryDelta{} }},
		{"duplicate command", func(b *sso.DirectoryDeltaBatch) { b.Deltas = append(b.Deltas, b.Deltas[0]) }},
		{"oversized batch", func(b *sso.DirectoryDeltaBatch) { b.Deltas = make([]sso.DirectoryDelta, 1001) }},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			batch := directoryBatch(t)
			tt.edit(&batch)
			got, err := mapper.MapDirectoryDelta(batch)
			if !errors.Is(err, scimorganization.ErrInvalidMappingInput) || !reflect.DeepEqual(got, scimorganization.DirectoryMembershipBatch{}) {
				t.Fatal("malformed batch produced mapping intent")
			}
		})
	}
	var zero scimorganization.DirectoryMapper
	if _, err := zero.MapDirectoryDelta(directoryBatch(t)); !errors.Is(err, scimorganization.ErrInvalidMappingInput) {
		t.Fatal("zero mapper accepted a batch")
	}
}

func TestDirectoryMapperRejectsInvalidOrAmbiguousConfiguration(t *testing.T) {
	tests := []struct {
		name string
		edit func(*scimorganization.DirectoryMappingConfig)
	}{
		{"empty tenant", func(c *scimorganization.DirectoryMappingConfig) { c.TenantID = "" }},
		{"empty organization", func(c *scimorganization.DirectoryMappingConfig) { c.OrganizationID = "" }},
		{"empty provider", func(c *scimorganization.DirectoryMappingConfig) { c.ProviderID = "" }},
		{"empty connection", func(c *scimorganization.DirectoryMappingConfig) { c.ConnectionID = "" }},
		{"zero version", func(c *scimorganization.DirectoryMappingConfig) { c.MappingVersion = 0 }},
		{"empty groups", func(c *scimorganization.DirectoryMappingConfig) { c.Groups = nil }},
		{"empty members", func(c *scimorganization.DirectoryMappingConfig) { c.Members = nil }},
		{"empty group", func(c *scimorganization.DirectoryMappingConfig) { c.Groups[0].GroupID = "" }},
		{"empty team", func(c *scimorganization.DirectoryMappingConfig) { c.Groups[0].TeamID = "" }},
		{"empty member", func(c *scimorganization.DirectoryMappingConfig) { c.Members[0].MemberID = "" }},
		{"empty user", func(c *scimorganization.DirectoryMappingConfig) { c.Members[0].UserID = "" }},
		{"duplicate group", func(c *scimorganization.DirectoryMappingConfig) { c.Groups = append(c.Groups, c.Groups[0]) }},
		{"conflicting group", func(c *scimorganization.DirectoryMappingConfig) {
			c.Groups = append(c.Groups, scimorganization.DirectoryGroupTeamMapping{GroupID: "Group.A", TeamID: "Team.Other"})
		}},
		{"duplicate member", func(c *scimorganization.DirectoryMappingConfig) { c.Members = append(c.Members, c.Members[0]) }},
		{"conflicting member", func(c *scimorganization.DirectoryMappingConfig) {
			c.Members = append(c.Members, scimorganization.DirectoryMemberUserMapping{MemberID: "Member.A", UserID: "User.Other"})
		}},
		{"oversized group list", func(c *scimorganization.DirectoryMappingConfig) {
			c.Groups = make([]scimorganization.DirectoryGroupTeamMapping, 1001)
		}},
		{"oversized member list", func(c *scimorganization.DirectoryMappingConfig) {
			c.Members = make([]scimorganization.DirectoryMemberUserMapping, 1001)
		}},
		{"oversized source ID", func(c *scimorganization.DirectoryMappingConfig) { c.Groups[0].GroupID = strings.Repeat("a", 129) }},
		{"control byte", func(c *scimorganization.DirectoryMappingConfig) { c.Members[0].MemberID = "Member\x7f" }},
		{"whitespace", func(c *scimorganization.DirectoryMappingConfig) { c.Groups[0].TeamID = "Team A" }},
		{"invalid UTF-8", func(c *scimorganization.DirectoryMappingConfig) {
			c.Members[0].UserID = identity.UserID(string([]byte{0xff}))
		}},
		{"non-ASCII provider", func(c *scimorganization.DirectoryMappingConfig) { c.ProviderID = "Provider.Ä" }},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			config := directoryConfig()
			tt.edit(&config)
			if _, err := scimorganization.NewDirectoryMapper(config); !errors.Is(err, scimorganization.ErrInvalidMappingInput) {
				t.Fatal("invalid or ambiguous config was accepted")
			}
		})
	}
}

func TestDirectoryMapperAllowsExplicitCaseDistinctAndSharedTargets(t *testing.T) {
	config := directoryConfig()
	config.Groups = append(config.Groups, scimorganization.DirectoryGroupTeamMapping{GroupID: "group.A", TeamID: organization.ID("Team.A")})
	config.Members = append(config.Members, scimorganization.DirectoryMemberUserMapping{MemberID: "member.A", UserID: identity.UserID("User.Other")})
	mapper, err := scimorganization.NewDirectoryMapper(config)
	if err != nil {
		t.Fatal(err)
	}
	batch := directoryBatch(t)
	batch.Deltas[0] = directoryDelta(t, "AQEBAQEBAQEBAQEBAQEBAQ", "group.A", "member.A", sso.DirectoryMembershipRemove)
	got, err := mapper.MapDirectoryDelta(batch)
	if err != nil || got.Memberships[0].GroupID != "group.A" || got.Memberships[0].UserID != "User.Other" || got.Memberships[0].TeamID != "Team.A" {
		t.Fatal("case-exact explicit mappings were conflated")
	}
}

func TestDirectoryMappingRedactsImplicitOutput(t *testing.T) {
	config := directoryConfig()
	mapper, err := scimorganization.NewDirectoryMapper(config)
	if err != nil {
		t.Fatal(err)
	}
	mapped, err := mapper.MapDirectoryDelta(directoryBatch(t))
	if err != nil {
		t.Fatal(err)
	}
	for _, value := range []any{config, mapper, mapped, mapped.Memberships[0]} {
		if text := fmt.Sprintf("%+v %#v", value, value); strings.Contains(text, "Group.A") || strings.Contains(text, "User.A") || strings.Contains(text, "Tenant.A") {
			t.Fatal("implicit formatting exposed mapping identifiers")
		}
		if _, err := json.Marshal(value); !errors.Is(err, scimorganization.ErrSensitiveSerialization) {
			t.Fatal("implicit JSON exposed mapping data")
		}
	}
}

func directoryConfig() scimorganization.DirectoryMappingConfig {
	return scimorganization.DirectoryMappingConfig{
		TenantID: "Tenant.A", OrganizationID: "Org.A", ProviderID: "Provider.A", ConnectionID: "Connection.A", MappingVersion: 7,
		Groups:  []scimorganization.DirectoryGroupTeamMapping{{GroupID: "Group.A", TeamID: "Team.A"}},
		Members: []scimorganization.DirectoryMemberUserMapping{{MemberID: "Member.A", UserID: "User.A"}},
	}
}

func directoryBatch(t *testing.T) sso.DirectoryDeltaBatch {
	t.Helper()
	return sso.DirectoryDeltaBatch{
		TenantID: "Tenant.A", OrganizationID: "Org.A", ProviderID: "Provider.A", ConnectionID: "Connection.A", Generation: 9, MappingVersion: 7,
		PredecessorCheckpoint: [32]byte{1, 2, 3},
		Deltas:                []sso.DirectoryDelta{directoryDelta(t, "AQEBAQEBAQEBAQEBAQEBAQ", "Group.A", "Member.A", sso.DirectoryMembershipAdd)},
	}
}

func directoryDelta(t *testing.T, command identity.CommandID, group, member string, action sso.DirectoryMembershipAction) sso.DirectoryDelta {
	t.Helper()
	delta, err := sso.NewDirectoryGroupMembershipDelta(command, group, member, action)
	if err != nil {
		t.Fatal(err)
	}
	return delta
}
