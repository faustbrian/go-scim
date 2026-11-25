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

	identity "github.com/faustbrian/go-identity"
	scimorganization "github.com/faustbrian/go-scim/organization"
	"github.com/faustbrian/go-sso"
)

func TestDirectoryUserMapperPreservesExactSelectionsAndSource(t *testing.T) {
	mapper, err := scimorganization.NewDirectoryUserMapper(directoryUserConfig())
	if err != nil {
		t.Fatal(err)
	}
	batch := directoryUserBatch(t)
	want := []scimorganization.DirectoryUserIntent{
		{CommandID: "AQEBAQEBAQEBAQEBAQEBAQ", ResourceID: "Member.A", SourceRevision: "Revision.A", UserID: "User.A", Action: scimorganization.DirectoryUserAdmit},
		{CommandID: "AgICAgICAgICAgICAgICAg", ResourceID: "Member.A", SourceRevision: "Revision.B", UserID: "User.A", Action: scimorganization.DirectoryUserWithdrawInactive},
		{CommandID: "AwMDAwMDAwMDAwMDAwMDAw", ResourceID: "Member.A", SourceRevision: "Revision.C", UserID: "User.A", Action: scimorganization.DirectoryUserWithdrawDeleted},
	}
	got, err := mapper.MapDirectoryUserDelta(batch)
	if err != nil || !reflect.DeepEqual(got.Source, batch) || !reflect.DeepEqual(got.Users, want) {
		t.Fatal("mapping changed original scope, revisions, commands, order or selected actions")
	}
	got.Source.Deltas[0] = sso.DirectoryDelta{}
	got.Users[0].UserID = "Other.User"
	batch.Deltas[1] = sso.DirectoryDelta{}
	again, err := mapper.MapDirectoryUserDelta(directoryUserBatch(t))
	if err != nil || !reflect.DeepEqual(again.Users, want) {
		t.Fatal("caller output or input mutated the mapper")
	}
	if _, err := batch.Deltas[0].UserAdmission(); err != nil {
		t.Fatal("mapped source aliases the caller delta slice")
	}
}

func TestDirectoryUserMapperSnapshotsConfigurationAndExactCase(t *testing.T) {
	config := directoryUserConfig()
	config.Members = append(config.Members, scimorganization.DirectoryMemberUserMapping{MemberID: "member.A", UserID: "User.Other"})
	mapper, err := scimorganization.NewDirectoryUserMapper(config)
	if err != nil {
		t.Fatal(err)
	}
	config.Members[0].UserID = "Changed.User"
	config.Members[1].MemberID = "Changed.Member"
	config.AllowAdmission = false
	config.AllowWithdrawal = false
	batch := directoryUserBatch(t)
	batch.Deltas = []sso.DirectoryDelta{directoryUserAdmission(t, "AQEBAQEBAQEBAQEBAQEBAQ", "member.A", "Revision.A")}
	got, err := mapper.MapDirectoryUserDelta(batch)
	if err != nil || len(got.Users) != 1 || got.Users[0].UserID != "User.Other" || got.Users[0].ResourceID != "member.A" {
		t.Fatal("mapper conflated case-exact IDs or retained caller configuration")
	}
	batch = directoryUserBatch(t)
	got, err = mapper.MapDirectoryUserDelta(batch)
	if err != nil || got.Users[0].UserID != "User.A" {
		t.Fatal("mapper retained mutable member mapping")
	}
}

func TestDirectoryUserMapperRequiresSelectedActionPolicy(t *testing.T) {
	for _, policy := range []struct {
		name       string
		admission  bool
		withdrawal bool
	}{
		{"admission only", true, false},
		{"withdrawal only", false, true},
	} {
		t.Run(policy.name, func(t *testing.T) {
			config := directoryUserConfig()
			config.AllowAdmission, config.AllowWithdrawal = policy.admission, policy.withdrawal
			mapper, err := scimorganization.NewDirectoryUserMapper(config)
			if err != nil {
				t.Fatal(err)
			}
			for i, delta := range directoryUserBatch(t).Deltas {
				batch := directoryUserBatch(t)
				batch.Deltas = []sso.DirectoryDelta{delta}
				got, err := mapper.MapDirectoryUserDelta(batch)
				allowed := policy.withdrawal
				if i == 0 {
					allowed = policy.admission
				}
				if allowed {
					if err != nil || len(got.Users) != 1 {
						t.Fatal("explicitly selected action was denied")
					}
				} else if !errors.Is(err, scimorganization.ErrMappingDenied) || !reflect.DeepEqual(got, scimorganization.DirectoryUserBatch{}) {
					t.Fatal("unselected action produced mapping output")
				}
			}
			got, err := mapper.MapDirectoryUserDelta(directoryUserBatch(t))
			if !errors.Is(err, scimorganization.ErrMappingDenied) || !reflect.DeepEqual(got, scimorganization.DirectoryUserBatch{}) {
				t.Fatal("partially selected batch leaked mapped output")
			}
		})
	}
}

func TestDirectoryUserMapperRejectsWrongPartitionVersionAndUnknownResource(t *testing.T) {
	mapper, err := scimorganization.NewDirectoryUserMapper(directoryUserConfig())
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
		{"resource case", func(b *sso.DirectoryDeltaBatch) {
			b.Deltas[1] = directoryUserWithdrawal(t, "AgICAgICAgICAgICAgICAg", "member.A", "Revision.B", sso.DirectoryUserInactive)
		}},
		{"no local ID fallback", func(b *sso.DirectoryDeltaBatch) {
			b.Deltas[1] = directoryUserWithdrawal(t, "AgICAgICAgICAgICAgICAg", "User.A", "Revision.B", sso.DirectoryUserInactive)
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			batch := directoryUserBatch(t)
			test.edit(&batch)
			got, err := mapper.MapDirectoryUserDelta(batch)
			if !errors.Is(err, scimorganization.ErrMappingDenied) || !reflect.DeepEqual(got, scimorganization.DirectoryUserBatch{}) {
				t.Fatal("wrong partition, version or resource produced any output")
			}
		})
	}
}

func TestDirectoryUserMapperRejectsUnsupportedAndMalformedBatches(t *testing.T) {
	mapper, err := scimorganization.NewDirectoryUserMapper(directoryUserConfig())
	if err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		name string
		edit func(*sso.DirectoryDeltaBatch)
	}{
		{"no children", func(b *sso.DirectoryDeltaBatch) { b.Deltas = nil }},
		{"zero child", func(b *sso.DirectoryDeltaBatch) { b.Deltas[1] = sso.DirectoryDelta{} }},
		{"duplicate child", func(b *sso.DirectoryDeltaBatch) { b.Deltas[1] = b.Deltas[0] }},
		{"oversized", func(b *sso.DirectoryDeltaBatch) { b.Deltas = make([]sso.DirectoryDelta, 1001) }},
		{"zero generation", func(b *sso.DirectoryDeltaBatch) { b.Generation = 0 }},
		{"zero version", func(b *sso.DirectoryDeltaBatch) { b.MappingVersion = 0 }},
		{"zero predecessor", func(b *sso.DirectoryDeltaBatch) { b.PredecessorCheckpoint = [32]byte{} }},
		{"group only", func(b *sso.DirectoryDeltaBatch) { b.Deltas = directoryBatch(t).Deltas }},
		{"mixed group and user", func(b *sso.DirectoryDeltaBatch) {
			b.Deltas[1] = directoryDelta(t, "AgICAgICAgICAgICAgICAg", "Group.A", "Member.A", sso.DirectoryMembershipAdd)
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			batch := directoryUserBatch(t)
			test.edit(&batch)
			got, err := mapper.MapDirectoryUserDelta(batch)
			if !errors.Is(err, scimorganization.ErrInvalidMappingInput) || !reflect.DeepEqual(got, scimorganization.DirectoryUserBatch{}) {
				t.Fatal("malformed or unsupported batch produced output")
			}
		})
	}
	var zero scimorganization.DirectoryUserMapper
	got, err := zero.MapDirectoryUserDelta(directoryUserBatch(t))
	if !errors.Is(err, scimorganization.ErrInvalidMappingInput) || !reflect.DeepEqual(got, scimorganization.DirectoryUserBatch{}) {
		t.Fatal("zero mapper granted mapping policy")
	}
}

func TestDirectoryUserMapperValidatesBoundedUnambiguousConfiguration(t *testing.T) {
	for _, test := range []struct {
		name string
		edit func(*scimorganization.DirectoryUserMappingConfig)
	}{
		{"empty tenant", func(c *scimorganization.DirectoryUserMappingConfig) { c.TenantID = "" }},
		{"empty organization", func(c *scimorganization.DirectoryUserMappingConfig) { c.OrganizationID = "" }},
		{"empty provider", func(c *scimorganization.DirectoryUserMappingConfig) { c.ProviderID = "" }},
		{"non ASCII provider", func(c *scimorganization.DirectoryUserMappingConfig) { c.ProviderID = "Provider.Ä" }},
		{"empty connection", func(c *scimorganization.DirectoryUserMappingConfig) { c.ConnectionID = "" }},
		{"zero version", func(c *scimorganization.DirectoryUserMappingConfig) { c.MappingVersion = 0 }},
		{"no policy", func(c *scimorganization.DirectoryUserMappingConfig) {
			c.AllowAdmission = false
			c.AllowWithdrawal = false
		}},
		{"no members", func(c *scimorganization.DirectoryUserMappingConfig) { c.Members = nil }},
		{"too many members", func(c *scimorganization.DirectoryUserMappingConfig) {
			c.Members = make([]scimorganization.DirectoryMemberUserMapping, 1001)
		}},
		{"empty resource", func(c *scimorganization.DirectoryUserMappingConfig) { c.Members[0].MemberID = "" }},
		{"empty local user", func(c *scimorganization.DirectoryUserMappingConfig) { c.Members[0].UserID = "" }},
		{"resource too long", func(c *scimorganization.DirectoryUserMappingConfig) { c.Members[0].MemberID = strings.Repeat("a", 129) }},
		{"local user too long", func(c *scimorganization.DirectoryUserMappingConfig) {
			c.Members[0].UserID = identity.UserID(strings.Repeat("a", 129))
		}},
		{"whitespace", func(c *scimorganization.DirectoryUserMappingConfig) { c.ConnectionID = "Connection A" }},
		{"control", func(c *scimorganization.DirectoryUserMappingConfig) { c.Members[0].MemberID = "Member\x7f" }},
		{"invalid UTF8", func(c *scimorganization.DirectoryUserMappingConfig) {
			c.Members[0].UserID = identity.UserID(string([]byte{0xff}))
		}},
		{"duplicate", func(c *scimorganization.DirectoryUserMappingConfig) { c.Members = append(c.Members, c.Members[0]) }},
		{"conflicting source", func(c *scimorganization.DirectoryUserMappingConfig) {
			c.Members = append(c.Members, scimorganization.DirectoryMemberUserMapping{MemberID: "Member.A", UserID: "User.Other"})
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			config := directoryUserConfig()
			test.edit(&config)
			if _, err := scimorganization.NewDirectoryUserMapper(config); !errors.Is(err, scimorganization.ErrInvalidMappingInput) {
				t.Fatal("invalid or ambiguous policy was accepted")
			}
		})
	}
	config := directoryUserConfig()
	config.Members = make([]scimorganization.DirectoryMemberUserMapping, 1000)
	for i := range config.Members {
		config.Members[i] = scimorganization.DirectoryMemberUserMapping{MemberID: fmt.Sprintf("Member.%d", i), UserID: "User.A"}
	}
	config.Members[0].MemberID = strings.Repeat("ä", 64)
	if _, err := scimorganization.NewDirectoryUserMapper(config); err != nil {
		t.Fatal("valid maximum table, UTF8 boundary or explicit shared target was rejected")
	}
}

func TestDirectoryUserMappingRedactsImplicitOutput(t *testing.T) {
	config := directoryUserConfig()
	mapper, err := scimorganization.NewDirectoryUserMapper(config)
	if err != nil {
		t.Fatal(err)
	}
	mapped, err := mapper.MapDirectoryUserDelta(directoryUserBatch(t))
	if err != nil {
		t.Fatal(err)
	}
	for _, value := range []any{config, mapper, mapped, mapped.Users[0]} {
		formatted := fmt.Sprintf("%v %+v %#v %s", value, value, value, value)
		logged := value.(slog.LogValuer).LogValue().String()
		for _, sensitive := range []string{"Tenant.A", "Org.A", "Provider.A", "Connection.A", "Member.A", "User.A", "Revision.A", "AQEBAQEBAQEBAQEBAQEBAQ"} {
			if strings.Contains(formatted, sensitive) || strings.Contains(logged, sensitive) {
				t.Fatal("implicit formatting or structured logging exposed mapping identifiers")
			}
		}
		if _, err := json.Marshal(value); !errors.Is(err, scimorganization.ErrSensitiveSerialization) {
			t.Fatal("implicit JSON exposed mapping data")
		}
		if _, err := value.(encoding.TextMarshaler).MarshalText(); !errors.Is(err, scimorganization.ErrSensitiveSerialization) {
			t.Fatal("implicit text exposed mapping data")
		}
	}
}

func directoryUserConfig() scimorganization.DirectoryUserMappingConfig {
	return scimorganization.DirectoryUserMappingConfig{
		TenantID: "Tenant.A", OrganizationID: "Org.A", ProviderID: "Provider.A", ConnectionID: "Connection.A", MappingVersion: 7,
		Members:        []scimorganization.DirectoryMemberUserMapping{{MemberID: "Member.A", UserID: "User.A"}},
		AllowAdmission: true, AllowWithdrawal: true,
	}
}

func directoryUserBatch(t *testing.T) sso.DirectoryDeltaBatch {
	t.Helper()
	batch := directoryBatch(t)
	batch.Deltas = []sso.DirectoryDelta{
		directoryUserAdmission(t, "AQEBAQEBAQEBAQEBAQEBAQ", "Member.A", "Revision.A"),
		directoryUserWithdrawal(t, "AgICAgICAgICAgICAgICAg", "Member.A", "Revision.B", sso.DirectoryUserInactive),
		directoryUserWithdrawal(t, "AwMDAwMDAwMDAwMDAwMDAw", "Member.A", "Revision.C", sso.DirectoryUserDeleted),
	}
	return batch
}

func directoryUserAdmission(t *testing.T, command identity.CommandID, resource, revision string) sso.DirectoryDelta {
	t.Helper()
	delta, err := sso.NewDirectoryUserAdmissionDelta(command, resource, revision)
	if err != nil {
		t.Fatal(err)
	}
	return delta
}

func directoryUserWithdrawal(t *testing.T, command identity.CommandID, resource, revision string, state sso.DirectoryUserDeprovisionState) sso.DirectoryDelta {
	t.Helper()
	delta, err := sso.NewDirectoryUserDeprovisionDelta(command, resource, revision, state)
	if err != nil {
		t.Fatal(err)
	}
	return delta
}
