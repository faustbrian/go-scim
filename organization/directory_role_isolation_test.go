package scimorganization_test

import (
	"errors"
	"reflect"
	"testing"

	scimorganization "github.com/faustbrian/go-scim/organization"
	"github.com/faustbrian/go-sso"
)

func TestDirectoryMapperKeepsRoleLikeGroupIDsWithinExplicitMappings(t *testing.T) {
	config := directoryConfig()
	config.Groups[0] = scimorganization.DirectoryGroupTeamMapping{
		GroupID: "Administrators",
		TeamID:  "Team.ReadOnly",
	}
	mapper, err := scimorganization.NewDirectoryMapper(config)
	if err != nil {
		t.Fatal(err)
	}
	batch := directoryBatch(t)
	batch.Deltas[0] = directoryDelta(t, "AQEBAQEBAQEBAQEBAQEBAQ", "Administrators", "Member.A", sso.DirectoryMembershipAdd)

	t.Run("configured role-like ID retains only the explicit target", func(t *testing.T) {
		got, err := mapper.MapDirectoryDelta(batch)
		if err != nil {
			t.Fatal(err)
		}
		want := []scimorganization.DirectoryMembershipIntent{{
			CommandID: "AQEBAQEBAQEBAQEBAQEBAQ",
			GroupID:   "Administrators",
			MemberID:  "Member.A",
			TeamID:    "Team.ReadOnly",
			UserID:    "User.A",
			Action:    sso.DirectoryMembershipAdd,
		}}
		if !reflect.DeepEqual(got.Source, batch) || !reflect.DeepEqual(got.Memberships, want) {
			t.Fatal("role-like source ID changed the explicit target or broadened mapping output")
		}
	})

	for _, groupID := range []string{"Administrator", "Owner", "administrators", "Team.ReadOnly"} {
		t.Run("unconfigured ID "+groupID, func(t *testing.T) {
			candidate := batch
			candidate.Deltas = []sso.DirectoryDelta{
				batch.Deltas[0],
				directoryDelta(t, "AgICAgICAgICAgICAgICAg", groupID, "Member.A", sso.DirectoryMembershipAdd),
			}
			got, err := mapper.MapDirectoryDelta(candidate)
			if !errors.Is(err, scimorganization.ErrMappingDenied) {
				t.Fatal("unconfigured role-like ID or local target ID was accepted as a source alias", err)
			}
			if !reflect.DeepEqual(got, scimorganization.DirectoryMembershipBatch{}) {
				t.Fatal("denied source alias returned mapping output, including an otherwise valid prefix")
			}
		})
	}
}
