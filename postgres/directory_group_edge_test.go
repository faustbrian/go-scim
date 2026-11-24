package scimpostgres

import (
	"bytes"
	"context"
	"testing"

	identity "github.com/faustbrian/go-identity"
	kernel "github.com/faustbrian/go-identity/postgres"
)

func TestDirectoryGroupEdgeCommandCommitmentBindsExactIDsAndPresence(t *testing.T) {
	edge := DirectoryGroupEdge{GroupID: "AAAAAAAAAAAAAAAAAAAAAQ", UserID: "AAAAAAAAAAAAAAAAAAAAAg", Present: true}
	field, err := edge.Field()
	if err != nil || field.Name != "scim.directory-group-edge" || field.Value.Kind != identity.FeatureBytes || len(field.Value.Bytes) != 32 {
		t.Fatal("exact edge lacks bounded command commitment", err)
	}
	for _, changed := range []DirectoryGroupEdge{
		{GroupID: "AAAAAAAAAAAAAAAAAAAAAw", UserID: edge.UserID, Present: true},
		{GroupID: edge.GroupID, UserID: "AAAAAAAAAAAAAAAAAAAABg", Present: true},
		{GroupID: edge.GroupID, UserID: edge.UserID, Present: false},
	} {
		other, err := changed.Field()
		if err != nil || bytes.Equal(field.Value.Bytes, other.Value.Bytes) {
			t.Fatal("different edge shares original command commitment", err)
		}
	}
	for _, invalid := range []DirectoryGroupEdge{
		{}, {GroupID: edge.GroupID}, {UserID: edge.UserID},
		{GroupID: edge.GroupID + "=", UserID: edge.UserID},
		{GroupID: edge.GroupID, UserID: "AAAAAAAAAAAAAAAAAAAAAh"},
	} {
		if _, err := invalid.Field(); err == nil {
			t.Fatal("missing or noncanonical exact ID produced a commitment")
		}
	}
	field.Value.Bytes[0] ^= 1
	again, err := edge.Field()
	if err != nil || bytes.Equal(field.Value.Bytes, again.Value.Bytes) {
		t.Fatal("detached field mutated edge commitment", err)
	}
	groups, observation := directorySourceTestObservation()
	if err := groups.RequireDirectoryGroupEdge(context.Background(), kernel.Work{}, nil, identity.Command{}, observation, edge); err == nil {
		t.Fatal("edge assertion substituted for authenticated Apply Work")
	}
	if err := groups.RequireDirectoryGroupEdgeAtCommit(context.Background(), kernel.Work{}, nil, identity.Command{}, observation, edge); err == nil {
		t.Fatal("edge assertion substituted for authenticated final Work")
	}
}
