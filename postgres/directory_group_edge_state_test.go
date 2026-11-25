package scimpostgres

import "testing"

func TestDirectoryGroupEdgeStateRequiresAProvenProjection(t *testing.T) {
	t.Parallel()
	edge := DirectoryGroupRoleEdge{UserID: "selected"}
	for _, tc := range []struct {
		name                  string
		groupFound, userFound bool
		local                 string
		want                  DirectoryGroupEdgeState
	}{
		{name: "known-tombstones", groupFound: true, userFound: true, local: "selected", want: DirectoryGroupEdgeAbsent},
		{name: "missing-group", userFound: true, local: "selected", want: DirectoryGroupEdgeUnproven},
		{name: "missing-user", groupFound: true, want: DirectoryGroupEdgeUnproven},
		{name: "changed-link", groupFound: true, userFound: true, local: "Selected", want: DirectoryGroupEdgeUnproven},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := classifyDirectoryGroupEdge(edge, "", tc.groupFound, tc.groupFound, []byte("null"), tc.userFound, tc.userFound, tc.local, []byte("null"))
			if err != nil || got != tc.want {
				t.Fatalf("edge state = %v, %v; want %v", got, err, tc.want)
			}
		})
	}
	if got, err := classifyDirectoryGroupEdge(edge, "", true, true, []byte("{}"), true, true, "selected", []byte("null")); err == nil || got != 0 {
		t.Fatal("a malformed tombstone was classified", got, err)
	}
}
