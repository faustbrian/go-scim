package scimpostgres

import "testing"

func TestManagedUserDeactivationSelectsTheFinalCoreAssignment(t *testing.T) {
	for _, tc := range []struct {
		name, operations string
		want             bool
	}{
		{"direct", `{"op":"replace","path":"active","value":false}`, true},
		{"qualified", `{"op":"Add","path":"urn:ietf:params:scim:schemas:core:2.0:User:Active","value":false}`, true},
		{"pathless", `{"op":"replace","value":{"ACTIVE":false,"displayName":"Name"}}`, true},
		{"unrelated", `{"op":"replace","path":"displayName","value":"false"}`, false},
		{"extension", `{"op":"replace","path":"urn:example:extension:active","value":false}`, false},
		{"later unset", `{"op":"replace","path":"active","value":false},{"op":"remove","path":"active"}`, false},
		{"later true", `{"op":"add","value":{"active":false}},{"op":"replace","path":"active","value":true}`, false},
		{"later unrelated", `{"op":"add","value":{"active":false}},{"op":"replace","path":"displayName","value":"Name"}`, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			canonical := []byte(`{"Operation":"identity.scim.user-patch","Body":{"Operations":[` + tc.operations + `]}}`)
			if got, err := managedPatchRequestsInactive(canonical); err != nil || got != tc.want {
				t.Fatalf("managed deactivation selection = %v, %v; want %v", got, err, tc.want)
			}
		})
	}
}
