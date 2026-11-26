package scim_test

import (
	"encoding/json"
	"testing"

	scim "github.com/faustbrian/go-scim"
)

func TestErrorSCIMTypeReportsNormalizedSafeType(t *testing.T) {
	var nilError *scim.Error
	cases := []struct {
		name string
		err  *scim.Error
		want string
	}{
		{"invalid filter", scim.NewError(400, "invalidFilter"), "invalidFilter"},
		{"too many", scim.NewError(400, "tooMany"), "tooMany"},
		{"mutability", scim.NewError(400, "mutability"), "mutability"},
		{"invalid syntax", scim.NewError(400, "invalidSyntax"), "invalidSyntax"},
		{"invalid path", scim.NewError(400, "invalidPath"), "invalidPath"},
		{"no target", scim.NewError(400, "noTarget"), "noTarget"},
		{"invalid value", scim.NewError(400, "invalidValue"), "invalidValue"},
		{"invalid version", scim.NewError(400, "invalidVers"), "invalidVers"},
		{"uniqueness", scim.NewError(409, "uniqueness"), "uniqueness"},
		{"untyped", scim.NewError(404, ""), ""},
		{"unknown type", scim.NewError(400, "unregistered-provider-detail"), ""},
		{"wrong type status", scim.NewError(409, "invalidPath"), ""},
		{"wrong uniqueness status", scim.NewError(400, "uniqueness"), ""},
		{"unsupported status", scim.NewError(499, "invalidValue"), ""},
		{"zero value", new(scim.Error), ""},
		{"nil", nilError, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			typed, ok := any(tc.err).(interface{ SCIMType() string })
			if !ok {
				t.Fatal("*scim.Error does not expose SCIMType() string")
			}
			before, err := tc.err.MarshalJSON()
			if err != nil {
				t.Fatal(err)
			}
			if got := typed.SCIMType(); got != tc.want {
				t.Fatalf("SCIMType() = %q, want %q", got, tc.want)
			}
			after, err := tc.err.MarshalJSON()
			if err != nil {
				t.Fatal(err)
			}
			if string(after) != string(before) {
				t.Fatalf("SCIMType changed the wire error: before %s, after %s", before, after)
			}
			var wire struct {
				Type string `json:"scimType"`
			}
			if err := json.Unmarshal(after, &wire); err != nil {
				t.Fatal(err)
			}
			if wire.Type != tc.want {
				t.Fatalf("wire scimType = %q, want %q", wire.Type, tc.want)
			}
		})
	}
}
