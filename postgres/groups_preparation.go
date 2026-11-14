package scimpostgres

import (
	"encoding/json"
	"unicode/utf8"

	identity "github.com/faustbrian/go-identity"
	scim "github.com/faustbrian/go-scim"
)

func (p *nativePhase) validateGroupOriginal(input originalInput) error {
	if input.Schema != 3 || input.Operation != p.intent.Operation || !p.group() || input.KernelVersion != 0 || input.UserAuthority != 0 || !nativeVersion(input.Version) {
		return identity.UnavailableError{}
	}
	if input.Operation == scim.GroupCreate {
		if input.Current != nil || input.Generation != 0 {
			return identity.UnavailableError{}
		}
	} else if !nativeMutation(input.Operation) || input.ID != p.intent.ResourceID || input.Current == nil && input.Generation != 0 {
		return identity.UnavailableError{}
	}
	if current := input.Current; current != nil {
		wire, err := json.Marshal(current)
		if err != nil || len(wire) > 131072 || current.ID != input.ID || !nativeVersion(current.Version) || current.CreatedAt.IsZero() || current.LastModified.Before(current.CreatedAt) || current.LastModified.After(input.At) || input.Generation < 1 {
			return identity.UnavailableError{}
		}
	}
	if input.Operation == scim.GroupCreate || input.Current != nil {
		if _, err := identity.ParseSubjectID(input.ID); err != nil {
			return identity.UnavailableError{}
		}
	} else if input.ID == "" || len(input.ID) > 128 || !utf8.ValidString(input.ID) {
		return identity.UnavailableError{}
	}
	return nil
}
