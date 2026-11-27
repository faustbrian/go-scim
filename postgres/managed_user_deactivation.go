package scimpostgres

import (
	"encoding/json"
	"strings"

	identity "github.com/faustbrian/go-identity"
	scim "github.com/faustbrian/go-scim"
)

// The protocol has already validated and bounded this canonical PatchOp.
// Identify the final explicit assignment to the core active attribute without
// reimplementing patch application. Commit must still verify the mapped result.
func managedPatchRequestsInactive(wire []byte) (bool, error) {
	var canonical struct {
		Operation scim.Operation
		Body      struct {
			Operations []struct {
				Op, Path string
				Value    json.RawMessage
			}
		}
	}
	if json.Unmarshal(wire, &canonical) != nil || canonical.Operation != scim.UserPatch || len(canonical.Body.Operations) == 0 {
		return false, identity.UnavailableError{}
	}
	active := func(path string) bool {
		return strings.EqualFold(path, "active") || strings.EqualFold(path, "urn:ietf:params:scim:schemas:core:2.0:User:active")
	}
	inactive := false
	for _, op := range canonical.Body.Operations {
		if active(op.Path) {
			inactive = !strings.EqualFold(op.Op, "remove") && string(op.Value) == "false"
		} else if op.Path == "" {
			var values map[string]json.RawMessage
			if json.Unmarshal(op.Value, &values) != nil {
				return false, identity.UnavailableError{}
			}
			for name, value := range values {
				if active(name) {
					inactive = string(value) == "false"
				}
			}
		}
	}
	return inactive, nil
}

func inactiveProjection(resource *scim.Resource) bool {
	if resource == nil {
		return false
	}
	active, explicit := resource.Attributes["active"].(bool)
	return explicit && !active
}

func (p *nativePhase) deactivatesProjection() bool {
	return p.managedUserPatch() && p.original.Current != nil && !inactiveProjection(p.original.Current) && inactiveProjection(&p.resource)
}

// Old encrypted preparations can still replay a previously committed exact
// result. If one reaches Apply, it cannot make a new partial deactivation:
// the old request did not freeze an authoritative source withdrawal.
func (p *nativePhase) legacyDeactivation() bool {
	return p.deactivatesProjection() && p.original.ManagedPatchUser == ""
}
