package scimpostgres

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"strings"

	identity "github.com/faustbrian/go-identity"
	kernel "github.com/faustbrian/go-identity/postgres"
	scim "github.com/faustbrian/go-scim"
)

// DirectoryGroupEdge selects one exact, direct SCIM Group-to-User resource
// edge. IDs are canonical, case-sensitive resource IDs, not names, externalId
// values or identity user IDs. Present=false requires a known Group whose edge
// is absent (including a retained Group tombstone), never an unknown Group.
// This detached claim grants no permission and owns no resources.
type DirectoryGroupEdge struct {
	GroupID string
	UserID  string
	Present bool
}

// Field commits the exact IDs and selected presence to the original feature
// command before reservation. Both this commitment and the original source
// observation's Field are required by the Work fences; neither is authority.
// Missing or noncanonical IDs return Forbidden without retaining their values.
func (e DirectoryGroupEdge) Field() (identity.FeatureField, error) {
	if _, err := identity.ParseSubjectID(e.GroupID); err != nil {
		return identity.FeatureField{}, identity.ForbiddenError{}
	}
	if _, err := identity.ParseSubjectID(e.UserID); err != nil {
		return identity.FeatureField{}, identity.ForbiddenError{}
	}
	wire, err := json.Marshal(e)
	if err != nil {
		return identity.FeatureField{}, identity.ForbiddenError{}
	}
	defer clear(wire)
	digest := sha256.Sum256(append([]byte("scim-postgres/directory-group-edge/v1\x00"), wire...))
	return identity.FeatureField{Name: "scim.directory-group-edge", Value: identity.FeatureValue{Kind: identity.FeatureBytes, Bytes: digest[:]}}, nil
}

// RequireDirectoryGroupEdge authenticates the original command/owner/Apply
// invocation and original source, then checks the exact scoped current edge
// while holding the existing connection writer fence. The User projection's
// stored identity mapping must equal command.Binding.UserID; a grant requires
// both resources live. No nested Group is traversed or treated as a User.
// This borrows Work, creates no transaction or permission decision, and never
// renews source evidence. Propagate failure and recheck with the matching final
// fence in the exact owner's CheckFeatureCommit invocation.
func (s *GroupsService) RequireDirectoryGroupEdge(ctx context.Context, w kernel.Work, owner kernel.FeatureExecutionContributor, command identity.Command, observation DirectorySourceObservation, edge DirectoryGroupEdge) error {
	if err := s.RequireDirectorySource(ctx, w, owner, command, observation); err != nil {
		return err
	}
	return s.requireDirectoryGroupEdge(ctx, w, command, observation, edge)
}

// RequireDirectoryGroupEdgeAtCommit rechecks the same original source and
// claimed edge in the authenticated final invocation. As with the source final
// fence, the owner must compare command to its retained original command first.
// Removal permits retained User/Group tombstones but requires the exact known
// User-to-identity mapping and known Group. Missing, malformed or changed state
// denies and must roll back all provisional effects.
func (s *GroupsService) RequireDirectoryGroupEdgeAtCommit(ctx context.Context, w kernel.Work, owner kernel.FeatureExecutionContributor, command identity.Command, observation DirectorySourceObservation, edge DirectoryGroupEdge) error {
	if err := s.RequireDirectorySourceAtCommit(ctx, w, owner, command, observation); err != nil {
		return err
	}
	return s.requireDirectoryGroupEdge(ctx, w, command, observation, edge)
}

const directoryGroupEdgeGroupSQL = `SELECT resource,deleted_at IS NOT NULL FROM scim.groups WHERE tenant_id=$1 AND organization_id=$2 AND provider_id=$3 AND connection_id=$4 AND resource_id=$5 AND octet_length(resource)<=131072`
const directoryGroupEdgeUserSQL = `SELECT user_id,resource,deleted_at IS NOT NULL FROM scim.users WHERE tenant_id=$1 AND organization_id=$2 AND provider_id=$3 AND connection_id=$4 AND resource_id=$5 AND octet_length(resource)<=131072`

func (s *GroupsService) requireDirectoryGroupEdge(ctx context.Context, w kernel.Work, command identity.Command, observation DirectorySourceObservation, edge DirectoryGroupEdge) error {
	return s.requireDirectoryGroupEdgeWithProfile(ctx, w, command, observation, edge, false)
}

func (s *GroupsService) requireDirectoryRoleGroupEdge(ctx context.Context, w kernel.Work, command identity.Command, observation DirectorySourceObservation, edge DirectoryGroupEdge) error {
	return s.requireDirectoryGroupEdgeWithProfile(ctx, w, command, observation, edge, true)
}

func (s *GroupsService) requireDirectoryGroupEdgeWithProfile(ctx context.Context, w kernel.Work, command identity.Command, observation DirectorySourceObservation, edge DirectoryGroupEdge, role bool) error {
	expected, err := edge.Field()
	if err != nil {
		return err
	}
	spec, ok := command.Feature()
	if !ok {
		return identity.ForbiddenError{}
	}
	matches := 0
	for _, field := range spec.Fields {
		if field.Name != expected.Name {
			continue
		}
		if field.Value.Kind != identity.FeatureBytes || !bytes.Equal(field.Value.Bytes, expected.Value.Bytes) {
			return identity.ForbiddenError{}
		}
		matches++
	}
	if matches != 1 {
		return identity.ForbiddenError{}
	}
	ctx, cancel := context.WithTimeout(ctx, s.native.config().MaximumDuration)
	defer cancel()
	// RequireDirectorySource has acquired scim.connections FOR UPDATE, the
	// serialization owner used by every supported Group/User projection writer.
	// These two full-primary-key reads therefore observe the same protected edge.
	scope := s.native.config().Scope
	rows, err := w.Query(ctx, directoryGroupEdgeGroupSQL, append(scopeArgs(scope), edge.GroupID)...)
	if err != nil {
		return identity.UnavailableError{}
	}
	defer rows.Close()
	var groupWire []byte
	var groupDeleted bool
	if !rows.Next() || rows.Scan(&groupWire, &groupDeleted) != nil || rows.Next() || rows.Err() != nil {
		return identity.ForbiddenError{}
	}
	rows.Close()
	defer clear(groupWire)
	if groupDeleted && (edge.Present || !bytes.Equal(groupWire, []byte("null"))) {
		return identity.ForbiddenError{}
	}
	if !groupDeleted {
		group, err := directoryGroupEdgeResource(groupWire, edge.GroupID, "Group")
		if err != nil {
			return err
		}
		present, err := directoryGroupEdgePresent(group, edge.UserID, s.native.config().BaseURL)
		if err != nil || present != edge.Present {
			return identity.ForbiddenError{}
		}
	}
	rows, err = w.Query(ctx, directoryGroupEdgeUserSQL, append(scopeArgs(scope), edge.UserID)...)
	if err != nil {
		return identity.UnavailableError{}
	}
	defer rows.Close()
	var userID string
	var userWire []byte
	var userDeleted bool
	if !rows.Next() || rows.Scan(&userID, &userWire, &userDeleted) != nil || rows.Next() || rows.Err() != nil {
		return identity.ForbiddenError{}
	}
	rows.Close()
	defer clear(userWire)
	if userID != string(spec.Binding.UserID) {
		return identity.ForbiddenError{}
	}
	if userDeleted {
		if edge.Present || !bytes.Equal(userWire, []byte("null")) {
			return identity.ForbiddenError{}
		}
	} else {
		user, err := directoryGroupEdgeResource(userWire, edge.UserID, "User")
		if err != nil {
			return err
		}
		if role && edge.Present {
			active, err := directoryGroupRoleUserActive(user)
			if err != nil {
				return err
			}
			if !active {
				return identity.ForbiddenError{}
			}
		}
	}
	// The connection lock retains source versions, but a slow lookup cannot
	// retain time. Recheck the original deadline after all projection work.
	source := observation.admission.connection
	now, err := w.DatabaseTime(ctx)
	if err != nil || !now.Before(source.AuthorityValidUntil) || !now.Before(source.ExpiresAt) || !liveConnection(ctx, source) {
		return identity.ForbiddenError{}
	}
	return nil
}

func directoryGroupEdgeResource(wire []byte, id, kind string) (scim.Resource, error) {
	var resource scim.Resource
	if len(wire) == 0 || len(wire) > 131072 || json.Unmarshal(wire, &resource) != nil || resource.ID != id || resource.Version == "" || resource.CreatedAt.IsZero() || resource.LastModified.Before(resource.CreatedAt) || resource.Attributes == nil {
		return scim.Resource{}, identity.ForbiddenError{}
	}
	core := "urn:ietf:params:scim:schemas:core:2.0:" + kind
	found := false
	for _, schema := range resource.Schemas {
		if schema == core {
			if found {
				return scim.Resource{}, identity.ForbiddenError{}
			}
			found = true
		}
	}
	if !found {
		return scim.Resource{}, identity.ForbiddenError{}
	}
	return resource, nil
}

func directoryGroupEdgePresent(resource scim.Resource, userID, baseURL string) (bool, error) {
	raw, exists := resource.Attributes["members"]
	if !exists {
		return false, nil
	}
	members, ok := raw.([]any)
	if !ok || len(members) > scim.DefaultGroupMembers {
		return false, identity.ForbiddenError{}
	}
	found := false
	seen := make(map[string]bool, len(members))
	for _, raw := range members {
		member, ok := raw.(map[string]any)
		if !ok {
			return false, identity.ForbiddenError{}
		}
		id, _ := member["value"].(string)
		kind, _ := member["type"].(string)
		ref, _ := member["$ref"].(string)
		if _, err := identity.ParseSubjectID(id); err != nil || kind != "User" && kind != "Group" || ref != baseURL+"/"+kind+"s/"+id {
			return false, identity.ForbiddenError{}
		}
		key := kind + "\x00" + strings.ToLower(id)
		if seen[key] {
			return false, identity.ForbiddenError{}
		}
		seen[key] = true
		if kind == "User" && id == userID {
			found = true
		}
	}
	return found, nil
}
