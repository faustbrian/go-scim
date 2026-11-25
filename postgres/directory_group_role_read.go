package scimpostgres

import (
	"bytes"
	"context"
	"fmt"
	"strconv"
	"unicode/utf8"

	identity "github.com/faustbrian/go-identity"
	scim "github.com/faustbrian/go-scim"
)

const maximumDirectoryGroupRoleEdges = 128

// DirectoryGroupRoleEdge claims one direct Group/member resource edge and
// its exact persisted local identity mapping. It conveys no role authority.
type DirectoryGroupRoleEdge struct {
	GroupID, MemberResourceID string
	UserID                    identity.UserID
}

func (DirectoryGroupRoleEdge) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("scimpostgres.DirectoryGroupRoleEdge(redacted)"))
}

// ReadDirectoryGroupRoleEdges checks 1..128 edges in input order on the
// configured primary, with one snapshot of the exact connection and resources.
// False means no direct live edge for the exact local identity (including an
// explicitly inactive User); malformed storage, changed or unavailable source
// authority, and expired evidence yield no results. The source observation's
// deadline is not extended. This is trusted composition, not SCIM bearer
// admission, a permission decision, or an SSO provider/mapping check.
func (s *GroupsService) ReadDirectoryGroupRoleEdges(ctx context.Context, observation DirectorySourceObservation, edges []DirectoryGroupRoleEdge) ([]bool, error) {
	if s == nil || s.native == nil || s.native.config == nil || ctx == nil || observation.source != s.native ||
		len(edges) == 0 || len(edges) > maximumDirectoryGroupRoleEdges {
		return nil, identity.ForbiddenError{}
	}
	groupIDs := make([]string, len(edges))
	memberIDs := make([]string, len(edges))
	for i, edge := range edges {
		if _, err := identity.ParseSubjectID(edge.GroupID); err != nil {
			return nil, identity.ForbiddenError{}
		}
		if _, err := identity.ParseSubjectID(edge.MemberResourceID); err != nil {
			return nil, identity.ForbiddenError{}
		}
		if !directoryGroupRoleLocalID(string(edge.UserID)) {
			return nil, identity.ForbiddenError{}
		}
		groupIDs[i], memberIDs[i] = edge.GroupID, edge.MemberResourceID
	}
	native := s.native
	c := native.config()
	ctx, cancel := context.WithTimeout(ctx, c.MaximumDuration)
	defer cancel()
	bindings, err := observation.bindings(ctx)
	if err != nil {
		return nil, err
	}
	original := observation.admission
	rows, err := native.pool.Raw().Query(ctx, directoryGroupRoleEdgesSQL, directoryGroupRoleEdgeArguments(native, bindings, original, groupIDs, memberIDs)...)
	if err != nil {
		return nil, identity.UnavailableError{}
	}
	defer rows.Close()
	results := make([]bool, 0, len(edges))
	for rows.Next() {
		var ordinal int64
		var groupFound, groupDeleted, userFound, userDeleted bool
		var groupWire, userWire []byte
		var localUser string
		if err := rows.Scan(&ordinal, &groupFound, &groupDeleted, &groupWire, &userFound, &userDeleted, &localUser, &userWire); err != nil ||
			ordinal != int64(len(results)+1) || len(results) >= len(edges) {
			return nil, identity.UnavailableError{}
		}
		match, err := checkDirectoryGroupRoleEdge(edges[len(results)], c.BaseURL, groupFound, groupDeleted, groupWire, userFound, userDeleted, localUser, userWire)
		if err != nil {
			return nil, err
		}
		results = append(results, match)
	}
	if rows.Err() != nil || len(results) != len(edges) {
		return nil, identity.UnavailableError{}
	}
	rows.Close()
	// The SQL snapshot is coherent for the edge rows. After that read, fence
	// the other owners' original evidence without renewing its validity.
	if err := native.recheckRead(ctx, &original); err != nil {
		return nil, err
	}
	if !liveConnection(ctx, original.connection) {
		return nil, identity.ForbiddenError{}
	}
	return results, nil
}

func directoryGroupRoleEdgeArguments(native *Service, b DirectorySourceBindings, original invocation, groups, members []string) []any {
	c := native.config()
	return append(scopeArgs(b.Scope), strconv.FormatUint(b.ConnectionVersion, 10),
		strconv.FormatUint(original.epoch, 10), strconv.FormatUint(original.organization.CredentialVersion, 10),
		c.Credential.id, c.Credential.expected[:], native.profile[:], c.CredentialExpiresAt, b.ValidUntil, groups, members)
}

func checkDirectoryGroupRoleEdge(edge DirectoryGroupRoleEdge, baseURL string, groupFound, groupDeleted bool, groupWire []byte, userFound, userDeleted bool, localUser string, userWire []byte) (bool, error) {
	defer clear(groupWire)
	defer clear(userWire)
	present := false
	if groupFound {
		if groupDeleted {
			if !bytes.Equal(groupWire, []byte("null")) {
				return false, identity.UnavailableError{}
			}
		} else {
			group, err := directoryGroupEdgeResource(groupWire, edge.GroupID, "Group")
			if err != nil {
				return false, identity.UnavailableError{}
			}
			present, err = directoryGroupEdgePresent(group, edge.MemberResourceID, baseURL)
			if err != nil {
				return false, identity.UnavailableError{}
			}
		}
	}
	if !userFound {
		return false, nil
	}
	if userDeleted {
		if !bytes.Equal(userWire, []byte("null")) {
			return false, identity.UnavailableError{}
		}
		return false, nil
	}
	user, err := directoryGroupEdgeResource(userWire, edge.MemberResourceID, "User")
	if err != nil {
		return false, identity.UnavailableError{}
	}
	active, err := directoryGroupRoleUserActive(user)
	if err != nil {
		return false, err
	}
	return active && present && localUser == string(edge.UserID), nil
}

func directoryGroupRoleUserActive(user scim.Resource) (bool, error) {
	raw, exists := user.Attributes["active"]
	if !exists {
		// Existing native projections may omit this optional Boolean.
		return true, nil
	}
	active, ok := raw.(bool)
	if !ok {
		return false, identity.UnavailableError{}
	}
	return active, nil
}

// A stored local mapping can be a provisioned canonical ID such as a ULID,
// not necessarily one of the SubjectIDs used as native SCIM resource IDs.
func directoryGroupRoleLocalID(id string) bool {
	if len(id) == 0 || len(id) > 128 || !utf8.ValidString(id) {
		return false
	}
	for _, r := range id {
		if r <= ' ' || r == 127 {
			return false
		}
	}
	return true
}

// Unnest drives full-key Group and User point lookups in one statement. Keep
// oversized existing resources distinct from absence without returning them.
const directoryGroupRoleEdgesSQL = `WITH admitted AS MATERIALIZED (
 SELECT tenant_id,organization_id,provider_id,connection_id FROM scim.connections
 WHERE tenant_id=$1 AND organization_id=$2 AND provider_id=$3 AND connection_id=$4
 AND version=$5::numeric AND authority_version=$6::numeric AND organization_credential_version=$7::numeric
 AND credential_id=$8 AND credential_digest=$9 AND configuration_digest=$10 AND expires_at=$11 AND state='active'
 AND clock_timestamp()<$12 AND clock_timestamp()<expires_at
)
SELECT e.ordinal,g.resource_id IS NOT NULL,g.deleted_at IS NOT NULL,
 g.wire,
 u.resource_id IS NOT NULL,u.deleted_at IS NOT NULL,coalesce(u.user_id::text,''),
 u.wire
FROM admitted c
CROSS JOIN unnest($13::text[],$14::text[]) WITH ORDINALITY AS e(group_id,member_id,ordinal)
LEFT JOIN LATERAL (
 SELECT resource_id,deleted_at,CASE WHEN octet_length(resource)<=131072 THEN resource END AS wire
 FROM scim.groups WHERE tenant_id=c.tenant_id AND organization_id=c.organization_id AND provider_id=c.provider_id
 AND connection_id=c.connection_id AND resource_id=e.group_id LIMIT 1
) g ON true
LEFT JOIN LATERAL (
 SELECT resource_id,deleted_at,user_id,CASE WHEN octet_length(resource)<=131072 THEN resource END AS wire
 FROM scim.users WHERE tenant_id=c.tenant_id AND organization_id=c.organization_id AND provider_id=c.provider_id
 AND connection_id=c.connection_id AND resource_id=e.member_id LIMIT 1
) u ON true
ORDER BY e.ordinal`
