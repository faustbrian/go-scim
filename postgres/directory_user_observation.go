package scimpostgres

import (
	"bytes"
	"context"
	"fmt"

	identity "github.com/faustbrian/go-identity"
	scim "github.com/faustbrian/go-scim"
)

// DirectoryUserTarget names a SCIM resource and its expected exact persisted
// local identity. The two identifiers need not have the same format.
type DirectoryUserTarget struct {
	ResourceID string
	UserID     identity.UserID
}

func (DirectoryUserTarget) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("scimpostgres.DirectoryUserTarget(redacted)"))
}

// DirectoryUserObservation describes explicit current source state at the
// returned native revision. A zero value is unproven, not a deletion or a
// withdrawal instruction. It confers no authority to apply a delta.
type DirectoryUserObservation struct {
	State    DirectoryUserMembershipState
	Revision scim.Version
}

func (DirectoryUserObservation) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("scimpostgres.DirectoryUserObservation(redacted)"))
}

// ReadDirectoryUserStates observes 1..128 User targets in order in one primary
// snapshot. A missing row, mismatched local identity or omitted active field
// produces a zero observation. A retained deletion uses the original delete
// revision, not the previous live ETag. Errors disclose no prefix. The read
// never renews source freshness or writes; callers own directory authorization
// and any later reconciliation policy. Do not mutate targets during the call.
func (s *GroupsService) ReadDirectoryUserStates(ctx context.Context, observation DirectorySourceObservation, targets []DirectoryUserTarget) ([]DirectoryUserObservation, error) {
	if s == nil || s.native == nil || s.native.config == nil || ctx == nil || observation.source != s.native ||
		len(targets) == 0 || len(targets) > maximumDirectoryGroupRoleEdges {
		return nil, identity.ForbiddenError{}
	}
	ids := make([]string, len(targets))
	for i, target := range targets {
		if _, err := identity.ParseSubjectID(target.ResourceID); err != nil || !directoryGroupRoleLocalID(string(target.UserID)) {
			return nil, identity.ForbiddenError{}
		}
		ids[i] = target.ResourceID
	}

	native := s.native
	ctx, cancel := context.WithTimeout(ctx, native.config().MaximumDuration)
	defer cancel()
	bindings, err := observation.bindings(ctx)
	if err != nil {
		return nil, err
	}
	ctx, finish := context.WithDeadline(ctx, bindings.ValidUntil)
	defer finish()
	original := observation.admission
	rows, err := native.pool.Raw().Query(ctx, directoryUserStatesSQL, directorySourceReadArguments(native, bindings, original, ids)...)
	if err != nil {
		return nil, identity.UnavailableError{}
	}
	defer rows.Close()
	results := make([]DirectoryUserObservation, 0, len(ids))
	for rows.Next() {
		var ordinal int64
		var found, deleted bool
		var user, command string
		var wire []byte
		if err := rows.Scan(&ordinal, &found, &deleted, &user, &command, &wire); err != nil || len(results) >= len(ids) || ordinal != int64(len(results)+1) {
			clear(wire)
			return nil, identity.UnavailableError{}
		}
		state, err := classifyDirectoryUser(targets[len(results)], found, deleted, user, command, wire)
		if err != nil {
			return nil, err
		}
		results = append(results, state)
	}
	if rows.Err() != nil || len(results) != len(ids) {
		return nil, identity.UnavailableError{}
	}
	rows.Close()
	if err := native.recheckRead(ctx, &original); err != nil {
		return nil, err
	}
	if !liveConnection(ctx, original.connection) {
		return nil, identity.ForbiddenError{}
	}
	return results, nil
}

func classifyDirectoryUser(target DirectoryUserTarget, found, deleted bool, user, command string, wire []byte) (DirectoryUserObservation, error) {
	defer clear(wire)
	if !found || user != string(target.UserID) {
		return DirectoryUserObservation{}, nil
	}
	if deleted {
		revision := scim.Version(`"` + command + `"`)
		if !bytes.Equal(wire, []byte("null")) || !nativeVersion(revision) {
			return DirectoryUserObservation{}, identity.UnavailableError{}
		}
		return DirectoryUserObservation{State: DirectoryMembershipUserDeleted, Revision: revision}, nil
	}
	projected, err := directoryGroupEdgeResource(wire, target.ResourceID, "User")
	if err != nil || !nativeVersion(projected.Version) {
		return DirectoryUserObservation{}, identity.UnavailableError{}
	}
	raw, present := projected.Attributes["active"]
	if !present {
		return DirectoryUserObservation{}, nil
	}
	active, ok := raw.(bool)
	if !ok {
		return DirectoryUserObservation{}, identity.UnavailableError{}
	}
	state := DirectoryMembershipUserInactive
	if active {
		state = DirectoryMembershipUserActive
	}
	return DirectoryUserObservation{State: state, Revision: projected.Version}, nil
}

const directoryUserStatesSQL = directorySourceReadCTE + `SELECT t.ordinal,u.resource_id IS NOT NULL,u.deleted_at IS NOT NULL,
 COALESCE(u.user_id::text,''),COALESCE(u.command_id::text,''),u.wire
FROM admitted c
CROSS JOIN unnest($13::text[]) WITH ORDINALITY AS t(resource_id,ordinal)
LEFT JOIN LATERAL (
 SELECT resource_id,deleted_at,user_id,command_id,CASE WHEN octet_length(resource)<=131072 THEN resource END AS wire
 FROM scim.users WHERE tenant_id=c.tenant_id AND organization_id=c.organization_id AND provider_id=c.provider_id
 AND connection_id=c.connection_id AND resource_id=t.resource_id LIMIT 1
) u ON true
ORDER BY t.ordinal`
