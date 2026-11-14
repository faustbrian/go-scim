package scimpostgres

import (
	"context"
	"encoding/json"

	identity "github.com/faustbrian/go-identity"
	scim "github.com/faustbrian/go-scim"
	"github.com/jackc/pgx/v5"
)

// Snapshot deliberately leaves filter/sort/projection semantics with the public
// SCIM owner. PostgreSQL provides one bounded complete connection snapshot; a
// preflight over at most limit+1 rows rejects excess before resource decoding.
// Repeatable read keeps that admission and all returned values on one snapshot,
// so concurrent writers cannot turn a complete result into a partial count.
func (b *protocolBridge) Snapshot(ctx context.Context, scope scim.Scope, budget scim.SnapshotBudget) (scim.Snapshot, error) {
	i, err := currentInvocation(ctx)
	if err != nil || scope != i.connection.Scope || !liveConnection(ctx, i.connection) {
		return scim.Snapshot{}, identity.ForbiddenError{}
	}
	s := b.service
	limits := s.config().Limits
	if budget.Resources < 1 || budget.Resources > limits.SnapshotResources || budget.Bytes < 1 || budget.Bytes > limits.SnapshotBytes {
		return scim.Snapshot{}, identity.InvalidInputError{Field: "scim_snapshot_budget"}
	}
	tx, err := s.pool.Raw().BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.RepeatableRead, AccessMode: pgx.ReadOnly})
	if err != nil {
		return scim.Snapshot{}, identity.UnavailableError{}
	}
	defer func() {
		cleanup, cancel := context.WithTimeout(context.WithoutCancel(ctx), s.config().MaximumDuration)
		defer cancel()
		_ = tx.Rollback(cleanup)
	}()
	args := append(scopeArgs(scope), budget.Resources+1)
	var count, bytes int64
	preflight := `SELECT count(*),COALESCE(sum(octet_length(resource)),0)::bigint FROM (
 SELECT resource FROM scim.users WHERE tenant_id=$1 AND organization_id=$2 AND provider_id=$3 AND connection_id=$4 AND deleted_at IS NULL ORDER BY resource_id LIMIT $5
) AS bounded_snapshot`
	if b.groups {
		preflight = `SELECT count(*),COALESCE(sum(octet_length(resource)),0)::bigint FROM (
 SELECT resource FROM scim.groups WHERE tenant_id=$1 AND organization_id=$2 AND provider_id=$3 AND connection_id=$4 AND deleted_at IS NULL ORDER BY resource_id LIMIT $5
) AS bounded_snapshot`
	}
	err = tx.QueryRow(ctx, preflight, args...).Scan(&count, &bytes)
	if err != nil || count < 0 || bytes < 0 {
		return scim.Snapshot{}, identity.UnavailableError{}
	}
	if count > int64(budget.Resources) || bytes > int64(budget.Bytes) {
		if err := tx.Commit(ctx); err != nil {
			return scim.Snapshot{}, identity.UnavailableError{}
		}
		if err := s.recheckRead(ctx, i); err != nil {
			return scim.Snapshot{}, err
		}
		return scim.Snapshot{Complete: false}, nil
	}
	query := `SELECT s.resource_id,s.user_id,s.resource,u.status FROM scim.users s
 JOIN identity.users u ON u.tenant_id=s.tenant_id AND u.user_id=s.user_id
 WHERE s.tenant_id=$1 AND s.organization_id=$2 AND s.provider_id=$3 AND s.connection_id=$4 AND s.deleted_at IS NULL ORDER BY s.resource_id`
	if b.groups {
		query = `SELECT resource_id,''::text,resource,''::text FROM scim.groups WHERE tenant_id=$1 AND organization_id=$2 AND provider_id=$3 AND connection_id=$4 AND deleted_at IS NULL ORDER BY resource_id`
	}
	rows, err := tx.Query(ctx, query, scopeArgs(scope)...)
	if err != nil {
		return scim.Snapshot{}, identity.UnavailableError{}
	}
	defer rows.Close()
	resources := make([]scim.Resource, 0, int(count))
	remaining := int64(budget.Bytes)
	for rows.Next() {
		var id, user, status string
		var wire []byte
		if rows.Scan(&id, &user, &wire, &status) != nil || len(resources) >= int(count) || len(wire) > 131072 || int64(len(wire)) > remaining {
			return scim.Snapshot{}, identity.UnavailableError{}
		}
		if _, err := identity.ParseSubjectID(id); err != nil || !b.groups && (user != id || status != string(identity.StatusActive)) {
			return scim.Snapshot{}, identity.ForbiddenError{}
		}
		var resource scim.Resource
		if json.Unmarshal(wire, &resource) != nil || resource.ID != id {
			return scim.Snapshot{}, identity.UnavailableError{}
		}
		remaining -= int64(len(wire))
		resources = append(resources, resource)
	}
	if rows.Err() != nil || len(resources) != int(count) {
		return scim.Snapshot{}, identity.UnavailableError{}
	}
	rows.Close()
	if err := tx.Commit(ctx); err != nil {
		return scim.Snapshot{}, identity.UnavailableError{}
	}
	if err := s.recheckRead(ctx, i); err != nil {
		return scim.Snapshot{}, err
	}
	return scim.Snapshot{Resources: resources, Complete: true}, nil
}
