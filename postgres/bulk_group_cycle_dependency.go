package scimpostgres

import (
	"context"
	"encoding/json"
	"slices"

	identity "github.com/faustbrian/go-identity"
	kernel "github.com/faustbrian/go-identity/postgres"
)

type bulkCycleDependency struct {
	parent   identity.CommandID
	order    int
	id       int
	members  []*bulkChildExecution
	external string
}

func newBulkCycleDependency(members []*bulkChildExecution) (*bulkCycleDependency, error) {
	if len(members) == 0 {
		return nil, identity.UnavailableError{}
	}
	internal := make(map[string]struct{}, len(members))
	for _, member := range members {
		internal[member.row.Command] = struct{}{}
	}
	// The original sealed graph owns these IDs. Distinct external IDs are
	// bounded by the request's operation limit, even for dense internal edges.
	external := make(map[string]struct{})
	for _, member := range members {
		for _, edge := range member.row.Dependencies {
			if _, inCycle := internal[edge]; !inCycle {
				external[edge] = struct{}{}
			}
		}
	}
	if len(external) == 0 {
		return nil, nil
	}
	ids := make([]string, 0, len(external))
	for id := range external {
		ids = append(ids, id)
	}
	slices.Sort(ids)
	encoded, err := json.Marshal(ids)
	if err != nil {
		return nil, identity.UnavailableError{}
	}
	first := members[0]
	return &bulkCycleDependency{parent: first.parent, order: first.row.ComponentOrder,
		id: first.row.ComponentID, members: members, external: string(encoded)}, nil
}

func (c *bulkCycleDependency) args() []any {
	return []any{string(c.parent), c.order, c.id}
}

type bulkCycleDependencyState struct {
	status                   string
	cutoff, ordered          bool
	failed, pending, skipped bool
}

func (s bulkCycleDependencyState) canFail() bool {
	if !s.failed {
		return false
	}
	if s.cutoff {
		return s.status == "dependency-blocked"
	}
	return s.ordered && (s.status == "admitted" || s.status == "dependency-blocked")
}

func (s bulkCycleDependencyState) canStart() bool {
	return !s.cutoff && s.ordered && !s.failed && !s.pending && !s.skipped &&
		(s.status == "admitted" || s.status == "dependency-blocked")
}

const bulkCycleDependencyRead = `SELECT parent.cutoff_active,(` + bulkPriorComponentsReady + `),
 members.total,members.first_status,members.last_status,dep.failed,dep.pending,dep.skipped
FROM scim.bulk_requests parent
CROSS JOIN (SELECT $1::text parent_id,$2::smallint component_order) child
CROSS JOIN LATERAL (
 SELECT count(*) total,min(member.status) first_status,max(member.status) last_status
 FROM scim.bulk_children member WHERE member.parent_id=parent.parent_id
  AND member.component_order=child.component_order AND member.component_id=$3 AND member.cyclic
) members
CROSS JOIN LATERAL (
 SELECT coalesce(bool_or(predecessor.status='failed'),false) failed,
  coalesce(bool_or(predecessor.status IS NULL OR predecessor.status NOT IN ('succeeded','failed','skipped')),false) pending,
  coalesce(bool_or(predecessor.status='skipped'),false) skipped
 FROM jsonb_array_elements_text($4::jsonb) edge(id)
 LEFT JOIN LATERAL (
  SELECT status FROM scim.bulk_children predecessor
  WHERE predecessor.command_id=edge.id AND predecessor.parent_id=parent.parent_id LIMIT 1
 ) predecessor ON true
) dep WHERE parent.parent_id=$1`

const bulkCycleDependencyBlock = `UPDATE scim.bulk_children member SET status='dependency-blocked'
WHERE member.parent_id=$1
 AND member.component_order=$2 AND member.component_id=$3 AND member.cyclic
 AND member.status='admitted'
 AND (SELECT NOT cutoff_active FROM scim.bulk_requests WHERE parent_id=$1)`

const bulkCycleDependencySkip = `UPDATE scim.bulk_children member SET status='skipped',skip_reason='fail-on-errors'
WHERE member.parent_id=$1
 AND member.component_order=$2 AND member.component_id=$3 AND member.cyclic
 AND member.status='dependency-blocked'
 AND (SELECT cutoff_active FROM scim.bulk_requests WHERE parent_id=$1)`

func readBulkCycleDependency(ctx context.Context, w kernel.Work, cycle *bulkCycleDependency) (bulkCycleDependencyState, error) {
	var state bulkCycleDependencyState
	rows, err := w.Query(ctx, bulkCycleDependencyRead, append(cycle.args(), cycle.external)...)
	if err != nil {
		return state, err
	}
	defer rows.Close()
	var size int64
	var last string
	if !rows.Next() || rows.Scan(&state.cutoff, &state.ordered, &size, &state.status, &last, &state.failed, &state.pending, &state.skipped) != nil ||
		rows.Next() || rows.Err() != nil || size != int64(len(cycle.members)) || last != state.status {
		return bulkCycleDependencyState{}, identity.UnavailableError{}
	}
	return state, nil
}

func (p *nativePhase) reconcileBulkCycleDependency(ctx context.Context, w kernel.Work, probe *bulkDependencyProbe) (bool, error) {
	cycle := probe.cycle
	if cycle.parent != p.original.Command {
		return false, identity.ForbiddenError{}
	}
	if err := p.checkAdmission(ctx, w, p.admission); err != nil {
		return false, err
	}
	state, err := readBulkCycleDependency(ctx, w, cycle)
	if err != nil {
		return false, err
	}
	probe.failed, probe.ready = state.canFail(), state.canStart()
	if probe.failed || probe.ready {
		return false, nil // the original member commands still own terminal effects.
	}
	switch {
	case state.status == "admitted" && state.pending && !state.cutoff:
		changed, err := w.Exec(ctx, bulkCycleDependencyBlock, cycle.args()...)
		if err != nil || changed != int64(len(cycle.members)) {
			return false, identity.UnavailableError{}
		}
	case state.status == "dependency-blocked" && state.cutoff && !state.pending && !state.failed:
		changed, err := w.Exec(ctx, bulkCycleDependencySkip, cycle.args()...)
		if err != nil || changed != int64(len(cycle.members)) {
			return false, identity.UnavailableError{}
		}
		skipped := make([]kernel.SCIMBulkSkippedChild, len(cycle.members))
		for i, child := range cycle.members {
			skipped[i] = kernel.SCIMBulkSkippedChild{CommandID: child.original.Command, Ordinal: uint16(child.row.Ordinal)}
		}
		if err := w.PersistSCIMBulkChildSkipAudits(ctx, p, skipped); err != nil {
			return false, err
		}
	default:
		return false, nil
	}
	return true, p.checkAdmission(ctx, w, p.admission)
}
