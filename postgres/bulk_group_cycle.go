package scimpostgres

import (
	"context"

	identity "github.com/faustbrian/go-identity"
	kernel "github.com/faustbrian/go-identity/postgres"
	scim "github.com/faustbrian/go-scim"
)

// groupCreateCycleMember holds only the authorized in-cycle Group targets
// declared by this member's original dependency edges. External references
// and references to Users always use ordinary existence validation.
type groupCreateCycleMember struct {
	deferredGroupIDs map[string]struct{}
}

const bulkCycleChildMatch = `parent.parent_id=child.parent_id AND child.parent_id=$1 AND child.ordinal=$2
 AND child.command_id=$3 AND child.request_fingerprint=$4 AND child.resource_id=$5
 AND child.component_order=$6 AND child.component_id=$7 AND child.cyclic AND child.status='admitted'
 AND ` + bulkPriorComponentsReady + `
 AND NOT EXISTS (SELECT 1 FROM unnest(child.dependency_ids) AS dependency(id)
  WHERE NOT EXISTS (SELECT 1 FROM scim.bulk_children AS predecessor WHERE predecessor.parent_id=child.parent_id
   AND predecessor.command_id=dependency.id AND (predecessor.status='succeeded'
    OR (predecessor.cyclic AND predecessor.component_order=child.component_order
     AND predecessor.component_id=child.component_id AND predecessor.status `

const bulkCycleChildStart = `UPDATE scim.bulk_children AS child SET status='running'
FROM scim.bulk_requests AS parent WHERE ` + bulkCycleChildMatch + `IN ('admitted','running')))))`

const bulkCycleChildFail = `UPDATE scim.bulk_children AS child SET status='failed',result_code=424
FROM scim.bulk_requests AS parent WHERE ` + bulkCycleChildMatch + `IN ('admitted','failed')))))`

const bulkCycleParentFail = `UPDATE scim.bulk_requests AS parent SET failed_count=failed_count+$4::integer,
 cutoff_active=(parent.fail_on_errors>0 AND parent.failed_count+$4::integer>=parent.fail_on_errors)
WHERE parent.parent_id=$1 AND NOT parent.cutoff_active AND (
 SELECT count(*) FROM scim.bulk_children AS member
 WHERE member.parent_id=parent.parent_id AND member.component_order=$2 AND member.component_id=$3
  AND member.cyclic AND member.status='failed' AND member.result_code=424
)=$4::integer
RETURNING parent.cutoff_active`

func (s *GroupBulkService) executeGroupCreateCycle(ctx context.Context, request BulkAdmissionRequest, parent *nativePhase, plan scim.BulkPlan, rows []bulkChildRow, ordinal int) (scim.BulkChildResult, error) {
	selected := rows[ordinal]
	group := parent.bulk.components[selected.ComponentOrder]
	members := make([]*bulkChildExecution, len(group.Operations))
	componentIDs := make(map[string]string, len(members))
	allocated := make(map[int]string, len(rows))
	for i, child := range parent.bulk.children {
		if child.Error == nil && bulkCreatesGroup(child) {
			allocated[i] = rows[i].Resource
		}
	}
	for i, index := range group.Operations {
		row := rows[index]
		if allocated[index] == "" || row.ComponentID != selected.ComponentID || row.ComponentOrder != selected.ComponentOrder || !row.Cyclic {
			return scim.BulkChildResult{}, scim.NewError(501, "")
		}
		componentIDs[row.Command] = row.Resource
		members[i] = newBulkGroupExecution(parent.original, row, scim.GroupCreate, row.Resource, "")
	}
	// Parse/map and authorize every member before touching any child journal.
	// GroupsService must not be told that a provisional Group has committed.
	phases := make([]*nativePhase, len(members))
	for i, child := range members {
		child.cycle = &groupCreateCycleMember{deferredGroupIDs: make(map[string]struct{})}
		for _, id := range child.row.Dependencies {
			if target, ok := componentIDs[id]; ok {
				child.cycle.deferredGroupIDs[target] = struct{}{}
			}
		}
		resolved, err := plan.ResolveOperation(child.row.Ordinal, allocated)
		if err != nil {
			return scim.BulkChildResult{}, err
		}
		phases[i], err = s.prepareGroupCycleChild(ctx, request, parent, child, resolved)
		clear(resolved.Data)
		if err != nil {
			return scim.BulkChildResult{}, err
		}
	}
	owned := make([]kernel.SCIMBulkComponentMember, len(phases))
	for i, p := range phases {
		plan, err := p.executionPlan()
		if err != nil {
			return scim.BulkChildResult{}, err
		}
		spec, _ := p.command.Feature()
		reservation, _, err := p.coordinator.ReserveCommand(ctx, spec.Binding, p.command, plan)
		if err != nil {
			return scim.BulkChildResult{}, err
		}
		if reservation == (kernel.Reservation{}) {
			// A competing executor may have committed the component while this
			// caller was preparing. Only an authorized retained row can prove it.
			return s.readGroupCycleMember(ctx, parent, selected)
		}
		owned[i] = kernel.SCIMBulkComponentMember{Reservation: reservation, Command: p.command}
	}
	if _, err := kernel.ExecuteSCIMBulkGroupCreateComponent(ctx, owned); err != nil {
		return scim.BulkChildResult{}, err
	}
	return s.readGroupCycleMember(ctx, parent, selected)
}

func (s *GroupBulkService) readGroupCycleMember(ctx context.Context, parent *nativePhase, row bulkChildRow) (scim.BulkChildResult, error) {
	phase := newBulkGroupExecution(parent.original, row, scim.GroupCreate, row.Resource, "")
	result, _, err := s.native.readBulkChild(ctx, phase)
	if err != nil {
		return scim.BulkChildResult{}, err
	}
	if result.Status != scim.BulkChildSucceeded && result.Status != scim.BulkChildFailed && result.Status != scim.BulkChildSkipped {
		return scim.BulkChildResult{}, identity.ConflictError{}
	}
	if err := s.native.recheckRead(ctx, &parent.admission); err != nil {
		return scim.BulkChildResult{}, err
	}
	return result, nil
}

// RecordSCIMBulkGroupComponentFailure is invoked only after the kernel has
// discarded every provisional effect for this exact component. Each member
// records its own denial; the last callback counts the complete failed SCC
// before cutoff can skip any other child.
func (p *nativePhase) RecordSCIMBulkGroupComponentFailure(ctx context.Context, w kernel.Work, count int) error {
	child := p.bulkChild
	binding, registration, lifecycle, err := w.FeatureScope(p)
	spec, ok := p.command.Feature()
	if err != nil || !ok || child == nil || child.cycle == nil || !child.row.Cyclic ||
		p.intent.Operation != scim.GroupCreate || registration != p.registration() || lifecycle != p.lifecycle() ||
		binding != spec.Binding || binding.CommandID != child.original.Command ||
		binding.RecordID != child.original.ID || binding.CorrelationID != string(child.parent) {
		return identity.ForbiddenError{}
	}
	if err := p.checkCurrent(ctx, w); err != nil {
		return err
	}
	changed, err := w.Exec(ctx, bulkCycleChildFail, append(child.args(), child.row.ComponentID)...)
	if err != nil || changed != 1 {
		return identity.UnavailableError{}
	}
	if count == 0 {
		return nil
	}
	var cutoff bool
	if err := readBulkFailureCheckpoint(ctx, w, bulkCycleParentFail, &cutoff, string(child.parent), child.row.ComponentOrder, child.row.ComponentID, count); err != nil {
		return err
	}
	if cutoff {
		skipped, err := skipAdmittedBulkChildren(ctx, w, child.parent)
		if err != nil {
			return err
		}
		if len(skipped) != 0 {
			if err := w.PersistSCIMBulkChildSkipAudits(ctx, p, skipped); err != nil {
				return err
			}
		}
	}
	return p.checkCurrent(ctx, w)
}
