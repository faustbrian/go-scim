package scimpostgres

import (
	"context"
	"errors"

	identity "github.com/faustbrian/go-identity"
	kernel "github.com/faustbrian/go-identity/postgres"
	scim "github.com/faustbrian/go-scim"
)

type bulkDependencyProbe struct {
	child  *bulkChildExecution
	cycle  *bulkCycleDependency
	ready  bool
	failed bool
}

type bulkDependencyState struct {
	status          string
	cutoff          bool
	failed, pending bool
}

func (s bulkDependencyState) canFail() bool {
	return s.failed && (s.status == "dependency-blocked" || s.status == "admitted" && !s.cutoff)
}

const bulkDependencyChildScope = `parent.parent_id=child.parent_id AND child.parent_id=$1
 AND child.ordinal=$2 AND child.command_id=$3 AND child.request_fingerprint=$4
 AND child.resource_id=$5 AND child.component_order=$6 AND NOT child.cyclic`

const bulkDependencyRead = `SELECT child.status,parent.cutoff_active,
 coalesce(dep.failed,false) AND (parent.cutoff_active OR (` + bulkPriorComponentsReady + `)),
 coalesce(dep.pending,false)
FROM scim.bulk_children child JOIN scim.bulk_requests parent ON parent.parent_id=child.parent_id
CROSS JOIN LATERAL (
 SELECT bool_or(predecessor.status='failed') failed,
  bool_or(predecessor.status IS NULL OR predecessor.status NOT IN ('succeeded','failed','skipped')) pending
 FROM unnest(child.dependency_ids) AS edge(id)
 LEFT JOIN scim.bulk_children predecessor ON predecessor.parent_id=child.parent_id AND predecessor.command_id=edge.id
) dep WHERE ` + bulkDependencyChildScope

const bulkDependencyBlock = `UPDATE scim.bulk_children child SET status='dependency-blocked'
FROM scim.bulk_requests parent WHERE ` + bulkDependencyChildScope + `
 AND child.status='admitted' AND NOT parent.cutoff_active`

const bulkDependencyCutoffSkip = `UPDATE scim.bulk_children child SET status='skipped',skip_reason='fail-on-errors'
FROM scim.bulk_requests parent WHERE ` + bulkDependencyChildScope + `
 AND child.status='dependency-blocked' AND parent.cutoff_active`

const bulkDependencyFail = `WITH failed AS (
 UPDATE scim.bulk_children child SET status='failed',result_code=424
 FROM scim.bulk_requests parent WHERE ` + bulkDependencyChildScope + `
  AND (child.status='dependency-blocked' OR child.status='admitted' AND NOT parent.cutoff_active)
  AND (parent.cutoff_active OR (` + bulkPriorComponentsReady + `))
  AND EXISTS(SELECT 1 FROM unnest(child.dependency_ids) AS edge(id)
   JOIN scim.bulk_children predecessor ON predecessor.parent_id=child.parent_id AND predecessor.command_id=edge.id
   WHERE predecessor.status='failed')
 RETURNING child.parent_id
)
UPDATE scim.bulk_requests parent SET failed_count=parent.failed_count+1,
 cutoff_active=parent.cutoff_active OR (parent.fail_on_errors>0 AND parent.failed_count+1>=parent.fail_on_errors)
FROM failed WHERE parent.parent_id=failed.parent_id RETURNING parent.cutoff_active`

func readBulkDependency(ctx context.Context, w kernel.Work, child *bulkChildExecution) (bulkDependencyState, error) {
	var state bulkDependencyState
	rows, err := w.Query(ctx, bulkDependencyRead, child.args()...)
	if err != nil {
		return state, err
	}
	defer rows.Close()
	if !rows.Next() || rows.Scan(&state.status, &state.cutoff, &state.failed, &state.pending) != nil || rows.Next() || rows.Err() != nil {
		return bulkDependencyState{}, identity.UnavailableError{}
	}
	return state, nil
}

func (s *GroupBulkService) resolveBulkDependency(ctx context.Context, parent *nativePhase, child *bulkChildExecution) (scim.BulkChildResult, bool, error) {
	if len(child.row.Dependencies) == 0 {
		return scim.BulkChildResult{}, false, nil
	}
	probe := &bulkDependencyProbe{child: child}
	if err := parent.observeBulkDependency(ctx, probe); err != nil {
		return scim.BulkChildResult{}, false, err
	}
	if probe.failed {
		if err := s.retainBulkDependencyDenial(ctx, parent, child); err != nil {
			return scim.BulkChildResult{}, false, err
		}
	}
	result, ready, err := s.native.readBulkChild(ctx, child)
	if err != nil {
		return scim.BulkChildResult{}, false, err
	}
	if err := s.native.recheckRead(ctx, &parent.admission); err != nil {
		return scim.BulkChildResult{}, false, err
	}
	return result, ready, nil
}

func (parent *nativePhase) observeBulkDependency(ctx context.Context, probe *bulkDependencyProbe) error {
	parent.dependency = probe
	defer func() { parent.dependency = nil }()
	plan, err := parent.executionPlan()
	if err != nil {
		return err
	}
	spec, _ := parent.command.Feature()
	reservation, receipt, err := parent.coordinator.ReserveCommand(ctx, spec.Binding, parent.command, plan)
	if err != nil || reservation != (kernel.Reservation{}) || receipt.Outcome != identity.CommitOutcomeCommitted {
		return identity.UnavailableError{}
	}
	return nil
}

func (p *nativePhase) SCIMBulkDependencyCheckpointSelected() bool {
	return p.bulk != nil && p.dependency != nil
}

// ReconcileSCIMBulkDependency borrows the locked committed parent's scope.
// All native writers take the same connection lock before touching the graph;
// the observed predecessor state therefore stays authoritative for this CAS.
func (p *nativePhase) ReconcileSCIMBulkDependency(ctx context.Context, w kernel.Work) (bool, error) {
	if !p.SCIMBulkDependencyCheckpointSelected() {
		return false, identity.ForbiddenError{}
	}
	probe := p.dependency
	child := probe.child
	binding, registration, lifecycle, err := w.FeatureScope(p)
	if probe.cycle != nil {
		if err != nil || binding.CommandID != p.original.Command || registration != p.registration() || lifecycle != p.lifecycle() {
			return false, identity.ForbiddenError{}
		}
		return p.reconcileBulkCycleDependency(ctx, w, probe)
	}
	if err != nil || child == nil || child.row.Ordinal < 0 || child.row.Ordinal >= len(p.bulk.children) ||
		child.row.Cyclic || child.parent != p.original.Command ||
		binding.CommandID != child.parent || registration != p.registration() || lifecycle != p.lifecycle() {
		return false, identity.ForbiddenError{}
	}
	if err := p.checkAdmission(ctx, w, p.admission); err != nil {
		return false, err
	}
	state, err := readBulkDependency(ctx, w, child)
	if err != nil {
		return false, err
	}
	probe.failed = state.canFail()
	switch {
	case probe.failed:
		return false, nil // the original child owns the terminal command and audit.
	case state.status == "admitted" && state.pending && !state.cutoff:
		count, err := w.Exec(ctx, bulkDependencyBlock, child.args()...)
		if err != nil || count != 1 {
			return false, identity.UnavailableError{}
		}
	case state.status == "dependency-blocked" && !state.pending && state.cutoff:
		count, err := w.Exec(ctx, bulkDependencyCutoffSkip, child.args()...)
		if err != nil || count != 1 {
			return false, identity.UnavailableError{}
		}
		skipped := kernel.SCIMBulkSkippedChild{CommandID: child.original.Command, Ordinal: uint16(child.row.Ordinal)}
		if err := w.PersistSCIMBulkChildSkipAudits(ctx, p, []kernel.SCIMBulkSkippedChild{skipped}); err != nil {
			return false, err
		}
	default:
		return false, nil
	}
	return true, p.checkAdmission(ctx, w, p.admission)
}

func (s *GroupBulkService) retainBulkDependencyDenial(ctx context.Context, parent *nativePhase, child *bulkChildExecution) error {
	if child.original.Operation == bulkInvalidChild {
		if !child.validStructuralRow() || !child.structuralAuthority.symbolic {
			return identity.ForbiddenError{}
		}
		// Dependency failure belongs to the exact authorized resource
		// operation. The internal malformed-child operation owns only 400.
		authority := child.structuralAuthority
		child = newBulkChildExecution(parent.original, child.row, authority.operation, authority.target, "")
	}
	p := &nativePhase{service: s.native, admission: parent.admission, bulkChild: child, original: child.original,
		denialOnly: kernel.FeatureFailureSCIMBulkDependency, intent: scim.WriteIntent{Operation: child.original.Operation,
			Scope: parent.admission.connection.Scope, ResourceID: child.original.ID, IfMatch: child.ifMatch}}
	coordinator, registry, err := s.native.coordinator(p)
	if err != nil {
		return err
	}
	p.coordinator, p.registry = coordinator, registry
	if err := p.initialize(ctx, []byte("identity.scim.bulk.failed-dependency.v1")); err != nil {
		return err
	}
	result, err := p.execute(ctx)
	var denial kernel.TypedFeatureFailureError
	if result.Outcome != identity.CommitOutcomeNotCommitted || !errors.As(err, &denial) || denial.Code != p.denialOnly {
		return identity.UnavailableError{}
	}
	return nil
}

func (p *nativePhase) recordBulkDependencyFailure(ctx context.Context, w kernel.Work) error {
	if err := p.checkAdmission(ctx, w, p.admission); err != nil {
		return err
	}
	var cutoff bool
	if err := readBulkFailureCheckpoint(ctx, w, bulkDependencyFail, &cutoff, p.bulkChild.args()...); err != nil {
		return err
	}
	if cutoff {
		skipped, err := skipAdmittedBulkChildren(ctx, w, p.bulkChild.parent)
		if err != nil {
			return err
		}
		if len(skipped) != 0 {
			if err := w.PersistSCIMBulkChildSkipAudits(ctx, p, skipped); err != nil {
				return err
			}
		}
	}
	return p.checkAdmission(ctx, w, p.admission)
}
