package scimpostgres

import (
	"context"
	"encoding/json"

	identity "github.com/faustbrian/go-identity"
	kernel "github.com/faustbrian/go-identity/postgres"
	scim "github.com/faustbrian/go-scim"
)

var _ kernel.SCIMBulkChildReconciler = (*nativePhase)(nil)

const bulkChildFail = `WITH failed AS (
 UPDATE scim.bulk_children AS child SET status='failed',result_code=$7
 FROM scim.bulk_requests AS parent
 WHERE parent.parent_id=child.parent_id AND child.parent_id=$1 AND child.ordinal=$2
  AND child.command_id=$3 AND child.request_fingerprint=$4 AND child.resource_id=$5
  AND child.component_order=$6 AND NOT child.cyclic AND child.status='admitted'
  AND ` + bulkChildReady + `
 RETURNING child.parent_id
)
UPDATE scim.bulk_requests AS parent SET failed_count=failed_count+1,
 cutoff_active=(parent.fail_on_errors>0 AND parent.failed_count+1>=parent.fail_on_errors)
FROM failed WHERE parent.parent_id=failed.parent_id
RETURNING parent.cutoff_active`

// Return only server-owned identity metadata. One bounded aggregate is needed
// because a parent may have 999 skipped siblings but Work limits returned rows.
const bulkCutoffSkip = `WITH skipped AS (
 UPDATE scim.bulk_children AS child SET status='skipped',skip_reason='fail-on-errors'
 FROM scim.bulk_requests AS parent
 WHERE child.parent_id=$1 AND parent.parent_id=child.parent_id AND parent.cutoff_active AND child.status='admitted'
 RETURNING child.command_id,child.ordinal
)
SELECT coalesce(json_agg(json_build_object('command_id',command_id,'ordinal',ordinal) ORDER BY ordinal),'[]'::json)::text
FROM skipped`

// RecordSCIMBulkChildFailure materializes the original typed denial only after
// the coordinator has rolled back the Group attempt. Under the same journal,
// audit and current connection fences, admitted means the aborted attempt's
// provisional running state and any projection have disappeared.
func (p *nativePhase) RecordSCIMBulkChildFailure(ctx context.Context, w kernel.Work, failure kernel.FeatureFailureCode) error {
	phase := p.bulkChild
	binding, registration, _, err := w.FeatureScope(p)
	if err != nil || phase == nil || registration != p.registration() || binding.CommandID != phase.original.Command || binding.CorrelationID != string(phase.parent) || binding.RecordID != phase.original.ID {
		return identity.ForbiddenError{}
	}
	var status int
	switch failure {
	case kernel.FeatureFailureInvalidGroupMember:
		status = 400
	case kernel.FeatureFailureConflict:
		status = 409
	default:
		return identity.UnavailableError{}
	}
	if err := p.checkCurrent(ctx, w); err != nil {
		return err
	}
	cutoff, err := p.projectBulkChildFailure(ctx, w, status)
	if err != nil {
		return err
	}
	if !cutoff {
		return nil
	}
	// Appending a large cutoff set can span the original authority expiry.
	return p.checkCurrent(ctx, w)
}

// ReconcileSCIMBulkChildFailure projects only the retained terminal denial.
// Current authority permits this checkpoint repair, not another Group attempt
// or renewal of the original command's execution authority.
func (p *nativePhase) ReconcileSCIMBulkChildFailure(ctx context.Context, w kernel.Work, failure kernel.FeatureFailureCode) (bool, error) {
	if err := p.checkBulkChildReconciliationScope(w); err != nil {
		return false, err
	}
	var status int
	switch failure {
	case kernel.FeatureFailureInvalidGroupMember:
		status = 400
	case kernel.FeatureFailureConflict:
		status = 409
	default:
		return false, identity.UnavailableError{}
	}
	if err := p.checkAdmission(ctx, w, p.admission); err != nil {
		return false, err
	}
	checkpoint, ready, err := p.readBulkChildCheckpoint(ctx, w)
	if err != nil {
		return false, err
	}
	if checkpoint.Status == scim.BulkChildFailed && checkpoint.Code == status {
		return false, nil
	}
	if checkpoint.Status != scim.BulkChildAdmitted || !ready {
		return false, identity.UnavailableError{}
	}
	if _, err := p.projectBulkChildFailure(ctx, w, status); err != nil {
		return false, err
	}
	return true, nil
}

func (p *nativePhase) projectBulkChildFailure(ctx context.Context, w kernel.Work, status int) (bool, error) {
	var cutoff bool
	if err := readBulkFailureCheckpoint(ctx, w, bulkChildFail, &cutoff, append(p.bulkChild.args(), status)...); err != nil {
		return false, err
	}
	if !cutoff {
		return false, nil
	}
	children, err := skipAdmittedBulkChildren(ctx, w, p.bulkChild.parent)
	if err != nil {
		return false, err
	}
	if len(children) > 0 {
		if err := w.PersistSCIMBulkChildSkipAudits(ctx, p, children); err != nil {
			return false, err
		}
	}
	return true, nil
}

// CheckSCIMBulkChildReconciliation refences the same current observations after
// the kernel has appended its reconciliation audit, without reading new proof.
func (p *nativePhase) CheckSCIMBulkChildReconciliation(ctx context.Context, w kernel.Work) error {
	if err := p.checkBulkChildReconciliationScope(w); err != nil {
		return err
	}
	return p.checkAdmission(ctx, w, p.admission)
}

func (p *nativePhase) checkBulkChildReconciliationScope(w kernel.Work) error {
	if p == nil || p.service == nil || p.bulk != nil || p.bootstrap || p.bulkChild == nil || p.intent.Operation != scim.GroupCreate {
		return identity.ForbiddenError{}
	}
	phase := p.bulkChild
	binding, registration, lifecycle, err := w.FeatureScope(p)
	spec, ok := p.command.Feature()
	if err != nil || !ok || binding != spec.Binding || registration != p.registration() || spec.Operation != registration.Operation || lifecycle != p.lifecycle() {
		return identity.ForbiddenError{}
	}
	if binding.CommandID != phase.original.Command || binding.CorrelationID != string(phase.parent) || binding.RecordID != phase.original.ID ||
		phase.row.Command != string(binding.CommandID) || phase.row.Resource != binding.RecordID || phase.row.Cyclic {
		return identity.ForbiddenError{}
	}
	if p.original.Command != phase.original.Command || p.original.ID != phase.original.ID || p.original.Version != phase.original.Version ||
		p.original.Operation != scim.GroupCreate || phase.original.Operation != scim.GroupCreate {
		return identity.ForbiddenError{}
	}
	return nil
}

func (p *nativePhase) readBulkChildCheckpoint(ctx context.Context, w kernel.Work) (scim.BulkChildResult, bool, error) {
	rows, err := w.Query(ctx, bulkChildCheckpointRead, p.bulkChild.args()...)
	if err != nil {
		return scim.BulkChildResult{}, false, identity.UnavailableError{}
	}
	defer rows.Close()
	var status string
	// The Work scanner allows a nullable integer only at int64 width.
	var code *int64
	var resource, version *string
	var ready bool
	if !rows.Next() || rows.Scan(&status, &code, &resource, &version, &ready) != nil || rows.Next() || rows.Err() != nil {
		return scim.BulkChildResult{}, false, identity.UnavailableError{}
	}
	return decodeBulkChildCheckpoint(p.bulkChild, status, code, resource, version, ready)
}

func readBulkFailureCheckpoint(ctx context.Context, w kernel.Work, statement string, out any, args ...any) error {
	rows, err := w.Query(ctx, statement, args...)
	if err != nil {
		return identity.UnavailableError{}
	}
	defer rows.Close()
	if !rows.Next() || rows.Scan(out) != nil || rows.Next() || rows.Err() != nil {
		return identity.UnavailableError{}
	}
	return nil
}

func skipAdmittedBulkChildren(ctx context.Context, w kernel.Work, parent identity.CommandID) ([]kernel.SCIMBulkSkippedChild, error) {
	var encoded string
	if err := readBulkFailureCheckpoint(ctx, w, bulkCutoffSkip, &encoded, string(parent)); err != nil {
		return nil, err
	}
	// The graph admits at most 1,000 rows and each entry carries only a
	// canonical 22-byte command and an ordinal below 1,000.
	if len(encoded) == 0 || len(encoded) > 64<<10 {
		return nil, identity.UnavailableError{}
	}
	var skipped []struct {
		Command string `json:"command_id"`
		Ordinal uint16 `json:"ordinal"`
	}
	if err := json.Unmarshal([]byte(encoded), &skipped); err != nil || skipped == nil || len(skipped) > 999 {
		return nil, identity.UnavailableError{}
	}
	result := make([]kernel.SCIMBulkSkippedChild, 0, len(skipped))
	for _, child := range skipped {
		id, err := identity.ParseCommandID(child.Command)
		if err != nil || child.Ordinal >= 1000 {
			return nil, identity.UnavailableError{}
		}
		result = append(result, kernel.SCIMBulkSkippedChild{CommandID: id, Ordinal: child.Ordinal})
	}
	return result, nil
}

func bulkGroupFailureResult(status int) (scim.BulkChildResult, bool) {
	result := scim.BulkChildResult{Status: scim.BulkChildFailed, Code: status}
	switch status {
	case 400:
		result.SCIMType = "invalidValue"
	case 409:
	default:
		return scim.BulkChildResult{}, false
	}
	return result, true
}
