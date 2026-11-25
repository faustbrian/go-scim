package scimpostgres

import (
	"context"
	"encoding/json"

	identity "github.com/faustbrian/go-identity"
	kernel "github.com/faustbrian/go-identity/postgres"
	scim "github.com/faustbrian/go-scim"
)

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
	var cutoff bool
	if err := readBulkFailureCheckpoint(ctx, w, bulkChildFail, &cutoff, append(phase.args(), status)...); err != nil {
		return err
	}
	if !cutoff {
		return nil
	}
	children, err := skipAdmittedBulkChildren(ctx, w, phase.parent)
	if err != nil {
		return err
	}
	if len(children) > 0 {
		if err := w.PersistSCIMBulkChildSkipAudits(ctx, p, children); err != nil {
			return err
		}
	}
	// Appending a large cutoff set can span the original authority expiry.
	return p.checkCurrent(ctx, w)
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
