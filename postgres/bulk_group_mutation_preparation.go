package scimpostgres

import (
	"context"

	identity "github.com/faustbrian/go-identity"
)

const readBulkMutationInput = `SELECT child.group_mutation_input FROM scim.bulk_children AS child
WHERE child.parent_id=$1 AND child.ordinal=$2 AND child.command_id=$3 AND child.request_fingerprint=$4
 AND child.resource_id=$5 AND child.component_order=$6 AND NOT child.cyclic`

const retainBulkMutationInput = `UPDATE scim.bulk_children AS child SET group_mutation_input=$7
FROM scim.bulk_requests AS parent
WHERE parent.parent_id=child.parent_id AND child.parent_id=$1 AND child.ordinal=$2
 AND child.command_id=$3 AND child.request_fingerprint=$4 AND child.resource_id=$5
 AND child.component_order=$6 AND NOT child.cyclic AND child.status IN ('admitted','dependency-blocked')
 AND child.group_mutation_input IS NULL AND clock_timestamp()<$8 AND ` + bulkChildReady

// prepareBulkMutationOriginal freezes one eligible child, not the entire graph.
// The existing command journal still owns execution. In particular, an
// acknowledged preparation gives no new lease or authorization to mutate.
func (p *nativePhase) prepareBulkMutationOriginal(ctx context.Context, parent originalInput) (originalInput, error) {
	admission, err := p.service.restoreAdmission(parent.Admission, parent.At)
	if err != nil || !liveConnection(ctx, admission.connection) {
		return originalInput{}, identity.ForbiddenError{}
	}
	args := p.bulkChild.args()
	var retained []byte
	if err := p.service.pool.Raw().QueryRow(ctx, readBulkMutationInput, args...).Scan(&retained); err != nil {
		return originalInput{}, identity.UnavailableError{}
	}
	if retained != nil {
		defer clear(retained)
		return p.openBulkMutationInput(ctx, retained, parent)
	}
	// A projection read may copy the original admission but must never replace it
	// with a newer observation from the current retry.
	snapshot := *p
	snapshot.admission = admission
	readContext := context.WithValue(ctx, invocationKey{}, &admission)
	input, err := snapshot.newOriginalInput(readContext, identity.CommandID(p.bulkChild.row.Command))
	if err != nil {
		return originalInput{}, err
	}
	// As with Bulk create, the independently allocated child owns the new ETag.
	// Result replay can verify it without opening the encrypted pre-image.
	input.Version = bulkChildVersion(p.bulkChild.row.Command)
	candidate, err := p.sealBulkMutationInput(ctx, input, parent)
	if err != nil {
		return originalInput{}, err
	}
	defer clear(candidate)
	if err := p.service.recheckRead(ctx, &admission); err != nil {
		return originalInput{}, err
	}
	result, err := p.service.pool.Raw().Exec(ctx, retainBulkMutationInput, append(args, candidate, parent.Admission.ValidUntil)...)
	if err != nil {
		// An uncertain acknowledgement cannot select a second input on retry.
		return originalInput{}, identity.UnavailableError{}
	}
	if result.RowsAffected() == 1 {
		return input, nil
	}
	if result.RowsAffected() != 0 || p.service.pool.Raw().QueryRow(ctx, readBulkMutationInput, args...).Scan(&retained) != nil || retained == nil {
		return originalInput{}, identity.UnavailableError{}
	}
	defer clear(retained)
	return p.openBulkMutationInput(ctx, retained, parent)
}
