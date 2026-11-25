package scimpostgres

import (
	"context"

	identity "github.com/faustbrian/go-identity"
	kernel "github.com/faustbrian/go-identity/postgres"
	scim "github.com/faustbrian/go-scim"
)

type bulkChildExecution struct {
	parent   identity.CommandID
	row      bulkChildRow
	original originalInput
}

// ExecuteChild executes or recovers the original Group create at ordinal. The
// original request and currently authorized connection are required on every
// call. It advances only an acyclic Group create whose preceding components
// completed successfully, and cannot start it after the original parent
// authority expires. Other children are not executed by this selection.
// A returned result is only this child's checkpoint, never a terminal Bulk
// response. Retry the exact request and ordinal after an uncertain outcome.
func (s *GroupBulkService) ExecuteChild(ctx context.Context, request BulkAdmissionRequest, ordinal int) (result scim.BulkChildResult, err error) {
	if s == nil || s.native == nil || s.groups == nil || ctx == nil {
		return result, scim.NewError(503, "")
	}
	if ordinal < 0 || ordinal >= s.request.MaxOperations {
		return result, scim.NewError(400, "invalidValue")
	}
	ctx, cancel := context.WithTimeout(ctx, s.native.config().MaximumDuration)
	defer cancel()
	defer func() {
		if recover() != nil || ctx.Err() != nil {
			result, err = scim.BulkChildResult{}, scim.NewError(503, "")
		} else if err != nil {
			result, err = scim.BulkChildResult{}, bulkProtocolError(err)
		}
	}()
	parent, plan, err := s.admitGraph(ctx, request, &ordinal)
	if err != nil {
		return result, err
	}
	child := parent.bulk.children[ordinal]
	if child.Error != nil {
		return result, child.Error
	}
	if !bulkCreatesGroup(child) {
		return result, scim.NewError(501, "")
	}
	if err := s.native.decide(ctx, string(scim.GroupCreate), "", "identity.scim.group"); err != nil {
		return result, err
	}
	rows, err := parent.bulk.childRows()
	if err != nil {
		return result, err
	}
	selected := rows[ordinal]
	if selected.Cyclic {
		return result, scim.NewError(501, "")
	}
	phase := &bulkChildExecution{parent: parent.original.Command, row: selected, original: originalInput{
		Command: identity.CommandID(selected.Command), ID: selected.Resource, Operation: scim.GroupCreate,
		Version: scim.Version(`"` + selected.Command + `"`), At: parent.original.At, Admission: parent.original.Admission,
	}}
	checkpoint, ready, err := s.native.readBulkChild(ctx, phase)
	if err != nil {
		return result, err
	}
	if checkpoint.Status == scim.BulkChildSucceeded {
		if err := s.native.recheckRead(ctx, &parent.admission); err != nil {
			return result, err
		}
		return checkpoint, nil
	}
	if !ready {
		return result, identity.ConflictError{}
	}
	allocated := make(map[int]string)
	for i, declared := range parent.bulk.children {
		if declared.Error == nil && bulkCreatesGroup(declared) {
			allocated[i] = parent.bulk.allocation[i].Resource
		}
	}
	resolved, err := plan.ResolveOperation(ordinal, allocated)
	if err != nil {
		return result, err
	}
	defer clear(resolved.Data)
	// Use the configured Group protocol for schema, member kinds, normalization,
	// mapping and admission. The private invocation alone carries the exact
	// allocated input into its existing Store. Its separate authentication does
	// not replace the original parent authority used inside protected Work.
	i := parent.admission
	i.bulkChild = phase
	ctx = context.WithValue(ctx, invocationKey{}, &i)
	response, err := s.groups.Execute(ctx, scim.Request{Operation: scim.GroupCreate, Credential: request.Credential, Body: resolved.Data, ContentType: "application/scim+json"})
	if err != nil {
		return result, err
	}
	if response.Status != 201 || response.ETag != phase.original.Version {
		return result, identity.UnavailableError{}
	}
	checkpoint, _, err = s.native.readBulkChild(ctx, phase)
	if err != nil || checkpoint.Status != scim.BulkChildSucceeded {
		return result, identity.UnavailableError{}
	}
	if err := s.native.recheckRead(ctx, &i); err != nil {
		return result, err
	}
	return checkpoint, nil
}

// The parent was verified against original custody and the adapter's exact
// scope. The child predicates bind the immutable graph identity and plan;
// only current success can bypass the first-ready guard (historical replay).
// Induction keeps earlier components concluded: a component could not have
// succeeded before its own immediate predecessor. Check only that component
// and the explicit dependency IDs, rather than scanning the completed prefix
// again for every child in a long request.
const bulkChildReady = `NOT parent.cutoff_active AND
 (child.component_order=0 OR (
  EXISTS (SELECT 1 FROM scim.bulk_children AS prior WHERE prior.parent_id=child.parent_id AND prior.component_order=child.component_order-1)
  AND NOT EXISTS (SELECT 1 FROM scim.bulk_children AS prior WHERE prior.parent_id=child.parent_id
   AND prior.component_order=child.component_order-1 AND prior.status<>'succeeded')))
 AND NOT EXISTS (SELECT 1 FROM unnest(child.dependency_ids) AS dependency(id)
  WHERE NOT EXISTS (SELECT 1 FROM scim.bulk_children AS predecessor WHERE predecessor.parent_id=child.parent_id
   AND predecessor.command_id=dependency.id AND predecessor.status='succeeded'))`

const bulkChildCheckpointRead = `SELECT child.status, child.result_code, child.result_resource_id, child.result_version,
 (` + bulkChildReady + `)
FROM scim.bulk_children child JOIN scim.bulk_requests parent ON parent.parent_id=child.parent_id
WHERE child.parent_id=$1 AND child.ordinal=$2 AND child.command_id=$3 AND child.request_fingerprint=$4
 AND child.resource_id=$5 AND child.component_order=$6 AND NOT child.cyclic`

const bulkChildStart = `UPDATE scim.bulk_children AS child SET status='running'
FROM scim.bulk_requests AS parent
WHERE parent.parent_id=child.parent_id AND child.parent_id=$1 AND child.ordinal=$2
 AND child.command_id=$3 AND child.request_fingerprint=$4 AND child.resource_id=$5
 AND child.component_order=$6 AND NOT child.cyclic AND child.status='admitted'
 AND ` + bulkChildReady

const bulkChildSucceed = `UPDATE scim.bulk_children SET status='succeeded',result_code=201,result_resource_id=$5,result_version=$7
WHERE parent_id=$1 AND ordinal=$2 AND command_id=$3 AND request_fingerprint=$4 AND resource_id=$5
 AND component_order=$6 AND status='running'`

func (p *bulkChildExecution) args() []any {
	return []any{string(p.parent), p.row.Ordinal, p.row.Command, p.row.Fingerprint, p.row.Resource, p.row.ComponentOrder}
}

func (s *Service) readBulkChild(ctx context.Context, phase *bulkChildExecution) (scim.BulkChildResult, bool, error) {
	var status string
	var code *int16
	var resource, version *string
	var ready bool
	err := s.pool.Raw().QueryRow(ctx, bulkChildCheckpointRead, phase.args()...).Scan(&status, &code, &resource, &version, &ready)
	if err != nil {
		return scim.BulkChildResult{}, false, identity.UnavailableError{}
	}
	if status == "succeeded" && code != nil && *code == 201 && resource != nil && *resource == phase.original.ID && version != nil && *version == string(phase.original.Version) {
		return scim.BulkChildResult{Status: scim.BulkChildSucceeded, Code: 201, ResourceID: *resource, Version: scim.Version(*version)}, false, nil
	}
	if status == "admitted" && code == nil && resource == nil && version == nil {
		return scim.BulkChildResult{Status: scim.BulkChildAdmitted}, ready, nil
	}
	return scim.BulkChildResult{}, false, identity.UnavailableError{}
}

func (p *nativePhase) applyBulkGroupChild(ctx context.Context, w kernel.Work) (identity.FeatureReceipt, error) {
	phase := p.bulkChild
	// ApplyFeature already holds the current connection writer fence. Both
	// child transitions join this same Work, so a failure cannot leave running
	// status or acknowledge a projection without a result checkpoint.
	count, err := w.Exec(ctx, bulkChildStart, phase.args()...)
	if err != nil || count != 1 {
		return identity.FeatureReceipt{}, identity.UnavailableError{}
	}
	receipt, err := p.applyGroupProjection(ctx, w)
	if err != nil {
		return identity.FeatureReceipt{}, err
	}
	if p.resource.ID != phase.original.ID || p.resource.Version != phase.original.Version {
		return identity.FeatureReceipt{}, identity.UnavailableError{}
	}
	count, err = w.Exec(ctx, bulkChildSucceed, append(phase.args(), string(p.resource.Version))...)
	if err != nil || count != 1 {
		return identity.FeatureReceipt{}, identity.UnavailableError{}
	}
	return receipt, nil
}
