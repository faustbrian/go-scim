package scimpostgres

import (
	"context"
	"errors"

	identity "github.com/faustbrian/go-identity"
	kernel "github.com/faustbrian/go-identity/postgres"
	scim "github.com/faustbrian/go-scim"
)

type bulkChildExecution struct {
	parent              identity.CommandID
	row                 bulkChildRow
	original            originalInput
	ifMatch             scim.Version
	acknowledgedFailure bool
	cycle               *groupCreateCycleMember
}

// ExecuteChild executes or recovers the original Group mutation at ordinal. The
// original request and currently authorized connection are required on every
// call. It advances an acyclic Group child or its all-Group create cycle
// only after the preceding components and external dependencies allow it.
// Execution cannot start after the original parent authority expires.
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
	rows, err := parent.bulk.childRows()
	if err != nil {
		return result, err
	}
	selected := rows[ordinal]
	operation, target := parent.bulk.selectChild(ordinal, parent.bulk.groupCreateTargets())
	if operation != "" {
		if err := s.native.decide(ctx, string(operation), target, bulkChildAuthorizationType(operation)); err != nil {
			return result, err
		}
	}
	phase := newBulkChildExecution(parent.original, selected, operation, target, scim.Version(child.Version))
	checkpoint, ready, err := s.native.readBulkChild(ctx, phase)
	if err != nil {
		return result, err
	}
	// Cutoff can skip any admitted declaration, including a child whose parsed
	// operation would be invalid or unsupported. Replay that retained skip, not
	// a new operation result. Before cutoff the original errors still apply.
	if checkpoint.Status != scim.BulkChildSkipped {
		if child.Error != nil {
			return result, child.Error
		}
		if operation == "" || selected.Cyclic && operation != scim.GroupCreate {
			return result, scim.NewError(501, "")
		}
	}
	if checkpoint.Status == scim.BulkChildSucceeded || checkpoint.Status == scim.BulkChildFailed || checkpoint.Status == scim.BulkChildSkipped {
		if err := s.native.checkBulkChildDisclosure(ctx, operation, checkpoint); err != nil {
			return result, err
		}
		if err := s.native.recheckRead(ctx, &parent.admission); err != nil {
			return result, err
		}
		return checkpoint, nil
	}
	if selected.Cyclic {
		return s.executeGroupCreateCycle(ctx, request, parent, plan, rows, ordinal)
	}
	if !ready {
		checkpoint, ready, err = s.resolveBulkDependency(ctx, parent, phase)
		if err != nil {
			return result, err
		}
		if checkpoint.Status == scim.BulkChildSucceeded || checkpoint.Status == scim.BulkChildFailed || checkpoint.Status == scim.BulkChildSkipped {
			return checkpoint, nil
		}
		if !ready {
			return result, identity.ConflictError{}
		}
	}
	allocated := make(map[int]string)
	for i, declared := range parent.bulk.children {
		if declared.Error == nil && bulkCreatesResource(declared) {
			allocated[i] = parent.bulk.allocation[i].Resource
		}
	}
	resolved, err := plan.ResolveOperation(ordinal, allocated)
	if err != nil {
		return result, err
	}
	defer clear(resolved.Data)
	if operation != scim.GroupCreate && (resolved.Target.ResourceID != target || scim.Version(resolved.Version) != phase.ifMatch) {
		return result, identity.UnavailableError{}
	}
	if nativeMutation(operation) && phase.ifMatch != "" {
		preparer := nativePhase{service: s.native, bulkChild: phase, intent: scim.WriteIntent{
			Operation: operation, Scope: parent.admission.connection.Scope, ResourceID: target, IfMatch: phase.ifMatch,
		}}
		phase.original, err = preparer.prepareBulkMutationOriginal(ctx, parent.original)
		if err != nil {
			return result, err
		}
	}
	// Use the configured resource protocol for schema, member kinds, normalization,
	// mapping and admission. The private invocation alone carries the exact
	// allocated input into its existing Store. Its separate authentication does
	// not replace the original parent authority used inside protected Work.
	i := parent.admission
	i.bulkChild = phase
	ctx = context.WithValue(ctx, invocationKey{}, &i)
	execute := s.groups.Execute
	if operation == scim.UserCreate {
		execute = s.native.protocol.Execute
	}
	response, err := execute(ctx, scim.Request{Operation: operation, ResourceID: target, IfMatch: phase.ifMatch, Credential: request.Credential, Body: resolved.Data, ContentType: "application/scim+json"})
	if err != nil {
		var protocol *scim.Error
		if !phase.acknowledgedFailure && errors.As(err, &protocol) && nativeMutation(operation) {
			var code kernel.FeatureFailureCode
			p := i.phase
			switch protocol.StatusCode() {
			case 404:
				if p != nil && p.bulkDenialMatches(kernel.FeatureFailureGroupMissing) {
					code = kernel.FeatureFailureGroupMissing
				}
			case 412:
				if p != nil && p.hasStaleBulkPrecondition() {
					code = kernel.FeatureFailurePrecondition
				}
			case 428:
				if p == nil && phase.ifMatch == "" {
					// Ordinary Group validation rejected the missing precondition
					// before Prepare. The admitted child already binds the full
					// request and original authority; do not read the projection.
					p = &nativePhase{service: s.native, bulkChild: phase, admission: i, original: phase.original, intent: scim.WriteIntent{
						Operation: operation, Scope: i.connection.Scope, ResourceID: target,
						CanonicalRequest: []byte("identity.scim.bulk.missing-if-match.v1"),
					}}
					coordinator, registry, setupErr := s.native.coordinator(p)
					if setupErr != nil {
						return result, setupErr
					}
					p.coordinator, p.registry = coordinator, registry
					code = kernel.FeatureFailureGroupVersionRequired
				}
			}
			if code != 0 {
				if err := p.recordBulkProtocolDenial(ctx, code); err != nil {
					return result, err
				}
			}
		}
		if phase.acknowledgedFailure {
			checkpoint, _, readErr := s.native.readBulkChild(ctx, phase)
			if readErr != nil {
				return result, readErr
			}
			if checkpoint.Status == scim.BulkChildFailed {
				if readErr := s.native.recheckRead(ctx, &i); readErr != nil {
					return result, readErr
				}
				return checkpoint, nil
			}
		}
		return result, err
	}
	checkpoint, _, err = s.native.readBulkChild(ctx, phase)
	if err != nil || checkpoint.Status != scim.BulkChildSucceeded || response.Status != checkpoint.Code || response.ETag != checkpoint.Version {
		return result, identity.UnavailableError{}
	}
	if err := s.native.checkBulkChildDisclosure(ctx, operation, checkpoint); err != nil {
		return result, err
	}
	if err := s.native.recheckRead(ctx, &i); err != nil {
		return result, err
	}
	return checkpoint, nil
}

func (p *nativePhase) hasStaleBulkPrecondition() bool {
	return p.bulkChild != nil && p.group() && nativeMutation(p.intent.Operation) &&
		p.original.Current != nil && p.intent.IfMatch != "" && p.original.Current.Version != p.intent.IfMatch
}

func (p *nativePhase) bulkDenialMatches(code kernel.FeatureFailureCode) bool {
	if code == kernel.FeatureFailureSCIMBulkDependency {
		return p.bulkChild != nil && p.group() && !p.bulkChild.row.Cyclic &&
			len(p.bulkChild.row.Dependencies) > 0 && p.original == p.bulkChild.original && p.intent.Operation == p.original.Operation
	}
	if p.bulkChild == nil || !p.group() || !nativeMutation(p.intent.Operation) || p.intent.ResourceID != p.original.ID || p.original.Operation != p.intent.Operation {
		return false
	}
	switch code {
	case kernel.FeatureFailureGroupMissing:
		return p.intent.IfMatch != "" && p.original.Schema == 3 && p.original.Current == nil && p.original.Generation == 0
	case kernel.FeatureFailureGroupVersionRequired:
		return p.intent.IfMatch == "" && p.original.Schema == 0 && p.original.Current == nil && p.original.Generation == 0
	default:
		return false
	}
}

func (p *nativePhase) recordBulkProtocolDenial(ctx context.Context, code kernel.FeatureFailureCode) error {
	// The Group protocol has already authorized, parsed and rejected this exact
	// request. The actual denial is derived again from the sealed original in
	// Work. No transport error value or fresh projection can choose the outcome.
	if err := p.service.decide(ctx, string(p.intent.Operation), p.intent.ResourceID, "identity.scim.group"); err != nil {
		return err
	}
	if code != kernel.FeatureFailurePrecondition {
		if !p.bulkDenialMatches(code) {
			return identity.ForbiddenError{}
		}
		p.denialOnly = code
	}
	if err := p.initialize(ctx, p.intent.CanonicalRequest); err != nil {
		return err
	}
	result, err := p.execute(ctx)
	var denial kernel.TypedFeatureFailureError
	if result.Outcome != identity.CommitOutcomeNotCommitted || !errors.As(err, &denial) || denial.Code != code {
		return identity.UnavailableError{}
	}
	p.bulkChild.acknowledgedFailure = true
	return nil
}

func (p *bulkAdmissionPhase) groupCreateTargets() map[string]string {
	targets := make(map[string]string)
	for i, child := range p.children {
		if child.Error == nil && bulkCreatesGroup(child) && child.BulkID != "" {
			targets[child.BulkID] = p.allocation[i].Resource
		}
	}
	return targets
}

func (p *bulkAdmissionPhase) selectChild(ordinal int, targets map[string]string) (scim.Operation, string) {
	child := p.children[ordinal]
	if child.Error != nil {
		return "", ""
	}
	if child.Target.ResourceType == "User" && child.Method == "POST" {
		return scim.UserCreate, ""
	}
	if child.Target.ResourceType != "Group" {
		return "", ""
	}
	if child.Method == "POST" {
		return scim.GroupCreate, ""
	}
	target := child.Target.ResourceID
	if child.Target.BulkID != "" {
		target = targets[child.Target.BulkID]
	}
	if target == "" {
		return "", ""
	}
	switch child.Method {
	case "PUT":
		return scim.GroupReplace, target
	case "PATCH":
		return scim.GroupPatch, target
	case "DELETE":
		return scim.GroupDelete, target
	default:
		return "", ""
	}
}

func newBulkChildExecution(parent originalInput, row bulkChildRow, op scim.Operation, target string, ifMatch scim.Version) *bulkChildExecution {
	if nativeCreate(op) {
		target = row.Resource
	}
	return &bulkChildExecution{parent: parent.Command, row: row, ifMatch: ifMatch, original: originalInput{
		Command: identity.CommandID(row.Command), ID: target, Operation: op,
		Version: bulkChildVersion(row.Command), At: parent.At, Admission: parent.Admission,
	}}
}

func bulkChildAuthorizationType(operation scim.Operation) string {
	if operation == scim.UserCreate {
		return "identity.scim.user"
	}
	return "identity.scim.group"
}

func (s *Service) checkBulkChildDisclosure(ctx context.Context, operation scim.Operation, result scim.BulkChildResult) error {
	if operation == scim.UserCreate && result.Status == scim.BulkChildSucceeded {
		user, err := s.directory.Get(ctx, identity.GetUserQuery{TenantID: s.config().Scope.TenantID, UserID: identity.UserID(result.ResourceID)})
		if err != nil || user.Status != identity.StatusActive {
			return identity.ForbiddenError{}
		}
	}
	return nil
}

func bulkChildVersion(command string) scim.Version { return scim.Version(`"` + command + `"`) }

// The parent was verified against original custody and the adapter's exact
// scope. The child predicates bind the immutable graph identity and plan;
// only a retained outcome can bypass the first-ready guard (historical replay).
// Induction keeps earlier components concluded: a component could not have
// concluded before its immediate predecessor. The preceding component need
// only be terminal, but explicit dependencies must all have succeeded. Check
// only those rows instead of repeatedly scanning the completed prefix.
const bulkPriorComponentsReady = `NOT parent.cutoff_active AND
 (child.component_order=0 OR (
  EXISTS (SELECT 1 FROM scim.bulk_children AS prior WHERE prior.parent_id=child.parent_id AND prior.component_order=child.component_order-1)
  AND NOT EXISTS (SELECT 1 FROM scim.bulk_children AS prior WHERE prior.parent_id=child.parent_id
   AND prior.component_order=child.component_order-1 AND prior.status NOT IN ('succeeded','failed'))))`

const bulkChildReady = bulkPriorComponentsReady + `
 AND NOT EXISTS (SELECT 1 FROM unnest(child.dependency_ids) AS dependency(id)
  WHERE NOT EXISTS (SELECT 1 FROM scim.bulk_children AS predecessor WHERE predecessor.parent_id=child.parent_id
   AND predecessor.command_id=dependency.id AND predecessor.status='succeeded'))`

const bulkChildCheckpointRead = `SELECT child.status, child.result_code, child.result_resource_id, child.result_version,
 (NOT child.cyclic AND ` + bulkChildReady + `)
FROM scim.bulk_children child JOIN scim.bulk_requests parent ON parent.parent_id=child.parent_id
WHERE child.parent_id=$1 AND child.ordinal=$2 AND child.command_id=$3 AND child.request_fingerprint=$4
 AND child.resource_id=$5 AND child.component_order=$6`

const bulkChildStart = `UPDATE scim.bulk_children AS child SET status='running'
FROM scim.bulk_requests AS parent
WHERE parent.parent_id=child.parent_id AND child.parent_id=$1 AND child.ordinal=$2
 AND child.command_id=$3 AND child.request_fingerprint=$4 AND child.resource_id=$5
 AND child.component_order=$6 AND NOT child.cyclic AND child.status IN ('admitted','dependency-blocked')
 AND ` + bulkChildReady

const bulkChildSucceed = `UPDATE scim.bulk_children SET status='succeeded',result_code=201,result_resource_id=$5,result_version=$7
WHERE parent_id=$1 AND ordinal=$2 AND command_id=$3 AND request_fingerprint=$4 AND resource_id=$5
 AND component_order=$6 AND status='running'`

const bulkGroupMutationSucceed = `UPDATE scim.bulk_children SET status='succeeded',result_code=$7,result_resource_id=$8,result_version=NULLIF($9::text,'')
WHERE parent_id=$1 AND ordinal=$2 AND command_id=$3 AND request_fingerprint=$4 AND resource_id=$5
 AND component_order=$6 AND status='running' AND group_mutation_input IS NOT NULL`

func (p *bulkChildExecution) args() []any {
	return []any{string(p.parent), p.row.Ordinal, p.row.Command, p.row.Fingerprint, p.row.Resource, p.row.ComponentOrder}
}

func (s *Service) readBulkChild(ctx context.Context, phase *bulkChildExecution) (scim.BulkChildResult, bool, error) {
	var status string
	var code *int64
	var resource, version *string
	var ready bool
	err := s.pool.Raw().QueryRow(ctx, bulkChildCheckpointRead, phase.args()...).Scan(&status, &code, &resource, &version, &ready)
	if err != nil {
		return scim.BulkChildResult{}, false, identity.UnavailableError{}
	}
	return decodeBulkChildCheckpoint(phase, status, code, resource, version, ready)
}

func decodeBulkChildCheckpoint(phase *bulkChildExecution, status string, code *int64, resource, version *string, ready bool) (scim.BulkChildResult, bool, error) {
	if status == "succeeded" && code != nil && resource != nil && *resource == phase.original.ID {
		if result, ok := phase.successfulResult(*code, version); ok {
			return result, false, nil
		}
	}
	if status == "failed" && code != nil && resource == nil && version == nil {
		if result, ok := phase.failureResult(int(*code)); ok {
			return result, false, nil
		}
	}
	if status == "admitted" && code == nil && resource == nil && version == nil {
		return scim.BulkChildResult{Status: scim.BulkChildAdmitted}, ready, nil
	}
	if status == "dependency-blocked" && code == nil && resource == nil && version == nil {
		return scim.BulkChildResult{Status: scim.BulkChildDependencyBlocked}, ready, nil
	}
	if status == "skipped" && !ready && code == nil && resource == nil && version == nil {
		// The graph schema permits only the fail-on-errors reason for skipped rows.
		return scim.BulkChildResult{Status: scim.BulkChildSkipped, SkipReason: scim.BulkSkipFailOnErrors}, false, nil
	}
	return scim.BulkChildResult{}, false, identity.UnavailableError{}
}

func (p *bulkChildExecution) failureResult(code int) (scim.BulkChildResult, bool) {
	if code == 424 && (p.row.Cyclic && p.original.Operation == scim.GroupCreate ||
		!p.row.Cyclic && len(p.row.Dependencies) > 0 && groupOperation(p.original.Operation)) {
		return scim.BulkChildResult{Status: scim.BulkChildFailed, Code: code}, true
	}
	if p.original.Operation == scim.UserCreate && !p.row.Cyclic && code == 409 {
		// The native User-create callback accepts only the kernel's uniqueness
		// denial for this checkpoint code; generic conflicts are not equivalent.
		return scim.BulkChildResult{Status: scim.BulkChildFailed, Code: code, SCIMType: "uniqueness"}, true
	}
	if !p.row.Cyclic && code == 503 && (p.original.Operation == scim.UserCreate ||
		groupOperation(p.original.Operation) && (nativeCreate(p.original.Operation) || nativeMutation(p.original.Operation))) {
		return scim.BulkChildResult{Status: scim.BulkChildFailed, Code: code}, true
	}
	return bulkGroupFailureResult(p.original.Operation, code)
}

func (p *bulkChildExecution) successfulResult(code int64, version *string) (scim.BulkChildResult, bool) {
	result := scim.BulkChildResult{Status: scim.BulkChildSucceeded, Code: int(code), ResourceID: p.original.ID}
	if p.original.ID == "" {
		return result, false
	}
	if p.original.Operation == scim.GroupDelete {
		return result, code == 204 && version == nil
	}
	if version == nil {
		return result, false
	}
	result.Version = scim.Version(*version)
	switch p.original.Operation {
	case scim.GroupCreate, scim.UserCreate:
		return result, code == 201 && result.Version == p.original.Version
	case scim.GroupReplace:
		return result, code == 200 && result.Version == p.original.Version
	case scim.GroupPatch:
		return result, code == 200 && (result.Version == p.original.Version || p.ifMatch != "" && result.Version == p.ifMatch)
	default:
		return result, false
	}
}

func (p *nativePhase) applyBulkGroupChild(ctx context.Context, w kernel.Work) (identity.FeatureReceipt, error) {
	phase := p.bulkChild
	// ApplyFeature already holds the current connection writer fence. Both
	// child transitions join this same Work, so a failure cannot leave running
	// status or acknowledge a projection without a result checkpoint.
	var count int64
	var err error
	if phase.cycle != nil {
		count, err = w.Exec(ctx, bulkCycleChildStart, append(phase.args(), phase.row.ComponentID)...)
		if err != nil || count != 1 {
			return identity.FeatureReceipt{}, identity.UnavailableError{}
		}
	} else if err := p.startAcyclicBulkChild(ctx, w); err != nil {
		return identity.FeatureReceipt{}, err
	}
	receipt, err := p.applyGroupProjection(ctx, w)
	if err != nil {
		return identity.FeatureReceipt{}, err
	}
	if p.intent.Operation == scim.GroupCreate {
		return p.finishBulkCreate(ctx, w, receipt)
	} else {
		code, version := 204, ""
		if p.intent.Operation != scim.GroupDelete {
			code, version = 200, string(p.resource.Version)
			if p.resource.ID != phase.original.ID {
				return identity.FeatureReceipt{}, identity.UnavailableError{}
			}
			if _, ok := phase.successfulResult(int64(code), &version); !ok {
				return identity.FeatureReceipt{}, identity.UnavailableError{}
			}
		}
		count, err = w.Exec(ctx, bulkGroupMutationSucceed, append(phase.args(), code, phase.original.ID, version)...)
	}
	if err != nil || count != 1 {
		return identity.FeatureReceipt{}, identity.UnavailableError{}
	}
	return receipt, nil
}

func (p *nativePhase) startAcyclicBulkChild(ctx context.Context, w kernel.Work) error {
	count, err := w.Exec(ctx, bulkChildStart, p.bulkChild.args()...)
	if err != nil || count != 1 {
		return identity.UnavailableError{}
	}
	return w.MarkSCIMBulkChildStarted(ctx, p, p.command)
}

func (p *nativePhase) finishBulkCreate(ctx context.Context, w kernel.Work, receipt identity.FeatureReceipt) (identity.FeatureReceipt, error) {
	phase := p.bulkChild
	if p.resource.ID != phase.original.ID || p.resource.Version != phase.original.Version {
		return identity.FeatureReceipt{}, identity.UnavailableError{}
	}
	count, err := w.Exec(ctx, bulkChildSucceed, append(phase.args(), string(p.resource.Version))...)
	if err != nil || count != 1 {
		return identity.FeatureReceipt{}, identity.UnavailableError{}
	}
	return receipt, nil
}
