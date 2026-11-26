package scimpostgres

import (
	"context"
	"errors"

	identity "github.com/faustbrian/go-identity"
	kernel "github.com/faustbrian/go-identity/postgres"
	scim "github.com/faustbrian/go-scim"
)

type bulkChildExecution struct {
	parent                identity.CommandID
	row                   bulkChildRow
	original              originalInput
	ifMatch               scim.Version
	acknowledgedFailure   bool
	cycle                 *groupCreateCycleMember
	structuralAuthority   bulkChildAuthority
	retainTypedValidation bool
}

const bulkInvalidChild scim.Operation = "identity.scim.bulk-child-invalid"

type bulkChildAuthority struct {
	operation scim.Operation
	target    string
	symbolic  bool
}

func structuralBulkInvalidValue(child scim.BulkOperation) bool {
	return child.Error != nil && child.Error.StatusCode() == 400 && child.Error.SCIMType() == "invalidValue"
}

func resourceFreeBulkError(child scim.BulkOperation) bool {
	return structuralBulkInvalidValue(child) &&
		child.Target == (scim.BulkTarget{}) && len(child.Dependencies) == 0
}

func structuralBulkAuthority(child scim.BulkOperation, targets map[string]string) bulkChildAuthority {
	if !structuralBulkInvalidValue(child) {
		return bulkChildAuthority{}
	}
	symbolic := child.Target.BulkID != ""
	if symbolic {
		if child.Target.ResourceID != "" || len(child.Dependencies) != 1 {
			return bulkChildAuthority{}
		}
	} else if child.Target.ResourceID == "" || len(child.Dependencies) != 0 {
		return bulkChildAuthority{}
	}
	op, target := selectDeclaredBulkChild(child, targets)
	if !nativeMutation(op) || target == "" {
		return bulkChildAuthority{}
	}
	return bulkChildAuthority{operation: op, target: target, symbolic: symbolic}
}

func newStructuralBulkChild(parent originalInput, row bulkChildRow, child scim.BulkOperation, targets map[string]string) *bulkChildExecution {
	authority := structuralBulkAuthority(child, targets)
	if !resourceFreeBulkError(child) && authority.operation == "" {
		return nil
	}
	// Command identity is also the denial record identity, not a resource ID.
	phase := newBulkChildExecution(parent, row, bulkInvalidChild, row.Command, "")
	phase.structuralAuthority = authority
	if !phase.validStructuralRow() {
		return nil
	}
	return phase
}

func (p *bulkChildExecution) validStructuralRow() bool {
	if p.original.Operation != bulkInvalidChild || p.row.Resource != "" || p.row.Cyclic {
		return false
	}
	if p.structuralAuthority.symbolic {
		return len(p.row.Dependencies) == 1 && nativeMutation(p.structuralAuthority.operation) && p.structuralAuthority.target != ""
	}
	return len(p.row.Dependencies) == 0
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
	rows, err := parent.bulk.childRows()
	if err != nil {
		return result, err
	}
	return s.executeAdmittedBulkChild(ctx, request, parent, plan, rows, ordinal)
}

func (s *GroupBulkService) executeAdmittedBulkChild(ctx context.Context, request BulkAdmissionRequest, parent *nativePhase, plan scim.BulkPlan, rows []bulkChildRow, ordinal int) (result scim.BulkChildResult, err error) {
	child := parent.bulk.children[ordinal]
	selected := rows[ordinal]
	targets := parent.bulk.createTargets()
	operation, target := parent.bulk.selectChild(ordinal, targets)
	if operation != "" {
		if err := s.native.decide(ctx, string(operation), target, bulkChildAuthorizationType(operation)); err != nil {
			return result, err
		}
	}
	phase := newStructuralBulkChild(parent.original, selected, child, targets)
	structural := phase != nil
	if !structural {
		phase = newBulkChildExecution(parent.original, selected, operation, target, scim.Version(child.Version))
	}
	phase.retainTypedValidation = parent.bulk.retainTypedValidation
	checkpoint, ready, err := s.native.readBulkChild(ctx, phase)
	if err != nil {
		return result, err
	}
	// Cutoff can skip any admitted declaration, including a child whose parsed
	// operation would be invalid or unsupported. Replay that retained skip, not
	// a new operation result. Before cutoff the original errors still apply.
	if checkpoint.Status != scim.BulkChildSkipped && !structural {
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
	if structural {
		return s.retainStructuralBulkDenial(ctx, parent, phase)
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
	if !groupOperation(operation) {
		execute = s.native.protocol.Execute
	}
	response, err := execute(ctx, scim.Request{Operation: operation, ResourceID: target, IfMatch: phase.ifMatch, Credential: request.Credential, Body: resolved.Data, ContentType: "application/scim+json"})
	if err != nil {
		var protocol *scim.Error
		if !phase.acknowledgedFailure && errors.As(err, &protocol) && protocol != nil {
			var code kernel.FeatureFailureCode
			p := i.phase
			switch protocol.StatusCode() {
			case 400:
				if i.prepareStarted || p != nil {
					break
				}
				kind := protocol.SCIMType()
				code = phase.validationFailure(kind)
				canonical := "identity.scim.bulk.pre-prepare.v1:" + kind
				if operation == scim.GroupCreate && kind == "invalidValue" {
					// Preserve the already-published command fingerprint and code.
					canonical = "identity.scim.bulk.group-create-invalid-value.v1"
					code = kernel.FeatureFailureGroupCreateInvalidValue
				}
				if code != 0 {
					p = &nativePhase{service: s.native, bulkChild: phase, admission: i, original: phase.original, intent: scim.WriteIntent{
						Operation: operation, Scope: i.connection.Scope, ResourceID: target, IfMatch: phase.ifMatch,
						CanonicalRequest: []byte(canonical),
					}}
					coordinator, registry, setupErr := s.native.coordinator(p)
					if setupErr != nil {
						return result, setupErr
					}
					p.coordinator, p.registry = coordinator, registry
				}
			case 404:
				if nativeMutation(operation) && p != nil {
					missing := kernel.FeatureFailureGroupMissing
					if !p.group() {
						missing = kernel.FeatureFailureUserMissing
					}
					if p.bulkDenialMatches(missing) {
						code = missing
					}
				}
			case 412:
				if nativeMutation(operation) && p != nil && p.hasStaleBulkPrecondition() {
					code = kernel.FeatureFailurePrecondition
					if !p.group() {
						code = kernel.FeatureFailureUserVersionMismatch
					}
				}
			case 428:
				if nativeMutation(operation) && p == nil && phase.ifMatch == "" {
					// Ordinary validation rejected the missing precondition
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
					if !p.group() {
						code = kernel.FeatureFailureUserVersionRequired
					}
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
	return p.bulkChild != nil && nativeMutation(p.intent.Operation) &&
		p.original.Current != nil && p.intent.IfMatch != "" && p.original.Current.Version != p.intent.IfMatch
}

func (p *nativePhase) bulkDenialMatches(code kernel.FeatureFailureCode) bool {
	if _, ok := bulkValidationKind(p.intent.Operation, code); ok {
		return p.typedValidationMatches(code)
	}
	if code == kernel.FeatureFailureBulkChildInvalid {
		child := p.bulkChild
		return child != nil && child.validStructuralRow() &&
			p.intent.Operation == bulkInvalidChild && p.intent.ResourceID == "" && p.intent.IfMatch == "" &&
			p.original == child.original && p.original.Operation == bulkInvalidChild && p.original.ID == string(p.original.Command)
	}
	if code == kernel.FeatureFailureSCIMBulkDependency {
		return p.bulkChild != nil && (nativeMutation(p.intent.Operation) || p.intent.Operation == scim.GroupCreate) && !p.bulkChild.row.Cyclic &&
			len(p.bulkChild.row.Dependencies) > 0 && p.original == p.bulkChild.original && p.intent.Operation == p.original.Operation
	}
	if code == kernel.FeatureFailureGroupCreateInvalidValue {
		return p.bulkChild != nil && !p.bulkChild.row.Cyclic && p.intent.Operation == scim.GroupCreate &&
			p.original.Operation == p.intent.Operation && p.original == p.bulkChild.original &&
			p.original.ID == p.bulkChild.row.Resource && p.original.ID != "" &&
			p.intent.ResourceID == "" && p.intent.IfMatch == "" && p.bulkChild.ifMatch == ""
	}
	if p.bulkChild == nil || p.bulkChild.row.Cyclic || !nativeMutation(p.intent.Operation) || p.intent.ResourceID != p.original.ID || p.original.Operation != p.intent.Operation {
		return false
	}
	switch code {
	case kernel.FeatureFailureGroupMissing:
		return p.group() && p.intent.IfMatch != "" && p.original.Schema == 3 && p.original.Current == nil && p.original.Generation == 0
	case kernel.FeatureFailureGroupVersionRequired:
		return p.group() && p.intent.IfMatch == "" && p.original.Schema == 0 && p.original.Current == nil && p.original.Generation == 0
	case kernel.FeatureFailureUserMissing:
		return !p.group() && p.intent.IfMatch != "" && p.original.Schema == 2 && p.original.Current == nil && p.original.Generation == 0
	case kernel.FeatureFailureUserVersionRequired:
		return !p.group() && p.intent.IfMatch == "" && p.original.Schema == 0 && p.original.Current == nil && p.original.Generation == 0
	case kernel.FeatureFailureUserVersionMismatch:
		return !p.group() && p.original.Schema == 2 && p.hasStaleBulkPrecondition()
	default:
		return false
	}
}

func (p *nativePhase) recordBulkProtocolDenial(ctx context.Context, code kernel.FeatureFailureCode) error {
	// The resource protocol has already authorized, parsed and rejected this exact
	// request. The actual denial is derived again from the sealed original in
	// Work. No transport error value or fresh projection can choose the outcome.
	op, target, kind := p.intent.Operation, p.intent.ResourceID, bulkChildAuthorizationType(p.intent.Operation)
	if code == kernel.FeatureFailureBulkChildInvalid {
		op, target, kind = scim.Bulk, p.service.config().Scope.ConnectionID, "identity.scim.bulk"
	}
	if err := p.service.decide(ctx, string(op), target, kind); err != nil {
		return err
	}
	if code != kernel.FeatureFailurePrecondition {
		if !p.bulkDenialMatches(code) {
			return identity.ForbiddenError{}
		}
		p.denialOnly = code
	}
	if code == kernel.FeatureFailureBulkChildInvalid {
		// The internal journal operation is not a resource permission. A
		// malformed literal still needs its declared permission at settlement.
		authority := p.bulkChild.structuralAuthority
		if authority.operation != "" {
			if err := p.service.decide(ctx, string(authority.operation), authority.target, bulkChildAuthorizationType(authority.operation)); err != nil {
				return err
			}
		}
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

func (p *bulkAdmissionPhase) createTargets() map[string]string {
	targets := make(map[string]string)
	for i, child := range p.children {
		if child.Error == nil && bulkCreatesResource(child) && child.BulkID != "" {
			targets[child.BulkID] = p.allocation[i].Resource
		}
	}
	return targets
}

func (p *bulkAdmissionPhase) selectChild(ordinal int, targets map[string]string) (scim.Operation, string) {
	child := p.children[ordinal]
	if child.Error != nil {
		authority := structuralBulkAuthority(child, targets)
		return authority.operation, authority.target
	}
	return selectDeclaredBulkChild(child, targets)
}

func selectDeclaredBulkChild(child scim.BulkOperation, targets map[string]string) (scim.Operation, string) {
	if child.Target.ResourceType == "User" && child.Method == "POST" {
		return scim.UserCreate, ""
	}
	user := child.Target.ResourceType == "User"
	if child.Target.ResourceType != "Group" && !user {
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
		if user {
			return scim.UserReplace, target
		}
		return scim.GroupReplace, target
	case "PATCH":
		if user {
			return scim.UserPatch, target
		}
		return scim.GroupPatch, target
	case "DELETE":
		if user {
			return scim.UserDelete, target
		}
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
	if !groupOperation(operation) {
		return "identity.scim.user"
	}
	return "identity.scim.group"
}

func (s *Service) checkBulkChildDisclosure(ctx context.Context, operation scim.Operation, result scim.BulkChildResult) error {
	if !groupOperation(operation) && result.Status == scim.BulkChildSucceeded {
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

const bulkChildCheckpointProjection = `SELECT child.status, child.result_code, child.result_resource_id, child.result_version,
 (NOT child.cyclic AND ` + bulkChildReady + `)`
const bulkChildCheckpointFilter = `
FROM scim.bulk_children child JOIN scim.bulk_requests parent ON parent.parent_id=child.parent_id
WHERE child.parent_id=$1 AND child.ordinal=$2 AND child.command_id=$3 AND child.request_fingerprint=$4
 AND child.resource_id=$5 AND child.component_order=$6`

const bulkChildCheckpointRead = bulkChildCheckpointProjection + bulkChildCheckpointFilter
const bulkTypedChildCheckpointRead = bulkChildCheckpointProjection + `,child.result_denial_code` + bulkChildCheckpointFilter

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
	var row bulkChildCheckpoint
	query, destinations := row.selectFor(phase)
	err := s.pool.Raw().QueryRow(ctx, query, phase.args()...).Scan(destinations...)
	if err != nil {
		return scim.BulkChildResult{}, false, identity.UnavailableError{}
	}
	return row.decode(phase)
}

type bulkChildCheckpoint struct {
	status            string
	code, denial      *int64
	resource, version *string
	ready             bool
}

func (r *bulkChildCheckpoint) selectFor(phase *bulkChildExecution) (string, []any) {
	destinations := []any{&r.status, &r.code, &r.resource, &r.version, &r.ready}
	if phase.retainTypedValidation {
		return bulkTypedChildCheckpointRead, append(destinations, &r.denial)
	}
	return bulkChildCheckpointRead, destinations
}

func (r bulkChildCheckpoint) decode(phase *bulkChildExecution) (scim.BulkChildResult, bool, error) {
	status, code, resource, version, ready := r.status, r.code, r.resource, r.version, r.ready
	if r.denial != nil {
		result, err := phase.retainedTypedValidation(status, code, resource, version, *r.denial)
		return result, false, err
	}
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
	if p.original.Operation == bulkInvalidChild {
		if code == 400 && p.validStructuralRow() {
			return scim.BulkChildResult{Status: scim.BulkChildFailed, Code: code, SCIMType: "invalidValue"}, true
		}
		if code == 424 && p.validStructuralRow() && p.structuralAuthority.symbolic {
			return scim.BulkChildResult{Status: scim.BulkChildFailed, Code: code}, true
		}
		return scim.BulkChildResult{}, false
	}
	if code == 424 && (p.row.Cyclic && p.original.Operation == scim.GroupCreate ||
		!p.row.Cyclic && len(p.row.Dependencies) > 0 && (nativeMutation(p.original.Operation) || p.original.Operation == scim.GroupCreate)) {
		return scim.BulkChildResult{Status: scim.BulkChildFailed, Code: code}, true
	}
	if !p.row.Cyclic && code == 409 && (p.original.Operation == scim.UserCreate || p.original.Operation == scim.UserReplace || p.original.Operation == scim.UserPatch) {
		// The native User callback accepts only the kernel's uniqueness
		// denial for this checkpoint code; generic conflicts are not equivalent.
		return scim.BulkChildResult{Status: scim.BulkChildFailed, Code: code, SCIMType: "uniqueness"}, true
	}
	if !p.row.Cyclic && code == 503 && (nativeCreate(p.original.Operation) || nativeMutation(p.original.Operation)) {
		return scim.BulkChildResult{Status: scim.BulkChildFailed, Code: code}, true
	}
	if !p.row.Cyclic && !groupOperation(p.original.Operation) && nativeMutation(p.original.Operation) && (code == 404 || code == 412 || code == 428) {
		return scim.BulkChildResult{Status: scim.BulkChildFailed, Code: code}, true
	}
	return bulkGroupFailureResult(p.original.Operation, code)
}

func (p *bulkChildExecution) successfulResult(code int64, version *string) (scim.BulkChildResult, bool) {
	result := scim.BulkChildResult{Status: scim.BulkChildSucceeded, Code: int(code), ResourceID: p.original.ID}
	if p.original.ID == "" {
		return result, false
	}
	if nativeDelete(p.original.Operation) {
		return result, code == 204 && version == nil
	}
	if version == nil {
		return result, false
	}
	result.Version = scim.Version(*version)
	switch p.original.Operation {
	case scim.GroupCreate, scim.UserCreate:
		return result, code == 201 && result.Version == p.original.Version
	case scim.GroupReplace, scim.UserReplace:
		return result, code == 200 && result.Version == p.original.Version
	case scim.GroupPatch, scim.UserPatch:
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
	}
	return p.finishBulkMutation(ctx, w, receipt)
}

func (p *nativePhase) finishBulkMutation(ctx context.Context, w kernel.Work, receipt identity.FeatureReceipt) (identity.FeatureReceipt, error) {
	phase := p.bulkChild
	code, version := 204, ""
	if !nativeDelete(p.intent.Operation) {
		code, version = 200, string(p.resource.Version)
		if p.resource.ID != phase.original.ID {
			return identity.FeatureReceipt{}, identity.UnavailableError{}
		}
		if _, ok := phase.successfulResult(int64(code), &version); !ok {
			return identity.FeatureReceipt{}, identity.UnavailableError{}
		}
	}
	count, err := w.Exec(ctx, bulkGroupMutationSucceed, append(phase.args(), code, phase.original.ID, version)...)
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
