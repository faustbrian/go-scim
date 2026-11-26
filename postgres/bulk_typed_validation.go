package scimpostgres

import (
	"context"

	identity "github.com/faustbrian/go-identity"
	kernel "github.com/faustbrian/go-identity/postgres"
	scim "github.com/faustbrian/go-scim"
)

// The closed wire types can be retained only before any resource commit.
var bulkValidationDenials = [...]struct {
	code kernel.FeatureFailureCode
	kind string
}{
	{kernel.FeatureFailureSCIMBulkInvalidValue, "invalidValue"},
	{kernel.FeatureFailureSCIMBulkMutability, "mutability"},
	{kernel.FeatureFailureSCIMBulkInvalidSyntax, "invalidSyntax"},
	{kernel.FeatureFailureSCIMBulkInvalidPath, "invalidPath"},
	{kernel.FeatureFailureSCIMBulkUntypedBadRequest, ""},
	{kernel.FeatureFailureSCIMBulkNoTarget, "noTarget"},
}

func bulkValidationKind(op scim.Operation, code kernel.FeatureFailureCode) (string, bool) {
	if !nativeCreate(op) && !nativeMutation(op) {
		return "", false
	}
	for _, entry := range bulkValidationDenials {
		if entry.code != code {
			continue
		}
		replace := op == scim.UserReplace || op == scim.GroupReplace
		patch := op == scim.UserPatch || op == scim.GroupPatch
		switch code {
		case kernel.FeatureFailureSCIMBulkMutability:
			return entry.kind, !nativeDelete(op)
		case kernel.FeatureFailureSCIMBulkInvalidSyntax:
			return entry.kind, nativeCreate(op) || replace
		case kernel.FeatureFailureSCIMBulkInvalidPath, kernel.FeatureFailureSCIMBulkNoTarget:
			return entry.kind, patch
		default:
			return entry.kind, true
		}
	}
	return "", false
}

func (p *bulkChildExecution) validationFailure(kind string) kernel.FeatureFailureCode {
	if kind == "noTarget" {
		return 0 // Only evaluation against the original snapshot can prove this.
	}
	return p.typedValidationFailure(kind)
}

func (p *bulkChildExecution) typedValidationFailure(kind string) kernel.FeatureFailureCode {
	if !p.retainTypedValidation || p.row.Cyclic {
		return 0
	}
	for _, entry := range bulkValidationDenials {
		if entry.kind == kind {
			if _, ok := bulkValidationKind(p.original.Operation, entry.code); ok {
				return entry.code
			}
			return 0
		}
	}
	return 0
}

func (p *nativePhase) typedValidationMatches(code kernel.FeatureFailureCode) bool {
	child := p.bulkChild
	if child == nil || !child.retainTypedValidation || child.row.Cyclic || p.original != child.original ||
		p.original.ID == "" || p.original.Operation != p.intent.Operation || p.intent.IfMatch != child.ifMatch ||
		child.plannerDenial != 0 && child.plannerDenial != code {
		return false
	}
	if _, ok := bulkValidationKind(p.intent.Operation, code); !ok {
		return false
	}
	if nativeCreate(p.intent.Operation) {
		return p.original.ID == child.row.Resource && p.intent.ResourceID == "" && p.intent.IfMatch == ""
	}
	if code == kernel.FeatureFailureSCIMBulkNoTarget && (p.original.Current == nil || p.intent.IfMatch == "" || p.original.Current.Version != p.intent.IfMatch) {
		return false
	}
	return p.original.ID == p.intent.ResourceID
}

// Prepare copies only the original immutable input. Abort can observe its
// resource validation result before Commit, but never persist a denial itself.
func (i *invocation) observeBulkValidationAbort(prepared scim.PreparedWrite) {
	if i == nil || i.phase == nil || i.bulkChild == nil || i.phase.bulkChild != i.bulkChild ||
		!i.prepareStarted || i.commitStarted || i.snapshotFailure != 0 || i.bulkChild.plannerDenial != 0 ||
		prepared.Replay != nil || prepared.Failure == nil || prepared.Failure.StatusCode() != 400 ||
		!i.phase.matchesPreparedIntent(prepared.Intent) {
		return
	}
	p := i.phase
	kind := prepared.Failure.SCIMType()
	if kind != "noTarget" && kind != "mutability" && kind != "invalidValue" {
		return
	}
	code := i.bulkChild.typedValidationFailure(kind)
	if code == 0 || !p.typedValidationMatches(code) {
		return
	}
	if nativeCreate(p.intent.Operation) {
		// A create can exceed the prospective response limit after Prepare,
		// but there is no prior resource on which to evaluate mutability.
		meta := prepared.CreateMetadata
		if kind != "invalidValue" || prepared.Current != nil || prepared.UpdateMetadata != nil || meta == nil ||
			meta.ID != p.original.ID || meta.Version != p.original.Version || !meta.CreatedAt.Equal(p.original.At) || !meta.LastModified.Equal(p.original.At) {
			return
		}
	} else {
		current, original := prepared.Current, p.original.Current
		if nativeDelete(p.intent.Operation) || prepared.CreateMetadata != nil || current == nil || original == nil ||
			current.ID != p.original.ID || current.ID != original.ID || current.Version != original.Version ||
			p.intent.IfMatch == "" || original.Version != p.intent.IfMatch {
			return
		}
	}
	i.snapshotFailure = code
}

func (p *bulkChildExecution) retainedTypedValidation(status string, code *int64, target, version *string, denial int64) (scim.BulkChildResult, error) {
	if !p.retainTypedValidation || p.row.Cyclic || status != "failed" || code == nil || *code != 400 ||
		target == nil || *target != p.original.ID || *target == "" || version != nil || denial < 0 || denial > 255 {
		return scim.BulkChildResult{}, identity.UnavailableError{}
	}
	retained := kernel.FeatureFailureCode(denial)
	kind, ok := bulkValidationKind(p.original.Operation, retained)
	if !ok || p.plannerDenial != 0 && p.plannerDenial != retained {
		return scim.BulkChildResult{}, identity.UnavailableError{}
	}
	return scim.BulkChildResult{Status: scim.BulkChildFailed, Code: 400, SCIMType: kind}, nil
}

func (s *GroupBulkService) newBulkValidationPhase(admission invocation, child *bulkChildExecution, target, canonical string) (*nativePhase, error) {
	p := &nativePhase{service: s.native, bulkChild: child, admission: admission, original: child.original, intent: scim.WriteIntent{
		Operation: child.original.Operation, Scope: admission.connection.Scope, ResourceID: target, IfMatch: child.ifMatch,
		CanonicalRequest: []byte(canonical),
	}}
	coordinator, registry, err := s.native.coordinator(p)
	if err != nil {
		return nil, err
	}
	p.coordinator, p.registry = coordinator, registry
	return p, nil
}

func (s *GroupBulkService) retainPlannerBulkDenial(ctx context.Context, parent *nativePhase, child *bulkChildExecution, target string) (scim.BulkChildResult, error) {
	kind, ok := bulkValidationKind(child.original.Operation, child.plannerDenial)
	if !ok {
		return scim.BulkChildResult{}, identity.UnavailableError{}
	}
	p, err := s.newBulkValidationPhase(parent.admission, child, target, "identity.scim.bulk.planner-validation.v1:"+kind)
	if err != nil {
		return scim.BulkChildResult{}, err
	}
	if err := p.recordBulkProtocolDenial(ctx, child.plannerDenial); err != nil {
		return scim.BulkChildResult{}, err
	}
	result, _, err := s.native.readBulkChild(ctx, child)
	if err != nil || result != (scim.BulkChildResult{Status: scim.BulkChildFailed, Code: 400, SCIMType: kind}) {
		return scim.BulkChildResult{}, identity.UnavailableError{}
	}
	if err := s.native.recheckRead(ctx, &parent.admission); err != nil {
		return scim.BulkChildResult{}, err
	}
	return result, nil
}
