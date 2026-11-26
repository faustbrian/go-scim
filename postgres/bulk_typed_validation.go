package scimpostgres

import (
	"context"

	identity "github.com/faustbrian/go-identity"
	kernel "github.com/faustbrian/go-identity/postgres"
	scim "github.com/faustbrian/go-scim"
)

// These are the operation-specific resource request errors produced before
// Prepare. Snapshot-derived errors such as noTarget are not classified here.
var bulkPrePrepareValidation = [...]struct {
	code kernel.FeatureFailureCode
	kind string
}{
	{kernel.FeatureFailureSCIMBulkInvalidValue, "invalidValue"},
	{kernel.FeatureFailureSCIMBulkMutability, "mutability"},
	{kernel.FeatureFailureSCIMBulkInvalidSyntax, "invalidSyntax"},
	{kernel.FeatureFailureSCIMBulkInvalidPath, "invalidPath"},
	{kernel.FeatureFailureSCIMBulkUntypedBadRequest, ""},
}

func bulkValidationKind(op scim.Operation, code kernel.FeatureFailureCode) (string, bool) {
	if !nativeCreate(op) && !nativeMutation(op) {
		return "", false
	}
	for _, entry := range bulkPrePrepareValidation {
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
		case kernel.FeatureFailureSCIMBulkInvalidPath:
			return entry.kind, patch
		default:
			return entry.kind, true
		}
	}
	return "", false
}

func (p *bulkChildExecution) validationFailure(kind string) kernel.FeatureFailureCode {
	if !p.retainTypedValidation || p.row.Cyclic {
		return 0
	}
	for _, entry := range bulkPrePrepareValidation {
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
	return p.original.ID == p.intent.ResourceID
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
