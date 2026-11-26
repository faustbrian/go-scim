package scimpostgres

import (
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
		p.original.ID == "" || p.original.Operation != p.intent.Operation || p.intent.IfMatch != child.ifMatch {
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
	kind, ok := bulkValidationKind(p.original.Operation, kernel.FeatureFailureCode(denial))
	if !ok {
		return scim.BulkChildResult{}, identity.UnavailableError{}
	}
	return scim.BulkChildResult{Status: scim.BulkChildFailed, Code: 400, SCIMType: kind}, nil
}
