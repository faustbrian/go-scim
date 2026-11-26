package scimpostgres

import (
	"context"

	identity "github.com/faustbrian/go-identity"
	kernel "github.com/faustbrian/go-identity/postgres"
	scim "github.com/faustbrian/go-scim"
)

func (s *GroupBulkService) retainStructuralBulkDenial(ctx context.Context, parent *nativePhase, child *bulkChildExecution) (scim.BulkChildResult, error) {
	p := &nativePhase{service: s.native, bulkChild: child, original: child.original, admission: parent.admission, intent: scim.WriteIntent{
		Operation: bulkInvalidChild, Scope: parent.admission.connection.Scope,
		CanonicalRequest: []byte("identity.scim.bulk.invalid-child.v1"),
	}}
	coordinator, registry, err := s.native.coordinator(p)
	if err != nil {
		return scim.BulkChildResult{}, err
	}
	p.coordinator, p.registry = coordinator, registry
	if err := p.recordBulkProtocolDenial(ctx, kernel.FeatureFailureBulkChildInvalid); err != nil {
		return scim.BulkChildResult{}, err
	}
	result, _, err := s.native.readBulkChild(ctx, child)
	if err != nil || result.Status != scim.BulkChildFailed {
		return scim.BulkChildResult{}, identity.UnavailableError{}
	}
	if err := s.native.recheckRead(ctx, &parent.admission); err != nil {
		return scim.BulkChildResult{}, err
	}
	return result, nil
}
