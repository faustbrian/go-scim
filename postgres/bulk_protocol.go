package scimpostgres

import (
	"context"

	authentication "github.com/faustbrian/go-authentication/v2"
	scim "github.com/faustbrian/go-scim"
)

// BulkPolicies returns the effective immutable request and response limits
// used by this executor. A nil or zero service returns zero policies.
func (s *BulkService) BulkPolicies() (scim.BulkPolicy, scim.BulkResponsePolicy) {
	graph := s.executor()
	if graph == nil {
		return scim.BulkPolicy{}, scim.BulkResponsePolicy{}
	}
	return graph.request, graph.response
}

// ReadBulkServiceProviderConfig reads authorized discovery for the selected
// executor. It advertises the same limits used by ExecuteBulkProtocol, not
// transport-supplied settings. It requires a gate after native discovery
// authentication and authorization. It does not change ordinary discovery.
func (s *BulkService) ReadBulkServiceProviderConfig(ctx context.Context, credential authentication.BearerCredential, admit scim.ProtocolAdmission) (scim.Response, error) {
	graph := s.executor()
	if graph == nil || graph.native == nil || graph.native.protocol == nil || ctx == nil || admit == nil {
		return scim.Response{}, scim.NewError(503, "")
	}
	native := graph.native
	request := scim.Request{Operation: scim.ServiceProviderConfig, Credential: credential}
	return native.executeProtocol(ctx, request, func(ctx context.Context, r scim.Request) (scim.Response, error) {
		return native.protocol.ReadServiceProviderConfigWithBulk(ctx, r.Credential, graph.request, func(ctx context.Context) *scim.Error {
			return native.admitBulkProtocol(ctx, admit)
		})
	})
}

func (s *Service) admitBulkProtocol(ctx context.Context, admit scim.ProtocolAdmission) *scim.Error {
	if ctx.Err() != nil {
		return scim.NewError(503, "")
	}
	config := s.config()
	denial := admit(ctx, scim.ProtocolClient{ID: config.ActorID, TenantID: config.Scope.TenantID})
	if ctx.Err() != nil {
		return scim.NewError(503, "")
	}
	if denial == nil {
		return nil
	}
	switch denial.StatusCode() {
	case 403:
		return scim.NewError(403, "")
	case 429:
		if denial.RetryAfterSeconds() != 0 {
			return denial
		}
	}
	return scim.NewError(503, "")
}
