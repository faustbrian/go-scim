package scimpostgres

import (
	"context"
	"errors"

	identity "github.com/faustbrian/go-identity"
	scim "github.com/faustbrian/go-scim"
)

// ExecuteManagedProvisioning uses the issued bearer for the exact tenant and
// active managed connection. This selection exposes User Create, Get, List,
// and conditional Delete under RemoveMembership. Delete removes the exact
// source contribution, not the identity account. Other writes remain unavailable.
func (s *ManagedConnectionService) ExecuteManagedProvisioning(ctx context.Context, tenant identity.TenantID, request scim.Request) (scim.Response, error) {
	if s == nil || ctx == nil || s.writer == nil {
		return scim.Response{}, scim.NewError(503, "")
	}
	ctx, cancel := context.WithTimeout(ctx, s.config.MaximumDuration)
	defer cancel()
	source, err := s.loadManagedProvisioning(ctx, tenant, request.Credential)
	if err != nil {
		var denied identity.ForbiddenError
		if errors.As(err, &denied) {
			return scim.Response{}, scim.NewError(401, "")
		}
		return scim.Response{}, scim.NewError(503, "")
	}
	switch request.Operation {
	case scim.UserCreate, scim.UserGet, scim.UserList, scim.UserDelete:
		return source.Execute(ctx, request)
	default:
		return scim.Response{}, scim.NewError(501, "")
	}
}
