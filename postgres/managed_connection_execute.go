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

// ExecuteManagedAdmittedRead selects only User Get and List for an issued
// managed bearer in the exact tenant. A nonnil synchronous admission gate is
// required; other operations return 501 and missing composition returns 503.
// ExecuteManagedProvisioning retains its existing behavior.
//
// The request and gate are borrowed only during this call. The gate runs once
// after current native bearer authentication and operation authorization, before
// resource I/O or disclosure. It receives only the selected native service's
// configured service-account client and tenant, never a request-selected actor
// or bearer material. It must honor ctx and retain no invocation or detached work.
// The root protocol owns redacted gate denials, remaining original authority and
// deadline enforcement, and the final disclosure fence, including cancellation
// or expiry during the gate. No quota engine, HTTP route or write is selected.
func (s *ManagedConnectionService) ExecuteManagedAdmittedRead(ctx context.Context, tenant identity.TenantID, request scim.Request, admit scim.ProtocolAdmission) (scim.Response, error) {
	if s == nil || ctx == nil || s.writer == nil || admit == nil {
		return scim.Response{}, scim.NewError(503, "")
	}
	if request.Operation != scim.UserGet && request.Operation != scim.UserList {
		return scim.Response{}, scim.NewError(501, "")
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
	return source.executeProtocol(ctx, request, func(ctx context.Context, request scim.Request) (scim.Response, error) {
		return source.protocol.ExecuteAdmittedRead(ctx, request, func(ctx context.Context) *scim.Error {
			configured := source.config()
			return admit(ctx, scim.ProtocolClient{ID: configured.ActorID, TenantID: configured.Scope.TenantID})
		})
	})
}

// ExecuteManagedAdmittedCreate selects only User Create for an issued managed
// bearer in the exact tenant. A nonnil synchronous admission gate is required;
// other operations return 501 and missing composition returns 503. Ordinary
// provisioning and admitted reads retain their existing behavior.
//
// The request and gate are borrowed only during this call. Existing root request
// and schema validation, current native bearer authentication and operation
// authorization precede the gate. It receives the exact configured native
// service-account client and tenant, never request-selected actor authority.
// The root owns once-per-attempt admission before mapping or command effects,
// redacted denials/retry metadata, original deadlines and disclosure fencing.
// Store-owned original commands, write authority and replay remain unchanged.
// The gate must honor ctx, retain no invocation/context and start no detached
// work. No limiter, HTTP route, other write or managed lifecycle is selected.
func (s *ManagedConnectionService) ExecuteManagedAdmittedCreate(ctx context.Context, tenant identity.TenantID, request scim.Request, admit scim.ProtocolAdmission) (scim.Response, error) {
	if s == nil || ctx == nil || s.writer == nil || admit == nil {
		return scim.Response{}, scim.NewError(503, "")
	}
	if request.Operation != scim.UserCreate {
		return scim.Response{}, scim.NewError(501, "")
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
	return source.executeProtocol(ctx, request, func(ctx context.Context, request scim.Request) (scim.Response, error) {
		return source.protocol.ExecuteAdmittedCreate(ctx, request, func(ctx context.Context) *scim.Error {
			configured := source.config()
			return admit(ctx, scim.ProtocolClient{ID: configured.ActorID, TenantID: configured.Scope.TenantID})
		})
	})
}
