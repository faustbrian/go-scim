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

// ExecuteManagedAdmittedGroupRead selects only Group Get and List for an issued
// managed bearer in the exact tenant, using the existing native Groups store.
// maximumMembers is trusted deployment configuration, never request input: its
// explicit 0..scim.DefaultGroupMembers bound has NewGroupsService's semantics,
// including zero permitting only empty Groups. Invalid composition returns 503;
// other operations return 501. Existing managed selections are unchanged.
//
// The request and gate are borrowed synchronously. Current native bearer and
// operation authority precede the gate's one invocation, before Group Get or
// snapshot/projection. It receives only the configured service-account client
// and tenant, never a request-selected identity or bearer material. The root
// protocol owns original authority/deadlines, redacted denials/retry metadata,
// descendant-context reentry and final disclosure fences. The gate must honor
// ctx, retain no invocation/context and start no detached work. No quota owner,
// SQL, lifecycle, Group write/discovery/search selection or HTTP route is added.
func (s *ManagedConnectionService) ExecuteManagedAdmittedGroupRead(ctx context.Context, tenant identity.TenantID, request scim.Request, maximumMembers int, admit scim.ProtocolAdmission) (scim.Response, error) {
	if s == nil || ctx == nil || s.writer == nil || admit == nil {
		return scim.Response{}, scim.NewError(503, "")
	}
	if request.Operation != scim.GroupGet && request.Operation != scim.GroupList {
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
	groups, err := NewGroupsService(source, maximumMembers)
	if err != nil {
		return scim.Response{}, scim.NewError(503, "")
	}
	return source.executeProtocol(ctx, request, func(ctx context.Context, request scim.Request) (scim.Response, error) {
		return groups.protocol.ExecuteAdmittedRead(ctx, request, func(ctx context.Context) *scim.Error {
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

// ExecuteManagedAdmittedDelete selects only conditional User Delete for an
// issued managed bearer in the exact tenant. A nonnil synchronous admission
// gate is required; other operations return 501 and missing composition 503.
// Current native authority and existing root target/If-Match preflight precede
// the gate, which receives only the configured service-account client and tenant.
//
// The request and gate are borrowed for this call. The root owns once-per-attempt
// admission, original deadlines, redacted denials and late-result fencing. The
// gate must honor ctx, retain no invocation/context and start no detached work.
// Native precondition comparison, RemoveMembership withdrawal, tombstones and
// canonical headerless receipt replay retain their existing owners and authority.
// No limiter, SQL, lifecycle, HTTP route or caller-key behavior is introduced.
func (s *ManagedConnectionService) ExecuteManagedAdmittedDelete(ctx context.Context, tenant identity.TenantID, request scim.Request, admit scim.ProtocolAdmission) (scim.Response, error) {
	if s == nil || ctx == nil || s.writer == nil || admit == nil {
		return scim.Response{}, scim.NewError(503, "")
	}
	if request.Operation != scim.UserDelete {
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
		return source.protocol.ExecuteAdmittedDelete(ctx, request, func(ctx context.Context) *scim.Error {
			configured := source.config()
			return admit(ctx, scim.ProtocolClient{ID: configured.ActorID, TenantID: configured.Scope.TenantID})
		})
	})
}

// ExecuteManagedAdmittedPatch selects only conditional User Patch for the
// issued bearer and exact tenant. It requires a synchronous gate and rejects
// caller request keys. After current authority, bounded preflight and the gate,
// the native Store binds the canonical request to one original command.
// Atomic patching, CAS and recovery stay with the existing mutation owner.
// The gate receives the configured client and must honor its context without
// retaining the invocation or starting detached work.
func (s *ManagedConnectionService) ExecuteManagedAdmittedPatch(ctx context.Context, tenant identity.TenantID, request scim.Request, admit scim.ProtocolAdmission) (scim.Response, error) {
	if s == nil || ctx == nil || s.writer == nil || admit == nil {
		return scim.Response{}, scim.NewError(503, "")
	}
	if request.Operation != scim.UserPatch {
		return scim.Response{}, scim.NewError(501, "")
	}
	if request.IdempotencyKey != "" {
		return scim.Response{}, scim.NewError(400, "invalidValue")
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
		return source.protocol.ExecuteAdmittedPatch(ctx, request, func(ctx context.Context) *scim.Error {
			configured := source.config()
			return admit(ctx, scim.ProtocolClient{ID: configured.ActorID, TenantID: configured.Scope.TenantID})
		})
	})
}

// ExecuteManagedAdmittedReplace selects only conditional User Replace for the
// issued bearer and exact tenant. It requires a synchronous gate and rejects
// caller request keys. Current native authority, the bounded complete writable
// replacement and required strong If-Match precede the gate. The canonical
// scoped request then selects one original command with the existing Store;
// replacement semantics, CAS, atomic effects and replay retain their owners.
// The gate receives the configured client and must honor its original context
// without retaining the invocation or starting detached work. Ordinary managed
// provisioning and other operation selections remain unchanged.
func (s *ManagedConnectionService) ExecuteManagedAdmittedReplace(ctx context.Context, tenant identity.TenantID, request scim.Request, admit scim.ProtocolAdmission) (scim.Response, error) {
	if s == nil || ctx == nil || s.writer == nil || admit == nil {
		return scim.Response{}, scim.NewError(503, "")
	}
	if request.Operation != scim.UserReplace {
		return scim.Response{}, scim.NewError(501, "")
	}
	if request.IdempotencyKey != "" {
		return scim.Response{}, scim.NewError(400, "invalidValue")
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
		return source.protocol.ExecuteAdmittedReplace(ctx, request, func(ctx context.Context) *scim.Error {
			configured := source.config()
			return admit(ctx, scim.ProtocolClient{ID: configured.ActorID, TenantID: configured.Scope.TenantID})
		})
	})
}
