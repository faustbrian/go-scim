package scimpostgres

import (
	"context"
	"fmt"

	scim "github.com/faustbrian/go-scim"
)

// GroupsService is an explicitly selected native Group projection profile. It
// borrows the configured Service's pool, key custody and authority owners, and
// owns no goroutines or shutdown work. It neither exposes Users nor reconciles
// identities, teams, roles or organization membership.
type GroupsService struct {
	native   *Service
	protocol *scim.GroupsService
}

// NewGroupsService selects Groups on an already configured native runtime.
// Install GroupsMigrationSource before calling Execute; construction performs
// no IO. maximumMembers is an explicit 0..scim.DefaultGroupMembers ceiling;
// zero admits only empty Groups. Resource and snapshot budgets remain those
// of the borrowed Service. Member existence is checked atomically at commit,
// not inferred from a URI or an organization membership.
func NewGroupsService(native *Service, maximumMembers int) (*GroupsService, error) {
	if native == nil || native.protocol == nil || native.config == nil {
		return nil, ErrInvalidConfiguration
	}
	c := native.config()
	bridge := &protocolBridge{service: native, groups: true}
	protocol, err := scim.NewGroupsService(scim.GroupsConfig{Store: bridge, Authenticator: bridge, Authorizer: bridge, Mapper: bridge, Limits: c.Limits, GroupMembers: maximumMembers, BaseURL: c.BaseURL, RequestTimeout: c.MaximumDuration})
	if err != nil {
		return nil, ErrInvalidConfiguration
	}
	return &GroupsService{native: native, protocol: protocol}, nil
}

// Execute supports only Groups CRUD/list/search and Group discovery, using the
// same bounded primary authority and original command journal as native Users.
// A nested Group is a typed directory reference, never traversed or fetched.
// Delete removes only this Group's projection; member resources are unchanged.
func (s *GroupsService) Execute(ctx context.Context, request scim.Request) (scim.Response, error) {
	if s == nil || s.native == nil || s.protocol == nil || ctx == nil {
		return scim.Response{}, scim.NewError(503, "")
	}
	if !nativeGroupOperation(request.Operation) {
		return scim.Response{}, scim.NewError(501, "")
	}
	return s.native.executeProtocol(ctx, request, s.protocol.Execute)
}

// Format redacts borrowed runtime composition for every formatting verb.
func (GroupsService) Format(state fmt.State, _ rune) {
	_, _ = state.Write([]byte("scimpostgres.GroupsService(redacted)"))
}

// MarshalJSON forbids accidental export of borrowed runtime custody.
func (GroupsService) MarshalJSON() ([]byte, error) { return nil, ErrInvalidConfiguration }

func groupOperation(op scim.Operation) bool {
	switch op {
	case scim.GroupCreate, scim.GroupGet, scim.GroupList, scim.GroupSearch, scim.GroupReplace, scim.GroupPatch, scim.GroupDelete:
		return true
	}
	return false
}

func nativeGroupOperation(op scim.Operation) bool {
	switch op {
	case scim.ServiceProviderConfig, scim.SchemasList, scim.SchemaGet, scim.ResourceTypesList, scim.ResourceTypeGet:
		return true
	}
	return groupOperation(op)
}

func nativeCreate(op scim.Operation) bool { return op == scim.UserCreate || op == scim.GroupCreate }
func nativeDelete(op scim.Operation) bool { return op == scim.UserDelete || op == scim.GroupDelete }
func nativePatch(op scim.Operation) bool  { return op == scim.UserPatch || op == scim.GroupPatch }

func (p *nativePhase) group() bool { return groupOperation(p.intent.Operation) }

func (b *protocolBridge) MapGroup(ctx context.Context, scope scim.Scope, resource scim.WritableResource) (scim.WritableResource, error) {
	invocation, err := currentInvocation(ctx)
	if err != nil || !b.groups || scope != invocation.connection.Scope || !liveConnection(ctx, invocation.connection) {
		return scim.WritableResource{}, scim.NewError(403, "")
	}
	// The root owns Group/member schema and immutable representation rules.
	// Native admission adds only exact typed existence, inside protected Work.
	return resource, nil
}

func (b *protocolBridge) PrepareGroup(ctx context.Context, intent scim.WriteIntent) (scim.PreparedWrite, error) {
	return b.Prepare(ctx, intent)
}
func (b *protocolBridge) CommitGroup(ctx context.Context, prepared scim.PreparedWrite, change scim.Change) (scim.WriteResult, error) {
	return b.Commit(ctx, prepared, change)
}
func (b *protocolBridge) AbortGroup(ctx context.Context, prepared scim.PreparedWrite) error {
	return b.Abort(ctx, prepared)
}
