package scimpostgres

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"strconv"
	"time"

	authentication "github.com/faustbrian/go-authentication/v2"
	"github.com/faustbrian/go-authorization/v3"
	identity "github.com/faustbrian/go-identity"
	kernel "github.com/faustbrian/go-identity/postgres"
	organization "github.com/faustbrian/go-organization"
	scim "github.com/faustbrian/go-scim"
	"github.com/jackc/pgx/v5"
)

type invocationKey struct{}

// This request-local slot is created only by Execute, never accepted from a
// caller. It retains actual typed primary observations across the root protocol
// callbacks; it is neither a positive cache nor a transferable proof. Execute
// and the synchronous protocol use it serially. No shared map or mutex exists.
type invocation struct {
	connection   scim.Connection
	organization organization.CredentialAuthorityObservation
	epoch        uint64
	directory    kernel.DirectoryAuthorityAdmission
	phase        *nativePhase
}

type protocolBridge struct {
	service *Service
	groups  bool
}

// Execute runs the configured native Users protocol; Groups and Bulk return 501.
// A supplied idempotency key selects scoped original replay. Headerless creates
// use ordinary server-owned commands without inventing client keys; DELETE
// always uses the existing kernel's canonical target/precondition custody.
// Credentials/body remain borrowed for this call;
// results are detached and all failures have stable redacted protocol errors.
func (s *Service) Execute(ctx context.Context, r scim.Request) (response scim.Response, err error) {
	if s == nil || s.protocol == nil || ctx == nil {
		return response, scim.NewError(503, "")
	}
	if !nativeOperation(r.Operation) {
		return response, scim.NewError(501, "")
	}
	return s.executeProtocol(ctx, r, s.protocol.Execute)
}

func (s *Service) executeProtocol(ctx context.Context, r scim.Request, execute func(context.Context, scim.Request) (scim.Response, error)) (response scim.Response, err error) {
	ctx, cancel := context.WithTimeout(ctx, s.config().MaximumDuration)
	defer cancel()
	defer func() {
		if recover() != nil {
			response = scim.Response{}
			err = scim.NewError(503, "")
		}
		if ctx.Err() != nil {
			response = scim.Response{}
			err = scim.NewError(503, "")
		}
	}()
	response, rootErr := execute(context.WithValue(ctx, invocationKey{}, new(invocation)), r)
	if rootErr != nil {
		var protocolError *scim.Error
		if errors.As(rootErr, &protocolError) && protocolError != nil {
			return scim.Response{}, protocolError
		}
		return scim.Response{}, scim.NewError(503, "")
	}
	return response, nil
}

func currentInvocation(ctx context.Context) (*invocation, error) {
	if ctx == nil || ctx.Err() != nil {
		return nil, identity.ForbiddenError{}
	}
	i, ok := ctx.Value(invocationKey{}).(*invocation)
	if !ok || i == nil {
		return nil, identity.ForbiddenError{}
	}
	return i, nil
}

func (b *protocolBridge) Authenticate(ctx context.Context, credential authentication.BearerCredential) (scim.Connection, error) {
	i, err := currentInvocation(ctx)
	if err != nil || b == nil || b.service == nil {
		return scim.Connection{}, identity.ForbiddenError{}
	}
	s, c := b.service, b.service.config()
	if !c.Credential.matches(credential) {
		return scim.Connection{}, identity.ForbiddenError{}
	}
	start := time.Now().UTC()
	directory, err := s.directory.GetDirectoryAuthority(ctx, c.directoryQuery())
	if err != nil || !directory.Enabled {
		return scim.Connection{}, identity.ForbiddenError{}
	}
	var digest, profile []byte
	var version, epoch, organizationCredential, credentialID, state string
	var expiry time.Time
	err = s.pool.Raw().QueryRow(ctx, `SELECT credential_id,credential_digest,configuration_digest,version::text,state,expires_at,authority_version::text,organization_credential_version::text FROM scim.connections WHERE tenant_id=$1 AND organization_id=$2 AND provider_id=$3 AND connection_id=$4`, scopeArgs(c.Scope)...).Scan(&credentialID, &digest, &profile, &version, &state, &expiry, &epoch, &organizationCredential)
	if err != nil || credentialID != c.Credential.id || version != strconv.FormatUint(c.ConnectionVersion, 10) || state != "active" || len(digest) != 32 || len(profile) != 32 || subtle.ConstantTimeCompare(digest, c.Credential.expected[:]) != 1 || subtle.ConstantTimeCompare(profile, s.profile[:]) != 1 || !expiry.Equal(c.CredentialExpiresAt) {
		return scim.Connection{}, identity.ForbiddenError{}
	}
	observed, err := s.organizations.ObserveCredentialAuthority(ctx, organization.CredentialAuthorityQuery{TenantID: c.Scope.TenantID, OrganizationID: c.Scope.OrganizationID})
	if err != nil || organizationCredential != strconv.FormatUint(observed.CredentialVersion, 10) {
		return scim.Connection{}, identity.ForbiddenError{}
	}
	authority, err := s.authority.Get(ctx, c.authorityScope())
	if err != nil || strconv.FormatUint(authority.Version, 10) != epoch {
		return scim.Connection{}, identity.ForbiddenError{}
	}
	until := start.Add(20 * time.Second)
	if observed.ValidUntil.Before(until) {
		until = observed.ValidUntil
	}
	if expiry.Before(until) {
		until = expiry
	}
	connection := scim.Connection{Scope: c.Scope, CredentialID: credentialID, Version: c.ConnectionVersion, ExpiresAt: expiry, AuthorityReadBeganAt: start, AuthorityValidUntil: until}
	if !liveConnection(ctx, connection) {
		return scim.Connection{}, identity.ForbiddenError{}
	}
	i.connection, i.organization, i.epoch = connection, observed, authority.Version
	i.directory = kernel.DirectoryAuthorityAdmission{Query: directory.Query, GlobalVersion: directory.GlobalVersion, TenantVersion: directory.TenantVersion}
	return connection, nil
}

func liveConnection(ctx context.Context, c scim.Connection) bool {
	now := time.Now().UTC()
	return ctx != nil && ctx.Err() == nil && c.Version > 0 && !c.AuthorityReadBeganAt.IsZero() && !now.Before(c.AuthorityReadBeganAt) && c.AuthorityValidUntil.After(c.AuthorityReadBeganAt) && !c.AuthorityValidUntil.After(c.AuthorityReadBeganAt.Add(20*time.Second)) && now.Before(c.AuthorityValidUntil) && now.Before(c.ExpiresAt)
}

func (s *Service) decide(ctx context.Context, operation, target, resourceType string) error {
	c := s.config()
	d := authorization.DecisionContext{PolicyRevision: authorization.Revision(c.PolicyVersion), Request: authorization.Request{Subject: authorization.Subject{Kind: authorization.SubjectServiceAccount, ID: authorization.SubjectID(c.ActorID)}, Action: authorization.Action(operation), Resource: authorization.Resource{Type: authorization.ResourceType(resourceType), ID: authorization.ResourceID(target)}, Tenant: authorization.TenantID(c.Scope.TenantID), Environment: authorization.Environment{Time: time.Now().UTC()}}}
	decision, err := c.Authorization.Decide(ctx, d)
	if err != nil || ctx.Err() != nil || decision.Outcome != authorization.Allow || decision.Revision != d.PolicyRevision {
		return identity.ForbiddenError{}
	}
	return nil
}

func (b *protocolBridge) Authorize(ctx context.Context, c scim.Connection, op scim.Operation, target string) error {
	i, err := currentInvocation(ctx)
	selected := nativeOperation(op)
	kind := "identity.scim.user"
	if b.groups {
		selected, kind = nativeGroupOperation(op), "identity.scim.group"
	}
	if err != nil || c != i.connection || !liveConnection(ctx, c) || !selected {
		return identity.ForbiddenError{}
	}
	return b.service.decide(ctx, string(op), target, kind)
}

func nativeOperation(op scim.Operation) bool {
	switch op {
	case scim.UserCreate, scim.UserGet, scim.UserReplace, scim.UserPatch, scim.UserDelete, scim.UserList, scim.UserSearch, scim.Search,
		scim.ServiceProviderConfig, scim.SchemasList, scim.SchemaGet, scim.ResourceTypesList, scim.ResourceTypeGet:
		return true
	default:
		return false
	}
}

func (b *protocolBridge) MapUser(ctx context.Context, scope scim.Scope, r scim.WritableResource) (scim.WritableResource, error) {
	i, err := currentInvocation(ctx)
	if err != nil || scope != i.connection.Scope || !liveConnection(ctx, i.connection) {
		return scim.WritableResource{}, identity.ForbiddenError{}
	}
	if len(r.Schemas) != 1 || r.Schemas[0] != "urn:ietf:params:scim:schemas:core:2.0:User" {
		return scim.WritableResource{}, scim.NewError(400, "invalidValue")
	}
	// The root protocol already owns complete core-User schema validation and
	// bounded complex/multivalue PATCH semantics. Only configured native scalar
	// mappings add this adapter's field bound. Other attributes remain SCIM
	// projection data: active is not global identity status, and emails/names
	// never create verified identifiers or organization membership.
	if _, err := mappedString(r.Attributes, "userName"); err != nil {
		return scim.WritableResource{}, scim.NewError(400, "invalidValue")
	}
	if b.service.config().DisplayNameField != "" {
		if _, err := mappedString(r.Attributes, "displayName"); err != nil {
			return scim.WritableResource{}, scim.NewError(400, "invalidValue")
		}
	}
	return r, nil
}

func scopeArgs(s scim.Scope) []any {
	return []any{string(s.TenantID), string(s.OrganizationID), s.ProviderID, s.ConnectionID}
}

func (b *protocolBridge) Get(ctx context.Context, scope scim.Scope, id string) (scim.Resource, error) {
	i, err := currentInvocation(ctx)
	if err != nil || scope != i.connection.Scope || !liveConnection(ctx, i.connection) {
		return scim.Resource{}, identity.ForbiddenError{}
	}
	if _, err := identity.ParseSubjectID(id); err != nil {
		return scim.Resource{}, scim.ErrNotFound
	}
	args := append(scopeArgs(scope), id)
	var wire []byte
	var user string
	err = b.service.pool.Raw().QueryRow(ctx, `SELECT resource,user_id FROM scim.users WHERE tenant_id=$1 AND organization_id=$2 AND provider_id=$3 AND connection_id=$4 AND resource_id=$5 AND deleted_at IS NULL AND octet_length(resource)<=131072`, args...).Scan(&wire, &user)
	if errors.Is(err, pgx.ErrNoRows) {
		return scim.Resource{}, scim.ErrNotFound
	}
	if err != nil || len(wire) > 131072 {
		return scim.Resource{}, identity.UnavailableError{}
	}
	var resource scim.Resource
	if json.Unmarshal(wire, &resource) != nil || resource.ID != id || user != id {
		return scim.Resource{}, identity.UnavailableError{}
	}
	// Projection presence is not kernel-user state or current organization/token
	// authority. Read the actual identity owner and recheck original admission
	// before disclosure. The deadline is never renewed by these reads.
	kernelUser, err := b.service.directory.Get(ctx, identity.GetUserQuery{TenantID: scope.TenantID, UserID: identity.UserID(user)})
	if err != nil || kernelUser.Status != identity.StatusActive || !liveConnection(ctx, i.connection) {
		return scim.Resource{}, identity.ForbiddenError{}
	}
	if err := b.service.recheckRead(ctx, i); err != nil {
		return scim.Resource{}, err
	}
	return resource, nil
}
