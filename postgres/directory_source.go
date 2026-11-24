package scimpostgres

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"time"

	"github.com/faustbrian/go-authorization/v3"
	authoritypg "github.com/faustbrian/go-authorization/v3/postgres"
	identity "github.com/faustbrian/go-identity"
	kernel "github.com/faustbrian/go-identity/postgres"
	organization "github.com/faustbrian/go-organization"
	scim "github.com/faustbrian/go-scim"
)

// DirectorySourceBindings is a detached, nonsecret projection of configured
// source identity and original freshness. It carries no credential, admission
// digest, synchronization grant, generation, Group delta or mapping policy.
// Editing it never changes the opaque observation or its validity.
type DirectorySourceBindings struct {
	Scope             scim.Scope
	ActorID           identity.ActorID
	ConnectionVersion uint64
	ReadStartedAt     time.Time
	ValidUntil        time.Time
}

// DirectorySourceObservation retains one configured source's original bounded
// owner observations. Only ObserveDirectorySource issues it; zero values deny.
// Copies share immutable service composition and retain the same deadline.
// It owns no resources and is safe to copy concurrently, but is not persistable
// or transferable to another configured Service. It grants no SSO permission.
type DirectorySourceObservation struct {
	source    *Service
	admission invocation
}

// Bindings returns only the original configured scope, service principal,
// connection version and freshness bounds. Missing, malformed or expired
// observations return zero and Forbidden. This performs no IO: current storage
// state must still be fenced through RequireDirectorySource in borrowed Work.
func (o DirectorySourceObservation) Bindings() (DirectorySourceBindings, error) {
	return o.bindings(context.Background())
}

// Field returns the exact scim.directory-source dependency commitment required
// in the original SSO child's feature command before reservation. It binds this
// configured scope/principal/version and every original authority epoch/time,
// not bearer material or a permission grant. The detached bytes must not be
// logged or exposed as a protocol response. Missing/expired evidence denies;
// copies retain the same commitment and do not renew its original deadline.
func (o DirectorySourceObservation) Field() (identity.FeatureField, error) {
	return o.field(context.Background())
}

func (o DirectorySourceObservation) field(ctx context.Context) (identity.FeatureField, error) {
	bindings, err := o.bindings(ctx)
	if err != nil {
		return identity.FeatureField{}, err
	}
	snapshot, err := o.source.captureAdmission(ctx, o.admission)
	if err != nil {
		return identity.FeatureField{}, err
	}
	wire, err := json.Marshal(struct {
		Bindings  DirectorySourceBindings
		Authority admissionSnapshot
	}{bindings, snapshot})
	if err != nil {
		return identity.FeatureField{}, identity.UnavailableError{}
	}
	defer clear(wire)
	h := sha256.New()
	_, _ = h.Write([]byte("scim-postgres/directory-source/v1\x00"))
	_, _ = h.Write(wire)
	return identity.FeatureField{Name: "scim.directory-source", Value: identity.FeatureValue{Kind: identity.FeatureBytes, Bytes: h.Sum(nil)}}, nil
}

func (o DirectorySourceObservation) requireCommandField(ctx context.Context, fields []identity.FeatureField) error {
	expected, err := o.field(ctx)
	if err != nil {
		return err
	}
	matches := 0
	for _, field := range fields {
		if field.Name != expected.Name {
			continue
		}
		if field.Value.Kind != identity.FeatureBytes || !bytes.Equal(field.Value.Bytes, expected.Value.Bytes) {
			return identity.ForbiddenError{}
		}
		matches++
	}
	if matches != 1 {
		return identity.ForbiddenError{}
	}
	return nil
}

func (o DirectorySourceObservation) bindings(ctx context.Context) (DirectorySourceBindings, error) {
	if o.source == nil || o.source.config == nil || !liveConnection(ctx, o.admission.connection) {
		return DirectorySourceBindings{}, identity.ForbiddenError{}
	}
	c, i := o.source.config(), o.admission
	if i.connection.Scope != c.Scope || i.connection.CredentialID != c.Credential.id || i.connection.Version != c.ConnectionVersion || !i.connection.ExpiresAt.Equal(c.CredentialExpiresAt) {
		return DirectorySourceBindings{}, identity.ForbiddenError{}
	}
	snapshot, err := o.source.captureAdmission(ctx, i)
	if err != nil {
		return DirectorySourceBindings{}, err
	}
	original, err := o.source.restoreAdmission(snapshot, time.Now().UTC())
	if err != nil || original.connection != i.connection || original.directory != i.directory || original.organization != i.organization {
		return DirectorySourceBindings{}, identity.ForbiddenError{}
	}
	return DirectorySourceBindings{Scope: c.Scope, ActorID: c.ActorID, ConnectionVersion: c.ConnectionVersion, ReadStartedAt: i.connection.AuthorityReadBeganAt, ValidUntil: i.connection.AuthorityValidUntil}, nil
}

// Format redacts retained owner observations and borrowed service composition.
func (DirectorySourceObservation) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("scimpostgres.DirectorySourceObservation(redacted)"))
}

// MarshalJSON forbids exporting source custody or reconstructing an observation.
func (DirectorySourceObservation) MarshalJSON() ([]byte, error) {
	return nil, ErrInvalidConfiguration
}

// ObserveDirectorySource is a trusted configured-runtime read for exactly this
// Service's already-installed connection. It is not a bearer-authentication or
// public connection-discovery endpoint. It reuses the genuine primary directory,
// organization, scoped authorization epoch and connection/configuration owners;
// absent, changed, disabled or expired state returns zero and Forbidden.
// Cancellation and MaximumDuration bound IO. The original <=20-second freshness
// starts before the first owner read and is never renewed by subsequent fences.
// SSO separately authorizes synchronization and owns its generation and delta.
func (s *GroupsService) ObserveDirectorySource(ctx context.Context, scope scim.Scope) (DirectorySourceObservation, error) {
	if s == nil || s.native == nil || s.protocol == nil || s.native.config == nil || ctx == nil || ctx.Err() != nil {
		return DirectorySourceObservation{}, identity.ForbiddenError{}
	}
	native, c := s.native, s.native.config()
	if scope != c.Scope {
		return DirectorySourceObservation{}, identity.ForbiddenError{}
	}
	ctx, cancel := context.WithTimeout(ctx, c.MaximumDuration)
	defer cancel()
	start := time.Now().UTC()
	directory, err := native.directory.GetDirectoryAuthority(ctx, c.directoryQuery())
	if err != nil || !directory.Enabled {
		return DirectorySourceObservation{}, identity.ForbiddenError{}
	}
	observed, err := native.organizations.ObserveCredentialAuthority(ctx, organization.CredentialAuthorityQuery{TenantID: scope.TenantID, OrganizationID: scope.OrganizationID})
	if err != nil {
		return DirectorySourceObservation{}, identity.ForbiddenError{}
	}
	authority, err := native.authority.Get(ctx, c.authorityScope())
	if err != nil {
		return DirectorySourceObservation{}, identity.ForbiddenError{}
	}
	until := start.Add(20 * time.Second)
	if observed.ValidUntil.Before(until) {
		until = observed.ValidUntil
	}
	if c.CredentialExpiresAt.Before(until) {
		until = c.CredentialExpiresAt
	}
	i := invocation{
		connection:   scim.Connection{Scope: scope, CredentialID: c.Credential.id, Version: c.ConnectionVersion, ExpiresAt: c.CredentialExpiresAt, AuthorityReadBeganAt: start, AuthorityValidUntil: until},
		organization: observed,
		epoch:        authority.Version,
		directory:    kernel.DirectoryAuthorityAdmission{Query: directory.Query, GlobalVersion: directory.GlobalVersion, TenantVersion: directory.TenantVersion},
	}
	if err := native.recheckRead(ctx, &i); err != nil {
		return DirectorySourceObservation{}, err
	}
	observation := DirectorySourceObservation{source: native, admission: i}
	if _, err := observation.bindings(ctx); err != nil {
		return DirectorySourceObservation{}, err
	}
	return observation, nil
}

// RequireDirectorySource fences configured source validity only during the exact
// registered SSO internal directory-sync child's synchronous Apply invocation.
// The original command and exact owner instance must match authenticated Work;
// reconstructed commands, foreign owners and unauthenticated Work deny.
// The command must contain exactly one unchanged observation.Field commitment.
// It borrows Work, acquiring the existing owner locks without creating a
// transaction, journal, permission decision or Group delta. The caller must
// propagate any failure, authorize synchronization independently, and call
// RequireDirectorySourceAtCommit in CheckFeatureCommit to cover late expiry.
func (s *GroupsService) RequireDirectorySource(ctx context.Context, w kernel.Work, owner kernel.FeatureExecutionContributor, command identity.Command, observation DirectorySourceObservation) error {
	if err := w.RequireFeatureCommand(ctx, owner, command); err != nil {
		return err
	}
	return s.requireDirectorySource(ctx, w, owner, command, observation, directoryGroupSourceRegistration())
}

// RequireDirectorySourceAtCommit rechecks the same original evidence and expiry
// in the exact owner's CheckFeatureCommit invocation. Live FeatureScope binds
// the original Work registration and command binding. The owner must additionally
// compare command with its retained original command before calling: Work's
// original-command custody check is deliberately Apply-only. This method cannot
// substitute for RequireDirectorySource during Apply or renew its evidence.
func (s *GroupsService) RequireDirectorySourceAtCommit(ctx context.Context, w kernel.Work, owner kernel.FeatureExecutionContributor, command identity.Command, observation DirectorySourceObservation) error {
	return s.requireDirectorySource(ctx, w, owner, command, observation, directoryGroupSourceRegistration())
}

func directoryGroupSourceRegistration() kernel.FeatureRegistration {
	return kernel.FeatureRegistration{
		Contributor: kernel.ContributorDescriptor{Owner: "sso/postgres", ContractID: "sso.directory-team-membership", Version: 1},
		Operation:   identity.FeatureOperation{Owner: "sso", OperationID: "identity.sso.directory-sync.apply-child", SchemaID: "sso.directory-team-membership", SchemaVersion: 1, RecordRequirement: identity.FeatureRecordRequired, SubjectRequirement: identity.FeatureSubjectUser, VersionPolicy: identity.FeatureVersionSequential},
	}
}

func (s *GroupsService) requireDirectorySource(ctx context.Context, w kernel.Work, owner kernel.FeatureExecutionContributor, command identity.Command, observation DirectorySourceObservation, expected kernel.FeatureRegistration) error {
	if s == nil || s.native == nil || s.native.config == nil || ctx == nil || observation.source != s.native {
		return identity.ForbiddenError{}
	}
	binding, registration, _, err := w.FeatureScope(owner)
	if err != nil {
		return identity.ForbiddenError{}
	}
	spec, ok := command.Feature()
	if !ok || spec.Binding != binding || spec.Operation != registration.Operation || registration != expected {
		return identity.ForbiddenError{}
	}
	bindings, err := observation.bindings(ctx)
	if err != nil || binding.TenantID != bindings.Scope.TenantID || binding.ActorKind != authorization.SubjectServiceAccount || binding.ActorID != bindings.ActorID {
		return identity.ForbiddenError{}
	}
	if err := observation.requireCommandField(ctx, spec.Fields); err != nil {
		return err
	}
	native, c := s.native, s.native.config()
	ctx, cancel := context.WithTimeout(ctx, c.MaximumDuration)
	defer cancel()
	original := observation.admission
	if err := w.RequireActiveDirectoryAuthority(ctx, owner, original.directory); err != nil {
		return err
	}
	if err := native.organizations.RequireCredentialAuthority(ctx, w, owner, original.organization); err != nil {
		return err
	}
	if err := authoritypg.RequireAuthority(ctx, w, c.authorityScope(), original.epoch, c.MaximumDuration); err != nil {
		return identity.ForbiddenError{}
	}
	if err := (&nativePhase{service: native}).requireConnection(ctx, w, original); err != nil {
		return err
	}
	now, err := w.DatabaseTime(ctx)
	if err != nil || !now.Before(bindings.ValidUntil) || !now.Before(c.CredentialExpiresAt) || !liveConnection(ctx, original.connection) {
		return identity.ForbiddenError{}
	}
	return nil
}
