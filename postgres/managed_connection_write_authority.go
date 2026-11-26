package scimpostgres

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"time"

	"github.com/faustbrian/go-authorization/v3"
	authoritypg "github.com/faustbrian/go-authorization/v3/postgres"
	identity "github.com/faustbrian/go-identity"
	kernel "github.com/faustbrian/go-identity/postgres"
	"github.com/faustbrian/go-identity/session"
	sessionpg "github.com/faustbrian/go-identity/session/postgres"
	organization "github.com/faustbrian/go-organization"
	scim "github.com/faustbrian/go-scim"
)

// These closed projections are sealed as original command input. Native owner
// handles deliberately reject JSON; persist only their nonsecret expectations,
// never a session, bearer or newly minted validity witness.
type managedCreateAuthority struct {
	Scope              scim.Scope
	Profile            [32]byte
	ActorID            identity.UserID
	SessionFingerprint [32]byte
	Directory          managedCreateDirectoryAuthority
	Credential         managedCreateCredentialAuthority
	ActorPolicyVersion uint64
	Organization       organization.CredentialAuthorityObservation
	ProvisioningEpoch  uint64
	ReadStartedAt      time.Time
	SessionValidUntil  time.Time
	ValidUntil         time.Time
}

type managedCreateDirectoryAuthority struct {
	GlobalAuthorityID            string
	TenantID                     identity.TenantID
	GlobalVersion, TenantVersion uint64
}

type managedCreateCredentialAuthority struct {
	Reference                                                                    identity.CredentialRef
	UserAuthorityVersion, IdentifierAuthorityVersion, CredentialAuthorityVersion uint64
}

func captureManagedCreateAuthority(ctx context.Context, source *Service, admin managedAdmin, view organization.View) (managedCreateAuthority, error) {
	if ctx == nil || source == nil {
		return managedCreateAuthority{}, ErrInvalidConfiguration
	}
	start := time.Now().UTC()
	c := source.config()
	binding := identity.CommandBinding{TenantID: admin.tenant, UserID: admin.user, ActorID: identity.ActorID(admin.user), ActorKind: authorization.SubjectUser}
	directory, credential, policy, fingerprint, err := managedCreateSessionAuthority(source, admin, binding, start)
	if err != nil {
		return managedCreateAuthority{}, err
	}
	if c.Scope.TenantID != admin.tenant || view.Organization.ID != c.Scope.OrganizationID || view.Organization.TenantID != admin.tenant || !view.Organization.Active || !view.Actor.Active || (view.Actor.Role != organization.RoleOwner && view.Actor.Role != organization.RoleAdministrator) {
		return managedCreateAuthority{}, identity.ForbiddenError{}
	}
	currentDirectory, err := source.directory.GetDirectoryAuthority(ctx, directory.Query)
	if err != nil {
		return managedCreateAuthority{}, managedCreateAuthorityError(ctx, err)
	}
	if !currentDirectory.Enabled || currentDirectory.Query != directory.Query || currentDirectory.GlobalVersion != directory.GlobalVersion || currentDirectory.TenantVersion != directory.TenantVersion {
		return managedCreateAuthority{}, identity.ForbiddenError{}
	}
	query := organization.CredentialAuthorityQuery{TenantID: admin.tenant, OrganizationID: c.Scope.OrganizationID, ActorID: admin.user}
	observed, err := source.organizations.ObserveCredentialAuthority(ctx, query)
	if err != nil {
		return managedCreateAuthority{}, managedCreateAuthorityError(ctx, err)
	}
	if observed.Version != view.Organization.Version || observed.Actor != view.Actor {
		return managedCreateAuthority{}, identity.ForbiddenError{}
	}
	provisioning, err := source.authority.Get(ctx, c.authorityScope())
	if err != nil {
		return managedCreateAuthority{}, managedCreateAuthorityError(ctx, err)
	}
	until := admin.session.ValidUntil()
	if ceiling := start.Add(20 * time.Second); ceiling.Before(until) {
		until = ceiling
	}
	if observed.ValidUntil.Before(until) {
		until = observed.ValidUntil
	}
	now := time.Now().UTC()
	if ctx.Err() != nil {
		return managedCreateAuthority{}, ctx.Err()
	}
	if admin.session.ValidateAt(now) != nil || observed.Validate(query, now) != nil || provisioning.Version == 0 || !now.Before(until) {
		return managedCreateAuthority{}, identity.ForbiddenError{}
	}
	return managedCreateAuthority{
		Scope: c.Scope, Profile: source.profile, ActorID: admin.user, SessionFingerprint: fingerprint,
		Directory:          managedCreateDirectoryAuthority{directory.Query.GlobalAuthorityID, directory.Query.TenantID, directory.GlobalVersion, directory.TenantVersion},
		Credential:         managedCreateCredentialAuthority{credential.Credential, credential.UserAuthorityVersion, credential.IdentifierAuthorityVersion, credential.CredentialAuthorityVersion},
		ActorPolicyVersion: policy.Version, Organization: observed, ProvisioningEpoch: provisioning.Version,
		ReadStartedAt: start, SessionValidUntil: admin.session.ValidUntil(), ValidUntil: until,
	}, nil
}

func requireManagedCreateAuthority(ctx context.Context, w kernel.Work, owner kernel.FeatureExecutionContributor, source *Service, store sessionpg.Config, expected managedCreateAuthority, admin managedAdmin) error {
	if ctx == nil || source == nil || owner == nil {
		return ErrInvalidConfiguration
	}
	binding, _, _, err := w.FeatureScope(owner)
	if err != nil {
		return err
	}
	c := source.config()
	now, err := w.DatabaseTime(ctx)
	if err != nil {
		return err
	}
	if expected.Scope != c.Scope || c.Scope.TenantID != admin.tenant || expected.Profile != source.profile || expected.ActorID != admin.user || expected.ActorID == "" || expected.ProvisioningEpoch == 0 {
		return identity.ForbiddenError{}
	}
	if expected.ReadStartedAt.IsZero() || expected.ReadStartedAt.After(now) || !now.Before(expected.ValidUntil) {
		return identity.ForbiddenError{}
	}
	if expected.ValidUntil.After(expected.ReadStartedAt.Add(20*time.Second)) || expected.ValidUntil.After(expected.SessionValidUntil) || expected.ValidUntil.After(expected.Organization.ValidUntil) {
		return identity.ForbiddenError{}
	}
	directory, credential, policy, fingerprint, err := managedCreateSessionAuthority(source, admin, binding, now)
	if err != nil {
		return err
	}
	observedDirectory := managedCreateDirectoryAuthority{directory.Query.GlobalAuthorityID, directory.Query.TenantID, directory.GlobalVersion, directory.TenantVersion}
	observedCredential := managedCreateCredentialAuthority{credential.Credential, credential.UserAuthorityVersion, credential.IdentifierAuthorityVersion, credential.CredentialAuthorityVersion}
	query := organization.CredentialAuthorityQuery{TenantID: admin.tenant, OrganizationID: c.Scope.OrganizationID, ActorID: admin.user}
	if fingerprint != expected.SessionFingerprint || expected.Directory != observedDirectory || expected.Credential != observedCredential || expected.ActorPolicyVersion != policy.Version || expected.Organization.Validate(query, now) != nil || (expected.Organization.Actor.Role != organization.RoleOwner && expected.Organization.Actor.Role != organization.RoleAdministrator) {
		return identity.ForbiddenError{}
	}
	// Keep the native owners' existing lock order: directory, user/credential,
	// user policy, session/family, then organization/member/scoped policy.
	if err := w.RequireActiveDirectoryAuthority(ctx, owner, directory); err != nil {
		return err
	}
	if _, err := w.RequireActiveActorCredential(ctx, owner, credential); err != nil {
		return err
	}
	if err := w.RequireActiveActorAuthorization(ctx, owner, policy); err != nil {
		return err
	}
	// The current authenticated result can witness a retry only when its entire
	// session fingerprint matches the sealed original. Its newer acceptance
	// deadline never replaces expected.ValidUntil.
	if err := sessionpg.RequireSession(ctx, w, store, admin.session.Session); err != nil {
		return err
	}
	if err := source.organizations.RequireCredentialAuthority(ctx, w, owner, expected.Organization); err != nil {
		return err
	}
	if err := authoritypg.RequireAuthority(ctx, w, c.authorityScope(), expected.ProvisioningEpoch, c.MaximumDuration); err != nil {
		return managedCreateAuthorityError(ctx, err)
	}
	now, err = w.DatabaseTime(ctx)
	if err != nil {
		return err
	}
	if now.Before(expected.ReadStartedAt) || !now.Before(expected.ValidUntil) || admin.session.ValidateAt(now) != nil {
		return identity.ForbiddenError{}
	}
	return nil
}

func managedCreateSessionAuthority(source *Service, admin managedAdmin, binding identity.CommandBinding, now time.Time) (kernel.DirectoryAuthorityAdmission, kernel.CredentialAdmission, kernel.UserAuthorizationAdmission, [32]byte, error) {
	deny := func() (kernel.DirectoryAuthorityAdmission, kernel.CredentialAdmission, kernel.UserAuthorizationAdmission, [32]byte, error) {
		return kernel.DirectoryAuthorityAdmission{}, kernel.CredentialAdmission{}, kernel.UserAuthorizationAdmission{}, [32]byte{}, identity.ForbiddenError{}
	}
	if admin.session.ValidateAt(now) != nil {
		return deny()
	}
	spec, err := admin.session.Session.Bindings()
	if err != nil || spec != admin.spec || spec.TenantID != admin.tenant || spec.UserID != admin.user || binding.TenantID != admin.tenant || binding.UserID != admin.user || binding.ActorID != identity.ActorID(admin.user) || binding.ActorKind != authorization.SubjectUser {
		return deny()
	}
	c := source.config()
	// This selected write profile deliberately shares deployment/user-policy
	// namespace with provisioning. Other authentication profiles fail through
	// the session owner rather than silently dropping factor or organization.
	profile := sessionpg.IdentifierAdmissionConfig{GlobalAuthorityID: c.GlobalAuthorityID, PolicyNamespace: c.AuthorityNamespace, Audience: spec.Audience, AuthenticationMethod: "password", CredentialKind: identity.CredentialPassword, CredentialOwner: "identity/password"}
	directory, credential, policy, err := sessionpg.OriginalSessionAdmission(profile, admin.session.Session, binding)
	if err != nil {
		return deny()
	}
	fingerprint, err := managedCreateSessionFingerprint(admin.session.Session)
	if err != nil {
		return deny()
	}
	return directory, credential, policy, fingerprint, nil
}

func managedCreateSessionFingerprint(record session.Session) ([32]byte, error) {
	spec, err := record.Bindings()
	if err != nil {
		return [32]byte{}, err
	}
	remember, err := spec.Remember.Bindings()
	if err != nil {
		return [32]byte{}, err
	}
	vector, err := spec.Authority.Bindings()
	if err != nil {
		return [32]byte{}, err
	}
	csrf, _ := record.CSRFState().Bindings() // Zero is the supported tokenless bearer profile.
	continuation, continued := record.CredentialContinuation()
	encoded, err := json.Marshal(struct {
		SessionID, FamilyID      string
		TenantID                 identity.TenantID
		UserID                   identity.UserID
		Audience                 string
		Version, FamilyVersion   uint64
		Remember                 session.RememberPolicySpec
		Authority                session.AuthoritySnapshotSpec
		Lookup                   session.TokenDigest
		Authentication           session.AuthenticationMetadata
		IssuedAt, LastActivityAt time.Time
		CSRF                     session.CSRFStateSpec
		Continuation             session.CredentialContinuationSpec
		Continued                bool
	}{spec.SessionID, spec.FamilyID, spec.TenantID, spec.UserID, spec.Audience, spec.Version, spec.FamilyVersion, remember, vector, spec.Lookup, spec.Authentication, spec.IssuedAt, spec.LastActivityAt, csrf, continuation, continued})
	if err != nil {
		return [32]byte{}, err
	}
	defer clear(encoded)
	hash := sha256.New()
	_, _ = hash.Write([]byte("scim-managed-create-session-v1\x00"))
	_, _ = hash.Write(encoded)
	var fingerprint [32]byte
	copy(fingerprint[:], hash.Sum(nil))
	return fingerprint, nil
}

func managedCreateAuthorityError(ctx context.Context, err error) error {
	if ctx.Err() != nil {
		return ctx.Err()
	}
	if errors.Is(err, context.Canceled) {
		return context.Canceled
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return context.DeadlineExceeded
	}
	if errors.Is(err, organization.ErrForbidden) || errors.Is(err, authoritypg.ErrAuthorityDenied) {
		return identity.ForbiddenError{}
	}
	var denied identity.ForbiddenError
	if errors.As(err, &denied) {
		return identity.ForbiddenError{}
	}
	return identity.UnavailableError{}
}
