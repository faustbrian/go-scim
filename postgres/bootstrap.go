package scimpostgres

import (
	"context"
	"errors"
	"time"

	identity "github.com/faustbrian/go-identity"
	kernel "github.com/faustbrian/go-identity/postgres"
	organization "github.com/faustbrian/go-organization"
	scim "github.com/faustbrian/go-scim"
	"github.com/jackc/pgx/v5"
)

// ConfiguredConnectionResult reports the sole coordinator's outcome, not a
// credential, connection lifecycle receipt or provisioning completion. Version
// is nonzero only for a durably committed original configured connection.
type ConfiguredConnectionResult struct {
	Outcome identity.CommitOutcome
	Version uint64
}

// InitializeConfiguredConnection installs exactly this trusted deployment's
// preprovisioned connection/credential through the existing command coordinator,
// actual organization authority, audit and outbox owners. Identical repeats use
// original request-key/command custody. Existing changed, revoked or deleted
// state fails closed: this method never rotates, updates or reactivates anything.
// This explicit bootstrap is not SCIM ConnectionService or its eight lifecycle
// operations. The existing service-principal policy epoch must already exist;
// bootstrap cannot invent a principal or reset its authority. No raw bearer is
// retained or returned. Earlier cancellation/deadlines and original <=20-second
// admission win; ambiguous commit remains unknown until the same call recovers.
func (s *Service) InitializeConfiguredConnection(ctx context.Context) (result ConfiguredConnectionResult, err error) {
	if s == nil || s.config == nil || ctx == nil {
		return result, ErrInvalidConfiguration
	}
	c := s.config()
	ctx, cancel := context.WithTimeout(ctx, c.MaximumDuration)
	defer cancel()
	defer func() {
		if recover() != nil {
			result = ConfiguredConnectionResult{}
			err = identity.UnavailableError{}
		}
		if ctx.Err() != nil && err == nil {
			result = ConfiguredConnectionResult{Outcome: identity.CommitOutcomeUnknown}
			err = ctx.Err()
		}
	}()
	start := time.Now().UTC()
	if !start.Before(c.CredentialExpiresAt) {
		return result, identity.ForbiddenError{}
	}
	directory, err := s.directory.GetDirectoryAuthority(ctx, c.directoryQuery())
	if err != nil || !directory.Enabled {
		return result, identity.ForbiddenError{}
	}
	if err := s.decide(ctx, connectionOperation().OperationID, c.Scope.ConnectionID, "identity.scim.connection"); err != nil {
		return result, err
	}
	observed, err := s.organizations.ObserveCredentialAuthority(ctx, organization.CredentialAuthorityQuery{TenantID: c.Scope.TenantID, OrganizationID: c.Scope.OrganizationID})
	if err != nil {
		return result, identity.ForbiddenError{}
	}
	authority, err := s.authority.Get(ctx, c.authorityScope())
	if err != nil {
		return result, identity.ForbiddenError{}
	}
	until := start.Add(20 * time.Second)
	if observed.ValidUntil.Before(until) {
		until = observed.ValidUntil
	}
	if c.CredentialExpiresAt.Before(until) {
		until = c.CredentialExpiresAt
	}
	i := invocation{connection: scim.Connection{Scope: c.Scope, CredentialID: c.Credential.id, Version: c.ConnectionVersion, ExpiresAt: c.CredentialExpiresAt, AuthorityReadBeganAt: start, AuthorityValidUntil: until}, organization: observed, epoch: authority.Version}
	i.directory = kernel.DirectoryAuthorityAdmission{Query: directory.Query, GlobalVersion: directory.GlobalVersion, TenantVersion: directory.TenantVersion}
	if !liveConnection(ctx, i.connection) {
		return result, identity.ForbiddenError{}
	}
	var version, epoch, organizationCredential, credential, state string
	var digest, profile []byte
	var expiry time.Time
	err = s.pool.Raw().QueryRow(ctx, `SELECT version::text,authority_version::text,organization_credential_version::text,credential_id,state,credential_digest,configuration_digest,expires_at FROM scim.connections WHERE tenant_id=$1 AND organization_id=$2 AND provider_id=$3 AND connection_id=$4`, scopeArgs(c.Scope)...).Scan(&version, &epoch, &organizationCredential, &credential, &state, &digest, &profile, &expiry)
	if err == nil && !s.matchConnection(version, epoch, organizationCredential, credential, state, digest, profile, expiry, i.epoch, i.organization.CredentialVersion) {
		return result, identity.ForbiddenError{}
	}
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return result, identity.UnavailableError{}
	}
	p := &nativePhase{service: s, bootstrap: true, admission: i}
	canonical := append([]byte("configured-connection-bootstrap-v1\x00"), s.profile[:]...)
	if err := p.resolveOriginal(ctx, "configured-bootstrap-v1", canonical); err != nil {
		return result, err
	}
	if err := p.initialize(ctx, canonical); err != nil {
		return result, err
	}
	receipt, err := p.execute(ctx)
	result.Outcome = receipt.Outcome
	if err == nil && receipt.Outcome == identity.CommitOutcomeCommitted {
		if err := s.recheckRead(ctx, &i); err != nil {
			return ConfiguredConnectionResult{Outcome: identity.CommitOutcomeUnknown}, err
		}
		result.Version = c.ConnectionVersion
	}
	return result, err
}
