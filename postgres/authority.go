package scimpostgres

import (
	"bytes"
	"context"
	"strconv"
	"time"

	identity "github.com/faustbrian/go-identity"
	kernel "github.com/faustbrian/go-identity/postgres"
	organization "github.com/faustbrian/go-organization"
)

func (s *Service) recheckRead(ctx context.Context, i *invocation) error {
	if i == nil || !liveConnection(ctx, i.connection) {
		return identity.ForbiddenError{}
	}
	c := s.config()
	directory, err := s.directory.GetDirectoryAuthority(ctx, c.directoryQuery())
	if err != nil || !directory.Enabled || directory.Query != i.directory.Query || directory.GlobalVersion != i.directory.GlobalVersion || directory.TenantVersion != i.directory.TenantVersion {
		return identity.ForbiddenError{}
	}
	observed, err := s.organizations.ObserveCredentialAuthority(ctx, organization.CredentialAuthorityQuery{TenantID: c.Scope.TenantID, OrganizationID: c.Scope.OrganizationID})
	if err != nil || observed.Version != i.organization.Version || observed.CredentialVersion != i.organization.CredentialVersion {
		return identity.ForbiddenError{}
	}
	authority, err := s.authority.Get(ctx, c.authorityScope())
	if err != nil || authority.Version != i.epoch {
		return identity.ForbiddenError{}
	}
	var version, epoch, organizationCredential, credential, state string
	var digest, profile []byte
	var expiry, now time.Time
	err = s.pool.Raw().QueryRow(ctx, `SELECT version::text,authority_version::text,organization_credential_version::text,credential_id,state,credential_digest,configuration_digest,expires_at,clock_timestamp() FROM scim.connections WHERE tenant_id=$1 AND organization_id=$2 AND provider_id=$3 AND connection_id=$4`, scopeArgs(c.Scope)...).Scan(&version, &epoch, &organizationCredential, &credential, &state, &digest, &profile, &expiry, &now)
	if err != nil || !s.matchConnection(version, epoch, organizationCredential, credential, state, digest, profile, expiry, i.epoch, i.organization.CredentialVersion) || !now.Before(i.connection.AuthorityValidUntil) || !now.Before(expiry) || !liveConnection(ctx, i.connection) {
		return identity.ForbiddenError{}
	}
	return nil
}

func (s *Service) matchConnection(version, epoch, organizationCredential, credential, state string, digest, profile []byte, expiry time.Time, expectedEpoch, expectedOrganizationCredential uint64) bool {
	c := s.config()
	return version == strconv.FormatUint(c.ConnectionVersion, 10) && epoch == strconv.FormatUint(expectedEpoch, 10) && organizationCredential == strconv.FormatUint(expectedOrganizationCredential, 10) && credential == c.Credential.id && state == "active" && bytes.Equal(digest, c.Credential.expected[:]) && bytes.Equal(profile, s.profile[:]) && expiry.Equal(c.CredentialExpiresAt)
}

func (p *nativePhase) requireConnection(ctx context.Context, w kernel.Work, original invocation) error {
	c := p.service.config()
	// This existing row owns create serialization: the following exact username
	// check must observe the preceding writer's commit under Work's READ COMMITTED
	// isolation. Get uses the separate unlocked current-authority read path.
	rows, err := w.Query(ctx, `SELECT version::text,authority_version::text,organization_credential_version::text,credential_id,state,credential_digest,configuration_digest,expires_at FROM scim.connections WHERE tenant_id=$1 AND organization_id=$2 AND provider_id=$3 AND connection_id=$4 FOR UPDATE`, scopeArgs(c.Scope)...)
	if err != nil {
		return identity.ForbiddenError{}
	}
	defer rows.Close()
	var version, epoch, organizationCredential, credential, state string
	var digest, profile []byte
	var expiry time.Time
	if !rows.Next() || rows.Scan(&version, &epoch, &organizationCredential, &credential, &state, &digest, &profile, &expiry) != nil || rows.Next() || rows.Err() != nil || !p.service.matchConnection(version, epoch, organizationCredential, credential, state, digest, profile, expiry, original.epoch, original.organization.CredentialVersion) {
		return identity.ForbiddenError{}
	}
	return nil
}
