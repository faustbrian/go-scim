package scimpostgres

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"time"

	identity "github.com/faustbrian/go-identity"
	kernel "github.com/faustbrian/go-identity/postgres"
	organization "github.com/faustbrian/go-organization"
	scim "github.com/faustbrian/go-scim"
)

// This closed private projection is authenticated inside the existing request
// preparation. It retains exact original owner observations; it is not a new
// proof issuer, journal or permission decision. Current replay disclosure uses
// the separately authenticated current invocation, never these historical facts.
type admissionSnapshot struct {
	GlobalVersion, TenantVersion                                              uint64
	OrganizationVersion, OrganizationCredentialVersion                        uint64
	AuthorizationEpoch                                                        uint64
	ReadStartedAt, ValidUntil                                                 time.Time
	OrganizationReadStartedAt, OrganizationVerifiedAt, OrganizationValidUntil time.Time
}

func (c Config) directoryQuery() kernel.DirectoryAuthorityQuery {
	return kernel.DirectoryAuthorityQuery{GlobalAuthorityID: c.GlobalAuthorityID, TenantID: c.Scope.TenantID}
}

func (s *Service) captureAdmission(ctx context.Context, i invocation) (admissionSnapshot, error) {
	c := s.config()
	if !liveConnection(ctx, i.connection) || i.connection.Scope != c.Scope || i.directory.Query != c.directoryQuery() {
		return admissionSnapshot{}, identity.ForbiddenError{}
	}
	until := i.connection.AuthorityValidUntil
	// This is authoritative credential/issuer validity, not a transport
	// deadline. The current context still bounds this invocation, but cancelling
	// it cannot permanently tombstone a correlated command while its original
	// authority remains valid. Retain the exact source deadline unchanged.
	return admissionSnapshot{GlobalVersion: i.directory.GlobalVersion, TenantVersion: i.directory.TenantVersion, OrganizationVersion: i.organization.Version, OrganizationCredentialVersion: i.organization.CredentialVersion, AuthorizationEpoch: i.epoch, ReadStartedAt: i.connection.AuthorityReadBeganAt, ValidUntil: until, OrganizationReadStartedAt: i.organization.ReadStartedAt, OrganizationVerifiedAt: i.organization.VerifiedAt, OrganizationValidUntil: i.organization.ValidUntil}, nil
}

func (s *Service) restoreAdmission(a admissionSnapshot, at time.Time) (invocation, error) {
	c := s.config()
	if a.GlobalVersion == 0 || a.TenantVersion == 0 || a.AuthorizationEpoch == 0 || a.ReadStartedAt.IsZero() || !a.ValidUntil.After(a.ReadStartedAt) || a.ValidUntil.Sub(a.ReadStartedAt) > 20*time.Second || a.ValidUntil.After(c.CredentialExpiresAt) || at.Before(a.ReadStartedAt) || at.After(a.ValidUntil) {
		return invocation{}, identity.ForbiddenError{}
	}
	o := organization.CredentialAuthorityObservation{TenantID: c.Scope.TenantID, OrganizationID: c.Scope.OrganizationID, Version: a.OrganizationVersion, CredentialVersion: a.OrganizationCredentialVersion, ReadStartedAt: a.OrganizationReadStartedAt, VerifiedAt: a.OrganizationVerifiedAt, ValidUntil: a.OrganizationValidUntil}
	if o.Validate(organization.CredentialAuthorityQuery{TenantID: c.Scope.TenantID, OrganizationID: c.Scope.OrganizationID}, at) != nil || o.ReadStartedAt.Before(a.ReadStartedAt) || a.ValidUntil.After(o.ValidUntil) {
		return invocation{}, identity.ForbiddenError{}
	}
	connection := scim.Connection{Scope: c.Scope, CredentialID: c.Credential.id, Version: c.ConnectionVersion, ExpiresAt: c.CredentialExpiresAt, AuthorityReadBeganAt: a.ReadStartedAt, AuthorityValidUntil: a.ValidUntil}
	return invocation{connection: connection, organization: o, epoch: a.AuthorizationEpoch, directory: kernel.DirectoryAuthorityAdmission{Query: c.directoryQuery(), GlobalVersion: a.GlobalVersion, TenantVersion: a.TenantVersion}}, nil
}

func (a admissionSnapshot) commitment() ([32]byte, error) {
	wire, err := json.Marshal(a)
	if err != nil {
		return [32]byte{}, identity.UnavailableError{}
	}
	h := sha256.New()
	_, _ = h.Write([]byte("scim-native-original-admission-v1\x00"))
	_, _ = h.Write(wire)
	clear(wire)
	var digest [32]byte
	copy(digest[:], h.Sum(nil))
	return digest, nil
}
