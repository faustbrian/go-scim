package scimpostgres

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"time"

	authentication "github.com/faustbrian/go-authentication/v2"
	identity "github.com/faustbrian/go-identity"
	database "github.com/faustbrian/go-postgres"
	scim "github.com/faustbrian/go-scim"
)

func (w *managedConnectionWriter) provisionedService(pool *database.Pool, scope scim.ConnectionScope, credentialID identity.SubjectID, digest [32]byte, expiry time.Time, mappings scim.MappingSet) (*Service, error) {
	if w == nil || digest == ([32]byte{}) || !managedBearerInputsValid(scope, credentialID, w.config.CredentialKey) {
		return nil, ErrInvalidConfiguration
	}
	if _, err := w.encodeSelectedMappings(mappings); err != nil {
		return nil, err
	}
	c := w.config.Provisioning
	c.Scope = scim.Scope{
		TenantID: scope.TenantID, OrganizationID: scope.OrganizationID,
		ProviderID: string(scope.ProviderID), ConnectionID: string(scope.ProviderConnectionID),
	}
	c.ConnectionVersion = 1
	c.CredentialExpiresAt = expiry.UTC()
	// Managed mappings are the selected profile, not an overlay on the trusted
	// template. An omitted displayName must not retain the template's mapping.
	c.DisplayNameField = ""
	for _, entry := range mappings.Entries() {
		switch entry.Source.String() {
		case "userName":
			c.UserNameField = entry.Target
		case "displayName":
			c.DisplayNameField = entry.Target
		}
	}
	key := w.config.CredentialKey
	c.Credential = ConfiguredCredential{
		id: string(credentialID), expected: digest,
		lookup: func(candidate authentication.BearerCredential) ([32]byte, bool) {
			connection, credential, valid := parseManagedBearer(candidate)
			if !valid || connection != scope.ProviderConnectionID || credential != credentialID {
				return [32]byte{}, false
			}
			return managedBearerDigest(scope, credentialID, key, candidate), true
		},
	}
	return NewService(pool, c, w.config.Keyring)
}

const managedRemoveMembership = "remove-membership"

type managedProvisioning struct {
	mappings [32]byte
}

const managedProvisioningSQL = `SELECT m.organization_id,m.provider_id,m.mappings,m.deprovision_policy,c.version::text,c.credential_id,c.credential_digest,c.configuration_digest,c.expires_at,clock_timestamp()
 FROM scim.managed_connections m
 JOIN scim.connections c USING(tenant_id,organization_id,provider_id,connection_id)
 WHERE m.tenant_id=$1 AND m.connection_id=$2 AND c.credential_id=$3 AND c.state='active'`

func (s *ManagedConnectionService) loadManagedProvisioning(ctx context.Context, tenant identity.TenantID, bearer authentication.BearerCredential) (*Service, error) {
	if s == nil || ctx == nil {
		return nil, ErrInvalidConfiguration
	}
	connectionID, credentialID, valid := parseManagedBearer(bearer)
	if _, err := identity.ParseSubjectID(string(tenant)); err != nil || !valid || s.writer == nil {
		return nil, identity.ForbiddenError{}
	}
	ctx, cancel := context.WithTimeout(ctx, s.config.MaximumDuration)
	defer cancel()
	scope := scim.ConnectionScope{TenantID: tenant, ProviderConnectionID: connectionID}
	var mappingsWire, digestWire, profileWire []byte
	var version, storedCredential, policy string
	var expiry, now time.Time
	err := s.pool.Raw().QueryRow(ctx, managedProvisioningSQL, string(tenant), string(connectionID), string(credentialID)).Scan(
		&scope.OrganizationID, &scope.ProviderID, &mappingsWire, &policy, &version, &storedCredential, &digestWire, &profileWire, &expiry, &now,
	)
	if err != nil {
		return nil, managedConnectionReadError(ctx, err)
	}
	if version != "1" || policy != managedRemoveMembership || storedCredential != string(credentialID) || len(digestWire) != 32 || len(profileWire) != 32 || !now.Before(expiry) {
		return nil, identity.ForbiddenError{}
	}
	writer := s.writer()
	if writer == nil || !matchManagedBearer(scope, credentialID, writer.config.CredentialKey, bearer, [32]byte(digestWire)) {
		return nil, identity.ForbiddenError{}
	}
	mappings, err := decodeManagedMappings(mappingsWire, s.config.Limits)
	if err != nil {
		return nil, identity.ForbiddenError{}
	}
	service, err := writer.provisionedService(s.pool, scope, credentialID, [32]byte(digestWire), expiry, mappings)
	if err != nil {
		return nil, identity.ForbiddenError{}
	}
	if subtle.ConstantTimeCompare(service.profile[:], profileWire) != 1 {
		return nil, identity.ForbiddenError{}
	}
	service.managed = &managedProvisioning{mappings: sha256.Sum256(mappingsWire)}
	return service, nil
}
