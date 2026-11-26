package scimpostgres

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"maps"
	"slices"
	"time"

	auditpg "github.com/faustbrian/go-audit/postgres"
	authentication "github.com/faustbrian/go-authentication/v2"
	"github.com/faustbrian/go-authorization/v3"
	"github.com/faustbrian/go-clock"
	identity "github.com/faustbrian/go-identity"
	kernel "github.com/faustbrian/go-identity/postgres"
	sessionpg "github.com/faustbrian/go-identity/session/postgres"
	organization "github.com/faustbrian/go-organization"
	scim "github.com/faustbrian/go-scim"
	envelope "github.com/faustbrian/go-secret-envelope/v2"
	"github.com/faustbrian/go-secret-envelope/v2/adapters/keyring"
	lifecyclepg "github.com/faustbrian/go-transactional-outbox/postgres/identity"
)

// ManagedConnectionWriteConfig explicitly selects durable create for core User
// mappings and RemoveMembership. Provisioning supplies the trusted field
// profile and existing service principal, not a scope or existing credential.
// CredentialKey is dedicated to this deployment. The owner must retain it and
// the envelope keys while their original records remain in use.
type ManagedConnectionWriteConfig struct {
	SessionStorage     sessionpg.Config
	Provisioning       Config
	Keyring            *keyring.Provider
	CredentialKey      [32]byte
	CredentialLifetime time.Duration
}

func (ManagedConnectionWriteConfig) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("scimpostgres.ManagedConnectionWriteConfig(redacted)"))
}

func (ManagedConnectionWriteConfig) MarshalJSON() ([]byte, error) {
	return nil, ErrInvalidConfiguration
}

type managedConnectionWriter struct {
	config      ManagedConnectionWriteConfig
	crypto      *envelope.Service
	coordinator kernel.CoordinatorConfig
	keys        kernel.RequestKeyConfig
	directory   *kernel.Repository
}

func (s *ManagedConnectionService) configureWriter(c ManagedConnectionWriteConfig) error {
	p := &c.Provisioning
	if c.Keyring == nil || c.CredentialKey == ([32]byte{}) || c.CredentialLifetime < time.Second || c.CredentialLifetime > 365*24*time.Hour ||
		c.SessionStorage.Schema == "" || c.SessionStorage.MaximumDuration <= 0 || c.SessionStorage.MaximumDuration > s.config.MaximumDuration ||
		p.Scope != (scim.Scope{}) || p.Credential.lookup != nil || p.Credential.id != "" || p.Credential.expected != ([32]byte{}) || p.ConnectionVersion != 0 || !p.CredentialExpiresAt.IsZero() ||
		!boundedASCII(p.ConfigurationID, 1, 128) || !boundedASCII(p.PolicyID, 1, 128) || !boundedASCII(p.ActiveEnvelopeKeyID, 1, 256) || !boundedASCII(p.RequestKeys.Namespace, 1, 128) || p.UserNameField == "" || p.Limits != s.config.Limits {
		return ErrInvalidConfiguration
	}
	p.FieldSchema.Fields = slices.Clone(p.FieldSchema.Fields)
	for i := range p.FieldSchema.Fields {
		p.FieldSchema.Fields[i].Default.List = slices.Clone(p.FieldSchema.Fields[i].Default.List)
	}
	p.Coordinator.RetainedFingerprintKeys = maps.Clone(p.Coordinator.RetainedFingerprintKeys)
	crypto, err := envelope.NewService(c.Keyring)
	if err != nil {
		return ErrInvalidConfiguration
	}
	directory, err := kernel.NewRepository(s.pool, kernel.Config{MaximumDuration: s.config.MaximumDuration})
	if err != nil {
		return ErrInvalidConfiguration
	}
	query := kernel.CommandQueryPolicy{Authorization: s.config.Authorization, Clock: clock.System{}, PolicyVersion: s.config.PolicyVersion}
	coordinator := p.Coordinator
	coordinator.MaximumDuration, coordinator.AdmissionPolicy, coordinator.QueryPolicy = s.config.MaximumDuration, &query, &query
	keys := p.RequestKeys
	namespace := sha256.Sum256([]byte("scim-managed-admin-v1\x00" + keys.Namespace))
	keys.Namespace, keys.Policy = "scim-admin-"+base64.RawURLEncoding.EncodeToString(namespace[:]), query
	writer := &managedConnectionWriter{config: c, crypto: crypto, coordinator: coordinator, keys: keys, directory: directory}
	if _, err := writer.compose(s, &managedCreatePhase{}); err != nil {
		return ErrInvalidConfiguration
	}
	s.writer = func() *managedConnectionWriter { return writer }
	return nil
}

// ConnectionCreateRequest creates a new, canonical organization-owned scope.
// Authentication supplies the real administrator; IdempotencyKey correlates
// the exact original intent and does not confer permission.
type ConnectionCreateRequest struct {
	Authentication organization.Authentication
	OrganizationID organization.ID
	ProviderID     scim.ProviderID
	Mappings       scim.MappingSet
	IdempotencyKey identity.IdempotencyKey
}

// ConnectionCreateResult includes a bearer only in the original invocation
// that confirms its own commit. Safe retries return the original record alone.
type ConnectionCreateResult struct {
	Connection scim.ConnectionRecord
	Bearer     authentication.BearerCredential
}

// ConnectionCreate uses the existing kernel request-key and feature journal.
// It never retains bearer plaintext, repeats effects or reveals on recovery.
func (s *ManagedConnectionService) ConnectionCreate(ctx context.Context, request ConnectionCreateRequest) (ConnectionCreateResult, error) {
	if s == nil || s.writer == nil || ctx == nil {
		return ConnectionCreateResult{}, ErrInvalidConfiguration
	}
	if _, err := identity.ParseSubjectID(string(request.OrganizationID)); err != nil || !configuredID(string(request.ProviderID)) {
		return ConnectionCreateResult{}, identity.InvalidInputError{Field: "connection_scope"}
	}
	writer := s.writer()
	mappings, err := writer.encodeSelectedMappings(request.Mappings)
	if err != nil {
		return ConnectionCreateResult{}, err
	}
	ctx, cancel := context.WithTimeout(ctx, s.config.MaximumDuration)
	defer cancel()
	admin, err := s.authenticateManagedAdmin(ctx, request.Authentication)
	if err != nil {
		return ConnectionCreateResult{}, err
	}
	view, err := s.authorizeManagedAdmin(ctx, admin, request.OrganizationID, "org:scim-write")
	if err != nil {
		return ConnectionCreateResult{}, err
	}
	phase := &managedCreatePhase{service: s, writer: writer, request: request, admin: admin, view: view, mappings: mappings}
	coordinator, err := writer.compose(s, phase)
	if err != nil {
		return ConnectionCreateResult{}, identity.UnavailableError{}
	}
	intent, err := phase.intent()
	if err != nil {
		return ConnectionCreateResult{}, err
	}
	requestScope := kernel.RequestKeyScope{TenantID: admin.tenant, ActorID: identity.ActorID(admin.user), ActorKind: authorization.SubjectUser, Method: "POST", RouteID: managedCreateOperation().OperationID}
	caller := phase.caller("identity.request-admission", requestScope.RouteID)
	bound, wire, err := coordinator.ResolvePreparedRequestKey(ctx, requestScope, request.IdempotencyKey, intent, caller, phase.registration(), phase)
	defer clear(wire)
	if err != nil {
		if phase.preparationErr != nil {
			return ConnectionCreateResult{}, phase.preparationErr
		}
		return ConnectionCreateResult{}, err
	}
	input, err := phase.openInput(ctx, bound, wire)
	if err != nil {
		return ConnectionCreateResult{}, err
	}
	winner := phase.input.Scope.ProviderConnectionID != "" && phase.input.Scope == input.Scope && phase.input.Digest == input.Digest
	if !winner {
		phase.bearer = authentication.BearerCredential{}
		b := phase.binding(input)
		query := identity.RecoveryQuery{CommandID: b.CommandID, TenantID: b.TenantID, UserID: b.UserID, ActorID: b.ActorID, ActorKind: b.ActorKind, OperationID: b.OperationID, RecordID: b.RecordID}
		result, err := coordinator.RecoverPreparedFeatureCommand(ctx, query, phase.caller("identity.user", string(b.UserID)), phase.registration(), phase)
		if err != nil || result.Outcome != identity.CommitOutcomeCommitted {
			if err == nil {
				err = identity.UnknownCommitError{CommandID: input.CommandID}
			}
			return ConnectionCreateResult{}, err
		}
	} else {
		if err := phase.execute(ctx, coordinator, input); err != nil {
			return ConnectionCreateResult{}, err
		}
	}
	if err := s.recheckManagedAdmin(ctx, request.Authentication, admin, view, "org:scim-write"); err != nil {
		return ConnectionCreateResult{}, err
	}
	record, err := scim.NewConnectionRecord(input.Scope, request.Mappings, scim.RemoveMembership, 1)
	if err != nil {
		return ConnectionCreateResult{}, identity.UnavailableError{}
	}
	return ConnectionCreateResult{Connection: record, Bearer: phase.bearer}, nil
}

func (w *managedConnectionWriter) compose(s *ManagedConnectionService, p *managedCreatePhase) (*kernel.Coordinator, error) {
	audits, err := auditpg.NewIdentityContributor(auditpg.Config{})
	if err != nil {
		return nil, err
	}
	outbox, err := lifecyclepg.NewContributor()
	if err != nil {
		return nil, err
	}
	p.registry, err = kernel.NewContributorRegistry([]kernel.Contributor{w.directory, audits, outbox, p})
	if err != nil {
		return nil, err
	}
	return kernel.NewCoordinatorWithRequestKeys(s.pool, p.registry, w.coordinator, w.keys)
}

func (w *managedConnectionWriter) encodeSelectedMappings(mappings scim.MappingSet) ([]byte, error) {
	entries := mappings.Entries()
	if len(entries) < 1 || len(entries) > 2 {
		return nil, identity.InvalidInputError{Field: "mappings"}
	}
	wire := make([]managedMappingWire, 0, len(entries))
	var userName bool
	for _, entry := range entries {
		source := entry.Source.String()
		if !entry.Writable || (source != "userName" || entry.Target != w.config.Provisioning.UserNameField) && (source != "displayName" || entry.Target != w.config.Provisioning.DisplayNameField) {
			return nil, identity.InvalidInputError{Field: "mappings"}
		}
		userName = userName || source == "userName"
		wire = append(wire, managedMappingWire{Source: source, Target: entry.Target, Writable: true})
	}
	if !userName {
		return nil, identity.InvalidInputError{Field: "mappings"}
	}
	return json.Marshal(wire)
}
