package scimpostgres

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"maps"
	"slices"
	"time"

	auditpg "github.com/faustbrian/go-audit/postgres"
	"github.com/faustbrian/go-authorization/v3"
	authoritypg "github.com/faustbrian/go-authorization/v3/postgres"
	"github.com/faustbrian/go-clock"
	identity "github.com/faustbrian/go-identity"
	kernel "github.com/faustbrian/go-identity/postgres"
	organizationpg "github.com/faustbrian/go-organization/postgres"
	database "github.com/faustbrian/go-postgres"
	scim "github.com/faustbrian/go-scim"
	envelope "github.com/faustbrian/go-secret-envelope/v2"
	"github.com/faustbrian/go-secret-envelope/v2/adapters/keyring"
	lifecyclepg "github.com/faustbrian/go-transactional-outbox/postgres/identity"
)

// Config is trusted immutable deployment composition, never request-decoded.
// The primary pool, immutable field processor and policy service remain borrowed
// and must support concurrent bounded calls. Fields must use exactly FieldSchema,
// PolicyVersion and the same Authorization policy selected here. Mapping selects
// only userName and optional displayName as nonsecret scalar native fields;
// externalId remains a nonunique SCIM correlation value, never account linking.
// ActorID is the preconfigured service principal, not the prospective user.
// Its existing AuthorityNamespace epoch must be provisioned through the real
// authorization owner. Bootstrap records that epoch and cannot reset it.
// ConfigurationID versions the stable borrowed field/policy callback semantics;
// change it when those semantics change. It is configuration identity, not a
// permission grant. Original profiles/keys must remain available for recovery.
// ConnectionVersion is exactly one in this create-only configured profile;
// snapshot import and connection lifecycle successors are not selected.
// GlobalAuthorityID selects the exact existing kernel deployment authority;
// missing/disabled tenant authority is never bootstrapped by this adapter.
type Config struct {
	Scope                           scim.Scope
	ConnectionVersion               uint64
	Credential                      ConfiguredCredential
	CredentialExpiresAt             time.Time
	ActorID                         identity.ActorID
	PolicyID                        string
	ConfigurationID                 string
	PolicyVersion                   uint64
	Authorization                   authorization.Service
	AuthorityNamespace              string
	GlobalAuthorityID               string
	Fields                          *identity.AttributeProcessor
	FieldSchema                     identity.AttributeSchema
	UserNameField, DisplayNameField string
	Coordinator                     kernel.CoordinatorConfig
	RequestKeys                     kernel.RequestKeyConfig
	IntentKey                       [32]byte
	ActiveEnvelopeKeyID             string
	Limits                          scim.Limits
	BaseURL                         string
	MaximumDuration                 time.Duration
}

// Format prevents nested secret keys, private defaults and credential digests
// from escaping through any formatting verb.
func (Config) Format(s fmt.State, _ rune) { _, _ = s.Write([]byte("scimpostgres.Config(redacted)")) }

// MarshalJSON rejects implicit persistence of trusted runtime composition.
func (Config) MarshalJSON() ([]byte, error) { return nil, ErrInvalidConfiguration }

// Service owns the selected protocol/native bridge, not the pool or a new
// journal. Each Execute owns its invocation state; no global registry, shared
// request map, worker or goroutine exists. Install all owner migrations before
// InitializeConfiguredConnection; construction performs no IO or callbacks.
type Service struct {
	pool          *database.Pool
	config        func() Config
	profile       [32]byte
	directory     *kernel.Repository
	domain        *kernel.SCIMUserCreationDomain
	organizations *organizationpg.Repository
	authority     *authoritypg.AuthorityStore
	crypto        *envelope.Service
	protocol      *scim.UsersService
}

// Format redacts all borrowed runtime and secret custody for every verb.
func (Service) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("scimpostgres.Service(redacted)"))
}

// MarshalJSON forbids implicit export of runtime composition.
func (Service) MarshalJSON() ([]byte, error) { return nil, ErrInvalidConfiguration }

// NewService validates and snapshots the bounded create/get profile without IO,
// migrations, policy callbacks or credential comparison. The local keyring
// protects original prepared input under the existing kernel request mapping.
// There is no adapter-owned connection lifecycle or caller-supplied domain store.
func NewService(pool *database.Pool, c Config, keys *keyring.Provider) (*Service, error) {
	bad := func() (*Service, error) { return nil, ErrInvalidConfiguration }
	if pool == nil || pool.Raw() == nil || keys == nil {
		return bad()
	}
	if c.Credential.lookup == nil || c.ConnectionVersion != 1 || c.Authorization == nil || c.PolicyVersion == 0 {
		return bad()
	}
	if c.Fields == nil || c.FieldSchema.Validate() != nil || c.IntentKey == ([32]byte{}) {
		return bad()
	}
	if c.MaximumDuration <= 0 || c.MaximumDuration > 5*time.Second {
		return bad()
	}
	if !boundedASCII(c.PolicyID, 1, 128) || !boundedASCII(c.ConfigurationID, 1, 128) || !boundedASCII(c.ActiveEnvelopeKeyID, 1, 256) {
		return bad()
	}
	if c.CredentialExpiresAt.IsZero() || c.CredentialExpiresAt.Year() < 1 || c.CredentialExpiresAt.Year() > 9999 {
		return bad()
	}
	if !c.CredentialExpiresAt.Equal(c.CredentialExpiresAt.Truncate(time.Microsecond)) {
		return bad()
	}
	for _, value := range []string{string(c.Scope.TenantID), string(c.Scope.OrganizationID), c.Scope.ProviderID, c.Scope.ConnectionID, string(c.ActorID)} {
		if !configuredID(value) {
			return bad()
		}
	}
	if !nativeAuditScopeID(string(c.Scope.TenantID)) || !nativeAuditScopeID(c.Scope.ConnectionID) {
		return bad()
	}
	if c.authorityScope().Validate() != nil || (kernel.DirectoryAuthorityQuery{GlobalAuthorityID: c.GlobalAuthorityID, TenantID: c.Scope.TenantID}).Validate() != nil || c.UserNameField == "" || c.UserNameField == c.DisplayNameField {
		return bad()
	}
	for _, name := range []string{c.UserNameField, c.DisplayNameField} {
		if name == "" {
			continue
		}
		found := false
		for _, f := range c.FieldSchema.Fields {
			if f.Name == name {
				writable := f.InputPermission == identity.FieldWrite || f.InputPermission == identity.FieldReadWrite
				found = f.Kind == identity.AttributeString && f.Cardinality == identity.CardinalityScalar && f.Sensitivity != identity.SensitivitySecret && writable
			}
		}
		if !found {
			return bad()
		}
	}
	c.FieldSchema.Fields = slices.Clone(c.FieldSchema.Fields)
	for i := range c.FieldSchema.Fields {
		c.FieldSchema.Fields[i].Default.List = slices.Clone(c.FieldSchema.Fields[i].Default.List)
	}
	c.Coordinator.RetainedFingerprintKeys = maps.Clone(c.Coordinator.RetainedFingerprintKeys)
	// One actual decision snapshot owns protocol, retry admission and receipt
	// disclosure. Do not compare injected interface instances or retain a second
	// independently configured authorization service through the coordinator.
	query := kernel.CommandQueryPolicy{Authorization: c.Authorization, Clock: clock.System{}, PolicyVersion: c.PolicyVersion}
	c.Coordinator.QueryPolicy = &query
	c.Coordinator.AdmissionPolicy = &query
	c.RequestKeys.Policy = query
	// The kernel lookup scope contains tenant/actor/route but no connection.
	// Domain-separate the configured namespace by the exact connection tuple,
	// preserving independent client-key custody across providers/connections.
	if !boundedASCII(c.RequestKeys.Namespace, 1, 128) {
		return bad()
	}
	namespaceFrame, err := json.Marshal(struct {
		Domain, Namespace string
		Scope             scim.Scope
	}{"scim-native-request-namespace-v1", c.RequestKeys.Namespace, c.Scope})
	if err != nil {
		return bad()
	}
	namespaceDigest := sha256.Sum256(namespaceFrame)
	clear(namespaceFrame)
	c.RequestKeys.Namespace = "scim-" + base64.RawURLEncoding.EncodeToString(namespaceDigest[:])
	c.Coordinator.MaximumDuration = c.MaximumDuration
	directory, err := kernel.NewRepository(pool, kernel.Config{MaximumDuration: c.MaximumDuration, AttributeSchemas: []identity.AttributeSchema{c.FieldSchema}})
	if err != nil {
		return bad()
	}
	domain, err := kernel.NewSCIMUserCreationDomain(directory)
	if err != nil {
		return bad()
	}
	organizations, err := organizationpg.NewRepository(pool, organizationpg.Config{MaximumDuration: c.MaximumDuration})
	if err != nil {
		return bad()
	}
	authority, err := authoritypg.NewAuthorityStore(pool.Raw(), c.MaximumDuration)
	if err != nil {
		return bad()
	}
	crypto, err := envelope.NewService(keys)
	if err != nil {
		return bad()
	}
	frame, err := json.Marshal(struct {
		Scope                                                  scim.Scope
		Version                                                uint64
		CredentialID                                           string
		CredentialDigest                                       [32]byte
		Expiry                                                 time.Time
		Actor                                                  identity.ActorID
		Policy, Configuration                                  string
		PolicyVersion                                          uint64
		Namespace, GlobalAuthority                             string
		Schema                                                 identity.AttributeSchema
		Username, Display, Comparison, RetryNamespace, BaseURL string
		Limits                                                 scim.Limits
	}{c.Scope, c.ConnectionVersion, c.Credential.id, c.Credential.expected, c.CredentialExpiresAt, c.ActorID, c.PolicyID, c.ConfigurationID, c.PolicyVersion, c.AuthorityNamespace, c.GlobalAuthorityID, c.FieldSchema, c.UserNameField, c.DisplayNameField, scim.UsernameComparisonProfile, c.RequestKeys.Namespace, c.BaseURL, c.Limits})
	if err != nil {
		return bad()
	}
	profile := sha256.Sum256(frame)
	clear(frame)
	s := &Service{pool: pool, config: func() Config { return c }, profile: profile, directory: directory, domain: domain, organizations: organizations, authority: authority, crypto: crypto}
	bridge := &protocolBridge{service: s}
	s.protocol, err = scim.NewUsersService(scim.Config{Store: bridge, Authenticator: bridge, Authorizer: bridge, Mapper: bridge, Limits: c.Limits, BaseURL: c.BaseURL, RequestTimeout: c.MaximumDuration})
	if err != nil {
		return bad()
	}
	if _, _, err := s.coordinator(&nativePhase{service: s}); err != nil {
		return bad()
	}
	return s, nil
}

// The pinned go-identity/postgres work_audit.go auditSafeID profile applies to
// the exact tenant context and connection subject. Reject unusable configured
// IDs before bootstrap rather than remapping those policy/audit identities.
func nativeAuditScopeID(value string) bool {
	if len(value) == 0 || len(value) > 64 {
		return false
	}
	for i := range len(value) {
		b := value[i]
		if !(b >= 'a' && b <= 'z' || b >= 'A' && b <= 'Z' || b >= '0' && b <= '9' || b == '-' || b == '_') {
			return false
		}
	}
	return true
}

func (c Config) authorityScope() authoritypg.AuthorityScope {
	return authoritypg.AuthorityScope{TenantID: authorization.TenantID(c.Scope.TenantID), PolicyNamespace: c.AuthorityNamespace, SubjectID: authorization.SubjectID(c.ActorID)}
}

func (s *Service) coordinator(p *nativePhase) (*kernel.Coordinator, *kernel.ContributorRegistry, error) {
	audits, err := auditpg.NewIdentityContributor(auditpg.Config{})
	if err != nil {
		return nil, nil, err
	}
	outbox, err := lifecyclepg.NewContributor()
	if err != nil {
		return nil, nil, err
	}
	registry, err := kernel.NewContributorRegistry([]kernel.Contributor{s.directory, audits, outbox, p})
	if err != nil {
		return nil, nil, err
	}
	c := s.config()
	coordinator, err := kernel.NewCoordinatorWithRequestKeys(s.pool, registry, c.Coordinator, c.RequestKeys)
	return coordinator, registry, err
}
