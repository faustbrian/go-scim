package scimpostgres

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"strconv"
	"time"

	"github.com/faustbrian/go-audit"
	auditpg "github.com/faustbrian/go-audit/postgres"
	authentication "github.com/faustbrian/go-authentication/v2"
	"github.com/faustbrian/go-authorization/v3"
	identity "github.com/faustbrian/go-identity"
	kernel "github.com/faustbrian/go-identity/postgres"
	organization "github.com/faustbrian/go-organization"
	scim "github.com/faustbrian/go-scim"
	envelope "github.com/faustbrian/go-secret-envelope/v2"
	lifecyclepg "github.com/faustbrian/go-transactional-outbox/postgres/identity"
)

const managedRotateAction = "identity.scim.connection-rotate"
const managedRotateMaximumInput = 16384

type managedRotateBinding struct {
	Credential                                       identity.SubjectID
	Digest, Profile                                  [32]byte
	Expiry                                           time.Time
	ProvisioningEpoch, OrganizationCredentialVersion uint64
	CommandID                                        identity.CommandID
	Effect                                           [32]byte
}

// Original custody contains only nonsecret expectations. Successor entropy is
// generated after the first kernel reservation and is never persisted here.
type managedRotateInput struct {
	CommandID       identity.CommandID
	Scope           scim.ConnectionScope
	ExpectedVersion uint64
	Previous        managedRotateBinding
	Credential      identity.SubjectID
	Mappings        []byte
	At, Expiry      time.Time
	Authority       managedCreateAuthority
}

type managedRotatePhase struct {
	service           *ManagedConnectionService
	writer            *managedConnectionWriter
	request           ConnectionRotatePreparationRequest
	admin             managedAdmin
	view              organization.View
	keys              kernel.RequestKeyConfig
	registry          *kernel.ContributorRegistry
	input             managedRotateInput
	command           identity.Command
	effect            [32]byte
	source, successor *Service
	bearer            authentication.BearerCredential
	applied           bool
	preparationErr    error
}

func (*managedRotatePhase) Descriptor() kernel.ContributorDescriptor {
	return kernel.ContributorDescriptor{Owner: "scim/postgres", ContractID: "identity.scim.managed-rotate", Version: 1}
}
func (*managedRotatePhase) FeatureOperations() []identity.FeatureOperation {
	return []identity.FeatureOperation{managedRotateOperation()}
}
func managedRotateOperation() identity.FeatureOperation {
	return identity.FeatureOperation{Owner: "scim", OperationID: managedRotateAction, SchemaID: managedRotateAction + ".managed-v1", SchemaVersion: 1, RecordRequirement: identity.FeatureRecordRequired}
}
func (p *managedRotatePhase) registration() kernel.FeatureRegistration {
	return kernel.FeatureRegistration{Contributor: p.Descriptor(), Operation: managedRotateOperation()}
}
func (p *managedRotatePhase) lifecycle() kernel.LifecyclePlan {
	return kernel.LifecyclePlan{EventType: "identity.scim.connection_rotated.v1", BeforeVersion: p.input.ExpectedVersion, AfterVersion: p.input.ExpectedVersion + 1}
}
func (p *managedRotatePhase) caller(resourceType, target string) authorization.DecisionContext {
	return authorization.DecisionContext{PolicyRevision: authorization.Revision(p.service.config.PolicyVersion), Request: authorization.Request{
		Subject: authorization.Subject{Kind: authorization.SubjectUser, ID: authorization.SubjectID(p.admin.user)}, Action: managedRotateAction,
		Resource: authorization.Resource{Type: authorization.ResourceType(resourceType), ID: authorization.ResourceID(target)}, Tenant: authorization.TenantID(p.admin.tenant), Environment: authorization.Environment{Time: time.Now().UTC()},
	}}
}

func (s *ManagedConnectionService) prepareManagedRotationCall(ctx context.Context, request ConnectionRotatePreparationRequest) (*managedRotatePhase, *kernel.Coordinator, kernel.RequestKeyScope, kernel.CanonicalRequestKey, identity.RequestIntent, error) {
	bad := func(err error) (*managedRotatePhase, *kernel.Coordinator, kernel.RequestKeyScope, kernel.CanonicalRequestKey, identity.RequestIntent, error) {
		return nil, nil, kernel.RequestKeyScope{}, kernel.CanonicalRequestKey{}, identity.RequestIntent{}, err
	}
	admin, view, err := s.managedRotationAdmin(ctx, request)
	if err != nil {
		return bad(err)
	}
	writer := s.writer()
	p := &managedRotatePhase{service: s, writer: writer, request: request, admin: admin, view: view, keys: writer.keys}
	namespace := sha256.Sum256([]byte("scim-managed-rotate-v1\x00" + p.keys.Namespace))
	p.keys.Namespace = "scim-rotate-" + base64.RawURLEncoding.EncodeToString(namespace[:])
	coordinator, err := p.compose()
	if err != nil {
		return bad(identity.UnavailableError{})
	}
	fields := []identity.FeatureField{
		{Name: "connection", Value: identity.FeatureValue{Kind: identity.FeatureText, Text: string(request.ConnectionID)}},
		{Name: "expected-version", Value: identity.FeatureValue{Kind: identity.FeatureUint64, Uint64: request.ExpectedVersion}},
		{Name: "configuration", Value: identity.FeatureValue{Kind: identity.FeatureText, Text: writer.config.Provisioning.ConfigurationID}},
	}
	intent, err := identity.NewRequestIntent(fields)
	if err != nil {
		return bad(err)
	}
	// The coordinator independently partitions tenant/real actor/method/route.
	// The protocol selector binds exactly the target and its original version.
	selectorWire, err := json.Marshal(struct {
		Connection scim.ConnectionID
		Version    uint64
	}{request.ConnectionID, request.ExpectedVersion})
	if err != nil {
		return bad(identity.UnavailableError{})
	}
	selector, err := kernel.NewCanonicalRequestKey(selectorWire)
	clear(selectorWire)
	if err != nil {
		return bad(err)
	}
	scope := kernel.RequestKeyScope{TenantID: admin.tenant, ActorID: identity.ActorID(admin.user), ActorKind: authorization.SubjectUser, Method: "POST", RouteID: managedRotateAction}
	return p, coordinator, scope, selector, intent, nil
}

func (p *managedRotatePhase) compose() (*kernel.Coordinator, error) {
	audits, err := auditpg.NewIdentityContributor(auditpg.Config{})
	if err != nil {
		return nil, err
	}
	outbox, err := lifecyclepg.NewContributor()
	if err != nil {
		return nil, err
	}
	p.registry, err = kernel.NewContributorRegistry([]kernel.Contributor{p.writer.directory, audits, outbox, p})
	if err != nil {
		return nil, err
	}
	coordinator := p.writer.coordinator
	// Native original authority is capped at 20 seconds by
	// requireManagedCreateAuthority. A rotation lease must outlive it: an
	// unknown reservation can never take over while that proof can mint a
	// bearer. Do not inherit a shorter provisioning lease for this profile.
	coordinator.LeaseDuration = time.Minute
	return kernel.NewCoordinatorWithCanonicalPostRequestKeys(p.service.pool, p.registry, coordinator, p.keys)
}

func (p *managedRotatePhase) inputContext(b kernel.RequestKeyPreparationBinding) (envelope.Context, error) {
	if b.Namespace != p.keys.Namespace || b.Feature != p.registration() || b.Scope.ActorID != identity.ActorID(p.admin.user) || b.Scope.ActorKind != authorization.SubjectUser || b.Scope.TenantID != p.admin.tenant || b.Scope.Method != "POST" || b.Scope.RouteID != managedRotateAction || b.PolicyVersion != p.service.config.PolicyVersion || b.IntentDigest == ([32]byte{}) || b.Admission.FingerprintKeyVersion == 0 {
		return envelope.Context{}, identity.ForbiddenError{}
	}
	if _, err := identity.ParseCommandID(string(b.Admission.CommandID)); err != nil {
		return envelope.Context{}, identity.ForbiddenError{}
	}
	frame, err := json.Marshal(struct {
		Namespace, Method, Route, Tenant, Actor, Command, Configuration string
		Policy                                                          uint64
		KeyVersion                                                      uint32
		Intent                                                          [32]byte
	}{b.Namespace, b.Scope.Method, b.Scope.RouteID, string(b.Scope.TenantID), string(b.Scope.ActorID), string(b.Admission.CommandID), p.writer.config.Provisioning.ConfigurationID, b.PolicyVersion, b.Admission.FingerprintKeyVersion, b.IntentDigest})
	if err != nil {
		return envelope.Context{}, identity.UnavailableError{}
	}
	hash := sha256.Sum256(frame)
	return envelope.NewContext(map[string]string{"profile": "scim-managed-rotate-input-v1", "binding": base64.RawURLEncoding.EncodeToString(hash[:])})
}

// The managed metadata join prevents enrolling a configured/static binding.
const managedRotatePreparationSQL = `SELECT m.provider_id,m.mappings,m.deprovision_policy,c.credential_id,c.credential_digest,c.configuration_digest,c.expires_at,c.authority_version::text,c.organization_credential_version::text,c.command_id,c.effect_digest
 FROM scim.managed_connections m JOIN scim.connections c USING(tenant_id,organization_id,provider_id,connection_id)
 WHERE m.tenant_id=$1 AND m.organization_id=$2 AND m.connection_id=$3 AND c.version=$4::numeric AND c.state='active'`

func (p *managedRotatePhase) PrepareRequestKey(ctx context.Context, b kernel.RequestKeyPreparationBinding, _ identity.RequestIntent) (wire []byte, err error) {
	defer func() { p.preparationErr = err }()
	aad, err := p.inputContext(b)
	if err != nil {
		return nil, err
	}
	x := managedRotateInput{CommandID: b.Admission.CommandID, Scope: scim.ConnectionScope{TenantID: p.admin.tenant, OrganizationID: p.view.Organization.ID, ProviderConnectionID: p.request.ConnectionID}, ExpectedVersion: p.request.ExpectedVersion}
	var digest, profile, effect []byte
	var policy, epoch, orgCredential string
	err = p.service.pool.Raw().QueryRow(ctx, managedRotatePreparationSQL, string(x.Scope.TenantID), string(x.Scope.OrganizationID), string(x.Scope.ProviderConnectionID), strconv.FormatUint(x.ExpectedVersion, 10)).Scan(&x.Scope.ProviderID, &x.Mappings, &policy, &x.Previous.Credential, &digest, &profile, &x.Previous.Expiry, &epoch, &orgCredential, &x.Previous.CommandID, &effect)
	if err != nil {
		return nil, managedConnectionReadError(ctx, err)
	}
	x.Previous.ProvisioningEpoch, err = strconv.ParseUint(epoch, 10, 64)
	if err != nil {
		return nil, identity.UnavailableError{}
	}
	x.Previous.OrganizationCredentialVersion, err = strconv.ParseUint(orgCredential, 10, 64)
	if err != nil || len(digest) != 32 || len(profile) != 32 || len(effect) != 32 || policy != managedRemoveMembership {
		return nil, identity.UnavailableError{}
	}
	x.Previous.Digest, x.Previous.Profile, x.Previous.Effect = [32]byte(digest), [32]byte(profile), [32]byte(effect)
	mappings, err := decodeManagedMappings(x.Mappings, p.service.config.Limits)
	if err != nil {
		return nil, identity.UnavailableError{}
	}
	source, err := p.writer.provisionedVersionService(p.service.pool, x.Scope, x.Previous.Credential, x.Previous.Digest, x.Previous.Expiry, mappings, x.ExpectedVersion)
	if err != nil || source.profile != x.Previous.Profile {
		return nil, identity.ForbiddenError{}
	}
	x.Authority, err = captureManagedCreateAuthority(ctx, source, p.admin, p.view)
	if err != nil {
		return nil, err
	}
	x.Credential, err = identity.NewSubjectID()
	if err != nil {
		return nil, identity.UnavailableError{}
	}
	x.At = time.Now().UTC().Truncate(time.Microsecond)
	x.Expiry = x.At.Add(p.writer.config.CredentialLifetime).Truncate(time.Microsecond)
	plain, err := json.Marshal(x)
	if err != nil || len(plain) > managedRotateMaximumInput {
		return nil, identity.UnavailableError{}
	}
	defer clear(plain)
	sealed, err := p.writer.crypto.Encrypt(ctx, envelope.EncryptRequest{Plaintext: plain, KeyReference: p.writer.config.Provisioning.ActiveEnvelopeKeyID, Context: aad})
	if err != nil {
		return nil, identity.UnavailableError{}
	}
	wire, err = sealed.MarshalBinary()
	if err != nil || len(wire) > managedRotateMaximumInput+4096 {
		return nil, identity.UnavailableError{}
	}
	return wire, nil
}

func (p *managedRotatePhase) openInput(ctx context.Context, b kernel.RequestKeyPreparationBinding, wire []byte) (managedRotateInput, error) {
	bad := func() (managedRotateInput, error) { return managedRotateInput{}, identity.UnavailableError{} }
	aad, err := p.inputContext(b)
	if err != nil || len(wire) == 0 || len(wire) > managedRotateMaximumInput+4096 {
		return bad()
	}
	sealed, err := envelope.ParseEnvelope(wire)
	if err != nil {
		return bad()
	}
	plain, err := p.writer.crypto.Decrypt(ctx, envelope.DecryptRequest{Envelope: sealed, Context: aad})
	if err != nil {
		return bad()
	}
	defer clear(plain)
	var x managedRotateInput
	if len(plain) > managedRotateMaximumInput || json.Unmarshal(plain, &x) != nil {
		return bad()
	}
	canonical, err := json.Marshal(x)
	defer clear(canonical)
	if err != nil || !bytes.Equal(plain, canonical) || x.CommandID != b.Admission.CommandID || x.Scope.TenantID != p.admin.tenant || x.Scope.OrganizationID != p.view.Organization.ID || x.Scope.ProviderConnectionID != p.request.ConnectionID || x.ExpectedVersion != p.request.ExpectedVersion || !managedBearerInputsValid(x.Scope, x.Credential, p.writer.config.CredentialKey) || !managedBearerInputsValid(x.Scope, x.Previous.Credential, p.writer.config.CredentialKey) || x.Credential == x.Previous.Credential || x.Previous.Digest == ([32]byte{}) || x.Previous.Profile == ([32]byte{}) || x.Previous.Effect == ([32]byte{}) || x.Previous.ProvisioningEpoch == 0 || x.Previous.OrganizationCredentialVersion == 0 || x.At.IsZero() || !x.Expiry.After(x.At) || !x.Authority.ValidUntil.After(x.At) {
		return bad()
	}
	if _, err := identity.ParseCommandID(string(x.Previous.CommandID)); err != nil {
		return bad()
	}
	return x, nil
}

func (p *managedRotatePhase) RestoreRequestKey(ctx context.Context, b kernel.RequestKeyPreparationBinding, wire []byte) (identity.CommandBinding, error) {
	x, err := p.openInput(ctx, b, wire)
	if err != nil {
		return identity.CommandBinding{}, err
	}
	return p.binding(x), nil
}
func (p *managedRotatePhase) binding(x managedRotateInput) identity.CommandBinding {
	op := managedRotateOperation()
	return identity.CommandBinding{CommandID: x.CommandID, TenantID: x.Scope.TenantID, UserID: p.admin.user, ActorID: identity.ActorID(p.admin.user), ActorKind: authorization.SubjectUser, OperationID: op.OperationID, SchemaID: op.SchemaID, SchemaVersion: op.SchemaVersion, PolicyID: p.writer.config.Provisioning.PolicyID, PolicyVersion: p.service.config.PolicyVersion, CorrelationID: string(x.CommandID), RecordID: string(x.Scope.ProviderConnectionID)}
}
func (p *managedRotatePhase) originalCommand(x managedRotateInput) (identity.Command, error) {
	frame, err := json.Marshal(x)
	if err != nil {
		return identity.Command{}, identity.UnavailableError{}
	}
	effect := sha256.Sum256(frame)
	clear(frame)
	return identity.NewFeatureCommand(identity.FeatureCommandSpec{Binding: p.binding(x), Operation: managedRotateOperation(), Fields: []identity.FeatureField{{Name: "scim.managed-rotate-original", Value: identity.FeatureValue{Kind: identity.FeatureBytes, Bytes: effect[:]}}}})
}
func (p *managedRotatePhase) acceptCommand(x managedRotateInput, command identity.Command) error {
	original, err := p.originalCommand(x)
	if err != nil {
		return err
	}
	wanted, _ := original.Feature()
	provided, ok := command.Feature()
	if !ok || provided.Binding != wanted.Binding || provided.Operation != wanted.Operation || len(provided.Fields) != 1 || provided.Fields[0].Name != wanted.Fields[0].Name || provided.Fields[0].Value.Kind != identity.FeatureBytes || !bytes.Equal(provided.Fields[0].Value.Bytes, wanted.Fields[0].Value.Bytes) {
		return identity.ConflictError{}
	}
	mappings, err := decodeManagedMappings(x.Mappings, p.service.config.Limits)
	if err != nil {
		return identity.UnavailableError{}
	}
	source, err := p.writer.provisionedVersionService(p.service.pool, x.Scope, x.Previous.Credential, x.Previous.Digest, x.Previous.Expiry, mappings, x.ExpectedVersion)
	if err != nil || source.profile != x.Previous.Profile {
		return identity.UnavailableError{}
	}
	p.input, p.command, p.source = x, command, source
	copy(p.effect[:], wanted.Fields[0].Value.Bytes)
	return nil
}

func (p *managedRotatePhase) ValidateFeatureCommand(command identity.Command, plan kernel.CommandPlan) error {
	if command == (identity.Command{}) || command != p.command || plan.Feature == nil || *plan.Feature != p.registration() || plan.SubjectType != managedCreateSubject || plan.Lifecycle == nil || *plan.Lifecycle != p.lifecycle() || len(plan.Audits) != 1 || plan.Audits[0].EventType != managedRotateAction || !plan.Audits[0].Required {
		return identity.ForbiddenError{}
	}
	return nil
}

func (p *managedRotatePhase) plan(coordinator *kernel.Coordinator) (kernel.CommandPlan, error) {
	b, op := p.binding(p.input), managedRotateOperation()
	builder, err := audit.NewBuilder(audit.BuilderConfig{})
	if err != nil {
		return kernel.CommandPlan{}, identity.UnavailableError{}
	}
	lifecycle := p.lifecycle()
	record, err := builder.Build(audit.RecordInput{OccurredAt: p.input.At, Action: managedRotateAction, Outcome: audit.OutcomeSucceeded,
		Actor: audit.ActorInput{Kind: audit.ActorHuman, ID: string(b.ActorID)}, Subject: audit.SubjectInput{Type: managedCreateSubject, ID: b.RecordID}, Context: audit.ContextInput{TenantID: string(b.TenantID), CorrelationID: b.CorrelationID},
		Policy: audit.PolicyMetadata{PolicyID: b.PolicyID, Version: strconv.FormatUint(b.PolicyVersion, 10)}, Changes: audit.ChangeSetInput{Redacted: true},
		Attributes: map[string]string{"command.id": string(b.CommandID), "aggregate.type": managedCreateSubject, "aggregate.id": b.RecordID, "aggregate.before_version": strconv.FormatUint(lifecycle.BeforeVersion, 10), "aggregate.after_version": strconv.FormatUint(lifecycle.AfterVersion, 10), "retention.class": "protected"},
	})
	if err != nil {
		return kernel.CommandPlan{}, err
	}
	digest, err := kernel.FeatureAuditBindingDigest(b, op, managedCreateSubject, record)
	if err != nil {
		return kernel.CommandPlan{}, err
	}
	registration := p.registration()
	return coordinator.PrepareCommandPlan(b, p.command, kernel.CommandPlan{Contributors: p.registry.Descriptors(), Feature: &registration, SubjectType: managedCreateSubject, Lifecycle: &lifecycle, Audits: []kernel.AuditPlan{{EventType: managedRotateAction, SchemaVersion: 1, Required: true, RequiredRecordCount: 1, MaxRecordBytes: 16384, MaxAggregateBytes: 16384, RetentionPolicyVersion: 1, RetentionClass: "protected", BindingDigest: digest}}})
}
