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
	authentication "github.com/faustbrian/go-authentication/v2"
	"github.com/faustbrian/go-authorization/v3"
	identity "github.com/faustbrian/go-identity"
	kernel "github.com/faustbrian/go-identity/postgres"
	organization "github.com/faustbrian/go-organization"
	scim "github.com/faustbrian/go-scim"
	envelope "github.com/faustbrian/go-secret-envelope/v2"
)

const managedCreateSubject = "scim_connection"
const managedCreateAction = "identity.scim.connection-create"
const managedCreateMaximumInput = 16384

type managedCreateInput struct {
	CommandID  identity.CommandID
	Scope      scim.ConnectionScope
	Credential identity.SubjectID
	Digest     [32]byte
	Profile    [32]byte
	At, Expiry time.Time
	Authority  managedCreateAuthority
}

type managedCreatePhase struct {
	service        *ManagedConnectionService
	writer         *managedConnectionWriter
	request        ConnectionCreateRequest
	admin          managedAdmin
	view           organization.View
	mappings       []byte
	registry       *kernel.ContributorRegistry
	input          managedCreateInput
	source         *Service
	command        identity.Command
	effect         [32]byte
	bearer         authentication.BearerCredential
	preparationErr error
}

func (*managedCreatePhase) Descriptor() kernel.ContributorDescriptor {
	return kernel.ContributorDescriptor{Owner: "scim/postgres", ContractID: "identity.scim.managed", Version: 1}
}

func (*managedCreatePhase) FeatureOperations() []identity.FeatureOperation {
	return []identity.FeatureOperation{managedCreateOperation()}
}

func managedCreateOperation() identity.FeatureOperation {
	return identity.FeatureOperation{Owner: "scim", OperationID: managedCreateAction, SchemaID: "identity.scim.connection-create.managed-v1", SchemaVersion: 1, RecordRequirement: identity.FeatureRecordRequired}
}

func managedCreateLifecycle() kernel.LifecyclePlan {
	return kernel.LifecyclePlan{EventType: "identity.scim.connection_created.v1", AfterVersion: 1}
}

func (p *managedCreatePhase) registration() kernel.FeatureRegistration {
	return kernel.FeatureRegistration{Contributor: p.Descriptor(), Operation: managedCreateOperation()}
}

func (p *managedCreatePhase) caller(resourceType, target string) authorization.DecisionContext {
	return authorization.DecisionContext{PolicyRevision: authorization.Revision(p.service.config.PolicyVersion), Request: authorization.Request{
		Subject:     authorization.Subject{Kind: authorization.SubjectUser, ID: authorization.SubjectID(p.admin.user)},
		Action:      managedCreateAction,
		Resource:    authorization.Resource{Type: authorization.ResourceType(resourceType), ID: authorization.ResourceID(target)},
		Tenant:      authorization.TenantID(p.admin.tenant),
		Environment: authorization.Environment{Time: time.Now().UTC()},
	}}
}

func (p *managedCreatePhase) intent() (identity.RequestIntent, error) {
	mapping := sha256.Sum256(p.mappings)
	configuration := p.writer.config.Provisioning.ConfigurationID
	return identity.NewRequestIntent([]identity.FeatureField{
		{Name: "organization", Value: identity.FeatureValue{Kind: identity.FeatureText, Text: string(p.request.OrganizationID)}},
		{Name: "provider", Value: identity.FeatureValue{Kind: identity.FeatureText, Text: string(p.request.ProviderID)}},
		{Name: "mapping", Value: identity.FeatureValue{Kind: identity.FeatureBytes, Bytes: mapping[:]}},
		{Name: "configuration", Value: identity.FeatureValue{Kind: identity.FeatureText, Text: configuration}},
	})
}

func (p *managedCreatePhase) inputContext(b kernel.RequestKeyPreparationBinding) (envelope.Context, error) {
	if b.Namespace != p.writer.keys.Namespace || b.Feature != p.registration() || b.Scope.ActorID != identity.ActorID(p.admin.user) || b.Scope.ActorKind != authorization.SubjectUser || b.Scope.TenantID != p.admin.tenant || b.Scope.Method != "POST" || b.Scope.RouteID != managedCreateAction || b.PolicyVersion != p.service.config.PolicyVersion || b.IntentDigest == ([32]byte{}) || b.Admission.FingerprintKeyVersion == 0 {
		return envelope.Context{}, identity.ForbiddenError{}
	}
	if _, err := identity.ParseCommandID(string(b.Admission.CommandID)); err != nil {
		return envelope.Context{}, identity.ForbiddenError{}
	}
	// The owner binding deliberately has no JSON serialization. Frame its
	// validated values explicitly, not its unsupported reflection projection.
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
	return envelope.NewContext(map[string]string{"profile": "scim-managed-create-input-v1", "binding": base64.RawURLEncoding.EncodeToString(hash[:])})
}

func (p *managedCreatePhase) PrepareRequestKey(ctx context.Context, b kernel.RequestKeyPreparationBinding, _ identity.RequestIntent) (wire []byte, err error) {
	defer func() { p.preparationErr = err }()
	aad, err := p.inputContext(b)
	if err != nil {
		return nil, err
	}
	id, err := identity.NewSubjectID()
	if err != nil {
		return nil, identity.UnavailableError{}
	}
	credential, err := identity.NewSubjectID()
	if err != nil {
		return nil, identity.UnavailableError{}
	}
	scope := scim.ConnectionScope{TenantID: p.admin.tenant, OrganizationID: p.request.OrganizationID, ProviderID: p.request.ProviderID, ProviderConnectionID: scim.ConnectionID(id)}
	at := time.Now().UTC().Truncate(time.Microsecond)
	expiry := at.Add(p.writer.config.CredentialLifetime).Truncate(time.Microsecond)
	bearer, digest, err := issueManagedBearer(scope, credential, p.writer.config.CredentialKey)
	if err != nil {
		return nil, identity.UnavailableError{}
	}
	source, err := p.writer.provisionedService(p.service.pool, scope, credential, digest, expiry, p.request.Mappings)
	if err != nil {
		return nil, err
	}
	proof, err := captureManagedCreateAuthority(ctx, source, p.admin, p.view)
	if err != nil {
		return nil, err
	}
	input := managedCreateInput{CommandID: b.Admission.CommandID, Scope: scope, Credential: credential, Digest: digest, Profile: source.profile, At: at, Expiry: expiry, Authority: proof}
	plain, err := json.Marshal(input)
	if err != nil || len(plain) > managedCreateMaximumInput {
		return nil, identity.UnavailableError{}
	}
	defer clear(plain)
	sealed, err := p.writer.crypto.Encrypt(ctx, envelope.EncryptRequest{Plaintext: plain, KeyReference: p.writer.config.Provisioning.ActiveEnvelopeKeyID, Context: aad})
	if err != nil {
		return nil, identity.UnavailableError{}
	}
	wire, err = sealed.MarshalBinary()
	if err != nil || len(wire) > managedCreateMaximumInput+4096 {
		return nil, identity.UnavailableError{}
	}
	p.input, p.source, p.bearer = input, source, bearer
	return wire, nil
}

func (p *managedCreatePhase) openInput(ctx context.Context, b kernel.RequestKeyPreparationBinding, wire []byte) (managedCreateInput, error) {
	var input managedCreateInput
	aad, err := p.inputContext(b)
	if err != nil || len(wire) == 0 || len(wire) > managedCreateMaximumInput+4096 {
		return input, identity.UnavailableError{}
	}
	sealed, err := envelope.ParseEnvelope(wire)
	if err != nil {
		return input, identity.UnavailableError{}
	}
	plain, err := p.writer.crypto.Decrypt(ctx, envelope.DecryptRequest{Envelope: sealed, Context: aad})
	if err != nil {
		return input, identity.UnavailableError{}
	}
	defer clear(plain)
	if len(plain) > managedCreateMaximumInput || json.Unmarshal(plain, &input) != nil {
		return managedCreateInput{}, identity.UnavailableError{}
	}
	canonical, err := json.Marshal(input)
	defer clear(canonical)
	if err != nil || !bytes.Equal(plain, canonical) || input.CommandID != b.Admission.CommandID || input.Scope.TenantID != p.admin.tenant || input.Scope.OrganizationID != p.request.OrganizationID || input.Scope.ProviderID != p.request.ProviderID || !managedBearerInputsValid(input.Scope, input.Credential, p.writer.config.CredentialKey) || input.Digest == ([32]byte{}) || input.Profile == ([32]byte{}) || input.At.IsZero() || !input.Expiry.After(input.At) || !input.Authority.ValidUntil.After(input.At) {
		return managedCreateInput{}, identity.UnavailableError{}
	}
	return input, nil
}

func (p *managedCreatePhase) RestoreRequestKey(ctx context.Context, b kernel.RequestKeyPreparationBinding, wire []byte) (identity.CommandBinding, error) {
	input, err := p.openInput(ctx, b, wire)
	if err != nil {
		return identity.CommandBinding{}, err
	}
	return p.binding(input), nil
}

func (p *managedCreatePhase) binding(input managedCreateInput) identity.CommandBinding {
	op := managedCreateOperation()
	return identity.CommandBinding{CommandID: input.CommandID, TenantID: input.Scope.TenantID, UserID: p.admin.user, ActorID: identity.ActorID(p.admin.user), ActorKind: authorization.SubjectUser, OperationID: op.OperationID, SchemaID: op.SchemaID, SchemaVersion: op.SchemaVersion, PolicyID: p.writer.config.Provisioning.PolicyID, PolicyVersion: p.service.config.PolicyVersion, CorrelationID: string(input.CommandID), RecordID: string(input.Scope.ProviderConnectionID)}
}

func (p *managedCreatePhase) ValidateFeatureCommand(command identity.Command, plan kernel.CommandPlan) error {
	if command == (identity.Command{}) || command != p.command || plan.Feature == nil || *plan.Feature != p.registration() || plan.SubjectType != managedCreateSubject || plan.Lifecycle == nil || *plan.Lifecycle != managedCreateLifecycle() || len(plan.Audits) != 1 || plan.Audits[0].EventType != managedCreateAction || !plan.Audits[0].Required {
		return identity.ForbiddenError{}
	}
	return nil
}

func (p *managedCreatePhase) execute(ctx context.Context, coordinator *kernel.Coordinator, input managedCreateInput) error {
	if p.source == nil || p.source.profile != input.Profile || p.bearer.Token() == "" {
		return identity.UnavailableError{}
	}
	p.input = input
	b, op := p.binding(input), managedCreateOperation()
	frame, err := json.Marshal(input)
	if err != nil {
		return identity.UnavailableError{}
	}
	p.effect = sha256.Sum256(frame)
	clear(frame)
	p.command, err = identity.NewFeatureCommand(identity.FeatureCommandSpec{Binding: b, Operation: op, Fields: []identity.FeatureField{
		{Name: "scim.managed-original", Value: identity.FeatureValue{Kind: identity.FeatureBytes, Bytes: p.effect[:]}},
	}})
	if err != nil {
		return err
	}
	plan, err := p.plan(coordinator)
	if err != nil {
		return err
	}
	reservation, result, err := coordinator.ReserveCommand(ctx, b, p.command, plan)
	if err != nil {
		return err
	}
	if reservation == (kernel.Reservation{}) {
		p.bearer = authentication.BearerCredential{}
		if result.Outcome == identity.CommitOutcomeCommitted {
			return nil
		}
		return identity.UnknownCommitError{CommandID: b.CommandID}
	}
	work, err := coordinator.Begin(ctx, reservation)
	if err != nil {
		return err
	}
	defer func() { _, _ = coordinator.Abort(work, identity.UnavailableError{}) }()
	result, err = coordinator.ApplyFeature(ctx, work, p.command)
	if err != nil {
		_, err = coordinator.Abort(work, err)
		return err
	}
	result, err = coordinator.Commit(work, result)
	if err != nil {
		return err
	}
	if result.Outcome != identity.CommitOutcomeCommitted {
		return identity.UnknownCommitError{CommandID: b.CommandID}
	}
	return nil
}

func (p *managedCreatePhase) plan(coordinator *kernel.Coordinator) (kernel.CommandPlan, error) {
	b, op := p.binding(p.input), managedCreateOperation()
	lifecycle := managedCreateLifecycle()
	builder, err := audit.NewBuilder(audit.BuilderConfig{})
	if err != nil {
		return kernel.CommandPlan{}, identity.UnavailableError{}
	}
	record, err := builder.Build(audit.RecordInput{
		OccurredAt: p.input.At, Action: managedCreateAction, Outcome: audit.OutcomeSucceeded,
		Actor:      audit.ActorInput{Kind: audit.ActorHuman, ID: string(b.ActorID)},
		Subject:    audit.SubjectInput{Type: managedCreateSubject, ID: b.RecordID},
		Context:    audit.ContextInput{TenantID: string(b.TenantID), CorrelationID: b.CorrelationID},
		Policy:     audit.PolicyMetadata{PolicyID: b.PolicyID, Version: strconv.FormatUint(b.PolicyVersion, 10)},
		Changes:    audit.ChangeSetInput{Redacted: true},
		Attributes: map[string]string{"command.id": string(b.CommandID), "aggregate.type": managedCreateSubject, "aggregate.id": b.RecordID, "aggregate.before_version": "0", "aggregate.after_version": "1", "retention.class": "protected"},
	})
	if err != nil {
		return kernel.CommandPlan{}, err
	}
	digest, err := kernel.FeatureAuditBindingDigest(b, op, managedCreateSubject, record)
	if err != nil {
		return kernel.CommandPlan{}, err
	}
	registration := p.registration()
	return coordinator.PrepareCommandPlan(b, p.command, kernel.CommandPlan{
		Contributors: p.registry.Descriptors(), Feature: &registration, SubjectType: managedCreateSubject, Lifecycle: &lifecycle,
		Audits: []kernel.AuditPlan{{EventType: managedCreateAction, SchemaVersion: 1, Required: true, RequiredRecordCount: 1, MaxRecordBytes: 16384, MaxAggregateBytes: 16384, RetentionPolicyVersion: 1, RetentionClass: "protected", BindingDigest: digest}},
	})
}

const managedCreateBindingSQL = `INSERT INTO scim.connections(tenant_id,organization_id,provider_id,connection_id,credential_id,credential_digest,configuration_digest,version,state,expires_at,authority_version,organization_credential_version,command_id,effect_digest)
VALUES($1,$2,$3,$4,$5,$6,$7,1,'active',$8,$9::numeric,$10::numeric,$11,$12) ON CONFLICT DO NOTHING`

const managedCreateProjectionSQL = `INSERT INTO scim.managed_connections(tenant_id,organization_id,provider_id,connection_id,mappings,deprovision_policy)
VALUES($1,$2,$3,$4,$5,'remove-membership') ON CONFLICT DO NOTHING`

func (p *managedCreatePhase) ApplyFeature(ctx context.Context, work kernel.Work, command identity.Command) (identity.FeatureReceipt, error) {
	if err := work.RequireFeatureCommand(ctx, p, command); err != nil {
		return identity.FeatureReceipt{}, err
	}
	if err := p.CheckFeatureCommit(ctx, work, command); err != nil {
		return identity.FeatureReceipt{}, err
	}
	x := p.input
	keys := []any{string(x.Scope.TenantID), string(x.Scope.OrganizationID), string(x.Scope.ProviderID), string(x.Scope.ProviderConnectionID)}
	args := append(keys, string(x.Credential), x.Digest[:], x.Profile[:], x.Expiry, strconv.FormatUint(x.Authority.ProvisioningEpoch, 10), strconv.FormatUint(x.Authority.Organization.CredentialVersion, 10), string(x.CommandID), p.effect[:])
	count, err := work.Exec(ctx, managedCreateBindingSQL, args...)
	if err != nil {
		return identity.FeatureReceipt{}, identity.UnavailableError{}
	}
	if count != 1 {
		return identity.FeatureReceipt{}, identity.ConflictError{}
	}
	count, err = work.Exec(ctx, managedCreateProjectionSQL, append(keys, p.mappings)...)
	if err != nil {
		return identity.FeatureReceipt{}, identity.UnavailableError{}
	}
	if count != 1 {
		return identity.FeatureReceipt{}, identity.ConflictError{}
	}
	return identity.FeatureReceipt{Operation: managedCreateOperation(), AfterVersion: 1}, nil
}

func (p *managedCreatePhase) CheckFeatureCommit(ctx context.Context, work kernel.Work, command identity.Command) error {
	if command != p.command || p.source == nil {
		return identity.ForbiddenError{}
	}
	return requireManagedCreateAuthority(ctx, work, p, p.source, p.writer.config.SessionStorage, p.input.Authority, p.admin)
}

func (p *managedCreatePhase) RecoverParticipant(ctx context.Context, work kernel.RecoveryWork) (kernel.RecoveryStatus, error) {
	b, feature, lifecycle, err := work.FeatureScope(p)
	if err != nil || feature != p.registration() || lifecycle != managedCreateLifecycle() {
		return kernel.RecoveryUnknown, identity.ForbiddenError{}
	}
	rows, err := work.Query(ctx, `SELECT effect_digest FROM scim.connections WHERE command_id=$1`, string(b.CommandID))
	if err != nil {
		return kernel.RecoveryUnknown, err
	}
	defer rows.Close()
	if rows.Next() {
		return kernel.RecoveryUnknown, nil
	}
	if rows.Err() != nil {
		return kernel.RecoveryUnknown, identity.UnavailableError{}
	}
	return kernel.RecoveryNotCommitted, nil
}
