package scimpostgres

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"strconv"

	"github.com/faustbrian/go-audit"
	"github.com/faustbrian/go-authorization/v3"
	authoritypg "github.com/faustbrian/go-authorization/v3/postgres"
	identity "github.com/faustbrian/go-identity"
	kernel "github.com/faustbrian/go-identity/postgres"
	scim "github.com/faustbrian/go-scim"
)

type nativePhase struct {
	service     *Service
	bootstrap   bool
	admission   invocation
	original    originalInput
	coordinator *kernel.Coordinator
	registry    *kernel.ContributorRegistry
	command     identity.Command
	creation    identity.CreateUserCommand
	resource    scim.Resource
	effect      [32]byte
	intent      scim.WriteIntent
}

func (*nativePhase) Descriptor() kernel.ContributorDescriptor {
	return kernel.ContributorDescriptor{Owner: "scim/postgres", ContractID: "identity.scim", Version: 1}
}
func (*nativePhase) FeatureOperations() []identity.FeatureOperation {
	return []identity.FeatureOperation{userOperation(), connectionOperation()}
}
func userOperation() identity.FeatureOperation {
	return identity.FeatureOperation{Owner: "scim", OperationID: string(scim.UserCreate), SchemaID: "identity.scim.user-create.native-v1", SchemaVersion: 1, RecordRequirement: identity.FeatureRecordRequired}
}
func connectionOperation() identity.FeatureOperation {
	return identity.FeatureOperation{Owner: "scim", OperationID: "identity.scim.connection-create", SchemaID: "identity.scim.connection-create.configured-v1", SchemaVersion: 1, RecordRequirement: identity.FeatureRecordRequired}
}
func (p *nativePhase) operation() identity.FeatureOperation {
	if p.bootstrap {
		return connectionOperation()
	}
	return userOperation()
}
func (p *nativePhase) registration() kernel.FeatureRegistration {
	return kernel.FeatureRegistration{Contributor: p.Descriptor(), Operation: p.operation()}
}
func (p *nativePhase) subjectType() string {
	if p.bootstrap {
		return "scim_connection"
	}
	return "scim_user"
}
func (p *nativePhase) eventType() string {
	if p.bootstrap {
		return "identity.scim.connection_created.v1"
	}
	return "identity.scim.user_created.v1"
}

func (p *nativePhase) initialize(ctx context.Context, canonical []byte) error {
	c, op := p.service.config(), p.operation()
	id := p.original.ID
	if p.bootstrap {
		id = string(c.ActorID)
	}
	record := p.original.ID
	if p.bootstrap {
		record = c.Scope.ConnectionID
	}
	b := identity.CommandBinding{CommandID: p.original.Command, TenantID: c.Scope.TenantID, UserID: identity.UserID(id), ActorID: c.ActorID, ActorKind: authorization.SubjectServiceAccount, OperationID: op.OperationID, PolicyID: c.PolicyID, PolicyVersion: c.PolicyVersion, SchemaID: op.SchemaID, SchemaVersion: 1, CorrelationID: string(p.original.Command), RecordID: record}
	intent, err := p.service.requestIntent(canonical, op.OperationID)
	if err != nil {
		return err
	}
	fields, _ := intent.Fields()
	admissionDigest, err := p.original.Admission.commitment()
	if err != nil {
		return err
	}
	fields = append(fields, identity.FeatureField{Name: "scim.admission", Value: identity.FeatureValue{Kind: identity.FeatureBytes, Bytes: admissionDigest[:]}})
	if !p.bootstrap {
		creationBinding := b
		creationBinding.OperationID = "identity.user.create"
		creationBinding.SchemaID = c.FieldSchema.ID
		creationBinding.SchemaVersion = c.FieldSchema.Version
		creationBinding.RecordID = ""
		updates := []identity.AttributeUpdate{{Name: c.UserNameField, Value: identity.AttributeValue{Kind: identity.AttributeString, Scalar: identity.AttributeScalar{Kind: identity.AttributeString, String: p.resource.Attributes["userName"].(string)}}}}
		if value, ok := p.resource.Attributes["displayName"].(string); ok {
			updates = append(updates, identity.AttributeUpdate{Name: c.DisplayNameField, Value: identity.AttributeValue{Kind: identity.AttributeString, Scalar: identity.AttributeScalar{Kind: identity.AttributeString, String: value}}})
		}
		prepared, err := c.Fields.Prepare(ctx, identity.AttributePrepareRequest{TenantID: b.TenantID, UserID: b.UserID, SchemaVersion: c.FieldSchema.Version, Updates: updates, Context: p.service.caller("identity.user.create", id, "identity.user")})
		if err != nil {
			return err
		}
		p.creation = identity.CreateUserCommand{Binding: creationBinding, Status: identity.StatusActive, Attributes: prepared}
		creationFields, err := kernel.SCIMUserCreationFields(p.creation)
		if err != nil {
			return err
		}
		fields = append(fields, creationFields...)
		fields = append(fields,
			identity.FeatureField{Name: "scim.resource.version", Value: identity.FeatureValue{Kind: identity.FeatureText, Text: string(p.original.Version)}},
			identity.FeatureField{Name: "scim.resource.created-at", Value: identity.FeatureValue{Kind: identity.FeatureTime, Time: p.original.At}},
		)
	}
	p.command, err = identity.NewFeatureCommand(identity.FeatureCommandSpec{Binding: b, Operation: op, Fields: fields})
	if err != nil {
		return err
	}
	spec, _ := p.command.Feature()
	frame, err := json.Marshal(spec)
	if err != nil {
		return identity.UnavailableError{}
	}
	p.effect = sha256.Sum256(frame)
	clear(frame)
	return nil
}

func (p *nativePhase) ValidateFeatureCommand(command identity.Command, plan kernel.CommandPlan) error {
	if p == nil || p.service == nil || command != p.command || command == (identity.Command{}) || plan.Feature == nil || *plan.Feature != p.registration() || plan.SubjectType != p.subjectType() || plan.Lifecycle == nil || *plan.Lifecycle != (kernel.LifecyclePlan{EventType: p.eventType(), AfterVersion: 1}) || len(plan.Audits) != 1 || plan.Audits[0].EventType != p.operation().OperationID {
		return identity.InvalidInputError{Field: "scim_command"}
	}
	return nil
}

func (p *nativePhase) ApplyFeature(ctx context.Context, w kernel.Work, command identity.Command) (identity.FeatureReceipt, error) {
	if err := w.RequireFeatureCommand(ctx, p, command); err != nil {
		return identity.FeatureReceipt{}, err
	}
	if err := p.checkCurrent(ctx, w); err != nil {
		return identity.FeatureReceipt{}, err
	}
	c := p.service.config()
	if p.bootstrap {
		args := append(scopeArgs(c.Scope), c.Credential.id, c.Credential.expected[:], p.service.profile[:], strconv.FormatUint(c.ConnectionVersion, 10), c.CredentialExpiresAt, strconv.FormatUint(p.original.Admission.AuthorizationEpoch, 10), strconv.FormatUint(p.original.Admission.OrganizationCredentialVersion, 10), string(p.original.Command), p.effect[:])
		count, err := w.Exec(ctx, `INSERT INTO scim.connections(tenant_id,organization_id,provider_id,connection_id,credential_id,credential_digest,configuration_digest,version,state,expires_at,authority_version,organization_credential_version,command_id,effect_digest) VALUES($1,$2,$3,$4,$5,$6,$7,$8::numeric,'active',$9,$10::numeric,$11::numeric,$12,$13) ON CONFLICT DO NOTHING`, args...)
		if err != nil {
			return identity.FeatureReceipt{}, identity.UnavailableError{}
		}
		if count != 1 {
			return identity.FeatureReceipt{}, identity.ConflictError{}
		}
	} else {
		username, err := scim.UsernameComparisonKey(p.resource.Attributes["userName"].(string))
		if err != nil {
			return identity.FeatureReceipt{}, identity.InvalidInputError{Field: "scim_username"}
		}
		usernameDigest := sha256.Sum256([]byte(username))
		if err := p.requireAvailableUsername(ctx, w, username, usernameDigest); err != nil {
			return identity.FeatureReceipt{}, err
		}
		if _, err := p.service.domain.Apply(ctx, w, p, command, p.creation); err != nil {
			return identity.FeatureReceipt{}, err
		}
		observed, err := w.SCIMUserCreation(p)
		if err != nil || observed.ID != p.creation.Binding.UserID || observed.Status != identity.StatusActive {
			return identity.FeatureReceipt{}, identity.UnavailableError{}
		}
		wire, err := json.Marshal(p.resource)
		if err != nil || len(wire) > 131072 {
			return identity.FeatureReceipt{}, identity.InvalidInputError{Field: "scim_resource"}
		}
		args := append(scopeArgs(c.Scope), p.resource.ID, string(observed.ID), username, usernameDigest[:], p.resource.ExternalID, wire, string(p.original.Command), p.effect[:])
		count, err := w.Exec(ctx, `INSERT INTO scim.users(tenant_id,organization_id,provider_id,connection_id,resource_id,user_id,username_key,username_digest,external_id,resource,command_id,effect_digest) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12) ON CONFLICT DO NOTHING`, args...)
		if err != nil {
			return identity.FeatureReceipt{}, identity.UnavailableError{}
		}
		if count != 1 {
			return identity.FeatureReceipt{}, identity.ConflictError{}
		}
	}
	return identity.FeatureReceipt{Operation: p.operation(), AfterVersion: 1}, nil
}

func (p *nativePhase) requireAvailableUsername(ctx context.Context, w kernel.Work, username string, digest [32]byte) error {
	args := append(scopeArgs(p.service.config().Scope), digest[:], username)
	rows, err := w.Query(ctx, `SELECT 1 FROM scim.users WHERE tenant_id=$1 AND organization_id=$2 AND provider_id=$3 AND connection_id=$4 AND username_digest=$5 AND username_key=$6 LIMIT 1`, args...)
	if err != nil {
		return identity.UnavailableError{}
	}
	defer rows.Close()
	if rows.Next() {
		return identity.ConflictError{}
	}
	if rows.Err() != nil {
		return identity.UnavailableError{}
	}
	return nil
}

func (p *nativePhase) CheckFeatureCommit(ctx context.Context, w kernel.Work, command identity.Command) error {
	if command != p.command {
		return identity.ForbiddenError{}
	}
	return p.checkCurrent(ctx, w)
}

func (p *nativePhase) checkCurrent(ctx context.Context, w kernel.Work) error {
	c := p.service.config()
	original, err := p.service.restoreAdmission(p.original.Admission, p.original.At)
	if err != nil || !liveConnection(ctx, original.connection) {
		return identity.ForbiddenError{}
	}
	if err := w.RequireActiveDirectoryAuthority(ctx, p, original.directory); err != nil {
		return err
	}
	if err := p.service.organizations.RequireCredentialAuthority(ctx, w, p, original.organization); err != nil {
		return err
	}
	if err := authoritypg.RequireAuthority(ctx, w, c.authorityScope(), original.epoch, c.MaximumDuration); err != nil {
		return identity.ForbiddenError{}
	}
	if !p.bootstrap {
		if err := p.requireConnection(ctx, w, original); err != nil {
			return err
		}
	}
	now, err := w.DatabaseTime(ctx)
	if err != nil || !now.Before(original.connection.AuthorityValidUntil) || !now.Before(c.CredentialExpiresAt) {
		return identity.ForbiddenError{}
	}
	return nil
}

func (p *nativePhase) executionPlan() (kernel.CommandPlan, error) {
	spec, _ := p.command.Feature()
	b, op := spec.Binding, spec.Operation
	builder, err := audit.NewBuilder(audit.BuilderConfig{})
	if err != nil {
		return kernel.CommandPlan{}, err
	}
	seed, err := builder.Build(audit.RecordInput{OccurredAt: p.original.At, Action: op.OperationID, Outcome: audit.OutcomeSucceeded, Actor: audit.ActorInput{Kind: audit.ActorService, ID: string(b.ActorID)}, Subject: audit.SubjectInput{Type: p.subjectType(), ID: b.RecordID}, Context: audit.ContextInput{TenantID: string(b.TenantID), CorrelationID: b.CorrelationID}, Policy: audit.PolicyMetadata{PolicyID: b.PolicyID, Version: strconv.FormatUint(b.PolicyVersion, 10)}, Changes: audit.ChangeSetInput{Redacted: true}, Attributes: map[string]string{"command.id": string(b.CommandID), "aggregate.type": p.subjectType(), "aggregate.id": b.RecordID, "aggregate.before_version": "0", "aggregate.after_version": "1", "retention.class": "protected"}})
	if err != nil {
		return kernel.CommandPlan{}, err
	}
	digest, err := kernel.FeatureAuditBindingDigest(b, op, p.subjectType(), seed)
	if err != nil {
		return kernel.CommandPlan{}, err
	}
	registration := p.registration()
	plan := kernel.CommandPlan{Contributors: p.registry.Descriptors(), Feature: &registration, SubjectType: p.subjectType(), Lifecycle: &kernel.LifecyclePlan{EventType: p.eventType(), AfterVersion: 1}, Audits: []kernel.AuditPlan{{EventType: op.OperationID, SchemaVersion: 1, Required: true, RequiredRecordCount: 1, MaxRecordBytes: 16384, MaxAggregateBytes: 16384, RetentionPolicyVersion: 1, RetentionClass: "protected", BindingDigest: digest}}}
	return p.coordinator.PrepareCommandPlan(b, p.command, plan)
}

func (p *nativePhase) execute(ctx context.Context) (result identity.CommandResult, err error) {
	plan, err := p.executionPlan()
	if err != nil {
		return result, err
	}
	spec, _ := p.command.Feature()
	reservation, result, err := p.coordinator.ReserveCommand(ctx, spec.Binding, p.command, plan)
	if err != nil || reservation == (kernel.Reservation{}) {
		return result, err
	}
	work, err := p.coordinator.Begin(ctx, reservation)
	if err != nil {
		return result, err
	}
	defer func() { _, _ = p.coordinator.Abort(work, identity.UnavailableError{}) }()
	result, err = p.coordinator.ApplyFeature(ctx, work, p.command)
	if err != nil {
		return p.coordinator.Abort(work, err)
	}
	return p.coordinator.Commit(work, result)
}

func (p *nativePhase) RecoverParticipant(ctx context.Context, w kernel.RecoveryWork) (kernel.RecoveryStatus, error) {
	b, feature, lifecycle, err := w.FeatureScope(p)
	if err != nil || feature != p.registration() || lifecycle != (kernel.LifecyclePlan{EventType: p.eventType(), AfterVersion: 1}) {
		return kernel.RecoveryUnknown, identity.ForbiddenError{}
	}
	// Existing exact native effect is positive/ambiguous evidence, never a
	// reconstructed commit receipt. Only the retained kernel journal proves commit.
	sql := `SELECT effect_digest FROM scim.users WHERE command_id=$1`
	if p.bootstrap {
		sql = `SELECT effect_digest FROM scim.connections WHERE command_id=$1`
	}
	rows, err := w.Query(ctx, sql, string(b.CommandID))
	if err != nil {
		return kernel.RecoveryUnknown, err
	}
	defer rows.Close()
	if !rows.Next() {
		if rows.Err() != nil {
			return kernel.RecoveryUnknown, identity.UnavailableError{}
		}
		return kernel.RecoveryNotCommitted, nil
	}
	return kernel.RecoveryUnknown, nil
}
