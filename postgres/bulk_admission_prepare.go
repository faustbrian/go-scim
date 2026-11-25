package scimpostgres

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"time"

	"github.com/faustbrian/go-authorization/v3"
	identity "github.com/faustbrian/go-identity"
	kernel "github.com/faustbrian/go-identity/postgres"
	scim "github.com/faustbrian/go-scim"
	envelope "github.com/faustbrian/go-secret-envelope/v2"
)

type bulkAdmissionPhase struct {
	children          []scim.BulkOperation
	components        []scim.BulkComponent
	cutoff, maximum   int
	profile           [32]byte
	intent            [32]byte
	allocation        []bulkAllocation
	preparationSchema uint8
}

type bulkAllocation struct {
	Command  identity.CommandID
	Resource string
}

// The same encrypted request-key mapping owns the random original allocation.
// It retains only metadata, not provider bodies or a second graph/state record.
type bulkPreparedInput struct {
	Schema      uint8
	Parent      identity.CommandID
	At          time.Time
	Profile     [32]byte
	Maximum     int
	Admission   admissionSnapshot
	Allocations []bulkAllocation
}

const (
	bulkPreparationPlaintextLimit       = 110 * 1024
	bulkPreparationLegacy         uint8 = 1
	bulkPreparationAuditAdmit     uint8 = 2
)

func (p *nativePhase) prepareBulkRequest(ctx context.Context, b kernel.RequestKeyPreparationBinding) ([]byte, error) {
	return p.prepareBulkRequestVersion(ctx, b, bulkPreparationAuditAdmit)
}

func (p *nativePhase) prepareBulkRequestVersion(ctx context.Context, b kernel.RequestKeyPreparationBinding, schema uint8) ([]byte, error) {
	aad, err := p.preparationAAD(b)
	if err != nil {
		return nil, err
	}
	admission, err := p.service.captureAdmission(ctx, p.admission)
	if err != nil {
		return nil, err
	}
	at := time.Now().UTC().Truncate(time.Microsecond)
	if _, err := p.service.restoreAdmission(admission, at); err != nil {
		return nil, err
	}
	input := bulkPreparedInput{Schema: schema, Parent: b.Admission.CommandID, At: at, Profile: p.bulk.profile,
		Maximum: p.bulk.maximum, Admission: admission, Allocations: make([]bulkAllocation, len(p.bulk.children))}
	for i, child := range p.bulk.children {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		initial, err := identity.NewCommandID()
		if err != nil {
			return nil, err
		}
		input.Allocations[i].Command = initial
		if bulkCreatesGroup(child) {
			resource, err := identity.NewSubjectID()
			if err != nil {
				return nil, err
			}
			input.Allocations[i].Resource = string(resource)
		}
	}
	plain, err := json.Marshal(input)
	defer clear(plain)
	if err != nil || len(plain) > bulkPreparationPlaintextLimit {
		return nil, identity.UnavailableError{}
	}
	sealed, err := p.service.crypto.Encrypt(ctx, envelope.EncryptRequest{Plaintext: plain, KeyReference: p.service.config().ActiveEnvelopeKeyID, Context: aad})
	if err != nil {
		return nil, identity.UnavailableError{}
	}
	wire, err := sealed.MarshalBinary()
	if err != nil || len(wire) > bulkPreparationPlaintextLimit+4096 {
		return nil, identity.UnavailableError{}
	}
	return wire, nil
}

func (p *nativePhase) restoreBulkRequest(ctx context.Context, b kernel.RequestKeyPreparationBinding, wire []byte, fields []identity.FeatureField) error {
	if len(wire) == 0 || len(wire) > bulkPreparationPlaintextLimit+4096 {
		return identity.UnavailableError{}
	}
	aad, err := p.preparationAAD(b)
	if err != nil {
		return err
	}
	sealed, err := envelope.ParseEnvelope(wire)
	if err != nil {
		return identity.UnavailableError{}
	}
	plain, err := p.service.crypto.Decrypt(ctx, envelope.DecryptRequest{Envelope: sealed, Context: aad})
	if err != nil {
		return identity.UnavailableError{}
	}
	defer clear(plain)
	var input bulkPreparedInput
	if len(plain) > bulkPreparationPlaintextLimit || json.Unmarshal(plain, &input) != nil || !p.bulk.validAllocation(input, b.Admission.CommandID) {
		return identity.UnavailableError{}
	}
	if _, err := p.service.restoreAdmission(input.Admission, input.At); err != nil {
		return err
	}
	p.original = originalInput{Command: input.Parent, At: input.At, Admission: input.Admission}
	p.bulk.allocation, p.bulk.intent = input.Allocations, b.IntentDigest
	p.bulk.preparationSchema = input.Schema

	c, op := p.service.config(), p.operation()
	binding := identity.CommandBinding{CommandID: input.Parent, TenantID: c.Scope.TenantID, UserID: identity.UserID(c.ActorID),
		ActorID: c.ActorID, ActorKind: authorization.SubjectServiceAccount, OperationID: op.OperationID, PolicyID: c.PolicyID,
		PolicyVersion: c.PolicyVersion, SchemaID: op.SchemaID, SchemaVersion: op.SchemaVersion, CorrelationID: string(input.Parent), RecordID: string(input.Parent)}
	allocationDigest := sha256.Sum256(plain)
	fields = append(fields, identity.FeatureField{Name: "scim.bulk.allocation", Value: identity.FeatureValue{Kind: identity.FeatureBytes, Bytes: allocationDigest[:]}})
	p.command, err = identity.NewFeatureCommand(identity.FeatureCommandSpec{Binding: binding, Operation: op, Fields: fields})
	return err
}

func (p *bulkAdmissionPhase) validAllocation(input bulkPreparedInput, command identity.CommandID) bool {
	if (input.Schema != bulkPreparationLegacy && input.Schema != bulkPreparationAuditAdmit) ||
		input.Parent != command || input.Profile != p.profile || input.Maximum != p.maximum ||
		len(input.Allocations) != len(p.children) || input.At.IsZero() || input.At.Year() < 1 || input.At.Year() > 9999 || !input.At.Equal(input.At.Truncate(time.Microsecond)) {
		return false
	}
	commands := map[identity.CommandID]bool{command: true}
	resources := make(map[string]bool)
	for i, allocated := range input.Allocations {
		if _, err := identity.ParseCommandID(string(allocated.Command)); err != nil || commands[allocated.Command] {
			return false
		}
		commands[allocated.Command] = true
		if !bulkCreatesGroup(p.children[i]) {
			if allocated.Resource != "" {
				return false
			}
			continue
		}
		if _, err := identity.ParseSubjectID(allocated.Resource); err != nil || resources[allocated.Resource] {
			return false
		}
		resources[allocated.Resource] = true
	}
	return true
}

func bulkCreatesGroup(child scim.BulkOperation) bool {
	return child.Method == "POST" && child.Target.ResourceType == "Group"
}
