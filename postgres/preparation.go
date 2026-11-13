package scimpostgres

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"time"

	"github.com/faustbrian/go-authorization/v3"
	identity "github.com/faustbrian/go-identity"
	kernel "github.com/faustbrian/go-identity/postgres"
	scim "github.com/faustbrian/go-scim"
	envelope "github.com/faustbrian/go-secret-envelope/v2"
)

// Only this code-free original metadata is encrypted in the existing immutable
// request-key mapping. It is not a second journal, receipt or current authority.
type originalInput struct {
	Schema    uint8
	Command   identity.CommandID
	ID        string
	Version   scim.Version
	At        time.Time
	Profile   [32]byte
	Admission admissionSnapshot
}

func (s *Service) requestIntent(canonical []byte, operation string) (identity.RequestIntent, error) {
	c := s.config()
	h := hmac.New(sha256.New, c.IntentKey[:])
	_, _ = h.Write([]byte("scim-postgres/request-intent/v1\x00"))
	_, _ = h.Write(canonical)
	return identity.NewRequestIntent([]identity.FeatureField{{Name: "configuration", Value: identity.FeatureValue{Kind: identity.FeatureBytes, Bytes: s.profile[:]}}, {Name: "canonical", Value: identity.FeatureValue{Kind: identity.FeatureBytes, Bytes: h.Sum(nil)}}, {Name: "operation", Value: identity.FeatureValue{Kind: identity.FeatureText, Text: operation}}})
}

func (p *nativePhase) PrepareRequestKey(ctx context.Context, b kernel.RequestKeyPreparationBinding, _ identity.RequestIntent) ([]byte, error) {
	aad, err := p.preparationAAD(b)
	if err != nil {
		return nil, err
	}
	input, err := p.newOriginalInput(ctx, b.Admission.CommandID)
	if err != nil {
		return nil, err
	}
	wire, err := json.Marshal(input)
	if err != nil {
		return nil, ErrInvalidConfiguration
	}
	defer clear(wire)
	sealed, err := p.service.crypto.Encrypt(ctx, envelope.EncryptRequest{Plaintext: wire, KeyReference: p.service.config().ActiveEnvelopeKeyID, Context: aad})
	if err != nil {
		return nil, identity.UnavailableError{}
	}
	return sealed.MarshalBinary()
}

func (p *nativePhase) newOriginalInput(ctx context.Context, command identity.CommandID) (originalInput, error) {
	if _, err := identity.ParseCommandID(string(command)); err != nil {
		return originalInput{}, identity.ForbiddenError{}
	}
	input := originalInput{Schema: 1, Command: command, At: time.Now().UTC().Truncate(time.Microsecond), Profile: p.service.profile}
	var err error
	input.Admission, err = p.service.captureAdmission(ctx, p.admission)
	if err != nil {
		return originalInput{}, err
	}
	if _, err := p.service.restoreAdmission(input.Admission, input.At); err != nil {
		return originalInput{}, err
	}
	if p.bootstrap {
		return input, nil
	}
	id, err := identity.NewSubjectID()
	if err != nil {
		return originalInput{}, err
	}
	version, err := identity.NewCommandID()
	if err != nil {
		return originalInput{}, err
	}
	input.ID, input.Version = string(id), scim.Version(`"`+string(version)+`"`)
	return input, nil
}

func (p *nativePhase) restoreOriginal(ctx context.Context, b kernel.RequestKeyPreparationBinding, wire []byte) (originalInput, error) {
	if len(wire) == 0 || len(wire) > 8192 {
		return originalInput{}, identity.UnavailableError{}
	}
	aad, err := p.preparationAAD(b)
	if err != nil {
		return originalInput{}, err
	}
	sealed, err := envelope.ParseEnvelope(wire)
	if err != nil {
		return originalInput{}, identity.UnavailableError{}
	}
	plain, err := p.service.crypto.Decrypt(ctx, envelope.DecryptRequest{Envelope: sealed, Context: aad})
	if err != nil {
		return originalInput{}, identity.UnavailableError{}
	}
	defer clear(plain)
	var input originalInput
	if len(plain) > 4096 || json.Unmarshal(plain, &input) != nil || input.Schema != 1 || input.Command != b.Admission.CommandID || input.Profile != p.service.profile || input.At.IsZero() || input.At.Year() < 1 || input.At.Year() > 9999 || !input.At.Equal(input.At.Truncate(time.Microsecond)) {
		return originalInput{}, identity.UnavailableError{}
	}
	if _, err := p.service.restoreAdmission(input.Admission, input.At); err != nil {
		return originalInput{}, identity.UnavailableError{}
	}
	if p.bootstrap {
		if input.ID != "" || input.Version != "" {
			return originalInput{}, identity.UnavailableError{}
		}
		return input, nil
	}
	if _, err := identity.ParseSubjectID(input.ID); err != nil {
		return originalInput{}, identity.UnavailableError{}
	}
	if len(input.Version) != 24 || input.Version[0] != '"' || input.Version[23] != '"' {
		return originalInput{}, identity.UnavailableError{}
	}
	if _, err := identity.ParseCommandID(string(input.Version[1:23])); err != nil {
		return originalInput{}, identity.UnavailableError{}
	}
	return input, nil
}

func (p *nativePhase) preparationAAD(b kernel.RequestKeyPreparationBinding) (envelope.Context, error) {
	c := p.service.config()
	if b.Namespace != c.RequestKeys.Namespace || b.Scope.TenantID != c.Scope.TenantID || b.Scope.ActorID != c.ActorID || b.Scope.ActorKind != authorization.SubjectServiceAccount || b.Scope.Method != "POST" || b.Scope.RouteID != p.operation().OperationID || b.Feature != p.registration() || b.PolicyVersion != c.PolicyVersion || b.IntentDigest == ([32]byte{}) || b.Admission.FingerprintKeyVersion == 0 {
		return envelope.Context{}, identity.ForbiddenError{}
	}
	if _, err := identity.ParseCommandID(string(b.Admission.CommandID)); err != nil {
		return envelope.Context{}, identity.ForbiddenError{}
	}
	frame, err := json.Marshal(struct {
		Namespace             string
		Scope                 kernel.RequestKeyScope
		Admission             kernel.RequestKeyAdmission
		Feature               kernel.FeatureRegistration
		Policy                uint64
		Intent, Configuration [32]byte
	}{b.Namespace, b.Scope, b.Admission, b.Feature, b.PolicyVersion, b.IntentDigest, p.service.profile})
	if err != nil {
		return envelope.Context{}, identity.UnavailableError{}
	}
	digest := sha256.Sum256(frame)
	clear(frame)
	return envelope.NewContext(map[string]string{"profile": "scim-native-original-input-v1", "binding": base64.RawURLEncoding.EncodeToString(digest[:])})
}

func (s *Service) caller(operation, target, kind string) authorization.DecisionContext {
	c := s.config()
	return authorization.DecisionContext{PolicyRevision: authorization.Revision(c.PolicyVersion), Request: authorization.Request{Subject: authorization.Subject{Kind: authorization.SubjectServiceAccount, ID: authorization.SubjectID(c.ActorID)}, Tenant: authorization.TenantID(c.Scope.TenantID), Action: authorization.Action(operation), Resource: authorization.Resource{Type: authorization.ResourceType(kind), ID: authorization.ResourceID(target)}, Environment: authorization.Environment{Time: time.Now().UTC()}}}
}

func (p *nativePhase) resolveOriginal(ctx context.Context, key string, canonical []byte) error {
	c := p.service.config()
	intent, err := p.service.requestIntent(canonical, p.operation().OperationID)
	if err != nil {
		return err
	}
	idempotency, err := identity.NewIdempotencyKey([]byte(key))
	if err != nil {
		return scim.NewError(400, "invalidValue")
	}
	coordinator, registry, err := p.service.coordinator(p)
	if err != nil {
		return err
	}
	p.coordinator, p.registry = coordinator, registry
	scope := kernel.RequestKeyScope{TenantID: c.Scope.TenantID, ActorID: c.ActorID, ActorKind: authorization.SubjectServiceAccount, Method: "POST", RouteID: p.operation().OperationID}
	binding, wire, err := coordinator.ResolvePreparedRequestKey(ctx, scope, idempotency, intent, p.service.caller(scope.RouteID, scope.RouteID, "identity.request-admission"), p.registration(), p)
	if err != nil {
		return err
	}
	defer clear(wire)
	p.original, err = p.restoreOriginal(ctx, binding, wire)
	return err
}
