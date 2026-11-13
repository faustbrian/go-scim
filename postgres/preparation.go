package scimpostgres

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"time"
	"unicode/utf8"

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
	// Schema 2 retains the pre-mutation projection, not another outcome or
	// permission. The existing journal alone decides whether effects committed.
	// Old schema-1 creation/bootstrap custody remains byte-compatible.
	Operation     scim.Operation `json:",omitempty"`
	Current       *scim.Resource `json:",omitempty"`
	KernelVersion uint64         `json:",omitempty"`
	UserAuthority uint64         `json:",omitempty"`
	Generation    int64          `json:",omitempty"`
}

// Preserve the existing 4 KiB scalar provenance allowance while adding at most
// one native 128 KiB projection. The local keyring envelope's bounded key
// reference, wrapped key, nonce and framing fit a separate 4 KiB allowance.
const originalPlaintextBytes = 131072 + 4096
const originalCiphertextBytes = originalPlaintextBytes + 4096

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
	if err != nil || len(wire) > originalPlaintextBytes {
		return nil, ErrInvalidConfiguration
	}
	defer clear(wire)
	sealed, err := p.service.crypto.Encrypt(ctx, envelope.EncryptRequest{Plaintext: wire, KeyReference: p.service.config().ActiveEnvelopeKeyID, Context: aad})
	if err != nil {
		return nil, identity.UnavailableError{}
	}
	encoded, err := sealed.MarshalBinary()
	if err != nil || len(encoded) > originalCiphertextBytes {
		return nil, identity.UnavailableError{}
	}
	return encoded, nil
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
	if p.intent.Operation != "" && p.intent.Operation != scim.UserCreate {
		if !nativeMutation(p.intent.Operation) {
			return originalInput{}, identity.ForbiddenError{}
		}
		if p.intent.ResourceID == "" || len(p.intent.ResourceID) > 128 || !utf8.ValidString(p.intent.ResourceID) {
			return originalInput{}, identity.InvalidInputError{Field: "scim_resource_id"}
		}
		input.Schema, input.Operation, input.ID = 2, p.intent.Operation, p.intent.ResourceID
		current, err := (&protocolBridge{service: p.service}).Get(ctx, p.intent.Scope, p.intent.ResourceID)
		if err != nil && !errors.Is(err, scim.ErrNotFound) {
			return originalInput{}, err
		}
		if err == nil {
			status, err := p.service.directory.GetStatus(ctx, identity.UserStatusQuery{TenantID: p.intent.Scope.TenantID, UserID: identity.UserID(input.ID)})
			if err != nil || status.User.Status != identity.StatusActive {
				return originalInput{}, identity.ForbiddenError{}
			}
			wire, err := json.Marshal(current)
			if err != nil || len(wire) > 131072 {
				return originalInput{}, identity.UnavailableError{}
			}
			args := append(scopeArgs(p.intent.Scope), input.ID, wire)
			err = p.service.pool.Raw().QueryRow(ctx, `SELECT generation FROM scim.users WHERE tenant_id=$1 AND organization_id=$2 AND provider_id=$3 AND connection_id=$4 AND resource_id=$5 AND resource=$6 AND deleted_at IS NULL`, args...).Scan(&input.Generation)
			clear(wire)
			if err != nil || input.Generation < 1 {
				return originalInput{}, identity.UnavailableError{}
			}
			input.Current, input.KernelVersion, input.UserAuthority = &current, status.User.Version, status.AuthorityVersion
			if input.At.Before(current.LastModified) {
				input.At = current.LastModified
			}
		}
		version, err := identity.NewCommandID()
		if err != nil {
			return originalInput{}, err
		}
		input.Version = scim.Version(`"` + string(version) + `"`)
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
	if len(wire) == 0 || len(wire) > originalCiphertextBytes {
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
	if len(plain) > originalPlaintextBytes || json.Unmarshal(plain, &input) != nil || input.Schema != 1 && input.Schema != 2 || input.Command != b.Admission.CommandID || input.Profile != p.service.profile || input.At.IsZero() || input.At.Year() < 1 || input.At.Year() > 9999 || !input.At.Equal(input.At.Truncate(time.Microsecond)) {
		return originalInput{}, identity.UnavailableError{}
	}
	if _, err := p.service.restoreAdmission(input.Admission, input.At); err != nil {
		return originalInput{}, identity.UnavailableError{}
	}
	if p.bootstrap {
		if input.Schema != 1 || input.ID != "" || input.Version != "" || input.Operation != "" || input.Current != nil || input.KernelVersion != 0 || input.UserAuthority != 0 || input.Generation != 0 {
			return originalInput{}, identity.UnavailableError{}
		}
		return input, nil
	}
	if input.Schema == 1 {
		if p.intent.Operation != "" && p.intent.Operation != scim.UserCreate || input.Operation != "" || input.Current != nil || input.KernelVersion != 0 || input.UserAuthority != 0 || input.Generation != 0 {
			return originalInput{}, identity.UnavailableError{}
		}
	} else {
		if !nativeMutation(input.Operation) || input.Operation != p.intent.Operation || input.ID != p.intent.ResourceID || input.Current == nil && (input.KernelVersion != 0 || input.UserAuthority != 0 || input.Generation != 0) {
			return originalInput{}, identity.UnavailableError{}
		}
		if current := input.Current; current != nil {
			wire, err := json.Marshal(current)
			if err != nil || len(wire) > 131072 || current.ID != input.ID || !nativeVersion(current.Version) || current.CreatedAt.IsZero() || current.LastModified.Before(current.CreatedAt) || current.LastModified.After(input.At) || input.KernelVersion == 0 || input.UserAuthority == 0 || input.Generation < 1 {
				return originalInput{}, identity.UnavailableError{}
			}
		}
	}
	if input.Schema == 1 || input.Current != nil {
		if _, err := identity.ParseSubjectID(input.ID); err != nil {
			return originalInput{}, identity.UnavailableError{}
		}
	} else if input.ID == "" || len(input.ID) > 128 || !utf8.ValidString(input.ID) {
		return originalInput{}, identity.UnavailableError{}
	}
	if !nativeVersion(input.Version) {
		return originalInput{}, identity.UnavailableError{}
	}
	return input, nil
}

func (p *nativePhase) preparationAAD(b kernel.RequestKeyPreparationBinding) (envelope.Context, error) {
	c := p.service.config()
	if b.Namespace != p.service.requestKeys(p).Namespace || b.Scope.TenantID != c.Scope.TenantID || b.Scope.ActorID != c.ActorID || b.Scope.ActorKind != authorization.SubjectServiceAccount || b.Scope.Method != p.method() || b.Scope.RouteID != p.operation().OperationID || b.Feature != p.registration() || b.PolicyVersion != c.PolicyVersion || b.IntentDigest == ([32]byte{}) || b.Admission.FingerprintKeyVersion == 0 {
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
	coordinator, registry, err := p.service.coordinator(p)
	if err != nil {
		return err
	}
	p.coordinator, p.registry = coordinator, registry
	scope := kernel.RequestKeyScope{TenantID: c.Scope.TenantID, ActorID: c.ActorID, ActorKind: authorization.SubjectServiceAccount, Method: p.method(), RouteID: p.operation().OperationID}
	caller := p.service.caller(scope.RouteID, scope.RouteID, "identity.request-admission")
	var binding kernel.RequestKeyPreparationBinding
	var wire []byte
	if p.intent.Operation == scim.UserDelete && !p.bootstrap {
		// Stable DELETE identity is connection/route/target/If-Match, not the
		// entire canonical request. Query changes remain full-intent conflicts
		// against that one original, never permission to allocate another one.
		// The kernel applies its stable private lookup-key HMAC; neither the
		// adapter intent key nor rotating fingerprint keys select the original.
		frame, frameErr := json.Marshal(struct {
			Scope      scim.Scope
			Operation  scim.Operation
			ResourceID string
			IfMatch    scim.Version
		}{c.Scope, p.intent.Operation, p.intent.ResourceID, p.intent.IfMatch})
		if frameErr != nil {
			return identity.UnavailableError{}
		}
		digest := sha256.Sum256(frame)
		clear(frame)
		selectorBytes := append([]byte("scim-native-delete-selector-v1\x00"), digest[:]...)
		selector, selectorErr := kernel.NewCanonicalRequestKey(selectorBytes)
		if selectorErr != nil {
			return selectorErr
		}
		var optional *identity.IdempotencyKey
		if key != "" {
			idempotency, keyErr := identity.NewIdempotencyKey([]byte(key))
			if keyErr != nil {
				return scim.NewError(400, "invalidValue")
			}
			optional = &idempotency
		}
		if optional != nil {
			// Detect an existing alias bound to another selector before any
			// target lookup/preparation. Resolve still owns atomic late-alias
			// attachment before the original command can execute.
			_, prior, _, readErr := coordinator.ReadPreparedCanonicalRequest(ctx, scope, selector, optional, intent, caller, p.registration(), p)
			clear(prior)
			if readErr != nil {
				return readErr
			}
		}
		binding, wire, err = coordinator.ResolvePreparedCanonicalRequest(ctx, scope, selector, optional, intent, caller, p.registration(), p)
	} else {
		idempotency, keyErr := identity.NewIdempotencyKey([]byte(key))
		if keyErr != nil {
			return scim.NewError(400, "invalidValue")
		}
		binding, wire, err = coordinator.ResolvePreparedRequestKey(ctx, scope, idempotency, intent, caller, p.registration(), p)
	}
	if err != nil {
		return err
	}
	defer clear(wire)
	p.original, err = p.restoreOriginal(ctx, binding, wire)
	return err
}

func nativeMutation(op scim.Operation) bool {
	return op == scim.UserReplace || op == scim.UserPatch || op == scim.UserDelete
}

func nativeVersion(version scim.Version) bool {
	if len(version) != 24 || version[0] != '"' || version[23] != '"' {
		return false
	}
	_, err := identity.ParseCommandID(string(version[1:23]))
	return err == nil
}

func (p *nativePhase) method() string {
	if !p.bootstrap {
		switch p.intent.Operation {
		case scim.UserReplace:
			return "PUT"
		case scim.UserPatch:
			return "PATCH"
		case scim.UserDelete:
			return "DELETE"
		}
	}
	return "POST"
}
