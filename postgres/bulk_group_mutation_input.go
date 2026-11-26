package scimpostgres

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"time"
	"unicode/utf8"

	identity "github.com/faustbrian/go-identity"
	scim "github.com/faustbrian/go-scim"
	envelope "github.com/faustbrian/go-secret-envelope/v2"
)

// The existing child row owns this one encrypted original projection. It is
// historical input custody only: no authority capture, command allocation or
// outcome decision happens here.
func (p *nativePhase) sealBulkMutationInput(ctx context.Context, input originalInput, parent originalInput) ([]byte, error) {
	if ctx == nil {
		return nil, identity.UnavailableError{}
	}
	aad, err := p.bulkMutationInputAAD(parent)
	if err != nil {
		return nil, err
	}
	if err := p.validateBulkMutationInput(input, parent); err != nil {
		return nil, err
	}
	plain, err := json.Marshal(input)
	defer clear(plain)
	if err != nil || len(plain) > originalPlaintextBytes {
		return nil, identity.UnavailableError{}
	}
	sealed, err := p.service.crypto.Encrypt(ctx, envelope.EncryptRequest{
		Plaintext: plain, KeyReference: p.service.config().ActiveEnvelopeKeyID, Context: aad,
	})
	if err != nil {
		return nil, identity.UnavailableError{}
	}
	wire, err := sealed.MarshalBinary()
	if err != nil || len(wire) > originalCiphertextBytes {
		return nil, identity.UnavailableError{}
	}
	return wire, nil
}

func (p *nativePhase) openBulkMutationInput(ctx context.Context, wire []byte, parent originalInput) (originalInput, error) {
	if ctx == nil || len(wire) == 0 || len(wire) > originalCiphertextBytes {
		return originalInput{}, identity.UnavailableError{}
	}
	aad, err := p.bulkMutationInputAAD(parent)
	if err != nil {
		return originalInput{}, err
	}
	sealed, err := envelope.ParseEnvelope(wire)
	if err != nil {
		return originalInput{}, identity.UnavailableError{}
	}
	plain, err := p.service.crypto.Decrypt(ctx, envelope.DecryptRequest{Envelope: sealed, Context: aad})
	defer clear(plain)
	if err != nil || len(plain) > originalPlaintextBytes {
		return originalInput{}, identity.UnavailableError{}
	}
	var input originalInput
	if json.Unmarshal(plain, &input) != nil {
		return originalInput{}, identity.UnavailableError{}
	}
	if err := p.validateBulkMutationInput(input, parent); err != nil {
		return originalInput{}, err
	}
	return input, nil
}

func (p *nativePhase) bulkMutationInputAAD(parent originalInput) (envelope.Context, error) {
	if p == nil || p.service == nil || p.service.config == nil || p.service.crypto == nil || p.bulkChild == nil || p.bulk != nil || p.bootstrap {
		return envelope.Context{}, identity.UnavailableError{}
	}
	if !nativeMutation(p.intent.Operation) {
		return envelope.Context{}, identity.UnavailableError{}
	}
	c, child := p.service.config(), p.bulkChild
	// The parser's existing Bulk cap is 1000 operations; the retained ordinal
	// must identify one such child, never an unbounded alternate slot.
	if child.parent != parent.Command || child.row.Ordinal < 0 || child.row.Ordinal >= scim.DefaultBulkPolicy().MaxOperations || len(child.row.Fingerprint) != sha256.Size || child.row.Command == string(parent.Command) || p.intent.Scope != c.Scope || p.intent.ResourceID == "" || len(p.intent.ResourceID) > 128 || !utf8.ValidString(p.intent.ResourceID) || len(p.intent.IfMatch) > 256 || !utf8.ValidString(string(p.intent.IfMatch)) || !bulkMutationInputTime(parent.At) {
		return envelope.Context{}, identity.UnavailableError{}
	}
	if _, err := identity.ParseCommandID(string(parent.Command)); err != nil {
		return envelope.Context{}, identity.UnavailableError{}
	}
	if _, err := identity.ParseCommandID(child.row.Command); err != nil {
		return envelope.Context{}, identity.UnavailableError{}
	}
	if _, err := p.service.restoreAdmission(parent.Admission, parent.At); err != nil {
		return envelope.Context{}, identity.UnavailableError{}
	}
	admission, err := parent.Admission.commitment()
	if err != nil {
		return envelope.Context{}, identity.UnavailableError{}
	}
	// NewService's profile commits the complete scope and configured actor.
	// Exact target and If-Match are additionally bound here because the row's
	// command/fingerprint alone must not permit another resolved invocation.
	frame, err := json.Marshal(struct {
		Configuration [32]byte
		Parent        identity.CommandID
		ParentAt      time.Time
		Admission     [32]byte
		Ordinal       int
		Command       string
		Fingerprint   []byte
		Operation     scim.Operation
		Target        string
		IfMatch       scim.Version
	}{p.service.profile, parent.Command, parent.At, admission, child.row.Ordinal, child.row.Command,
		child.row.Fingerprint, p.intent.Operation, p.intent.ResourceID, p.intent.IfMatch})
	defer clear(frame)
	if err != nil {
		return envelope.Context{}, identity.UnavailableError{}
	}
	digest := sha256.Sum256(frame)
	profile := "scim-bulk-group-mutation-original-v1"
	if !p.group() {
		profile = "scim-bulk-user-mutation-original-v1"
	}
	aad, err := envelope.NewContext(map[string]string{
		"profile": profile,
		"binding": base64.RawURLEncoding.EncodeToString(digest[:]),
	})
	if err != nil {
		return envelope.Context{}, identity.UnavailableError{}
	}
	return aad, nil
}

func (p *nativePhase) validateBulkMutationInput(input originalInput, parent originalInput) error {
	if input.Command != identity.CommandID(p.bulkChild.row.Command) || input.Profile != p.service.profile || !bulkMutationInputTime(input.At) || input.At.Before(parent.At) || input.At.After(parent.Admission.ValidUntil) {
		return identity.UnavailableError{}
	}
	originalAdmission, err := input.Admission.commitment()
	if err != nil {
		return identity.UnavailableError{}
	}
	parentAdmission, err := parent.Admission.commitment()
	if err != nil || originalAdmission != parentAdmission {
		return identity.UnavailableError{}
	}
	if _, err := p.service.restoreAdmission(input.Admission, input.At); err != nil {
		return identity.UnavailableError{}
	}
	validate := p.validateGroupOriginal
	if !p.group() {
		validate = p.validateUserOriginal
	}
	if err := validate(input); err != nil {
		return identity.UnavailableError{}
	}
	if input.Current != nil && (!bulkMutationInputTime(input.Current.CreatedAt) || !bulkMutationInputTime(input.Current.LastModified)) {
		return identity.UnavailableError{}
	}
	return nil
}

func bulkMutationInputTime(at time.Time) bool {
	return !at.IsZero() && at.Year() >= 1 && at.Year() <= 9999 && at.Location() == time.UTC && at.Equal(at.Truncate(time.Microsecond))
}
