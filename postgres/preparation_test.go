package scimpostgres

import (
	"bytes"
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	authentication "github.com/faustbrian/go-authentication/v2"
	"github.com/faustbrian/go-authorization/v3"
	identity "github.com/faustbrian/go-identity"
	kernel "github.com/faustbrian/go-identity/postgres"
	organization "github.com/faustbrian/go-organization"
	scim "github.com/faustbrian/go-scim"
	envelope "github.com/faustbrian/go-secret-envelope/v2"
	"github.com/faustbrian/go-secret-envelope/v2/adapters/keyring"
)

// This fixture proves only the actual authenticated envelope codec. It is not
// a forged database mapping/admission, policy grant or provisioning consumer.
func preparationCodec(t testing.TB) (*nativePhase, kernel.RequestKeyPreparationBinding, []byte) {
	t.Helper()
	keys, err := keyring.New(map[string][]byte{"codec": bytes.Repeat([]byte{89}, 32)})
	if err != nil {
		t.Fatal(err)
	}
	crypto, err := envelope.NewService(keys)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	credential, err := NewConfiguredCredential("credential", authentication.NewBearerCredential("native-codec-credential-with-admitted-length"), [32]byte{2})
	if err != nil {
		t.Fatal(err)
	}
	c := Config{Scope: scim.Scope{TenantID: "tenant", OrganizationID: "organization", ProviderID: "provider", ConnectionID: "connection"}, ConnectionVersion: 1, Credential: credential, CredentialExpiresAt: now.Add(time.Hour).Truncate(time.Microsecond), GlobalAuthorityID: "deployment", ActorID: "service", PolicyVersion: 7, RequestKeys: kernel.RequestKeyConfig{Namespace: "codec-test"}, ActiveEnvelopeKeyID: "codec"}
	p := &nativePhase{service: &Service{config: func() Config { return c }, profile: [32]byte{3}, crypto: crypto}}
	p.admission = invocation{connection: scim.Connection{Scope: c.Scope, CredentialID: c.Credential.id, Version: 1, ExpiresAt: c.CredentialExpiresAt, AuthorityReadBeganAt: now.Add(-time.Millisecond), AuthorityValidUntil: now.Add(time.Second)}, organization: organization.CredentialAuthorityObservation{TenantID: c.Scope.TenantID, OrganizationID: c.Scope.OrganizationID, Version: 1, CredentialVersion: 1, ReadStartedAt: now, VerifiedAt: now, ValidUntil: now.Add(20 * time.Second)}, epoch: 1, directory: kernel.DirectoryAuthorityAdmission{Query: c.directoryQuery(), GlobalVersion: 1, TenantVersion: 1}}
	id, err := identity.NewCommandID()
	if err != nil {
		t.Fatal(err)
	}
	b := kernel.RequestKeyPreparationBinding{Namespace: c.RequestKeys.Namespace, Scope: kernel.RequestKeyScope{TenantID: c.Scope.TenantID, ActorID: c.ActorID, ActorKind: authorization.SubjectServiceAccount, Method: "POST", RouteID: p.operation().OperationID}, Admission: kernel.RequestKeyAdmission{CommandID: id, FingerprintKeyVersion: 1}, Feature: p.registration(), PolicyVersion: 7, IntentDigest: [32]byte{4}}
	intent, err := identity.NewRequestIntent(nil)
	if err != nil {
		t.Fatal(err)
	}
	wire, err := p.PrepareRequestKey(context.Background(), b, intent)
	if err != nil {
		t.Fatal(err)
	}
	return p, b, wire
}

func TestOriginalMetadataUsesActualEnvelopeAndExactProvenance(t *testing.T) {
	p, b, wire := preparationCodec(t)
	original, err := p.restoreOriginal(context.Background(), b, wire)
	if err != nil || original.ID == "" || original.Command != b.Admission.CommandID {
		t.Fatal("valid protected original metadata", err)
	}
	if bytes.Contains(wire, []byte(original.ID)) {
		t.Fatal("original input stored without envelope")
	}
	for name, change := range map[string]func(*kernel.RequestKeyPreparationBinding){
		"namespace":   func(b *kernel.RequestKeyPreparationBinding) { b.Namespace = "other" },
		"tenant":      func(b *kernel.RequestKeyPreparationBinding) { b.Scope.TenantID = "other" },
		"actor":       func(b *kernel.RequestKeyPreparationBinding) { b.Scope.ActorID = "other" },
		"kind":        func(b *kernel.RequestKeyPreparationBinding) { b.Scope.ActorKind = authorization.SubjectUser },
		"method":      func(b *kernel.RequestKeyPreparationBinding) { b.Scope.Method = "DELETE" },
		"route":       func(b *kernel.RequestKeyPreparationBinding) { b.Scope.RouteID = "other" },
		"command":     func(b *kernel.RequestKeyPreparationBinding) { b.Admission.CommandID, _ = identity.NewCommandID() },
		"fingerprint": func(b *kernel.RequestKeyPreparationBinding) { b.Admission.FingerprintKeyVersion++ },
		"feature":     func(b *kernel.RequestKeyPreparationBinding) { b.Feature.Operation.SchemaVersion++ },
		"policy":      func(b *kernel.RequestKeyPreparationBinding) { b.PolicyVersion++ },
		"intent":      func(b *kernel.RequestKeyPreparationBinding) { b.IntentDigest[0]++ },
	} {
		t.Run(name, func(t *testing.T) {
			changed := b
			change(&changed)
			if got, err := p.restoreOriginal(context.Background(), changed, wire); err == nil || got != (originalInput{}) {
				t.Fatal("changed provenance authenticated")
			}
		})
	}
	p.service.profile[0]++
	if _, err := p.restoreOriginal(context.Background(), b, wire); err == nil {
		t.Fatal("changed configuration authenticated original input")
	}
}

func mutationPreparationCodec(t testing.TB) (*nativePhase, kernel.RequestKeyPreparationBinding, originalInput) {
	t.Helper()
	p, binding, creationWire := preparationCodec(t)
	input, err := p.restoreOriginal(context.Background(), binding, creationWire)
	if err != nil {
		t.Fatal(err)
	}
	input.Schema, input.Operation = 2, scim.UserPatch
	input.KernelVersion, input.UserAuthority, input.Generation = 7, 11, 3
	input.Current = &scim.Resource{ID: input.ID, Version: input.Version, CreatedAt: input.At, LastModified: input.At, Schemas: []string{"urn:ietf:params:scim:schemas:core:2.0:User"}, Attributes: map[string]any{"userName": "Original", "name": map[string]any{"formatted": strings.Repeat("x", 12000)}}}
	p.intent = scim.WriteIntent{Operation: scim.UserPatch, ResourceID: input.ID, IfMatch: input.Version}
	binding.Scope.Method, binding.Scope.RouteID, binding.Feature = "PATCH", p.operation().OperationID, p.registration()
	return p, binding, input
}

func sealOriginalInput(t testing.TB, p *nativePhase, binding kernel.RequestKeyPreparationBinding, input originalInput) []byte {
	t.Helper()
	aad, err := p.preparationAAD(binding)
	if err != nil {
		t.Fatal(err)
	}
	plain, err := json.Marshal(input)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(plain)
	sealed, err := p.service.crypto.Encrypt(context.Background(), envelope.EncryptRequest{Plaintext: plain, KeyReference: "codec", Context: aad})
	if err != nil {
		t.Fatal(err)
	}
	wire, err := sealed.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	return wire
}

func TestMutationOriginalMetadataRetainsBoundedDetachedProjection(t *testing.T) {
	p, binding, input := mutationPreparationCodec(t)
	wire := sealOriginalInput(t, p, binding, input)
	if len(wire) <= 8192 {
		t.Fatal("bounded mutation fixture did not exercise enlarged preparation")
	}
	got, err := p.restoreOriginal(context.Background(), binding, wire)
	if err != nil || got.Current == nil || got.Current.ID != input.ID || got.KernelVersion != 7 || got.UserAuthority != 11 || got.Generation != 3 {
		t.Fatal("authenticated original mutation inputs did not survive", err)
	}
	got.Current.Attributes["userName"] = "Changed detached copy"
	if input.Current.Attributes["userName"] != "Original" {
		t.Fatal("original mutation projection was aliased")
	}
	for _, change := range []func(*originalInput){
		func(i *originalInput) { i.Operation = scim.UserReplace },
		func(i *originalInput) { i.UserAuthority = 0 },
		func(i *originalInput) { i.Generation = 0 },
		func(i *originalInput) { i.KernelVersion = 0 },
		func(i *originalInput) { i.Current = nil },
	} {
		changed := input
		change(&changed)
		if _, err := p.restoreOriginal(context.Background(), binding, sealOriginalInput(t, p, binding, changed)); err == nil {
			t.Fatal("incomplete or changed original mutation custody admitted")
		}
	}
	p.intent.ResourceID = "changed-target"
	if _, err := p.restoreOriginal(context.Background(), binding, wire); err == nil {
		t.Fatal("authenticated ciphertext moved to a different target")
	}
}

func FuzzOriginalMetadataEnvelope(f *testing.F) {
	p, b, wire := preparationCodec(f)
	mutation, mutationBinding, mutationInput := mutationPreparationCodec(f)
	f.Add(wire)
	f.Add(sealOriginalInput(f, mutation, mutationBinding, mutationInput))
	f.Add([]byte{})
	f.Add([]byte("invalid envelope"))
	f.Fuzz(func(t *testing.T, input []byte) {
		if len(input) > originalCiphertextBytes+1 {
			return
		}
		for _, codec := range []struct {
			phase   *nativePhase
			binding kernel.RequestKeyPreparationBinding
		}{{p, b}, {mutation, mutationBinding}} {
			got, err := codec.phase.restoreOriginal(context.Background(), codec.binding, input)
			if err == nil && (got.Command != codec.binding.Admission.CommandID || got.Profile != codec.phase.service.profile || got.ID == "" || codec.phase == mutation && (got.Schema != 2 || got.Current == nil || got.KernelVersion == 0 || got.UserAuthority == 0 || got.Generation < 1)) {
				t.Fatal("invalid protected input admitted")
			}
		}
	})
}
