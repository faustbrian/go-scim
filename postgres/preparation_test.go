package scimpostgres

import (
	"bytes"
	"context"
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

func FuzzOriginalMetadataEnvelope(f *testing.F) {
	p, b, wire := preparationCodec(f)
	f.Add(wire)
	f.Add([]byte{})
	f.Add([]byte("invalid envelope"))
	f.Fuzz(func(t *testing.T, input []byte) {
		if len(input) > 16384 {
			return
		}
		got, err := p.restoreOriginal(context.Background(), b, input)
		if err == nil && (got.Command != b.Admission.CommandID || got.Profile != p.service.profile || got.ID == "") {
			t.Fatal("invalid protected input admitted")
		}
	})
}
