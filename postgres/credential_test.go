package scimpostgres

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	authentication "github.com/faustbrian/go-authentication/v2"
)

func TestConfiguredCredentialIsScopedOpaqueAndExact(t *testing.T) {
	secret := strings.Repeat("native-scim-private-", 3)
	credential, err := NewConfiguredCredential("credential-a", authentication.NewBearerCredential(secret), [32]byte{1})
	if err != nil {
		t.Fatal(err)
	}
	for _, verb := range []string{"%v", "%+v", "%#v", "%s"} {
		if strings.Contains(fmt.Sprintf(verb, credential), secret) {
			t.Fatal("configured credential disclosed")
		}
	}
	if _, err := json.Marshal(credential); err == nil {
		t.Fatal("configured credential serialized")
	}
	if !credential.matches(authentication.NewBearerCredential(secret)) || credential.matches(authentication.NewBearerCredential(secret+" ")) {
		t.Fatal("credential comparison changed bytes")
	}
	other, err := NewConfiguredCredential("credential-b", authentication.NewBearerCredential(secret), [32]byte{1})
	if err != nil || credential.digest() == other.digest() {
		t.Fatal("credential ID missing from digest domain")
	}
	for _, token := range []string{"", "short", strings.Repeat("x", 4097)} {
		if _, err := NewConfiguredCredential("credential-a", authentication.NewBearerCredential(token), [32]byte{1}); err == nil {
			t.Fatal("invalid credential accepted")
		}
	}
	if _, err := NewConfiguredCredential("credential-a", authentication.NewBearerCredential(secret), [32]byte{}); err == nil {
		t.Fatal("missing lookup key accepted")
	}
}

func TestConfiguredCredentialRejectsUnusableProtocolInputs(t *testing.T) {
	for _, token := range []string{strings.Repeat("a", 32) + "$", strings.Repeat("a", 32) + "=b", strings.Repeat("=", 32)} {
		if _, err := NewConfiguredCredential("credential", authentication.NewBearerCredential(token), [32]byte{1}); err == nil {
			t.Fatal("configured bearer cannot pass SCIM protocol admission")
		}
	}
	for _, id := range []string{"credential/one", "credential?one", "credential#one", "credential\\one"} {
		if _, err := NewConfiguredCredential(id, authentication.NewBearerCredential(strings.Repeat("a", 32)), [32]byte{1}); err == nil {
			t.Fatal("configured credential ID cannot pass SCIM protocol admission")
		}
	}
}
