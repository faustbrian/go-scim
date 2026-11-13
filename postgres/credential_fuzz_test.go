package scimpostgres

import (
	"strings"
	"testing"

	authentication "github.com/faustbrian/go-authentication/v2"
)

func FuzzConfiguredCredentialBounds(f *testing.F) {
	f.Add("", "credential")
	f.Add(strings.Repeat("a", 32), "credential")
	f.Add(strings.Repeat("x", 4097), "credential")
	f.Fuzz(func(t *testing.T, token, id string) {
		if len(token) > 8192 || len(id) > 256 {
			return
		}
		credential, err := NewConfiguredCredential(id, authentication.NewBearerCredential(token), [32]byte{7})
		if err == nil && !credential.matches(authentication.NewBearerCredential(token)) {
			t.Fatal("exact configured bytes failed")
		}
		if err != nil && credential.lookup != nil {
			t.Fatal("invalid credential retained key custody")
		}
	})
}
