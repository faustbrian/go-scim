package scimpostgres

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/binary"
	"strings"

	authentication "github.com/faustbrian/go-authentication/v2"
	identity "github.com/faustbrian/go-identity"
	scim "github.com/faustbrian/go-scim"
)

// The managed profile keeps routing identifiers distinct from configured bearer
// material. Its fixed 95-byte representation bounds decoding and digest work.
const managedBearerLength = len("scim1.") + 22 + 1 + 22 + 1 + 43

func issueManagedBearer(scope scim.ConnectionScope, credentialID identity.SubjectID, key [32]byte) (authentication.BearerCredential, [32]byte, error) {
	if !managedBearerInputsValid(scope, credentialID, key) {
		return authentication.BearerCredential{}, [32]byte{}, ErrInvalidConfiguration
	}
	var secret [32]byte
	if _, err := rand.Read(secret[:]); err != nil {
		return authentication.BearerCredential{}, [32]byte{}, ErrInvalidConfiguration
	}
	token := "scim1." + string(scope.ProviderConnectionID) + "." + string(credentialID) + "." + base64.RawURLEncoding.EncodeToString(secret[:])
	bearer := authentication.NewBearerCredential(token)
	digest := managedBearerDigest(scope, credentialID, key, bearer)
	if digest == ([32]byte{}) {
		return authentication.BearerCredential{}, [32]byte{}, ErrInvalidConfiguration
	}
	return bearer, digest, nil
}

func parseManagedBearer(bearer authentication.BearerCredential) (scim.ConnectionID, identity.SubjectID, bool) {
	token := bearer.Token()
	if len(token) != managedBearerLength || !strings.HasPrefix(token, "scim1.") || token[28] != '.' || token[51] != '.' {
		return "", "", false
	}
	connectionID, err := scim.ParseConnectionID(token[6:28])
	if err != nil {
		return "", "", false
	}
	credentialID, err := identity.ParseSubjectID(token[29:51])
	if err != nil {
		return "", "", false
	}
	var secret [32]byte
	encodedSecret := token[52:]
	n, err := base64.RawURLEncoding.Strict().Decode(secret[:], []byte(encodedSecret))
	if err != nil || n != len(secret) || base64.RawURLEncoding.EncodeToString(secret[:]) != encodedSecret {
		return "", "", false
	}
	return connectionID, credentialID, true
}

func matchManagedBearer(scope scim.ConnectionScope, credentialID identity.SubjectID, key [32]byte, bearer authentication.BearerCredential, expected [32]byte) bool {
	if expected == ([32]byte{}) || !managedBearerInputsValid(scope, credentialID, key) {
		return false
	}
	connection, credential, ok := parseManagedBearer(bearer)
	if !ok || connection != scope.ProviderConnectionID || credential != credentialID {
		return false
	}
	digest := managedBearerDigest(scope, credentialID, key, bearer)
	return subtle.ConstantTimeCompare(digest[:], expected[:]) == 1
}

func managedBearerInputsValid(scope scim.ConnectionScope, credentialID identity.SubjectID, key [32]byte) bool {
	if key == ([32]byte{}) {
		return false
	}
	for _, id := range [...]string{string(scope.TenantID), string(scope.OrganizationID), string(scope.ProviderConnectionID), string(credentialID)} {
		if _, err := identity.ParseSubjectID(id); err != nil {
			return false
		}
	}
	// Match the provider admission in scim.NewConnectionRecord; the legacy
	// configured path intentionally retains its separate scope policy.
	provider := string(scope.ProviderID)
	return boundedASCII(provider, 1, 128) && !strings.ContainsAny(provider, "/\\?#")
}

func managedBearerDigest(scope scim.ConnectionScope, credentialID identity.SubjectID, key [32]byte, bearer authentication.BearerCredential) [32]byte {
	mac := hmac.New(sha256.New, key[:])
	_, _ = mac.Write([]byte("scim-postgres/managed-bearer/v1\x00"))
	for _, value := range [...]string{string(scope.TenantID), string(scope.OrganizationID), string(scope.ProviderID), string(scope.ProviderConnectionID), string(credentialID), bearer.Token()} {
		var length [8]byte
		binary.BigEndian.PutUint64(length[:], uint64(len(value)))
		_, _ = mac.Write(length[:])
		_, _ = mac.Write([]byte(value))
	}
	var digest [32]byte
	copy(digest[:], mac.Sum(nil))
	return digest
}
