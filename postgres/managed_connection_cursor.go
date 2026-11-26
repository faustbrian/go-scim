package scimpostgres

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"

	identity "github.com/faustbrian/go-identity"
	organization "github.com/faustbrian/go-organization"
	scim "github.com/faustbrian/go-scim"
)

// Managed IDs are canonical 22-byte encodings. A version byte, last ID and
// SHA-256 authenticator give one fixed bounded wire shape for List pagination.
const (
	managedConnectionCursorPayloadBytes = 1 + 22
	managedConnectionCursorBytes        = managedConnectionCursorPayloadBytes + sha256.Size
	managedConnectionCursorLength       = 74
)

func encodeManagedConnectionCursor(tenant identity.TenantID, org organization.ID, after scim.ConnectionID, key [32]byte) string {
	if !managedConnectionCursorScopeValid(tenant, org, key) {
		return ""
	}
	if _, err := scim.ParseConnectionID(string(after)); err != nil {
		return ""
	}
	var cursor [managedConnectionCursorBytes]byte
	cursor[0] = 1
	copy(cursor[1:managedConnectionCursorPayloadBytes], after)
	digest := managedConnectionCursorDigest(tenant, org, cursor[:managedConnectionCursorPayloadBytes], key)
	copy(cursor[managedConnectionCursorPayloadBytes:], digest[:])
	return base64.RawURLEncoding.EncodeToString(cursor[:])
}

func decodeManagedConnectionCursor(raw string, tenant identity.TenantID, org organization.ID, key [32]byte) (scim.ConnectionID, bool) {
	if len(raw) != 0 && len(raw) != managedConnectionCursorLength {
		return "", false
	}
	if !managedConnectionCursorScopeValid(tenant, org, key) {
		return "", false
	}
	if raw == "" {
		return "", true
	}
	var cursor [managedConnectionCursorBytes]byte
	n, err := base64.RawURLEncoding.Strict().Decode(cursor[:], []byte(raw))
	if err != nil || n != len(cursor) || cursor[0] != 1 || base64.RawURLEncoding.EncodeToString(cursor[:]) != raw {
		return "", false
	}
	digest := managedConnectionCursorDigest(tenant, org, cursor[:managedConnectionCursorPayloadBytes], key)
	if !hmac.Equal(cursor[managedConnectionCursorPayloadBytes:], digest[:]) {
		return "", false
	}
	after, err := scim.ParseConnectionID(string(cursor[1:managedConnectionCursorPayloadBytes]))
	if err != nil {
		return "", false
	}
	return after, true
}

func managedConnectionCursorScopeValid(tenant identity.TenantID, org organization.ID, key [32]byte) bool {
	if key == ([32]byte{}) {
		return false
	}
	if _, err := identity.ParseSubjectID(string(tenant)); err != nil {
		return false
	}
	_, err := identity.ParseSubjectID(string(org))
	return err == nil
}

func managedConnectionCursorDigest(tenant identity.TenantID, org organization.ID, payload []byte, key [32]byte) [32]byte {
	mac := hmac.New(sha256.New, key[:])
	_, _ = mac.Write([]byte("scim-postgres/managed-connection-list-cursor/v1\x00"))
	// Canonical tenant and organization IDs have fixed lengths, so these
	// fields cannot be reframed. Binding a cursor does not authorize its use.
	_, _ = mac.Write([]byte(tenant))
	_, _ = mac.Write([]byte(org))
	_, _ = mac.Write(payload)
	var digest [32]byte
	copy(digest[:], mac.Sum(nil))
	return digest
}
