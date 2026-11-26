package scimpostgres

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"strings"
	"testing"

	identity "github.com/faustbrian/go-identity"
	organization "github.com/faustbrian/go-organization"
	scim "github.com/faustbrian/go-scim"
)

func managedConnectionCursorTestID(value byte) string {
	var raw [16]byte
	raw[0] = value
	return base64.RawURLEncoding.EncodeToString(raw[:])
}

func TestManagedConnectionCursorRoundTripAndScopeBinding(t *testing.T) {
	tenant := identity.TenantID(managedConnectionCursorTestID(1))
	org := organization.ID(managedConnectionCursorTestID(2))
	after := scim.ConnectionID(managedConnectionCursorTestID(3))
	key := [32]byte{9}
	raw := encodeManagedConnectionCursor(tenant, org, after, key)
	if raw == "" {
		t.Fatal("valid managed connection cursor was not encoded")
	}
	if got, ok := decodeManagedConnectionCursor(raw, tenant, org, key); !ok || got != after {
		t.Fatal("cursor did not preserve its last connection ID")
	}
	if got := encodeManagedConnectionCursor(tenant, org, after, key); got != raw {
		t.Fatal("unchanged page boundary did not preserve canonical representation")
	}
	if got, ok := decodeManagedConnectionCursor("", tenant, org, key); !ok || got != "" {
		t.Fatal("valid empty cursor did not select the initial page")
	}
	for _, tc := range []struct {
		name   string
		tenant identity.TenantID
		org    organization.ID
		key    [32]byte
	}{
		{"different tenant", identity.TenantID(managedConnectionCursorTestID(4)), org, key},
		{"different organization", tenant, organization.ID(managedConnectionCursorTestID(4)), key},
		{"swapped scope", identity.TenantID(org), organization.ID(tenant), key},
		{"different key", tenant, org, [32]byte{10}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got, ok := decodeManagedConnectionCursor(raw, tc.tenant, tc.org, tc.key); ok || got != "" {
				t.Fatal("cursor escaped its tenant, organization or signing-key scope")
			}
		})
	}
}

func TestManagedConnectionCursorRejectsInvalidScopeAndKeyBeforeInitialPage(t *testing.T) {
	tenant := identity.TenantID(managedConnectionCursorTestID(1))
	org := organization.ID(managedConnectionCursorTestID(2))
	after := scim.ConnectionID(managedConnectionCursorTestID(3))
	key := [32]byte{9}
	raw := encodeManagedConnectionCursor(tenant, org, after, key)
	invalidIDs := []string{"", strings.Repeat("A", 22), string(tenant) + "==", string(tenant)[:21] + "B", "legacy-id", strings.Repeat("x", 4096)}
	for _, bad := range invalidIDs {
		for _, scope := range []struct {
			tenant identity.TenantID
			org    organization.ID
		}{{identity.TenantID(bad), org}, {tenant, organization.ID(bad)}} {
			if encodeManagedConnectionCursor(scope.tenant, scope.org, after, key) != "" {
				t.Fatal("invalid cursor scope was encoded")
			}
			for _, candidate := range []string{"", raw} {
				if got, ok := decodeManagedConnectionCursor(candidate, scope.tenant, scope.org, key); ok || got != "" {
					t.Fatal("invalid scope selected an initial or subsequent page")
				}
			}
		}
		if encodeManagedConnectionCursor(tenant, org, scim.ConnectionID(bad), key) != "" {
			t.Fatal("invalid last connection ID was encoded")
		}
	}
	if encodeManagedConnectionCursor(tenant, org, after, [32]byte{}) != "" {
		t.Fatal("zero signing key was encoded")
	}
	for _, candidate := range []string{"", raw} {
		if got, ok := decodeManagedConnectionCursor(candidate, tenant, org, [32]byte{}); ok || got != "" {
			t.Fatal("zero signing key selected an initial or subsequent page")
		}
	}
}

func TestManagedConnectionCursorRejectsNoncanonicalAndTamperedInputs(t *testing.T) {
	tenant := identity.TenantID(managedConnectionCursorTestID(1))
	org := organization.ID(managedConnectionCursorTestID(2))
	after := scim.ConnectionID(managedConnectionCursorTestID(3))
	key := [32]byte{9}
	raw := encodeManagedConnectionCursor(tenant, org, after, key)
	if raw == "" {
		t.Fatal("valid managed connection cursor was not encoded")
	}
	for _, candidate := range []string{
		"not-a-cursor", raw[:len(raw)-1], raw + "x", raw + "=", " " + raw,
		raw + "\n", raw[:20] + "\r" + raw[21:], strings.Repeat("x", 4097),
	} {
		if got, ok := decodeManagedConnectionCursor(candidate, tenant, org, key); ok || got != "" {
			t.Fatal("malformed cursor selected a page or leaked a partial ID")
		}
	}
	// Every byte belongs to the version, page boundary or authenticator.
	payload, err := base64.RawURLEncoding.Strict().DecodeString(raw)
	if err != nil || len(payload) != 55 {
		t.Fatal("cursor did not use the bounded version/ID/authenticator representation")
	}
	for i := range payload {
		changed := append([]byte(nil), payload...)
		changed[i] ^= 1
		if got, ok := decodeManagedConnectionCursor(base64.RawURLEncoding.EncodeToString(changed), tenant, org, key); ok || got != "" {
			t.Fatalf("tampering with cursor byte %d selected a page", i)
		}
	}
	// Raw URL encoding's unused bits must not provide aliases of a valid cursor.
	const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
	last := strings.IndexByte(alphabet, raw[len(raw)-1])
	alias := raw[:len(raw)-1] + string(alphabet[last+1])
	if got, ok := decodeManagedConnectionCursor(alias, tenant, org, key); ok || got != "" {
		t.Fatal("noncanonical base64 alias selected a page")
	}
}

func TestManagedConnectionCursorAuthenticatesItsExactDomainAndCanonicalID(t *testing.T) {
	tenant := identity.TenantID(managedConnectionCursorTestID(1))
	org := organization.ID(managedConnectionCursorTestID(2))
	after := managedConnectionCursorTestID(3)
	key := [32]byte{9}
	const domain = "scim-postgres/managed-connection-list-cursor/v1\x00"
	// The independent encoder also creates authenticated but invalid payloads;
	// an authentic MAC must not bypass version or canonical-ID admission.
	sign := func(version byte, id, purpose string) string {
		payload := append([]byte{version}, id...)
		mac := hmac.New(sha256.New, key[:])
		_, _ = mac.Write([]byte(purpose))
		_, _ = mac.Write([]byte(tenant))
		_, _ = mac.Write([]byte(org))
		_, _ = mac.Write(payload)
		return base64.RawURLEncoding.EncodeToString(mac.Sum(payload))
	}
	if raw := sign(1, after, domain); raw != encodeManagedConnectionCursor(tenant, org, scim.ConnectionID(after), key) {
		t.Fatal("cursor does not bind its exact domain, scope and payload")
	}
	for _, raw := range []string{
		sign(2, after, domain), sign(1, strings.Repeat("A", 22), domain),
		sign(1, after[:21]+"B", domain), sign(1, after[:21]+"+", domain),
		sign(1, after, "scim-postgres/managed-bearer/v1\x00"),
	} {
		if got, ok := decodeManagedConnectionCursor(raw, tenant, org, key); ok || got != "" {
			t.Fatal("authenticated wrong-purpose, unsupported-version or invalid-ID cursor selected a page")
		}
	}
}

func FuzzManagedConnectionCursor(f *testing.F) {
	tenant := identity.TenantID(managedConnectionCursorTestID(1))
	org := organization.ID(managedConnectionCursorTestID(2))
	after := scim.ConnectionID(managedConnectionCursorTestID(3))
	key := [32]byte{9}
	f.Add("")
	f.Add(encodeManagedConnectionCursor(tenant, org, after, key))
	f.Add(strings.Repeat("x", 4097))
	f.Fuzz(func(t *testing.T, raw string) {
		got, ok := decodeManagedConnectionCursor(raw, tenant, org, key)
		if !ok {
			if got != "" {
				t.Fatal("rejected cursor disclosed a partial page boundary")
			}
			return
		}
		if raw == "" {
			if got != "" {
				t.Fatal("initial-page cursor returned a boundary")
			}
			return
		}
		if _, err := scim.ParseConnectionID(string(got)); err != nil || encodeManagedConnectionCursor(tenant, org, got, key) != raw {
			t.Fatal("accepted cursor was not an exact canonical round trip")
		}
	})
}
