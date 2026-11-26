package scimpostgres

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	authentication "github.com/faustbrian/go-authentication/v2"
	identity "github.com/faustbrian/go-identity"
	organization "github.com/faustbrian/go-organization"
	scim "github.com/faustbrian/go-scim"
)

func managedBearerTestScope() scim.ConnectionScope {
	id := func(value byte) string {
		var raw [16]byte
		raw[0] = value
		return base64.RawURLEncoding.EncodeToString(raw[:])
	}
	return scim.ConnectionScope{
		TenantID: identity.TenantID(id(1)), OrganizationID: organization.ID(id(2)),
		ProviderID: "directory-provider", ProviderConnectionID: scim.ConnectionID(id(3)),
	}
}

func managedBearerTestCredentialID() identity.SubjectID {
	var raw [16]byte
	raw[0] = 4
	return identity.SubjectID(base64.RawURLEncoding.EncodeToString(raw[:]))
}

func TestManagedBearerIssueRoundTripAndExactDigest(t *testing.T) {
	scope, credentialID, key := managedBearerTestScope(), managedBearerTestCredentialID(), [32]byte{9}
	bearer, digest, err := issueManagedBearer(scope, credentialID, key)
	if err != nil {
		t.Fatal("valid managed bearer issuance failed")
	}
	connection, credential, ok := parseManagedBearer(bearer)
	if !ok || connection != scope.ProviderConnectionID || credential != credentialID {
		t.Fatal("issued bearer did not preserve independently supplied IDs")
	}
	parts := strings.Split(bearer.Token(), ".")
	if len(parts) != 4 || parts[0] != "scim1" || len(parts[3]) != 43 || len(bearer.Token()) != 95 {
		t.Fatal("issued bearer has incorrect purpose or component bounds")
	}
	secret, err := base64.RawURLEncoding.Strict().DecodeString(parts[3])
	if err != nil || len(secret) != 32 || base64.RawURLEncoding.EncodeToString(secret) != parts[3] {
		t.Fatal("issued bearer secret is not canonical 256-bit material")
	}
	mac := hmac.New(sha256.New, key[:])
	_, _ = mac.Write([]byte("scim-postgres/managed-bearer/v1\x00"))
	for _, field := range []string{string(scope.TenantID), string(scope.OrganizationID), string(scope.ProviderID), string(scope.ProviderConnectionID), string(credentialID), bearer.Token()} {
		var length [8]byte
		binary.BigEndian.PutUint64(length[:], uint64(len(field)))
		_, _ = mac.Write(length[:])
		_, _ = mac.Write([]byte(field))
	}
	var expected [32]byte
	copy(expected[:], mac.Sum(nil))
	if digest == ([32]byte{}) || digest != expected || !matchManagedBearer(scope, credentialID, key, bearer, expected) {
		t.Fatal("managed bearer digest does not bind the complete framed domain")
	}
	other, otherDigest, err := issueManagedBearer(scope, credentialID, key)
	if err != nil || other.Token() == bearer.Token() || otherDigest == digest {
		t.Fatal("separate issuance reused bearer material")
	}
	configured, err := NewConfiguredCredential(string(credentialID), bearer, key)
	if err != nil || configured.digest() == digest {
		t.Fatal("managed and configured credential digest purposes overlap")
	}
}

func TestManagedBearerRejectsMalformedAndWrongPurpose(t *testing.T) {
	scope, credentialID, key := managedBearerTestScope(), managedBearerTestCredentialID(), [32]byte{9}
	bearer, digest, err := issueManagedBearer(scope, credentialID, key)
	if err != nil {
		t.Fatal("valid managed bearer issuance failed")
	}
	parts := strings.Split(bearer.Token(), ".")
	for _, tc := range []struct{ name, token string }{
		{"empty", ""}, {"legacy", strings.Repeat("a", 95)},
		{"wrong purpose", "other" + bearer.Token()[5:]},
		{"wrong version", "scim2" + bearer.Token()[5:]},
		{"extra component", bearer.Token() + ".x"},
		{"oversized", strings.Repeat("x", 4097)},
		{"short secret", bearer.Token()[:94]},
		{"padded secret", bearer.Token() + "="},
		{"padded connection", "scim1." + parts[1] + "=." + parts[2] + "." + parts[3]},
		{"padded credential", "scim1." + parts[1] + "." + parts[2] + "=." + parts[3]},
		{"zero connection", "scim1." + strings.Repeat("A", 22) + "." + parts[2] + "." + parts[3]},
		{"zero credential", "scim1." + parts[1] + "." + strings.Repeat("A", 22) + "." + parts[3]},
		{"noncanonical connection", "scim1." + parts[1][:21] + "B." + parts[2] + "." + parts[3]},
		{"noncanonical credential", "scim1." + parts[1] + "." + parts[2][:21] + "B." + parts[3]},
		{"noncanonical secret", bearer.Token()[:94] + "B"},
		{"invalid secret character", bearer.Token()[:94] + "+"},
		{"newline secret", bearer.Token()[:94] + "\n"},
		{"space suffix", bearer.Token()[:94] + " "},
		{"missing separator", bearer.Token()[:28] + "_" + bearer.Token()[29:]},
	} {
		t.Run(tc.name, func(t *testing.T) {
			candidate := authentication.NewBearerCredential(tc.token)
			connection, credential, ok := parseManagedBearer(candidate)
			if ok || connection != "" || credential != "" {
				t.Fatal("malformed bearer exposed a successful or partial parse")
			}
			candidateDigest := managedBearerDigest(scope, credentialID, key, candidate)
			if matchManagedBearer(scope, credentialID, key, candidate, digest) || matchManagedBearer(scope, credentialID, key, candidate, candidateDigest) {
				t.Fatal("malformed bearer authenticated")
			}
		})
	}
}

func TestManagedBearerMatchBindsEveryScopeAndCredentialField(t *testing.T) {
	scope, credentialID, key := managedBearerTestScope(), managedBearerTestCredentialID(), [32]byte{9}
	bearer, digest, err := issueManagedBearer(scope, credentialID, key)
	if err != nil {
		t.Fatal("valid managed bearer issuance failed")
	}
	for _, tc := range []struct {
		name   string
		change func(*scim.ConnectionScope)
	}{
		{"tenant", func(s *scim.ConnectionScope) { s.TenantID = identity.TenantID(credentialID) }},
		{"organization", func(s *scim.ConnectionScope) { s.OrganizationID = organization.ID(credentialID) }},
		{"provider", func(s *scim.ConnectionScope) { s.ProviderID += "-other" }},
		{"connection", func(s *scim.ConnectionScope) { s.ProviderConnectionID = scim.ConnectionID(credentialID) }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			changed := scope
			tc.change(&changed)
			if matchManagedBearer(changed, credentialID, key, bearer, digest) {
				t.Fatal("cross-scope bearer authenticated")
			}
		})
	}
	if matchManagedBearer(scope, identity.SubjectID(scope.ProviderConnectionID), key, bearer, digest) ||
		matchManagedBearer(scope, credentialID, [32]byte{10}, bearer, digest) ||
		matchManagedBearer(scope, credentialID, [32]byte{}, bearer, digest) ||
		matchManagedBearer(scope, credentialID, key, bearer, [32]byte{}) {
		t.Fatal("wrong credential, key or absent digest authenticated")
	}
	changedDigest := digest
	changedDigest[31] ^= 1
	parts := strings.Split(bearer.Token(), ".")
	secret, _ := base64.RawURLEncoding.DecodeString(parts[3])
	secret[0] ^= 1
	parts[3] = base64.RawURLEncoding.EncodeToString(secret)
	if matchManagedBearer(scope, credentialID, key, bearer, changedDigest) ||
		matchManagedBearer(scope, credentialID, key, authentication.NewBearerCredential(strings.Join(parts, ".")), digest) {
		t.Fatal("changed digest or canonical secret authenticated")
	}
}

func TestManagedBearerRejectsInvalidNativeScopeAndIDsWithoutDiagnostics(t *testing.T) {
	scope, credentialID, key := managedBearerTestScope(), managedBearerTestCredentialID(), [32]byte{9}
	bearer, digest, err := issueManagedBearer(scope, credentialID, key)
	if err != nil {
		t.Fatal("valid managed bearer issuance failed")
	}
	for _, tc := range []struct {
		name   string
		change func(*scim.ConnectionScope)
	}{
		{"empty tenant", func(s *scim.ConnectionScope) { s.TenantID = "" }},
		{"malformed tenant", func(s *scim.ConnectionScope) { s.TenantID = "tenant" }},
		{"empty organization", func(s *scim.ConnectionScope) { s.OrganizationID = "" }},
		{"noncanonical organization", func(s *scim.ConnectionScope) { s.OrganizationID += "=" }},
		{"empty provider", func(s *scim.ConnectionScope) { s.ProviderID = "" }},
		{"long provider", func(s *scim.ConnectionScope) { s.ProviderID = scim.ProviderID(strings.Repeat("p", 129)) }},
		{"nonascii provider", func(s *scim.ConnectionScope) { s.ProviderID = "dírectory" }},
		{"provider delimiter", func(s *scim.ConnectionScope) { s.ProviderID = "directory/other" }},
		{"provider space", func(s *scim.ConnectionScope) { s.ProviderID = "directory other" }},
		{"malformed connection", func(s *scim.ConnectionScope) { s.ProviderConnectionID = "connection" }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			invalid := scope
			tc.change(&invalid)
			issued, value, err := issueManagedBearer(invalid, credentialID, key)
			if err != ErrInvalidConfiguration || issued.Token() != "" || value != ([32]byte{}) {
				t.Fatal("invalid native scope did not fail closed with redacted error")
			}
			invalidScopeDigest := managedBearerDigest(invalid, credentialID, key, bearer)
			if matchManagedBearer(invalid, credentialID, key, bearer, digest) || matchManagedBearer(invalid, credentialID, key, bearer, invalidScopeDigest) {
				t.Fatal("invalid native scope authenticated")
			}
		})
	}
	for _, id := range []identity.SubjectID{"", "credential", identity.SubjectID(strings.Repeat("A", 22)), credentialID + "="} {
		issued, value, err := issueManagedBearer(scope, id, key)
		if err != ErrInvalidConfiguration || issued.Token() != "" || value != ([32]byte{}) || matchManagedBearer(scope, id, key, bearer, digest) {
			t.Fatal("invalid credential ID did not fail closed")
		}
	}
	if issued, value, err := issueManagedBearer(scope, credentialID, [32]byte{}); err != ErrInvalidConfiguration || issued.Token() != "" || value != ([32]byte{}) {
		t.Fatal("zero key admitted bearer issuance")
	}
	for _, verb := range []string{"%v", "%+v", "%#v", "%s", "%q"} {
		if strings.Contains(fmt.Sprintf(verb, bearer), bearer.Token()) {
			t.Fatal("bearer formatting disclosed secret material")
		}
	}
	encoded, err := json.Marshal(bearer)
	if err != nil || strings.Contains(string(encoded), bearer.Token()) {
		t.Fatal("bearer JSON disclosed secret material")
	}
}

func FuzzManagedBearerCanonicalBounded(f *testing.F) {
	scope, credentialID := managedBearerTestScope(), managedBearerTestCredentialID()
	var secret [32]byte
	canonical := "scim1." + string(scope.ProviderConnectionID) + "." + string(credentialID) + "." + base64.RawURLEncoding.EncodeToString(secret[:])
	for _, seed := range []string{"", canonical, canonical + "=", strings.Repeat("x", 4097)} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, token string) {
		connection, credential, ok := parseManagedBearer(authentication.NewBearerCredential(token))
		if !ok {
			if connection != "" || credential != "" {
				t.Fatal("invalid bearer exposed partial routing identifiers")
			}
			return
		}
		if len(token) != 95 || connection == "" || credential == "" {
			t.Fatal("parser accepted invalid bounds or empty routing identifiers")
		}
		parts := strings.Split(token, ".")
		if len(parts) != 4 {
			t.Fatal("parser accepted invalid component count")
		}
		decoded, err := base64.RawURLEncoding.Strict().DecodeString(parts[3])
		if err != nil || len(decoded) != 32 {
			t.Fatal("parser accepted malformed secret encoding")
		}
		rebuilt := "scim1." + string(connection) + "." + string(credential) + "." + base64.RawURLEncoding.EncodeToString(decoded)
		if rebuilt != token {
			t.Fatal("parser accepted a noncanonical bearer")
		}
	})
}
