// Package scimpostgres supplies the selected native SCIM create/read profile.
package scimpostgres

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/binary"
	"errors"
	"fmt"
	"strings"

	authentication "github.com/faustbrian/go-authentication/v2"
)

// ErrInvalidConfiguration is a redacted admission failure. Provider, database
// and credential diagnostics are never included in this error.
var ErrInvalidConfiguration = errors.New("scim postgres: invalid configuration")

// ConfiguredCredential is immutable trusted deployment custody for one
// preprovisioned credential. It retains a keyed digest, never the bearer itself.
// The lookup key must be dedicated to this deployment and retained unchanged
// while its configured connections exist. Copies share immutable key custody;
// concurrent comparisons are supported. Zero values cannot authenticate.
type ConfiguredCredential struct {
	id       string
	lookup   func(authentication.BearerCredential) ([32]byte, bool)
	expected [32]byte
}

// NewConfiguredCredential validates one exact credential without IO. The local
// 32..4096-byte RFC 6750 bearer-token bound is an adapter admission policy, not an RFC
// entropy guarantee: generate the actual bearer using a cryptographic source.
// Credential IDs are 1..128 printable ASCII bytes without SCIM path delimiters.
// Neither ID nor token is
// normalized. A nonzero dedicated 256-bit HMAC key is required; caller bytes are
// copied into private closure custody rather than a publicly inspectable field.
func NewConfiguredCredential(id string, bearer authentication.BearerCredential, key [32]byte) (ConfiguredCredential, error) {
	if !configuredID(id) || !configuredBearer(bearer.Token()) || key == ([32]byte{}) {
		return ConfiguredCredential{}, ErrInvalidConfiguration
	}
	lookup := func(candidate authentication.BearerCredential) ([32]byte, bool) {
		if !configuredBearer(candidate.Token()) {
			return [32]byte{}, false
		}
		h := hmac.New(sha256.New, key[:])
		_, _ = h.Write([]byte("scim-postgres/configured-credential/v1\x00"))
		var length [8]byte
		binary.BigEndian.PutUint64(length[:], uint64(len(id)))
		_, _ = h.Write(length[:])
		_, _ = h.Write([]byte(id))
		binary.BigEndian.PutUint64(length[:], uint64(len(candidate.Token())))
		_, _ = h.Write(length[:])
		_, _ = h.Write([]byte(candidate.Token()))
		var digest [32]byte
		copy(digest[:], h.Sum(nil))
		return digest, true
	}
	expected, _ := lookup(bearer)
	return ConfiguredCredential{id: id, lookup: lookup, expected: expected}, nil
}

func configuredID(value string) bool {
	return boundedASCII(value, 1, 128) && !strings.ContainsAny(value, "/\\?#")
}

func configuredBearer(value string) bool {
	if len(value) < 32 || len(value) > 4096 || value[0] == '=' {
		return false
	}
	padding := false
	for i := range len(value) {
		b := value[i]
		if b == '=' {
			padding = true
			continue
		}
		if padding || !(b >= 'a' && b <= 'z' || b >= 'A' && b <= 'Z' || b >= '0' && b <= '9' || strings.ContainsRune("-._~+/", rune(b))) {
			return false
		}
	}
	return true
}

func boundedASCII(value string, minimum, maximum int) bool {
	if len(value) < minimum || len(value) > maximum {
		return false
	}
	for i := range len(value) {
		if value[i] < 0x21 || value[i] > 0x7e {
			return false
		}
	}
	return true
}

func (c ConfiguredCredential) matches(candidate authentication.BearerCredential) bool {
	if c.lookup == nil {
		return false
	}
	digest, valid := c.lookup(candidate)
	return subtle.ConstantTimeCompare(digest[:], c.expected[:]) == 1 && valid
}

func (c ConfiguredCredential) digest() [32]byte { return c.expected }

// Format redacts credential identity and digest for every formatting verb.
func (ConfiguredCredential) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("scimpostgres.ConfiguredCredential(redacted)"))
}

// MarshalJSON forbids exporting credential custody or verification material.
func (ConfiguredCredential) MarshalJSON() ([]byte, error) { return nil, ErrInvalidConfiguration }
