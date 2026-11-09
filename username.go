package scim

import (
	"unicode/utf8"

	"golang.org/x/text/cases"
	"golang.org/x/text/language"
	"golang.org/x/text/secure/precis"
	"golang.org/x/text/unicode/norm"
	"golang.org/x/text/width"
)

// UsernameComparisonProfile identifies the stable core userName comparison and
// uniqueness policy. It uses RFC 8265 UsernameCaseMapped with Unicode 17.0.0
// data from golang.org/x/text v0.42.0. Persisted indexes must bind this identity;
// changing it requires explicit collision reconciliation and index migration.
const UsernameComparisonProfile = "scim-username-rfc8265-ucd17.0.0-v1"

const maxUsernameBytes = 65536

// Capture the standard immutable profile, not the exported variable's later
// assignments. Its selected root-locale casing transformer is stateless.
var usernameCaseMapped = precis.UsernameCaseMapped

// UsernameComparisonKey prepares a core userName for comparison and atomic
// Store uniqueness checks under UsernameComparisonProfile. It does not rewrite
// a resource, identifier or caller input, and confers no ownership or authority.
// Input must be nonempty valid UTF-8 and at most 65,536 bytes, the profile's
// maximum source-string boundary; services also enforce effective limits.
// Preparation may expand that bounded input. Callers own the returned key and
// must not truncate it or substitute an independently normalized representation.
// Width mapping, lowercase mapping, NFC, IdentifierClass/context and Bidi rules
// are enforced by the pinned upstream PRECIS implementation, not a local engine.
// Invalid input returns a redacted 400/invalidValue Error. The function is safe
// for concurrent calls and retains no input. Store must use this key together
// with the complete connection scope and enforce uniqueness atomically.
func UsernameComparisonKey(value string) (string, error) {
	if value == "" || len(value) > maxUsernameBytes || !utf8.ValidString(value) {
		return "", failure(400, "invalidValue")
	}
	key, err := usernameCaseMapped.CompareKey(value)
	if err != nil || key == "" {
		return "", failure(400, "invalidValue")
	}
	return key, nil
}

func isUsernameAttribute(a Attribute) bool {
	// Only the fixed core userName has server uniqueness; extension schemas
	// cannot claim it. A same-named extension retains its own type/case policy.
	return a.Name == "userName" && a.Type == "string" && a.Uniqueness == "server" && !a.CaseExact
}

func comparisonStrings(x, y string, a Attribute) (string, string, bool) {
	if isUsernameAttribute(a) {
		left, err := UsernameComparisonKey(x)
		if err != nil {
			return "", "", false
		}
		right, err := UsernameComparisonKey(y)
		return left, right, err == nil
	}
	if !a.CaseExact && a.Type != "binary" && a.Type != "reference" {
		return foldString(x), foldString(y), true
	}
	return x, y, true
}

// RFC 7644 Table 3 compares substring literals, not new standalone usernames.
// Reuse the pinned UsernameCaseMapped width/root-lower/NFC transforms without
// applying whole-identifier context/Bidi or nonempty admission to a fragment.
// The actual stored username still uses the complete profile above.
func usernameFragmentKey(value string) (string, error) {
	if len(value) > maxUsernameBytes || !utf8.ValidString(value) {
		return "", failure(400, "invalidValue")
	}
	value = width.Fold.String(value)
	value = cases.Lower(language.Und, cases.HandleFinalSigma(false)).String(value)
	return norm.NFC.String(value), nil
}

func substringComparisonStrings(x, y string, a Attribute) (string, string, bool) {
	if !isUsernameAttribute(a) {
		return comparisonStrings(x, y, a)
	}
	left, err := UsernameComparisonKey(x)
	if err != nil {
		return "", "", false
	}
	right, err := usernameFragmentKey(y)
	return left, right, err == nil
}
