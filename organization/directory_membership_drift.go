package scimorganization

import (
	"fmt"
	"log/slog"
)

// DirectorySourceMembership describes source evidence for one exact mapped
// membership. It is not source authority or permission to change membership.
// Zero and unrecognized values are invalid.
type DirectorySourceMembership uint8

const (
	// DirectorySourceMembershipPresent reports a source membership for an active User.
	DirectorySourceMembershipPresent DirectorySourceMembership = iota + 1
	// DirectorySourceMembershipAbsent reports explicit source membership absence.
	DirectorySourceMembershipAbsent
	// DirectorySourceMembershipInactiveUser reports an inactive source User.
	DirectorySourceMembershipInactiveUser
	// DirectorySourceMembershipUnproven reports insufficient source evidence.
	DirectorySourceMembershipUnproven
)

// DirectoryLocalMembership contains detached observations for one exact
// mapped membership. Observed means the local read completed; Attributed means
// a grant belongs to the exact source, not merely that effective membership
// exists. Local reports an independent local grant and never proves source
// attribution. Attributed and Local must both be false when Observed is false.
// The caller owns scope matching and the authority and freshness of each read.
type DirectoryLocalMembership struct {
	Observed   bool
	Attributed bool
	Local      bool
}

// DirectoryMembershipDriftKind classifies observations without selecting a
// repair or source-of-truth policy. Zero is not a successful classification.
type DirectoryMembershipDriftKind uint8

const (
	// DirectoryMembershipDriftInSync reports agreement on exact source attribution.
	DirectoryMembershipDriftInSync DirectoryMembershipDriftKind = iota + 1
	// DirectoryMembershipDriftMissingSourceGrant reports a present source membership
	// with no locally attributed grant, even if an independent local grant exists.
	DirectoryMembershipDriftMissingSourceGrant
	// DirectoryMembershipDriftUnexpectedSourceGrant reports an attributed grant
	// despite explicit source absence. An independent local grant is not drift.
	DirectoryMembershipDriftUnexpectedSourceGrant
	// DirectoryMembershipDriftConflict reports inactive or unproven source state,
	// or an unobserved local state. It does not select a withdrawal policy.
	DirectoryMembershipDriftConflict
)

// DirectoryMembershipDrift is detached read-only classification. LocalGrant
// reports an independent local grant separately from source-attribution drift.
// No kind grants repair authority, issues a command or advances a cursor.
type DirectoryMembershipDrift struct {
	Kind       DirectoryMembershipDriftKind
	LocalGrant bool
}

// ClassifyDirectoryMembershipDrift compares explicit source evidence with the
// exact source-attributed local grant. Inactive Users, unproven source evidence
// and unobserved local state always produce Conflict; absence of an attributed
// grant cannot make those states InSync. Local grants never substitute for a
// source grant. Malformed inputs return zero output and ErrInvalidMappingInput.
// This pure function performs no IO or mutation and is safe for concurrent calls.
func ClassifyDirectoryMembershipDrift(source DirectorySourceMembership, local DirectoryLocalMembership) (DirectoryMembershipDrift, error) {
	switch source {
	case DirectorySourceMembershipPresent, DirectorySourceMembershipAbsent,
		DirectorySourceMembershipInactiveUser, DirectorySourceMembershipUnproven:
	default:
		return DirectoryMembershipDrift{}, ErrInvalidMappingInput
	}
	if !local.Observed && (local.Attributed || local.Local) {
		return DirectoryMembershipDrift{}, ErrInvalidMappingInput
	}

	drift := DirectoryMembershipDrift{LocalGrant: local.Local}
	switch {
	case !local.Observed || source == DirectorySourceMembershipInactiveUser || source == DirectorySourceMembershipUnproven:
		drift.Kind = DirectoryMembershipDriftConflict
	case source == DirectorySourceMembershipPresent && !local.Attributed:
		drift.Kind = DirectoryMembershipDriftMissingSourceGrant
	case source == DirectorySourceMembershipAbsent && local.Attributed:
		drift.Kind = DirectoryMembershipDriftUnexpectedSourceGrant
	default:
		drift.Kind = DirectoryMembershipDriftInSync
	}
	return drift, nil
}

func (DirectoryLocalMembership) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("scimorganization.DirectoryLocalMembership(redacted)"))
}
func (DirectoryMembershipDrift) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("scimorganization.DirectoryMembershipDrift(redacted)"))
}

func (DirectoryLocalMembership) LogValue() slog.Value {
	return slog.StringValue("scimorganization.DirectoryLocalMembership(redacted)")
}
func (DirectoryMembershipDrift) LogValue() slog.Value {
	return slog.StringValue("scimorganization.DirectoryMembershipDrift(redacted)")
}

func (DirectoryLocalMembership) MarshalJSON() ([]byte, error) {
	return nil, ErrSensitiveSerialization
}
func (DirectoryMembershipDrift) MarshalJSON() ([]byte, error) {
	return nil, ErrSensitiveSerialization
}

func (DirectoryLocalMembership) MarshalText() ([]byte, error) {
	return nil, ErrSensitiveSerialization
}
func (DirectoryMembershipDrift) MarshalText() ([]byte, error) {
	return nil, ErrSensitiveSerialization
}
