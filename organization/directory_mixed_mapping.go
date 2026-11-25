package scimorganization

import (
	"fmt"
	"log/slog"

	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-sso"
)

// DirectoryMixedMappingConfig composes an existing User policy with a Group
// membership policy, a Group role policy, or both. A zero Groups or Roles mapper
// omits that policy. Selected policies must share the exact source partition
// and version, and agree on every source User ID any two of them share.
// The two Group policies must select disjoint source Group IDs.
type DirectoryMixedMappingConfig struct {
	Users  DirectoryUserMapper
	Groups DirectoryMapper
	Roles  DirectoryRoleMapper
}

// DirectoryMixedMapper is immutable and safe for concurrent calls. Its zero
// value rejects every input. It owns no execution, authorization or cursor.
type DirectoryMixedMapper struct {
	config DirectoryMixedMappingConfig
}

// DirectoryMixedBatch retains the detached original envelope and exactly one
// intent per original child, in the same order. It conveys no authority.
type DirectoryMixedBatch struct {
	Source   sso.DirectoryDeltaBatch
	Children []DirectoryMixedIntent
}

// DirectoryMixedIntent is a closed mapping result for one original delta.
// Exactly one accessor succeeds for a mapped child; none succeeds on zero.
type DirectoryMixedIntent struct {
	user       DirectoryUserIntent
	membership DirectoryMembershipIntent
	role       DirectoryRoleIntent
}

// User projects an explicitly mapped User admission or withdrawal.
func (i DirectoryMixedIntent) User() (DirectoryUserIntent, bool) {
	return i.user, i.user.Action != 0
}

// Membership projects an explicitly mapped ordinary Group membership change.
func (i DirectoryMixedIntent) Membership() (DirectoryMembershipIntent, bool) {
	return i.membership, i.membership.Action != 0
}

// Role projects an explicitly mapped Group custom-role change.
func (i DirectoryMixedIntent) Role() (DirectoryRoleIntent, bool) {
	return i.role, i.role.RoleID != ""
}

// NewDirectoryMixedMapper combines immutable, already-validated mappers.
// An incomplete, inconsistent or ambiguous policy returns ErrInvalidMappingInput
// and a zero mapper. No role or local user is inferred from a source name.
func NewDirectoryMixedMapper(config DirectoryMixedMappingConfig) (DirectoryMixedMapper, error) {
	users, groups := config.Users.state, config.Groups.state
	var roleGroups *directoryMappingState
	if config.Roles.state != nil {
		roleGroups = config.Roles.state.directory.state
	}
	if users == nil || (groups == nil && roleGroups == nil) {
		return DirectoryMixedMapper{}, ErrInvalidMappingInput
	}
	for _, policy := range [...]*directoryMappingState{groups, roleGroups} {
		if policy == nil {
			continue
		}
		if policy.tenantID != users.tenantID || policy.organizationID != users.organizationID ||
			policy.providerID != users.providerID || policy.connectionID != users.connectionID || policy.mappingVersion != users.mappingVersion ||
			!compatibleMixedMembers(users.members, policy.members) {
			return DirectoryMixedMapper{}, ErrInvalidMappingInput
		}
	}
	if groups != nil && roleGroups != nil {
		if !compatibleMixedMembers(groups.members, roleGroups.members) {
			return DirectoryMixedMapper{}, ErrInvalidMappingInput
		}
		for id := range groups.groups {
			if _, duplicate := roleGroups.groups[id]; duplicate {
				return DirectoryMixedMapper{}, ErrInvalidMappingInput
			}
		}
	}
	return DirectoryMixedMapper{config: config}, nil
}

func compatibleMixedMembers(a, b map[string]identity.UserID) bool {
	for id, user := range a {
		if other, shared := b[id]; shared && other != user {
			return false
		}
	}
	return true
}

// MapDirectoryMixedDelta maps one complete validated SSO batch without
// regrouping its children or changing commands, revisions or the predecessor.
// Malformed inputs and a zero mapper return ErrInvalidMappingInput; wrong
// scope/version, unknown source IDs and unselected actions return ErrMappingDenied.
// All failures return zero output. Do not mutate batch.Deltas concurrently.
func (m DirectoryMixedMapper) MapDirectoryMixedDelta(batch sso.DirectoryDeltaBatch) (DirectoryMixedBatch, error) {
	users := m.config.Users.state
	if users == nil {
		return DirectoryMixedBatch{}, ErrInvalidMappingInput
	}
	source, err := batch.Snapshot()
	if err != nil {
		return DirectoryMixedBatch{}, ErrInvalidMappingInput
	}
	if source.TenantID != users.tenantID || source.OrganizationID != users.organizationID || source.ProviderID != users.providerID ||
		source.ConnectionID != users.connectionID || source.MappingVersion != users.mappingVersion {
		return DirectoryMixedBatch{}, ErrMappingDenied
	}
	children := make([]DirectoryMixedIntent, 0, len(source.Deltas))
	for _, delta := range source.Deltas {
		child, err := m.mapChild(delta)
		if err != nil {
			return DirectoryMixedBatch{}, err
		}
		children = append(children, child)
	}
	return DirectoryMixedBatch{Source: source, Children: children}, nil
}

func (m DirectoryMixedMapper) mapChild(delta sso.DirectoryDelta) (DirectoryMixedIntent, error) {
	membership, err := delta.GroupMembership()
	if err != nil {
		user, err := m.config.Users.state.mapUserDelta(delta)
		if err != nil {
			return DirectoryMixedIntent{}, err
		}
		return DirectoryMixedIntent{user: user}, nil
	}
	if roles := m.config.Roles.state; roles != nil {
		if role, selected := roles.roles[membership.GroupID]; selected {
			intent, err := roles.directory.state.mapMembership(membership)
			if err != nil {
				return DirectoryMixedIntent{}, err
			}
			return DirectoryMixedIntent{role: DirectoryRoleIntent{Membership: intent, RoleID: role}}, nil
		}
	}
	if m.config.Groups.state == nil {
		return DirectoryMixedIntent{}, ErrMappingDenied
	}
	intent, err := m.config.Groups.state.mapMembership(membership)
	if err != nil {
		return DirectoryMixedIntent{}, err
	}
	return DirectoryMixedIntent{membership: intent}, nil
}

func (DirectoryMixedMappingConfig) Format(s fmt.State, _ rune) {
	_, _ = fmt.Fprint(s, "scimorganization.DirectoryMixedMappingConfig(redacted)")
}
func (DirectoryMixedMapper) Format(s fmt.State, _ rune) {
	_, _ = fmt.Fprint(s, "scimorganization.DirectoryMixedMapper(redacted)")
}
func (DirectoryMixedBatch) Format(s fmt.State, _ rune) {
	_, _ = fmt.Fprint(s, "scimorganization.DirectoryMixedBatch(redacted)")
}
func (DirectoryMixedIntent) Format(s fmt.State, _ rune) {
	_, _ = fmt.Fprint(s, "scimorganization.DirectoryMixedIntent(redacted)")
}

func (DirectoryMixedMappingConfig) LogValue() slog.Value {
	return slog.StringValue("scimorganization.DirectoryMixedMappingConfig(redacted)")
}
func (DirectoryMixedMapper) LogValue() slog.Value {
	return slog.StringValue("scimorganization.DirectoryMixedMapper(redacted)")
}
func (DirectoryMixedBatch) LogValue() slog.Value {
	return slog.StringValue("scimorganization.DirectoryMixedBatch(redacted)")
}
func (DirectoryMixedIntent) LogValue() slog.Value {
	return slog.StringValue("scimorganization.DirectoryMixedIntent(redacted)")
}

func (DirectoryMixedMappingConfig) MarshalJSON() ([]byte, error) {
	return nil, ErrSensitiveSerialization
}
func (DirectoryMixedMappingConfig) MarshalText() ([]byte, error) {
	return nil, ErrSensitiveSerialization
}
func (DirectoryMixedMapper) MarshalJSON() ([]byte, error) { return nil, ErrSensitiveSerialization }
func (DirectoryMixedMapper) MarshalText() ([]byte, error) { return nil, ErrSensitiveSerialization }
func (DirectoryMixedBatch) MarshalJSON() ([]byte, error)  { return nil, ErrSensitiveSerialization }
func (DirectoryMixedBatch) MarshalText() ([]byte, error)  { return nil, ErrSensitiveSerialization }
func (DirectoryMixedIntent) MarshalJSON() ([]byte, error) { return nil, ErrSensitiveSerialization }
func (DirectoryMixedIntent) MarshalText() ([]byte, error) { return nil, ErrSensitiveSerialization }
