package scimorganization

import (
	"fmt"
	"log/slog"

	identity "github.com/faustbrian/go-identity"
	organization "github.com/faustbrian/go-organization"
	"github.com/faustbrian/go-sso"
)

// DirectoryGroupRoleMapping explicitly selects one existing dynamic role for
// a case-exact source Group and its configured team. RoleID uses the bounded
// identifier grammar of DirectoryMappingConfig and cannot be a static
// organization role. No name, attribute or implied elevated role is consulted.
type DirectoryGroupRoleMapping struct {
	GroupID string
	TeamID  organization.ID
	RoleID  organization.ID
}

// DirectoryRoleMappingConfig extends an explicit membership profile with
// exactly one role selection for every configured Group/team. Missing, extra,
// mismatched and duplicate selections are invalid. Distinct source Groups may
// explicitly select the same team and role. NewDirectoryRoleMapper snapshots
// all configuration; do not mutate its slices concurrently with construction.
type DirectoryRoleMappingConfig struct {
	Directory DirectoryMappingConfig
	Roles     []DirectoryGroupRoleMapping
}

// DirectoryRoleMapper is immutable policy safe for concurrent calls. Its zero
// value rejects every input. It owns no IO, authorization, target existence,
// provisioning, durable commands, source observations or synchronization cursor.
type DirectoryRoleMapper struct {
	state *directoryRoleMappingState
}

type directoryRoleMappingState struct {
	directory DirectoryMapper
	roles     map[string]organization.ID
}

// DirectoryRoleIntent retains one original membership child and its explicitly
// configured dynamic role. It grants no execution or source-edge authority.
// Native consumers must independently verify current ownership and eligibility.
type DirectoryRoleIntent struct {
	Membership DirectoryMembershipIntent
	RoleID     organization.ID
}

// DirectoryRoleBatch contains a detached original SSO envelope and one ordered
// role intent per child. It is policy output, not a result, receipt or cursor.
// Editing this output grants no authority to execute the resulting values.
type DirectoryRoleBatch struct {
	Source sso.DirectoryDeltaBatch
	Roles  []DirectoryRoleIntent
}

// DirectoryRoleScope identifies the exact configured partition and positive
// mapping version to recheck. It is not a source observation or authorization.
type DirectoryRoleScope struct {
	TenantID       identity.TenantID
	OrganizationID organization.ID
	ProviderID     sso.ProviderID
	ConnectionID   string
	MappingVersion uint64
}

// DirectoryRoleTarget identifies one complete source-to-target selection.
// GroupID and MemberID are exact source resource IDs, never local ID aliases.
type DirectoryRoleTarget struct {
	GroupID  string
	MemberID string
	TeamID   organization.ID
	RoleID   organization.ID
	UserID   identity.UserID
}

// NewDirectoryRoleMapper validates and snapshots a complete role policy using
// NewDirectoryMapper's exact membership profile. Invalid input returns a zero
// mapper and ErrInvalidMappingInput. Explicit dynamic role IDs select policy;
// they do not prove that targets exist, are eligible or grant permissions.
func NewDirectoryRoleMapper(config DirectoryRoleMappingConfig) (DirectoryRoleMapper, error) {
	if len(config.Roles) == 0 || len(config.Roles) > maxDirectoryMappings || len(config.Roles) != len(config.Directory.Groups) {
		return DirectoryRoleMapper{}, ErrInvalidMappingInput
	}
	directory, err := NewDirectoryMapper(config.Directory)
	if err != nil {
		return DirectoryRoleMapper{}, err
	}
	roles := make(map[string]organization.ID, len(config.Roles))
	for _, selection := range config.Roles {
		teamID, mapped := directory.state.groups[selection.GroupID]
		if !mapped || teamID != selection.TeamID || !directoryMappingID(string(selection.RoleID)) || organization.Role(selection.RoleID).Valid() {
			return DirectoryRoleMapper{}, ErrInvalidMappingInput
		}
		if _, duplicate := roles[selection.GroupID]; duplicate {
			return DirectoryRoleMapper{}, ErrInvalidMappingInput
		}
		roles[selection.GroupID] = selection.RoleID
	}
	return DirectoryRoleMapper{state: &directoryRoleMappingState{directory: directory, roles: roles}}, nil
}

// MapDirectoryRoleDelta applies MapDirectoryDelta's exact validation and
// all-or-zero mapping, then associates each child with its configured role.
// Malformed input and zero mappers return ErrInvalidMappingInput; wrong scope,
// version and unmapped sources return ErrMappingDenied. Every error returns
// zero output. Do not mutate batch.Deltas concurrently with the call.
// No effects, new commands, receipts, checkpoints or role inference occur.
func (m DirectoryRoleMapper) MapDirectoryRoleDelta(batch sso.DirectoryDeltaBatch) (DirectoryRoleBatch, error) {
	if m.state == nil {
		return DirectoryRoleBatch{}, ErrInvalidMappingInput
	}
	mapped, err := m.state.directory.MapDirectoryDelta(batch)
	if err != nil {
		return DirectoryRoleBatch{}, err
	}
	roles := make([]DirectoryRoleIntent, 0, len(mapped.Memberships))
	for _, membership := range mapped.Memberships {
		roles = append(roles, DirectoryRoleIntent{Membership: membership, RoleID: m.state.roles[membership.GroupID]})
	}
	return DirectoryRoleBatch{Source: mapped.Source, Roles: roles}, nil
}

// MatchesDirectoryRoleSource reports whether every scope and target field
// exactly matches this immutable profile. Zero, partial, stale, aliased or
// different selections fail closed. A match is only a policy recheck; it proves
// no current source edge, target existence, command custody or authorization.
func (m DirectoryRoleMapper) MatchesDirectoryRoleSource(scope DirectoryRoleScope, target DirectoryRoleTarget) bool {
	if m.state == nil {
		return false
	}
	directory := m.state.directory.state
	if scope.TenantID != directory.tenantID || scope.OrganizationID != directory.organizationID ||
		scope.ProviderID != directory.providerID || scope.ConnectionID != directory.connectionID || scope.MappingVersion != directory.mappingVersion {
		return false
	}
	teamID, groupMapped := directory.groups[target.GroupID]
	userID, memberMapped := directory.members[target.MemberID]
	roleID, roleMapped := m.state.roles[target.GroupID]
	return groupMapped && memberMapped && roleMapped && teamID == target.TeamID && userID == target.UserID && roleID == target.RoleID
}

func (DirectoryGroupRoleMapping) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("scimorganization.DirectoryGroupRoleMapping(redacted)"))
}
func (DirectoryRoleMappingConfig) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("scimorganization.DirectoryRoleMappingConfig(redacted)"))
}
func (DirectoryRoleMapper) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("scimorganization.DirectoryRoleMapper(redacted)"))
}
func (DirectoryRoleIntent) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("scimorganization.DirectoryRoleIntent(redacted)"))
}
func (DirectoryRoleBatch) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("scimorganization.DirectoryRoleBatch(redacted)"))
}
func (DirectoryRoleScope) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("scimorganization.DirectoryRoleScope(redacted)"))
}
func (DirectoryRoleTarget) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("scimorganization.DirectoryRoleTarget(redacted)"))
}

func (DirectoryGroupRoleMapping) LogValue() slog.Value {
	return slog.StringValue("scimorganization.DirectoryGroupRoleMapping(redacted)")
}
func (DirectoryRoleMappingConfig) LogValue() slog.Value {
	return slog.StringValue("scimorganization.DirectoryRoleMappingConfig(redacted)")
}
func (DirectoryRoleMapper) LogValue() slog.Value {
	return slog.StringValue("scimorganization.DirectoryRoleMapper(redacted)")
}
func (DirectoryRoleIntent) LogValue() slog.Value {
	return slog.StringValue("scimorganization.DirectoryRoleIntent(redacted)")
}
func (DirectoryRoleBatch) LogValue() slog.Value {
	return slog.StringValue("scimorganization.DirectoryRoleBatch(redacted)")
}
func (DirectoryRoleScope) LogValue() slog.Value {
	return slog.StringValue("scimorganization.DirectoryRoleScope(redacted)")
}
func (DirectoryRoleTarget) LogValue() slog.Value {
	return slog.StringValue("scimorganization.DirectoryRoleTarget(redacted)")
}

func (DirectoryGroupRoleMapping) MarshalJSON() ([]byte, error) { return nil, ErrSensitiveSerialization }
func (DirectoryGroupRoleMapping) MarshalText() ([]byte, error) { return nil, ErrSensitiveSerialization }
func (DirectoryRoleMappingConfig) MarshalJSON() ([]byte, error) {
	return nil, ErrSensitiveSerialization
}
func (DirectoryRoleMappingConfig) MarshalText() ([]byte, error) {
	return nil, ErrSensitiveSerialization
}
func (DirectoryRoleMapper) MarshalJSON() ([]byte, error) { return nil, ErrSensitiveSerialization }
func (DirectoryRoleMapper) MarshalText() ([]byte, error) { return nil, ErrSensitiveSerialization }
func (DirectoryRoleIntent) MarshalJSON() ([]byte, error) { return nil, ErrSensitiveSerialization }
func (DirectoryRoleIntent) MarshalText() ([]byte, error) { return nil, ErrSensitiveSerialization }
func (DirectoryRoleBatch) MarshalJSON() ([]byte, error)  { return nil, ErrSensitiveSerialization }
func (DirectoryRoleBatch) MarshalText() ([]byte, error)  { return nil, ErrSensitiveSerialization }
func (DirectoryRoleScope) MarshalJSON() ([]byte, error)  { return nil, ErrSensitiveSerialization }
func (DirectoryRoleScope) MarshalText() ([]byte, error)  { return nil, ErrSensitiveSerialization }
func (DirectoryRoleTarget) MarshalJSON() ([]byte, error) { return nil, ErrSensitiveSerialization }
func (DirectoryRoleTarget) MarshalText() ([]byte, error) { return nil, ErrSensitiveSerialization }
