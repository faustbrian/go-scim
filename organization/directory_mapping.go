// Package scimorganization owns explicit SCIM-to-organization mapping policy.
// The selected profile translates existing source Group/User edges into existing
// team/user intents. It performs no lookup, authorization, provisioning or write.
package scimorganization

import (
	"fmt"
	"log/slog"
	"unicode/utf8"

	identity "github.com/faustbrian/go-identity"
	organization "github.com/faustbrian/go-organization"
	"github.com/faustbrian/go-sso"
)

// MappingError classifies a mapping decision without retaining source values.
type MappingError string

func (e MappingError) Error() string { return string(e) }

const (
	// ErrInvalidMappingInput rejects malformed configuration, batch or zero mapper.
	ErrInvalidMappingInput MappingError = "scim/organization: invalid mapping input"
	// ErrMappingDenied deliberately conflates wrong scope, stale mapping versions
	// and unmapped source IDs. No partial intent is returned after denial.
	ErrMappingDenied MappingError = "scim/organization: mapping denied"
	// ErrSensitiveSerialization prevents implicit export of mapping identifiers.
	ErrSensitiveSerialization MappingError = "scim/organization: sensitive serialization forbidden"
)

// The selected finite profile bounds each lookup table independently before
// allocation. It supports at most the SSO batch profile's 1,000 source entries
// in either dimension; larger directories require a separately selected policy.
const maxDirectoryMappings = 1000

// DirectoryGroupTeamMapping explicitly maps one case-exact source Group ID to
// an existing team. Distinct groups may contribute to the same team; the native
// organization owner retains their independent source grants. Names and roles
// are not mapping inputs. This value proves no current target existence.
type DirectoryGroupTeamMapping struct {
	GroupID string
	TeamID  organization.ID
}

// DirectoryMemberUserMapping explicitly selects an existing local user for one
// case-exact source User resource ID. It does not match by externalId, username,
// email or display name, and cannot authorize linking or account takeover.
type DirectoryMemberUserMapping struct {
	MemberID string
	UserID   identity.UserID
}

// DirectoryMappingConfig selects one exact tenant/organization/provider/
// connection partition and positive mapping version. Groups and Members must
// each contain 1..1,000 entries with unique source IDs, including no identical
// duplicate rows. IDs use the upstream bounded case-exact identifier grammar:
// 1..128 valid UTF-8 bytes without ASCII whitespace/control characters; provider
// IDs use printable ASCII. No identifier is trimmed or normalized.
//
// Construct a mapper before sharing configuration, without concurrent mutation.
// NewDirectoryMapper snapshots all input; later config changes have no effect.
// A mapping version is caller-managed configuration identity, not admission or
// proof of source truth. A new version requires construction of a new mapper.
type DirectoryMappingConfig struct {
	TenantID       identity.TenantID
	OrganizationID organization.ID
	ProviderID     sso.ProviderID
	ConnectionID   string
	MappingVersion uint64
	Groups         []DirectoryGroupTeamMapping
	Members        []DirectoryMemberUserMapping
}

// DirectoryMapper is immutable mapping policy safe for concurrent calls. Its
// zero value rejects all input. It owns no resources, clock, random source,
// repository, background work, command receipts or synchronization cursor.
type DirectoryMapper struct {
	state *directoryMappingState
}

type directoryMappingState struct {
	tenantID       identity.TenantID
	organizationID organization.ID
	providerID     sso.ProviderID
	connectionID   string
	mappingVersion uint64
	groups         map[string]organization.ID
	members        map[string]identity.UserID
}

// DirectoryMembershipIntent is detached policy output for one original SSO
// child. CommandID, GroupID, MemberID and Action preserve the source exactly;
// TeamID and UserID are explicit configuration selections. None grants current
// authorization, target existence or source-edge authority. Native composition
// must verify those owners and retain this original child for durable effects.
type DirectoryMembershipIntent struct {
	CommandID identity.CommandID
	GroupID   string
	MemberID  string
	TeamID    organization.ID
	UserID    identity.UserID
	Action    sso.DirectoryMembershipAction
}

// DirectoryMembershipBatch contains the detached original SSO envelope and
// one ordered intent per delta. The generation, mapping version and predecessor
// remain owned by SSO; this output is not a contributor result or a checkpoint.
// Callers may edit their copy but doing so conveys no execution authority.
type DirectoryMembershipBatch struct {
	Source      sso.DirectoryDeltaBatch
	Memberships []DirectoryMembershipIntent
}

// NewDirectoryMapper validates bounded, unambiguous policy and copies it into
// private lookup tables. Local target IDs remain explicit selections, not
// evidence that the targets exist or are eligible. There is no IO or mutation.
func NewDirectoryMapper(config DirectoryMappingConfig) (DirectoryMapper, error) {
	if !directoryMappingID(string(config.TenantID)) || !directoryMappingID(string(config.OrganizationID)) ||
		!directoryMappingProviderID(config.ProviderID) || !directoryMappingID(config.ConnectionID) || config.MappingVersion == 0 ||
		len(config.Groups) == 0 || len(config.Groups) > maxDirectoryMappings ||
		len(config.Members) == 0 || len(config.Members) > maxDirectoryMappings {
		return DirectoryMapper{}, ErrInvalidMappingInput
	}

	state := &directoryMappingState{
		tenantID: config.TenantID, organizationID: config.OrganizationID,
		providerID: config.ProviderID, connectionID: config.ConnectionID, mappingVersion: config.MappingVersion,
		groups:  make(map[string]organization.ID, len(config.Groups)),
		members: make(map[string]identity.UserID, len(config.Members)),
	}
	for _, group := range config.Groups {
		if !directoryMappingID(group.GroupID) || !directoryMappingID(string(group.TeamID)) {
			return DirectoryMapper{}, ErrInvalidMappingInput
		}
		if _, duplicate := state.groups[group.GroupID]; duplicate {
			return DirectoryMapper{}, ErrInvalidMappingInput
		}
		state.groups[group.GroupID] = group.TeamID
	}
	for _, member := range config.Members {
		if !directoryMappingID(member.MemberID) || !directoryMappingID(string(member.UserID)) {
			return DirectoryMapper{}, ErrInvalidMappingInput
		}
		if _, duplicate := state.members[member.MemberID]; duplicate {
			return DirectoryMapper{}, ErrInvalidMappingInput
		}
		state.members[member.MemberID] = member.UserID
	}
	return DirectoryMapper{state: state}, nil
}

// MapDirectoryDelta validates and snapshots an SSO batch, requires its exact
// configured source partition/version, and resolves every edge by exact source
// IDs. Malformed/duplicate children return ErrInvalidMappingInput; wrong scope,
// version or unmapped edges return ErrMappingDenied. All failures return zero
// output, never partially mapped children. Do not mutate batch.Deltas during
// this call. No effects, admission, receipts, new commands or cursor changes
// occur; the mapper does not implement sso.DirectorySyncContributor.
func (m DirectoryMapper) MapDirectoryDelta(batch sso.DirectoryDeltaBatch) (DirectoryMembershipBatch, error) {
	if m.state == nil {
		return DirectoryMembershipBatch{}, ErrInvalidMappingInput
	}
	source, err := batch.Snapshot()
	if err != nil {
		return DirectoryMembershipBatch{}, ErrInvalidMappingInput
	}
	state := m.state
	if source.TenantID != state.tenantID || source.OrganizationID != state.organizationID ||
		source.ProviderID != state.providerID || source.ConnectionID != state.connectionID || source.MappingVersion != state.mappingVersion {
		return DirectoryMembershipBatch{}, ErrMappingDenied
	}

	intents := make([]DirectoryMembershipIntent, 0, len(source.Deltas))
	for _, delta := range source.Deltas {
		// Snapshot has already validated the closed SSO delta profile.
		membership, err := delta.GroupMembership()
		if err != nil {
			return DirectoryMembershipBatch{}, ErrInvalidMappingInput
		}
		intent, err := state.mapMembership(membership)
		if err != nil {
			return DirectoryMembershipBatch{}, err
		}
		intents = append(intents, intent)
	}
	return DirectoryMembershipBatch{Source: source, Memberships: intents}, nil
}

func (s *directoryMappingState) mapMembership(membership sso.DirectoryGroupMembership) (DirectoryMembershipIntent, error) {
	teamID, groupMapped := s.groups[membership.GroupID]
	userID, memberMapped := s.members[membership.MemberID]
	if !groupMapped || !memberMapped {
		return DirectoryMembershipIntent{}, ErrMappingDenied
	}
	return DirectoryMembershipIntent{
		CommandID: membership.CommandID, GroupID: membership.GroupID, MemberID: membership.MemberID,
		TeamID: teamID, UserID: userID, Action: membership.Action,
	}, nil
}

// Match the SSO source and organization/identity owners' existing 128-byte
// case-exact grammar. This is structural policy input validation, not canonical
// identity issuance or current owner authorization.
func directoryMappingID(raw string) bool {
	if len(raw) == 0 || len(raw) > 128 || !utf8.ValidString(raw) {
		return false
	}
	for _, r := range raw {
		if r <= ' ' || r == 127 {
			return false
		}
	}
	return true
}

func directoryMappingProviderID(provider sso.ProviderID) bool {
	if len(provider) == 0 || len(provider) > 128 {
		return false
	}
	for _, b := range []byte(provider) {
		if b < '!' || b > '~' {
			return false
		}
	}
	return true
}

func (DirectoryMappingConfig) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("scimorganization.DirectoryMappingConfig(redacted)"))
}
func (DirectoryMapper) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("scimorganization.DirectoryMapper(redacted)"))
}
func (DirectoryMembershipBatch) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("scimorganization.DirectoryMembershipBatch(redacted)"))
}
func (DirectoryMembershipIntent) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("scimorganization.DirectoryMembershipIntent(redacted)"))
}

func (DirectoryMappingConfig) LogValue() slog.Value {
	return slog.StringValue("scimorganization.DirectoryMappingConfig(redacted)")
}
func (DirectoryMapper) LogValue() slog.Value {
	return slog.StringValue("scimorganization.DirectoryMapper(redacted)")
}
func (DirectoryMembershipBatch) LogValue() slog.Value {
	return slog.StringValue("scimorganization.DirectoryMembershipBatch(redacted)")
}
func (DirectoryMembershipIntent) LogValue() slog.Value {
	return slog.StringValue("scimorganization.DirectoryMembershipIntent(redacted)")
}

func (DirectoryMappingConfig) MarshalJSON() ([]byte, error) {
	return nil, ErrSensitiveSerialization
}
func (DirectoryMappingConfig) MarshalText() ([]byte, error) {
	return nil, ErrSensitiveSerialization
}
func (DirectoryMapper) MarshalJSON() ([]byte, error) { return nil, ErrSensitiveSerialization }
func (DirectoryMapper) MarshalText() ([]byte, error) { return nil, ErrSensitiveSerialization }
func (DirectoryMembershipBatch) MarshalJSON() ([]byte, error) {
	return nil, ErrSensitiveSerialization
}
func (DirectoryMembershipBatch) MarshalText() ([]byte, error) {
	return nil, ErrSensitiveSerialization
}
func (DirectoryMembershipIntent) MarshalJSON() ([]byte, error) {
	return nil, ErrSensitiveSerialization
}
func (DirectoryMembershipIntent) MarshalText() ([]byte, error) {
	return nil, ErrSensitiveSerialization
}
