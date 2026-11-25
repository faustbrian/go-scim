package scimorganization

import (
	"fmt"
	"log/slog"

	identity "github.com/faustbrian/go-identity"
	organization "github.com/faustbrian/go-organization"
	"github.com/faustbrian/go-sso"
)

// DirectoryUserAction selects an organization admission or source-owned
// withdrawal intent. It never selects a global identity lifecycle operation.
// Zero and unrecognized values are invalid; an intent grants no authority.
type DirectoryUserAction uint8

const (
	// DirectoryUserAdmit selects admission for an existing explicitly mapped user.
	DirectoryUserAdmit DirectoryUserAction = iota + 1
	// DirectoryUserWithdrawInactive selects withdrawal for an inactive source User.
	DirectoryUserWithdrawInactive
	// DirectoryUserWithdrawDeleted selects withdrawal for a source User tombstone.
	DirectoryUserWithdrawDeleted
)

// DirectoryUserMappingConfig selects one exact source partition, a positive
// caller-managed mapping version and 1..1,000 case-exact source User mappings.
// Members use the same bounded identifier grammar as DirectoryMappingConfig;
// duplicate source IDs are invalid, even when their target IDs agree. Distinct
// source IDs may explicitly select the same local user. No aliases, externalId,
// usernames, emails, display names or Group mappings are consulted.
//
// At least one of AllowAdmission and AllowWithdrawal must be explicitly true.
// AllowWithdrawal selects both inactive and deleted source User withdrawals;
// it does not choose a global identity suspension or deletion policy.
// NewDirectoryUserMapper snapshots the configuration. Do not mutate its slices
// concurrently with construction. A version change requires a new mapper.
type DirectoryUserMappingConfig struct {
	TenantID        identity.TenantID
	OrganizationID  organization.ID
	ProviderID      sso.ProviderID
	ConnectionID    string
	MappingVersion  uint64
	Members         []DirectoryMemberUserMapping
	AllowAdmission  bool
	AllowWithdrawal bool
}

// DirectoryUserMapper is immutable policy safe for concurrent calls. Its zero
// value rejects every batch. It owns no resources, synchronization cursor,
// repositories, authorization, durable commands or background work.
type DirectoryUserMapper struct {
	state *directoryUserMappingState
}

type directoryUserMappingState struct {
	tenantID        identity.TenantID
	organizationID  organization.ID
	providerID      sso.ProviderID
	connectionID    string
	mappingVersion  uint64
	members         map[string]identity.UserID
	allowAdmission  bool
	allowWithdrawal bool
}

// DirectoryUserIntent retains the exact source child command, User resource
// and revision with the explicitly selected local user and action. It does not
// prove target existence, current source state, source contribution ownership
// or permission. The native executor must independently verify those owners
// and retain original command custody before any durable effect.
type DirectoryUserIntent struct {
	CommandID      identity.CommandID
	ResourceID     string
	SourceRevision string
	UserID         identity.UserID
	Action         DirectoryUserAction
}

// DirectoryUserBatch contains a detached original SSO envelope and one ordered
// intent per User delta. It is policy output, not a contributor result, receipt
// or checkpoint. Editing the exported fields grants no execution authority.
type DirectoryUserBatch struct {
	Source sso.DirectoryDeltaBatch
	Users  []DirectoryUserIntent
}

// NewDirectoryUserMapper validates explicit, bounded User mapping policy and
// snapshots its member table. Invalid configuration returns ErrInvalidMappingInput.
// Local users remain caller selections, not evidence of existence or admission.
// Construction performs no IO and does not mutate the caller's configuration.
func NewDirectoryUserMapper(config DirectoryUserMappingConfig) (DirectoryUserMapper, error) {
	if !directoryMappingID(string(config.TenantID)) || !directoryMappingID(string(config.OrganizationID)) ||
		!directoryMappingProviderID(config.ProviderID) || !directoryMappingID(config.ConnectionID) || config.MappingVersion == 0 ||
		len(config.Members) == 0 || len(config.Members) > maxDirectoryMappings ||
		(!config.AllowAdmission && !config.AllowWithdrawal) {
		return DirectoryUserMapper{}, ErrInvalidMappingInput
	}

	state := &directoryUserMappingState{
		tenantID: config.TenantID, organizationID: config.OrganizationID,
		providerID: config.ProviderID, connectionID: config.ConnectionID, mappingVersion: config.MappingVersion,
		members:        make(map[string]identity.UserID, len(config.Members)),
		allowAdmission: config.AllowAdmission, allowWithdrawal: config.AllowWithdrawal,
	}
	for _, member := range config.Members {
		if !directoryMappingID(member.MemberID) || !directoryMappingID(string(member.UserID)) {
			return DirectoryUserMapper{}, ErrInvalidMappingInput
		}
		if _, duplicate := state.members[member.MemberID]; duplicate {
			return DirectoryUserMapper{}, ErrInvalidMappingInput
		}
		state.members[member.MemberID] = member.UserID
	}
	return DirectoryUserMapper{state: state}, nil
}

// MapDirectoryUserDelta snapshots a valid 1..1,000-child SSO batch and maps only
// explicitly selected User admission and withdrawal deltas. All-User batches
// may combine those actions; Group-only or mixed Group/User batches are invalid.
// Malformed, unsupported and zero-mapper input returns ErrInvalidMappingInput.
// Wrong scope/version, unmapped resources and unselected actions return
// ErrMappingDenied. Every failure returns zero output, never a partial mapping.
//
// Do not mutate batch.Deltas concurrently with this call. The mapper performs
// no effects, admission, identity activation or receipt/cursor changes, and
// does not implement sso.DirectorySyncContributor. Consumers must independently
// enforce their own supported batch size and authoritative lifecycle contract.
func (m DirectoryUserMapper) MapDirectoryUserDelta(batch sso.DirectoryDeltaBatch) (DirectoryUserBatch, error) {
	if m.state == nil {
		return DirectoryUserBatch{}, ErrInvalidMappingInput
	}
	source, err := batch.Snapshot()
	if err != nil {
		return DirectoryUserBatch{}, ErrInvalidMappingInput
	}
	state := m.state
	if source.TenantID != state.tenantID || source.OrganizationID != state.organizationID ||
		source.ProviderID != state.providerID || source.ConnectionID != state.connectionID || source.MappingVersion != state.mappingVersion {
		return DirectoryUserBatch{}, ErrMappingDenied
	}

	intents := make([]DirectoryUserIntent, 0, len(source.Deltas))
	for _, delta := range source.Deltas {
		intent, err := state.mapUserDelta(delta)
		if err != nil {
			return DirectoryUserBatch{}, err
		}
		intents = append(intents, intent)
	}
	return DirectoryUserBatch{Source: source, Users: intents}, nil
}

func (s *directoryUserMappingState) mapUserDelta(delta sso.DirectoryDelta) (DirectoryUserIntent, error) {
	var intent DirectoryUserIntent
	if admission, err := delta.UserAdmission(); err == nil {
		if !s.allowAdmission {
			return DirectoryUserIntent{}, ErrMappingDenied
		}
		intent = DirectoryUserIntent{
			CommandID: admission.CommandID, ResourceID: admission.ResourceID,
			SourceRevision: admission.SourceRevision, Action: DirectoryUserAdmit,
		}
	} else if withdrawal, err := delta.UserDeprovision(); err == nil {
		if !s.allowWithdrawal {
			return DirectoryUserIntent{}, ErrMappingDenied
		}
		intent = DirectoryUserIntent{
			CommandID: withdrawal.CommandID, ResourceID: withdrawal.ResourceID,
			SourceRevision: withdrawal.SourceRevision,
		}
		switch withdrawal.State {
		case sso.DirectoryUserInactive:
			intent.Action = DirectoryUserWithdrawInactive
		case sso.DirectoryUserDeleted:
			intent.Action = DirectoryUserWithdrawDeleted
		default:
			return DirectoryUserIntent{}, ErrInvalidMappingInput
		}
	} else {
		return DirectoryUserIntent{}, ErrInvalidMappingInput
	}

	userID, mapped := s.members[intent.ResourceID]
	if !mapped {
		return DirectoryUserIntent{}, ErrMappingDenied
	}
	intent.UserID = userID
	return intent, nil
}

func (DirectoryUserMappingConfig) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("scimorganization.DirectoryUserMappingConfig(redacted)"))
}
func (DirectoryUserMapper) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("scimorganization.DirectoryUserMapper(redacted)"))
}
func (DirectoryUserBatch) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("scimorganization.DirectoryUserBatch(redacted)"))
}
func (DirectoryUserIntent) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("scimorganization.DirectoryUserIntent(redacted)"))
}

func (DirectoryUserMappingConfig) LogValue() slog.Value {
	return slog.StringValue("scimorganization.DirectoryUserMappingConfig(redacted)")
}
func (DirectoryUserMapper) LogValue() slog.Value {
	return slog.StringValue("scimorganization.DirectoryUserMapper(redacted)")
}
func (DirectoryUserBatch) LogValue() slog.Value {
	return slog.StringValue("scimorganization.DirectoryUserBatch(redacted)")
}
func (DirectoryUserIntent) LogValue() slog.Value {
	return slog.StringValue("scimorganization.DirectoryUserIntent(redacted)")
}

func (DirectoryUserMappingConfig) MarshalJSON() ([]byte, error) {
	return nil, ErrSensitiveSerialization
}
func (DirectoryUserMappingConfig) MarshalText() ([]byte, error) {
	return nil, ErrSensitiveSerialization
}
func (DirectoryUserMapper) MarshalJSON() ([]byte, error) { return nil, ErrSensitiveSerialization }
func (DirectoryUserMapper) MarshalText() ([]byte, error) { return nil, ErrSensitiveSerialization }
func (DirectoryUserBatch) MarshalJSON() ([]byte, error)  { return nil, ErrSensitiveSerialization }
func (DirectoryUserBatch) MarshalText() ([]byte, error)  { return nil, ErrSensitiveSerialization }
func (DirectoryUserIntent) MarshalJSON() ([]byte, error) { return nil, ErrSensitiveSerialization }
func (DirectoryUserIntent) MarshalText() ([]byte, error) { return nil, ErrSensitiveSerialization }
