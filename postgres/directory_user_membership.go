package scimpostgres

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"time"

	identity "github.com/faustbrian/go-identity"
	kernel "github.com/faustbrian/go-identity/postgres"
	organization "github.com/faustbrian/go-organization"
	organizationpg "github.com/faustbrian/go-organization/postgres"
	scim "github.com/faustbrian/go-scim"
)

// AdvanceDirectorySourceAfterUserCommit carries exactly one durably recorded
// User child's organization successor into the next child in the same admitted
// batch. The caller supplies the exact resource and an independently authorized
// original kernel receipt. This does not authenticate a receipt, authorize or
// execute the next child, or validate historical prefixes after a restart.
//
// The observation must belong to the same configured Service. Its connection,
// actor, other owner epochs and all deadlines remain unchanged. The next child
// must still apply its normal live source fences inside Work. Failure returns
// a zero observation; cancellation and the original deadline bound recovery.
func (s *GroupsService) AdvanceDirectorySourceAfterUserCommit(ctx context.Context, original DirectorySourceObservation, resourceID string, receipt identity.CommandResult) (DirectorySourceObservation, error) {
	var zero DirectorySourceObservation
	if s == nil || s.native == nil || s.protocol == nil || ctx == nil || original.source != s.native {
		return zero, identity.ForbiddenError{}
	}
	if _, err := identity.ParseSubjectID(resourceID); err != nil {
		return zero, identity.ForbiddenError{}
	}
	bindings, err := original.bindings(ctx)
	if err != nil || receipt.Binding.ActorID != bindings.ActorID {
		return zero, identity.ForbiddenError{}
	}
	ctx, cancel := context.WithTimeout(ctx, min(s.native.config().MaximumDuration, time.Until(bindings.ValidUntil)))
	defer cancel()
	source := directoryMembershipOwnerSource(bindings.Scope, receipt.Binding.UserID, resourceID)
	successor, err := s.native.organizations.RecoverDirectoryMembershipSuccessor(ctx, source, original.admission.organization, receipt)
	if err != nil {
		return zero, err
	}
	advanced := original
	advanced.admission.organization.Version = successor.Version
	if _, err := advanced.bindings(ctx); err != nil {
		return zero, err
	}
	return advanced, nil
}

func directoryMembershipOwnerSource(scope scim.Scope, user identity.UserID, resourceID string) organizationpg.DirectoryMembershipSource {
	return organizationpg.DirectoryMembershipSource{TenantID: scope.TenantID, OrganizationID: organization.ID(scope.OrganizationID), UserID: user,
		ProviderID: organization.ID(scope.ProviderID), ConnectionID: organization.ID(scope.ConnectionID), ResourceID: organization.ID(resourceID)}
}

// DirectoryUserMembershipState selects an exact source condition, not an
// organization policy decision. No default User state is inferred.
type DirectoryUserMembershipState uint8

const (
	// DirectoryMembershipUserActive requires an explicit live active=true User.
	DirectoryMembershipUserActive DirectoryUserMembershipState = iota + 1
	// DirectoryMembershipUserInactive requires a live active=false User.
	DirectoryMembershipUserInactive
	// DirectoryMembershipUserDeleted requires a retained canonical tombstone.
	DirectoryMembershipUserDeleted
)

// DirectoryUserMembershipEvidence selects one configured source User at an
// exact native revision. Live values use the strong ETag; a tombstone uses
// the quoted retained delete command ID. It does not grant local permission.
type DirectoryUserMembershipEvidence struct {
	ResourceID string
	Revision   scim.Version
	State      DirectoryUserMembershipState
}

// Field binds the selected User condition into the original child. For an
// inactive or deleted User it preserves the existing deprovision field bytes.
// Active admission uses a distinct field and must not use a withdrawal child.
func (e DirectoryUserMembershipEvidence) Field() (identity.FeatureField, error) {
	switch e.State {
	case DirectoryMembershipUserInactive, DirectoryMembershipUserDeleted:
		return (DirectoryUserDeprovisionEvidence{ResourceID: e.ResourceID, Revision: e.Revision, Deleted: e.State == DirectoryMembershipUserDeleted}).Field()
	case DirectoryMembershipUserActive:
		if _, err := identity.ParseSubjectID(e.ResourceID); err != nil || !nativeVersion(e.Revision) {
			return identity.FeatureField{}, identity.ForbiddenError{}
		}
		wire, err := json.Marshal(e)
		if err != nil {
			return identity.FeatureField{}, identity.ForbiddenError{}
		}
		defer clear(wire)
		digest := sha256.Sum256(append([]byte("scim-postgres/directory-user-admission/v1\x00"), wire...))
		return identity.FeatureField{Name: "scim.directory-user-admission", Value: identity.FeatureValue{Kind: identity.FeatureBytes, Bytes: digest[:]}}, nil
	default:
		return identity.FeatureField{}, identity.ForbiddenError{}
	}
}

func (e DirectoryUserMembershipEvidence) registration() kernel.FeatureRegistration {
	if e.State == DirectoryMembershipUserActive {
		return kernel.FeatureRegistration{
			Contributor: kernel.ContributorDescriptor{Owner: "sso/postgres", ContractID: "sso.directory-user-admission", Version: 1},
			Operation:   identity.FeatureOperation{Owner: "sso", OperationID: "identity.sso.directory-sync.apply-user-admission", SchemaID: "sso.directory-user-admission", SchemaVersion: 1, RecordRequirement: identity.FeatureRecordRequired, SubjectRequirement: identity.FeatureSubjectUser, VersionPolicy: identity.FeatureVersionSequential},
		}
	}
	return directoryUserDeprovisionRegistration()
}

func (s *GroupsService) directoryMembershipSourceBinding(ctx context.Context, w kernel.Work, owner kernel.FeatureExecutionContributor, command identity.Command, observation DirectorySourceObservation, evidence DirectoryUserMembershipEvidence) (DirectorySourceBindings, error) {
	field, err := evidence.Field()
	if err != nil {
		return DirectorySourceBindings{}, err
	}
	if err := requireDirectoryUserField(command, field); err != nil {
		return DirectorySourceBindings{}, err
	}
	return s.directorySourceBinding(ctx, w, owner, command, observation, evidence.registration())
}

// LockDirectoryUserMembership fences the original command and User revision,
// acquiring authority in directory, organization, then connection order. The
// organization writer lock precedes SCIM's organization SHARE check to avoid
// lock upgrades. The returned lock is usable only by the exact organization
// update in this Work. This does not select a disposition, apply membership,
// admit an SSO generation, or renew any original freshness.
func (s *GroupsService) LockDirectoryUserMembership(ctx context.Context, w kernel.Work, owner kernel.FeatureExecutionContributor, command identity.Command, observation DirectorySourceObservation, evidence DirectoryUserMembershipEvidence, update organizationpg.DirectoryMembershipUpdate) (organizationpg.DirectoryMembershipLock, error) {
	if err := w.RequireFeatureCommand(ctx, owner, command); err != nil {
		return organizationpg.DirectoryMembershipLock{}, err
	}
	bindings, err := s.directoryMembershipSourceBinding(ctx, w, owner, command, observation, evidence)
	if err != nil {
		return organizationpg.DirectoryMembershipLock{}, err
	}
	ctx, cancel := context.WithTimeout(ctx, s.native.config().MaximumDuration)
	defer cancel()
	original := observation.admission
	if err := w.RequireActiveDirectoryAuthority(ctx, owner, original.directory); err != nil {
		return organizationpg.DirectoryMembershipLock{}, err
	}
	native := s.native
	locked, err := native.organizations.LockDirectoryMembershipUpdate(ctx, w, owner, command, update)
	if err != nil {
		return organizationpg.DirectoryMembershipLock{}, err
	}
	if err := native.organizations.RequireCredentialAuthority(ctx, w, owner, original.organization); err != nil {
		return organizationpg.DirectoryMembershipLock{}, err
	}
	if err := s.requireDirectorySourceConnection(ctx, w, original, bindings); err != nil {
		return organizationpg.DirectoryMembershipLock{}, err
	}
	if err := s.requireDirectoryMembershipUser(ctx, w, command, observation, evidence); err != nil {
		return organizationpg.DirectoryMembershipLock{}, err
	}
	return locked, nil
}

// RequireDirectoryUserMembershipAtCommit repeats the exact source fences
// after the provisional organization effect. Only the organization successor
// recorded by the same command and Work can satisfy its owner check. All
// original deadlines remain in force. Call during CheckFeatureCommit after
// checking original command custody and the exact organization effect, and
// propagate errors to roll back. It does not establish a terminal receipt.
func (s *GroupsService) RequireDirectoryUserMembershipAtCommit(ctx context.Context, w kernel.Work, owner kernel.FeatureExecutionContributor, command identity.Command, observation DirectorySourceObservation, evidence DirectoryUserMembershipEvidence, effect organizationpg.DirectoryMembershipEffect) error {
	bindings, err := s.directoryMembershipSourceBinding(ctx, w, owner, command, observation, evidence)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(ctx, s.native.config().MaximumDuration)
	defer cancel()
	original := observation.admission
	if err := w.RequireActiveDirectoryAuthority(ctx, owner, original.directory); err != nil {
		return err
	}
	spec, _ := command.Feature()
	source := directoryMembershipOwnerSource(bindings.Scope, spec.Binding.UserID, evidence.ResourceID)
	if err := s.native.organizations.RequireDirectoryMembershipSourceOwner(ctx, w, owner, command, source, original.organization, effect); err != nil {
		return err
	}
	if err := s.requireDirectorySourceConnection(ctx, w, original, bindings); err != nil {
		return err
	}
	return s.requireDirectoryMembershipUser(ctx, w, command, observation, evidence)
}
