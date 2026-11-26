package scimpostgres

import (
	"bytes"
	"context"
	"crypto/sha256"
	"math"

	identity "github.com/faustbrian/go-identity"
	kernel "github.com/faustbrian/go-identity/postgres"
	organization "github.com/faustbrian/go-organization"
	organizationpg "github.com/faustbrian/go-organization/postgres"
	scim "github.com/faustbrian/go-scim"
)

const managedMembershipField = "organization.directory-membership"

const (
	managedWithdrawalPrepareSQL = `SELECT generation,user_id FROM scim.users WHERE tenant_id=$1 AND organization_id=$2 AND provider_id=$3 AND connection_id=$4 AND resource_id=$5 AND resource=$6 AND deleted_at IS NULL`
	managedWithdrawalLockSQL    = `SELECT generation,resource,deleted_at FROM scim.users WHERE tenant_id=$1 AND organization_id=$2 AND provider_id=$3 AND connection_id=$4 AND resource_id=$5 AND user_id=$6 FOR UPDATE`
	managedWithdrawalProfileSQL = `SELECT mappings,deprovision_policy FROM scim.managed_connections WHERE tenant_id=$1 AND organization_id=$2 AND provider_id=$3 AND connection_id=$4 FOR SHARE`
)

type managedWithdrawalInput struct {
	UserID                         identity.UserID
	MemberVersion, MemberAuthority uint64
	ContributionVersion            uint64
	ContributionActive             bool
	FieldDigest, Mappings          [32]byte
}

type managedWithdrawalWork struct {
	update organizationpg.DirectoryMembershipUpdate
	locked organizationpg.DirectoryMembershipLock
}

type managedWithdrawalEffect struct {
	update organizationpg.DirectoryMembershipUpdate
	effect organizationpg.DirectoryMembershipEffect
}

func (p *nativePhase) managedDelete() bool {
	return p.service != nil && p.service.managed != nil && !p.bootstrap && p.bulk == nil && p.bulkChild == nil && p.intent.Operation == scim.UserDelete
}

func managedDeleteOperation() identity.FeatureOperation {
	return identity.FeatureOperation{
		Owner: "scim", OperationID: string(scim.UserDelete), SchemaID: "identity.scim.user-delete.managed-v1", SchemaVersion: 1,
		RecordRequirement: identity.FeatureRecordRequired, SubjectRequirement: identity.FeatureSubjectUser, VersionPolicy: identity.FeatureVersionSequential,
	}
}

func validManagedWithdrawal(input *managedWithdrawalInput) bool {
	if input == nil || input.FieldDigest == ([32]byte{}) || input.Mappings == ([32]byte{}) {
		return false
	}
	_, err := identity.ParseSubjectID(string(input.UserID))
	return err == nil && (input.MemberVersion == 0) == (input.MemberAuthority == 0) &&
		(input.MemberVersion != 0 || input.ContributionVersion == 0) && (input.ContributionVersion != 0 || !input.ContributionActive)
}

func (input *managedWithdrawalInput) field() identity.FeatureField {
	return identity.FeatureField{Name: managedMembershipField, Value: identity.FeatureValue{Kind: identity.FeatureBytes, Bytes: input.FieldDigest[:]}}
}

func (p *nativePhase) managedSource(id string, user identity.UserID) organizationpg.DirectoryMembershipSource {
	scope := p.service.config().Scope
	return organizationpg.DirectoryMembershipSource{
		TenantID: scope.TenantID, OrganizationID: scope.OrganizationID, UserID: user,
		ProviderID: organization.ID(scope.ProviderID), ConnectionID: organization.ID(scope.ConnectionID), ResourceID: organization.ID(id),
	}
}

func (p *nativePhase) managedUpdate(original originalInput, admission invocation, input *managedWithdrawalInput) (organizationpg.DirectoryMembershipUpdate, error) {
	if original.Generation < 1 || original.Generation == math.MaxInt64 {
		return organizationpg.DirectoryMembershipUpdate{}, identity.InvalidInputError{Field: "scim_projection_generation"}
	}
	return organizationpg.NewManagedSCIMMembershipWithdrawal(organizationpg.DirectoryMembershipInput{
		Source: p.managedSource(original.ID, input.UserID), ActorID: p.service.config().ActorID, Organization: admission.organization,
		MemberVersion: input.MemberVersion, MemberAuthorizationVersion: input.MemberAuthority, ExpectedVersion: input.ContributionVersion,
		Action: organizationpg.DirectoryMembershipWithdraw,
	}, input.ContributionActive, uint64(original.Generation))
}

func (p *nativePhase) prepareManagedWithdrawal(ctx context.Context, original *originalInput, user identity.UserID) error {
	if _, err := identity.ParseSubjectID(string(user)); err != nil {
		return identity.UnavailableError{}
	}
	admission, err := p.service.restoreAdmission(original.Admission, original.At)
	if err != nil {
		return err
	}
	observed, err := p.service.organizations.ObserveManagedSCIMDirectoryMembership(ctx, p.managedSource(original.ID, user))
	if err != nil {
		return identity.UnavailableError{}
	}
	input := &managedWithdrawalInput{
		UserID: user, MemberVersion: observed.Member.Version, MemberAuthority: observed.Member.AuthorizationVersion,
		ContributionVersion: observed.ContributionVersion, ContributionActive: observed.ContributionActive, Mappings: p.service.managed.mappings,
	}
	update, err := p.managedUpdate(*original, admission, input)
	if err != nil {
		return err
	}
	field, err := update.Field()
	if err != nil || field.Name != managedMembershipField || field.Value.Kind != identity.FeatureBytes || len(field.Value.Bytes) != len(input.FieldDigest) {
		return identity.UnavailableError{}
	}
	copy(input.FieldDigest[:], field.Value.Bytes)
	original.ManagedWithdrawal = input
	return nil
}

func (p *nativePhase) lockManagedWithdrawal(ctx context.Context, w kernel.Work, command identity.Command) (*managedWithdrawalWork, error) {
	input := p.original.ManagedWithdrawal
	admission, err := p.service.restoreAdmission(p.original.Admission, p.original.At)
	if !p.managedDelete() || !validManagedWithdrawal(input) || err != nil || !liveConnection(ctx, admission.connection) {
		return nil, identity.ForbiddenError{}
	}
	// Take the original directory fence before the organization owner's write
	// lock. The normal source fences then follow before the projection lock.
	if err := w.RequireActiveDirectoryAuthority(ctx, p, admission.directory); err != nil {
		return nil, err
	}
	update, err := p.managedUpdate(p.original, admission, input)
	if err != nil {
		return nil, identity.ForbiddenError{}
	}
	field, err := update.Field()
	if err != nil || field.Name != managedMembershipField || field.Value.Kind != identity.FeatureBytes || !bytes.Equal(field.Value.Bytes, input.FieldDigest[:]) {
		return nil, identity.ForbiddenError{}
	}
	locked, err := p.service.organizations.LockDirectoryMembershipUpdate(ctx, w, p, command, update)
	if err != nil {
		return nil, err
	}
	return &managedWithdrawalWork{update: update, locked: locked}, nil
}

func (p *nativePhase) applyManagedWithdrawal(ctx context.Context, w kernel.Work, command identity.Command, work *managedWithdrawalWork) error {
	effect, err := p.service.organizations.ApplyDirectoryMembershipUpdate(ctx, w, p, command, work.update, work.locked)
	if err != nil {
		return err
	}
	p.withdrawal = &managedWithdrawalEffect{update: work.update, effect: effect}
	return nil
}

func (p *nativePhase) requireOrganization(ctx context.Context, w kernel.Work, original invocation) error {
	if p.withdrawal == nil {
		return p.service.organizations.RequireCredentialAuthority(ctx, w, p, original.organization)
	}
	source := p.managedSource(p.original.ID, p.original.ManagedWithdrawal.UserID)
	return p.service.organizations.RequireDirectoryMembershipSourceOwner(ctx, w, p, p.command, source, original.organization, p.withdrawal.effect)
}

// Call only after the kernel confirmed this exact delete. The original Work
// may advance the organization by retiring the last source. Admit only that
// exact version on the fresh read, preserving every other original fence and
// timestamp. Replays without a local effect check their current invocation.
func (p *nativePhase) recheckDeleteAcknowledgement(ctx context.Context) error {
	admission := p.admission
	if p.withdrawal != nil {
		version, ok := p.withdrawal.effect.ManagedSCIMOrganizationVersion()
		if !ok || admission.organization.Version != p.original.Admission.OrganizationVersion {
			return identity.ForbiddenError{}
		}
		admission.organization.Version = version
	}
	return p.service.recheckRead(ctx, &admission)
}

func (p *nativePhase) requireManagedProfile(ctx context.Context, w kernel.Work) error {
	input := p.original.ManagedWithdrawal
	if !p.managedDelete() || input.Mappings != p.service.managed.mappings {
		return identity.ForbiddenError{}
	}
	rows, err := w.Query(ctx, managedWithdrawalProfileSQL, scopeArgs(p.service.config().Scope)...)
	if err != nil {
		return identity.UnavailableError{}
	}
	defer rows.Close()
	var mappings []byte
	var policy string
	if !rows.Next() || rows.Scan(&mappings, &policy) != nil || rows.Next() || rows.Err() != nil || policy != managedRemoveMembership || sha256.Sum256(mappings) != input.Mappings {
		return identity.ForbiddenError{}
	}
	return nil
}
