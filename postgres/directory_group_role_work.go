package scimpostgres

import (
	"context"

	identity "github.com/faustbrian/go-identity"
	kernel "github.com/faustbrian/go-identity/postgres"
	organizationpg "github.com/faustbrian/go-organization/postgres"
)

// LockDirectoryGroupRole borrows the original registered directory-sync child's
// Apply Work and returns the organization owner's exact provisional role lock.
// It binds the configured source observation, connection version, direct Group
// edge and identity target to the original command. The directory authority and
// organization writer are locked before the original organization credential
// observation and SCIM connection, preserving the cross-owner lock order.
// It creates no transaction, permission decision or effect and never renews
// source freshness. Propagate errors, apply through ApplyDirectoryTeamRoleUpdate,
// then use RequireDirectoryGroupRoleAtCommit in the same owner's final phase.
// The SSO owner separately fences its provider, mapping and synchronization grant.
func (s *GroupsService) LockDirectoryGroupRole(ctx context.Context, w kernel.Work, owner kernel.FeatureExecutionContributor, command identity.Command, observation DirectorySourceObservation, edge DirectoryGroupEdge, source organizationpg.DirectoryTeamRoleSource, update organizationpg.DirectoryTeamRoleUpdate) (organizationpg.DirectoryTeamRoleLock, error) {
	if err := w.RequireFeatureCommand(ctx, owner, command); err != nil {
		return organizationpg.DirectoryTeamRoleLock{}, err
	}
	bindings, err := s.directoryGroupRoleBinding(ctx, w, owner, command, observation, edge, source)
	if err != nil {
		return organizationpg.DirectoryTeamRoleLock{}, err
	}
	if !update.MatchesSource(source, edge.Present) {
		return organizationpg.DirectoryTeamRoleLock{}, identity.ForbiddenError{}
	}
	ctx, cancel := context.WithTimeout(ctx, s.native.config().MaximumDuration)
	defer cancel()
	original := observation.admission
	if err := w.RequireActiveDirectoryAuthority(ctx, owner, original.directory); err != nil {
		return organizationpg.DirectoryTeamRoleLock{}, err
	}
	locked, err := s.native.organizations.LockDirectoryTeamRoleUpdate(ctx, w, owner, command, update)
	if err != nil {
		return organizationpg.DirectoryTeamRoleLock{}, err
	}
	if err := s.native.organizations.RequireCredentialAuthority(ctx, w, owner, original.organization); err != nil {
		return organizationpg.DirectoryTeamRoleLock{}, err
	}
	if err := s.requireDirectorySourceConnection(ctx, w, original, bindings); err != nil {
		return organizationpg.DirectoryTeamRoleLock{}, err
	}
	if err := s.requireDirectoryRoleGroupEdge(ctx, w, command, observation, edge); err != nil {
		return organizationpg.DirectoryTeamRoleLock{}, err
	}
	return locked, nil
}

// RequireDirectoryGroupRoleAtCommit rechecks the original source and exact role
// contribution in the same owner's final invocation. Call after the organization
// owner's RequireDirectoryTeamRoleUpdate, and compare command with the retained
// original command first. Only that Work's verified organization successor is
// accepted; its credential epoch and the original source deadline stay unchanged.
// A mismatched source/update, late source change or elapsed deadline must roll
// back every provisional role, membership, authorization, audit and event effect.
// This borrows Work without opening a transaction or reobserving authority.
func (s *GroupsService) RequireDirectoryGroupRoleAtCommit(ctx context.Context, w kernel.Work, owner kernel.FeatureExecutionContributor, command identity.Command, observation DirectorySourceObservation, edge DirectoryGroupEdge, source organizationpg.DirectoryTeamRoleSource, locked organizationpg.DirectoryTeamRoleLock) error {
	bindings, err := s.directoryGroupRoleBinding(ctx, w, owner, command, observation, edge, source)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(ctx, s.native.config().MaximumDuration)
	defer cancel()
	original := observation.admission
	if err := w.RequireActiveDirectoryAuthority(ctx, owner, original.directory); err != nil {
		return err
	}
	if err := s.native.organizations.RequireDirectoryTeamRoleSourceOwner(ctx, w, owner, command, source, original.organization, locked); err != nil {
		return err
	}
	if err := s.requireDirectorySourceConnection(ctx, w, original, bindings); err != nil {
		return err
	}
	return s.requireDirectoryRoleGroupEdge(ctx, w, command, observation, edge)
}

func (s *GroupsService) directoryGroupRoleBinding(ctx context.Context, w kernel.Work, owner kernel.FeatureExecutionContributor, command identity.Command, observation DirectorySourceObservation, edge DirectoryGroupEdge, source organizationpg.DirectoryTeamRoleSource) (DirectorySourceBindings, error) {
	bindings, err := s.directorySourceBinding(ctx, w, owner, command, observation, directoryGroupSourceRegistration())
	if err != nil {
		return DirectorySourceBindings{}, err
	}
	spec, _ := command.Feature()
	scope := bindings.Scope
	if source.Scope.TenantID != scope.TenantID || source.Scope.OrganizationID != scope.OrganizationID ||
		string(source.Scope.ProviderID) != scope.ProviderID || string(source.Scope.ConnectionID) != scope.ConnectionID ||
		source.ConnectionVersion != bindings.ConnectionVersion || string(source.Scope.GroupID) != edge.GroupID ||
		string(source.MemberResourceID) != edge.UserID || source.Scope.UserID != spec.Binding.UserID ||
		source.ProviderVersion == 0 || source.MappingVersion == 0 {
		return DirectorySourceBindings{}, identity.ForbiddenError{}
	}
	return bindings, nil
}
