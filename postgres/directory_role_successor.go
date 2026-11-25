package scimpostgres

import (
	"context"
	"time"

	identity "github.com/faustbrian/go-identity"
	organization "github.com/faustbrian/go-organization"
	organizationpg "github.com/faustbrian/go-organization/postgres"
)

// AdvanceDirectorySourceAfterRoleCommit continues the original sealed source
// from an independently authenticated committed role receipt. Only the exact
// organization version changes. Connection, actor, freshness, and all other
// authority remain original. The next Work still fences those facts live.
func (s *GroupsService) AdvanceDirectorySourceAfterRoleCommit(ctx context.Context, original DirectorySourceObservation, source organizationpg.DirectoryTeamRoleSource, receipt identity.CommandResult) (DirectorySourceObservation, error) {
	var zero DirectorySourceObservation
	bindings, err := s.successorSourceBindings(ctx, original)
	if err != nil {
		return zero, err
	}
	want := directorySuccessorScope(bindings)
	if source.Scope.TenantID != want.TenantID || source.Scope.OrganizationID != want.OrganizationID ||
		source.Scope.ProviderID != want.ProviderID || source.Scope.ConnectionID != want.ConnectionID ||
		source.ConnectionVersion != bindings.ConnectionVersion || receipt.Binding.ActorID != want.ActorID {
		return zero, identity.ForbiddenError{}
	}
	ctx, cancel := context.WithTimeout(ctx, min(s.native.config().MaximumDuration, time.Until(bindings.ValidUntil)))
	defer cancel()
	successor, err := s.native.organizations.RecoverDirectoryTeamRoleSuccessor(ctx, source, original.admission.organization, receipt)
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

// ValidateDirectorySourceSuccessorPrefix verifies the independently recovered
// authority-changing children of the exact original batch prefix. The source
// must already have observed the current organization version. This check
// neither refreshes an older source nor returns new admission evidence. The
// caller owns receipt authentication, ordering, and any subsequent live Work.
func (s *GroupsService) ValidateDirectorySourceSuccessorPrefix(ctx context.Context, original DirectorySourceObservation, prefix []organizationpg.DirectorySourceCommittedChild) error {
	bindings, err := s.successorSourceBindings(ctx, original)
	if err != nil {
		return err
	}
	if len(prefix) == 0 || len(prefix) > 1000 {
		return identity.ForbiddenError{}
	}
	want := directorySuccessorScope(bindings)
	for _, child := range prefix {
		if !child.MatchesSource(want) {
			return identity.ForbiddenError{}
		}
	}
	ctx, cancel := context.WithTimeout(ctx, min(s.native.config().MaximumDuration, time.Until(bindings.ValidUntil)))
	defer cancel()
	if err := s.native.organizations.ValidateDirectorySourceSuccessorChain(ctx, original.admission.organization, prefix); err != nil {
		return err
	}
	_, err = original.bindings(ctx)
	return err
}

func (s *GroupsService) successorSourceBindings(ctx context.Context, original DirectorySourceObservation) (DirectorySourceBindings, error) {
	if s == nil || s.native == nil || s.protocol == nil || s.native.config == nil || ctx == nil || original.source != s.native {
		return DirectorySourceBindings{}, identity.ForbiddenError{}
	}
	return original.bindings(ctx)
}

func directorySuccessorScope(b DirectorySourceBindings) organizationpg.DirectorySuccessorSourceScope {
	return organizationpg.DirectorySuccessorSourceScope{
		TenantID: b.Scope.TenantID, OrganizationID: b.Scope.OrganizationID,
		ProviderID: organization.ID(b.Scope.ProviderID), ConnectionID: organization.ID(b.Scope.ConnectionID), ActorID: b.ActorID,
	}
}
