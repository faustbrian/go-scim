package scimpostgres

import (
	"context"
	"errors"
	"strconv"
	"time"

	"github.com/faustbrian/go-authorization/v3"
	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/session"
	organization "github.com/faustbrian/go-organization"
)

type managedAdmin struct {
	tenant  identity.TenantID
	user    identity.UserID
	spec    session.SessionSpec
	session session.GetResult
}

func (s *ManagedConnectionService) authenticateManagedAdmin(ctx context.Context, auth organization.Authentication) (managedAdmin, error) {
	if _, err := identity.ParseSubjectID(string(auth.TenantID)); err != nil {
		return managedAdmin{}, identity.InvalidInputError{Field: "tenant_id"}
	}
	token, err := session.ParseToken(auth.Bearer.Token())
	if err != nil {
		return managedAdmin{}, identity.ForbiddenError{}
	}
	credential, err := session.NewCredential(session.CredentialBearer, token)
	if err != nil {
		return managedAdmin{}, identity.ForbiddenError{}
	}
	observed, err := s.config.Sessions.Get(ctx, session.GetRequest{TenantID: auth.TenantID, Credential: credential})
	if err != nil {
		if ctx.Err() != nil {
			return managedAdmin{}, ctx.Err()
		}
		if errors.Is(err, session.ErrUnavailable) {
			return managedAdmin{}, identity.UnavailableError{}
		}
		return managedAdmin{}, identity.ForbiddenError{}
	}
	if observed.ValidateAt(time.Now().UTC()) != nil {
		return managedAdmin{}, identity.ForbiddenError{}
	}
	spec, err := observed.Session.Bindings()
	if err != nil || spec.TenantID != auth.TenantID || spec.Authentication.Kind != session.AuthenticationVerified {
		return managedAdmin{}, identity.ForbiddenError{}
	}
	if _, err := identity.ParseSubjectID(string(spec.UserID)); err != nil {
		return managedAdmin{}, identity.ForbiddenError{}
	}
	return managedAdmin{tenant: spec.TenantID, user: spec.UserID, spec: spec, session: observed}, nil
}

func (s *ManagedConnectionService) authorizeManagedAdmin(ctx context.Context, actor managedAdmin, org organization.ID, action authorization.Action) (view organization.View, err error) {
	defer func() {
		if recover() != nil {
			view, err = organization.View{}, identity.UnavailableError{}
		}
	}()
	view, err = s.organizations.Read(ctx, organization.Query{Operation: organization.Get, TenantID: actor.tenant, ActorID: actor.user, OrganizationID: org})
	if err != nil {
		if ctx.Err() != nil {
			return organization.View{}, ctx.Err()
		}
		if errors.Is(err, organization.ErrUnavailable) {
			return organization.View{}, identity.UnavailableError{}
		}
		return organization.View{}, identity.ForbiddenError{}
	}
	m := view.Actor
	o := view.Organization
	if !o.Active || !m.Active || o.ID != org || m.OrganizationID != org || o.TenantID != actor.tenant || m.TenantID != actor.tenant || m.UserID != actor.user || (m.Role != organization.RoleOwner && m.Role != organization.RoleAdministrator) {
		return organization.View{}, identity.ForbiddenError{}
	}
	revision := authorization.Revision(s.config.PolicyVersion)
	decision, err := s.config.Authorization.Decide(ctx, authorization.DecisionContext{
		PolicyRevision: revision,
		Request: authorization.Request{
			Subject: authorization.Subject{Kind: authorization.SubjectUser, ID: authorization.SubjectID(actor.user)},
			Action:  action,
			Resource: authorization.Resource{
				Type: "organization", ID: authorization.ResourceID(org),
				Attributes: authorization.Attributes{"organization.policy-version": authorization.StringValue(strconv.FormatUint(o.Version, 10))},
			},
			Tenant:      authorization.TenantID(actor.tenant),
			Environment: authorization.Environment{Time: time.Now().UTC()},
		},
	})
	if ctx.Err() != nil {
		return organization.View{}, ctx.Err()
	}
	if err != nil {
		return organization.View{}, identity.UnavailableError{}
	}
	if decision.Outcome != authorization.Allow || decision.Revision != revision || actor.session.ValidateAt(time.Now().UTC()) != nil {
		return organization.View{}, identity.ForbiddenError{}
	}
	return view, nil
}

func (s *ManagedConnectionService) recheckManagedAdmin(ctx context.Context, auth organization.Authentication, first managedAdmin, view organization.View, action authorization.Action) error {
	current, err := s.authenticateManagedAdmin(ctx, auth)
	if err != nil {
		return err
	}
	a, b := first.spec, current.spec
	if first.tenant != current.tenant || first.user != current.user || a.SessionID != b.SessionID || a.FamilyID != b.FamilyID || a.Version != b.Version || a.FamilyVersion != b.FamilyVersion {
		return identity.ForbiddenError{}
	}
	latest, err := s.authorizeManagedAdmin(ctx, current, view.Organization.ID, action)
	if err != nil {
		return err
	}
	if latest.Organization.Version != view.Organization.Version || latest.Actor.Version != view.Actor.Version || latest.Actor.AuthorizationVersion != view.Actor.AuthorizationVersion || latest.Actor.Role != view.Actor.Role || first.session.ValidateAt(time.Now().UTC()) != nil {
		return identity.ForbiddenError{}
	}
	return nil
}
