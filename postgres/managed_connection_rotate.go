package scimpostgres

import (
	"context"
	"math"

	authentication "github.com/faustbrian/go-authentication/v2"
	"github.com/faustbrian/go-authorization/v3"
	identity "github.com/faustbrian/go-identity"
	organization "github.com/faustbrian/go-organization"
	scim "github.com/faustbrian/go-scim"
)

// ConnectionRotatePreparationRequest selects one original managed rotation.
// The native service authenticates the actual session and derives the command;
// no client Idempotency-Key is accepted. Preparation never changes the bearer.
type ConnectionRotatePreparationRequest struct {
	Authentication  organization.Authentication
	ConnectionID    scim.ConnectionID
	ExpectedVersion uint64
}

// ConnectionRotateRequest executes only the exact server-prepared original.
// Command is mandatory and conveys no current session or organization authority.
type ConnectionRotateRequest struct {
	Authentication  organization.Authentication
	ConnectionID    scim.ConnectionID
	ExpectedVersion uint64
	Command         identity.Command
}

// PreviousBearerDisposition describes the original credential's committed fate.
// Zero is invalid; this native profile supports no grace or overlap period.
type PreviousBearerDisposition uint8

// PreviousBearerRevoked means the exact predecessor stopped authenticating in
// the same transaction that installed the successor.
const PreviousBearerRevoked PreviousBearerDisposition = 1

// ConnectionRotateResult returns original committed metadata on recovery.
// Bearer is populated only by the invocation that newly commits its reservation;
// retries and unknown outcomes never reveal or regenerate credential material.
type ConnectionRotateResult struct {
	Connection                scim.ConnectionRecord
	PreviousCredentialID      identity.SubjectID
	PreviousBearerDisposition PreviousBearerDisposition
	Bearer                    authentication.BearerCredential
}

// PrepareConnectionRotate authenticates and retains one immutable original in
// the existing canonical POST coordinator. It returns no bearer or permission
// witness. Retry the same target/version to recover the same command; neither
// current-state changes nor retries renew its original authority deadline.
// This trusted preparation seam is not a connection lifecycle operation.
func (s *ManagedConnectionService) PrepareConnectionRotate(ctx context.Context, request ConnectionRotatePreparationRequest) (identity.Command, error) {
	if s == nil || s.writer == nil || ctx == nil {
		return identity.Command{}, ErrInvalidConfiguration
	}
	ctx, cancel := context.WithTimeout(ctx, s.config.MaximumDuration)
	defer cancel()
	p, coordinator, scope, selector, intent, err := s.prepareManagedRotationCall(ctx, request)
	if err != nil {
		return identity.Command{}, err
	}
	b, wire, err := coordinator.ResolvePreparedCanonicalRequest(ctx, scope, selector, nil, intent, p.caller("identity.request-admission", managedRotateAction), p.registration(), p)
	defer clear(wire)
	if err != nil {
		if p.preparationErr != nil {
			err = p.preparationErr
		}
		return identity.Command{}, err
	}
	input, err := p.openInput(ctx, b, wire)
	if err != nil {
		return identity.Command{}, err
	}
	command, err := p.originalCommand(input)
	if err != nil {
		return identity.Command{}, err
	}
	if err := s.recheckManagedAdmin(ctx, request.Authentication, p.admin, p.view, "org:scim-write"); err != nil {
		return identity.Command{}, err
	}
	return command, nil
}

// ConnectionRotate requires the exact server-prepared command and current
// administrator authority. A new reservation alone may generate material and
// reveal after its confirmed commit. Recovery returns only original metadata.
// A missing/different command or changed target/version fails before effects.
func (s *ManagedConnectionService) ConnectionRotate(ctx context.Context, request ConnectionRotateRequest) (ConnectionRotateResult, error) {
	if s == nil || s.writer == nil || ctx == nil {
		return ConnectionRotateResult{}, ErrInvalidConfiguration
	}
	ctx, cancel := context.WithTimeout(ctx, s.config.MaximumDuration)
	defer cancel()
	if request.Command == (identity.Command{}) {
		return ConnectionRotateResult{}, identity.InvalidInputError{Field: "command"}
	}
	preparation := ConnectionRotatePreparationRequest{Authentication: request.Authentication, ConnectionID: request.ConnectionID, ExpectedVersion: request.ExpectedVersion}
	p, coordinator, scope, selector, intent, err := s.prepareManagedRotationCall(ctx, preparation)
	if err != nil {
		return ConnectionRotateResult{}, err
	}
	b, wire, found, err := coordinator.ReadPreparedCanonicalRequest(ctx, scope, selector, nil, intent, p.caller("identity.request-admission", managedRotateAction), p.registration(), p)
	defer clear(wire)
	if err != nil {
		return ConnectionRotateResult{}, err
	}
	if !found {
		return ConnectionRotateResult{}, identity.ConflictError{}
	}
	input, err := p.openInput(ctx, b, wire)
	if err != nil {
		return ConnectionRotateResult{}, err
	}
	if err := p.acceptCommand(input, request.Command); err != nil {
		return ConnectionRotateResult{}, err
	}
	if err := p.execute(ctx, coordinator); err != nil {
		return ConnectionRotateResult{}, err
	}
	if err := s.recheckManagedAdmin(ctx, request.Authentication, p.admin, p.view, "org:scim-write"); err != nil {
		return ConnectionRotateResult{}, err
	}
	mappings, err := decodeManagedMappings(input.Mappings, s.config.Limits)
	if err != nil {
		return ConnectionRotateResult{}, identity.UnavailableError{}
	}
	record, err := scim.NewConnectionRecord(input.Scope, mappings, scim.RemoveMembership, input.ExpectedVersion+1)
	if err != nil {
		return ConnectionRotateResult{}, identity.UnavailableError{}
	}
	return ConnectionRotateResult{Connection: record, PreviousCredentialID: input.Previous.Credential, PreviousBearerDisposition: PreviousBearerRevoked, Bearer: p.bearer}, nil
}

func (s *ManagedConnectionService) managedRotationAdmin(ctx context.Context, request ConnectionRotatePreparationRequest) (managedAdmin, organization.View, error) {
	if s == nil || s.writer == nil || ctx == nil {
		return managedAdmin{}, organization.View{}, ErrInvalidConfiguration
	}
	if _, err := scim.ParseConnectionID(string(request.ConnectionID)); err != nil || request.ExpectedVersion == 0 || request.ExpectedVersion == math.MaxUint64 {
		return managedAdmin{}, organization.View{}, identity.InvalidInputError{Field: "connection_version"}
	}
	admin, err := s.authenticateManagedAdmin(ctx, request.Authentication)
	if err != nil {
		return managedAdmin{}, organization.View{}, err
	}
	var org organization.ID
	if err := s.pool.Raw().QueryRow(ctx, managedConnectionOrganizationSQL, string(admin.tenant), string(request.ConnectionID)).Scan(&org); err != nil {
		return managedAdmin{}, organization.View{}, managedConnectionReadError(ctx, err)
	}
	view, err := s.authorizeManagedAdmin(ctx, admin, org, authorization.Action("org:scim-write"))
	return admin, view, err
}
