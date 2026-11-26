package scimpostgres

import (
	"bytes"
	"context"
	"strconv"
	"time"

	authentication "github.com/faustbrian/go-authentication/v2"
	identity "github.com/faustbrian/go-identity"
	kernel "github.com/faustbrian/go-identity/postgres"
)

func (p *managedRotatePhase) execute(ctx context.Context, coordinator *kernel.Coordinator) error {
	plan, err := p.plan(coordinator)
	if err != nil {
		return err
	}
	reservation, result, err := coordinator.ReserveCommand(ctx, p.binding(p.input), p.command, plan)
	if err != nil {
		return err
	}
	if reservation == (kernel.Reservation{}) {
		if result.Outcome == identity.CommitOutcomeCommitted {
			return nil
		}
		return identity.UnknownCommitError{CommandID: p.input.CommandID}
	}
	work, err := coordinator.Begin(ctx, reservation)
	if err != nil {
		return err
	}
	defer func() { _, _ = coordinator.Abort(work, identity.UnavailableError{}) }()
	committed := false
	defer func() {
		if !committed {
			p.bearer = authentication.BearerCredential{}
		}
	}()
	result, err = coordinator.ApplyFeature(ctx, work, p.command)
	if err != nil {
		_, err = coordinator.Abort(work, err)
		return err
	}
	result, err = coordinator.Commit(work, result)
	if err != nil {
		return err
	}
	if result.Outcome != identity.CommitOutcomeCommitted {
		return identity.UnknownCommitError{CommandID: p.input.CommandID}
	}
	committed = true
	return nil
}

const managedRotateFenceSQL = `SELECT c.version::text,c.credential_id,c.credential_digest,c.configuration_digest,c.expires_at,c.authority_version::text,c.organization_credential_version::text,c.command_id,c.effect_digest,m.mappings,m.deprovision_policy
 FROM scim.connections c JOIN scim.managed_connections m USING(tenant_id,organization_id,provider_id,connection_id)
 WHERE c.tenant_id=$1 AND c.organization_id=$2 AND c.provider_id=$3 AND c.connection_id=$4 AND c.state='active'
 FOR UPDATE OF c FOR SHARE OF m`

// The exact managed row and predecessor generation serialize rotations and
// native provisioning together. Neither Users nor source membership rows move.
const managedRotateUpdateSQL = `UPDATE scim.connections SET credential_id=$5,credential_digest=$6,configuration_digest=$7,expires_at=$8,version=$9::numeric,authority_version=$10::numeric,organization_credential_version=$11::numeric,command_id=$12,effect_digest=$13
 WHERE tenant_id=$1 AND organization_id=$2 AND provider_id=$3 AND connection_id=$4 AND version=$14::numeric AND credential_id=$15 AND credential_digest=$16 AND configuration_digest=$17 AND state='active'`

func (p *managedRotatePhase) ApplyFeature(ctx context.Context, work kernel.Work, command identity.Command) (identity.FeatureReceipt, error) {
	if err := work.RequireFeatureCommand(ctx, p, command); err != nil {
		return identity.FeatureReceipt{}, err
	}
	if p.successor != nil || p.applied {
		return identity.FeatureReceipt{}, identity.ForbiddenError{}
	}
	if err := p.CheckFeatureCommit(ctx, work, command); err != nil {
		return identity.FeatureReceipt{}, err
	}
	x := p.input
	// Only a new reservation with still-live original authority and the exact
	// locked predecessor can generate output entropy. Recovery has no bearer
	// custody and cannot extend this deadline or repeat the reveal.
	bearer, digest, err := issueManagedBearer(x.Scope, x.Credential, p.writer.config.CredentialKey)
	if err != nil {
		return identity.FeatureReceipt{}, identity.UnavailableError{}
	}
	mappings, err := decodeManagedMappings(x.Mappings, p.service.config.Limits)
	if err != nil {
		return identity.FeatureReceipt{}, identity.UnavailableError{}
	}
	p.successor, err = p.writer.provisionedVersionService(p.service.pool, x.Scope, x.Credential, digest, x.Expiry, mappings, x.ExpectedVersion+1)
	if err != nil {
		return identity.FeatureReceipt{}, identity.UnavailableError{}
	}
	successor := p.successor.config()
	keys := scopeArgs(p.source.config().Scope)
	args := append(keys, string(x.Credential), successor.Credential.expected[:], p.successor.profile[:], x.Expiry, strconv.FormatUint(x.ExpectedVersion+1, 10), strconv.FormatUint(x.Authority.ProvisioningEpoch, 10), strconv.FormatUint(x.Authority.Organization.CredentialVersion, 10), string(x.CommandID), p.effect[:], strconv.FormatUint(x.ExpectedVersion, 10), string(x.Previous.Credential), x.Previous.Digest[:], x.Previous.Profile[:])
	count, err := work.Exec(ctx, managedRotateUpdateSQL, args...)
	if err != nil {
		return identity.FeatureReceipt{}, identity.UnavailableError{}
	}
	if count != 1 {
		return identity.FeatureReceipt{}, identity.ConflictError{}
	}
	p.applied = true
	p.bearer = bearer
	return identity.FeatureReceipt{Operation: managedRotateOperation(), BeforeVersion: x.ExpectedVersion, AfterVersion: x.ExpectedVersion + 1}, nil
}

func (p *managedRotatePhase) CheckFeatureCommit(ctx context.Context, work kernel.Work, command identity.Command) error {
	if command != p.command || p.source == nil {
		return identity.ForbiddenError{}
	}
	if err := requireManagedCreateAuthority(ctx, work, p, p.source, p.writer.config.SessionStorage, p.input.Authority, p.admin); err != nil {
		return err
	}
	now, err := work.DatabaseTime(ctx)
	if err != nil {
		return err
	}
	if now.Before(p.input.At) || !now.Before(p.input.Expiry) {
		return identity.ForbiddenError{}
	}
	rows, err := work.Query(ctx, managedRotateFenceSQL, scopeArgs(p.source.config().Scope)...)
	if err != nil {
		return identity.UnavailableError{}
	}
	defer rows.Close()
	var version, credential, epoch, orgCredential, commandID, policy string
	var digest, profile, effect, mappings []byte
	var expiry time.Time
	if !rows.Next() || rows.Scan(&version, &credential, &digest, &profile, &expiry, &epoch, &orgCredential, &commandID, &effect, &mappings, &policy) != nil || rows.Next() || rows.Err() != nil {
		return identity.ConflictError{}
	}
	expected := p.input.Previous
	generation := p.input.ExpectedVersion
	if p.applied {
		if p.successor == nil {
			return identity.ForbiddenError{}
		}
		c := p.successor.config()
		expected = managedRotateBinding{Credential: p.input.Credential, Digest: c.Credential.expected, Profile: p.successor.profile, Expiry: p.input.Expiry, ProvisioningEpoch: p.input.Authority.ProvisioningEpoch, OrganizationCredentialVersion: p.input.Authority.Organization.CredentialVersion, CommandID: p.input.CommandID, Effect: p.effect}
		generation++
	}
	if version != strconv.FormatUint(generation, 10) || credential != string(expected.Credential) || !bytes.Equal(digest, expected.Digest[:]) || !bytes.Equal(profile, expected.Profile[:]) || !expiry.Equal(expected.Expiry) || epoch != strconv.FormatUint(expected.ProvisioningEpoch, 10) || orgCredential != strconv.FormatUint(expected.OrganizationCredentialVersion, 10) || commandID != string(expected.CommandID) || !bytes.Equal(effect, expected.Effect[:]) || !bytes.Equal(mappings, p.input.Mappings) || policy != managedRemoveMembership {
		return identity.ConflictError{}
	}
	return nil
}

func (p *managedRotatePhase) RecoverParticipant(ctx context.Context, work kernel.RecoveryWork) (kernel.RecoveryStatus, error) {
	b, feature, lifecycle, err := work.FeatureScope(p)
	if err != nil || feature != p.registration() || lifecycle != p.lifecycle() || b != p.binding(p.input) {
		return kernel.RecoveryUnknown, identity.ForbiddenError{}
	}
	rows, err := work.Query(ctx, managedRotateRecoverySQL, scopeArgs(p.source.config().Scope)...)
	if err != nil {
		return kernel.RecoveryUnknown, identity.UnavailableError{}
	}
	defer rows.Close()
	var version, command string
	var effect []byte
	if !rows.Next() || rows.Scan(&version, &command, &effect) != nil || rows.Next() || rows.Err() != nil {
		return kernel.RecoveryUnknown, nil
	}
	// Absence of our latest row marker is not rollback evidence after a later
	// rotation. Only the unchanged exact predecessor proves this effect absent.
	if version == strconv.FormatUint(p.input.ExpectedVersion, 10) && command == string(p.input.Previous.CommandID) && bytes.Equal(effect, p.input.Previous.Effect[:]) {
		return kernel.RecoveryNotCommitted, nil
	}
	if version == strconv.FormatUint(p.input.ExpectedVersion+1, 10) && command == string(p.input.CommandID) && bytes.Equal(effect, p.effect[:]) {
		return kernel.RecoveryCommitted, nil
	}
	return kernel.RecoveryUnknown, nil
}

const managedRotateRecoverySQL = `SELECT version::text,command_id,effect_digest FROM scim.connections WHERE tenant_id=$1 AND organization_id=$2 AND provider_id=$3 AND connection_id=$4`
