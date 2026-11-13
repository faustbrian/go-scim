package scimpostgres

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"

	identity "github.com/faustbrian/go-identity"
	scim "github.com/faustbrian/go-scim"
)

func (b *protocolBridge) Prepare(ctx context.Context, intent scim.WriteIntent) (scim.PreparedWrite, error) {
	i, err := currentInvocation(ctx)
	if err != nil || intent.Operation != scim.UserCreate || intent.Scope != i.connection.Scope || intent.Connection != i.connection || intent.ResourceID != "" || intent.IfMatch != "" || len(intent.CanonicalRequest) == 0 || len(intent.CanonicalRequest) > 131072 || !liveConnection(ctx, i.connection) {
		return scim.PreparedWrite{}, identity.ForbiddenError{}
	}
	p := &nativePhase{service: b.service, admission: *i}
	if intent.IdempotencyKey == "" {
		// Pure mapping needs no durable entropy preparation. Keep the root's
		// original proposal command and invocation-only metadata; Commit still
		// uses the same authoritative reservation/Work/journal as keyed creates.
		p.coordinator, p.registry, err = b.service.coordinator(p)
		if err != nil {
			return scim.PreparedWrite{}, err
		}
		p.original, err = p.newOriginalInput(ctx, intent.CommandID)
		if err != nil {
			return scim.PreparedWrite{}, err
		}
	} else {
		if err := p.resolveOriginal(ctx, intent.IdempotencyKey, intent.CanonicalRequest); err != nil {
			return scim.PreparedWrite{}, prepareError(err)
		}
	}
	intent.CommandID = p.original.Command
	intent.CanonicalRequest = bytes.Clone(intent.CanonicalRequest)
	p.intent = intent
	i.phase = p
	metadata := &scim.CreateMetadata{ID: p.original.ID, Version: p.original.Version, CreatedAt: p.original.At, LastModified: p.original.At}
	return scim.PreparedWrite{Intent: intent, CreateMetadata: metadata}, nil
}

func prepareError(err error) error {
	var conflict identity.ConflictError
	if errors.As(err, &conflict) {
		return scim.ErrConflict
	}
	return err
}

func (b *protocolBridge) Commit(ctx context.Context, prepared scim.PreparedWrite, change scim.Change) (scim.WriteResult, error) {
	i, err := currentInvocation(ctx)
	if err != nil || i.phase == nil {
		return scim.WriteResult{}, identity.ForbiddenError{}
	}
	p := i.phase
	expected := p.intent
	actual := prepared.Intent
	if actual.CommandID != expected.CommandID || actual.Scope != expected.Scope || actual.Connection != expected.Connection || actual.Operation != expected.Operation || actual.ResourceID != expected.ResourceID || actual.IfMatch != expected.IfMatch || actual.IdempotencyKey != expected.IdempotencyKey || !bytes.Equal(actual.CanonicalRequest, expected.CanonicalRequest) || prepared.Current != nil || prepared.Replay != nil || change.Delete || change.Resource == nil || prepared.CreateMetadata == nil || !liveConnection(ctx, i.connection) {
		return scim.WriteResult{}, identity.ForbiddenError{}
	}
	resource := change.Resource
	if resource.ID != p.original.ID || resource.Version != p.original.Version || !resource.CreatedAt.Equal(p.original.At) || !resource.LastModified.Equal(p.original.At) || prepared.CreateMetadata.ID != resource.ID || prepared.CreateMetadata.Version != resource.Version || !prepared.CreateMetadata.CreatedAt.Equal(resource.CreatedAt) || !prepared.CreateMetadata.LastModified.Equal(resource.LastModified) {
		return scim.WriteResult{}, identity.ForbiddenError{}
	}
	wire, err := json.Marshal(resource)
	if err != nil || len(wire) > 131072 {
		return scim.WriteResult{}, identity.InvalidInputError{Field: "scim_resource"}
	}
	if json.Unmarshal(wire, &p.resource) != nil {
		return scim.WriteResult{}, identity.UnavailableError{}
	}
	if _, ok := p.resource.Attributes["userName"].(string); !ok {
		return scim.WriteResult{}, identity.InvalidInputError{Field: "scim_username"}
	}
	if err := p.initialize(ctx, actual.CanonicalRequest); err != nil {
		return scim.WriteResult{Outcome: scim.WriteOutcomeNotCommitted}, err
	}
	result, err := p.execute(ctx)
	if result.Outcome == identity.CommitOutcomeCommitted && err == nil {
		stored, readErr := b.readOriginal(ctx, p)
		if readErr != nil {
			return scim.WriteResult{Outcome: scim.WriteOutcomeUnknown}, readErr
		}
		return scim.WriteResult{Outcome: scim.WriteOutcomeCommitted, Resource: &stored}, nil
	}
	var conflict identity.ConflictError
	if errors.As(err, &conflict) {
		return scim.WriteResult{Outcome: scim.WriteOutcomeNotCommitted}, scim.ErrUniqueness
	}
	switch result.Outcome {
	case identity.CommitOutcomeNotCommitted, identity.CommitOutcomeConflict:
		return scim.WriteResult{Outcome: scim.WriteOutcomeNotCommitted}, err
	case identity.CommitOutcomeInProgress:
		return scim.WriteResult{Outcome: scim.WriteOutcomeInProgress}, nil
	default:
		return scim.WriteResult{Outcome: scim.WriteOutcomeUnknown}, err
	}
}

func (b *protocolBridge) readOriginal(ctx context.Context, p *nativePhase) (scim.Resource, error) {
	args := append(scopeArgs(p.service.config().Scope), p.original.ID, string(p.original.Command))
	var wire []byte
	var digest []byte
	err := b.service.pool.Raw().QueryRow(ctx, `SELECT resource,effect_digest FROM scim.users WHERE tenant_id=$1 AND organization_id=$2 AND provider_id=$3 AND connection_id=$4 AND resource_id=$5 AND command_id=$6 AND octet_length(resource)<=131072`, args...).Scan(&wire, &digest)
	if err != nil || !bytes.Equal(digest, p.effect[:]) || len(wire) > 131072 || !liveConnection(ctx, p.admission.connection) {
		return scim.Resource{}, identity.UnavailableError{}
	}
	var resource scim.Resource
	if json.Unmarshal(wire, &resource) != nil || resource.ID != p.original.ID {
		return scim.Resource{}, identity.UnavailableError{}
	}
	// A retained committed receipt skips Apply's original-authority fences.
	// Disclosure therefore requires this invocation's genuine current owners,
	// not the historical encrypted admission or merely a live local deadline.
	if err := b.service.recheckRead(ctx, &p.admission); err != nil {
		return scim.Resource{}, err
	}
	return resource, nil
}

func (*protocolBridge) Abort(ctx context.Context, _ scim.PreparedWrite) error {
	// Prepare holds no locks, reservation or transaction. ResolvePreparedRequestKey
	// owns only immutable correlation; Commit's coordinator closes every Work.
	if ctx == nil {
		return identity.InvalidInputError{Field: "scim_context"}
	}
	return ctx.Err()
}
