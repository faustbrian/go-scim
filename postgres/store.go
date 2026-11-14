package scimpostgres

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"

	identity "github.com/faustbrian/go-identity"
	kernel "github.com/faustbrian/go-identity/postgres"
	scim "github.com/faustbrian/go-scim"
)

func (b *protocolBridge) Prepare(ctx context.Context, intent scim.WriteIntent) (scim.PreparedWrite, error) {
	i, err := currentInvocation(ctx)
	if err != nil || intent.Scope != i.connection.Scope || intent.Connection != i.connection || len(intent.CanonicalRequest) == 0 || !liveConnection(ctx, i.connection) {
		return scim.PreparedWrite{}, identity.ForbiddenError{}
	}
	// Only Execute mints this private invocation. The root has already bounded
	// the body/query before canonicalization; several valid PATCH operations
	// can exceed the separate 128 KiB final-resource/original-Current budget.
	if groupOperation(intent.Operation) != b.groups {
		return scim.PreparedWrite{}, identity.ForbiddenError{}
	}
	if nativeCreate(intent.Operation) {
		if intent.ResourceID != "" || intent.IfMatch != "" {
			return scim.PreparedWrite{}, identity.ForbiddenError{}
		}
	} else if !nativeMutation(intent.Operation) || intent.ResourceID == "" || intent.IfMatch == "" {
		return scim.PreparedWrite{}, identity.ForbiddenError{}
	}
	p := &nativePhase{service: b.service, admission: *i, intent: intent}
	if intent.IdempotencyKey == "" && !nativeDelete(intent.Operation) {
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
	if nativeMutation(intent.Operation) {
		current, err := copyCurrent(p.original.Current)
		if err != nil {
			return scim.PreparedWrite{}, err
		}
		prepared := scim.PreparedWrite{Intent: intent, Current: current}
		if current != nil && !nativeDelete(intent.Operation) {
			prepared.UpdateMetadata = &scim.UpdateMetadata{Version: p.original.Version, LastModified: p.original.At}
		}
		return prepared, nil
	}
	metadata := &scim.CreateMetadata{ID: p.original.ID, Version: p.original.Version, CreatedAt: p.original.At, LastModified: p.original.At}
	return scim.PreparedWrite{Intent: intent, CreateMetadata: metadata}, nil
}

func copyCurrent(current *scim.Resource) (*scim.Resource, error) {
	if current == nil {
		return nil, nil
	}
	wire, err := json.Marshal(current)
	if err != nil || len(wire) > 131072 {
		return nil, identity.UnavailableError{}
	}
	defer clear(wire)
	var detached scim.Resource
	if json.Unmarshal(wire, &detached) != nil {
		return nil, identity.UnavailableError{}
	}
	return &detached, nil
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
	if actual.CommandID != expected.CommandID || actual.Scope != expected.Scope || actual.Connection != expected.Connection || actual.Operation != expected.Operation || actual.ResourceID != expected.ResourceID || actual.IfMatch != expected.IfMatch || actual.IdempotencyKey != expected.IdempotencyKey || !bytes.Equal(actual.CanonicalRequest, expected.CanonicalRequest) || prepared.Replay != nil || !liveConnection(ctx, i.connection) {
		return scim.WriteResult{}, identity.ForbiddenError{}
	}
	if nativeDelete(actual.Operation) {
		return b.commitDelete(ctx, p, prepared, change)
	}
	if nativeMutation(actual.Operation) {
		return b.commitUpdate(ctx, p, prepared, change)
	}
	if prepared.Current != nil || prepared.UpdateMetadata != nil || change.Delete || change.Resource == nil || prepared.CreateMetadata == nil {
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
	if _, ok := p.resource.Attributes["userName"].(string); !ok && !p.group() {
		return scim.WriteResult{}, identity.InvalidInputError{Field: "scim_username"}
	}
	if err := p.initialize(ctx, actual.CanonicalRequest); err != nil {
		return scim.WriteResult{Outcome: scim.WriteOutcomeNotCommitted}, err
	}
	return b.executeResourceWrite(ctx, p)
}

func (b *protocolBridge) commitUpdate(ctx context.Context, p *nativePhase, prepared scim.PreparedWrite, change scim.Change) (scim.WriteResult, error) {
	current, metadata := p.original.Current, prepared.UpdateMetadata
	if current == nil || prepared.Current == nil || prepared.CreateMetadata != nil || metadata == nil || metadata.Version != p.original.Version || !metadata.LastModified.Equal(p.original.At) || change.Delete || change.Resource == nil || current.Version != p.intent.IfMatch {
		return scim.WriteResult{}, identity.ForbiddenError{}
	}
	original, err := json.Marshal(current)
	if err != nil {
		return scim.WriteResult{}, identity.UnavailableError{}
	}
	defer clear(original)
	preparedCurrent, err := json.Marshal(prepared.Current)
	if err != nil || !bytes.Equal(original, preparedCurrent) {
		return scim.WriteResult{}, identity.ForbiddenError{}
	}
	defer clear(preparedCurrent)
	resource := change.Resource
	if resource.ID != current.ID || !resource.CreatedAt.Equal(current.CreatedAt) {
		return scim.WriteResult{}, identity.ForbiddenError{}
	}
	wire, err := json.Marshal(resource)
	if err != nil || len(wire) > 131072 {
		return scim.WriteResult{}, identity.InvalidInputError{Field: "scim_resource"}
	}
	defer clear(wire)
	if resource.Version == current.Version {
		// Equal metadata is accepted only for the root's exact unchanged PATCH.
		// A reused ETag may never disguise a changed projection/core mutation.
		if !nativePatch(p.intent.Operation) || !bytes.Equal(original, wire) {
			return scim.WriteResult{}, identity.ForbiddenError{}
		}
	} else if resource.Version != p.original.Version || !resource.LastModified.Equal(p.original.At) {
		return scim.WriteResult{}, identity.ForbiddenError{}
	}
	if json.Unmarshal(wire, &p.resource) != nil {
		return scim.WriteResult{}, identity.UnavailableError{}
	}
	if !p.group() {
		if _, err := mappedString(p.resource.Attributes, "userName"); err != nil {
			return scim.WriteResult{}, err
		}
	}
	if err := p.initialize(ctx, prepared.Intent.CanonicalRequest); err != nil {
		return scim.WriteResult{Outcome: scim.WriteOutcomeNotCommitted}, err
	}
	return b.executeResourceWrite(ctx, p)
}

func (b *protocolBridge) executeResourceWrite(ctx context.Context, p *nativePhase) (scim.WriteResult, error) {
	result, err := p.execute(ctx)
	if result.Outcome == identity.CommitOutcomeCommitted && err == nil {
		stored, readErr := b.readOriginal(ctx, p)
		if readErr != nil {
			return scim.WriteResult{Outcome: scim.WriteOutcomeUnknown}, readErr
		}
		return scim.WriteResult{Outcome: scim.WriteOutcomeCommitted, Resource: &stored}, nil
	}
	if failure, ok := featureFailure(result, err); ok {
		if err := b.recheckFailureDisclosure(ctx, p); err != nil {
			return scim.WriteResult{Outcome: scim.WriteOutcomeUnknown}, err
		}
		return scim.WriteResult{Outcome: scim.WriteOutcomeNotCommitted}, failure
	}
	var conflict identity.ConflictError
	if (result.Outcome == identity.CommitOutcomeNotCommitted || result.Outcome == identity.CommitOutcomeConflict) && errors.As(err, &conflict) {
		return scim.WriteResult{Outcome: scim.WriteOutcomeNotCommitted}, scim.ErrConflict
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

func (b *protocolBridge) commitDelete(ctx context.Context, p *nativePhase, prepared scim.PreparedWrite, change scim.Change) (scim.WriteResult, error) {
	if !change.Delete || change.Resource != nil || prepared.CreateMetadata != nil || prepared.UpdateMetadata != nil || prepared.Current == nil || p.original.Current == nil || prepared.Current.ID != p.original.ID {
		return scim.WriteResult{}, identity.ForbiddenError{}
	}
	original, err := json.Marshal(p.original.Current)
	if err != nil {
		return scim.WriteResult{}, identity.UnavailableError{}
	}
	defer clear(original)
	current, err := json.Marshal(prepared.Current)
	if err != nil || !bytes.Equal(original, current) {
		return scim.WriteResult{}, identity.ForbiddenError{}
	}
	defer clear(current)
	if err := p.initialize(ctx, prepared.Intent.CanonicalRequest); err != nil {
		return scim.WriteResult{Outcome: scim.WriteOutcomeNotCommitted}, err
	}
	result, err := p.execute(ctx)
	if result.Outcome == identity.CommitOutcomeCommitted && err == nil {
		// A historical ACK requires this invocation's genuine current authority,
		// including actual kernel eligibility, but never the deleted SCIM
		// projection, which may have expired already.
		if !p.group() {
			user, err := p.service.directory.Get(ctx, identity.GetUserQuery{TenantID: p.service.config().Scope.TenantID, UserID: identity.UserID(p.original.ID)})
			if err != nil || user.Status != identity.StatusActive {
				return scim.WriteResult{Outcome: scim.WriteOutcomeUnknown}, identity.ForbiddenError{}
			}
		}
		if err := b.service.recheckRead(ctx, &p.admission); err != nil {
			return scim.WriteResult{Outcome: scim.WriteOutcomeUnknown}, err
		}
		return scim.WriteResult{Outcome: scim.WriteOutcomeCommitted}, nil
	}
	if failure, ok := featureFailure(result, err); ok {
		if err := b.recheckFailureDisclosure(ctx, p); err != nil {
			return scim.WriteResult{Outcome: scim.WriteOutcomeUnknown}, err
		}
		return scim.WriteResult{Outcome: scim.WriteOutcomeNotCommitted}, failure
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

// A typed detail is exported only with the kernel's known terminal outcome.
// Its private journal code never grants permission or upgrades uncertainty.
func featureFailure(result identity.CommandResult, err error) (error, bool) {
	if result.Outcome != identity.CommitOutcomeNotCommitted && result.Outcome != identity.CommitOutcomeConflict {
		return nil, false
	}
	var failure kernel.TypedFeatureFailureError
	if !errors.As(err, &failure) {
		return nil, false
	}
	switch failure.Code {
	case kernel.FeatureFailureUniqueness:
		return scim.ErrUniqueness, true
	case kernel.FeatureFailurePrecondition:
		return scim.ErrPreconditionFailed, true
	case kernel.FeatureFailureConflict:
		return scim.ErrConflict, true
	case kernel.FeatureFailureInvalidGroupMember:
		operation := scim.Operation(result.Binding.OperationID)
		if !groupOperation(operation) || !nativeCreate(operation) && !nativeMutation(operation) || result.Feature == nil || result.Feature.Operation != mutationOperation(operation) {
			return identity.UnavailableError{}, true
		}
		return scim.ErrInvalidGroupMember, true
	default:
		return identity.UnavailableError{}, true
	}
}

func (b *protocolBridge) recheckFailureDisclosure(ctx context.Context, p *nativePhase) error {
	if nativeMutation(p.intent.Operation) && !p.group() {
		user, err := p.service.directory.Get(ctx, identity.GetUserQuery{TenantID: p.service.config().Scope.TenantID, UserID: identity.UserID(p.original.ID)})
		if err != nil || user.Status != identity.StatusActive {
			return identity.ForbiddenError{}
		}
	}
	return b.service.recheckRead(ctx, &p.admission)
}

func (b *protocolBridge) readOriginal(ctx context.Context, p *nativePhase) (scim.Resource, error) {
	if !liveConnection(ctx, p.admission.connection) {
		return scim.Resource{}, identity.UnavailableError{}
	}
	// Called only after the real coordinator returns this exact command's
	// committed receipt. Its immutable prepared Current/metadata and canonical
	// request reconstruct the original candidate, even after later writes or
	// tombstone expiry. Current scim.users is not an original-result journal.
	resource, err := copyCurrent(&p.resource)
	if err != nil || resource == nil || resource.ID != p.original.ID {
		return scim.Resource{}, identity.UnavailableError{}
	}
	if !p.group() {
		user, err := p.service.directory.Get(ctx, identity.GetUserQuery{TenantID: p.service.config().Scope.TenantID, UserID: identity.UserID(resource.ID)})
		if err != nil || user.Status != identity.StatusActive {
			return scim.Resource{}, identity.ForbiddenError{}
		}
	}
	// A retained committed receipt skips Apply's original-authority fences.
	// Disclosure therefore requires this invocation's genuine current owners,
	// not the historical encrypted admission or merely a live local deadline.
	if err := b.service.recheckRead(ctx, &p.admission); err != nil {
		return scim.Resource{}, err
	}
	return *resource, nil
}

func (*protocolBridge) Abort(ctx context.Context, _ scim.PreparedWrite) error {
	// Prepare holds no locks, reservation or transaction. ResolvePreparedRequestKey
	// owns only immutable correlation; Commit's coordinator closes every Work.
	if ctx == nil {
		return identity.InvalidInputError{Field: "scim_context"}
	}
	return ctx.Err()
}
