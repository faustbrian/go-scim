package scimpostgres

import (
	"bytes"
	"context"
	"errors"
	"slices"

	identity "github.com/faustbrian/go-identity"
	scim "github.com/faustbrian/go-scim"
)

type groupCyclePreparationKey struct{}

// This synchronous request-local capture stops the ordinary Group create at
// Commit, after mapping and initialization but before reservation or Work. It
// carries no permission to apply the captured phase outside the SCC executor.
type groupCyclePreparation struct {
	service    *Service
	invocation *invocation
	child      *bulkChildExecution
	scope      scim.Scope
	phase      *nativePhase
}

func (s *GroupBulkService) prepareGroupCycleChild(ctx context.Context, request BulkAdmissionRequest, parent *nativePhase, child *bulkChildExecution, resolved scim.BulkOperation) (*nativePhase, error) {
	if s == nil || s.native == nil || s.groups == nil || ctx == nil || ctx.Err() != nil ||
		parent == nil || parent.service != s.native || parent.bulk == nil || child == nil {
		return nil, identity.ForbiddenError{}
	}
	ordinal := child.row.Ordinal
	if ordinal < 0 || ordinal >= len(parent.bulk.children) {
		return nil, identity.ForbiddenError{}
	}
	declared := parent.bulk.children[ordinal]
	if declared.Error != nil || !bulkCreatesGroup(declared) || resolved.Error != nil ||
		resolved.Index != ordinal || resolved.Method != "POST" || resolved.Target != declared.Target ||
		resolved.Path != declared.Path || resolved.BulkID != declared.BulkID || resolved.Version != "" ||
		!slices.Equal(resolved.Dependencies, declared.Dependencies) || child.ifMatch != "" {
		return nil, identity.ForbiddenError{}
	}
	actual := child.row
	if actual.ComponentOrder < 0 || actual.ComponentOrder >= len(parent.bulk.components) ||
		ordinal >= len(parent.bulk.allocation) || len(actual.Dependencies) != len(declared.Dependencies) {
		return nil, identity.ForbiddenError{}
	}
	component := parent.bulk.components[actual.ComponentOrder]
	allocation := parent.bulk.allocation[ordinal]
	_, member := slices.BinarySearch(component.Operations, ordinal)
	if !actual.Cyclic || !component.Cyclic || !member || actual.ComponentID != component.Operations[0] ||
		actual.Command != string(allocation.Command) || actual.Resource != allocation.Resource ||
		!bytes.Equal(actual.BulkID, []byte(declared.BulkID)) || !bytes.Equal(actual.Fingerprint, bulkChildFingerprint(parent.bulk.intent, ordinal)) ||
		child.parent != parent.original.Command || child.original.Command != allocation.Command || child.original.ID != allocation.Resource ||
		child.original.Operation != scim.GroupCreate || child.original.Version != bulkChildVersion(actual.Command) ||
		!child.original.At.Equal(parent.original.At) || child.original.Admission != parent.original.Admission ||
		parent.admission.connection.Scope != s.native.config().Scope {
		return nil, identity.ForbiddenError{}
	}
	for i, predecessor := range declared.Dependencies {
		if predecessor < 0 || predecessor >= len(parent.bulk.allocation) ||
			actual.Dependencies[i] != string(parent.bulk.allocation[predecessor].Command) {
			return nil, identity.ForbiddenError{}
		}
	}

	i := parent.admission
	i.phase, i.bulkChild = nil, child
	capture := &groupCyclePreparation{service: s.native, invocation: &i, child: child, scope: i.connection.Scope}
	ctx = context.WithValue(ctx, invocationKey{}, &i)
	ctx = context.WithValue(ctx, groupCyclePreparationKey{}, capture)
	response, err := s.groups.Execute(ctx, scim.Request{Operation: scim.GroupCreate, Credential: request.Credential, Body: resolved.Data, ContentType: "application/scim+json"})
	if capture.phase == nil {
		if err != nil {
			return nil, err
		}
		return nil, identity.ForbiddenError{}
	}
	// The public root maps InProgress to 503 and does not abort. A 503 alone
	// never proves preparation: only this exact private Commit capture does.
	var protocol *scim.Error
	if ctx.Err() != nil || !errors.As(err, &protocol) || protocol == nil || protocol.StatusCode() != 503 ||
		response.Status != 0 || response.ContentType != "" || len(response.Body) != 0 || response.ETag != "" || response.Location != "" ||
		capture.phase != i.phase || !capture.matches(s.native, &i, capture.phase) {
		return nil, identity.ForbiddenError{}
	}
	return capture.phase, nil
}

func (c *groupCyclePreparation) matches(service *Service, i *invocation, p *nativePhase) bool {
	return c != nil && c.service == service && c.invocation == i && c.child != nil &&
		c.child.row.Cyclic && c.child.original.Operation == scim.GroupCreate && c.child.ifMatch == "" &&
		i != nil && i.bulkChild == c.child && i.phase == p && i.connection.Scope == c.scope &&
		p != nil && p.service == service && p.bulk == nil && !p.bootstrap && p.bulkChild == c.child &&
		p.admission.bulkChild == c.child && p.admission.connection == i.connection &&
		p.intent.Operation == scim.GroupCreate && p.intent.Scope == c.scope && p.intent.Connection == i.connection &&
		p.intent.CommandID == c.child.original.Command && p.intent.ResourceID == "" && p.intent.IfMatch == "" && p.intent.IdempotencyKey == "" &&
		p.original == c.child.original && p.command != (identity.Command{})
}
