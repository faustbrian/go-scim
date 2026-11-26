package scimpostgres

import (
	"context"
	"errors"

	scim "github.com/faustbrian/go-scim"
)

// ExecuteBulk admits the graph, then advances retained dependency components in
// order within the configured native request budget. Acyclic children commit
// independently; one call for a cyclic component settles all of its members
// atomically. It returns only a currently authorized, complete BulkResponse.
// On interruption or an unknown outcome it returns no response bytes; retry
// the identical request and optional key to recover the original checkpoints.
func (s *BulkService) ExecuteBulk(ctx context.Context, request BulkAdmissionRequest) (wire []byte, err error) {
	graph := s.executor()
	if graph == nil || graph.native == nil || graph.groups == nil || ctx == nil {
		return nil, scim.NewError(503, "")
	}
	ctx, cancel := context.WithTimeout(ctx, graph.native.config().MaximumDuration)
	defer cancel()
	defer func() {
		if recover() != nil || ctx.Err() != nil {
			wire, err = nil, scim.NewError(503, "")
		} else if err != nil {
			wire, err = nil, bulkProtocolError(err)
		}
	}()

	prepared, err := graph.prepareBulkGraph(ctx, request, nil)
	if err != nil {
		return nil, err
	}
	if err := graph.commitBulkGraph(ctx, prepared, request.IdempotencyKey); err != nil {
		return nil, err
	}
	parent := prepared.phase
	// Terminal replay does not run the graph or read today's resource versions.
	checkpoints, err := parent.readBulkCheckpoints(ctx)
	if err == nil {
		return graph.writeBulkResult(ctx, prepared, checkpoints)
	}
	if !errors.Is(err, scim.ErrBulkIncomplete) {
		return nil, err
	}

	rows, err := parent.bulk.childRows()
	if err != nil {
		return nil, err
	}
	if len(checkpoints) != len(rows) {
		return nil, scim.NewError(503, "")
	}
	for _, component := range parent.bulk.components {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		ordinal := component.Operations[0]
		settled := settledBulkChild(checkpoints[ordinal])
		for _, member := range component.Operations[1:] {
			if settledBulkChild(checkpoints[member]) != settled {
				return nil, scim.NewError(503, "") // A cycle cannot be partially settled.
			}
		}
		if settled {
			continue
		}
		// A singleton has exactly one member. For a cycle the first ordinal
		// selects the existing atomic component operation, not a new child loop.
		result, err := graph.executeAdmittedBulkChild(ctx, request, parent, prepared.plan, rows, ordinal)
		if err != nil {
			return nil, err
		}
		if !settledBulkChild(result) {
			return nil, scim.NewError(503, "")
		}
	}
	return graph.readAdmittedBulkResult(ctx, prepared)
}

func settledBulkChild(result scim.BulkChildResult) bool {
	switch result.Status {
	case scim.BulkChildSucceeded, scim.BulkChildFailed, scim.BulkChildSkipped:
		return true
	default:
		return false
	}
}
