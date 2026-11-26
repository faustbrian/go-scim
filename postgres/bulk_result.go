package scimpostgres

import (
	"bytes"
	"context"
	"errors"

	identity "github.com/faustbrian/go-identity"
	scim "github.com/faustbrian/go-scim"
)

// ReadResult returns the complete retained SCIM Bulk response for the exact
// original request, after current authorization. It never admits a request,
// attaches a retry key, or executes a child. It returns scim.ErrBulkIncomplete
// and no bytes when no terminal graph can be observed. Retries return the
// same response without reconstructing results from current resource state.
func (s *GroupBulkService) ReadResult(ctx context.Context, request BulkAdmissionRequest) (wire []byte, err error) {
	if s == nil || s.native == nil || ctx == nil {
		return nil, scim.NewError(503, "")
	}
	ctx, cancel := context.WithTimeout(ctx, s.native.config().MaximumDuration)
	defer cancel()
	defer func() {
		if recover() != nil || ctx.Err() != nil {
			wire, err = nil, scim.NewError(503, "")
		} else if err != nil {
			wire = nil
			if !errors.Is(err, scim.ErrBulkIncomplete) {
				err = bulkProtocolError(err)
			}
		}
	}()
	prepared, err := s.prepareBulkGraph(ctx, request, nil)
	if err != nil {
		return nil, err
	}
	canonical := prepared.plan.CanonicalRequest()
	defer clear(canonical)
	p := prepared.phase
	if err := p.loadBulkOriginal(ctx, canonical, request.IdempotencyKey, bulkReadCustody); err != nil {
		return nil, err
	}
	results, err := p.readBulkTerminalCheckpoints(ctx)
	if err != nil {
		return nil, err
	}
	// An authorized Bulk connection is not authority to disclose each result.
	// Check the original operation against the same target as ExecuteChild.
	// Multiple results with the same operation and target have the same scope.
	type disclosure struct {
		op     scim.Operation
		target string
	}
	targets := p.bulk.createTargets()
	authorized := make(map[disclosure]struct{})
	for ordinal, result := range results {
		if result.Status == scim.BulkChildSkipped {
			continue
		}
		op, target := p.bulk.selectChild(ordinal, targets)
		if op == "" {
			return nil, identity.UnavailableError{}
		}
		key := disclosure{op: op, target: target}
		if _, ok := authorized[key]; !ok {
			if err := s.native.decide(ctx, string(op), target, bulkChildAuthorizationType(op)); err != nil {
				return nil, err
			}
			authorized[key] = struct{}{}
		}
		if err := s.native.checkBulkChildDisclosure(ctx, op, result); err != nil {
			return nil, err
		}
		if result.Status == scim.BulkChildFailed && p.bulk.children[ordinal].Target.BulkID != "" {
			results[ordinal].ResourceID = target
		}
	}
	var response bytes.Buffer
	if err := prepared.response.Write(&response, results); err != nil {
		return nil, err
	}
	if err := s.native.recheckRead(ctx, &p.admission); err != nil {
		return nil, err
	}
	return response.Bytes(), nil
}

// A single read observes both the committed parent and its complete ordered
// checkpoint set, so a concurrent cutoff cannot produce a mixed response.
// One extra row distinguishes an invalid graph from the expected bounded set.
const bulkTerminalCheckpoints = `WITH parent AS (
 SELECT parent_id,failed_count,cutoff_active FROM scim.bulk_requests WHERE ` + bulkParentMatch + `
)
SELECT child.ordinal,child.command_id,child.request_fingerprint,child.resource_id,child.component_order,child.cyclic,
 child.status,child.skip_reason,child.result_code,child.result_resource_id,child.result_version,parent.failed_count,parent.cutoff_active
FROM parent JOIN scim.bulk_children child USING(parent_id) ORDER BY child.ordinal LIMIT ($9::integer+1)`

func (p *nativePhase) readBulkTerminalCheckpoints(ctx context.Context) ([]scim.BulkChildResult, error) {
	expected, err := p.bulk.childRows()
	if err != nil {
		return nil, err
	}
	rows, err := p.service.pool.Raw().Query(ctx, bulkTerminalCheckpoints, p.bulkParentArgs()...)
	if err != nil {
		return nil, identity.UnavailableError{}
	}
	defer rows.Close()
	results := make([]scim.BulkChildResult, 0, len(expected))
	var failed, retainedFailures int
	var cutoff, incomplete bool
	targets := p.bulk.createTargets()
	for rows.Next() {
		index := len(results)
		if index == len(expected) {
			return nil, identity.UnavailableError{}
		}
		var r bulkTerminalCheckpoint
		if err := rows.Scan(&r.ordinal, &r.command, &r.fingerprint, &r.allocation, &r.componentOrder, &r.cyclic,
			&r.status, &r.skipReason, &r.code, &r.resource, &r.version, &retainedFailures, &cutoff); err != nil {
			return nil, identity.UnavailableError{}
		}
		original := expected[index]
		if r.ordinal != index || r.command != original.Command || r.allocation != original.Resource || r.componentOrder != original.ComponentOrder ||
			r.cyclic != original.Cyclic || !bytes.Equal(r.fingerprint, original.Fingerprint) {
			return nil, identity.UnavailableError{}
		}
		op, target := p.bulk.selectChild(index, targets)
		if original.Cyclic && op != scim.GroupCreate {
			op = ""
		}
		phase := newBulkChildExecution(p.original, original, op, target, scim.Version(p.bulk.children[index].Version))
		result, err := r.result(phase, cutoff)
		if err != nil && !errors.Is(err, scim.ErrBulkIncomplete) {
			return nil, err
		}
		incomplete = incomplete || err != nil
		if result.Status == scim.BulkChildFailed {
			failed++
		}
		results = append(results, result)
	}
	if rows.Err() != nil {
		return nil, identity.UnavailableError{}
	}
	if len(results) == 0 { // Missing graph or the preparation was never admitted.
		return nil, scim.ErrBulkIncomplete
	}
	if len(results) != len(expected) || failed != retainedFailures || cutoff != (p.bulk.cutoff > 0 && failed >= p.bulk.cutoff) {
		return nil, identity.UnavailableError{}
	}
	if incomplete {
		return nil, scim.ErrBulkIncomplete
	}
	return results, nil
}

type bulkTerminalCheckpoint struct {
	ordinal, componentOrder int
	command, allocation     string
	fingerprint             []byte
	cyclic                  bool
	status, skipReason      string
	code                    *int16
	resource, version       *string
}

func (r bulkTerminalCheckpoint) result(phase *bulkChildExecution, cutoff bool) (scim.BulkChildResult, error) {
	empty := r.code == nil && r.resource == nil && r.version == nil
	if r.status == "skipped" {
		if empty && cutoff && r.skipReason == "fail-on-errors" {
			return scim.BulkChildResult{Status: scim.BulkChildSkipped, SkipReason: scim.BulkSkipFailOnErrors}, nil
		}
		return scim.BulkChildResult{}, identity.UnavailableError{}
	}
	if r.skipReason != "none" {
		return scim.BulkChildResult{}, identity.UnavailableError{}
	}
	switch r.status {
	case "admitted", "running", "dependency-blocked":
		if empty {
			return scim.BulkChildResult{}, scim.ErrBulkIncomplete
		}
	case "failed":
		if phase.original.Operation != "" && r.code != nil && r.resource == nil && r.version == nil {
			if result, valid := phase.failureResult(int(*r.code)); valid {
				return result, nil
			}
		}
	case "succeeded":
		if r.code != nil && r.resource != nil && *r.resource == phase.original.ID {
			if result, ok := phase.successfulResult(int64(*r.code), r.version); ok {
				return result, nil
			}
		}
	}
	return scim.BulkChildResult{}, identity.UnavailableError{}
}
