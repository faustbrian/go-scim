package scim

import (
	"encoding/json"
	"net/url"
	"slices"
	"strings"
)

// ResolveOperation returns one detached child with its request-local target and
// schema-declared references replaced by retained create resource IDs. Map keys
// are ORIGINAL operation indexes, never SCC positions or execution order. A
// sparse map need contain only the referenced creates; supplied entries must
// name structurally valid creates in this plan and unambiguous resource IDs.
// Group member value slots receive IDs; reference URI slots receive service-
// relative Users/<id> or Groups/<id> paths, preserving a configured service root.
// A complete symbolic Group member with missing, null or empty type receives its
// create's resource type so Group normalization cannot default a Group to a User.
//
// The trusted native caller MUST supply the exact allocations retained for this
// plan in its authenticated connection. This pure function cannot authenticate
// an ID's provenance, discover resources, prove existence, or confer execution
// authority. Resource/PATCH validation, authority, durable dependency outcomes,
// and the SCC transaction boundary remain with that caller. It does not change
// the plan or retain the map, and every failure returns a zero operation.
func (p BulkPlan) ResolveOperation(index int, allocated map[int]string) (BulkOperation, error) {
	if index < 0 || index >= len(p.operations) || !p.limits.valid() || p.operations[index].Error != nil {
		return BulkOperation{}, failure(400, "invalidValue")
	}
	seen := map[BulkTarget]bool{}
	for originalIndex, id := range allocated {
		if originalIndex < 0 || originalIndex >= len(p.operations) || !safeID(id) || id == "." || id == ".." || strings.HasPrefix(id, "bulkId:") {
			return BulkOperation{}, failure(400, "invalidValue")
		}
		create := p.operations[originalIndex]
		if create.Method != "POST" || create.Error != nil || create.Target.ResourceType == "" {
			return BulkOperation{}, failure(400, "invalidValue")
		}
		target := BulkTarget{ResourceType: create.Target.ResourceType, ResourceID: id}
		if seen[target] {
			return BulkOperation{}, failure(400, "invalidValue")
		}
		seen[target] = true
	}
	creates := map[string]int{}
	for originalIndex, operation := range p.operations {
		if operation.Method == "POST" && operation.Error == nil {
			creates[operation.BulkID] = originalIndex
		}
	}
	resolve := func(reference bulkReference) (BulkTarget, error) {
		originalIndex, found := creates[reference.id]
		if !found {
			return BulkTarget{}, failure(400, "invalidValue")
		}
		id, found := allocated[originalIndex]
		create := p.operations[originalIndex]
		if !found || reference.resourceType != "" && reference.resourceType != create.Target.ResourceType {
			return BulkTarget{}, failure(400, "invalidValue")
		}
		return BulkTarget{ResourceType: create.Target.ResourceType, ResourceID: id}, nil
	}

	operation := p.operations[index]
	operation.Data = slices.Clone(operation.Data)
	operation.Dependencies = slices.Clone(operation.Dependencies)
	if operation.Target.BulkID != "" {
		target, err := resolve(bulkReference{id: operation.Target.BulkID, resourceType: operation.Target.ResourceType})
		if err != nil {
			return BulkOperation{}, err
		}
		operation.Target = target
		operation.Path = "/" + target.ResourceType + "s/" + url.PathEscape(target.ResourceID)
		if _, valid := parseBulkTarget(operation.Method, operation.Path, p.limits.PathBytes); !valid {
			return BulkOperation{}, failure(400, "invalidValue")
		}
	}
	if len(operation.Data) == 0 {
		return operation, nil
	}
	doc, err := decodeObject(operation.Data, p.limits)
	if err != nil {
		return BulkOperation{}, err
	}
	references, err := bulkBodyReferences(doc, &operation, p.extensions, p.limits)
	if err != nil {
		return BulkOperation{}, err
	}
	if operation.Error != nil {
		return BulkOperation{}, operation.Error
	}
	for _, reference := range references {
		target, err := resolve(reference)
		if err != nil {
			return BulkOperation{}, err
		}
		if reference.form == bulkReferenceID {
			reference.set(target.ResourceID)
		} else {
			reference.set(target.ResourceType + "s/" + url.PathEscape(target.ResourceID))
		}
		if reference.setKind != nil {
			reference.setKind(target.ResourceType)
		}
	}
	operation.Data, err = json.Marshal(doc)
	if err != nil {
		return BulkOperation{}, failure(400, "invalidValue")
	}
	if _, err := decodeObject(operation.Data, p.limits); err != nil {
		return BulkOperation{}, err
	}
	return operation, nil
}
