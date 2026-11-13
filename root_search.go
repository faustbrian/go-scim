package scim

import (
	"context"
	"sort"
	"strings"
)

// RootResourceType is the closed set of resource owners in a combined root
// search. Zero and other values are invalid; schemas never infer this owner.
type RootResourceType string

const (
	RootUser  RootResourceType = "User"
	RootGroup RootResourceType = "Group"
)

// RootResource binds an existing projection to its exact typed owner. Its core
// schema must match Type and all extensions must belong to that owner's frozen
// configuration. The same server-generated ID cannot occur twice in a snapshot.
type RootResource struct {
	Type     RootResourceType
	Resource Resource
}

// RootSnapshot is one complete transaction-consistent mixed User/Group view.
// Scope must exactly match the authenticated connection, including on empty
// results. Complete=false denies the whole query, even count=0. Resources and
// nested values are detached, caller-owned results, not mutable store aliases.
type RootSnapshot struct {
	Scope     Scope
	Resources []RootResource
	Complete  bool
}

// RootSnapshotter owns one bounded read of BOTH resource partitions in the same
// transaction or immutable view. Sequential Store.Snapshot/SnapshotGroups calls
// do not satisfy this contract. It must enforce SnapshotBudget before decoding,
// copying or materializing each value; Bytes counts aggregate Resource JSON as
// with SnapshotBudget, while Resources counts both types together.
//
// The verified Connection is original authority custody, not a new lease or
// caller authorization. The owner must fence current connection/token/policy
// authority and its unchanged original deadline at the protected read. It must
// honor context cancellation, return no partial success, retain no caller data,
// and be concurrency-safe. No transaction/lock may escape the call. This read
// contract grants no provisioning, mutation, replay or lifecycle authority.
type RootSnapshotter interface {
	SnapshotRoot(context.Context, Connection, SnapshotBudget) (RootSnapshot, error)
}

type rootSearchProfile struct {
	reader        RootSnapshotter
	users, groups *protocolService
}

func (p attributePath) appliesTo(doc map[string]any) bool {
	if p.rootType == "" {
		return true
	}
	meta, _ := doc["meta"].(map[string]any)
	return meta["resourceType"] == string(p.rootType)
}

func (r *rootSearchProfile) resolvePath(raw string, local []Attribute) (attributePath, error) {
	limits := r.users.config.Limits
	if local != nil {
		return resolvePath(raw, nil, limits, local)
	}
	for _, owner := range []*protocolService{r.users, r.groups} {
		path, err := resolvePath(raw, owner.config.Extensions, limits, nil, owner.profile.schema)
		if err != nil {
			continue
		}
		// RFC7644 3.4.2 spans resource types. An explicitly core-qualified
		// path must not read the same-named field of the OTHER resource type.
		// The existing resolver selects the longest schema ID. A longer
		// extension may itself begin with a core URN and belongs to any
		// resource declaring that extension, not only the core resource type.
		if path.extension == "" && strings.HasPrefix(raw, owner.profile.schema.ID+":") {
			path.rootType = RootResourceType(owner.profile.schema.Name)
		}
		return path, nil
	}
	return attributePath{}, failure(400, "invalidPath")
}

func (r *rootSearchProfile) search(ctx context.Context, connection Connection, query Query) (Response, error) {
	service := r.users
	plan, err := service.planResolvedQuery(query, r.resolvePath)
	if err != nil {
		return Response{}, err
	}
	readCtx, cancel, err := service.authorityContext(ctx, connection)
	if err != nil {
		return Response{}, err
	}
	budget := SnapshotBudget{Resources: service.config.Limits.SnapshotResources, Bytes: service.config.Limits.SnapshotBytes}
	snapshot, err := r.reader.SnapshotRoot(readCtx, connection, budget)
	cancel()
	if err != nil {
		return Response{}, storeError(err)
	}
	if snapshot.Scope != connection.Scope {
		return Response{}, failure(503, "")
	}
	if !snapshot.Complete || len(snapshot.Resources) > budget.Resources {
		return Response{}, failure(400, "tooMany")
	}
	// Check the aggregate before allocating documents, even count=0. The
	// trusted read owner has the same obligation before materializing results.
	remaining := budget.Bytes
	for _, resource := range snapshot.Resources {
		size, err := snapshotResourceSize(resource.Resource, remaining)
		if err != nil {
			return Response{}, failure(400, "tooMany")
		}
		remaining -= size
	}
	type entry struct {
		owner *protocolService
		doc   map[string]any
		id    string
	}
	entries := make([]entry, 0, len(snapshot.Resources))
	seen := make(map[string]bool, len(snapshot.Resources))
	for _, resource := range snapshot.Resources {
		if !service.authorityCurrent(ctx, connection) {
			return Response{}, failure(503, "")
		}
		var owner *protocolService
		switch resource.Type {
		case RootUser:
			owner = r.users
		case RootGroup:
			owner = r.groups
		default:
			return Response{}, failure(503, "")
		}
		doc, err := owner.resourceDocument(resource.Resource)
		if err != nil {
			return Response{}, err
		}
		if seen[resource.Resource.ID] {
			return Response{}, failure(503, "")
		}
		seen[resource.Resource.ID] = true
		if plan.filter.matches(doc) {
			entries = append(entries, entry{owner: owner, doc: doc, id: resource.Resource.ID})
		}
	}
	validSort := true
	sort.Slice(entries, func(i, j int) bool {
		if plan.sort != nil {
			left, right := sortValue(entries[i].doc, *plan.sort), sortValue(entries[j].doc, *plan.sort)
			comparison, valid := compareSortValue(left, right, plan.sort.attribute())
			validSort = validSort && valid
			if comparison != 0 {
				if plan.query.SortOrder == "descending" {
					return comparison > 0
				}
				return comparison < 0
			}
		}
		return entries[i].id < entries[j].id
	})
	if !validSort {
		return Response{}, failure(503, "")
	}
	total := len(entries)
	resources := []any{}
	start := plan.query.StartIndex - 1
	if start < total {
		// Subtract before adding: an arbitrarily large start index must not
		// overflow, while count remains capped by the effective page limit.
		end := start + min(*plan.query.Count, total-start)
		for _, entry := range entries[start:end] {
			projectedPlan := plan
			projectedPlan.include = rootProjectionPaths(plan.include, entry.owner.profile.schema.Name)
			projectedPlan.exclude = rootProjectionPaths(plan.exclude, entry.owner.profile.schema.Name)
			resources = append(resources, entry.owner.project(entry.doc, projectedPlan))
			if _, err := encodedSize(listDocument(resources, total, plan.query.StartIndex), service.config.Limits.ResponseBytes); err != nil {
				return Response{}, err
			}
		}
	}
	// Recheck the existing current policy before disclosure after the external
	// read, without reauthenticating or renewing the original Connection window.
	policyCtx, policyCancel, err := service.authorityContext(ctx, connection)
	if err != nil {
		return Response{}, err
	}
	err = service.config.Authorizer.Authorize(policyCtx, connection, Search, "")
	policyCancel()
	if err != nil {
		return Response{}, failure(403, "")
	}
	body, err := service.encode(listDocument(resources, total, plan.query.StartIndex))
	if err != nil {
		return Response{}, err
	}
	return Response{Status: 200, ContentType: "application/scim+json", Body: body}, nil
}

func rootProjectionPaths(paths []attributePath, resourceType string) []attributePath {
	out := make([]attributePath, 0, len(paths))
	for _, path := range paths {
		if path.rootType == "" || path.rootType == RootResourceType(resourceType) {
			out = append(out, path)
		}
	}
	return out
}
