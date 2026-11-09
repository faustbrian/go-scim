package scim

import (
	"context"
	"errors"
	"net/url"
	"strings"
	"time"
)

// DefaultGroupMembers is the selected scim.group_members ceiling from the
// identity platform reference configuration: 10,000. Independent resource
// attribute, body and response budgets can impose a smaller effective resource.
const DefaultGroupMembers = 10000

// GroupMapper is a bounded, concurrent-safe, side-effect-free Group
// representation policy. It must not provision teams, change memberships,
// infer identity from externalId, or turn a User into a Group. Immutable member
// values admitted by the protocol cannot be rewritten by mapping.
type GroupMapper interface {
	MapGroup(context.Context, Scope, WritableResource) (WritableResource, error)
}

// GroupStore is the trusted atomic Group projection/admission boundary.
// It has Store's detached ownership, cancellation, bounded snapshot, original
// authority deadline, CAS, audit, replay, retention and unknown-outcome rules,
// but is a distinct resource-type partition: none of its methods reads or
// mutates a User projection. Group names and externalId are not unique.
//
// PrepareGroup accepts only GroupCreate/Replace/Patch/Delete intents and recovers
// matching results before current-resource/precondition checks. CommitGroup
// atomically fences current connection/token/policy authority, the original
// authority deadline, IfMatch, new-ID absence, and each member's exact ID and
// declared User/Group type in the SAME full connection scope. A missing,
// cross-scope or wrong-type member must return ErrInvalidGroupMember without
// committing. Protocol URI validation does not establish resource existence.
//
// Use the existing durable command authority; these methods neither authorize
// a new journal nor implement organization reconciliation/deprovisioning.
// GroupDelete affects only the owned Group projection, never its member Users,
// nested Groups, identities, teams or organization memberships. Commit, semantic
// result and redacted audit attribution are atomic. Headerless GroupDelete
// recovery uses connection+type+target+precondition canonical lookup and remains
// replayable independently of tombstone retention. Unknown/in-progress outcomes
// never expire into permission to retry. AbortGroup records only a provably
// uncommitted terminal denial, including ErrInvalidGroupMember; arbitrary commit
// errors are unknown and must not be aborted or retried as new effects.
type GroupStore interface {
	GetGroup(context.Context, Scope, string) (Resource, error)
	SnapshotGroups(context.Context, Scope, SnapshotBudget) (Snapshot, error)
	PrepareGroup(context.Context, WriteIntent) (PreparedWrite, error)
	CommitGroup(context.Context, PreparedWrite, Change) (WriteResult, error)
	AbortGroup(context.Context, PreparedWrite) error
}

// ErrInvalidGroupMember guarantees no commit occurred because a member was
// missing or not a resource of its exact type in the connection partition.
// Its redacted wire error does not reveal which member or partition failed.
var ErrInvalidGroupMember = errors.New("scim: invalid group member")

// GroupsConfig selects only the storage-neutral Groups protocol profile.
// Common fields have Config's ownership, timeout, URL and limit semantics.
// GroupMembers is an explicit 0..DefaultGroupMembers ceiling; zero intentionally
// permits only empty Groups, not a default. Use DefaultGroupMembers for the
// reference ceiling. Extensions cannot override either registered core schema.
// Dependencies must be concurrency-safe and honor bounded contexts.
type GroupsConfig struct {
	Store            GroupStore
	Authenticator    Authenticator
	Authorizer       Authorizer
	Mapper           GroupMapper
	Limits           Limits
	GroupMembers     int
	BaseURL          string
	DocumentationURI string
	Extensions       []Schema
	Now              func() time.Time
	RequestTimeout   time.Duration
}

// GroupsService executes only Groups CRUD/list/search and its matching
// discovery. It owns no mutable resources, goroutines or shutdown work.
// Users, combined root search, Bulk and connection lifecycle fail closed.
type GroupsService struct{ service *protocolService }

// NewGroupsService validates and snapshots the selected runtime and discovery
// without external calls. It does not prove GroupStore's durable guarantees or
// provide identity/organization provisioning. NewUsersService is unchanged.
func NewGroupsService(c GroupsConfig) (*GroupsService, error) {
	if nilInterface(c.Store) || nilInterface(c.Mapper) || c.GroupMembers < 0 || c.GroupMembers > DefaultGroupMembers {
		return nil, failure(400, "invalidValue")
	}
	if root, err := url.Parse(c.BaseURL); err == nil {
		if root.ForceQuery || strings.ContainsRune(c.BaseURL, '#') || !unambiguousMemberPath(root.EscapedPath()) {
			return nil, failure(400, "invalidValue")
		}
	}
	common := Config{Authenticator: c.Authenticator, Authorizer: c.Authorizer, Limits: c.Limits, BaseURL: c.BaseURL, DocumentationURI: c.DocumentationURI, Extensions: c.Extensions, Now: c.Now, RequestTimeout: c.RequestTimeout}
	s, err := newProtocolService(common, groupProfile(), groupDependencies{store: c.Store, mapper: c.Mapper, members: c.GroupMembers})
	if err != nil {
		return nil, err
	}
	return &GroupsService{service: s}, nil
}

// Execute uses Request's HTTP-independent protocol model. Group operations can
// reach only GroupMapper and GroupStore, never their User-specific counterparts.
// Authentication derives scope, original authority is bounded to twenty seconds,
// and unknown mutation outcomes stay blocked in the Store's existing authority.
func (s *GroupsService) Execute(ctx context.Context, request Request) (Response, error) {
	if s == nil {
		return Response{}, failure(503, "")
	}
	return s.service.execute(ctx, request)
}

// ParseGroupFilter parses the same bounded grammar as ParseFilter, resolving
// Group core paths (including qualified URNs), not User core attributes.
func ParseGroupFilter(expression string, extensions []Schema, limits Limits) (Filter, error) {
	if !limits.valid() || !validGroupExtensions(extensions, limits) {
		return Filter{}, failure(400, "invalidFilter")
	}
	return parseFilter(expression, extensions, limits, nil, groupProfile().schema)
}

// ParseGroupPatch validates a bounded Group PatchOp message. Application,
// member identity/immutability and referential integrity require GroupsService
// and its trusted atomic store; a parsed Patch grants no write authority.
func ParseGroupPatch(body []byte, extensions []Schema, limits Limits) (Patch, error) {
	if !limits.valid() || !validGroupExtensions(extensions, limits) {
		return Patch{}, failure(400, "invalidValue")
	}
	doc, err := decodeObject(body, limits)
	if err != nil {
		return Patch{}, err
	}
	return parsePatchDocument(doc, extensions, limits, groupProfile().schema)
}

func validGroupExtensions(extensions []Schema, limits Limits) bool {
	if !validateSchemas(extensions, limits) {
		return false
	}
	for _, schema := range extensions {
		if strings.EqualFold(schema.ID, groupSchema) {
			return false
		}
	}
	return true
}

type resourceProfile struct {
	schema                                            Schema
	endpoint                                          string
	create, get, list, search, replace, patch, delete Operation
}

func userProfile() resourceProfile {
	return resourceProfile{schema: Schema{ID: userSchema, Name: "User", Description: "Selected Users profile", Attributes: coreAttributes()}, endpoint: "/Users", create: UserCreate, get: UserGet, list: UserList, search: UserSearch, replace: UserReplace, patch: UserPatch, delete: UserDelete}
}

func groupProfile() resourceProfile {
	return resourceProfile{schema: Schema{ID: groupSchema, Name: "Group", Description: "Selected Groups profile", Attributes: groupAttributes()}, endpoint: "/Groups", create: GroupCreate, get: GroupGet, list: GroupList, search: GroupSearch, replace: GroupReplace, patch: GroupPatch, delete: GroupDelete}
}

// The optional core parameter is private fixed-profile selection; public User
// parser signatures and their established default remain source-compatible.
func selectedCore(core []Schema) Schema {
	if len(core) == 1 {
		return core[0]
	}
	return userProfile().schema
}

type groupDependencies struct {
	store   GroupStore
	mapper  GroupMapper
	members int
}

func (s *protocolService) getResource(ctx context.Context, scope Scope, id string) (Resource, error) {
	if s.profile.schema.ID == groupSchema {
		return s.groups.store.GetGroup(ctx, scope, id)
	}
	return s.config.Store.Get(ctx, scope, id)
}

func (s *protocolService) snapshotResources(ctx context.Context, scope Scope, budget SnapshotBudget) (Snapshot, error) {
	if s.profile.schema.ID == groupSchema {
		return s.groups.store.SnapshotGroups(ctx, scope, budget)
	}
	return s.config.Store.Snapshot(ctx, scope, budget)
}

func (s *protocolService) prepareWrite(ctx context.Context, intent WriteIntent) (PreparedWrite, error) {
	if s.profile.schema.ID == groupSchema {
		return s.groups.store.PrepareGroup(ctx, intent)
	}
	return s.config.Store.Prepare(ctx, intent)
}

func (s *protocolService) commitWrite(ctx context.Context, prepared PreparedWrite, change Change) (WriteResult, error) {
	if s.profile.schema.ID == groupSchema {
		return s.groups.store.CommitGroup(ctx, prepared, change)
	}
	return s.config.Store.Commit(ctx, prepared, change)
}

func (s *protocolService) abortWrite(ctx context.Context, prepared PreparedWrite) error {
	if s.profile.schema.ID == groupSchema {
		return s.groups.store.AbortGroup(ctx, prepared)
	}
	return s.config.Store.Abort(ctx, prepared)
}

func (s *protocolService) mapResource(ctx context.Context, scope Scope, input WritableResource) (WritableResource, error) {
	if s.profile.schema.ID == groupSchema {
		return s.groups.mapper.MapGroup(ctx, scope, input)
	}
	return s.config.Mapper.MapUser(ctx, scope, input)
}

func groupAttributes() []Attribute {
	name := scalar("displayName", "string")
	// RFC 7643 4.2 and verified erratum 5368 require displayName. The
	// uncorrected example's required=false is not the selected wire contract.
	name.Required = true
	value := scalar("value", "string")
	// RFC 7643 4.2 explicitly allows required non-empty member identity.
	value.Required, value.Mutability = true, "immutable"
	ref := scalar("$ref", "reference")
	ref.CaseExact, ref.Mutability = true, "immutable"
	ref.ReferenceTypes = []string{"User", "Group"}
	typ := scalar("type", "string")
	typ.Mutability = "immutable"
	typ.CanonicalValues = []string{"User", "Group"}
	display := scalar("display", "string")
	display.Mutability = "immutable" // RFC 7643 2.4's display sub-attribute.
	members := scalar("members", "complex")
	members.MultiValued = true
	members.SubAttributes = []Attribute{value, ref, typ, display}
	return []Attribute{name, members}
}

func (s *protocolService) normalizeGroupMembers(value any, prior any) ([]any, error) {
	if value == nil {
		return nil, nil
	}
	members, ok := value.([]any)
	if !ok || len(members) > s.groups.members {
		return nil, failure(400, "invalidValue")
	}
	old := map[string]map[string]any{}
	if previous, ok := prior.([]any); ok {
		for _, raw := range previous {
			if member, ok := raw.(map[string]any); ok {
				old[groupMemberKey(member)] = member
			}
		}
	}
	out := make([]any, 0, len(members))
	seen := map[string]bool{}
	for _, raw := range members {
		member, ok := raw.(map[string]any)
		if !ok {
			return nil, failure(400, "invalidValue")
		}
		member = cloneMap(member)
		id, ok := member["value"].(string)
		if !ok || !safeID(id) || id == "." || id == ".." {
			return nil, failure(400, "invalidValue")
		}
		typ, _ := member["type"].(string)
		ref, _ := member["$ref"].(string)
		kind, canonical, err := s.groupMemberReference(id, typ, ref)
		if err != nil {
			return nil, err
		}
		member["type"], member["$ref"] = kind, canonical
		key := groupMemberKey(member)
		if seen[key] {
			return nil, failure(400, "invalidValue")
		}
		seen[key] = true
		if existing := old[key]; existing != nil {
			// A retained value has an exact resource identity, even though RFC
			// member.value filtering uses its declared case-insensitive schema.
			for name, before := range existing {
				if present(before) && !sameGroupMemberField(name, before, member[name]) {
					return nil, failure(400, "mutability")
				}
				if present(before) {
					member[name] = before
				}
			}
		}
		out = append(out, member)
	}
	return out, nil
}

func groupMemberKey(member map[string]any) string {
	typ, _ := member["type"].(string)
	id, _ := member["value"].(string)
	return typ + "\x00" + foldString(id)
}

func sameGroupMemberField(name string, before, after any) bool {
	if name == "display" {
		return sameValue(before, after, scalar("display", "string"))
	}
	return before == after
}

func (s *protocolService) groupMemberReference(id, typ, ref string) (string, string, error) {
	if typ != "" && !strings.EqualFold(typ, "User") && !strings.EqualFold(typ, "Group") {
		return "", "", failure(400, "invalidValue")
	}
	var resolved *url.URL
	if ref != "" {
		u, err := url.Parse(ref)
		if err != nil || u.User != nil || u.RawQuery != "" || u.ForceQuery || strings.ContainsRune(ref, '#') || !unambiguousMemberPath(u.EscapedPath()) {
			return "", "", failure(400, "invalidValue")
		}
		base, _ := url.Parse(s.config.BaseURL + "/")
		resolved = base.ResolveReference(u)
	}
	for _, kind := range []string{"User", "Group"} {
		if typ != "" && !strings.EqualFold(typ, kind) {
			continue
		}
		canonical := s.config.BaseURL + "/" + kind + "s/" + url.PathEscape(id)
		if resolved != nil {
			target, _ := url.Parse(canonical)
			// RFC 3986 6.2: scheme/host casing and percent-encoded
			// unreserved path characters cannot change the owned target.
			if strings.EqualFold(resolved.Scheme, target.Scheme) && strings.EqualFold(resolved.Host, target.Host) && resolved.Path == target.Path {
				return kind, canonical, nil
			}
		} else if ref == "" && (typ != "" || kind == "User") {
			return kind, canonical, nil
		}
	}
	return "", "", failure(400, "invalidValue")
}

func unambiguousMemberPath(path string) bool {
	for _, encoded := range strings.Split(path, "/") {
		segment, err := url.PathUnescape(encoded)
		if err != nil || segment == "." || segment == ".." || strings.ContainsAny(segment, "/\\") {
			return false
		}
	}
	return true
}

// Canonicalize only complete core-member operands before generic set equality.
// This makes adding an already present membership a no-op even when its optional
// type/reference/display were omitted. Supplied changed immutable metadata is
// refused, not silently discarded. Child updates retain normal immutable rules.
func (s *protocolService) canonicalGroupPatchOperation(op PatchOperation, current map[string]any) (PatchOperation, error) {
	if op.Op == "remove" {
		return op, nil
	}
	canonicalMembers := func(value any) (any, error) {
		a, _ := findAttribute(s.profile.schema.Attributes, "members")
		normalized, err := normalizeValue(value, a, nil)
		if err != nil {
			return nil, err
		}
		members, err := s.normalizeGroupMembers(normalized, nil)
		if err != nil || op.Op != "add" {
			return members, err
		}
		existing := map[string]map[string]any{}
		previous, _ := current["members"].([]any)
		for _, raw := range previous {
			member := raw.(map[string]any)
			existing[groupMemberKey(member)] = member
		}
		for i, raw := range members {
			member := raw.(map[string]any)
			before := existing[groupMemberKey(member)]
			if before == nil {
				continue
			}
			for name, value := range member {
				if !sameGroupMemberField(name, value, before[name]) {
					return nil, failure(400, "mutability")
				}
			}
			members[i] = cloneMap(before)
		}
		return members, nil
	}
	if op.Path == "" {
		values := cloneMap(op.Value.(map[string]any))
		for key, value := range values {
			path, err := parsePatchPath(key, s.config.Extensions, s.config.Limits, s.profile.schema)
			if err != nil {
				// Extension container syntax was validated independently and
				// never names the core Group members collection.
				if _, ok := extensionSchema(s.config.Extensions, key); ok {
					continue
				}
				return op, err
			}
			if path.path.extension == "" && len(path.path.parts) == 1 && path.path.parts[0].Name == "members" && !path.selected {
				values[key], err = canonicalMembers(value)
				if err != nil {
					return op, err
				}
			}
		}
		op.Value = values
		return op, nil
	}
	path, err := parsePatchPath(op.Path, s.config.Extensions, s.config.Limits, s.profile.schema)
	if err != nil {
		return op, err
	}
	if path.path.extension == "" && len(path.path.parts) == 1 && path.path.parts[0].Name == "members" && !path.selected {
		op.Value, err = canonicalMembers(op.Value)
	}
	return op, err
}
