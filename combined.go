package scim

import (
	"bytes"
	"context"
	"encoding/json"
	"strings"
	"time"
)

// CombinedConfig selects User and Group protocol owners under one effective
// authority, limits, URL, clock and timeout configuration. Stores and mappers
// retain their existing distinct contracts; combining them does not implement
// persistence or provisioning. Dependencies remain caller-owned, concurrent-safe
// and context-bounded. Extensions are cloned and remain resource-specific;
// identical shared schema IDs must have identical effective descriptors.
// GroupMembers has GroupsConfig's explicit zero-means-empty semantics.
type CombinedConfig struct {
	UserStore        Store
	UserMapper       Mapper
	GroupStore       GroupStore
	GroupMapper      GroupMapper
	Authenticator    Authenticator
	Authorizer       Authorizer
	Limits           Limits
	GroupMembers     int
	BaseURL          string
	DocumentationURI string
	UserExtensions   []Schema
	GroupExtensions  []Schema
	Now              func() time.Time
	RequestTimeout   time.Duration
}

// CombinedService executes the existing typed User and Group operations with
// shared discovery describing both actual owners. It caches no authentication,
// holds no transaction or lock, and starts no background work. Concurrent safety
// depends on its borrowed dependencies. Bulk, combined root search and connection
// lifecycle remain unsupported; this is not a native provisioning backend.
type CombinedService struct {
	users  *UsersService
	groups *GroupsService
}

type discoveryProfile struct {
	resource   resourceProfile
	extensions []Schema
}

// NewCombinedService validates and freezes both runtime profiles and their
// complete shared discovery before making any external call. Common policy and
// limits are supplied once, never inferred by comparing two collaborators.
// Conflicting or case-aliased shared schema IDs, core collisions, missing owners
// and limits unable to encode the complete discovery return nil/invalidValue.
// Existing single-resource constructors retain their own selected discovery.
func NewCombinedService(c CombinedConfig) (*CombinedService, error) {
	users, err := NewUsersService(Config{
		Store: c.UserStore, Mapper: c.UserMapper,
		Authenticator: c.Authenticator, Authorizer: c.Authorizer,
		Limits: c.Limits, BaseURL: c.BaseURL, DocumentationURI: c.DocumentationURI,
		Extensions: c.UserExtensions, Now: c.Now, RequestTimeout: c.RequestTimeout,
	})
	if err != nil {
		return nil, err
	}
	groups, err := NewGroupsService(GroupsConfig{
		Store: c.GroupStore, Mapper: c.GroupMapper,
		Authenticator: c.Authenticator, Authorizer: c.Authorizer,
		Limits: c.Limits, GroupMembers: c.GroupMembers,
		BaseURL: c.BaseURL, DocumentationURI: c.DocumentationURI,
		Extensions: c.GroupExtensions, Now: c.Now, RequestTimeout: c.RequestTimeout,
	})
	if err != nil {
		return nil, err
	}
	profiles := []discoveryProfile{
		{resource: users.service.profile, extensions: users.service.config.Extensions},
		{resource: groups.service.profile, extensions: groups.service.config.Extensions},
	}
	for _, profile := range profiles {
		for _, schema := range profile.extensions {
			if strings.EqualFold(schema.ID, userSchema) || strings.EqualFold(schema.ID, groupSchema) {
				return nil, failure(400, "invalidValue")
			}
		}
	}
	if err := validateSharedSchemas(profiles); err != nil {
		return nil, err
	}
	users.service.discoveryProfiles = profiles
	// A combined root search cannot truthfully reuse the existing User-only
	// snapshot: these stores do not provide one cross-type transaction snapshot.
	users.service.rootSearchUnavailable = true
	for _, operation := range []Operation{ServiceProviderConfig, SchemasList, ResourceTypesList} {
		doc, err := users.service.discovery(operation, "")
		if err != nil {
			return nil, err
		}
		if _, err := users.service.encodeDiscovery(doc); err != nil {
			return nil, failure(400, "invalidValue")
		}
	}
	return &CombinedService{users: users, groups: groups}, nil
}

// Execute authenticates and authorizes through the selected existing resource
// engine once per call. Requests cannot select a principal or connection scope.
// Discovery uses the same common admission and remaining original-authority
// budget as resource operations. Unknown outcomes, errors and cleanup retain the
// original typed owners' semantics; no second admission or replay engine exists.
func (s *CombinedService) Execute(ctx context.Context, request Request) (Response, error) {
	if s == nil || s.users == nil || s.groups == nil {
		return Response{}, failure(503, "")
	}
	switch request.Operation {
	case GroupCreate, GroupGet, GroupReplace, GroupPatch, GroupDelete, GroupList, GroupSearch:
		return s.groups.Execute(ctx, request)
	default:
		return s.users.Execute(ctx, request)
	}
}

func validateSharedSchemas(profiles []discoveryProfile) error {
	seen := make(map[string][]byte)
	for _, profile := range profiles {
		for _, schema := range append([]Schema{profile.resource.schema}, profile.extensions...) {
			encoded, err := json.Marshal(schema)
			if err != nil {
				return failure(400, "invalidValue")
			}
			key := strings.ToLower(schema.ID)
			if previous, exists := seen[key]; exists && !bytes.Equal(previous, encoded) {
				return failure(400, "invalidValue")
			}
			seen[key] = encoded
		}
	}
	return nil
}
