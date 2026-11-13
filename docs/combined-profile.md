# Combined Users and Groups protocol profile

[Repository entry](../README.md) · [Users profile](users-profile.md) ·
[Groups profile](groups-profile.md)

`NewCombinedService(CombinedConfig)` creates one HTTP-independent public
`Execute(context.Context, Request)` surface for the existing User and Group
operations plus shared discovery. It supplies no native store, token verifier,
organization mapper, provisioning engine, HTTP routes or background work.

## Caller and ownership

Supply the existing typed `Store`/`Mapper` and `GroupStore`/`GroupMapper` owners.
Configure `Authenticator`, `Authorizer`, `Limits`, `BaseURL`, optional
`DocumentationURI`, `Now` and `RequestTimeout` once, rather than composing two
independent policy snapshots. Each request still authenticates current scoped
credentials; construction does not authenticate or cache a connection.

```go
service, err := scim.NewCombinedService(scim.CombinedConfig{
    UserStore: userStore, UserMapper: userMapper,
    GroupStore: groupStore, GroupMapper: groupMapper,
    Authenticator: authenticator, Authorizer: authorizer,
    Limits: scim.DefaultLimits(), GroupMembers: scim.DefaultGroupMembers,
    BaseURL: "https://example.test/scim/v2", RequestTimeout: time.Second,
})
// Handle err. The same public Execute method accepts discovery, User and Group
// requests; no request may select its own tenant or provider connection.
response, err := service.Execute(ctx, scim.Request{
    Operation: scim.ResourceTypesList, Credential: credential,
})
```

The executable external consumer in `combined_test.go` discovers both types and
schemas, creates/reads a User, then creates/reads a Group referencing that User
through their original typed owners. Its explicit process-local store doubles
prove protocol dispatch and wire behavior only—not real bearer verification,
durable transactions, organization mapping or provisioning. Native adapters
must satisfy the existing stores' atomic authority/reference/outcome contracts.

## Shared discovery

- ResourceTypes lists exactly User and Group with their canonical endpoints,
  core schema IDs and per-resource `schemaExtensions` objects. Every extension
  has explicit `required:false`, matching the selected optional-extension model.
- Schemas includes both actual core descriptors and the selected extensions.
  An identical shared schema ID appears once. Shared IDs must have identical
  effective wire descriptors after the existing constructor normalization;
  case aliases, conflicting metadata/attributes and core collisions deny.
- Lists use the RFC ListResponse envelope and exact `totalResults`, `Resources`,
  `startIndex` and `itemsPerPage`. ResourceType and Schema lookup use the same
  frozen source descriptors as collection discovery.
- Construction validates the **combined** collections, not merely each child's
  smaller document. The same response/structural/string limits are enforced at
  request time. Impossible limits return no partially usable service.
- ServiceProviderConfig retains the actual shared filter/page, PATCH, sort,
  ETag and bearer-authentication capabilities. Bulk and password writes remain
  unsupported. Changing input extension slices after construction changes
  neither discovery nor resource validation.

These messages follow [RFC7643 sections5–7](https://www.rfc-editor.org/rfc/rfc7643)
and the retained exact discovery clauses. No additional provider or protocol
capability is inferred from selecting both resource owners.

## Runtime and exclusions

Group operations reach only the Group-specific contracts; User operations reach
only their existing contracts. Discovery uses the same authenticated/authorized
admission and original authority-expiry fences. Policy withdrawal, cancellation
or expired disclosure returns no successful body. Construction starts no
resource; caller-owned dependencies must remain alive and concurrency-safe.

`UserSearch` and `GroupSearch` remain resource-specific. Root `Search` is an
explicit opt-in through `CombinedConfig.RootSnapshotter`. Without it the service
retains 501; existing Users-only root-search behavior is unchanged.

## One mixed-resource root snapshot

```go
config.RootSnapshotter = rootSnapshotOwner
service, err := scim.NewCombinedService(config)
// Handle err. The owner implements SnapshotRoot(ctx, originalConnection, budget)
// and returns one complete scoped RootSnapshot with typed RootUser/RootGroup
// entries. A pair of sequential User/Group reads is not that contract.
response, err := service.Execute(ctx, scim.Request{
    Operation: scim.Search, Credential: credential,
    ContentType: "application/scim+json",
    Body: []byte(`{"schemas":["urn:ietf:params:scim:api:messages:2.0:SearchRequest"],"filter":"userName pr or members pr","count":100}`),
})
```

The read owner receives the existing verified Connection, including its original
credential, version and authority deadlines. These are custody metadata, not a
new authority lease. It must enforce current scope/authority and the unchanged
deadline at its protected read. It returns detached values from one transaction
or immutable view; no lock or transaction escapes the call. Snapshot resources
and bytes are aggregate User-plus-Group budgets, enforced before materialization.
The service independently checks returned scope, completeness, aggregate bounds,
closed resource kinds, matching per-type schemas and global ID uniqueness even
for count zero. Broken snapshots produce no partial count or resource response.

The library owns the entire mixed query: exact SearchRequest decoding, one
authenticated/authorized admission, type-aware filters, sort, projection and
pagination, followed by current-policy and original-deadline disclosure fences.
The original Connection window is never renewed. Unknown schema paths and
returned-never attributes deny; a known attribute absent from the other resource
type is unassigned, as required by
[RFC7644 section3.4.2](https://www.rfc-editor.org/rfc/rfc7644#section-3.4.2).
Core-schema-qualified paths apply only to that resource type, while declared
extension paths retain their exact schema identity. Sorting uses the declared
comparison and primary/value semantics, then server ID ascending as a stable
tie-break. Omitted sorting uses ID ascending. Counts and resources come from
the same frame, including count zero and empty/out-of-range pages.

`TestRootSearchPublicMixedResourceConsumer` creates a User and referencing Group
through the original typed owners, then queries one immutable combined frame
through the same public Execute surface. Its process-local snapshot fixture is
protocol proof only, not proof of native transaction consistency, token
validation, organization synchronization or provisioning.

Bulk, connection lifecycle, native provisioning, HTTP/OpenAPI integration and
whole-unit/release qualification remain separate work. Selecting this service
does not add a journal or transfer any persistence, policy or lifecycle owner.
