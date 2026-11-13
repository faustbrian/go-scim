# Groups profile decisions and limits

[Documentation index](README.md) · [Repository entry](../README.md)

## Supported public boundary

`NewGroupsService(GroupsConfig)` constructs one immutable Groups-only protocol
snapshot. `GroupsService.Execute` accepts `GroupCreate`, `GroupGet`, `GroupList`,
`GroupSearch`, `GroupReplace`, `GroupPatch`, `GroupDelete` and matching discovery.
The service is HTTP-independent: `GroupSearch` corresponds to `Groups/.search`,
not combined root `.search`. The optional [combined profile](combined-profile.md)
adds shared discovery, typed resource dispatch and optional explicit mixed-
snapshot root search. Transport remains separately owned. Bulk, connection lifecycle and password writes remain
unsupported. Existing `NewUsersService`, `Store`, `Mapper`, `ParseFilter` and
`ParsePatch` retain their User-specific contracts and defaults.

Two designs were considered: extending the User interfaces with Group methods,
or adding explicit Group contracts around one private fixed-profile engine.
The latter preserves existing implementations and prevents accidental User
mapping/storage calls for Group operations. `GroupMapper.MapGroup` is pure
representation policy; `GroupStore` methods are explicitly named by resource type.
No callback adapter, second replay journal or provisioning authority is created.

```go
func CreateGroup(ctx context.Context, service *scim.GroupsService,
    credential authentication.BearerCredential) (scim.Response, error) {
    return service.Execute(ctx, scim.Request{
        Operation: scim.GroupCreate,
        Credential: credential,
        ContentType: "application/scim+json",
        Body: []byte(`{"schemas":["urn:ietf:params:scim:schemas:core:2.0:Group"],"displayName":"Tour Guides"}`),
    })
}
```

Compose a service with `GroupsConfig{Store: groupStore, Mapper: groupMapper,
Authenticator: authenticator, Authorizer: authorizer, Limits: DefaultLimits(),
GroupMembers: DefaultGroupMembers, BaseURL: "https://example.test/scim/v2",
RequestTimeout: time.Second}`. Those dependencies are trusted, concurrency-safe
boundaries, not implementations supplied by the protocol library.

## Schema and membership

The fixed Group schema is
`urn:ietf:params:scim:schemas:core:2.0:Group`, with required `displayName` and optional
multi-valued `members`, plus common `schemas`, `externalId`, server `id` and `meta`.
Group names and external IDs are non-unique. Optional extensions use the same
required, mutability, returned and privacy policies as the Users profile.

Members use immutable `value`, `$ref`, `type` and optional `display`.
`value` is required and must be a nonempty bounded resource ID. Types are `User`
or `Group`, case-insensitively admitted and canonically returned. An omitted type
is inferred from a supplied local reference, otherwise defaults to `User`.
Omitted references are derived from the selected root/type/exact ID; absolute or
relative references must resolve to that same URI. Scheme/host casing and
unreserved percent encodings canonicalize without changing the exact target ID.
Foreign origins, paths, types, IDs, dot-segment/traversal or encoded-separator
ambiguity, credentials, queries and fragments are rejected, not fetched.
References confer no authority and do not prove target existence.

These choices follow [RFC 7643 §4.2](https://www.rfc-editor.org/rfc/rfc7643#section-4.2),
which permits requiring a nonempty member subattribute, and
[§2.4](https://www.rfc-editor.org/rfc/rfc7643#section-2.4)'s immutable `display`.
Required `displayName` follows §4.2 and
[verified erratum 5368](https://www.rfc-editor.org/errata/eid5368), not the
uncorrected example's `required: false`. References are case-exact per
[§2.3.7](https://www.rfc-editor.org/rfc/rfc7643#section-2.3.7). Member-value
filter/set comparison follows its case-insensitive schema descriptor; exact
authoritative IDs are retained and used for actual scoped Store resolution.
Canonical duplicate `(type, value)` membership identities are rejected, even when
their display text differs. User and Group references are distinct identities.

Changing a retained member's immutable metadata is refused. Remove a membership
then add a new value to change it; those explicit steps can share one atomic
PATCH. Selected whole-member replacement cannot change its immutable identity.
Adding an existing membership with omitted optional metadata is a no-op retaining
its projection, version and timestamps. Supplied conflicting metadata is refused,
not silently discarded. Group replacement removes omitted writable fields and
members while preserving immutability for retained values.

## Bounds, queries and outcomes

`GroupMembers` is explicit: `0` permits only empty Groups; `DefaultGroupMembers`
is the reference maximum 10,000 and configurations outside 0..10,000 fail. The
reference configuration's `scim.group_members` row supplies that ceiling.
`Limits.ResourceAttributes` (default 1,000 total parsed attributes), body, string,
resource-depth, response and snapshot bounds remain independently enforced.
The member ceiling does not promise that 10,000 full members fit those smaller
budgets. Lower member limits apply before mapping/admission and before allocating
a PATCH-expanded member collection. They also apply to mapped/stored projections.

`ParseGroupFilter` and `ParseGroupPatch` expose the Group-aware bounded parsers;
the existing parser functions remain User-aware. Qualified Group URN paths,
value-path member filters/selectors and `$ref` are supported. Each list uses one
complete bounded transaction snapshot, exact totals, deterministic schema-aware
sort plus ID tie-break, 1-based pages, configured default/capped count and exact
count-zero results. Search uses the same query/projection semantics. Every
resource response retains `meta.version`, even under projection.

Strong opaque ETags and exact mandatory `If-Match` apply to replace, PATCH and
delete: missing is 428, stale is 412, malformed/weak/list/wildcard is rejected.
`GroupStore` owns current authority, CAS, same-connection member existence and
type checks atomically with the protected mutation and audit/result retention.
Missing, cross-connection and wrong-type members produce the same redacted
`ErrInvalidGroupMember`/400 `invalidValue`, with no committed effects.

Original authority expires exclusively within twenty seconds of its original
read beginning. All read/map/admission/commit calls consume the remaining
earliest authority/token/request window. Late values and state-dependent errors
are withheld. A valid commit whose response arrives late remains committed;
withholding that response neither aborts it nor grants permission to retry.
The [Users authority and replay contract](users-profile.md) applies unchanged:
matching retries recover semantic results before current-resource checks,
fingerprint mismatches conflict, unknown/in-progress outcomes remain blocked,
and headerless deletion is recovered independently of tombstone retention.

## Qualification and exclusions

Tests use explicitly trusted process-local scoped protocol fixtures. They prove
the real public protocol service, not durable transactions, identity/org
provisioning, production tokens, native PostgreSQL adapters, directory-to-team
mapping or M29 completion. Group deletion removes only the owned projection,
not member Users, nested Groups, teams, identities or memberships. Incoming
reference cleanup and organization reconciliation/deprovisioning remain adapter
and lifecycle work, not implicit cascading deletion.

Native adapters, HTTP/OpenAPI composition,
independent-client full conformance, release qualification and public release
remain pending. The full SCIM goal and its broader acceptance are retained.
