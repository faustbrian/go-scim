# go-scim

Storage-neutral, HTTP-independent SCIM 2.0 **Users and Groups protocol profiles**, targeting
Go 1.27. This is an unreleased implementation, not a turnkey provisioning backend,
verified release, or completion of the wider SCIM unit. The optional
[PostgreSQL adapter](postgres/README.md) selects configured, authorized discovery
and Users create/get/replace/PATCH/delete/list/search through the actual identity
and authority owners. Its separately selected native Groups service provides
directory CRUD/query, typed same-connection member references and original retry
recovery without changing the default Users service. Organization reconciliation,
global deprovisioning and native connection management remain separate work.
The optional [organization mapping module](organization/README.md) selects
exact configured Group/User edges for the SSO-owned native reconciliation
workflow; it does not infer team roles or change global accounts.

## Durable command admission

The service proposes a random `WriteIntent.CommandID`, but `Store.Prepare` owns
the authoritative original command used by both fresh execution and replay.
A durable request-key owner may allocate a different valid server command;
the protocol carries that returned ID into Commit/Abort rather than requiring
an alias or second journal. The request cannot choose either server identity.
Prepared admission must echo the exact scope, operation, target, precondition,
canonical request and current lookup key. For a recovered headerless DELETE,
the current lookup key may differ from the original command's absent header;
it is correlation, not a replacement command. Fresh connection evidence must
retain its original fields and validity deadline. Malformed or substituted
admission denies before mapping, mutation or unsafe cleanup. This is protocol
composition support, not proof of a native provisioning implementation.

Durable admission may also supply `PreparedWrite.CreateMetadata` with the
original server ID, strong version and creation/modification timestamps. It is
validated and copied before mapping, with timestamps normalized to UTC without
changing their instants. UTC years must be 1 through 9999. It is used only for
fresh create and never
accepted in client JSON. All writable attributes still come through the same
schema and mapping pipeline. Nil retains legacy metadata generation; replay
uses its original committed result. The exact final resource comparison is
unchanged: a Store cannot replace the attempted resource after mutation.

For replace/PATCH, `PreparedWrite.UpdateMetadata` can retain the original
version and modification time alongside the detached original `Current`.
Resource ID and creation time still come only from that snapshot. The protocol
copies and UTC-normalizes metadata before mapping, rejects backward time or a
reused version for a changed resource, and preserves no-op PATCH metadata.
Nil keeps existing generation; replay still uses the original result. This is
not durable storage, CAS or permission to renew connection authority.

## Selected profile

`NewUsersService(Config)` constructs one immutable runtime/discovery snapshot.
`UsersService.Execute(context.Context, Request)` authenticates an opaque bearer,
authorizes the resulting organization/provider connection, and executes:

- ServiceProviderConfig, Schema and ResourceType document/collection discovery;
- User create, get, replace, atomic PATCH and delete followed by absence;
- deterministic, bounded GET-list and POST-search at the protocol operations
  corresponding to `.search` and `Users/.search`;
- typed, redacted RFC Error envelopes, strong opaque ETags and required exact
  `If-Match` preconditions for replace, PATCH and delete.

The fixed User schema supports `userName`, `name` (formatted, familyName,
givenName, middleName, honorificPrefix and honorificSuffix), `displayName`,
`active` and `emails` (value, type, primary and display), plus common `schemas`,
`externalId`, server `id` and `meta`. Other optional core User attributes are not
part of this selected schema and are rejected, not silently discarded.
Configured optional extensions are published with their exact schema descriptors.

Core usernames retain their original spelling and IDs while comparison uses
the versioned RFC 8265 UsernameCaseMapped/Unicode 17 profile. Stores must use
`UsernameComparisonKey` and `UsernameComparisonProfile` for scoped atomic
uniqueness; see the profile's preparation and index-upgrade contract below.

`NewUsersService` remains Users-only. The additive
[`NewGroupsService(GroupsConfig)` profile](docs/groups-profile.md) supports Group
discovery, CRUD, atomic PATCH, bounded list/filter/sort/page and `Groups/.search`
with distinct `GroupStore` and `GroupMapper` contracts. Group membership references
cannot select another connection or treat a User projection as a Group.

[`NewCombinedService(CombinedConfig)`](docs/combined-profile.md) selects both
existing typed resource owners through one public `Execute` surface. Its shared
Schemas/ResourceTypes discovery describes both actual profiles and their exact
optional extensions under one authority, limits, URL and clock configuration.
Identical shared schema IDs are listed once; conflicting descriptors and
unencodable combined collections fail construction. Existing single-resource
constructors retain their own discovery and behavior.

Combined root `.search` is available only with an explicit `RootSnapshotter`
owning one complete bounded mixed User/Group transaction or immutable view.
The same public Execute surface performs schema-aware filtering, sorting,
projection and exact pagination; it never stitches separate store snapshots.
Configurations without that read owner retain 501. See the
[root snapshot contract](docs/combined-profile.md#one-mixed-resource-root-snapshot).

Bulk, password/credential writes and connection lifecycle operations remain
unimplemented. Groups are absent from the Users service's ResourceTypes; ServiceProviderConfig
advertises Bulk and change-password as unsupported. Every password or
`returned: never` write is rejected at `DecideCredentialWrite` before mapping or
store admission. Reading, filtering, sorting or explicitly projecting those
attributes fails without revealing whether they exist.

The profile follows [RFC 7643](https://www.rfc-editor.org/rfc/rfc7643) and
[RFC 7644](https://www.rfc-editor.org/rfc/rfc7644) for the declared surface. It
makes no independent-client interoperability or full-conformance claim.

## Composition and authority

Supply concurrency-safe `Authenticator`, `Authorizer`, `Mapper` and `Store`
implementations. A request carries a credential, not an arbitrary principal,
connection, tenant, organization, permission Boolean or command ID.

Trusted composition can explicitly select
`UsersService.ExecuteAdmittedRead(ctx, request, gate)` for `UserGet` and
`UserList` only. A nonnil synchronous gate is required after the actual bearer
authentication and operation authorization, before any resource I/O. Bind any
authenticated client identity privately in that request-local gate; the
protocol's `Connection` is not actor authority. The gate consumes the original
remaining authority, request and parent deadlines without extending them. A nil
result allows the read; 403 and a bounded 429 with a positive retry delay are
normalized to redacted denials, and other failures become 503. Cancellation or
authority expiry during the gate overrides even its selected denial, and the
final disclosure fence remains in force. The gate must honor its context,
retain no invocation state and launch no detached work.

This selection does not add a rate engine, validate managed bearer storage,
implement HTTP routes, or enable search, Groups, discovery or writes. Ordinary
`Execute` and sibling services retain their existing behavior.

`UsersService.ExecuteAdmittedCreate(ctx, request, gate)` separately selects
`UserCreate` with a required synchronous trusted gate. Existing bounded JSON,
schema, target and query validation, actual bearer authentication and operation
authorization must pass before the gate runs. It runs once per valid authorized
attempt, including a retry, before mapping, server command allocation or Store
admission. The existing canonical write, idempotency and durable-owner command
remain unchanged; allowing admission does not grant write or replay authority.

The Create gate uses the same original deadlines and redacted denial rules as
admitted reads. Cancellation, exclusive authority expiry, panics and reentrant
protocol execution through its context fail closed before command effects.
The gate must not retain its context or start detached work. The final disclosure
fence still withholds a late result without rewriting a Store's committed outcome.
This entry point adds no limiter, native storage selection or HTTP route. It does
not select replacement, PATCH, delete, reads, Groups or Bulk, and ordinary
`Execute` retains its existing physical behavior.

`UsersService.ExecuteAdmittedDelete(ctx, request, gate)` separately selects
only `UserDelete`. Current bearer/operation authority and existing bounded
target, required strong `If-Match`, empty-body and query checks precede its
once-per-attempt gate. Actual state-dependent precondition checks, deletion,
unknown outcomes and headerless tombstone-backed replay stay with the existing
Store; admission does not grant or replace that authority. The same original
deadlines, normalized denials, reentry and late-result fences apply. Native
request-key behavior is unchanged. No HTTP transport is added, and this entry
point does not authorize the public HTTP `Idempotency-Key` extension.

`UsersService.ExecuteAdmittedPatch(ctx, request, gate)` separately selects
only `UserPatch`. Current bearer/operation authority and existing bounded
target, required strong `If-Match`, request/query and PatchOp checks precede
its once-per-attempt gate. The complete parsed patch and canonical request
continue unchanged through the existing Store's precondition, atomic CAS,
no-op metadata, failure/unknown outcome and replay rules. Admission grants none
of that authority. Original deadlines, normalized denials, descendant-context
reentry and late-result fences match admitted Create and Delete. No command,
mapping or resource I/O precedes an allowed, still-current gate result.
Ordinary execution and other selections are unchanged; no storage, HTTP route
or public HTTP `Idempotency-Key` extension is enabled by this entry point.

`UsersService.ExecuteAdmittedReplace(ctx, request, gate)` separately selects
only `UserReplace`. Current bearer/operation authority and the existing bounded
target, required strong `If-Match`, complete writable replacement and query
checks precede its once-per-attempt gate. Omitted writable fields retain the
existing replacement semantics, not PATCH merging. The normalized canonical
input, Store-owned original command, conditional CAS and replay stay unchanged;
admission grants none of that authority. Original deadlines, redacted denials,
descendant-context reentry and late-result fences match the other admitted
writes. No command, mapping or resource I/O precedes allowed current admission.
Ordinary execution and all other selectors are unchanged; no storage, HTTP
route or public HTTP `Idempotency-Key` extension is enabled.

```go
func CreateUser(ctx context.Context, service *scim.UsersService,
    credential authentication.BearerCredential) (scim.Response, error) {
    return service.Execute(ctx, scim.Request{
        Operation: scim.UserCreate,
        Credential: credential,
        ContentType: "application/scim+json",
        Body: []byte(`{"schemas":["urn:ietf:params:scim:schemas:core:2.0:User"],"userName":"bjensen"}`),
    })
}
```

This function assumes an already composed service with real authority and storage;
it does not provide those dependencies. The tests explicitly use trusted,
process-local boundary doubles. They are not production adapters or evidence of
identity, organization, token validation, database persistence or provisioning.

- **Authenticator** verifies a credential against current connection/token
  authority, including digest, expiry, revocation and tenant/org/provider scope.
  It preserves original read-began/valid-until metadata across cached copies and
  retries. Protected calls and disclosure expire at the earliest contributing
  authority/token deadline, never beyond twenty seconds from original read start.
- **Authorizer** evaluates current policy for that verified connection and exact
  operation/target. Errors, cancellation and panics deny without diagnostics.
- **Mapper** is a pure representation policy. It cannot persist, provision, grant
  memberships or take over accounts based on `externalId`.
- **Store** owns the single existing durable command/admission authority, scoped
  snapshots, atomic current-authority/ETag/uniqueness fencing, projection effects,
  audit attribution, replay and outcome recovery. `Prepare` returns detached
  state, never a held lock, transaction or callback engine. `Commit` must make
  the promised effects atomic. The protocol module provides no journal or
  successful-persistence substitute.

See the full Go documentation on `Store` and the
[profile decisions and limits](docs/users-profile.md) before implementing an
adapter. Do not infer database correctness from protocol tests.

### Managed connection metadata

`ParseConnectionID`, `ParseMappingPath`, `NewMappingSet`, and
`NewConnectionRecord` validate and detach the administrative data that an
owning connection store will persist and disclose. The tenant, organization,
and connection IDs must use the canonical nonzero 128-bit encoding. Mapping
paths resolve against declared readable User attributes; neither a mapping
nor its `Writable` flag grants permission. The record carries the selected
disposition but is not proof that any lifecycle can execute it.

`ConnectionRecord` is separate from the released `Connection` returned by an
`Authenticator`. It contains neither credential material nor authority
freshness, and these value constructors enable no management operations.

## Transport and integration

`Request`/`Response` do not depend on `net/http`. Transport composition owns actual
routes, raw/decoded streaming limits, TLS, header parsing, deadlines and writing
`*Error` with its `StatusCode()` and `application/scim+json`. It must expose no
Groups routes for a Users-only composition, or Users routes for a Groups-only
composition. No selected service exposes Bulk/connection-management routes.

`ParseBulk` is a protocol-only input boundary for a future native Bulk
adapter. Supply explicit operation and byte limits. Its immutable plan retains
the ordered requests and their exact semantic fingerprint input, and puts
local reference components in prerequisite-first order. It does not persist
children, allocate IDs, preflight the response, or execute any operation.
Before persisting children, call `PreflightBulkResponse` with that plan, the
trusted service root and an explicit response policy. Retain the proved byte
bound with the admitted parent. The response plan serializes terminal child
results in original request order, omits unprocessed children, and produces
no body for unresolved checkpoints. It does not validate database state or
implement the durable cutoff.
An executor can use `BulkPlan.ResolveOperation` on the original child index
with server IDs retained at admission. It substitutes only schema-declared
references and preserves the original request for replay. It does not look up
resources, establish their existence or grant execution authority.
Ordinary discovery continues to report Bulk as unsupported. A composition
with a native Bulk executor can use `BulkRequest` for borrowed request custody
and the authorized `ReadServiceProviderConfigWithBulk` read with that exact
executor's effective connection policy. Neither API enables an HTTP route.
The combined service dispatches Group operations only to GroupStore/GroupMapper
and User operations only to Store/Mapper. Combined root search requires the
explicit single mixed-resource snapshot owner and otherwise fails closed rather
than returning a User-only subset. No HTTP server,
background goroutine, environment lookup, database, network client or global
registration is started by this package.

Root SCIM consumes identity and organization types; it does not depend on all
SSO implementations. Native `scim/organization` mapping and `scim/postgres`
persistence remain separate units. The latter additionally depends on the former;
this protocol profile does not unlock or verify that adapter. The full platform
scope remains 67 units; these protocol profiles alone close neither M28 nor M29.

[Security boundaries](docs/security.md), the [repository goal](docs/goal.md), and
[private vulnerability reporting](SECURITY.md) describe the remaining integration
and qualification boundaries. Parent-owned inventory and release state are not
changed by this implementation.

## Verification

Use the checksum-verified public `golib` v2.5.1 release declared in
`.golib.yaml`, with Go 1.27.2 as the verification producer. The module's
minimum remains Go 1.27.0; this profile is not a verified release.
An ordinary standalone checkout is sufficient, without sibling repositories,
goal ledgers or building Tools from source:

```sh
make check
make ci
make runtime-check
```

Both routes, and the `make fast-check` alias, check configuration, repository
structure, cohesion, offline specification decisions, local documentation links
and unconditional whole-tree secrets. The first two routes run no application
tests, mutation campaigns or release checks. `runtime-check` runs the Users
and Groups protocol tests with the race detector and Go vet; hosted Required runs that same
target as well. Hosted Required applies the same structural checks
and scans committed changed content against the exact validated PR base or push
before commit, without a fallback base or a duplicate full-history scan.
Missing or invalid change identities and failed checks remain failures.
The changed-content scanner has a fatal 75-second deadline and five-second
termination grace, allowing bounded cold compilation without skipping scans.

`make check-full` optionally preserves the previous full manifest-selected
contract, including broad spelling and external-link documentation assurance.
It is not an ordinary CI prerequisite and does not establish runtime or release
qualification for this module.

`make check-online` explicitly adds authoritative specification refresh to the
local contract. Scheduled and manual CI also refresh those authorities online
and run whole-tree secrets. Passing any of these planning routes is not runtime
security or release qualification.

See the versioned [Golib ecosystem index](https://github.com/faustbrian/go-library-tools/blob/v1.4.0/docs/ecosystem/README.md)
and [package-family guidance](https://github.com/faustbrian/go-library-tools/blob/v1.4.0/docs/ecosystem/design-language.md#package-families-and-selection)
for the shared design language.

## License

MIT. See [LICENSE](LICENSE).

## Documentation navigation

[Complete documentation map](docs/README.md#complete-documentation-map)

Use the [versioned ecosystem entry](https://github.com/faustbrian/go-library-tools/blob/v1.4.0/docs/ecosystem/README.md) for package
selection. The [frozen compatibility cohort](https://github.com/faustbrian/go-library-tools/blob/v1.8.4/docs/ecosystem/compatibility-sets.md)
is separate from current package releases and unpublished source changes.
Adopting them does not silently update that cohort.
