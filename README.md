# go-scim

Storage-neutral, HTTP-independent SCIM 2.0 **Users and Groups protocol profiles**, targeting
Go 1.27. This is an unreleased implementation, not a turnkey provisioning backend,
verified release, native adapter, or completion of the wider SCIM unit.

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

## Transport and integration

`Request`/`Response` do not depend on `net/http`. Transport composition owns actual
routes, raw/decoded streaming limits, TLS, header parsing, deadlines and writing
`*Error` with its `StatusCode()` and `application/scim+json`. It must expose no
Groups routes for a Users-only composition, or Users routes for a Groups-only
composition. No selected service exposes Bulk/connection-management routes.
The combined service dispatches Group operations only to GroupStore/GroupMapper
and User operations only to Store/Mapper. Combined root search remains a later
integration obligation and fails closed rather than returning a User-only
subset. No HTTP server,
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
