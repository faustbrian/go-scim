# go-scim

Storage-neutral, HTTP-independent SCIM 2.0 **Users protocol profile**, targeting
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

Groups, Bulk, password/credential writes and connection lifecycle operations are
not implemented. Groups are absent from ResourceTypes; ServiceProviderConfig
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
Groups/Bulk/connection-management routes for this profile. No HTTP server,
background goroutine, environment lookup, database, network client or global
registration is started by this package.

Root SCIM consumes identity and organization types; it does not depend on all
SSO implementations. Native `scim/organization` mapping and `scim/postgres`
persistence remain separate units. The latter additionally depends on the former;
this protocol profile does not unlock or verify that adapter. The full platform
scope remains 67 units, and this profile alone does not close M28.

[Security boundaries](docs/security.md), the [repository goal](docs/goal.md), and
[private vulnerability reporting](SECURITY.md) describe the remaining integration
and qualification boundaries. Parent-owned inventory and release state are not
changed by this implementation.

## License

MIT. See [LICENSE](LICENSE).
