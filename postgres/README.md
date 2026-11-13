# Native SCIM configured Users

`github.com/faustbrian/go-scim/postgres` composes the public SCIM protocol with
the existing PostgreSQL identity, organization, authorization, audit and
transactional-outbox owners. It does not implement another identity engine,
transaction coordinator or command journal.

## Selected profile

The public service supports active `UserCreate` and exact scoped `UserGet`.
Configured tenant and connection IDs contain 1..64 ASCII letters, digits,
underscores or hyphens because the required native audit owner uses the exact
tenant in its context and the exact connection ID as its subject. Organization
and provider IDs retain their 128-byte bounds. The schema's 128-byte columns do
not widen this selected public profile.
`userName` is required; `displayName` is optional when its native field mapping
is configured. Both map through the actual identity `AttributeProcessor` into
the declared native attribute schema. `active:false` and other native field
profiles are not selected. SCIM `externalId` remains byte-exact, nonunique
connection correlation; it never selects or links an existing identity.

The service returns 501 for discovery, listing/search, replace/PATCH/delete,
Groups and Bulk rather than advertising unimplemented native capabilities.
Organization membership mapping, SSO synchronization, HTTP routing and native
connection lifecycle remain separate work. This profile is not complete SCIM
provisioning or whole-unit qualification.

## Composition

1. Borrow one **primary** `go-postgres` pool. Apply the existing owners' forward
   histories through the deployment's migrations runner: identity base plus
   request-key/prepared-input and explicit directory-authority schemas,
   organization plus credential authority,
   authorization scoped epochs, audit, root outbox and identity outbox binding.
   Append this module's `MigrationSource` at a permanently allocated version.
2. Configure an existing service-account principal and policy namespace through
   the authorization owner. Supply its real revision-fenced `authorization.Service`.
   Bootstrap never creates a principal, invents a grant or resets an epoch.
3. Configure an immutable identity `AttributeSchema` and `AttributeProcessor`
   using that same service/policy revision, stable normalization/value callbacks
   and exact native ID validation. Select its nonsecret scalar field names in
   `UserNameField` and optional `DisplayNameField`.
   `ConfigurationID` versions those borrowed callback semantics and must change
   when they change; old configuration identities are never silently re-enrolled.
4. Deliver a high-entropy bearer through the application's secret boundary and
   construct `NewConfiguredCredential`. Give `NewService` the resulting opaque
   credential, fixed tenant/organization/provider/connection, credential expiry,
   initial version one, exact `GlobalAuthorityID`, bounded policy/limits,
   coordinator/request-key configuration and a local secret-envelope keyring.
   Construction performs no IO or callbacks.
5. Explicitly call `InitializeConfiguredConnection`. It is create-only configured
   bootstrap, **not** `scim.ConnectionService`. An identical repeat returns the
   original command outcome; changed, inactive, revoked or deleted state denies.
6. Call the one `Execute` surface with ordinary `scim.Request` values. Consumers
   supply no domain stores, SQL glue, Boolean authority proofs or replay engine.

```go
credential, err := scimpostgres.NewConfiguredCredential(credentialID, bearer, lookupKey)
if err != nil { return err }
config.Credential = credential
service, err := scimpostgres.NewService(primary, config, localEnvelopeKeys)
if err != nil { return err }
initialized, err := service.InitializeConfiguredConnection(ctx)
if err != nil { return err } // inspect initialized.Outcome on ambiguity
_ = initialized
created, protocolError := service.Execute(ctx, scim.Request{
    Operation: scim.UserCreate,
    Credential: bearer,
    ContentType: "application/scim+json",
    IdempotencyKey: clientRetryKey, // optional; never server-generated for a caller
    Body: document,
})
if protocolError != nil { return protocolError }
_ = created // detached SCIM JSON, Location and ETag
```

These names refer to trusted deployment values, not an alternative application
implementation of authentication or persistence. The complete compiled native
consumer is in the integration tests and uses genuine owner schemas/adapters.

## Transaction and retry semantics

The configured bootstrap and each create use the existing kernel command journal
and one protected `Work`: native connection/projection, kernel user/attributes,
real audit record, lifecycle outbox notification and original result commit
atomically. The kernel owns command reservation, fencing, rollback and ambiguous
COMMIT reconciliation. The native effect's `command_id` is correlation, not a
second lease/outcome journal.

A supplied retry key is scoped by the native deployment namespace, exact
connection tuple, actor, tenant and operation. The existing kernel immutable
mapping retains authenticated encrypted original IDs/version/timestamps and
exact original authority observations; changed canonical input conflicts.
Matching retries cannot replace expired/changed original evidence for new
effects. Cancelling one transport does not tombstone an otherwise-valid original
observation. Known committed history separately requires genuine current
authority and can remain readable after the old observation expires.
Keep original lookup/fingerprint/envelope keys and callback configuration while
their records remain recoverable. Missing or incompatible historical custody
fails closed. Headerless creates use ordinary server-owned command/metadata
proposals and no pseudo-client key; a fresh retry is a new command and username
uniqueness still prevents a duplicate user.

## Authority and security

Bearer comparison is bounded, exact and keyed. No raw bearer is persisted or
returned. Configuration/service diagnostics and JSON do not expose key custody.
The 32..4096-byte RFC 6750 bearer bound and 128-byte credential ID bound are
local admission policy, not protocol mandates or proof of actual entropy.

Each request reads actual active connection/token, global/tenant directory state,
organization credential epoch and scoped authorization epoch. The original
earliest authoritative admission lasts no more than twenty seconds and never
extends token expiry. Earlier caller deadlines separately bound each invocation.
The native feature rechecks/fences these actual owners before effects and commit;
policy callbacks run before transactions, not under row locks. Organization
archive/restore and scoped epoch changes cannot revive an old configured token.
Permission-changing policy updates must advance the configured principal's
scoped epoch atomically through its existing authorization owner; changing a
callback alone cannot substitute for that lifecycle contract.
Get reads the real kernel user and rechecks current authority before disclosure.
An enabled directory-epoch bump does not by itself permanently revoke the
configured credential; it invalidates stale in-flight admission. Disabled
tenants deny new effects, reads and historical disclosure.

The service borrows its pool, field processor, policy and local keyring; it owns
no background goroutines and never closes borrowed resources. Keep dependencies
alive for all in-flight calls and stop admissions before retiring them. No
automatic migration, retry worker, synchronization or remote provider exists.

## Schema rollout and query boundaries

Install the optional schema before enabling the service. It creates only new
empty `scim` tables and indexes; it does not alter existing identity/organization
tables or backfill accounts. Deployment DDL requires bounded lock/statement
timeouts and normal migration ownership. Existing unmanaged schema collisions
fail; there is no destructive down migration or automatic adoption.

All resource/credential lookups use exact full connection scope and bounded
single-row primary-key queries. Username uniqueness uses the public SCIM
comparison owner, not database collation guesses. The complete canonical key is
retained, including admitted 4096-byte usernames. A nonunique index contains the
connection tuple and a 32-byte SHA-256 comparison digest so an admitted username
cannot exceed PostgreSQL's B-tree entry limit. A database check binds that digest
to the key's UTF-8 bytes; the lookup compares both digest and the complete key,
so different keys sharing a digest do not conflict.

The existing connection row is the synchronization owner for all supported
projection writers. Creates acquire it for update after directory, organization
and policy authority, then check exact scoped uniqueness before kernel creation
in the same READ COMMITTED Work. This deliberately serializes creates within one
connection; their existing context/transaction bounds still apply. Different
connections retain independent scope, and Get does not take this write lock.
Do not write projections directly or bypass this owner: the digest index is not
a unique constraint or an alternate equality policy. The initial schema uses
PostgreSQL's built-in `sha256(bytea)` and `convert_to(text,name)` without an
extension or a custom hashing function.

Stored resources are bounded to 128 KiB before persistence/decoding. Future
listing, extension and lifecycle profiles need their own owning contracts and
query evidence; this module supplies none implicitly.

## Verification

Use task-owned Go caches and a disposable loopback PostgreSQL cluster. Ordinary
unit/race/vet checks cover the public/codec boundaries; integration-tagged tests
require `SCIM_POSTGRES_TEST_DSN` selecting the explicit `scim_test` control
database and create/drop only their own isolated databases. They exercise
protocol create/get, original keyed replay, real atomic owners, authority
withdrawal, concurrent uniqueness, scoped credentials and a genuine dropped
COMMIT acknowledgement. Username regressions exercise the public maximum input,
the selected 64/128/128/64-byte scope, full-key persistence, casefold races and
exact-key discrimination inside a
synthetically shared digest bucket; the latter is not a claim to construct a
cryptographic SHA-256 collision. Separate raw-schema fixture inserts prove that
four 128-byte scope components and the full username fit the new index; they
do not demonstrate public provisioning at that unsupported scope. Fixtures are
not native organization/SSO provisioning.
