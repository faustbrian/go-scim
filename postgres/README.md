# Native SCIM configured Users and Groups

`github.com/faustbrian/go-scim/postgres` composes the public SCIM protocol with
the existing PostgreSQL identity, organization, authorization, audit and
transactional-outbox owners. It does not implement another identity engine,
transaction coordinator or command journal.

## Selected profile

The public service composes authorized discovery and Users create, get, replace,
PATCH, delete, list and POST search with the root protocol's schema, filtering,
sorting, attribute projection and pagination semantics.
Configured tenant and connection IDs contain 1..64 ASCII letters, digits,
underscores or hyphens because the required native audit owner uses the exact
tenant in its context and the exact connection ID as its subject. Organization
and provider IDs retain their 128-byte bounds. The schema's 128-byte columns do
not widen this selected public profile.
`userName` is required; `displayName` is optional. Configured scalar mappings go
through the actual identity `AttributeProcessor` into the declared native schema.
An unconfigured display name remains SCIM projection data. Removing a configured
display name clears its native scalar to an explicit empty string; the configured
field policy must permit that empty value for removal. Other core
attributes, including names, emails and `active:false`, remain schema-validated
SCIM projection data. They do not create verified identifiers, suspend or restore
a global user, or change organization membership. SCIM `externalId` remains byte-exact, nonunique
connection correlation; it never selects or links an existing identity.

The original `Service` remains Users-only and returns 501 for Groups and Bulk.
The separately selected `GroupsService` exposes only Groups and their discovery;
it returns 501 for Users, combined root search, Bulk and connection lifecycle.
Organization membership mapping, SSO synchronization, HTTP routing and native
connection lifecycle remain separate work. DELETE removes only this connection's
SCIM projection; it does not delete the global kernel user. Credential/password
writes retain the root protocol's explicit unsupported decision. This selected
Users milestone is not organization provisioning or whole-unit qualification.

## Managed connection provisioning

Apply `ManagedConnectionsMigrationSource` alongside the native SCIM migrations.
Select `NewManagedConnectionService` with the native session and provisioning
composition. The administrator that creates a managed connection can receive
its bearer once; retry, Get and List return only the safe record. Keep the
bearer with the exact directory provider and use it with
`ExecuteManagedProvisioning` for User Create, Get, List and conditional Delete.

For managed bearer rotation, call `PrepareConnectionRotate` with the current
administrator authentication, connection ID and expected version, then retain
its opaque `identity.Command`. Pass that exact command and the same target and
version to `ConnectionRotate` with current administrator authentication. Neither
entry point accepts a client `Idempotency-Key`. Preparation retains the original
nonsecret input in the kernel's existing canonical POST mapping; it does not
withdraw or issue a bearer. The original authority deadline is not renewed by
retrying preparation.

Only an invocation that newly commits the rotation receives its successor
bearer. Keep it at the provider's secret boundary. The predecessor credential
is revoked with zero overlap in that same transaction, alongside the connection
version, protected audit and lifecycle outbox event. The result names the exact
previous credential and its `PreviousBearerRevoked` disposition. A same-command
retry or recovery after an unknown commit returns only the original connection
metadata and disposition, never a bearer. Rotation preserves existing Users,
organization membership contributions and mappings. It does not enroll or alter
configured version-one credentials, install HTTP routes, or enable other
connection lifecycle operations. No new SCIM migration is required; the existing
kernel request-key/prepared-input histories must already be installed.

For an explicit admitted read, select `ExecuteManagedAdmittedRead` with that
issued bearer, the exact tenant and a nonnil `scim.ProtocolAdmission` gate.
Only User Get and List are selected. The gate runs once after current native
bearer authentication and operation authorization, before resource I/O, and
receives the selected native service's configured service-account actor and
tenant. It receives no bearer material or request-selected identity. The root
protocol retains the remaining original authority and parent/request deadlines,
normalizes gate denials including bounded 429 retry metadata, and withholds
output after cancellation or expiry. The gate is borrowed synchronously, must
honor its context and retain no invocation or detached work. Ordinary managed
provisioning stays unchanged; this adds neither a quota engine nor HTTP routes,
search, discovery, Groups or writes to the admitted selection.

`ExecuteManagedAdmittedCreate` separately selects only User Create with the
issued managed bearer, exact tenant and required `scim.ProtocolAdmission` gate.
Existing root request/schema validation and current native bearer/operation
authority precede its once-per-attempt gate, before mapping or command effects.
The gate receives only the selected native service's configured service-account
client and tenant. Denial, unavailability, cancellation or deadline expiry
produces no protected effect; a bounded positive quota wait retains its redacted
429 retry metadata. A later allowed attempt uses the same canonical native
write and original command/replay authority, rather than a new admission owner.
Root original deadlines and late-result disclosure fencing remain controlling.
The gate is synchronous and must honor its context, retain no invocation or
context and start no detached work. This adds no limiter, HTTP route, SQL or
migration, other selected operation, or change to ordinary managed provisioning
or admitted reads.

Managed Delete uses the connection's persisted `RemoveMembership` policy. The
same transaction tombstones the selected SCIM User resource and retires only
its current organization membership contribution. The last active directory
source can remove directory-owned membership and revoke its scoped authority;
local membership and other sources remain intact. This does not delete or
suspend the global user. The organization owner's directory membership migration
must be installed before selecting this profile. Other managed writes and HTTP
mounting are not included.

`ExecuteManagedAdmittedDelete` separately selects only conditional User Delete
with the issued bearer, exact tenant and a required `scim.ProtocolAdmission`
gate. Current native credential/operation authority and root target/strong
`If-Match` checks precede its once-per-attempt gate, before command or receipt
effects. The gate receives the exact configured native client, not a caller's
identity. Redacted quota denial retains its bounded positive retry delay and
performs no protected effect. Allowed deletion still uses the existing atomic
User tombstone and exact membership-source withdrawal; headerless retry returns
the original 204 without another write. Original deadlines and disclosure fences
remain controlling. The borrowed synchronous gate must honor its context and
retain no invocation/context or detached work. This selection adds no limiter,
SQL, migration, lifecycle, HTTP route or caller-key semantics, and ordinary
provisioning and admitted Create/read selections remain unchanged.

`ExecuteManagedAdmittedPatch` separately selects conditional User Patch with
the issued bearer, exact tenant and configured client. It rejects caller
request keys. Once current authority, strong `If-Match`, the bounded PatchOp
and the gate admit the call, the canonical scoped request selects one original
command. An equivalent retry returns the original resource and ETag without
another write. Different input with a stale ETag still fails the original CAS.
The underlying projection, audit, outbox and recovery retain their owners.

`NewGroupBulkService` explicitly selects Group Bulk **admission**. Apply the
kernel's `CanonicalSCIMBulkRequestMigrationSource` and this module's
`BulkAdmissionMigrationSource` before calling `Admit`. A bounded input and a
proved response byte ceiling are required before the request obtains custody.
The same protected transaction commits one parent, all allocated child IDs,
their exact dependencies and the planned component order, plus the admission
audit and outbox effect. Newly prepared admissions record
`identity.scim.bulk_admit`. Existing preparations retain their original
`identity.scim.bulk` action; retry does not rewrite or duplicate it. Upgrade
all processes sharing Group Bulk admission storage before accepting new
preparations: older binaries cannot resume the new preparation version.
A matching retry recovers the same parent and bound.
An optional key aliases that parent; using it for different input conflicts.
Admission itself executes no child and is not a Bulk response. Ordinary Users
and Groups, HTTP routing and discovery still do not enable Bulk.

`NewBulkService` explicitly selects mixed native Bulk on the same configured
connection. Use the same migrations as for Group Bulk and the existing native
Users migration. It accepts acyclic User creates, conditional replace/PATCH,
and conditional delete alongside the supported Group operations. Apply
`BulkGroupMutationMigrationSource` for either resource type before executing
mutations; the historical column name remains unchanged. A child referring
to a User by typed `bulkId` cannot run until the original User command commits.
Cycles containing Users remain unsupported. The Group-only constructor does
not accept a User operation. Select mixed Bulk only when every executor for
that connection can resume mixed requests.

Call `BulkService.ExecuteBulk(ctx, request)` to admit and drive the existing
native graph in dependency order within the configured request deadline. It
resumes from retained checkpoints and returns only the full, currently
authorized response in original request order. An interrupted call may have
committed earlier children; retry the same body and optional key rather than
constructing a new request. This is a native entry point, not a Bulk HTTP
route or discovery switch.

The applicable User record update, projection, child checkpoint, protected
audit and lifecycle effect commit together. A no-op PATCH keeps its original
ETag. DELETE tombstones only the connection-scoped SCIM projection, not the
identity record. An exact retry returns its original outcome despite later
projection changes. Missing targets and missing or stale preconditions retain
their original `404`, `428`, or `412`. A duplicate username retains `409` with
`scimType=uniqueness`. If a started acyclic child rolls back and its abort is
confirmed, the original child retains `503` and no successful projection or
lifecycle effect. A caller's unknown outcome gives no evidence of a child
failure. An exact retry of an aborted child reads its terminal result instead
of repeating the write. A dependent child retains `424` only after its
dependency is confirmed to have failed.

To retain the exact `scimType` of acyclic resource validation errors emitted
as `400` before Prepare, apply `BulkTypedValidationMigrationSource`'s expansion and
then use `service.WithTypedValidation()` on the connection's Group-only or
mixed Bulk service. Apply the constraint validation in a later migration;
there is no backfill. Upgrade every process that executes or reads this
connection's Bulk results before relying on typed results. Older readers
continue to read existing results, but return `503` rather than mislabel a
new typed result. The opt-in does not change admitted command identities,
enable HTTP or discovery, or put a reserved identifier on a failed create result.
The same profile settles malformed User and Group create declarations and
planner-invalid PATCH paths under the declared resource permission. A symbolic
PATCH still waits for its original predecessor; a confirmed predecessor
failure takes precedence over the PATCH validation error.

Unsupported child methods require only Bulk permission. They cannot mutate
the declared resource or include its Location in the result. A supported
symbolic target declaration still waits for its original predecessor:
confirmed failure retains `424`, otherwise a ready child retains
`400 invalidValue` unless cutoff skips it.

For transport integration, use the same `BulkService` as the owner of
`ExecuteBulkProtocol` and `ReadBulkServiceProviderConfig`. Each requires a
bounded admission gate, called once after native authentication and policy
and before either execution/replay or discovery output. The gate receives
the configured client and resource tenant, never the bearer. Its bounded
rate denial or outage returns no successful response. The consumer uses
`BulkPolicies` to apply the executor's actual transport limits. The
existing native entry points do not install transport routes or quotas.

Install the expansion from `BulkSnapshotValidationMigrationSource` before
using this profile with snapshot-dependent validation. A PATCH can retain
`noTarget` or `mutability` from its original prepared resource, without
running a write or changing the result on a later retry. The expansion adds
one finite denial code without backfilling checkpoints. Older readers keep
reading existing codes but reject the new result instead of mislabeling it.

Install `BulkChildExecutionMigrationSource` to call `ExecuteChild` with the
exact original request and a zero-based operation index. This selection runs
acyclic Group children in the retained dependency order. Install the further
`BulkGroupMutationMigrationSource` before sending Group replace, PATCH or
delete children; existing creates need no backfill. The usual Groups schema,
exact `If-Match` and permission rules apply. An unstarted child requires the
parent's original authority to remain live; retry does not renew it. The
replacement, PATCH or deletion uses its first encrypted Group snapshot even
if another writer later changes the Group. Projection, original kernel
journal, outbox, protected `identity.scim.bulk_apply_child` audit and result
checkpoint commit together. Replay returns the original 201 or 200 and ETag,
or the empty-version 204 for delete, to a caller currently authorized for the
exact operation and target. A no-op PATCH retains its original ETag. A stale
version denial records the original 412 even when the Group had already
changed before snapshot preparation. A missing target records 404; an omitted
`If-Match` records 428 without reading a Group projection. A definitive
protected denial records its result
and counts once, without a Group projection or success outbox event. At a
positive `failOnErrors` threshold, the failure transaction also skips every
remaining admitted child and appends one protected audit per skip. A skipped
child has no operation status, resource identity or version. For an acyclic
Group child, a predecessor without a known result retains a dependency block,
not an operation failure. Re-select the child when the predecessor settles.
A confirmed failed dependency retains 424 under the original child and counts
once. A successful resolution resumes the original child, or records an
audited skip if cutoff is already active. Unknown outcomes
do not count as failures; retry the same request and index to recover the
checkpoint when it is known. Call `ReadResult` with the exact original request
to read the complete response once all retained children have settled. The
read neither admits requests nor attaches retry keys. `scim.ErrBulkIncomplete`
means no terminal response is available; it returns no partial bytes. Calling
either member of a retained all-Group create cycle executes the whole cycle
atomically. It resolves the original final IDs before writing and checks the
within-cycle Group references before committing. An unresolved external
predecessor blocks the whole cycle without counting a failure. Re-select either
member after the predecessor settles: success resumes the whole cycle or
audits a skip for each member if cutoff is active. A confirmed predecessor
failure records an original 424 for each member, even after cutoff. A confirmed
member denial also records one 424 per member; any new cutoff takes effect
after the whole component is counted. An uncertain database or commit
acknowledgment returns no provisional result; retry the same request to read
settled checkpoints. If an older native writer recorded a denial without settling
its child checkpoint,
retry that child with `ExecuteChild`. Reconciliation uses current authority
and preserves the original denial and security audit. Other cyclic operations
and mixed User/Group execution remain unsupported.

## Composition

1. Borrow one **primary** `go-postgres` pool. Apply the existing owners' forward
   histories through the deployment's migrations runner: identity base plus
   request-key/prepared-input, canonical request-key aliases, user-status epochs
   and explicit directory-authority schemas,
   organization plus credential authority,
   authorization scoped epochs, audit, root outbox and identity outbox binding.
   Append this module's `MigrationSource` at a permanently allocated version,
   then `UsersMigrationSource` at a later permanent version before activating
   Users mutation support. Neither service construction nor bootstrap migrates.
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

### Explicit Groups selection

Append `GroupsMigrationSource{Base: usersHistory, Version: permanentGroupsVersion}`
after the installed Users history, using the same migration runner. This adds
one empty `scim.groups` table; it changes no identity, organization or existing
User data. Run it before routing any Groups operation to the new profile. The
older Users service remains usable without selecting or advertising Groups.

```go
groups, err := scimpostgres.NewGroupsService(service, scim.DefaultGroupMembers)
if err != nil { return err }
createdGroup, err := groups.Execute(ctx, scim.Request{
    Operation: scim.GroupCreate,
    Credential: bearer,
    ContentType: "application/scim+json",
    IdempotencyKey: clientRetryKey,
    Body: groupDocument,
})
if err != nil { return err }
_ = createdGroup
```

`maximumMembers` is explicit: zero allows only empty Groups; the reference
ceiling is 10,000, further constrained by the runtime's body/attribute budgets
and the native 128 KiB stored-resource ceiling. Group names and `externalId`
are not unique. Use a retry key to retain a Group creation: a repeated
headerless create is a new command and may create another Group with the same
name. Headerless Group DELETE uses the existing canonical command owner and
retains its original empty response independently of tombstone retention.

The root `GroupMapper` is pure representation. At commit, the native store
checks every exact member ID and declared User/Group type in the same complete
connection partition, under the same connection lock used by User and Group
writers. A URI is not existence proof. Missing, deleted, wrong-type or
cross-connection members deny the entire change with a redacted `invalidValue`
result retained by the kernel. No partial member update commits. Nested Groups
are references only: they are not traversed, remotely fetched or treated as
team/role/organization authority. Reference cycles are permitted; deleting a
Group changes no member or referring resource, so retained references can
become dangling. Group Get does not follow those references.

Group writes atomically commit only their projection/generation, real audit,
outbox and kernel result. They do not create a kernel user, change global user
status, reconcile organization membership or implement SSO synchronization.
Group PATCH no-op preserves the resource, ETag, time and generation while
recording its accepted audit/outbox; effective updates use exact native CAS.
Original success and failure replay, uncertain COMMIT handling and current
authority checks use the same owners as Users, not a Group outcome journal.

### Configured source evidence for SSO

`GroupsService.ObserveDirectorySource` is a trusted composition read for the
exact installed connection. The returned evidence does not authorize a sync.
Add its `Field` to the original SSO team-membership child command, then use
`RequireDirectorySource` in Apply and `RequireDirectorySourceAtCommit` from
the registered owner's final check after verifying the original command.
Both checks borrow the existing identity Work and retain the original
deadline. A different connection cannot supply evidence even when it uses
the same service account. This API does not commit, start generations, map
groups, or imply any permission to mutate organization memberships.

For a direct Group-to-User change, also bind `DirectoryGroupEdge.Field`
to the child. Use `RequireDirectoryGroupEdge` and
`RequireDirectoryGroupEdgeAtCommit` in place of the source-only fences.
They retain the same original source authority and connection writer lock,
require a known scoped Group and User, and require the stored User projection
to identify the child target. Adds require an exact live edge; withdrawals
accept explicit absence or a retained Group tombstone. The API does not
traverse nested groups or write a membership or cursor.

The User deprovisioning child instead binds `DirectoryUserDeprovisionEvidence`
and uses `RequireDirectoryUserDeprovision` and its final check. A live User
must be explicitly inactive at the selected revision. A deleted User must
have the retained tombstone for the exact delete revision. Both require the
source's stored local target, the original connection evidence and the
registered User child. These checks do not select a disposition, mutate
membership, or suspend an identity. SCIM User CRUD alone retains its
existing projection-only behavior.

When the selected SSO child also changes directory-owned organization
membership, bind `DirectoryUserMembershipEvidence.Field` to the original
command. An explicitly active revision uses the User admission operation;
explicit inactivity or a retained delete tombstone uses deprovisioning.
`LockDirectoryUserMembership` holds the existing directory authority,
organization and SCIM connection locks in that order and verifies the exact
stored User before returning the lock to the organization writer. Propagate
errors. Recheck the organization effect and call
`RequireDirectoryUserMembershipAtCommit` during the original final phase.
It recognizes only that Work's own organization successor and never extends
the source observation lifetime. Group fences and standalone User CRUD stay
unchanged. The caller owns admission policy, generation and command recovery.

To carry authority into the next child of the same admitted batch, install
the organization's `DirectoryMembershipSuccessorMigrationSource` and record
the successor in the original User Work. After authorized kernel receipt
recovery, pass the original sealed observation, exact User resource and
receipt to `AdvanceDirectorySourceAfterUserCommit`. Only the organization
version changes. The source, actor, connection, other epochs and all original
times stay unchanged. The next child's existing Apply and final fences still
check live authority. This API does not authorize replay of a historical
prefix or renew an expired observation.

### Explicit directory role source

For opt-in team-role permission checks, first take a current
`ObserveDirectorySource` and pass it to `ReadDirectoryGroupRoleEdges`.
The batch verifies up to 128 direct Group/User edges, exact stored local
identity mappings and the original connection in a single primary
statement. An absent edge, deleted projection, mapping mismatch, or
explicitly inactive User is not eligible. Unknown source state, corrupt
storage, or expired evidence returns no usable results. Keep the original
validity bound and do not cache results. This is not an SSO provider or
mapping-policy decision.

For drift inspection, `ReadDirectoryGroupEdgeStates` uses the same bounded
primary read but distinguishes a proven absence from a missing projection or
changed identity link. A still-present edge to an inactive or deleted User is
reported separately, not treated as automatic removal authority. The legacy
role query still returns true only for a live exact edge to an active User.

`ReadDirectoryUserStates` reads up to 128 mapped source Users in one snapshot
under the original observation. It returns explicit active, inactive or
retained-deletion states with exact revisions. A missing or changed mapping
or an omitted activity flag returns an unproven entry, never a reason to
withdraw a local grant. A failed read returns no usable report.

For a role-bearing child, bind the original source, Group edge and exact
organization grant/role fields. `LockDirectoryGroupRole` orders the
directory, organization and source checks before the organization's role
update. Keep the original lock for `RequireDirectoryGroupRoleAtCommit`
after rechecking the organization effect. It accepts only this Work's
organization successor, not refreshed or guessed source authority. No
route, scheduler, cursor or audit owner is added; ordinary Group
reconciliation keeps its original behavior.

To continue a mixed batch after role Work commits, install the organization's
role successor migration and record the transition in that original Work.
`AdvanceDirectorySourceAfterRoleCommit` then preserves the original SCIM
seal and deadline while carrying only the exact committed organization version.
After restart, `ValidateDirectorySourceSuccessorPrefix` compares the complete
ordered User and role prefix against the already-observed configured source.
A stale seal is rejected even when the prefix later became current, and
the next child still checks live authority in Work.

## Transaction and retry semantics

The configured bootstrap and every write use the existing kernel command journal
and one protected `Work`: native connection/projection, selected kernel user/attribute effects,
real audit record, lifecycle outbox notification and original result commit
atomically. The kernel owns command reservation, fencing, rollback and ambiguous
COMMIT reconciliation. The native effect's `command_id` is correlation, not a
second lease/outcome journal. Effective replace/PATCH uses the kernel's typed
attribute CAS with its original core version. The SCIM ETag, private projection
generation and core user version are separate values. An exact no-op PATCH
preserves all three and modification time, while still recording its accepted
command, audit and notification. A projection-only update performs no fake core
mutation. Target security uses the real user-status authority epoch, not the
aggregate core version.

A supplied retry key is scoped by the native deployment namespace, exact
connection tuple, actor, tenant and operation. The existing kernel immutable
mapping retains authenticated encrypted original IDs/version/timestamps, the
pre-mutation projection and its independent core/security/generation observations,
exact original authority observations; changed canonical input conflicts.
Matching retries cannot replace expired/changed original evidence for new
effects. Cancelling one transport does not tombstone an otherwise-valid original
observation. Known committed history separately requires genuine current
authority and can remain readable after the old observation expires.
Keep original lookup/fingerprint/envelope keys and callback configuration while
their records remain recoverable. Missing or incompatible historical custody
fails closed. Immutable original preparation plus the authoritative committed
receipt reconstructs the original response after later writes or deletion;
current projection data is not a result-history journal.
Headerless creates, replacements and PATCH use ordinary server-owned command/metadata
proposals and no pseudo-client key; a fresh retry is a new command and username
uniqueness still prevents a duplicate user. DELETE always resolves its scoped
operation/target/If-Match selector through the existing kernel canonical owner.
An optional late retry key aliases that same immutable original command. Changed
full input conflicts rather than allocating another command for the same selector.
Its original empty response survives scoped tombstone expiry; historical ACKs
still require genuine current authority and active kernel target eligibility.

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
Get and complete query snapshots read the real kernel user and recheck current
authority before disclosure. A SCIM inactive flag does not make a globally
inactive kernel user readable or writable.
An enabled directory-epoch bump does not by itself permanently revoke the
configured credential; it invalidates stale in-flight admission. Disabled
tenants deny new effects, reads and historical disclosure.

The service borrows its pool, field processor, policy and local keyring; it owns
no background goroutines and never closes borrowed resources. Keep dependencies
alive for all in-flight calls and stop admissions before retiring them. No
automatic migration, retry worker, synchronization or remote provider exists.

## Schema rollout and query boundaries

Install the optional schema before enabling the service. It creates only new
empty `scim` tables and indexes; it does not alter authoritative identity/organization
tables or backfill accounts. The Users successor adds constant-default
`generation` and nullable `deleted_at` metadata to existing projections without
a payload backfill. Its five-second lock timeout fails contended installation
instead of queueing traffic indefinitely. Install it before activating the new
binary; normal migration ownership controls retries. Deployment DDL requires bounded lock/statement
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
projection writers. Writes acquire it for update after directory, organization
and policy authority, then check exact scoped uniqueness before kernel creation
in the same READ COMMITTED Work. This deliberately serializes writers within one
connection; their existing context/transaction bounds still apply. Different
connections retain independent scope, and Get does not take this write lock.
Do not write projections directly or bypass this owner: the digest index is not
a unique constraint or an alternate equality policy. The initial schema uses
PostgreSQL's built-in `sha256(bytea)` and `convert_to(text,name)` without an
extension or a custom hashing function.

Stored resources are bounded to 128 KiB before persistence/decoding.
Request/body/query admission remains with the root protocol's
configured limits; multiple bounded PATCH operations may exceed the separate
final stored-resource budget without exceeding the request budget. Reads exclude
scoped tombstones. DELETE clears the live resource and correlation values;
an older binary cannot decode the cleared payload and therefore fails closed
instead of resurrecting it. No destructive down migration is provided.

List/search uses the root protocol's complete bounded fallback, not a second SQL
filter engine. A read-only repeatable-read transaction preflights resource/byte
budgets before decoding and returns one complete scoped snapshot. Users also
check actual kernel eligibility; Groups never infer a kernel identity from a
Group ID. Exhaustion denies the whole query, even `count=0`; it never
returns a partial total. These budgets bound materialized live resources, not
rows examined: retained tombstones can require broad index or table scans.
Deployments must choose budgets and retention appropriate to their connection
size and keep request timeouts bounded. Larger server-side query
profiles and extensions require their own explicit owning contracts.

## Verification

Use task-owned Go caches and a disposable loopback PostgreSQL cluster. Ordinary
unit/race/vet checks cover the public/codec boundaries; integration-tagged tests
require `SCIM_POSTGRES_TEST_DSN` selecting the explicit `scim_test` control
database and create/drop only their own isolated databases. They exercise
discovery, complete Users CRUD/query semantics, retained success and terminal
409/412 replay, real atomic owners, authority withdrawal, concurrent ETag writers,
scoped credentials and genuine dropped reservation/domain COMMIT acknowledgements.
No-op tests assert unchanged core/projection versions and ETag/time together with
actual audit/outbox persistence; a concurrent canonical DELETE must still finish.
The populated forward migration test holds an actual reader lock, observes the
configured timeout, then verifies preserved data after successful installation.
Username regressions exercise the public maximum input,
the selected 64/128/128/64-byte scope, full-key persistence, casefold races and
exact-key discrimination inside a
synthetically shared digest bucket; the latter is not a claim to construct a
cryptographic SHA-256 collision. Separate raw-schema fixture inserts prove that
four 128-byte scope components and the full username fit the new index; they
do not demonstrate public provisioning at that unsupported scope. Fixtures are
not native organization/SSO provisioning.
