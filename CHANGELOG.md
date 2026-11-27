# Changelog

## Unreleased

- Add explicit conditional GroupDelete admission after current bearer/operation
  authority and bounded target, strong If-Match, empty-body and query preflight,
  before command or Store effects. Preserve original canonical headerless and
  optional-key recovery, empty 204 replay, atomic conditional deletion, member
  isolation, unknown outcomes and original authority/disclosure fences;
  ordinary execution and sibling selections are unchanged.

- Add explicit conditional GroupPatch admission after current bearer/operation
  authority and existing bounded target, strong If-Match and Group PatchOp/schema
  preflight, before command, mapping or Store effects. Preserve the complete
  ordered patch, canonical Store command/replay, no-op metadata, exact-connection
  typed membership, atomic conditional writes and original authority/disclosure
  fences; ordinary execution and sibling selections are unchanged.

- Add explicit conditional GroupReplace admission after current bearer/operation
  authority and bounded target, strong If-Match, replacement/schema/member
  preflight, before command, mapping or Store effects. Preserve complete
  replacement semantics, canonical Store command/replay, exact-connection typed
  membership, atomic conditional writes, original deadlines and redacted
  disclosure/reentry fences; ordinary execution and sibling selections are
  unchanged.

- Add explicit GroupCreate admission after current bearer/operation authority
  and bounded Group/member preflight, before command, mapping or Store effects.
  Preserve canonical Store command/replay, exact-connection typed membership,
  atomic write authority, original deadlines and redacted disclosure/reentry
  fences; ordinary execution and sibling selections are unchanged.

- Add explicit GroupGet/GroupList admission after current bearer and operation
  authority, before GroupStore reads or projection. Reuse original deadlines,
  redacted denials, descendant-context reentry and final disclosure fencing;
  preserve Group query/version semantics, ordinary execution and User selections.

- Add explicit conditional UserReplace admission after current authority and
  existing bounded replacement/strong If-Match preflight, before command,
  mapping or resource effects. Preserve omitted-field replacement semantics,
  canonical Store command/replay, CAS and original authority/disclosure fences;
  ordinary execution and other operation selections are unchanged.

- Add explicit conditional UserPatch admission after current authority and
  existing bounded request, PatchOp and strong If-Match preflight, before
  command, mapping or resource effects. Preserve the complete patch, canonical
  Store command/replay, atomic CAS and original authority/disclosure fences;
  ordinary execution and other operation selections are unchanged.

- Add explicit conditional UserDelete admission after current authority and
  existing target/If-Match preflight, before command or receipt effects.
  Preserve Store-owned deletion, headerless replay and unknown outcomes;
  ordinary execution and other operation selections are unchanged.

- Add explicit UserCreate admission after existing request validation and current
  bearer/operation authority, before mapping or command effects. Retain canonical
  Store writes and replay, original deadlines and disclosure fencing; fail closed
  on denial, cancellation, expiry, panic and reentrant gate execution without
  changing ordinary Execute, admitted reads or sibling services.

- Add an explicit UserGet/UserList selection requiring a synchronous trusted
  gate after current bearer authentication and authorization, before resource
  I/O. Preserve original authority deadlines and final disclosure fencing;
  normalize redacted admission denials and bounded 429 retry metadata without
  changing ordinary execution, sibling services or enabling HTTP routes.

- Add immutable, credential-free managed connection records, canonical IDs,
  and bounded mapping paths and sets. The released authenticator `Connection`
  and available connection-management operations are unchanged.

- Add redacted, persistence-neutral Bulk request custody and authorized
  discovery rendering for an explicitly selected executor's effective limits.
  Support an after-authentication protocol rate decision and bounded 429
  retry metadata without changing the SCIM Error body shape.

- Suppress resource locations on Bulk errors for unsupported methods,
  without changing the planned dependencies or response-size bound.

- Expose the normalized, optional `scimType` from a protocol error without
  changing its JSON or exposing private diagnostics.

- Resolve request-local Bulk targets and schema-declared references using IDs
  from the native admission, including forward and cyclic references. Ordinary
  strings and the original request fingerprint input are unchanged.

- Preflight the worst-case Bulk response before native admission and serialize
  terminal child results in request order without exposing skipped children.
  Bulk execution and discovery remain disabled.

- Parse bounded Bulk requests into an immutable ordered child list and a
  deterministic dependency plan. This does not enable or advertise Bulk.

- Document the optional native Groups selection and its typed directory
  references, without changing root protocol APIs or default Users selection.

- Document the optional PostgreSQL adapter's configured discovery and complete
  Users CRUD/PATCH/query profile, with organization and global deprovisioning
  kept outside that selection. Root protocol APIs remain unchanged.

- Allow trusted durable preparation to retain replace/PATCH version and
  modification time while preserving resource identity, creation time and
  no-op PATCH metadata. Nil selection preserves existing generation.

### Fixed

- Run hosted verification on Go 1.27.4, matching the tested native adapter
  toolchain while preserving the public modules' Go 1.27.0 minimum.

- Accept the durable Store's original server command on fresh admission instead
  of requiring the protocol's unused proposal. Scope, operation, target,
  precondition, canonical request and lookup key remain exact; fresh connection
  observations cannot be substituted or renewed. This permits composition with
  the existing kernel idempotency allocator without another command journal.
- Accept optional retained server-only creation metadata from durable admission
  so keyed concurrent/recovery attempts preserve one original resource identity,
  version and timestamps. Validate it before mapping and keep the exact committed
  resource check; existing Stores without this selection retain their behavior.

- Apply primary validation, defaults, sorting and PATCH reassignment consistently
  to configured descriptor spellings, retaining canonical keys and omitted/false
  siblings without creating aliases or persisted comparison defaults.
- Compare omitted and explicit-false `primary` consistently in multi-valued
  element sets: reject supplied equivalents and retain original representation,
  version and modification time for existing-member PATCH additions and replay.
- Preserve valid username substring and empty-fragment predicates without
  weakening full RFC 8265 username admission or scoped uniqueness.
- Apply the full pinned RFC 8265 UsernameCaseMapped/Unicode 17 comparison policy
  to core usernames without rewriting source names or IDs. Expose a shared
  versioned uniqueness-key contract for Stores; existing indexes require
  explicit collision reconciliation and migration to adopt this policy.
- Compare empty strings lexically in relational filters while preserving
  sorting's unassigned placement and stable resource-ID tie-break.
- Treat omitted multi-valued `primary` as false in queries and PATCH selectors
  without fabricating missing collections or persisting client-unsupplied data.
- Validate PATCH operands before semantic equality or set-key construction,
  including bounded exact decimals outside the finite float64 range. Preserve
  partial immutable complex updates and Store-owned read-only descendants.
- Return supplied request-only attributes on write and replay responses, and
  retain minimum ancestors of always-returned descendants in projections.
- Reject binary ordering filters and missing logical-operator gaps; bound
  projection path counts before allocating split slots.
- Preserve complex PATCH siblings and immutable descendants; freeze selection
  before primary reassignment and reject ambiguous pathless aliases.
- Enforce snapshot/PATCH/output budgets before materialization and redact late
  state-dependent errors without changing actual commit outcomes.
- Canonicalize stored projection names, enforce binary/reference representations,
  compare schema-equivalent set/immutable values, and retain no-op timestamps.

### Added

- Add an optional PostgreSQL module for configured active SCIM User creation
  and scoped reads using the existing identity coordinator and current primary
  authority owners. Native user/projection, result, audit and outbox effects
  share one transaction. Other protocol and connection-management operations
  remain unselected; install the documented owner histories before activation.

- Opt-in combined root search through one explicit scoped User/Group snapshot
  owner, with schema-aware filtering, sorting, projection and exact bounded
  pagination. Existing combined configurations without that owner continue to
  return 501; existing single-resource APIs are unchanged. This extends the
  earlier combined composition without inferring a cross-type store snapshot.

- An additive combined User/Group protocol service with one shared authority
  and effective-limit configuration, truthful bounded discovery for both typed
  owners, immutable per-resource extensions and conflicting-schema rejection.
  Existing single-resource APIs are unchanged. Combined root search, Bulk and
  native provisioning remain unsupported by this selected composition.
- An additive storage-neutral Groups protocol profile with distinct GroupStore
  and GroupMapper contracts, matching discovery, Group CRUD/atomic PATCH and
  bounded filter/sort/page/search. Existing Users APIs remain User-specific.
- Bounded immutable typed Group members with local canonical references,
  duplicate-identity denial, explicit atomic same-connection existence fencing,
  and the existing strong-version, original-authority and replay/outcome rules.
  Native organization reconciliation and provisioning remain separate work.
- A storage-neutral SCIM 2.0 Users protocol-service profile with authenticated,
  authorized organization/provider scope, accurate discovery, create/read/replace,
  atomic PATCH intent, bounded deterministic list/search and delete/absence.
- Strong opaque ETags, mandatory mutation preconditions, typed redacted errors,
  schema/returned/mutability enforcement and explicit atomic store/replay contracts.
- Required original-read authority metadata with an exclusive twenty-second
  maximum, earliest contributing/token expiry and remaining-budget contexts;
  cached observations and retries cannot renew freshness. Expired responses are
  withheld without claiming rollback of a previously valid commit.
- Explicit rejection of disabled Groups, Bulk and password writes. Durable
  provisioning, connection lifecycle and native adapters remain separate work.
