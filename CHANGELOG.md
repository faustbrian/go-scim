# Changelog

## Unreleased

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
