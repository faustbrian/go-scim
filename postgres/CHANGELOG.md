# Changelog

## Unreleased

- Retain definitive native Group Bulk child denials without applying the Group.
  At the configured error threshold, skip remaining admitted children and
  append one protected audit per skip in the same transaction. Ambiguous
  outcomes remain retryable; Bulk HTTP and discovery stay disabled.

- Record protected `identity.scim.bulk_admit` events for newly prepared Group
  Bulk admissions. Existing preparations and requests retain their original
  event and retry behavior without re-emitting it.

- Execute and recover an admitted acyclic Group create using its original
  authorization and IDs. Commit its ordinary Group projection and typed
  result checkpoint together. Routing and discovery remain unchanged.

- Add explicit native Group Bulk admission. Prove the response ceiling before
  retaining one parent and every ordered child and dependency together. Exact
  retries recover the original admission. This does not execute children or
  enable Bulk in HTTP or discovery.

- Carry the exact original role transition across a sealed directory batch
  and reject recovered prefixes that do not match the current sealed owner.

- Carry the exact organization version committed by a directory User child
  into the next sealed source observation without renewing any original
  evidence or bypassing the next child's authorization fences.

- Expose bounded exact Group edge states for drift inspection. Distinguish
  proven absence, an inactive User and an unproven link while preserving the
  existing boolean role-eligibility API.

- Read exact current Group role edges in an ordered bounded primary batch
  and compose role-bearing Work with its own organization successor.
  Existing Group and User reconciliation remains unchanged.

- Fence SCIM User admission and withdrawal in the same transaction as the
  organization effect. Final source checks accept only that command's own
  organization successor and retain the original authority deadline.

- Fence the exact revision of an inactive or deleted SCIM User in the
  original SSO deprovisioning child's Work. A different identity, source
  revision, or later reactivation cannot authorize withdrawal.

- Fence the exact SCIM Group/User edge during the original SSO child write
  and final commit. Require the scoped User projection to identify the
  target. Withdrawal can use retained tombstones; unknown Groups and
  inferred or nested membership cannot authorize a change.

- Bind configured SCIM source evidence to the exact original SSO child
  command. Recheck the same organization, connection and expiry in native
  Work before changes and at final commit; no synchronization authority is
  inferred from a valid connection.

- Add an explicitly selected native Groups profile with authenticated discovery,
  complete CRUD/filter/search/pagination, atomic typed same-connection member
  validation, ETag/no-op/CAS and retained original retries through the existing
  kernel journal. Install the additive Groups migration before activation.
  Existing Users selection stays unchanged; Groups are projections/references,
  not authoritative teams, roles, identity creation or organization reconciliation.
- Add authorized native discovery and complete scoped Users CRUD, filtering,
  search and pagination over the existing protocol and PostgreSQL owners.
  Install the forward Users metadata migration and the kernel status/canonical
  request histories before activation. Updates use actual kernel attribute CAS;
  no-op PATCH preserves versions/time, and canonical DELETE retains its original
  empty response without deleting the global user. Core names/emails/active
  remain SCIM projection data, not verified identifiers or global deprovisioning.
- Preserve original uniqueness and ETag failures on exact retries, including
  after later resource changes or deletion, through the existing kernel journal.

- Complete the Linux/amd64 native dependency manifest and verified checksums
  without changing selected dependency versions.
- Preserve complete admitted usernames without PostgreSQL B-tree size failures;
  checked digest lookups retain exact canonical equality, with creates serialized
  through their existing connection row.
- Reject configured tenant and connection IDs outside the existing 1..64-byte
  ASCII letter/digit/underscore/hyphen audit profile before bootstrap; organization
  and provider IDs remain bounded to 128 bytes and admitted usernames to 4096 bytes.
- Add the optional native configured-connection SCIM active UserCreate/UserGet
  profile, using existing kernel, organization, authorization, audit and outbox
  owners for atomic provisioning and retained keyed command outcomes.
- Require explicit forward schema installation and trusted configured bootstrap;
  no existing connection rotation/reactivation, broader SCIM lifecycle, group,
  organization-membership, synchronization or HTTP profile is enabled.
