# Changelog

## Unreleased

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
