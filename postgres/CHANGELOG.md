# Changelog

## Unreleased

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
