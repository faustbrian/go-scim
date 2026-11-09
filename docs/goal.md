# Goal: SCIM Users protocol-service profile

The current implementation assignment supersedes the earlier planning-only
exclusion of source/runtime APIs for one finite, storage-neutral Users profile.
It does not make the module released, fully verified, durably provisioned or
complete the wider SCIM/identity platform goal.

## Current assignment

Implement accurate Users-profile discovery, authenticated/authorized
connection-scoped User create/get/replace/PATCH/list/search/delete and subsequent
absence through `UsersService.Execute`. Preserve schema and returned/mutability
rules, required ETags, bounded deterministic queries, atomic PATCH intent and
redacted typed RFC errors. Disabled Groups, Bulk and password changes must not
be advertised or silently accepted.

[Profile decisions](users-profile.md) document the exact supported schema,
configuration and store/authority obligations. Boundary doubles prove protocol
behavior only, not real identity/organization authority, connection bearer
validation, database transactions, durable replay or provisioning effects.

## Full goal retained

The complete SCIM goal remains the preserved coordination specification at
`.ai/identity-platform/goals/scim.md`, interpreted under the latest active
identity implementation goal rather than retired validator procedures. It
retains Users/Groups, filters, sorting, pagination, PATCH, Bulk, connection
lifecycle, independent-client conformance and final release qualification.

The full platform denominator remains 67 units. Root SCIM depends on committed
identity/organization contracts, not completion of every SSO protocol.
`scim/organization` mapping is separately owned and additionally depends on SSO
synchronization authority. `scim/postgres` separately depends on that mapper;
this protocol profile does not bypass that dependency or close M28.

## Delivery boundary

Root inventory, registration, workspace/tool/CI changes, native adapters,
independent final review, integration and Git delivery are parent-owned. Existing
planning/release metadata is not changed here. Runtime source, passing protocol
tests or a future registration change must not be described as whole-unit
verification, installable released behavior or durable consumer provisioning.
