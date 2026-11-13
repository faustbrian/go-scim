# Goal: SCIM Users and Groups protocol-service profiles

[Documentation index](README.md) · [Repository entry](../README.md)

The current implementation assignment supersedes the earlier planning-only
exclusion of source/runtime APIs for finite, storage-neutral Users and Groups profiles.
It does not make the module released, fully verified, durably provisioned or
complete the wider SCIM/identity platform goal.

## Current assignment

Implement accurate Users-profile discovery, authenticated/authorized
connection-scoped User create/get/replace/PATCH/list/search/delete and subsequent
absence through `UsersService.Execute`. Preserve schema and returned/mutability
rules, required ETags, bounded deterministic queries, atomic PATCH intent and
redacted typed RFC errors. The additive Groups service provides the corresponding
Group operations and `Groups/.search` through explicit `GroupStore`/`GroupMapper`
boundaries, preserving Users-only compatibility. Unsupported resource types,
Bulk and password changes must not
be advertised or silently accepted.

The additive combined profile selects both existing typed resource owners under
one authority/effective-limit configuration, exposing their complete shared
discovery and original User/Group operations through one public Execute surface.
Conflicting schema identities and impossible combined-response limits fail
construction. Root search additionally requires one explicit RootSnapshotter
owning a complete bounded mixed-resource transaction or immutable snapshot;
selecting separate stores alone does not supply that consistency. Unselected
configurations retain 501; no native adapter or provisioning claim is added.

[Users decisions](users-profile.md) and [Groups decisions](groups-profile.md) document the exact supported schemas,
configuration and store/authority obligations. Boundary doubles prove protocol
behavior only, not real identity/organization authority, connection bearer
validation, database transactions, durable replay or provisioning effects.

## Selected native configured Users profile

The optional [PostgreSQL module](../postgres/README.md) supplies one configured
active User create and scoped read path. It owns its connection/resource
projections, not identity tables, transaction outcomes or replacement authority.
Install its forward schema together with the genuine identity, organization,
authorization, audit and outbox owners. Native create keeps the kernel user,
projection, command result, audit and outbox effects atomic. Headerless creates
remain supported; optional keyed retries preserve original server metadata.

This selected profile does not advertise discovery, listing, User mutation or
deletion, Groups, Bulk, organization reconciliation, SSO synchronization or
HTTP routes. Its trusted create-only configured bootstrap is not the public
connection-management lifecycle. Those remain required full-goal work.

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
these protocol profiles bypass neither dependency and close neither M28 nor M29.

## Delivery boundary

Root inventory, registration, workspace/tool/CI changes, native adapters,
independent final review, integration and Git delivery are parent-owned. Existing
planning/release metadata is not changed here. Runtime source, passing protocol
tests or a future registration change must not be described as whole-unit
verification, installable released behavior or durable consumer provisioning.

Choose the next guide in the [documentation index](README.md)
or return to the [repository entry](../README.md) for installation and ownership.
