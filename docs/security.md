# Security boundaries

[Documentation index](README.md) · [Repository entry](../README.md)

The unreleased Users and Groups protocol profiles have bounded decoding, schema validation,
fail-closed credential-to-connection/authorization seams, typed redacted errors,
ETag/CAS intent and an explicit atomic store contract. These are protocol controls,
not evidence of real token validation, database persistence or provisioning.
The [private reporting policy](../SECURITY.md) remains active.

The [threat model](security/threat-model.md) separates implemented protocol
boundaries from remaining owner obligations. Trusted test doubles do not verify
production authentication, current authority fencing, durable admission/replay,
audit, native organization mapping, connection lifecycle or HTTP ingress controls.
Groups use explicitly named mapping/storage contracts and local typed membership
references. The trusted GroupStore must atomically fence member existence and
resource type in the full connection scope; URI validation is not that authority.

Release remains blocked by parent-owned metadata and qualification. Independent
review, interoperability, concrete adapters, selected security checks and a
per-module verdict are still required before a release or full-unit claim.

Choose the next guide in the [documentation index](README.md)
or return to the [repository entry](../README.md) for installation and ownership.
