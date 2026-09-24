# Goal: planned go-scim boundary

Status: planned

The coordination plan identifies `github.com/faustbrian/go-scim` as the future
owner of SCIM 2.0 discovery, Users and Groups, search, filtering, sorting,
pagination, PATCH, Bulk, ETags, typed protocol errors, and
organization/provider-owned connection lifecycle.

The source planning record is `.ai/identity-platform/goals/scim.md` in the
Golib coordination tree, with SHA-256
`f1265e043145851798a3cff7cffd34d1226e94100fee3101dcf2bf2c1e8d9eb8`.
That record contains proposed contracts; it is not implementation evidence.

## Current planning acceptance

- Keep this repository visibly planned and absent from installable consumer
  catalogs, with `releasable: false` and release delivery blocked.
- Record the frozen Protocols and Descriptions family, secondary capabilities,
  ownership, and delivery lifecycle in schema-v2 engineering metadata.
- Maintain a versioned SCIM threat model and private vulnerability reporting
  process without representing planned controls as implemented safeguards.
- Validate the metadata locally and in hosted CI with immutable,
  checksum-verified `go-library-tools` v1.4.0 tooling.
- Do not claim a public package identifier, installation path, runtime API,
  compatibility promise, protocol conformance, or released behavior.

## Deferred implementation

Source packages, nested modules, dependencies, API contracts, RFC 7643 and RFC
7644 behavior, hardening evidence, compatibility commitments, tags, and
releases remain outside this planning-only goal. They require separately
authorized work and their own executable acceptance evidence. Before a release,
the proposed trust boundaries need implemented controls, focused hostile-input
and lifecycle evidence, security gate results, and a per-module verdict.
