# go-scim

> **Status: planned.** This repository does not currently provide an
> installable package, a released version, or a runtime API.

`go-scim` reserves the planned Golib boundary for SCIM 2.0 discovery, Users
and Groups, search, filtering, sorting, pagination, PATCH, Bulk, ETags, typed
protocol errors, and organization/provider-owned connection lifecycle. The
plan keeps protocol behavior separate from organization mapping, persistence,
identity provider integration, and user interfaces.

## Planned responsibility

The future root package is intended to own SCIM protocol resources and
operations, service-provider discovery, request and response validation,
protocol error representation, and connection bearer issuance, rotation, and
revocation. Its contracts remain proposals until they are implemented,
reviewed, verified, and released.

## Non-goals

The planned root boundary does not own:

- organization-specific attribute mapping or persistence adapters;
- single sign-on or personal and otherwise unowned SCIM connections;
- outbound vendor-directory connectors or administration interfaces; or
- database clients, migrations, transactions, caches, or background workers.

Those concerns may become separate modules or compose existing Golib packages.
Their presence in planning material does not make them available here.

## Lifecycle and ownership

Implementation, hardening, and release have not started. The current module
declaration exists only so repository tooling can validate the planned
identity, family, ownership, and lifecycle metadata. It is explicitly
non-releasable; release remains blocked until implementation and security
evidence exist.

The plan requires caller-owned configuration and runtime resources, copied
mutable inputs, context-bounded external operations, and no package-owned
background work. These are design constraints, not claims about released
behavior.

## Planning and verification

The [repository goal](docs/goal.md) and `modules.json` record the planning scope
and schema-v2 engineering inventory. Planned lifecycle state excludes this
module from installable and released consumer catalogs. The local
`make cohesion` target validates that boundary with the exact checksum-pinned
`go-library-tools` v1.4.0 release declared in `.golib.yaml`.

[Security planning](docs/security.md) identifies the intended trust boundaries
and release prerequisites. Report suspected vulnerabilities through the
[private reporting process](SECURITY.md), not a public issue.

Passing repository checks proves only that the planning scaffold and metadata
are internally consistent. It does not prove any SCIM behavior or API.

The prepared `make fast-check GOLIB=/path/to/golib` entry point checks
configuration, repository structure, cohesion, offline specification decisions,
local documentation links and secrets. It does not run application tests or
online documentation campaigns. This entry point requires a verifier supporting
`golib docs check --local` and `golib secrets check`; the currently declared
v1.4.0 verifier does not support it. CI and `make ci` retain their existing
contract until a capable published verifier is qualified and adopted. Do not
treat the prepared command as the current required CI route.

See the versioned [Golib ecosystem index](https://github.com/faustbrian/go-library-tools/blob/v1.4.0/docs/ecosystem/README.md)
and [package-family guidance](https://github.com/faustbrian/go-library-tools/blob/v1.4.0/docs/ecosystem/design-language.md#package-families-and-selection)
for the shared design language.

## License

MIT. See [LICENSE](LICENSE).
