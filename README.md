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
`go-library-tools` v2.1.2 release declared in `.golib.yaml`.

[Security planning](docs/security.md) identifies the intended trust boundaries
and release prerequisites. Report suspected vulnerabilities through the
[private reporting process](SECURITY.md), not a public issue.

Passing repository checks proves only that the planning scaffold and metadata
are internally consistent. It does not prove any SCIM behavior or API.

Use the checksum-verified public `golib` v2.1.2 release declared in
`.golib.yaml`, with Go 1.27.2 as the verification producer. The planned module's
minimum remains Go 1.27.0; no runtime package or release is introduced.
An ordinary standalone checkout is sufficient, without sibling repositories,
goal ledgers or building Tools from source:

```sh
make check
make ci
```

Both routes, and the `make fast-check` alias, check configuration, repository
structure, cohesion, offline specification decisions, local documentation links
and unconditional whole-tree secrets. They run no application tests, mutation
campaigns or release checks. Hosted Required applies the same structural checks
and scans committed changed content against the exact validated PR base or push
before commit, without a fallback base or a duplicate full-history scan.
Missing or invalid change identities and failed checks remain failures.
The changed-content scanner has a fatal 75-second deadline and five-second
termination grace, allowing bounded cold compilation without skipping scans.

`make check-full` optionally preserves the previous full manifest-selected
contract, including broad spelling and external-link documentation assurance.
It is not an ordinary CI prerequisite and does not establish runtime or release
qualification for this planned module.

`make check-online` explicitly adds authoritative specification refresh to the
local contract. Scheduled and manual CI also refresh those authorities online
and run whole-tree secrets. Passing any of these planning routes is not runtime
security or release qualification.

See the versioned [Golib ecosystem index](https://github.com/faustbrian/go-library-tools/blob/v1.4.0/docs/ecosystem/README.md)
and [package-family guidance](https://github.com/faustbrian/go-library-tools/blob/v1.4.0/docs/ecosystem/design-language.md#package-families-and-selection)
for the shared design language.

## License

MIT. See [LICENSE](LICENSE).
