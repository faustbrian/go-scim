# SCIM threat model

[Documentation index](../README.md) · [Repository entry](../../README.md)

Version: 2 (Users protocol boundary, 2026-11-02)
Status: unreleased Users protocol implementation; native authority, persistence,
transport and full-unit qualification remain unverified.
Owner: go-scim maintainers. Review before release,
and whenever the protocol surface, connection lifecycle, or trust boundary
changes.

## Scope and assets

The implemented profile owns Users protocol behavior. The complete goal also
assigns it the public lifecycle of organization/provider-owned provisioning
connections; that lifecycle is not implemented in this profile. It does not own HTTP
transport deployment, tenant policy, organization mapping, persistence,
identity-provider clients, user interfaces, or database transactions. Adapters
and applications remain responsible for those boundaries, but a core API must
make their security obligations explicit and fail closed when they are absent.

Full-goal assets include bearer credentials and their digests, tenant/organization and
provider identifiers, Users and Groups, memberships, external IDs, bulk
checkpoints, resource versions, audit events, and operational metadata.
Attackers may control requests, headers, bearer tokens, resource attributes,
filter and PATCH paths, Bulk references and order, pagination/sort parameters,
provider responses, callback results, and replay timing. A malicious or
compromised dependency, CI action, release artifact, or maintainer credential
is a separate supply-chain threat.

## Implemented boundary and remaining owners

The protocol service rejects ambiguous JSON before authorization/mapping/store
access, bounds expressions/resources, validates declared schema policies and
returns no partial result on budget failure. Raw credentials must pass the
configured Authenticator; requests cannot select a principal or connection scope.
PATCH builds one candidate; Store owns its actual CAS/authority/uniqueness fence.
Arbitrary commit failures remain unknown, never asserted to have rolled back.

Groups, Bulk, credential writes and connection lifecycle are disabled. Native
identity/organization effects, token custody and durable replay/audit remain
separate trusted-owner obligations. The table retains the complete goal's
requirements; it is not a claim that every listed control exists here.

## Trust boundaries and required controls

| Boundary | Threat | Required design evidence before release |
| --- | --- | --- |
| HTTP transport to protocol decoder | Oversized, compressed, malformed, duplicate-key or case-colliding JSON; request smuggling or parser differentials | Enforce distinct raw, decoded, child, and response byte bounds; reject unsupported encodings and ambiguous members before mapping or mutation; compare with RFC fixtures and independent clients |
| Protocol expressions to query/store adapter | Filter or path complexity, regex-like denial of service, injection, traversal through extension paths, unbounded scans | Bound bytes, tokens, depth, nodes, result count and work; typed AST and parameterized adapter contract; reject resource-budget failures without partial results |
| Caller policy to resource and connection operations | Authentication bypass, cross-tenant access, confused deputy, enumeration through errors or filters | Explicit authenticator and authorizer decisions; organization/provider scope on every token, resource, lookup, Bulk reference and audit event; fail-closed tests |
| Credential issuance to storage and observability | Token reuse, timing leak, secret exposure in errors, logs, traces, metrics, fixtures or CI artifacts | Reveal once, store digests, constant-time sensitive comparison, expiry and rotation/revocation semantics; redaction at every output seam |
| Resource mutation to durable adapter | Lost updates, partial PATCH, inconsistent list snapshots, duplicate external-ID takeover | ETag preconditions, atomic PATCH, authoritative IDs, schema-aware comparisons, transaction ownership, stable sorting and snapshot-consistent totals |
| Bulk admission to execution/recovery | Cycles, cross-connection references, replay mismatch, duplicate or skipped children reported as committed | Bound complete dependency graph before mutation; durable child outcomes, deterministic ordering, exact scoped fingerprint, independent/atomic commit rules and explicit unknown outcomes |
| Connection deletion/reconciliation | Token remains active, pending work mutates after deletion, premature terminal status | Disable local authority first; coordinate pending Bulk/provider cleanup; preserve pending or unknown outcome until reconciliation closes; bounded cancellation and retry ownership |
| Dependencies, automation and release | Dependency or maintainer compromise, leaked secrets, tampered actions/artifacts | Review pinned dependencies/actions, secret and vulnerability scans, least-privilege workflow permissions, immutable release evidence and private advisory process |

No implicit network, filesystem, process, environment, database, cache, queue,
or background-goroutine access belongs in the core. Any future adapter that
crosses one of those boundaries must declare caller-owned configuration,
deadlines, limits, cancellation, cleanup, and independent verification. URL,
proxy, redirect, and DNS policy for any remote adapter must be caller-controlled
and SSRF-aware; archive and filesystem adapters, if ever introduced, need path
and symlink-escape controls. Custom cryptography is out of scope.

## Decisions and residual risk

No runtime risk is accepted by this document. Protocol tests use trusted
boundary doubles and do not establish real authority, durable atomicity or
provisioning. Scanner, interoperability and deployment evidence are not supplied
by that test fixture. Remaining full-goal controls stay unverified. The repository owner keeps release blocked until the affected
implementation has focused hostile-input and failure-path tests, selected
security scans, review of data exposure surfaces, and an explicit per-module
verdict. Any future accepted risk must record its owner, rationale, mitigation,
evidence, and review condition; critical and high findings cannot receive a
passing release verdict.

Choose the next guide in the [documentation index](../README.md)
or return to the [repository entry](../../README.md) for installation and ownership.
