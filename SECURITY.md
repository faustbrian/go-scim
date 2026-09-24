# Security Policy

## Supported versions

There is no importable package or published version. No version is currently
supported for runtime use. This repository is planning-only and its module is
not releasable. Supported version ranges will be stated here when a release is
actually published.

## Private reporting

Use [GitHub private vulnerability reporting](https://github.com/faustbrian/go-scim/security/advisories/new)
for suspected vulnerabilities or security-sensitive design flaws. Do not open
a public issue or include credentials, personal data, production payloads, or
exploit-enabling details in public artifacts. A report should identify the
affected repository and revision or version, expected and observed behavior,
impact, a minimal safe reproduction, and any known mitigation.

## Handling and disclosure

Maintainers will acknowledge the report privately, assess severity and affected
revisions or versions, assign an owner, and coordinate remediation and
disclosure with the reporter. The target acknowledgement is one business day
for critical, two for high, five for medium, and ten for low severity; these
are targets, not a promise of a fixed release date. Critical or high impact
blocks an affected release. Any accepted lower-severity risk requires an owner,
rationale, mitigation, and review condition.

The maintainer and reporter should agree on an embargo sufficient for a
focused fix, regression evidence, and a coordinated advisory. If a released
module is affected, the advisory should identify exact affected and fixed
versions, upgrade guidance, and any workaround. Security fixes should be
released for the affected module without unrelated package releases. Reporter
identity and private evidence remain private unless disclosure is agreed.

## Current boundary

The [versioned threat model](docs/security/threat-model.md) describes proposed
SCIM boundaries and release prerequisites. It is not evidence of implemented
controls, protocol conformance, or an available runtime API.
