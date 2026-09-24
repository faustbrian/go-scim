# Security planning

`go-scim` has no runtime implementation, importable package, or release.
The [threat model](security/threat-model.md) is version 1 of the proposed
security boundary; its controls are requirements for future implementation,
not present safeguards. The [private reporting policy](../SECURITY.md) is
active for this repository.

Release is blocked in `modules.json`. The future implementation must prove the
relevant protocol and connection controls with hostile-input, authorization,
isolation, redaction, resource-bound, cancellation, replay, and partial-failure
tests, along with selected security checks and a per-module release verdict.
The threat model and risk decisions must be revised when the API, integration,
or trust boundary changes. Planning metadata and structural checks alone do
not satisfy those gates.
