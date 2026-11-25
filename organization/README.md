# SCIM organization mapping

This optional Go 1.27 module maps direct SCIM Group/User source IDs to
explicitly configured existing teams and users. Construct a
`DirectoryMapper` with one tenant, organization, provider, connection and
mapping version, plus case-exact Group and User mappings. It copies the
configuration, rejects duplicate source IDs or an unmapped edge, and never
infers roles, traverses nested groups or creates organization accounts.

`MapDirectoryDelta` returns a detached ordered batch. It retains the
original SSO scope, predecessor, source IDs and child command IDs.
Mapping is a policy decision, not proof of an installed source, current
membership or a durable write.

To compose with SSO, construct `DirectoryReconciler` with the mapper and
the deployment's authorized native `DirectoryMembershipExecutor`. The
reconciler maps the complete batch before calling the executor and validates
the exact ordered receipts against its retained source batch. The native
executor must preserve original command custody and obtain receipts from
the authoritative transaction owner. SSO alone persists the checkpoint.
If execution stops before every child outcome is observed, the reconciler
returns the exact observed prefix and the execution or cancellation error.
The partial result cannot advance the checkpoint and says nothing about
whether unobserved children committed.
The mapping module has no database, HTTP routes, scheduler or retry store.

## Opt-in Group role mapping

`NewDirectoryRoleMapper` snapshots the exact Group and member mapping plus
one explicit role selection for each configured Group/team. A role must be
a custom role ID, never a static organization role. A Group's display name
or source ID cannot infer a role. The ordinary `DirectoryMapper` stays
membership-only.

`MapDirectoryRoleDelta` returns the original SSO batch and ordered mapped
edges with their explicit role IDs, or no result on failure.
`MatchesDirectoryRoleSource` compares a detached source and target to this
configuration without reading storage. It does not certify the Group edge,
enrolled native team-role binding, provider or organization authority.

## Opt-in User mapping

`DirectoryUserMapper` separately selects User admission and source-owned
organization withdrawal policy. Construct it with
`NewDirectoryUserMapper(DirectoryUserMappingConfig{...})`, the exact tenant,
organization, provider, connection and positive current mapping version,
1..1,000 explicit `Members`, and `AllowAdmission`, `AllowWithdrawal`, or both.
The zero mapper and an all-disabled configuration reject every action.
Configuration is snapshotted; update the version by constructing a new mapper.

`MapDirectoryUserDelta` preserves the original SSO envelope and ordered child
commands, source User resource IDs and revisions. It selects
`DirectoryUserAdmit`, `DirectoryUserWithdrawInactive` or
`DirectoryUserWithdrawDeleted` for the explicitly mapped existing local user.
Only the exact source User resource ID is a mapping key. There is no fallback
to aliases, externalId, usernames, emails, display names or Group mappings.
Duplicate source mapping rows are rejected, including identical duplicates.

The mapper accepts bounded all-User batches, including combined admission
and withdrawal actions, but rejects Group-only or mixed Group/User batches.
Wrong scope or version, unknown resources or unselected actions return
`ErrMappingDenied`; malformed or unsupported input returns
`ErrInvalidMappingInput`. Every failure returns zero output. Implicit
formatting and structured logs redact identifiers; implicit JSON and text
serialization return `ErrSensitiveSerialization`.

This output is mapping policy, not source authority, authorization, a durable
receipt or a checkpoint. A native executor must obtain the original source
observation, current policy and authoritative identity and organization
decisions before applying effects under the original child command. The
executor may support a narrower batch size than the pure mapper. The User
mapper does not implement the SSO contributor and does not change the existing
Group mapper or reconciler contract.

## Read-only membership drift classification

`ClassifyDirectoryMembershipDrift` compares explicit source membership evidence
with an observed grant attributed to that exact source. It reports in-sync,
missing-source-grant or unexpected-source-grant state. An independent local
grant is reported separately as `LocalGrant` and never substitutes for a source
grant. Inactive source Users, unproven source evidence and unobserved local
state report conflict, even when no source-attributed grant exists.

Zero or unknown source states and attribution/local flags without a completed
local observation return `ErrInvalidMappingInput` with zero output. The caller
must obtain exact-scope authoritative observations; classification does not
establish freshness, select repair or withdrawal policy, issue commands, or
advance an SSO cursor. Implicit formatting and logging redact observations;
implicit JSON and text serialization return `ErrSensitiveSerialization`.

These selected profiles do not qualify broader SCIM identity provisioning,
global identity suspension/deletion or full organization reconciliation.
