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

This selected direct-member profile does not qualify broader SCIM
provisioning, User deprovisioning or full organization reconciliation.
