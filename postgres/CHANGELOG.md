# Changelog

## Unreleased

- Add explicit admitted conditional User Delete for an issued managed bearer
  and exact configured native client. Preserve existing If-Match checks,
  membership-source withdrawal and canonical headerless 204 replay, without
  changing ordinary provisioning, SQL, migrations or caller-key behavior.

- Add explicit admitted User Create for an issued managed bearer and exact
  configured native client. Validate and authorize before charging the gate,
  then retain original native writes/replay, deadlines and redacted denials.
  Ordinary provisioning, admitted reads, SQL and HTTP routing are unchanged.

- Rotate managed connection bearers through an exact server-prepared command
  with current administrator authority and zero predecessor overlap. Commit
  the successor digest, version, protected audit and outbox together; recover
  original metadata without revealing bearer material again.

- Add explicit admitted User Get/List for an issued managed connection bearer.
  Bind the selected native service-account client and tenant after current
  authentication and authorization, using the root protocol's synchronous gate,
  original deadlines, redacted denials and final disclosure fence. Ordinary
  managed provisioning, SQL and HTTP routing are unchanged.

- Create and read managed SCIM connections with current administrator authority.
  Reveal the issued bearer once for scoped User provisioning. Conditional
  managed Delete atomically tombstones the User projection and withdraws only
  the exact organization membership contribution.

- Read ordered SCIM User source states for directory reconciliation, retaining
  exact native revisions and distinguishing unknown mappings from deletions.

- Bind Bulk execution and discovery to the same native executor and an
  authenticated, once-per-attempt transport admission decision.

- Retain unsupported Bulk methods without a resource operation or Location.
  Preserve symbolic dependencies, cutoff, and replay.

- Retain pre-write Bulk validation errors found after Prepare against the
  original snapshot, including PATCH `noTarget`, `mutability`, and replay.

- Retain malformed User/Group creates and planner-invalid PATCH paths as
  typed child results in opt-in Bulk. Preserve dependency and cutoff order.

- Add an opt-in Bulk profile that retains exact resource validation results
  emitted before Prepare, with audited cutoff and identical replay.

- Wait for the admitted target of a symbolic User or Group mutation with
  structural `invalidValue`. Retain dependency failures or audited cutoff
  skips before structural denial, and authorize the resolved Location.

- Retain structural `400 invalidValue` denials for literal User and Group
  mutations. The declared resource permission is required to settle or
  disclose the audited result and its Location.

- Retain a malformed Bulk child with no resource target as an audited
  `400 invalidValue`. Apply cutoff or continue without a resource write.

- Retain a Group-create `invalidValue` reported before writes as a protected
  Bulk child denial. Count it toward cutoff and replay the exact result.

- Drive the admitted mixed Bulk graph in one bounded native call. Preserve
  original component order, independent commits, and exact terminal replay;
  return no Bulk response on an incomplete or unknown outcome.

- Execute conditional User PUT, PATCH, and DELETE in opt-in native Bulk.
  Retain original result versions and confirmed failures on replay, and let
  User DELETE remove only the connection-scoped SCIM projection.

- Add opt-in native mixed Bulk for acyclic User creates and supported Group
  operations, with typed forward references and replay from original commands.
- Settle a started acyclic child as a retained 503 after the kernel confirms
  rollback, without reexecuting the aborted command or counting an unknown.

- Settle external predecessors of all-Group Bulk create cycles as a whole.
  Resume after success, retain an audited skip for each member at cutoff, or
  record each original dependency failure without applying any Group.

- Retain acyclic Group Bulk dependency blocks and definitive 424 results. Resume
  after predecessor success, or retain an audited skip if cutoff is already active.

- Execute an all-Group create cycle atomically through an original child.
  Replays retain all original successes or all protected dependency failures,
  including audited skips once the parent reaches its error threshold.

- Use the ordinary Group writer for acyclic Bulk replace, PATCH and delete.
  Retain encrypted original preparation, operation-specific replay, and the
  exact protected 404, 412 and 428 results. Install the additive Group Bulk
  mutation migration before selecting these operations.

- On an authorized Group Bulk retry, reconcile a previously recorded native
  denial that predates child failure accounting. Count it once and emit a
  separate reconciliation audit without changing the original denial.

- Read the terminal response for an admitted Group Bulk request without
  admitting another request, attaching a retry key, or executing a child.
  Replay preserves declaration order and omits unprocessed cutoff skips.

- Retain definitive native Group Bulk child denials without applying the Group.
  At the configured error threshold, skip remaining admitted children and
  append one protected audit per skip in the same transaction. Ambiguous
  outcomes remain retryable; Bulk HTTP and discovery stay disabled.

- Record protected `identity.scim.bulk_admit` events for newly prepared Group
  Bulk admissions. Existing preparations and requests retain their original
  event and retry behavior without re-emitting it.

- Execute and recover an admitted acyclic Group create using its original
  authorization and IDs. Commit its ordinary Group projection and typed
  result checkpoint together. Routing and discovery remain unchanged.

- Add explicit native Group Bulk admission. Prove the response ceiling before
  retaining one parent and every ordered child and dependency together. Exact
  retries recover the original admission. This does not execute children or
  enable Bulk in HTTP or discovery.

- Carry the exact original role transition across a sealed directory batch
  and reject recovered prefixes that do not match the current sealed owner.

- Carry the exact organization version committed by a directory User child
  into the next sealed source observation without renewing any original
  evidence or bypassing the next child's authorization fences.

- Expose bounded exact Group edge states for drift inspection. Distinguish
  proven absence, an inactive User and an unproven link while preserving the
  existing boolean role-eligibility API.

- Read exact current Group role edges in an ordered bounded primary batch
  and compose role-bearing Work with its own organization successor.
  Existing Group and User reconciliation remains unchanged.

- Fence SCIM User admission and withdrawal in the same transaction as the
  organization effect. Final source checks accept only that command's own
  organization successor and retain the original authority deadline.

- Fence the exact revision of an inactive or deleted SCIM User in the
  original SSO deprovisioning child's Work. A different identity, source
  revision, or later reactivation cannot authorize withdrawal.

- Fence the exact SCIM Group/User edge during the original SSO child write
  and final commit. Require the scoped User projection to identify the
  target. Withdrawal can use retained tombstones; unknown Groups and
  inferred or nested membership cannot authorize a change.

- Bind configured SCIM source evidence to the exact original SSO child
  command. Recheck the same organization, connection and expiry in native
  Work before changes and at final commit; no synchronization authority is
  inferred from a valid connection.

- Add an explicitly selected native Groups profile with authenticated discovery,
  complete CRUD/filter/search/pagination, atomic typed same-connection member
  validation, ETag/no-op/CAS and retained original retries through the existing
  kernel journal. Install the additive Groups migration before activation.
  Existing Users selection stays unchanged; Groups are projections/references,
  not authoritative teams, roles, identity creation or organization reconciliation.
- Add authorized native discovery and complete scoped Users CRUD, filtering,
  search and pagination over the existing protocol and PostgreSQL owners.
  Install the forward Users metadata migration and the kernel status/canonical
  request histories before activation. Updates use actual kernel attribute CAS;
  no-op PATCH preserves versions/time, and canonical DELETE retains its original
  empty response without deleting the global user. Core names/emails/active
  remain SCIM projection data, not verified identifiers or global deprovisioning.
- Preserve original uniqueness and ETag failures on exact retries, including
  after later resource changes or deletion, through the existing kernel journal.

- Complete the Linux/amd64 native dependency manifest and verified checksums
  without changing selected dependency versions.
- Preserve complete admitted usernames without PostgreSQL B-tree size failures;
  checked digest lookups retain exact canonical equality, with creates serialized
  through their existing connection row.
- Reject configured tenant and connection IDs outside the existing 1..64-byte
  ASCII letter/digit/underscore/hyphen audit profile before bootstrap; organization
  and provider IDs remain bounded to 128 bytes and admitted usernames to 4096 bytes.
- Add the optional native configured-connection SCIM active UserCreate/UserGet
  profile, using existing kernel, organization, authorization, audit and outbox
  owners for atomic provisioning and retained keyed command outcomes.
- Require explicit forward schema installation and trusted configured bootstrap;
  no existing connection rotation/reactivation, broader SCIM lifecycle, group,
  organization-membership, synchronization or HTTP profile is enabled.
