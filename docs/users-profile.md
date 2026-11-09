# Users profile decisions

## Ownership and outcomes

The root package owns protocol admission, schema validation, filtering, sorting,
projection, PATCH intent, response metadata and error redaction. It does not own
identity provisioning, organization membership, a token authority, the connection
lifecycle, durable replay storage, migrations or a transaction engine.

`Store` is an explicit trusted boundary required by the complete SCIM goal.
Its `Prepare`/`Commit`/`Abort` methods are not a second command authority:
adapters must use their existing durable admission/journal owner. A native
adapter cannot become ready from compilation against this interface alone.

The service generates a random command candidate and canonicalizes protocol
inputs before admission. Store owns versioned keyed fingerprints and optional-key
digests, atomic lookup/conflict rules, current authority, audit and retention.
Matching retries recover the original semantic result before stale/tombstone
checks. Changed fingerprints conflict. Headerless DELETE recovery is required,
including a later newly supplied optional key. Unknown/in-progress mappings stay
blocked; timeouts, errors or panics never imply rollback or permission to remap.

Only explicit not-committed outcomes or the documented no-commit sentinel errors
permit `Abort`. Abort records the typed terminal denial in that same command
authority so a matching retry returns its original error rather than reevaluating
a newer resource. `NewError` reconstructs retained safe status/type metadata
without accepting provider details. Once `Commit` is invoked, an arbitrary
failure remains unknown.
Cleanup gets a separate bounded context and does not launch background work.

## Original-read authority validity

`Connection.AuthorityReadBeganAt` identifies the original authoritative read
beginning, not its completion, cache retrieval or request start. The trusted
authenticator combines its actual source observations conservatively and retains
their earliest original read-began time and deadline in `AuthorityValidUntil`.
That exclusive deadline must be within twenty seconds of the original read.
Missing, future, overlong or expired metadata fails closed. Copies and retries
never renew it; token `ExpiresAt` remains a separate upper bound.

Each protected authorization, read, admission, mapping and commit call receives
only the remaining earliest authority/token/request budget. Current validity is
checked before those boundaries and again before returning output, including
state-dependent errors. Expired authority cannot distinguish 404 from success.
Additional policy authority must cover that effective window or be refreshed
within it; unavailable or earlier-expiring cached approval cannot extend access.

These metadata checks are not authenticated proof or a replacement authority.
The actual authenticator validates credentials/source observations. The actual
Store atomically fences current authority and original expiry with its protected
effects. A valid commit whose response arrives after expiry remains committed;
the service withholds success without aborting it or claiming rollback. Only
known-uncommitted admission cleanup may use its separate bounded cleanup context.

## Schema and protocol decisions

- Core User support is the exact subset listed in README and discovery. Unknown
  attributes, unknown schemas, client `id`/`meta`, and unsupported operation IDs
  fail closed. Writable inputs intentionally exclude server fields, even where
  RFC clients otherwise send read-only fields for servers to ignore.
- Names are compared case-insensitively; duplicate JSON names and case aliases
  are rejected in every object before authorization, mapping or store access.
  Schema URNs preserve their registered identity; core-URN-qualified attribute
  paths and configured extension-URN paths use the same owning attributes.
- Core `userName` comparison and server uniqueness use
  `UsernameComparisonKey` under the explicit `UsernameComparisonProfile`:
  `scim-username-rfc8265-ucd17.0.0-v1`. Store enforces that key atomically in the
  full connection partition. Original username spellings and resource IDs are
  retained; comparison keys are not replacement resource values. `externalId` is case-exact,
  non-unique and never an account-linking authority or takeover key.
- Extensions are optional. Their declared type, required, mutability, caseExact,
  returned and uniqueness descriptors are validated and published. Extension
  attributes must declare uniqueness none; server uniqueness is owned only for
  core userName in this profile. A misleading additional uniqueness claim fails
  configuration instead of relying on an unimplemented index. Required
  read-only extension fields are unsupported because this profile has no owner
  for arbitrary generated values. Read-only/immutable children under multi-valued
  extensions are rejected at configuration: preserving them across reorder and
  replacement requires a separate element-identity contract, not invented keys.
- Every write to password or a returned-never attribute is refused at the typed
  credential seam. A future approved password profile must consume
  `identity/password`. No accepted credentials enter a SCIM projection.
- Replace removes omitted writable data and refuses changes/removal of existing
  immutable data, including descendants of omitted/null mutable parents. Existing
  read-only projection data is retained and stored aliases are canonicalized
  before filtering or projection. PATCH supports
  add/remove/replace, complex merging, value selection and qualified paths.
  Adding a qualified extension attribute adds its schema automatically. Each
  intermediate operation must preserve required/mutability constraints; failed
  operations leave the resource and its version unchanged.
- Singular complex PATCH replacement retains unspecified siblings; selected
  whole multi-value records remain whole-record replacements. Selectors are
  resolved against the original operation input before primary resets. Pathless
  aliases/overlapping targets are rejected before admission, not ordered by maps.
  Operands are type-checked and names canonicalized before equality or set-key
  construction, even for no-op additions. Immutable complex comparisons retain
  the Store-owned read-only representation without permitting client echoes.
- Schema-equivalent decimals and date-times compare consistently for sets and
  immutable values. Binary values require standard base64 (optional padding);
  references require absolute/relative URI syntax. Both types are case-exact.
  Reference admission does not fetch or prove availability of the target.
  Binary ordering filters (`gt`, `ge`, `lt`, `le`) return `invalidFilter` under
  RFC 7644 section 3.4.2.2; equality, inequality and presence remain supported.
- A no-op add retains the resource version and modification timestamp while its
  successful command result remains replayable. Adding an existing set member is
  not a new duplicate member; duplicate values in supplied sets remain invalid.
- Setting a multi-value `primary` resets other primary values in the same PATCH,
  as required by RFC 7644 section 3.5.2. Comparison respects declared type and
  caseExact. Decimal comparison is exact within a bounded JSON representation:
  at most 128 bytes with exponent -308..308; integers must fit signed 64 bits.
  The same exact decimal domain applies to resource admission, set keys,
  immutable/no-op equality, filtering and sorting; it is not narrowed to finite
  float64 values. Logical filters require gaps on both sides of `and` and `or`.
  Omitted `primary` is assumed false when an actual multi-valued complex element
  is queried, sorted or evaluated by a PATCH selector (RFC 7643 section 2.4).
  Set keys and equality use that same immediate-element default: supplied
  omitted/false duplicates are invalid, while adding the existing member is a
  replayable no-op retaining its original representation, version and timestamps.
  This does not invent missing collections, change unrelated Boolean fields or
  persist defaults as if the client supplied them.
  The immediate singular Boolean primary descriptor is resolved
  case-insensitively, including configured `Primary`/`PRIMARY` extensions.
  Validation, comparison defaults, preferred-member sorting and PATCH
  reassignment retain that descriptor's canonical spelling. Reassignment writes
  only demoted true members, leaving absent/false siblings unchanged; singular
  parents and non-Boolean/multi-valued children do not acquire primary policy.
- Strong quoted versions are opaque, generated afresh and atomically checked by
  Store. This profile accepts one exact strong `If-Match`, not wildcards, weak
  validators or validator lists. Missing returns 428; stale returns 412.
- Every resource response exposes its version, including projected list entries.
  A projection can omit other metadata but retains `meta.version` for the next
  mutation; collection-level metadata cannot substitute for individual versions.
- RFC 7643 section 7 `returned: request` values supplied by create, replace or
  PATCH are returned in that write's default response and matching replay.
  Existing unsupplied request-only values remain omitted, including on ordinary
  GET. Explicit query projections retain their selection/exclusion policy.
  `returned: always` descendants retain their minimum complex ancestors even
  when an ancestor is unselected or excluded; ordinary siblings stay omitted.
  Neither behavior crosses a returned-never/write-only privacy boundary.

## Effective limits

Use `DefaultLimits()` and deliberately lower fields if necessary. Zero `Config`
(and zero limits) is invalid; ErrorDetailBytes alone may explicitly be zero. Construction verifies that discovery fits the same
structural/byte limits used at runtime. Runtime dependencies are required;
`Now == nil` selects `time.Now`. Other mutable inputs are copied. Callers must
not mutate an input concurrently with a call. The service owns no shutdown task.

| Boundary | Default / maximum |
| --- | --- |
| Request timeout | Explicit positive duration, at most one minute |
| Returned page | Default 100, maximum 1,000; custom default must not exceed maximum |
| Fallback snapshot | At most 10,000 resources and 8 MiB Resource JSON; byte maximum configurable up to 16 MiB |
| Filter | 8 KiB, 512 tokens, 256 nodes, depth 16 |
| Attribute/PATCH/projection/sort path | 1 KiB each |
| JSON resource | Depth 16, 1,000 object members and 1,000 array elements per array |
| String value/member name | 64 KiB |
| PATCH | 100 operations |
| Already-decoded JSON request | 1 MiB; configurable up to 2 MiB |
| Encoded response | 2 MiB; configurable up to 4 MiB |
| Error detail | 512 safe UTF-8 bytes; zero suppresses detail |
| Bearer credential | 8 KiB, RFC 6750 bearer syntax |
| Optional idempotency key | 256 UTF-8 bytes |

The Store `Snapshot` contract accepts `SnapshotBudget{Resources, Bytes}` and
must enforce both before decoding/copying each additional resource. Core code
also checks returned aggregate size before normalization/materialization. Escaped
output is sized before encoding; PATCH growth is checked prospectively before
append/clone and before normalization/Mapper. These are separate byte boundaries,
not claims that a serialized-byte budget is a literal process-memory bound.

The fallback snapshot must be complete and transaction-consistent. A truncated
snapshot, malformed stored resource, duplicate server ID, exhausted budget or
expired context never yields a partial page or invented total. Store must bound
its own allocation before returning. Production indexed implementations may
optimize behind that contract but cannot change query semantics.

Pagination is 1-based. Omitted/below-one start is 1; omitted count uses the
effective default; negative count is zero; excess count is capped. Count zero
returns exact snapshot totals and no resources. Absent sort is server ID
ascending. Explicit sorting uses schema comparisons, primary/first multi-value
semantics, unassigned values last ascending/first descending and an ID-ascending
tie-break. Both POST-search operations share the GET-list evaluator and RFC
ListResponse envelope.

The transport must separately enforce raw body, decompression and streaming
bounds before assembling `Request.Body`. The service accepts already decoded
JSON with absent/identity ContentEncoding and rejects other encodings before
JSON decoding. This is not evidence of a deployed HTTP ingress limit.
Projection comma counts are checked before allocating path slots, with the same
effective resource-attribute count limit used for the resulting path list.

## Versioned username preparation

RFC 7644 section 5 requires PRECIS before username comparison or uniqueness.
The selected case-insensitive core schema uses the complete RFC 8265
`UsernameCaseMapped` profile from pinned `golang.org/x/text v0.42.0`: width
mapping, root-locale lowercase mapping, NFC, IdentifierClass/context rules and
the Bidi rule. NFC alone, full case folding and NFKC are not substitutes. In
particular, sharp-s does not become `ss`, final sigma remains distinct from
ordinary sigma, and non-width compatibility numerals remain invalid.

The pinned upstream `secure/precis`, `cases`, `width`, `unicode/norm` and
`unicode/bidi` packages select their Unicode 17.0.0 tables with `go1.27` build
constraints, not exact-minor-version constraints. This repository requires Go
1.27 or later, so newer supported Go versions keep those same pinned tables.
The source-traced standard path is `UsernameCaseMapped` with `FoldWidth`,
`LowerCase()`, NFC and Bidi. `LowerCase()` selects `cases.Lower(language.Und,
cases.HandleFinalSigma(false))`, whose mapper is the stateless
`undLowerIgnoreSigmaCaser` backed by the pinned case trie. The `unicode.Greek`
and `unicode.Soft_Dotted` checks belong to unselected locale-specific casing
branches. The `unicode.Zs` mappings belong to OpaqueString/Nickname, not this
username path. No input-dependent stdlib Unicode tables are used on this path.

`UsernameComparisonKey` bounds source strings to 65,536 bytes and returns a
redacted typed error for invalid or empty names. Preparation may expand that
bounded input; keys must not be truncated. Effective service limits can be
lower. Create, replace, PATCH, mapped output, stored reads,
filter operands, comparisons and sort all use the same core username policy.
Substring filter operands (`co`, `sw`, `ew`) are bounded string fragments, not
standalone username registrations. They use the same pinned width mapping,
root lowercasing with final-sigma handling disabled, and NFC, without whole-name
IdentifierClass/context/Bidi or nonempty admission. Contextual fragments such
as `·`, `l·`, and `·l` and empty strings remain valid predicates against an
admitted username. The stored operand, equality/order comparisons, sorting and
uniqueness still use the complete profile. Null is not an empty string, and
absent attributes are not fabricated to match empty fragments.
Other attributes retain their declared type and `caseExact` policy, including
same-named extension attributes. The standard profile is immutable and its
selected casing transformer retains no per-call state.

Stores must bind `UsernameComparisonProfile` to persisted comparison indexes
and use the shared helper, not independent NFC, folding or database collation.
Any future profile/data upgrade requires explicit collision reconciliation and
index migration before adoption; it must not silently rewrite source usernames
or IDs. The protocol fixture demonstrates this contract only, not a native
adapter's transactional uniqueness or upgrade implementation.

String relational filters compare empty strings lexically. Sorting separately
retains this profile's unassigned-last ascending/unassigned-first descending
placement and stable ascending resource-ID tie-break.

## Remaining qualification

Tests exercise the real protocol service with explicitly trusted boundary
implementations. They cannot establish native transaction/recovery correctness,
connection bearer generation/digest/rotation/revocation, real organization or
identity effects, HTTP/OpenAPI composition, independent-client interoperability,
release qualification or M28 completion. Those remain owning-unit and parent
integration responsibilities, not waived requirements of the complete goal.
