// Package scim implements explicit storage-neutral, HTTP-independent SCIM 2.0
// Users and Groups profiles. Trusted composition supplies credential validation, current policy,
// pure mapping and an atomic scoped store. It supplies no durable provisioning,
// connection lifecycle, database, background work or Bulk implementation.
package scim

import (
	"context"
	"errors"
	"fmt"
	"io"
	"time"

	authentication "github.com/faustbrian/go-authentication/v2"
	identity "github.com/faustbrian/go-identity"
	organization "github.com/faustbrian/go-organization"
)

// Operation is an exact protocol operation, not caller-selected authority.
type Operation string

const (
	ServiceProviderConfig Operation = "identity.scim.service-provider-config"
	SchemasList           Operation = "identity.scim.schemas-list"
	SchemaGet             Operation = "identity.scim.schema-get"
	ResourceTypesList     Operation = "identity.scim.resource-types-list"
	ResourceTypeGet       Operation = "identity.scim.resource-type-get"
	UserCreate            Operation = "identity.scim.user-create"
	UserGet               Operation = "identity.scim.user-get"
	UserReplace           Operation = "identity.scim.user-replace"
	UserPatch             Operation = "identity.scim.user-patch"
	UserDelete            Operation = "identity.scim.user-delete"
	UserList              Operation = "identity.scim.user-list"
	UserSearch            Operation = "identity.scim.user-search"
	Search                Operation = "identity.scim.search"
	// Group operations are selected through NewGroupsService or NewCombinedService.
	GroupCreate  Operation = "identity.scim.group-create"
	GroupGet     Operation = "identity.scim.group-get"
	GroupReplace Operation = "identity.scim.group-replace"
	GroupPatch   Operation = "identity.scim.group-patch"
	GroupDelete  Operation = "identity.scim.group-delete"
	GroupList    Operation = "identity.scim.group-list"
	GroupSearch  Operation = "identity.scim.group-search"
	// Bulk is reserved and always fails closed.
	Bulk Operation = "identity.scim.bulk"
)

// Scope partitions every resource and external ID. Structural IDs confer no
// authority. The request cannot supply this scope: Authenticator establishes it.
type Scope struct {
	TenantID       identity.TenantID
	OrganizationID organization.ID
	ProviderID     string
	ConnectionID   string
}

// Connection is a trusted authenticator's current organization/provider-owned
// observation. Version fences connection authority; ExpiresAt is token expiry,
// not authority freshness. Implementations must validate token digest, revocation
// and scope and retain the original observation times below without renewal.
type Connection struct {
	Scope        Scope
	CredentialID string
	Version      uint64
	ExpiresAt    time.Time
	// AuthorityReadBeganAt is the original authoritative read-began time, not
	// cache retrieval, request start or read completion. For combined authority,
	// retain the earliest contributing original read-began time.
	AuthorityReadBeganAt time.Time
	// AuthorityValidUntil is the earliest original contributing authority
	// deadline, exclusive and at most twenty seconds after AuthorityReadBeganAt.
	// Copies and retries retain it unchanged. ExpiresAt separately bounds the
	// credential itself; neither field is authenticated proof. Actual credential
	// validation and current authority remain the trusted owner's responsibility.
	AuthorityValidUntil time.Time
}

// Authenticator validates a bounded opaque bearer and returns its connection.
// Implementations must be concurrency-safe, honor deadlines and fail closed on
// missing/expired/revoked authority. It is not an identity or provisioning store.
// Positive results retain the earliest original read-began time and original
// deadline across all contributing source observations, including cached ones.
// Completing a slow read or copying/retrying a cached result must not reset them.
type Authenticator interface {
	Authenticate(context.Context, authentication.BearerCredential) (Connection, error)
}

// Authorizer evaluates current policy for the verified connection and exact
// operation/target. An error denies; no request principal or Boolean can allow.
// Implementations must be concurrency-safe, bounded and side-effect-free.
// Any additional authority it consumes must cover the connection's remaining
// effective validity window. Earlier-expiring cached policy must be refreshed
// within that budget or denied, never promoted into a longer-lived approval.
type Authorizer interface {
	Authorize(context.Context, Connection, Operation, string) error
}

// WritableResource contains only writable schema IDs, external ID and declared
// attributes. No server ID, metadata, credentials or provisioning authority lives
// here. The service snapshots and revalidates mapper output before admission.
type WritableResource struct {
	Schemas    []string
	ExternalID string
	Attributes map[string]any
}

// Mapper is a bounded, concurrency-safe, side-effect-free representation policy.
// It must not persist, provision, link accounts or infer identity from externalId.
// Real organization mapping is a separate owner, not supplied by this module.
type Mapper interface {
	MapUser(context.Context, Scope, WritableResource) (WritableResource, error)
}

// Version is an opaque strong quoted ETag. Zero is invalid. Store implementations
// atomically compare it exactly; clients must not infer a numeric sequence.
type Version string

// Resource is a detached, credential-free store projection. Scope is carried by
// the store method, never inferred from attributes. Version and timestamps are
// server-owned; every effective mutation gets a fresh version. A replayable
// no-op PATCH retains its original version and modification timestamp. Attributes omit
// common fields and all returned-never values. Treat snapshots as immutable.
type Resource struct {
	ID           string
	Version      Version
	CreatedAt    time.Time
	LastModified time.Time
	Schemas      []string
	ExternalID   string
	Attributes   map[string]any
}

// Snapshot contains one complete transaction-consistent connection snapshot.
// Complete=false denies the entire query, including count=0; it is not a partial
// success. Store must enforce both supplied budgets before materializing values.
type Snapshot struct {
	Resources []Resource
	Complete  bool
}

// SnapshotBudget bounds a complete snapshot before resource materialization.
// Bytes counts the aggregate JSON representation of Resource values. An adapter
// may use a conservative upper bound; it must stop before decoding/copying the
// next resource when either bound would be exceeded and return Complete=false.
// Both fields must be positive. This grants no authority or storage guarantees.
type SnapshotBudget struct {
	Resources int
	Bytes     int
}

// WriteIntent is one bounded, validated protocol request. CommandID is a server
// proposal generated by the service, never accepted from the caller. The trusted
// Store may return its own valid original command identity from Prepare so its
// durable request-key authority remains the sole allocator. CanonicalRequest
// binds operation,
// target, precondition, body, and response-affecting query. Connection is the
// observed authority, not an unverified principal. Trusted Store owns keyed
// canonical fingerprints and optional-key digests, durable admission and replay
// in its existing command authority; this module implements no parallel journal.
type WriteIntent struct {
	CommandID        identity.CommandID
	Scope            Scope
	Connection       Connection
	Operation        Operation
	ResourceID       string
	IfMatch          Version
	IdempotencyKey   string
	CanonicalRequest []byte
}

// CreateMetadata is server-owned identity/version/time retained by durable
// preparation for one original create command. It contains no writable resource
// attributes, scope, credentials or authorization. Stores must bind it to the
// exact canonical request and preserve it across retries. IDs/versions follow
// Resource's bounds; timestamps normalize to UTC and must have nonzero RFC 3339
// years 1..9999, with modification not before creation. The protocol copies it
// before mapping. Nil selection in
// PreparedWrite preserves the service's existing per-call metadata generation.
type CreateMetadata struct {
	ID           string
	Version      Version
	CreatedAt    time.Time
	LastModified time.Time
}

// UpdateMetadata selects original server-owned version/time for one prepared
// replace or PATCH. The Store must bind it and Current to the original canonical
// request. ID and CreatedAt always come from Current, never these fields. Version
// follows Resource's bounds; LastModified is nonzero, normalizes to UTC, has a
// year in1..9999 and cannot precede Current.LastModified. A changed resource must
// receive a different version. No-op PATCH preserves Current's version/time.
// The protocol snapshots this value before mapping; nil retains per-call
// generation. It grants no authority or permission to bypass current CAS.
type UpdateMetadata struct {
	Version      Version
	LastModified time.Time
}

// Format prevents accidental command-payload/optional-key disclosure.
func (WriteIntent) Format(s fmt.State, _ rune) {
	_, _ = io.WriteString(s, "scim.WriteIntent(redacted)")
}

// MarshalJSON prevents implicit persistence or publication of command custody.
func (WriteIntent) MarshalJSON() ([]byte, error) {
	return nil, errors.New("scim: command serialization forbidden")
}

// PreparedWrite is an admission observation, never a held transaction/lock.
// Intent carries the Store's authoritative original CommandID and the exact
// current request scope, operation, target, precondition, canonical bytes and
// lookup IdempotencyKey. The current lookup key is echoed even when it recovers
// an original headerless DELETE; it does not replace that original command.
// Fresh admission must preserve Connection without renewing its observation.
// Store must bind this to one command, connection and canonical request. A replay
// carries the original semantic result and must be handled before preconditions.
// Current is a detached snapshot; Commit fences it with IfMatch atomically.
// Failure is supplied only to Abort for a provably uncommitted terminal denial.
type PreparedWrite struct {
	Intent  WriteIntent
	Current *Resource
	Replay  *WriteResult
	Failure *Error
	// CreateMetadata optionally selects retained server metadata for a fresh
	// create only. Other fresh operations reject it; replay uses the original
	// WriteResult instead. No client request field can select this metadata.
	CreateMetadata *CreateMetadata
	// UpdateMetadata optionally selects retained version/time for replace/PATCH
	// only. Other fresh operations reject it; replay uses original WriteResult.
	// A client request cannot select this trusted Store-owned metadata.
	UpdateMetadata *UpdateMetadata
}

// Change is the fully validated candidate or a deletion, never both. It carries
// no callback and cannot perform identity/membership changes. Store must commit
// projection, replay result and audit attribution together or report uncertainty.
type Change struct {
	Resource *Resource
	Delete   bool
}

// WriteOutcome is a closed durable observation. An error, panic, cancellation or
// timeout is not evidence of rollback. Zero/unknown values never mean success.
type WriteOutcome uint8

const (
	WriteOutcomeInvalid WriteOutcome = iota
	WriteOutcomeNotCommitted
	WriteOutcomeCommitted
	WriteOutcomeUnknown
	WriteOutcomeInProgress
)

// WriteResult is the original semantic mutation result. Only committed writes
// may carry a Resource; committed deletion carries nil. Unknown/in-progress
// admissions remain blocked and must never be reallocated after a timeout.
// A terminal not-committed denial carries Failure for exact semantic replay.
// Adapters may reconstruct a retained error using NewError, never raw details.
type WriteResult struct {
	Outcome  WriteOutcome
	Resource *Resource
	Failure  *Error
}

// Store is the trusted atomic projection/admission boundary, not a default
// implementation. Every method must enforce the exact connection partition,
// bounds, cancellation and detached ownership. Prepare atomically recovers or
// admits one server command, returning no open transaction or held lock. Commit
// atomically checks current connection/token/policy authority, IfMatch, userName
// uniqueness using UsernameComparisonKey and UsernameComparisonProfile, and
// candidate ID absence on create, then commits the mutation, existing command
// result and redacted audit attribution.
// An unchanged PATCH candidate is a replayable no-op: retain its projection,
// version and timestamps while recording the command's successful result.
// externalId is never unique or an account-takeover key. Username keys use
// the full connection partition; retain original userName values and IDs.
// A comparison-profile upgrade requires explicit collision
// reconciliation and index migration, not silent stored-name rewriting.
// Prepare/Commit must use one existing durable authority, not duplicate
// journals. No callbacks run under locks. Resource IDs and retired versions
// must never be reused.
// Commit must fence the unchanged original authority deadline and token expiry
// at the actual protected effect, as well as checking current source authority.
// A context deadline or metadata alone is not proof of that atomic fence.
// A valid commit may precede a late/expired response: withholding that response
// does not roll back its effects or permit releasing its command for retry.
//
// Matching optional keys recover the same command; changed fingerprints conflict
// before mutation. Headerless DELETE uses connection+target+precondition canonical
// lookup, including when a new optional key is supplied after a headerless delete.
// Replay retention is independent of tombstones; unresolved outcomes never expire
// into permission to retry. Abort records PreparedWrite.Failure as the original
// terminal denial in the
// same command authority, without changing projection state. Replay includes
// that exact typed denial, not current-state reevaluation. Abort only closes a
// provably uncommitted admission; it must never release committed, running or uncertain authority. Every error
// except the documented not-committed sentinels is conservatively unknown.
// Abort cleanup has its own bounded context after expiry/cancellation and may
// close only that existing admission, never authorize new protected effects.
// JSON attributes contain maps, []any, strings, booleans, json.Number and nil;
// adapters must preserve that representation rather than approximate numbers.
// Implementations are concurrency-safe and retain no caller-owned mutable data.
type Store interface {
	Get(context.Context, Scope, string) (Resource, error)
	Snapshot(context.Context, Scope, SnapshotBudget) (Snapshot, error)
	Prepare(context.Context, WriteIntent) (PreparedWrite, error)
	Commit(context.Context, PreparedWrite, Change) (WriteResult, error)
	Abort(context.Context, PreparedWrite) error
}

var (
	// ErrNotFound deliberately reveals no cross-connection resource existence.
	ErrNotFound = errors.New("scim: not found")
	// ErrConflict rejects changed canonical replay inputs before mutation.
	ErrConflict = errors.New("scim: conflict")
	// ErrPreconditionFailed guarantees no commit occurred under a stale version.
	ErrPreconditionFailed = errors.New("scim: precondition failed")
	// ErrUniqueness guarantees no commit occurred under a userName collision.
	ErrUniqueness = errors.New("scim: uniqueness conflict")
)

// Query preserves count omission separately from zero. Paths and filter use
// declared schema semantics; attributes and excludedAttributes cannot coexist.
// Callers must not mutate input maps/slices/pointers concurrently with Execute.
type Query struct {
	Filter             string
	SortBy             string
	SortOrder          string
	StartIndex         int
	Count              *int
	Attributes         string
	ExcludedAttributes string
}

// Request is HTTP-independent protocol input. Transport owns route selection,
// raw/decoded streaming limits, TLS, and header extraction. Body is already
// decoded JSON; non-identity ContentEncoding is rejected before JSON decoding.
// No request field selects a connection, principal, tenant or command identity.
type Request struct {
	Operation       Operation
	Credential      authentication.BearerCredential
	ResourceID      string
	IfMatch         Version
	IdempotencyKey  string
	Body            []byte
	ContentType     string
	ContentEncoding string
	Query           Query
}

// Format redacts credentials, bodies, filters and optional idempotency keys.
func (Request) Format(s fmt.State, _ rune) { _, _ = io.WriteString(s, "scim.Request(redacted)") }

// MarshalJSON rejects implicit serialization of request credential custody.
func (Request) MarshalJSON() ([]byte, error) {
	return nil, errors.New("scim: request serialization forbidden")
}

// Response carries successful SCIM JSON or an empty 204. Errors are returned
// separately as *Error and must be written by transport with their exact status
// and application/scim+json. ETag is also present in resource metadata.
type Response struct {
	Status      int
	ContentType string
	Body        []byte
	ETag        Version
	Location    string
}
