package scimorganization

import (
	"context"
	"fmt"
	"log/slog"
	"reflect"

	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-sso"
)

const (
	// ErrInvalidDirectoryReconciler rejects missing mapper/executor composition,
	// the zero reconciler and nil contexts without retaining configuration.
	ErrInvalidDirectoryReconciler MappingError = "scim/organization: invalid directory reconciler"
	// ErrInvalidDirectoryResult rejects incomplete, misbound or malformed native
	// receipts. It must not be interpreted as proof that execution rolled back.
	ErrInvalidDirectoryResult MappingError = "scim/organization: invalid directory result"
)

// DirectoryMembershipExecutor executes an already mapped, exact ordered batch
// through the public durable identity/organization owners under the original
// SSO child command IDs. It must independently admit the current generation,
// source and local authority; mapping intent alone grants none of them.
//
// The caller transfers the detached input for the duration of execution. The
// executor must honor ctx, return exact original native receipts in input order
// and preserve every committed sibling when a later child is denied or unknown.
// It must not fabricate terminal evidence from cancellation or an IO error, or
// mutate returned receipt storage concurrently with the caller. Errors must be
// stable and redacted. Native storage owns recovery; this boundary adds no
// command journal, transaction engine, cursor or background work.
type DirectoryMembershipExecutor interface {
	ExecuteMappedDirectoryMemberships(context.Context, DirectoryMembershipBatch) ([]sso.Completion, error)
}

// DirectoryReconciler implements SSO's contributor boundary by mapping the whole
// batch before native execution and validating exact owner receipts afterward.
// Its zero value rejects all input. It owns no resources, receipts, cursor or
// cancellation goroutines. Concurrent calls require a concurrently safe executor;
// the immutable mapper is safe to share. Executor lifetime remains with its owner.
type DirectoryReconciler struct {
	mapper   DirectoryMapper
	executor DirectoryMembershipExecutor
}

var _ sso.DirectorySyncContributor = DirectoryReconciler{}

// NewDirectoryReconciler requires a constructed mapper and a nonnil executor,
// including rejecting typed nils. It performs no IO, admission or execution.
func NewDirectoryReconciler(mapper DirectoryMapper, executor DirectoryMembershipExecutor) (DirectoryReconciler, error) {
	if mapper.state == nil || nilDirectoryExecutor(executor) {
		return DirectoryReconciler{}, ErrInvalidDirectoryReconciler
	}
	return DirectoryReconciler{mapper: mapper, executor: executor}, nil
}

// ApplyDirectoryDelta maps all children before execution and constructs only
// the SSO-owned result from exact ordered native receipts. It privately retains
// the original detached source and local user selections before calling the
// executor, so input mutation cannot change the expected command or user.
//
// Mapping failure or cancellation before execution returns zero without calling
// the executor. Invalid/missing native receipts return zero and
// ErrInvalidDirectoryResult, never synthetic outcomes or a rollback assertion.
// A complete valid result survives an executor error or late cancellation: the
// result and applicable error are both returned. An unresolved valid result
// without another error returns sso.ErrDirectoryReconciliation. The executor's
// error takes precedence over late cancellation or reconciliation. No cursor is
// stored or advanced; only the SSO native owner may settle the original result.
// Do not mutate batch.Deltas concurrently with this call.
func (r DirectoryReconciler) ApplyDirectoryDelta(ctx context.Context, batch sso.DirectoryDeltaBatch) (sso.DirectoryApplyResult, error) {
	if r.mapper.state == nil || nilDirectoryExecutor(r.executor) || ctx == nil {
		return sso.DirectoryApplyResult{}, ErrInvalidDirectoryReconciler
	}
	if err := ctx.Err(); err != nil {
		return sso.DirectoryApplyResult{}, err
	}
	mapped, err := r.mapper.MapDirectoryDelta(batch)
	if err != nil {
		return sso.DirectoryApplyResult{}, err
	}
	original, err := mapped.Source.Snapshot()
	if err != nil {
		return sso.DirectoryApplyResult{}, ErrInvalidMappingInput
	}
	expectedUsers := make([]identity.UserID, len(mapped.Memberships))
	for i, membership := range mapped.Memberships {
		expectedUsers[i] = membership.UserID
	}
	if err := ctx.Err(); err != nil {
		return sso.DirectoryApplyResult{}, err
	}

	receipts, executionErr := r.executor.ExecuteMappedDirectoryMemberships(ctx, mapped)
	if len(receipts) != len(expectedUsers) {
		return sso.DirectoryApplyResult{}, ErrInvalidDirectoryResult
	}
	for i, receipt := range receipts {
		if receipt.Binding.UserID != expectedUsers[i] {
			return sso.DirectoryApplyResult{}, ErrInvalidDirectoryResult
		}
	}
	result, err := sso.NewDirectoryApplyResult(original, receipts)
	if err != nil {
		return sso.DirectoryApplyResult{}, ErrInvalidDirectoryResult
	}
	if executionErr != nil {
		return result, executionErr
	}
	if err := ctx.Err(); err != nil {
		return result, err
	}
	if _, err := result.NextCheckpoint(original); err != nil {
		return result, err
	}
	return result, nil
}

func nilDirectoryExecutor(executor DirectoryMembershipExecutor) bool {
	if executor == nil {
		return true
	}
	v := reflect.ValueOf(executor)
	switch v.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
		return v.IsNil()
	default:
		return false
	}
}

func (DirectoryReconciler) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("scimorganization.DirectoryReconciler(redacted)"))
}

func (DirectoryReconciler) LogValue() slog.Value {
	return slog.StringValue("scimorganization.DirectoryReconciler(redacted)")
}

func (DirectoryReconciler) MarshalJSON() ([]byte, error) { return nil, ErrSensitiveSerialization }
func (DirectoryReconciler) MarshalText() ([]byte, error) { return nil, ErrSensitiveSerialization }
