package scimorganization_test

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/faustbrian/go-authorization/v3"
	identity "github.com/faustbrian/go-identity"
	scimorganization "github.com/faustbrian/go-scim/organization"
	"github.com/faustbrian/go-sso"
)

var _ sso.DirectorySyncContributor = scimorganization.DirectoryReconciler{}

func TestDirectoryReconcilerMapsEntireBatchBeforeExecution(t *testing.T) {
	mapper, err := scimorganization.NewDirectoryMapper(directoryConfig())
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.WithValue(context.Background(), reconcilerContextKey{}, "original")
	executor := directoryExecutorFunc(func(gotCtx context.Context, mapped scimorganization.DirectoryMembershipBatch) ([]sso.Completion, error) {
		if gotCtx != ctx || gotCtx.Value(reconcilerContextKey{}) != "original" {
			t.Fatal("executor did not receive the original caller context")
		}
		if !reflect.DeepEqual(mapped.Source, directoryBatch(t)) || len(mapped.Memberships) != 1 {
			t.Fatal("executor did not receive the exact mapped batch")
		}
		intent := mapped.Memberships[0]
		if intent.CommandID != "AQEBAQEBAQEBAQEBAQEBAQ" || intent.TeamID != "Team.A" || intent.UserID != "User.A" || intent.Action != sso.DirectoryMembershipAdd {
			t.Fatal("executor received altered policy selections")
		}
		return []sso.Completion{reconcilerReceipt(intent.CommandID, identity.CommitOutcomeCommitted)}, nil
	})
	reconciler, err := scimorganization.NewDirectoryReconciler(mapper, executor)
	if err != nil {
		t.Fatal(err)
	}
	batch := directoryBatch(t)
	result, err := reconciler.ApplyDirectoryDelta(ctx, batch)
	if err != nil || len(result.ChildOutcomes) != 1 || result.ChildOutcomes[0].Outcome != identity.CommitOutcomeCommitted {
		t.Fatal("valid original receipt was not retained", err)
	}
	if next, err := result.NextCheckpoint(batch); err != nil || next == ([32]byte{}) || next == batch.PredecessorCheckpoint {
		t.Fatal("exact terminal receipt did not produce the SSO-owned successor", err)
	}

	calls := 0
	denied, err := scimorganization.NewDirectoryReconciler(mapper, directoryExecutorFunc(func(context.Context, scimorganization.DirectoryMembershipBatch) ([]sso.Completion, error) {
		calls++
		return nil, nil
	}))
	if err != nil {
		t.Fatal(err)
	}
	batch.Deltas = append(batch.Deltas, directoryDelta(t, "AgICAgICAgICAgICAgICAg", "Unmapped", "Member.A", sso.DirectoryMembershipRemove))
	result, err = denied.ApplyDirectoryDelta(ctx, batch)
	if !errors.Is(err, scimorganization.ErrMappingDenied) || calls != 0 || !reflect.DeepEqual(result, sso.DirectoryApplyResult{}) {
		t.Fatal("execution began before the whole batch was mapped")
	}
}

func TestDirectoryReconcilerPreservesValidNativeOutcomesAndErrors(t *testing.T) {
	executionErr := errors.New("native operation unavailable")
	for _, outcome := range []identity.CommitOutcome{
		identity.CommitOutcomeCommitted, identity.CommitOutcomeNotCommitted,
		identity.CommitOutcomeUnknown, identity.CommitOutcomeInProgress, identity.CommitOutcomeConflict,
	} {
		for _, withError := range []bool{false, true} {
			t.Run(fmt.Sprintf("outcome-%d-error-%t", outcome, withError), func(t *testing.T) {
				var nativeErr error
				if withError {
					nativeErr = executionErr
				}
				receipts := []sso.Completion{reconcilerReceipt("AQEBAQEBAQEBAQEBAQEBAQ", outcome)}
				reconciler := newDirectoryReconciler(t, directoryExecutorFunc(func(context.Context, scimorganization.DirectoryMembershipBatch) ([]sso.Completion, error) {
					return receipts, nativeErr
				}))
				batch := directoryBatch(t)
				result, err := reconciler.ApplyDirectoryDelta(context.Background(), batch)
				if !reflect.DeepEqual(result.ChildOutcomes, receipts) || result.Generation != batch.Generation {
					t.Fatal("native result was lost or synthesized")
				}
				terminal := outcome == identity.CommitOutcomeCommitted || outcome == identity.CommitOutcomeNotCommitted
				switch {
				case withError && !errors.Is(err, executionErr):
					t.Fatal("valid receipts lost their native execution error", err)
				case !withError && terminal && err != nil:
					t.Fatal("valid terminal result was rejected", err)
				case !withError && !terminal && !errors.Is(err, sso.ErrDirectoryReconciliation):
					t.Fatal("unresolved native result did not require reconciliation", err)
				}
				next, nextErr := result.NextCheckpoint(batch)
				if terminal {
					if nextErr != nil || next == ([32]byte{}) {
						t.Fatal("valid terminal result lost its successor", nextErr)
					}
				} else if !errors.Is(nextErr, sso.ErrDirectoryReconciliation) || next != ([32]byte{}) {
					t.Fatal("unresolved result advanced a checkpoint", nextErr)
				}
			})
		}
	}
}

func TestDirectoryReconcilerPreservesCommittedPrefixOnInterruptedBatch(t *testing.T) {
	nativeErr := errors.New("later native child unavailable")
	for _, test := range []struct {
		name         string
		executionErr error
		cancel       bool
		wantErr      error
	}{
		{name: "native reconciliation", executionErr: sso.ErrDirectoryReconciliation, wantErr: sso.ErrDirectoryReconciliation},
		{name: "native failure", executionErr: nativeErr, wantErr: nativeErr},
		{name: "late cancellation", cancel: true, wantErr: context.Canceled},
		{name: "native failure precedes cancellation", executionErr: nativeErr, cancel: true, wantErr: nativeErr},
	} {
		t.Run(test.name, func(t *testing.T) {
			batch := directoryBatch(t)
			batch.Deltas = append(batch.Deltas,
				directoryDelta(t, "AgICAgICAgICAgICAgICAg", "Group.A", "Member.A", sso.DirectoryMembershipRemove),
				directoryDelta(t, "AwMDAwMDAwMDAwMDAwMDAw", "Group.A", "Member.A", sso.DirectoryMembershipAdd),
			)
			want := []sso.Completion{
				reconcilerReceipt("AQEBAQEBAQEBAQEBAQEBAQ", identity.CommitOutcomeCommitted),
				reconcilerReceipt("AgICAgICAgICAgICAgICAg", identity.CommitOutcomeCommitted),
			}
			receipts := []sso.Completion{
				reconcilerReceipt("AQEBAQEBAQEBAQEBAQEBAQ", identity.CommitOutcomeCommitted),
				reconcilerReceipt("AgICAgICAgICAgICAgICAg", identity.CommitOutcomeCommitted),
			}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			reconciler := newDirectoryReconciler(t, directoryExecutorFunc(func(gotCtx context.Context, mapped scimorganization.DirectoryMembershipBatch) ([]sso.Completion, error) {
				if gotCtx != ctx || !reflect.DeepEqual(mapped.Source, batch) || len(mapped.Memberships) != 3 {
					t.Fatal("executor did not receive the original complete mapped batch")
				}
				for i, membership := range mapped.Memberships {
					original, err := batch.Deltas[i].GroupMembership()
					if err != nil || membership.CommandID != original.CommandID || membership.Action != original.Action || membership.TeamID != "Team.A" || membership.UserID != "User.A" {
						t.Fatal("executor received an altered child mapping", err)
					}
				}
				if test.cancel {
					cancel()
				}
				return receipts, test.executionErr
			}))

			result, err := reconciler.ApplyDirectoryDelta(ctx, batch)
			if !errors.Is(err, test.wantErr) {
				t.Fatal("interrupted batch lost its original execution or cancellation error", err)
			}
			if result.Generation != batch.Generation || !reflect.DeepEqual(result.ChildOutcomes, want) {
				t.Fatal("interrupted batch lost the exact observed prefix or synthesized an unobserved child")
			}
			if result.Checkpoint != ([32]byte{}) {
				t.Fatal("incomplete batch produced a checkpoint")
			}
			if next, err := result.NextCheckpoint(batch); next != ([32]byte{}) || !errors.Is(err, sso.ErrDirectoryReconciliation) {
				t.Fatal("observed committed prefix advanced the incomplete batch", err)
			}

			receipts[0].Feature.AfterVersion++
			receipts[1].Feature.AfterVersion++
			receipts[0] = sso.Completion{}
			if !reflect.DeepEqual(result.ChildOutcomes, want) {
				t.Fatal("retained prefix aliases executor-owned receipt storage")
			}
			if next, err := result.NextCheckpoint(batch); next != ([32]byte{}) || !errors.Is(err, sso.ErrDirectoryReconciliation) {
				t.Fatal("executor mutation damaged the retained prefix evidence", err)
			}
		})
	}
}

func TestDirectoryReconcilerRejectsInvalidInterruptedPrefixes(t *testing.T) {
	batch := directoryBatch(t)
	batch.Deltas = append(batch.Deltas,
		directoryDelta(t, "AgICAgICAgICAgICAgICAg", "Group.A", "Member.A", sso.DirectoryMembershipRemove),
		directoryDelta(t, "AwMDAwMDAwMDAwMDAwMDAw", "Group.A", "Member.A", sso.DirectoryMembershipAdd),
	)
	first := reconcilerReceipt("AQEBAQEBAQEBAQEBAQEBAQ", identity.CommitOutcomeCommitted)
	second := reconcilerReceipt("AgICAgICAgICAgICAgICAg", identity.CommitOutcomeCommitted)
	wrongUser := second
	wrongUser.Binding.UserID = "OtherUser"
	nativeErr := errors.New("later native child unavailable")
	for _, test := range []struct {
		name         string
		receipts     []sso.Completion
		executionErr error
	}{
		{name: "missing suffix without stop signal", receipts: []sso.Completion{first, second}},
		{name: "wrong mapped user", receipts: []sso.Completion{first, wrongUser}, executionErr: nativeErr},
		{name: "reordered prefix", receipts: []sso.Completion{second, first}, executionErr: nativeErr},
		{name: "skipped first child", receipts: []sso.Completion{second}, executionErr: nativeErr},
		{name: "malformed prefix", receipts: []sso.Completion{first, {}}, executionErr: nativeErr},
	} {
		t.Run(test.name, func(t *testing.T) {
			reconciler := newDirectoryReconciler(t, directoryExecutorFunc(func(context.Context, scimorganization.DirectoryMembershipBatch) ([]sso.Completion, error) {
				return test.receipts, test.executionErr
			}))
			got, err := reconciler.ApplyDirectoryDelta(context.Background(), batch)
			if !errors.Is(err, scimorganization.ErrInvalidDirectoryResult) || !reflect.DeepEqual(got, sso.DirectoryApplyResult{}) {
				t.Fatal("invalid interrupted prefix produced retained results or synthetic outcomes", err)
			}
		})
	}
}

func TestDirectoryReconcilerRejectsInvalidNativeReceipts(t *testing.T) {
	batch := directoryBatch(t)
	batch.Deltas = append(batch.Deltas, directoryDelta(t, "AgICAgICAgICAgICAgICAg", "Group.A", "Member.A", sso.DirectoryMembershipRemove))
	first := reconcilerReceipt("AQEBAQEBAQEBAQEBAQEBAQ", identity.CommitOutcomeCommitted)
	second := reconcilerReceipt("AgICAgICAgICAgICAgICAg", identity.CommitOutcomeNotCommitted)
	foreign := second
	foreign.Binding.TenantID = "OtherTenant"
	wrongCommand := second
	wrongCommand.Binding.CommandID = first.Binding.CommandID
	for name, receipts := range map[string][]sso.Completion{
		"missing all":    nil,
		"extra":          {first, second, second},
		"reordered":      {second, first},
		"foreign tenant": {first, foreign},
		"wrong command":  {first, wrongCommand},
		"invalid":        {first, {}},
	} {
		t.Run(name, func(t *testing.T) {
			reconciler := newDirectoryReconciler(t, directoryExecutorFunc(func(context.Context, scimorganization.DirectoryMembershipBatch) ([]sso.Completion, error) {
				return receipts, errors.New("native failure")
			}))
			got, err := reconciler.ApplyDirectoryDelta(context.Background(), batch)
			if !errors.Is(err, scimorganization.ErrInvalidDirectoryResult) || !reflect.DeepEqual(got, sso.DirectoryApplyResult{}) {
				t.Fatal("invalid evidence produced retained results or synthetic outcomes", err)
			}
		})
	}
}

func TestDirectoryReconcilerCannotLaunderMutatedExecutorInput(t *testing.T) {
	original := directoryBatch(t)
	reconciler := newDirectoryReconciler(t, directoryExecutorFunc(func(_ context.Context, mapped scimorganization.DirectoryMembershipBatch) ([]sso.Completion, error) {
		mapped.Source.Deltas[0] = directoryDelta(t, "AgICAgICAgICAgICAgICAg", "Group.A", "Member.A", sso.DirectoryMembershipRemove)
		mapped.Memberships[0].CommandID = "AgICAgICAgICAgICAgICAg"
		mapped.Memberships[0].Action = sso.DirectoryMembershipRemove
		return []sso.Completion{reconcilerReceipt("AgICAgICAgICAgICAgICAg", identity.CommitOutcomeCommitted)}, nil
	}))
	got, err := reconciler.ApplyDirectoryDelta(context.Background(), original)
	if !errors.Is(err, scimorganization.ErrInvalidDirectoryResult) || !reflect.DeepEqual(got, sso.DirectoryApplyResult{}) {
		t.Fatal("executor mutation laundered another child command into the original batch")
	}
	member, err := original.Deltas[0].GroupMembership()
	if err != nil || member.CommandID != "AQEBAQEBAQEBAQEBAQEBAQ" || member.Action != sso.DirectoryMembershipAdd {
		t.Fatal("executor mutated the original caller batch")
	}
}

func TestDirectoryReconcilerRetainsDetachedOriginalSnapshotAndReceipts(t *testing.T) {
	batch := directoryBatch(t)
	receipts := []sso.Completion{reconcilerReceipt("AQEBAQEBAQEBAQEBAQEBAQ", identity.CommitOutcomeCommitted)}
	reconciler := newDirectoryReconciler(t, directoryExecutorFunc(func(_ context.Context, mapped scimorganization.DirectoryMembershipBatch) ([]sso.Completion, error) {
		mapped.Source.Deltas[0] = sso.DirectoryDelta{}
		mapped.Source.Generation++
		mapped.Source.PredecessorCheckpoint[0]++
		mapped.Memberships[0].TeamID = "OtherTeam"
		return receipts, nil
	}))
	result, err := reconciler.ApplyDirectoryDelta(context.Background(), batch)
	if err != nil {
		t.Fatal("executor mutation invalidated the retained original", err)
	}
	receipts[0].Feature.AfterVersion++
	receipts[0] = sso.Completion{}
	if next, err := result.NextCheckpoint(batch); err != nil || next == ([32]byte{}) || result.ChildOutcomes[0].Feature.AfterVersion != 1 {
		t.Fatal("executor-owned receipt storage aliases the returned result", err)
	}
}

func TestDirectoryReconcilerRejectsReceiptForChangedMappedUser(t *testing.T) {
	reconciler := newDirectoryReconciler(t, directoryExecutorFunc(func(_ context.Context, mapped scimorganization.DirectoryMembershipBatch) ([]sso.Completion, error) {
		mapped.Memberships[0].UserID = "OtherUser"
		receipt := reconcilerReceipt("AQEBAQEBAQEBAQEBAQEBAQ", identity.CommitOutcomeCommitted)
		receipt.Binding.UserID = "OtherUser"
		return []sso.Completion{receipt}, nil
	}))
	got, err := reconciler.ApplyDirectoryDelta(context.Background(), directoryBatch(t))
	if !errors.Is(err, scimorganization.ErrInvalidDirectoryResult) || !reflect.DeepEqual(got, sso.DirectoryApplyResult{}) {
		t.Fatal("executor mutation laundered another local user into the mapped result")
	}
}

func TestDirectoryReconcilerRejectsNilZeroAndCancelledInput(t *testing.T) {
	mapper, err := scimorganization.NewDirectoryMapper(directoryConfig())
	if err != nil {
		t.Fatal(err)
	}
	calls := 0
	executor := directoryExecutorFunc(func(context.Context, scimorganization.DirectoryMembershipBatch) ([]sso.Completion, error) {
		calls++
		return nil, nil
	})
	var typedNil directoryExecutorFunc
	for _, exec := range []scimorganization.DirectoryMembershipExecutor{nil, typedNil} {
		if _, err := scimorganization.NewDirectoryReconciler(mapper, exec); !errors.Is(err, scimorganization.ErrInvalidDirectoryReconciler) {
			t.Fatal("nil executor accepted", err)
		}
	}
	if _, err := scimorganization.NewDirectoryReconciler(scimorganization.DirectoryMapper{}, executor); !errors.Is(err, scimorganization.ErrInvalidDirectoryReconciler) {
		t.Fatal("zero mapper accepted", err)
	}
	var zero scimorganization.DirectoryReconciler
	if _, err := zero.ApplyDirectoryDelta(context.Background(), directoryBatch(t)); !errors.Is(err, scimorganization.ErrInvalidDirectoryReconciler) {
		t.Fatal("zero reconciler accepted input", err)
	}
	reconciler := newDirectoryReconciler(t, executor)
	if _, err := reconciler.ApplyDirectoryDelta(nil, directoryBatch(t)); !errors.Is(err, scimorganization.ErrInvalidDirectoryReconciler) {
		t.Fatal("nil context accepted", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := reconciler.ApplyDirectoryDelta(ctx, directoryBatch(t)); !errors.Is(err, context.Canceled) {
		t.Fatal("caller cancellation was not preserved", err)
	}
	if calls != 0 {
		t.Fatal("invalid or cancelled input reached execution")
	}
}

func TestDirectoryReconcilerRetainsOriginalResultAfterLateCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	reconciler := newDirectoryReconciler(t, directoryExecutorFunc(func(context.Context, scimorganization.DirectoryMembershipBatch) ([]sso.Completion, error) {
		cancel()
		return []sso.Completion{reconcilerReceipt("AQEBAQEBAQEBAQEBAQEBAQ", identity.CommitOutcomeCommitted)}, nil
	}))
	batch := directoryBatch(t)
	result, err := reconciler.ApplyDirectoryDelta(ctx, batch)
	if !errors.Is(err, context.Canceled) || len(result.ChildOutcomes) != 1 || result.ChildOutcomes[0].Outcome != identity.CommitOutcomeCommitted {
		t.Fatal("late cancellation erased a known native commit", err)
	}
	if _, err := result.NextCheckpoint(batch); err != nil {
		t.Fatal("late cancellation damaged original receipt evidence", err)
	}
}

func TestDirectoryReconcilerRedactsImplicitOutput(t *testing.T) {
	reconciler := newDirectoryReconciler(t, directoryExecutorFunc(func(context.Context, scimorganization.DirectoryMembershipBatch) ([]sso.Completion, error) {
		return nil, nil
	}))
	if text := fmt.Sprintf("%+v %#v", reconciler, reconciler); !strings.Contains(text, "redacted") || strings.Contains(text, "Tenant.A") {
		t.Fatal("implicit formatting exposed reconciler composition")
	}
	if _, err := json.Marshal(reconciler); !errors.Is(err, scimorganization.ErrSensitiveSerialization) {
		t.Fatal("reconciler was implicitly serialized", err)
	}
}

type directoryExecutorFunc func(context.Context, scimorganization.DirectoryMembershipBatch) ([]sso.Completion, error)

func (f directoryExecutorFunc) ExecuteMappedDirectoryMemberships(ctx context.Context, batch scimorganization.DirectoryMembershipBatch) ([]sso.Completion, error) {
	return f(ctx, batch)
}

type reconcilerContextKey struct{}

func newDirectoryReconciler(t *testing.T, executor scimorganization.DirectoryMembershipExecutor) scimorganization.DirectoryReconciler {
	t.Helper()
	mapper, err := scimorganization.NewDirectoryMapper(directoryConfig())
	if err != nil {
		t.Fatal(err)
	}
	reconciler, err := scimorganization.NewDirectoryReconciler(mapper, executor)
	if err != nil {
		t.Fatal(err)
	}
	return reconciler
}

func reconcilerReceipt(command identity.CommandID, outcome identity.CommitOutcome) sso.Completion {
	operation := sso.DirectoryTeamMembershipOperation()
	r := identity.CommandResult{
		Binding: identity.CommandBinding{
			CommandID: command, TenantID: "Tenant.A", UserID: "User.A", ActorID: "Service.A",
			ActorKind: authorization.SubjectServiceAccount, OperationID: operation.OperationID,
			PolicyID: "mapping", PolicyVersion: 7, SchemaID: operation.SchemaID, SchemaVersion: 1,
			CorrelationID: "Generation.A", RecordID: "MappedTarget.A",
		},
		Outcome: outcome,
		Feature: &identity.FeatureReceipt{Operation: operation},
	}
	switch outcome {
	case identity.CommitOutcomeCommitted:
		r.Feature.AfterVersion = 1
		r.AuditEventID = "Audit.A"
	case identity.CommitOutcomeInProgress:
		r.RetryAfter = time.Second
	}
	return r
}
