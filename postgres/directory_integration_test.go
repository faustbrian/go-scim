//go:build integration

package scimpostgres

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/faustbrian/go-clock"
	identity "github.com/faustbrian/go-identity"
	scim "github.com/faustbrian/go-scim"
)

type executionResult struct {
	response scim.Response
	err      error
}

func directoryCreate(f *nativeFixture, key string) scim.Request {
	return scim.Request{Operation: scim.UserCreate, Credential: f.bearer, IdempotencyKey: key, ContentType: "application/scim+json", Body: []byte(`{"schemas":["urn:ietf:params:scim:schemas:core:2.0:User"],"userName":"EpochGuard","displayName":"Actual native effect"}`)}
}

func assertNoNativeUsers(t *testing.T, f *nativeFixture) {
	t.Helper()
	var users, projections int
	if err := f.pool.Raw().QueryRow(f.ctx, `SELECT (SELECT count(*) FROM identity.users),(SELECT count(*) FROM scim.users)`).Scan(&users, &projections); err != nil {
		t.Fatal(err)
	}
	if users != 0 || projections != 0 {
		t.Fatal("changed original directory authority committed native effects", users, projections)
	}
}

func TestNativeDirectoryEpochChangedDuringAdmission(t *testing.T) {
	for _, kind := range []string{"global", "tenant"} {
		t.Run(kind, func(t *testing.T) {
			f := newNativeFixture(t)
			entered, release, finished := make(chan struct{}), make(chan struct{}), make(chan struct{})
			var admissionOnce, releaseOnce sync.Once
			// A bounded timing barrier in the real field owner's pure validation
			// callback lets another genuine primary connection advance the epoch.
			// It supplies no storage, authentication or Boolean permission proof.
			fields, err := identity.NewAttributeProcessor(f.config.FieldSchema, f.config.Authorization, func(_ context.Context, _ identity.NormalizationPolicy, v identity.AttributeScalar) (identity.AttributeScalar, error) {
				return v, nil
			}, identity.AttributeProcessorConfig{Clock: clock.System{}, MaximumDuration: time.Second, PolicyVersion: 1, ValidateCanonicalUserID: func(_ context.Context, id identity.UserID) error {
				_, err := identity.ParseSubjectID(string(id))
				return err
			}, ValidateValue: func(ctx context.Context, _ identity.FieldPolicy, _ identity.AttributeValue) error {
				var waitErr error
				admissionOnce.Do(func() {
					close(entered)
					select {
					case <-release:
					case <-ctx.Done():
						waitErr = ctx.Err()
					}
				})
				return waitErr
			}})
			if err != nil {
				t.Fatal(err)
			}
			c := f.config
			c.Fields = fields
			service, err := NewService(f.pool, c, f.keys)
			if err != nil {
				t.Fatal(err)
			}
			results := make(chan executionResult, 1)
			go func() {
				defer close(finished)
				response, err := service.Execute(f.ctx, directoryCreate(f, "epoch-admission"))
				results <- executionResult{response, err}
			}()
			defer func() {
				releaseOnce.Do(func() { close(release) })
				select {
				case <-finished:
				case <-f.ctx.Done():
					t.Error("native admission did not terminate")
				}
			}()
			select {
			case <-entered:
			case result := <-results:
				t.Fatalf("actual native admission not reached, status=%d error=%v", result.response.Status, result.err)
			case <-f.ctx.Done():
				t.Fatal("admission barrier timed out")
			}
			sql := `UPDATE identity.tenant_authorities SET version=version+1 WHERE tenant_id='tenant-a'`
			if kind == "global" {
				sql = `UPDATE identity.global_authorities SET version=version+1 WHERE authority_id='scim-deployment'`
			}
			if _, err := f.pool.Raw().Exec(f.ctx, sql); err != nil {
				t.Fatal("actual epoch change", err)
			}
			releaseOnce.Do(func() { close(release) })
			select {
			case result := <-results:
				if result.err == nil || len(result.response.Body) != 0 {
					t.Error("enabled but changed original epoch accepted", result.response.Status)
				}
			case <-f.ctx.Done():
				t.Fatal("native execution did not terminate")
			}
			assertNoNativeUsers(t, f)
		})
	}
}

func TestNativeDirectoryEpochChangedWhileWaitingForActualFence(t *testing.T) {
	f := newNativeFixture(t)
	tx, err := f.pool.Raw().Begin(f.ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(context.Background())
	var blocker int32
	if err := tx.QueryRow(f.ctx, `SELECT pg_backend_pid()`).Scan(&blocker); err != nil {
		t.Fatal(err)
	}
	if _, err := tx.Exec(f.ctx, `UPDATE identity.tenant_authorities SET version=version+1 WHERE tenant_id='tenant-a'`); err != nil {
		t.Fatal(err)
	}
	results := make(chan executionResult, 1)
	go func() {
		response, err := f.service.Execute(f.ctx, directoryCreate(f, "epoch-lock-wait"))
		results <- executionResult{response, err}
	}()
	deadline := time.NewTimer(2 * time.Second)
	defer deadline.Stop()
	poll := time.NewTicker(5 * time.Millisecond)
	defer poll.Stop()
	waiting := false
	for !waiting {
		select {
		case result := <-results:
			t.Fatalf("native effect bypassed actual directory row fence, status=%d error=%v", result.response.Status, result.err)
		case <-deadline.C:
			t.Fatal("actual directory row lock wait was not observed")
		case <-poll.C:
			var count int
			if err := f.pool.Raw().QueryRow(f.ctx, `SELECT count(*) FROM pg_stat_activity a WHERE a.datname=current_database() AND $1=ANY(pg_blocking_pids(a.pid)) AND a.wait_event_type='Lock'`, blocker).Scan(&count); err != nil {
				t.Fatal(err)
			}
			waiting = count > 0
		}
	}
	if err := tx.Commit(f.ctx); err != nil {
		t.Fatal("commit actual epoch successor", err)
	}
	select {
	case result := <-results:
		if result.err == nil || len(result.response.Body) != 0 {
			t.Error("changed epoch after real lock wait accepted", result.response.Status)
		}
	case <-f.ctx.Done():
		t.Fatal("native execution did not terminate")
	}
	assertNoNativeUsers(t, f)
}
