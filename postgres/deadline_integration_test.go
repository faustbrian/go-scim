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

type observedOriginal struct {
	started, until time.Time
	id             string
}

func TestNativeOriginalAdmissionExpiryAndCurrentReplay(t *testing.T) {
	f := newNativeFixture(t)
	pendingSource, cancelledSource := make(chan observedOriginal, 1), make(chan observedOriginal, 1)
	var pendingOnce, cancelledOnce sync.Once
	fields, err := identity.NewAttributeProcessor(f.config.FieldSchema, f.config.Authorization, func(_ context.Context, _ identity.NormalizationPolicy, v identity.AttributeScalar) (identity.AttributeScalar, error) {
		return v, nil
	}, identity.AttributeProcessorConfig{Clock: clock.System{}, MaximumDuration: time.Second, PolicyVersion: 1, ValidateCanonicalUserID: func(_ context.Context, id identity.UserID) error {
		_, err := identity.ParseSubjectID(string(id))
		return err
	}, ValidateValue: func(ctx context.Context, _ identity.FieldPolicy, _ identity.AttributeValue) error {
		i, err := currentInvocation(ctx)
		if err != nil || i.phase == nil {
			return err
		}
		var once *sync.Once
		var source chan observedOriginal
		switch i.phase.intent.IdempotencyKey {
		case "original-pending":
			once, source = &pendingOnce, pendingSource
		case "cancelled-then-retried":
			once, source = &cancelledOnce, cancelledSource
		default:
			return nil
		}
		var admissionErr error
		once.Do(func() {
			// Observe the actual authenticated producer, without changing its clock.
			source <- observedOriginal{i.connection.AuthorityReadBeganAt, i.connection.AuthorityValidUntil, i.phase.original.ID}
			<-ctx.Done()
			admissionErr = ctx.Err()
		})
		return admissionErr
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
	pending := directoryCreate(f, "original-pending")
	pending.Body = []byte(`{"schemas":["urn:ietf:params:scim:schemas:core:2.0:User"],"userName":"NeverCommitted","displayName":"Expired original"}`)
	commit := directoryCreate(f, "cancelled-then-retried")
	commit.Body = []byte(`{"schemas":["urn:ietf:params:scim:schemas:core:2.0:User"],"userName":"PreviouslyCommitted","displayName":"Current replay"}`)
	for _, request := range []scim.Request{pending, commit} {
		short, stop := context.WithTimeout(f.ctx, 500*time.Millisecond)
		response, protocolErr := service.Execute(short, request)
		cancelled := short.Err() != nil
		stop()
		if protocolErr == nil || len(response.Body) != 0 || !cancelled {
			t.Fatal("original caller cancellation was not exercised", protocolErr)
		}
	}
	pendingEvidence, cancelledEvidence := <-pendingSource, <-cancelledSource
	for _, evidence := range []observedOriginal{pendingEvidence, cancelledEvidence} {
		if evidence.id == "" || !evidence.until.After(evidence.started) || evidence.until.Sub(evidence.started) > 20*time.Second || !time.Now().Before(evidence.until) {
			t.Fatal("actual original bounded authority was not observed")
		}
	}
	// Cancellation bounds one invocation, not correlation while original evidence is valid.
	created, protocolErr := service.Execute(f.ctx, commit)
	if protocolErr != nil || created.Status != 201 {
		t.Fatal("cancelled caller incorrectly tombstoned valid original authority", protocolErr)
	}
	until := pendingEvidence.until
	if cancelledEvidence.until.After(until) {
		until = cancelledEvidence.until
	}
	timer := time.NewTimer(time.Until(until.Add(10 * time.Millisecond)))
	defer timer.Stop()
	select {
	case <-timer.C:
	case <-f.ctx.Done():
		t.Fatal("actual authoritative expiry was not reached")
	}
	if !time.Now().After(pendingEvidence.until) || !time.Now().After(cancelledEvidence.until) {
		t.Fatal("original authority has not actually expired")
	}
	if response, err := service.Execute(f.ctx, pending); err == nil || len(response.Body) != 0 {
		t.Error("retry renewed expired authoritative evidence", response.Status)
	}
	var users, projections int
	if err := f.pool.Raw().QueryRow(f.ctx, `SELECT (SELECT count(*) FROM identity.users WHERE tenant_id='tenant-a' AND user_id=$1),(SELECT count(*) FROM scim.users WHERE tenant_id='tenant-a' AND user_id=$1)`, pendingEvidence.id).Scan(&users, &projections); err != nil || users != 0 || projections != 0 {
		t.Error("expired original caused new native effects", users, projections, err)
	}
	if _, err := f.pool.Raw().Exec(f.ctx, `UPDATE identity.tenant_authorities SET version=version+1 WHERE tenant_id='tenant-a'`); err != nil {
		t.Fatal(err)
	}
	// Known committed history requires current genuine admission, not another Apply.
	replayed, replayErr := service.Execute(f.ctx, commit)
	if replayErr != nil || replayed.Status != 201 || replayed.ETag != created.ETag || string(replayed.Body) != string(created.Body) {
		t.Fatal("current admitted committed replay became permanently unreadable", replayErr)
	}
	if initialized, err := service.InitializeConfiguredConnection(f.ctx); err != nil || initialized.Outcome != identity.CommitOutcomeCommitted {
		t.Fatal("current admitted bootstrap history became unreadable", err)
	}
	fresh := directoryCreate(f, "fresh-after-enabled-epoch")
	fresh.Body = []byte(`{"schemas":["urn:ietf:params:scim:schemas:core:2.0:User"],"userName":"FreshAfterEpoch","displayName":"Fresh authority"}`)
	if result, err := service.Execute(f.ctx, fresh); err != nil || result.Status != 201 {
		t.Fatal("enabled epoch bump permanently revoked otherwise active credential", err)
	}
}
