//go:build integration

package scimpostgres

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"testing"

	migrations "github.com/faustbrian/go-migrations/v3"
	"github.com/jackc/pgx/v5/pgconn"
)

func bulkSnapshotValidationTestBase() BulkTypedValidationMigrationSource {
	return BulkTypedValidationMigrationSource{Base: bulkTypedValidationTestBase(), Version: 46, ValidationVersion: 47}
}

func expandBulkSnapshotValidation(t *testing.T, f *nativeFixture, base migrations.Source) {
	t.Helper()
	history, err := (BulkSnapshotValidationMigrationSource{Base: base, Version: 48, ValidationVersion: 49}).Load(f.ctx)
	if err != nil {
		t.Fatal("load snapshot validation expansion", err)
	}
	if _, err := f.pool.Raw().Exec(f.ctx, history[len(history)-2].UpSQL()); err != nil {
		t.Fatal("expand Bulk before enabling snapshot validation", err)
	}
}

type bulkSnapshotValidationHistory []migrations.Migration

func (s bulkSnapshotValidationHistory) Load(context.Context) ([]migrations.Migration, error) {
	return slices.Clone(s), nil
}

func TestBulkSnapshotValidationMigrationPreservesOrderedHistory(t *testing.T) {
	ctx := context.Background()
	base := bulkSnapshotValidationTestBase()
	for _, previous := range []migrations.Source{
		base,
		BulkTypedValidationMigrationSource{
			Base:    BulkGroupMutationMigrationSource{Base: bulkTypedValidationTestBase(), Version: 45},
			Version: 46, ValidationVersion: 47,
		},
	} {
		before, err := previous.Load(ctx)
		if err != nil {
			t.Fatal(err)
		}
		after, err := (BulkSnapshotValidationMigrationSource{Base: previous, Version: 48, ValidationVersion: 50}).Load(ctx)
		if err != nil || len(after) != len(before)+2 {
			t.Fatal("snapshot validation did not append expansion and separate validation", err)
		}
		for index := range before {
			if before[index] != after[index] {
				t.Fatal("snapshot validation rewrote an installed migration", index)
			}
		}
		expand, validate := after[len(before)], after[len(before)+1]
		if expand.Version() != 48 || validate.Version() != 50 || expand.DownSQL() != "" || validate.DownSQL() != "" ||
			expand.TransactionMode() != migrations.TransactionModeDefault || validate.TransactionMode() != migrations.TransactionModeDefault {
			t.Fatal("snapshot validation lost ordered forward-only transactional steps")
		}
	}
	before, err := base.Load(ctx)
	if err != nil {
		t.Fatal(err)
	}
	var missing *MigrationSource
	for _, source := range []BulkSnapshotValidationMigrationSource{
		{},
		{Base: missing, Version: 48, ValidationVersion: 49},
		{Base: bulkTypedValidationTestBase(), Version: 48, ValidationVersion: 49},
		{Base: bulkSnapshotValidationHistory(before[:len(before)-1]), Version: 48, ValidationVersion: 49},
		{Base: bulkSnapshotValidationHistory(append(slices.Clone(before[:len(before)-2]), before[len(before)-1])), Version: 48, ValidationVersion: 49},
		{Base: base, Version: 47, ValidationVersion: 49},
		{Base: base, Version: 48},
		{Base: base, Version: 48, ValidationVersion: 48},
		{Base: base, Version: 48, ValidationVersion: 47},
		{Base: base, Version: 1 << 63, ValidationVersion: 1<<63 + 1},
		{Base: base, Version: 48, ValidationVersion: 1 << 63},
	} {
		if history, err := source.Load(ctx); !errors.Is(err, ErrInvalidConfiguration) || len(history) != 0 {
			t.Fatal("invalid snapshot validation history admitted", err)
		}
	}
	source := BulkSnapshotValidationMigrationSource{Base: base, Version: 48, ValidationVersion: 49}
	if _, err := source.Load(nil); !errors.Is(err, ErrInvalidConfiguration) {
		t.Fatal("nil migration context admitted", err)
	}
	cancelled, cancel := context.WithCancel(ctx)
	cancel()
	if _, err := source.Load(cancelled); !errors.Is(err, context.Canceled) {
		t.Fatal("cancelled snapshot validation declaration succeeded", err)
	}
}

func TestNativeBulkSnapshotValidationSchemaPreservesTypedRowsAndExpandsOnlyCodeRange(t *testing.T) {
	f, service := bulkChildExecutionFixture(t)
	expandBulkTypedValidation(t, f, bulkTypedValidationTestBase())
	base := bulkSnapshotValidationTestBase()
	oldHistory, err := base.Load(f.ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.pool.Raw().Exec(f.ctx, oldHistory[len(oldHistory)-1].UpSQL()); err != nil {
		t.Fatal("validate the installed typed denial constraint", err)
	}
	var probe admittedBulkChild
	for code := 13; code <= 17; code++ {
		body := fmt.Sprintf(`{"schemas":["urn:ietf:params:scim:api:messages:2.0:BulkRequest"],"Operations":[{"method":"POST","path":"/Groups","bulkId":"typed-%d","data":{"schemas":["urn:ietf:params:scim:schemas:core:2.0:Group"],"displayName":"Retained %d"}}]}`, code, code)
		parent, err := service.Admit(f.ctx, BulkAdmissionRequest{Credential: f.bearer, Body: []byte(body)})
		if err != nil {
			t.Fatal("admit a row before snapshot expansion", err)
		}
		probe = originalBulkChild(t, f, parent, 0)
		if _, err := f.pool.Raw().Exec(f.ctx, `UPDATE scim.bulk_children SET status='failed',result_code=400,
 result_resource_id=resource_id,result_version=NULL,result_denial_code=$2 WHERE command_id=$1`, probe.command, code); err != nil {
			t.Fatal("retain a previously supported typed checkpoint", code, err)
		}
	}
	var before string
	if err := f.pool.Raw().QueryRow(f.ctx, `SELECT jsonb_agg(to_jsonb(b) ORDER BY parent_id,ordinal)::text FROM scim.bulk_children b`).Scan(&before); err != nil {
		t.Fatal(err)
	}
	tx, err := f.pool.Raw().Begin(f.ctx)
	if err != nil {
		t.Fatal(err)
	}
	_, err = tx.Exec(f.ctx, `UPDATE scim.bulk_children SET result_denial_code=18 WHERE command_id=$1`, probe.command)
	rollbackErr := tx.Rollback(f.ctx)
	var check *pgconn.PgError
	if !errors.As(err, &check) || check.Code != "23514" || check.ConstraintName != "bulk_typed_validation_result_shape" || rollbackErr != nil {
		t.Fatal("the old typed constraint must reject noTarget before expansion", err, rollbackErr)
	}

	history, err := (BulkSnapshotValidationMigrationSource{Base: base, Version: 48, ValidationVersion: 49}).Load(f.ctx)
	if err != nil {
		t.Fatal(err)
	}
	expandBulkSnapshotValidation(t, f, base)
	assertBulkSnapshotRowsUnchanged(t, f, before)
	var validated bool
	if err := f.pool.Raw().QueryRow(f.ctx, `SELECT convalidated FROM pg_constraint WHERE conrelid='scim.bulk_children'::regclass AND conname='bulk_typed_validation_result_shape'`).Scan(&validated); err != nil || validated {
		t.Fatal("snapshot expansion must not validate retained rows under its adding lock", err)
	}
	for _, invalid := range []struct{ name, shape string }{
		{"legacy code", `result_denial_code=12`},
		{"unknown code", `result_denial_code=19`},
		{"zero code", `result_denial_code=0`},
		{"missing HTTP code", `result_code=NULL`},
		{"different HTTP code", `result_code=409`},
		{"missing retained ID", `result_resource_id=NULL`},
		{"empty retained ID", `result_resource_id=''`},
		{"oversized retained ID", `result_resource_id=repeat('A',129)`},
		{"different retained ID", `result_resource_id='AAAAAAAAAAAAAAAAAAAAAA'`},
		{"version on failure", `result_version='W/"v"'`},
		{"cyclic child", `cyclic=true`},
		{"successful child", `status='succeeded',result_code=201,result_version='W/"v"'`},
		{"unprocessed child", `status='admitted',result_code=NULL,result_resource_id=NULL`},
	} {
		t.Run(invalid.name, func(t *testing.T) {
			tx, err := f.pool.Raw().Begin(f.ctx)
			if err != nil {
				t.Fatal(err)
			}
			defer tx.Rollback(f.ctx)
			if _, err := tx.Exec(f.ctx, `UPDATE scim.bulk_children SET result_denial_code=18 WHERE command_id=$1`, probe.command); err != nil {
				t.Fatal("snapshot noTarget must fit the expanded typed checkpoint", err)
			}
			_, err = tx.Exec(f.ctx, `UPDATE scim.bulk_children SET `+invalid.shape+` WHERE command_id=$1`, probe.command)
			var check *pgconn.PgError
			if !errors.As(err, &check) || check.Code != "23514" {
				t.Fatal("snapshot expansion weakened an existing result predicate", err)
			}
		})
	}
	for code := 13; code <= 18; code++ {
		tx, err := f.pool.Raw().Begin(f.ctx)
		if err != nil {
			t.Fatal(err)
		}
		_, err = tx.Exec(f.ctx, `UPDATE scim.bulk_children SET result_denial_code=$2 WHERE command_id=$1`, probe.command, code)
		rollbackErr := tx.Rollback(f.ctx)
		if err != nil || rollbackErr != nil {
			t.Fatal("expanded closed typed code range rejected", code, err, rollbackErr)
		}
	}
	tx, err = f.pool.Raw().Begin(f.ctx)
	if err != nil {
		t.Fatal(err)
	}
	_, err = tx.Exec(f.ctx, `UPDATE scim.bulk_children SET resource_id='',result_denial_code=18 WHERE command_id=$1`, probe.command)
	rollbackErr = tx.Rollback(f.ctx)
	if err != nil || rollbackErr != nil {
		t.Fatal("noTarget mutation may retain its resolved ID without an allocated create ID", err, rollbackErr)
	}
	if _, err := f.pool.Raw().Exec(f.ctx, history[len(history)-1].UpSQL()); err != nil {
		t.Fatal("validate the expanded constraint in its later migration", err)
	}
	if err := f.pool.Raw().QueryRow(f.ctx, `SELECT convalidated FROM pg_constraint WHERE conrelid='scim.bulk_children'::regclass AND conname='bulk_typed_validation_result_shape'`).Scan(&validated); err != nil || !validated {
		t.Fatal("later snapshot migration did not validate the expanded constraint", err)
	}
	assertBulkSnapshotRowsUnchanged(t, f, before)
}

func assertBulkSnapshotRowsUnchanged(t *testing.T, f *nativeFixture, before string) {
	t.Helper()
	var after string
	if err := f.pool.Raw().QueryRow(f.ctx, `SELECT jsonb_agg(to_jsonb(b) ORDER BY parent_id,ordinal)::text FROM scim.bulk_children b`).Scan(&after); err != nil || after != before {
		t.Fatal("snapshot constraint expansion or rolled-back probes changed retained rows", err)
	}
}
