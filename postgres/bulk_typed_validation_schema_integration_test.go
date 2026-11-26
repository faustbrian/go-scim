//go:build integration

package scimpostgres

import (
	"bytes"
	"context"
	"errors"
	"testing"

	migrations "github.com/faustbrian/go-migrations/v3"
	"github.com/jackc/pgx/v5/pgconn"
)

func bulkTypedValidationTestBase() BulkChildExecutionMigrationSource {
	return BulkChildExecutionMigrationSource{
		Base: BulkAdmissionMigrationSource{
			Base: GroupsMigrationSource{
				Base: UsersMigrationSource{Base: MigrationSource{Version: 40}, Version: 41}, Version: 42,
			}, Version: 43,
		}, Version: 44,
	}
}

func TestBulkTypedValidationMigrationPreservesOrderedHistory(t *testing.T) {
	ctx := context.Background()
	base := bulkTypedValidationTestBase()
	for _, previous := range []migrations.Source{base, BulkGroupMutationMigrationSource{Base: base, Version: 45}} {
		before, err := previous.Load(ctx)
		if err != nil {
			t.Fatal(err)
		}
		after, err := (BulkTypedValidationMigrationSource{Base: previous, Version: 46, ValidationVersion: 48}).Load(ctx)
		if err != nil || len(after) != len(before)+2 {
			t.Fatal("typed validation did not append expansion and separate validation", err)
		}
		for index := range before {
			if before[index] != after[index] {
				t.Fatal("typed validation rewrote an installed migration", index)
			}
		}
		expand, validate := after[len(before)], after[len(before)+1]
		if expand.Version() != 46 || validate.Version() != 48 || expand.DownSQL() != "" || validate.DownSQL() != "" ||
			expand.TransactionMode() != migrations.TransactionModeDefault || validate.TransactionMode() != migrations.TransactionModeDefault {
			t.Fatal("typed validation lost ordered forward-only transactional steps")
		}
	}
	var missing *MigrationSource
	for _, source := range []BulkTypedValidationMigrationSource{
		{},
		{Base: missing, Version: 46, ValidationVersion: 47},
		{Base: base.Base, Version: 46, ValidationVersion: 47},
		{Base: base, Version: 44, ValidationVersion: 47},
		{Base: base, Version: 46},
		{Base: base, Version: 46, ValidationVersion: 46},
		{Base: base, Version: 46, ValidationVersion: 45},
		{Base: base, Version: 1 << 63, ValidationVersion: 1<<63 + 1},
		{Base: base, Version: 46, ValidationVersion: 1 << 63},
	} {
		if history, err := source.Load(ctx); !errors.Is(err, ErrInvalidConfiguration) || len(history) != 0 {
			t.Fatal("invalid typed validation history admitted", err)
		}
	}
	source := BulkTypedValidationMigrationSource{Base: base, Version: 46, ValidationVersion: 47}
	if _, err := source.Load(nil); !errors.Is(err, ErrInvalidConfiguration) {
		t.Fatal("nil migration context admitted", err)
	}
	cancelled, cancel := context.WithCancel(ctx)
	cancel()
	if _, err := source.Load(cancelled); !errors.Is(err, context.Canceled) {
		t.Fatal("cancelled typed validation declaration succeeded", err)
	}
}

func TestNativeBulkTypedValidationSchemaPreservesLegacyRowsAndRejectsInvalidShapes(t *testing.T) {
	f, service := bulkChildExecutionFixture(t)
	terminal := BulkAdmissionRequest{Credential: f.bearer, Body: []byte(failedThenIndependentGroupBulk)}
	for ordinal := range 2 {
		if _, err := service.ExecuteChild(f.ctx, terminal, ordinal); err != nil {
			t.Fatal("populate terminal results before expansion", err)
		}
	}
	wire, err := service.ReadResult(f.ctx, terminal)
	if err != nil {
		t.Fatal("read pre-expansion terminal result", err)
	}
	pending, err := service.Admit(f.ctx, BulkAdmissionRequest{Credential: f.bearer, Body: []byte(dependentGroupBulkFixture)})
	if err != nil {
		t.Fatal("admit an unprocessed row before expansion", err)
	}
	child := originalBulkChild(t, f, pending, 0)
	var before string
	if err := f.pool.Raw().QueryRow(f.ctx, `SELECT jsonb_agg(to_jsonb(b) ORDER BY parent_id,ordinal)::text FROM scim.bulk_children b`).Scan(&before); err != nil {
		t.Fatal(err)
	}
	history, err := (BulkTypedValidationMigrationSource{Base: bulkTypedValidationTestBase(), Version: 46, ValidationVersion: 48}).Load(f.ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.pool.Raw().Exec(f.ctx, history[len(history)-2].UpSQL()); err != nil {
		t.Fatal("expand populated result storage", err)
	}
	var after string
	var allNull, noDefault, validated bool
	if err := f.pool.Raw().QueryRow(f.ctx, `SELECT jsonb_agg(to_jsonb(b)-'result_denial_code' ORDER BY parent_id,ordinal)::text,
 bool_and(result_denial_code IS NULL) FROM scim.bulk_children b`).Scan(&after, &allNull); err != nil || after != before || !allNull {
		t.Fatal("expansion changed legacy bytes or backfilled a synthetic denial", err)
	}
	if err := f.pool.Raw().QueryRow(f.ctx, `SELECT column_default IS NULL AND is_nullable='YES' AND data_type='smallint'
 FROM information_schema.columns WHERE table_schema='scim' AND table_name='bulk_children' AND column_name='result_denial_code'`).Scan(&noDefault); err != nil || !noDefault {
		t.Fatal("expansion must add only a nullable smallint without a default", err)
	}
	if err := f.pool.Raw().QueryRow(f.ctx, `SELECT convalidated FROM pg_constraint WHERE conrelid='scim.bulk_children'::regclass AND conname='bulk_typed_validation_result_shape'`).Scan(&validated); err != nil || validated {
		t.Fatal("expansion scanned and validated the old table", err)
	}
	if again, err := service.ReadResult(f.ctx, terminal); err != nil || !bytes.Equal(wire, again) {
		t.Fatal("expansion changed an existing terminal response", err)
	}

	for _, invalid := range []struct {
		name, shape string
	}{
		{"legacy code", `result_denial_code=12`},
		{"unknown code", `result_denial_code=18`},
		{"zero code", `result_denial_code=0`},
		{"missing HTTP code", `result_code=NULL`},
		{"different HTTP code", `result_code=409`},
		{"missing retained ID", `result_resource_id=NULL`},
		{"empty retained ID", `result_resource_id=''`},
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
			if _, err := tx.Exec(f.ctx, `UPDATE scim.bulk_children SET status='failed',result_code=400,
 result_resource_id=resource_id,result_version=NULL,result_denial_code=13 WHERE command_id=$1`, child.command); err != nil {
				t.Fatal("valid typed denial was rejected before the invalid variation", err)
			}
			_, err = tx.Exec(f.ctx, `UPDATE scim.bulk_children SET `+invalid.shape+` WHERE command_id=$1`, child.command)
			var check *pgconn.PgError
			if !errors.As(err, &check) || check.Code != "23514" {
				t.Fatal("new invalid result shape passed the database constraints", err)
			}
		})
	}
	for code := 13; code <= 17; code++ {
		tx, err := f.pool.Raw().Begin(f.ctx)
		if err != nil {
			t.Fatal(err)
		}
		_, err = tx.Exec(f.ctx, `UPDATE scim.bulk_children SET status='failed',result_code=400,
 result_resource_id=resource_id,result_version=NULL,result_denial_code=$2 WHERE command_id=$1`, child.command, code)
		rollbackErr := tx.Rollback(f.ctx)
		if err != nil || rollbackErr != nil {
			t.Fatal("closed typed denial code was rejected", code, err, rollbackErr)
		}
	}
	tx, err := f.pool.Raw().Begin(f.ctx)
	if err != nil {
		t.Fatal(err)
	}
	_, err = tx.Exec(f.ctx, `UPDATE scim.bulk_children SET status='failed',result_code=400,
 resource_id='',result_resource_id=$2,result_version=NULL,result_denial_code=13 WHERE command_id=$1`, child.command, child.resource)
	rollbackErr := tx.Rollback(f.ctx)
	if err != nil || rollbackErr != nil {
		t.Fatal("mutation without an allocated create ID must retain its resolved target", err, rollbackErr)
	}
	if _, err := f.pool.Raw().Exec(f.ctx, history[len(history)-1].UpSQL()); err != nil {
		t.Fatal("validate the additive check in its later migration", err)
	}
	if err := f.pool.Raw().QueryRow(f.ctx, `SELECT convalidated FROM pg_constraint WHERE conrelid='scim.bulk_children'::regclass AND conname='bulk_typed_validation_result_shape'`).Scan(&validated); err != nil || !validated {
		t.Fatal("later migration did not validate the check", err)
	}
	if err := f.pool.Raw().QueryRow(f.ctx, `SELECT jsonb_agg(to_jsonb(b)-'result_denial_code' ORDER BY parent_id,ordinal)::text FROM scim.bulk_children b`).Scan(&after); err != nil || after != before {
		t.Fatal("constraint probes or validation changed retained rows", err)
	}
}
