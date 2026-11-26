//go:build integration

package scimpostgres

import (
	"errors"
	"testing"

	"github.com/jackc/pgx/v5/pgconn"
)

func installBulkGroupMutationSchema(t *testing.T, f *nativeFixture) {
	t.Helper()
	source := BulkGroupMutationMigrationSource{
		Base: BulkChildExecutionMigrationSource{
			Base: BulkAdmissionMigrationSource{
				Base: GroupsMigrationSource{
					Base: UsersMigrationSource{Base: MigrationSource{Version: 40}, Version: 41}, Version: 42,
				}, Version: 43,
			}, Version: 44,
		}, Version: 45,
	}
	history, err := source.Load(f.ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.pool.Raw().Exec(f.ctx, history[len(history)-1].UpSQL()); err != nil {
		t.Fatal("expand an existing Bulk graph", err)
	}
}

func TestNativeGroupBulkMutationSchemaPreservesAdmittedChildren(t *testing.T) {
	f, service := bulkChildExecutionFixture(t)
	request := BulkAdmissionRequest{Credential: f.bearer, Body: []byte(dependentGroupBulkFixture)}
	parent, err := service.Admit(f.ctx, request)
	if err != nil {
		t.Fatal("admit children before expanding their schema", err)
	}
	first := originalBulkChild(t, f, parent, 0)
	installBulkGroupMutationSchema(t, f)
	var absent bool
	if err := f.pool.Raw().QueryRow(f.ctx, `SELECT group_mutation_input IS NULL FROM scim.bulk_children WHERE command_id=$1`, first.command).Scan(&absent); err != nil || !absent {
		t.Fatal("old child acquired synthetic preparation", err)
	}
	_, err = f.pool.Raw().Exec(f.ctx, `UPDATE scim.bulk_children SET group_mutation_input=$2 WHERE command_id=$1`, first.command, make([]byte, originalCiphertextBytes+1))
	var check *pgconn.PgError
	if !errors.As(err, &check) || check.Code != "23514" || check.ConstraintName != "bulk_group_mutation_input_size" {
		t.Fatal("oversized new input was not denied by the new column check", err)
	}
	result, err := service.ExecuteChild(f.ctx, request, 0)
	if err != nil || result.Code != 201 || result.ResourceID != first.resource {
		t.Fatal("schema expansion changed existing Group create or allocation", err)
	}
}
