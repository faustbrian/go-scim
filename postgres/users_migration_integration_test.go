//go:build integration

package scimpostgres

import (
	"context"
	"errors"
	"testing"
	"time"

	scim "github.com/faustbrian/go-scim"
	"github.com/jackc/pgx/v5/pgconn"
)

func TestNativeUsersForwardMigrationKeepsPopulatedProjection(t *testing.T) {
	f := newNativeFixture(t)
	id := createNativeNamed(t, f, "InstalledBeforeMigration", "Retained original fields")
	var original []byte
	if err := f.pool.Raw().QueryRow(f.ctx, `SELECT resource FROM scim.users WHERE resource_id=$1`, id).Scan(&original); err != nil {
		t.Fatal(err)
	}
	// This database belongs only to this fixture. Return its populated SCIM
	// table to the unchanged published predecessor shape before exercising the
	// forward step; no production down migration or user data is involved.
	if _, err := f.pool.Raw().Exec(f.ctx, `ALTER TABLE scim.users DROP COLUMN generation,DROP COLUMN deleted_at`); err != nil {
		t.Fatal("prepare populated predecessor", err)
	}
	history, err := (UsersMigrationSource{Base: MigrationSource{Version: 40}, Version: 41}).Load(f.ctx)
	if err != nil {
		t.Fatal(err)
	}
	tx, err := f.pool.Raw().Begin(f.ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(context.Background())
	if _, err := tx.Exec(f.ctx, `SELECT resource FROM scim.users WHERE resource_id=$1`, id); err != nil {
		t.Fatal("hold actual reader metadata lock", err)
	}
	start := time.Now()
	_, err = f.pool.Raw().Exec(f.ctx, history[1].UpSQL())
	var locked *pgconn.PgError
	if !errors.As(err, &locked) || locked.Code != "55P03" || time.Since(start) >= 8*time.Second {
		t.Fatal("forward metadata acquisition did not fail at its bounded lock timeout", err)
	}
	if err := tx.Rollback(f.ctx); err != nil {
		t.Fatal("release fixture reader", err)
	}
	if _, err := f.pool.Raw().Exec(f.ctx, history[1].UpSQL()); err != nil {
		t.Fatal("forward installation after reader release", err)
	}
	var generation int64
	var stored []byte
	var deleted *time.Time
	if err := f.pool.Raw().QueryRow(f.ctx, `SELECT generation,resource,deleted_at FROM scim.users WHERE resource_id=$1`, id).Scan(&generation, &stored, &deleted); err != nil || generation != 1 || deleted != nil || string(stored) != string(original) {
		t.Fatal("metadata expansion changed populated projection/initial generation", err)
	}
	response, err := f.service.Execute(f.ctx, scim.Request{Operation: scim.UserGet, Credential: f.bearer, ResourceID: id})
	if err != nil || response.Status != 200 || parseNativeUser(t, response).UserName != "InstalledBeforeMigration" {
		t.Fatal("forward installation did not preserve native reader", err)
	}
}
