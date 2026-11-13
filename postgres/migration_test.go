package scimpostgres

import (
	"context"
	"strings"
	"testing"

	migrations "github.com/faustbrian/go-migrations/v3"
)

func TestNativeMigrationOwnsOnlyNewSCIMState(t *testing.T) {
	for _, version := range []migrations.Version{0, 1 << 63} {
		if history, err := (MigrationSource{Version: version}).Load(context.Background()); err == nil || len(history) != 0 {
			t.Fatal("invalid migration version accepted")
		}
	}
	history, err := (MigrationSource{Version: 40}).Load(context.Background())
	if err != nil || len(history) != 1 || history[0].Version() != 40 || history[0].DownSQL() != "" {
		t.Fatal("forward schema declaration", err)
	}
	sql := history[0].UpSQL()
	for _, required := range []string{"CREATE SCHEMA scim", "CREATE TABLE scim.connections", "CREATE TABLE scim.users", "username_key", "external_id", "configuration_digest", "credential_digest"} {
		if !strings.Contains(sql, required) {
			t.Fatal("missing owned schema", required)
		}
	}
	for _, forbidden := range []string{"CREATE TABLE identity.", "CREATE TABLE organization.", "CREATE TABLE audit.", "CREATE TABLE public.outbox", "scim.commands", "scim.request_keys"} {
		if strings.Contains(sql, forbidden) {
			t.Fatal("duplicate owner", forbidden)
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := (MigrationSource{Version: 40}).Load(ctx); err == nil {
		t.Fatal("cancelled migration succeeded")
	}
}
