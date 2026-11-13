package scimpostgres

import (
	"context"
	"testing"

	migrations "github.com/faustbrian/go-migrations/v3"
)

func TestUsersMigrationRequiresOrderedOwnedHistory(t *testing.T) {
	var missing *MigrationSource
	for _, source := range []UsersMigrationSource{
		{},
		{Base: missing, Version: 41},
		{Base: MigrationSource{Version: 40}, Version: 40},
		{Base: MigrationSource{Version: 40}, Version: 1 << 63},
	} {
		if history, err := source.Load(context.Background()); err == nil || len(history) != 0 {
			t.Fatal("invalid forward Users history admitted")
		}
	}
	base, err := (MigrationSource{Version: 40}).Load(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	source := UsersMigrationSource{Base: MigrationSource{Version: 40}, Version: 41}
	history, err := source.Load(context.Background())
	if err != nil || len(history) != 2 || history[0].UpSQL() != base[0].UpSQL() || history[1].Version() != migrations.Version(41) || history[1].DownSQL() != "" {
		t.Fatal("forward Users migration rewrote its installed predecessor", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := source.Load(ctx); err == nil {
		t.Fatal("cancelled forward declaration succeeded")
	}
}
