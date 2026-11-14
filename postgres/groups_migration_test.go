package scimpostgres

import (
	"context"
	"testing"
)

func TestGroupsMigrationPreservesImmutableUsersHistory(t *testing.T) {
	base := UsersMigrationSource{Base: MigrationSource{Version: 40}, Version: 41}
	before, err := base.Load(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	source := GroupsMigrationSource{Base: base, Version: 42}
	after, err := source.Load(context.Background())
	if err != nil || len(after) != len(before)+1 || after[2].Version() != 42 || after[2].DownSQL() != "" {
		t.Fatal("invalid additive Groups history", err)
	}
	for index := range before {
		if before[index].Version() != after[index].Version() || before[index].UpSQL() != after[index].UpSQL() || before[index].DownSQL() != after[index].DownSQL() {
			t.Fatal("Groups migration rewrote its installed predecessor")
		}
	}
	var missing *MigrationSource
	for _, invalid := range []GroupsMigrationSource{{}, {Base: missing, Version: 42}, {Base: base, Version: 41}, {Base: base, Version: 1 << 63}} {
		if history, err := invalid.Load(context.Background()); err == nil || len(history) != 0 {
			t.Fatal("invalid Groups migration source admitted")
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := source.Load(ctx); err == nil {
		t.Fatal("cancelled Groups declaration succeeded")
	}
}
