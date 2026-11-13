package scimpostgres

import (
	"context"
	"math"
	"reflect"
	"slices"

	migrations "github.com/faustbrian/go-migrations/v3"
)

// UsersMigrationSource appends native Users mutation support to an existing
// immutable history. Allocate Version permanently after that history and apply
// it before enabling this version's Users service. It adds only metadata-backed
// constant/default columns; there is no data backfill or destructive down step.
// Existing binaries can still create rows using the constant generation default.
// A reverted binary cannot decode the cleared payload of a deleted resource and
// therefore denies it rather than resurrecting the SCIM projection.
type UsersMigrationSource struct {
	Base    migrations.Source
	Version migrations.Version
}

// Load returns detached ordered forward declarations without database IO. The
// consumer's existing migration runner owns installation and transaction scope.
// The short lock timeout makes contended metadata acquisition fail rather than
// queueing unbounded traffic; ALTER does not scan/rewrite populated projections.
func (s UsersMigrationSource) Load(ctx context.Context) ([]migrations.Migration, error) {
	if ctx == nil || nilMigrationSource(s.Base) || s.Version == 0 || s.Version > migrations.Version(math.MaxInt64) {
		return nil, ErrInvalidConfiguration
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	history, err := s.Base.Load(ctx)
	if err != nil {
		return nil, err
	}
	if len(history) == 0 {
		return nil, ErrInvalidConfiguration
	}
	for _, step := range history {
		if step.Version() >= s.Version {
			return nil, ErrInvalidConfiguration
		}
	}
	step, err := migrations.NewMigration(s.Version, "scim_users_mutation_metadata", migrations.TransactionModeDefault, usersMutationSQL, "")
	if err != nil {
		return nil, ErrInvalidConfiguration
	}
	return append(slices.Clone(history), step), nil
}

func nilMigrationSource(source migrations.Source) bool {
	if source == nil {
		return true
	}
	v := reflect.ValueOf(source)
	switch v.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
		return v.IsNil()
	default:
		return false
	}
}

const usersMutationSQL = `SET LOCAL lock_timeout='5s';
ALTER TABLE scim.users
 ADD COLUMN generation bigint NOT NULL DEFAULT 1,
 ADD COLUMN deleted_at timestamptz;`
