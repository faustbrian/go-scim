package scimpostgres

import (
	"context"
	"math"
	"slices"

	migrations "github.com/faustbrian/go-migrations/v3"
)

// BulkGroupMutationMigrationSource adds original-input custody for Group
// replace, PATCH and delete to the existing Bulk child row. Install this
// expansion before selecting those operations. Existing Group creates and
// request histories do not require a backfill.
type BulkGroupMutationMigrationSource struct {
	Base    migrations.Source
	Version migrations.Version
}

// Load preserves the previous history and appends the additive expansion.
func (s BulkGroupMutationMigrationSource) Load(ctx context.Context) ([]migrations.Migration, error) {
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
	foundChildResults := false
	for _, step := range history {
		if step.Version() >= s.Version {
			return nil, ErrInvalidConfiguration
		}
		foundChildResults = foundChildResults || step.UpSQL() == bulkChildResultSQL
	}
	if !foundChildResults {
		return nil, ErrInvalidConfiguration
	}
	step, err := migrations.NewMigration(s.Version, "scim_bulk_group_mutation_input", migrations.TransactionModeDefault, bulkGroupMutationInputSQL, "")
	if err != nil {
		return nil, ErrInvalidConfiguration
	}
	return append(slices.Clone(history), step), nil
}

// The 139264-byte ceiling is the native originalCiphertextBytes bound. The
// nullable column has no default or backfill; NOT VALID avoids scanning old
// rows while still checking newly written input.
const bulkGroupMutationInputSQL = `SET LOCAL lock_timeout='5s';
ALTER TABLE scim.bulk_children
 ADD COLUMN group_mutation_input bytea,
 ADD CONSTRAINT bulk_group_mutation_input_size CHECK (
  group_mutation_input IS NULL OR octet_length(group_mutation_input) BETWEEN 1 AND 139264
 ) NOT VALID;`
