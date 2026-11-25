package scimpostgres

import (
	"context"
	"math"
	"slices"

	migrations "github.com/faustbrian/go-migrations/v3"
)

// BulkChildExecutionMigrationSource adds semantic checkpoint results to the
// existing Bulk graph. Install it before calling GroupBulkService.ExecuteChild.
// Current admission rows require no backfill; the graph and response ceiling
// remain unchanged. No route or discovery feature is enabled.
type BulkChildExecutionMigrationSource struct {
	Base    migrations.Source
	Version migrations.Version
}

// Load returns the unchanged original graph history and the result migration.
func (s BulkChildExecutionMigrationSource) Load(ctx context.Context) ([]migrations.Migration, error) {
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
	foundAdmission := false
	for _, step := range history {
		if step.Version() >= s.Version {
			return nil, ErrInvalidConfiguration
		}
		foundAdmission = foundAdmission || step.UpSQL() == bulkAdmissionSQL
	}
	if !foundAdmission {
		return nil, ErrInvalidConfiguration
	}
	step, err := migrations.NewMigration(s.Version, "scim_bulk_child_result", migrations.TransactionModeDefault, bulkChildResultSQL, "")
	if err != nil {
		return nil, ErrInvalidConfiguration
	}
	return append(slices.Clone(history), step), nil
}

const bulkChildResultSQL = `SET LOCAL lock_timeout='5s';
ALTER TABLE scim.bulk_children
 ADD COLUMN result_code smallint,
 ADD COLUMN result_resource_id text COLLATE "C",
 ADD COLUMN result_version text COLLATE "C",
 ADD CONSTRAINT bulk_child_result_shape CHECK (
  (status='succeeded' AND result_code IS NOT NULL AND result_code BETWEEN 200 AND 299
   AND result_resource_id IS NOT NULL AND octet_length(result_resource_id) BETWEEN 1 AND 128
   AND (result_code=204 OR result_version IS NOT NULL)
   AND (result_version IS NULL OR octet_length(result_version) BETWEEN 3 AND 256))
  OR (status='failed' AND result_code IS NOT NULL AND result_code BETWEEN 400 AND 599
   AND (result_resource_id IS NULL OR octet_length(result_resource_id) BETWEEN 1 AND 128) AND result_version IS NULL)
  OR (status NOT IN ('succeeded','failed') AND result_code IS NULL AND result_resource_id IS NULL AND result_version IS NULL)
 );`
