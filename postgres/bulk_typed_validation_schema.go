package scimpostgres

import (
	"context"
	"math"
	"slices"

	migrations "github.com/faustbrian/go-migrations/v3"
)

// BulkTypedValidationMigrationSource adds opt-in typed validation denials to
// existing Bulk child results. Base must contain BulkChildExecutionMigrationSource;
// BulkGroupMutationMigrationSource is optional. Install the expansion before
// enabling typed validation in application code. Version and ValidationVersion
// identify separate, ordered transactional expansion and validation migrations.
// Existing rows remain NULL without a default or backfill. Reverting application
// code does not remove retained denial custody; these migrations are forward-only.
type BulkTypedValidationMigrationSource struct {
	Base              migrations.Source
	Version           migrations.Version
	ValidationVersion migrations.Version
}

// Load preserves the installed history and appends expansion and later check
// validation. Both ALTER statements bound lock acquisition to five seconds;
// only the later validation scans retained rows, without the expansion lock.
func (s BulkTypedValidationMigrationSource) Load(ctx context.Context) ([]migrations.Migration, error) {
	if ctx == nil || nilMigrationSource(s.Base) || s.Version == 0 ||
		s.Version > migrations.Version(math.MaxInt64) || s.ValidationVersion <= s.Version ||
		s.ValidationVersion > migrations.Version(math.MaxInt64) {
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
	expand, err := migrations.NewMigration(s.Version, "scim_bulk_typed_validation_expand", migrations.TransactionModeDefault, bulkTypedValidationExpandSQL, "")
	if err != nil {
		return nil, ErrInvalidConfiguration
	}
	validate, err := migrations.NewMigration(s.ValidationVersion, "scim_bulk_typed_validation_validate", migrations.TransactionModeDefault, bulkTypedValidationValidateSQL, "")
	if err != nil {
		return nil, ErrInvalidConfiguration
	}
	return append(slices.Clone(history), expand, validate), nil
}

// Codes 13..17 follow the kernel's frozen legacy denials. Retaining the original
// allocation on failed creates makes older readers reject the unfamiliar shape
// rather than mislabel its SCIM type. Mutation rows have no allocated resource_id;
// their exact resolved target is checked by the typed runtime on replay.
const bulkTypedValidationExpandSQL = `SET LOCAL lock_timeout='5s';
ALTER TABLE scim.bulk_children
 ADD COLUMN result_denial_code smallint,
 ADD CONSTRAINT bulk_typed_validation_result_shape CHECK (
  result_denial_code IS NULL OR (
   result_denial_code BETWEEN 13 AND 17
   AND cyclic IS FALSE AND status='failed'
   AND result_code IS NOT NULL AND result_code=400
   AND result_resource_id IS NOT NULL AND octet_length(result_resource_id) BETWEEN 1 AND 128
   AND (resource_id='' OR result_resource_id=resource_id)
   AND result_version IS NULL
  )
 ) NOT VALID;`

const bulkTypedValidationValidateSQL = `SET LOCAL lock_timeout='5s';
ALTER TABLE scim.bulk_children VALIDATE CONSTRAINT bulk_typed_validation_result_shape;`
