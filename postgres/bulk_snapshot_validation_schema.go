package scimpostgres

import (
	"context"
	"math"
	"slices"

	migrations "github.com/faustbrian/go-migrations/v3"
)

// BulkSnapshotValidationMigrationSource widens the typed Bulk denial checkpoint
// to retain snapshot-dependent noTarget failures. Base must contain both steps
// of BulkTypedValidationMigrationSource. Install this opt-in expansion before
// enabling snapshot validation in application code. Version and ValidationVersion
// identify separate, ordered transactional expansion and validation migrations.
// No rows are rewritten or backfilled. Reverting application code preserves the
// retained denials; these migrations are forward-only.
type BulkSnapshotValidationMigrationSource struct {
	Base              migrations.Source
	Version           migrations.Version
	ValidationVersion migrations.Version
}

// Load preserves the installed history and appends the constraint expansion and
// later validation. Lock acquisition is bounded to five seconds; the expansion
// does not scan retained rows while holding its constraint replacement lock.
func (s BulkSnapshotValidationMigrationSource) Load(ctx context.Context) ([]migrations.Migration, error) {
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
	var typedExpansionVersion, typedValidationVersion migrations.Version
	for _, step := range history {
		if step.Version() >= s.Version {
			return nil, ErrInvalidConfiguration
		}
		switch step.UpSQL() {
		case bulkTypedValidationExpandSQL:
			typedExpansionVersion = step.Version()
		case bulkTypedValidationValidateSQL:
			typedValidationVersion = step.Version()
		}
	}
	if typedExpansionVersion == 0 || typedValidationVersion <= typedExpansionVersion {
		return nil, ErrInvalidConfiguration
	}

	expand, err := migrations.NewMigration(s.Version, "scim_bulk_snapshot_validation_expand", migrations.TransactionModeDefault, bulkSnapshotValidationExpandSQL, "")
	if err != nil {
		return nil, ErrInvalidConfiguration
	}
	validate, err := migrations.NewMigration(s.ValidationVersion, "scim_bulk_snapshot_validation_validate", migrations.TransactionModeDefault, bulkSnapshotValidationValidateSQL, "")
	if err != nil {
		return nil, ErrInvalidConfiguration
	}
	return append(slices.Clone(history), expand, validate), nil
}

// Code 18 adds noTarget to the immutable 13..17 typed range. Replacing the
// constraint in one ALTER transaction leaves no unconstrained write window;
// every other result-shape predicate is unchanged from the typed expansion.
const bulkSnapshotValidationExpandSQL = `SET LOCAL lock_timeout='5s';
ALTER TABLE scim.bulk_children
 DROP CONSTRAINT bulk_typed_validation_result_shape,
 ADD CONSTRAINT bulk_typed_validation_result_shape CHECK (
  result_denial_code IS NULL OR (
   result_denial_code BETWEEN 13 AND 18
   AND cyclic IS FALSE AND status='failed'
   AND result_code IS NOT NULL AND result_code=400
   AND result_resource_id IS NOT NULL AND octet_length(result_resource_id) BETWEEN 1 AND 128
   AND (resource_id='' OR result_resource_id=resource_id)
   AND result_version IS NULL
  )
 ) NOT VALID;`

const bulkSnapshotValidationValidateSQL = `SET LOCAL lock_timeout='5s';
ALTER TABLE scim.bulk_children VALIDATE CONSTRAINT bulk_typed_validation_result_shape;`
