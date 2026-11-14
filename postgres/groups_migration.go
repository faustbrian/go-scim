package scimpostgres

import (
	"context"
	"math"
	"slices"

	migrations "github.com/faustbrian/go-migrations/v3"
)

// GroupsMigrationSource appends the optional Group projection to an existing
// immutable SCIM history. Allocate Version permanently after UsersMigrationSource
// and install before selecting NewGroupsService. Existing Users binaries need
// no rollout change: this adds an empty owned table, with no foreign-owner data
// rewrite, backfill or destructive down migration. Outcomes remain exclusively
// in the kernel journal; command_id is ordinary effect correlation only.
type GroupsMigrationSource struct {
	Base    migrations.Source
	Version migrations.Version
}

// Load returns detached ordered forward declarations without database IO. The
// existing deployment migration runner owns the transaction. A bounded lock
// wait prevents new-table/FK installation from queuing traffic indefinitely.
func (s GroupsMigrationSource) Load(ctx context.Context) ([]migrations.Migration, error) {
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
	step, err := migrations.NewMigration(s.Version, "scim_groups_projection", migrations.TransactionModeDefault, groupsProjectionSQL, "")
	if err != nil {
		return nil, ErrInvalidConfiguration
	}
	return append(slices.Clone(history), step), nil
}

// Members remain bounded typed references in the resource payload, not another
// organization membership graph. Connection-row serialization shared with Users
// protects existence checks against concurrent member deletion. Group names and
// externalId deliberately have no unique constraint (root GroupStore contract).
const groupsProjectionSQL = `SET LOCAL lock_timeout='5s';
CREATE TABLE scim.groups (
 tenant_id identity.directory_id NOT NULL,
 organization_id identity.directory_id NOT NULL,
 provider_id identity.directory_id NOT NULL,
 connection_id identity.directory_id NOT NULL,
 resource_id identity.directory_id NOT NULL,
 resource bytea NOT NULL CHECK(octet_length(resource) BETWEEN 1 AND 131072),
 generation bigint NOT NULL DEFAULT 1 CHECK(generation>0),
 deleted_at timestamptz,
 command_id text COLLATE "C" NOT NULL UNIQUE CHECK(command_id ~ '^[A-Za-z0-9_-]{22}$'),
 effect_digest bytea NOT NULL CHECK(octet_length(effect_digest)=32),
 PRIMARY KEY(tenant_id,organization_id,provider_id,connection_id,resource_id),
 FOREIGN KEY(tenant_id,organization_id,provider_id,connection_id) REFERENCES scim.connections(tenant_id,organization_id,provider_id,connection_id)
);`
