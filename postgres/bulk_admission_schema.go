package scimpostgres

import (
	"context"
	"math"
	"slices"

	migrations "github.com/faustbrian/go-migrations/v3"
)

// BulkAdmissionMigrationSource appends opt-in Bulk graph and checkpoint storage
// to the existing Groups projection history. Install it and the kernel's
// canonical Bulk alias migration before selecting native Bulk. The new tables
// do not change ordinary Users or Groups behavior or enable discovery.
type BulkAdmissionMigrationSource struct {
	Base    migrations.Source
	Version migrations.Version
}

// Load retains the immutable Groups history and declares one owned migration.
func (s BulkAdmissionMigrationSource) Load(ctx context.Context) ([]migrations.Migration, error) {
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
	foundGroups := false
	for _, step := range history {
		if step.Version() >= s.Version {
			return nil, ErrInvalidConfiguration
		}
		foundGroups = foundGroups || step.UpSQL() == groupsProjectionSQL
	}
	if !foundGroups {
		return nil, ErrInvalidConfiguration
	}
	step, err := migrations.NewMigration(s.Version, "scim_bulk_admission", migrations.TransactionModeDefault, bulkAdmissionSQL, "")
	if err != nil {
		return nil, ErrInvalidConfiguration
	}
	return append(slices.Clone(history), step), nil
}

// The kernel journal proves whether the admission Work committed. The adapter
// owns this graph and the mutable child progress; parent admission alone does
// not imply that a child ran or that a terminal response exists.
// bulk_id uses bytes because even an invalid-but-declared string can contain a
// NUL that PostgreSQL text cannot store. Commitments never contain raw bodies.
const bulkAdmissionSQL = `SET LOCAL lock_timeout='5s';
CREATE TABLE scim.bulk_requests (
 parent_id text COLLATE "C" PRIMARY KEY CHECK(parent_id ~ '^[A-Za-z0-9_-]{22}$'),
 tenant_id identity.directory_id NOT NULL,
 organization_id identity.directory_id NOT NULL,
 provider_id identity.directory_id NOT NULL,
 connection_id identity.directory_id NOT NULL,
 intent_digest bytea NOT NULL CHECK(octet_length(intent_digest)=32),
 configuration_digest bytea NOT NULL CHECK(octet_length(configuration_digest)=32),
 response_bytes integer NOT NULL CHECK(response_bytes BETWEEN 1 AND 4194304),
 child_count smallint NOT NULL CHECK(child_count BETWEEN 1 AND 1000),
 fail_on_errors smallint NOT NULL CHECK(fail_on_errors BETWEEN 0 AND 100),
 failed_count smallint NOT NULL DEFAULT 0 CHECK(failed_count BETWEEN 0 AND child_count),
 cutoff_active boolean NOT NULL DEFAULT false CHECK(cutoff_active=(fail_on_errors>0 AND failed_count>=fail_on_errors)),
 created_at timestamptz NOT NULL,
 FOREIGN KEY(tenant_id,organization_id,provider_id,connection_id) REFERENCES scim.connections(tenant_id,organization_id,provider_id,connection_id)
);
CREATE TABLE scim.bulk_children (
 parent_id text COLLATE "C" NOT NULL REFERENCES scim.bulk_requests(parent_id),
 ordinal smallint NOT NULL CHECK(ordinal BETWEEN 0 AND 999),
 command_id text COLLATE "C" NOT NULL UNIQUE CHECK(command_id ~ '^[A-Za-z0-9_-]{22}$' AND command_id<>parent_id),
 bulk_id bytea NOT NULL CHECK(octet_length(bulk_id)<=65536),
 request_fingerprint bytea NOT NULL CHECK(octet_length(request_fingerprint)=32),
 resource_id text COLLATE "C" NOT NULL CHECK(resource_id='' OR resource_id ~ '^[A-Za-z0-9_-]{22}$'),
 component_id smallint NOT NULL CHECK(component_id BETWEEN 0 AND 999),
 component_order smallint NOT NULL CHECK(component_order BETWEEN 0 AND 999),
 cyclic boolean NOT NULL,
 dependency_ids text[] NOT NULL CHECK(cardinality(dependency_ids)<=1000 AND array_position(dependency_ids,NULL) IS NULL),
 status text COLLATE "C" NOT NULL DEFAULT 'admitted' CHECK(status IN ('admitted','running','succeeded','failed','dependency-blocked','skipped')),
 skip_reason text COLLATE "C" NOT NULL DEFAULT 'none' CHECK((status='skipped' AND skip_reason='fail-on-errors') OR (status<>'skipped' AND skip_reason='none')),
 PRIMARY KEY(parent_id,ordinal)
);
CREATE INDEX bulk_children_component_idx ON scim.bulk_children(parent_id,component_order,ordinal);`
