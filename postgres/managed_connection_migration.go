package scimpostgres

import (
	"context"
	"math"
	"slices"

	migrations "github.com/faustbrian/go-migrations/v3"
)

// ManagedConnectionsMigrationSource appends managed administrative metadata
// after the installed SCIM history. Apply Version before selecting managed
// connection operations. Configured provisioning does not use the new table.
// Existing credentials are neither copied nor enrolled as managed connections.
type ManagedConnectionsMigrationSource struct {
	Base    migrations.Source
	Version migrations.Version
}

// Load returns forward-only declarations; the existing migration runner owns
// installation. The new table is empty when its constraints and index are
// added. The foreign key's lock on the existing binding table is time-bounded.
func (s ManagedConnectionsMigrationSource) Load(ctx context.Context) ([]migrations.Migration, error) {
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
	step, err := migrations.NewMigration(s.Version, "scim_managed_connections", migrations.TransactionModeDefault, managedConnectionsSQL, "")
	if err != nil {
		return nil, ErrInvalidConfiguration
	}
	return append(slices.Clone(history), step), nil
}

// The existing binding remains the only owner of bearer digest, state and
// generation. The managed identity is unique within a tenant even if distinct
// configured credentials have the same ID in other exact provider scopes.
const managedConnectionsSQL = `SET LOCAL lock_timeout='5s';
CREATE TABLE scim.managed_connections (
 tenant_id identity.directory_id NOT NULL CHECK(tenant_id ~ '^[A-Za-z0-9_-]{21}[AQgw]$' AND tenant_id <> repeat('A',22)),
 organization_id identity.directory_id NOT NULL CHECK(organization_id ~ '^[A-Za-z0-9_-]{21}[AQgw]$' AND organization_id <> repeat('A',22)),
 provider_id identity.directory_id NOT NULL,
 connection_id identity.directory_id NOT NULL CHECK(connection_id ~ '^[A-Za-z0-9_-]{21}[AQgw]$' AND connection_id <> repeat('A',22)),
 mappings bytea NOT NULL CHECK(octet_length(mappings) BETWEEN 2 AND 65536),
 deprovision_policy text COLLATE "C" NOT NULL CHECK(deprovision_policy = 'remove-membership'),
 PRIMARY KEY(tenant_id,connection_id),
 FOREIGN KEY(tenant_id,organization_id,provider_id,connection_id)
   REFERENCES scim.connections(tenant_id,organization_id,provider_id,connection_id)
);
CREATE INDEX managed_connections_organization_page ON scim.managed_connections(tenant_id,organization_id,connection_id);`
