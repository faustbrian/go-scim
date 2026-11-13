package scimpostgres

import (
	"context"
	"math"

	migrations "github.com/faustbrian/go-migrations/v3"
)

// MigrationSource owns only the optional SCIM adapter's forward schema. Allocate
// Version permanently after the identity and organization histories, including
// organization credential authority. Load performs no IO and creates no ledger.
// Install through the deployment's existing migrations runner before activating
// NewService. Removing this state can resurrect credentials or duplicate user
// provisioning; no destructive down migration is provided.
type MigrationSource struct{ Version migrations.Version }

// Load returns detached immutable forward SQL, preserving cancellation. A fresh
// installation requires an unoccupied scim schema and never adopts unmanaged
// tables. The new empty tables do not rewrite identity or organization data.
func (s MigrationSource) Load(ctx context.Context) ([]migrations.Migration, error) {
	if ctx == nil || s.Version == 0 || s.Version > migrations.Version(math.MaxInt64) {
		return nil, ErrInvalidConfiguration
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	step, err := migrations.NewMigration(s.Version, "scim_configured_users", migrations.TransactionModeDefault, schemaSQL, "")
	if err != nil {
		return nil, ErrInvalidConfiguration
	}
	return []migrations.Migration{step}, nil
}

// The projection is not a second journal: command_id only binds the native
// effect to the existing kernel command. Outcomes, leases and replay remain
// exclusively in identity.commands. All equality is byte-exact; username_key
// is computed by the root SCIM schema comparison owner, not database collation.
// The digest index bounds B-tree entries without making a hash collision equal
// to a full key. Supported creates serialize on their existing connection row
// and compare both digest and full key in the same kernel Work.
const schemaSQL = `CREATE SCHEMA scim;
CREATE TABLE scim.connections (
 tenant_id identity.directory_id NOT NULL,
 organization_id identity.directory_id NOT NULL,
 provider_id identity.directory_id NOT NULL,
 connection_id identity.directory_id NOT NULL,
 credential_id identity.directory_id NOT NULL,
 credential_digest bytea NOT NULL CHECK(octet_length(credential_digest)=32),
 configuration_digest bytea NOT NULL CHECK(octet_length(configuration_digest)=32),
 version identity.version NOT NULL,
 state text COLLATE "C" NOT NULL CHECK(state IN('active','revoked','deleted')),
 expires_at timestamptz NOT NULL,
 authority_version identity.version NOT NULL,
 organization_credential_version identity.version NOT NULL,
 command_id text COLLATE "C" NOT NULL UNIQUE CHECK(command_id ~ '^[A-Za-z0-9_-]{22}$'),
 effect_digest bytea NOT NULL CHECK(octet_length(effect_digest)=32),
 PRIMARY KEY(tenant_id,organization_id,provider_id,connection_id),
 FOREIGN KEY(tenant_id,organization_id) REFERENCES organization.organizations(tenant_id,organization_id)
);
CREATE TABLE scim.users (
 tenant_id identity.directory_id NOT NULL,
 organization_id identity.directory_id NOT NULL,
 provider_id identity.directory_id NOT NULL,
 connection_id identity.directory_id NOT NULL,
 resource_id identity.directory_id NOT NULL,
 user_id identity.directory_id NOT NULL,
 username_key text COLLATE "C" NOT NULL CHECK(octet_length(username_key) BETWEEN 1 AND 16384),
 username_digest bytea NOT NULL CONSTRAINT users_username_digest_matches_key CHECK(octet_length(username_digest)=32 AND username_digest=sha256(convert_to(username_key,'UTF8'))),
 external_id text COLLATE "C" NOT NULL CHECK(octet_length(external_id)<=65536),
 resource bytea NOT NULL CHECK(octet_length(resource) BETWEEN 1 AND 131072),
 command_id text COLLATE "C" NOT NULL UNIQUE CHECK(command_id ~ '^[A-Za-z0-9_-]{22}$'),
 effect_digest bytea NOT NULL CHECK(octet_length(effect_digest)=32),
 PRIMARY KEY(tenant_id,organization_id,provider_id,connection_id,resource_id),
 UNIQUE(tenant_id,organization_id,provider_id,connection_id,user_id),
 FOREIGN KEY(tenant_id,organization_id,provider_id,connection_id) REFERENCES scim.connections(tenant_id,organization_id,provider_id,connection_id),
 FOREIGN KEY(tenant_id,user_id) REFERENCES identity.users(tenant_id,user_id)
);
CREATE INDEX users_username_digest_idx ON scim.users(tenant_id,organization_id,provider_id,connection_id,username_digest);`
