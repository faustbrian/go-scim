//go:build integration

package scimpostgres

import (
	"bytes"
	"context"
	"encoding/json"
	"io/fs"
	"os"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	auditpg "github.com/faustbrian/go-audit/postgres"
	authentication "github.com/faustbrian/go-authentication/v2"
	"github.com/faustbrian/go-authorization/v3"
	authoritypg "github.com/faustbrian/go-authorization/v3/postgres"
	"github.com/faustbrian/go-clock"
	identity "github.com/faustbrian/go-identity"
	kernel "github.com/faustbrian/go-identity/postgres"
	migrations "github.com/faustbrian/go-migrations/v3"
	organizationpg "github.com/faustbrian/go-organization/postgres"
	database "github.com/faustbrian/go-postgres"
	scim "github.com/faustbrian/go-scim"
	"github.com/faustbrian/go-secret-envelope/v2/adapters/keyring"
	lifecyclepg "github.com/faustbrian/go-transactional-outbox/postgres/identity"
	outboxpg "github.com/faustbrian/go-transactional-outbox/v2/postgres"
	"github.com/jackc/pgx/v5"
)

type nativeFixture struct {
	ctx     context.Context
	pool    *database.Pool
	service *Service
	config  Config
	bearer  authentication.BearerCredential
	keys    *keyring.Provider
	deny    *atomic.Bool
}

type configuredPolicy func(context.Context, authorization.DecisionContext) (authorization.Decision, error)

func (p configuredPolicy) Decide(ctx context.Context, d authorization.DecisionContext) (authorization.Decision, error) {
	return p(ctx, d)
}

func newNativeFixture(t *testing.T) *nativeFixture {
	t.Helper()
	dsn := os.Getenv("SCIM_POSTGRES_TEST_DSN")
	parsed, err := pgx.ParseConfig(dsn)
	if dsn == "" || err != nil || parsed.Host != "127.0.0.1" || parsed.Database != "scim_test" {
		t.Fatal("explicit disposable loopback scim_test required")
	}
	ctx, cancel := context.WithTimeout(t.Context(), 45*time.Second)
	t.Cleanup(cancel)
	admin, err := pgx.ConnectConfig(ctx, parsed)
	if err != nil {
		t.Fatal("owned disposable database unavailable")
	}
	t.Cleanup(func() {
		bounded, stop := context.WithTimeout(context.Background(), 3*time.Second)
		defer stop()
		if err := admin.Close(bounded); err != nil {
			t.Error("admin cleanup")
		}
	})
	id, err := identity.NewSubjectID()
	if err != nil {
		t.Fatal(err)
	}
	name := "scim_" + string(id)
	quoted := pgx.Identifier{name}.Sanitize()
	if _, err := admin.Exec(ctx, "CREATE DATABASE "+quoted); err != nil {
		t.Fatal("create owned database")
	}
	t.Cleanup(func() {
		bounded, stop := context.WithTimeout(context.Background(), 3*time.Second)
		defer stop()
		if _, err := admin.Exec(bounded, "DROP DATABASE "+quoted); err != nil {
			t.Error("database cleanup")
		}
	})
	pool, err := database.Connect(ctx, database.Config{DSN: dsn, MaxConns: 8, Configure: func(c *database.PoolConfig) error { c.ConnConfig.Database = name; return nil }})
	if err != nil {
		t.Fatal("native pool")
	}
	t.Cleanup(func() {
		bounded, stop := context.WithTimeout(context.Background(), 3*time.Second)
		defer stop()
		if err := pool.Close(bounded); err != nil {
			t.Error("pool cleanup")
		}
	})
	base := kernel.RequestKeyPreparationMigrationSource{Base: kernel.RequestKeyMigrationSource{Base: kernel.MigrationSource{}, Version: 10}, Version: 11}
	installSource(t, ctx, pool, kernel.DirectoryAuthorityMigrationSource{Base: base, Version: 12, GlobalAuthorityID: "scim-deployment", TenantIDs: []identity.TenantID{"tenant-a"}})
	installSource(t, ctx, pool, organizationpg.MigrationSource{Version: 20})
	installSource(t, ctx, pool, organizationpg.CredentialAuthorityMigrationSource{Version: 21})
	authoritySQL, err := authoritypg.AuthoritySchemaMigration(30)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Raw().Exec(ctx, authoritySQL.Up); err != nil {
		t.Fatal("authority schema")
	}
	// Roles are cluster-global. Reused fixture roles are never altered; fresh
	// empty-cluster installation reserves them with the supplier's actual SQL.
	var roles int
	if err := pool.Raw().QueryRow(ctx, `SELECT count(*) FROM pg_roles WHERE rolname IN ('audit_writer','audit_reader','audit_retention')`).Scan(&roles); err != nil {
		t.Fatal(err)
	}
	if roles == 0 {
		if _, err := pool.Raw().Exec(ctx, auditpg.FreshInstallPreflightSQL()); err != nil {
			t.Fatal("audit roles")
		}
	} else if roles != 3 {
		t.Fatal("partial fixture role state")
	}
	installFS(t, ctx, pool, auditpg.Migrations())
	installFS(t, ctx, pool, outboxpg.Migrations())
	installFS(t, ctx, pool, lifecyclepg.Migrations())
	installSource(t, ctx, pool, MigrationSource{Version: 40})
	if _, err := pool.Raw().Exec(ctx, `INSERT INTO organization.organizations(tenant_id,organization_id,slug,name,state,version,member_count,owner_count,credential_version) VALUES('tenant-a','organization-a','scim-fixture','SCIM fixture','active',1,1,1,1)`); err != nil {
		t.Fatal("configured organization fixture")
	}
	deny := new(atomic.Bool)
	policy := configuredPolicy(func(ctx context.Context, d authorization.DecisionContext) (authorization.Decision, error) {
		if ctx.Err() != nil || d.Validate() != nil {
			return authorization.Decision{}, authorization.ErrDecisionUnavailable
		}
		outcome := authorization.Allow
		if deny.Load() {
			outcome = authorization.Deny
		}
		return authorization.Decision{Outcome: outcome, Revision: d.PolicyRevision}, nil
	})
	q := kernel.CommandQueryPolicy{Authorization: policy, Clock: clock.System{}, PolicyVersion: 1}
	requestKeys, err := kernel.NewRequestKeyConfig("scim-native-test", [32]byte{71}, q)
	if err != nil {
		t.Fatal(err)
	}
	bearer := authentication.NewBearerCredential("configured-native-scim-test-credential-with-entropy-bound")
	credential, err := NewConfiguredCredential("credential-a", bearer, [32]byte{72})
	if err != nil {
		t.Fatal(err)
	}
	schema := identity.AttributeSchema{ID: "scim-fixture", Version: 1}
	for _, name := range []string{"scim_user_name", "scim_display_name"} {
		schema.Fields = append(schema.Fields, identity.FieldPolicy{Name: name, Kind: identity.AttributeString, Cardinality: identity.CardinalityScalar, Normalization: identity.NormalizeNone, InputPermission: identity.FieldWrite, OutputPermission: identity.FieldRead, WriteAuthorization: identity.FieldWriteSystem, Sensitivity: identity.SensitivityPersonal, MigrationVersion: 1})
	}
	fields, err := identity.NewAttributeProcessor(schema, policy, func(_ context.Context, _ identity.NormalizationPolicy, s identity.AttributeScalar) (identity.AttributeScalar, error) {
		return s, nil
	}, identity.AttributeProcessorConfig{Clock: clock.System{}, MaximumDuration: time.Second, PolicyVersion: 1, ValidateCanonicalUserID: func(_ context.Context, id identity.UserID) error {
		_, err := identity.ParseSubjectID(string(id))
		return err
	}, ValidateValue: func(context.Context, identity.FieldPolicy, identity.AttributeValue) error { return nil }})
	if err != nil {
		t.Fatal(err)
	}
	c := Config{Scope: scim.Scope{TenantID: "tenant-a", OrganizationID: "organization-a", ProviderID: "configured-provider", ConnectionID: "connection-a"}, ConnectionVersion: 1, Credential: credential, CredentialExpiresAt: time.Now().UTC().Add(time.Hour).Truncate(time.Microsecond), ActorID: "scim-service", PolicyID: "scim-policy", PolicyVersion: 1, Authorization: policy, AuthorityNamespace: "scim-test", Fields: fields, FieldSchema: schema, UserNameField: "scim_user_name", DisplayNameField: "scim_display_name", Coordinator: kernel.CoordinatorConfig{MaximumDuration: 3 * time.Second, LeaseDuration: time.Minute, CurrentFingerprintKeyVersion: 1, RetainedFingerprintKeys: map[uint32][32]byte{1: {73}}, QueryPolicy: &q, AdmissionPolicy: &q}, RequestKeys: requestKeys, IntentKey: [32]byte{74}, ActiveEnvelopeKeyID: "native-input", Limits: scim.DefaultLimits(), BaseURL: "https://scim.example.test/v2", MaximumDuration: 3 * time.Second}
	c.ConfigurationID = "native-scim-fixture-v1"
	c.GlobalAuthorityID = "scim-deployment"
	_, err = authoritypg.InitializeAuthority(ctx, pool.Raw(), authoritypg.AuthorityScope{TenantID: "tenant-a", PolicyNamespace: c.AuthorityNamespace, SubjectID: authorization.SubjectID(c.ActorID)}, time.Second)
	if err != nil {
		t.Fatal("existing configured service policy authority", err)
	}
	keys, err := keyring.New(map[string][]byte{"native-input": bytes.Repeat([]byte{75}, 32)})
	if err != nil {
		t.Fatal(err)
	}
	service, err := NewService(pool, c, keys)
	if err != nil {
		t.Fatal("native construction", err)
	}
	installed, err := service.InitializeConfiguredConnection(ctx)
	if err != nil || installed.Outcome != identity.CommitOutcomeCommitted || installed.Version != 1 {
		t.Fatal("configured native bootstrap did not commit", installed.Outcome, err)
	}
	return &nativeFixture{ctx: ctx, pool: pool, service: service, config: c, bearer: bearer, keys: keys, deny: deny}
}

func installSource(t *testing.T, ctx context.Context, pool *database.Pool, source migrations.Source) {
	t.Helper()
	history, err := source.Load(ctx)
	if err != nil {
		t.Fatal("migration source", err)
	}
	for _, step := range history {
		if _, err := pool.Raw().Exec(ctx, step.UpSQL()); err != nil {
			t.Fatal("owned schema migration", step.Version())
		}
	}
}

func installFS(t *testing.T, ctx context.Context, pool *database.Pool, source fs.FS) {
	t.Helper()
	entries, err := fs.ReadDir(source, ".")
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".sql") {
			continue
		}
		wire, err := fs.ReadFile(source, entry.Name())
		if err != nil {
			t.Fatal(err)
		}
		up := strings.SplitN(string(wire), "-- +migrations Down", 2)[0]
		if _, err := pool.Raw().Exec(ctx, up); err != nil {
			t.Fatal("published SQL migration", entry.Name())
		}
	}
}

func (f *nativeFixture) assertAtomicCreation(t *testing.T, resource string, want int) {
	t.Helper()
	var users, attributes, projections, audits, events, results int
	err := f.pool.Raw().QueryRow(f.ctx, `SELECT
 (SELECT count(*) FROM identity.users u JOIN scim.users s USING(tenant_id,user_id) WHERE s.resource_id=$1),
 (SELECT count(*) FROM identity.user_attributes a JOIN scim.users s USING(tenant_id,user_id) WHERE s.resource_id=$1),
 (SELECT count(*) FROM scim.users WHERE resource_id=$1),
 (SELECT count(*) FROM audit.identity_command_bindings a JOIN scim.users s ON a.command_id=decode(translate(s.command_id,'-_','+/')||'==','base64') WHERE s.resource_id=$1),
 (SELECT count(*) FROM public.outbox_messages),
 (SELECT count(*) FROM identity.commands c JOIN scim.users s ON c.command_id=decode(translate(s.command_id,'-_','+/')||'==','base64') WHERE s.resource_id=$1 AND c.state='committed')`, resource).Scan(&users, &attributes, &projections, &audits, &events, &results)
	if err != nil {
		t.Fatal("read actual durable owner results", err)
	}
	if users != want || attributes != want || projections != want || audits != want || results != want || events < 2 {
		t.Fatalf("atomic owner results users=%d attrs=%d projection=%d audits=%d outbox=%d journal=%d", users, attributes, projections, audits, events, results)
	}
	reader, err := kernel.NewRepository(f.pool, kernel.Config{MaximumDuration: time.Second, AttributeSchemas: []identity.AttributeSchema{f.config.FieldSchema}, ProfileSchema: kernel.ProfileSchemaRef{ID: f.config.FieldSchema.ID, Version: f.config.FieldSchema.Version}})
	if err != nil {
		t.Fatal(err)
	}
	stored, err := reader.GetProfile(f.ctx, identity.ProfileQuery{TenantID: f.config.Scope.TenantID, UserID: identity.UserID(resource)})
	if err != nil || len(stored.Profile.AdditionalFields) != 2 {
		t.Fatal("actual typed kernel attribute map was not retained", err)
	}
	var projectionBytes []byte
	if err := f.pool.Raw().QueryRow(f.ctx, `SELECT resource FROM scim.users WHERE tenant_id=$1 AND organization_id=$2 AND provider_id=$3 AND connection_id=$4 AND resource_id=$5`, append(scopeArgs(f.config.Scope), resource)...).Scan(&projectionBytes); err != nil {
		t.Fatal(err)
	}
	var projection scim.Resource
	if json.Unmarshal(projectionBytes, &projection) != nil {
		t.Fatal("stored SCIM representation")
	}
	expected := map[string]any{f.config.UserNameField: projection.Attributes["userName"], f.config.DisplayNameField: projection.Attributes["displayName"]}
	for _, field := range stored.Profile.AdditionalFields {
		if field.Value.Kind != identity.AttributeString || field.Value.Scalar.Kind != identity.AttributeString || field.Value.Scalar.String != expected[field.Name] {
			t.Fatal("kernel typed value differs from admitted SCIM value", field.Name)
		}
	}
}
