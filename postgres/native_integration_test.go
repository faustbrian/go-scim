//go:build integration

package scimpostgres

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/faustbrian/go-audit"
	authentication "github.com/faustbrian/go-authentication/v2"
	identity "github.com/faustbrian/go-identity"
	database "github.com/faustbrian/go-postgres"
	scim "github.com/faustbrian/go-scim"
	"github.com/jackc/pgx/v5/pgconn"
)

// nativeFixture installs genuine published kernel, organization, authorization,
// audit and outbox histories in one disposable database. Policy callbacks are
// deployment configuration, never replacement identity or projection stores.
func TestNativeConfiguredCreateGetReplay(t *testing.T) {
	f := newNativeFixture(t)
	if _, err := f.service.InitializeConfiguredConnection(f.ctx); err != nil {
		t.Fatal("configured initialization", err)
	}
	if _, err := f.service.InitializeConfiguredConnection(f.ctx); err != nil {
		t.Fatal("identical bootstrap", err)
	}
	body := []byte(`{"schemas":["urn:ietf:params:scim:schemas:core:2.0:User"],"userName":"Provisioned","displayName":"First User","externalId":"not-an-identity-link"}`)
	r := scim.Request{Operation: scim.UserCreate, Credential: f.bearer, IdempotencyKey: "create-one", ContentType: "application/scim+json", Body: body}
	created, err := f.service.Execute(f.ctx, r)
	if err != nil || created.Status != 201 || created.ETag == "" {
		t.Fatal("native create", created.Status, err)
	}
	var view struct {
		ID          string `json:"id"`
		UserName    string `json:"userName"`
		DisplayName string `json:"displayName"`
	}
	if json.Unmarshal(created.Body, &view) != nil || view.ID == "" || view.UserName != "Provisioned" || view.DisplayName != "First User" {
		t.Fatal("wrong SCIM projection")
	}
	f.assertAtomicCreation(t, view.ID, 1)
	// The same externalId is correlation, not a unique identifier or permission
	// to link a provisioned projection to an existing kernel user.
	other := r
	other.IdempotencyKey = "second-external-id"
	other.Body = []byte(`{"schemas":["urn:ietf:params:scim:schemas:core:2.0:User"],"userName":"AnotherProvisioned","displayName":"Second User","externalId":"not-an-identity-link"}`)
	second, secondErr := f.service.Execute(f.ctx, other)
	var secondView struct {
		ID string `json:"id"`
	}
	if secondErr != nil || json.Unmarshal(second.Body, &secondView) != nil || secondView.ID == "" || secondView.ID == view.ID {
		t.Fatal("externalId became linking/uniqueness authority", secondErr)
	}
	f.assertAtomicCreation(t, secondView.ID, 1)
	get := scim.Request{Operation: scim.UserGet, ResourceID: view.ID, Credential: f.bearer}
	read, err := f.service.Execute(f.ctx, get)
	if err != nil || read.Status != 200 || read.ETag != created.ETag || string(read.Body) != string(created.Body) {
		t.Fatal("exact scoped read", err)
	}
	for range 2 {
		replay, err := f.service.Execute(f.ctx, r)
		if err != nil || replay.ETag != created.ETag || string(replay.Body) != string(created.Body) {
			t.Fatal("original keyed result changed", err)
		}
		f.assertAtomicCreation(t, view.ID, 1)
	}
	r.Body = []byte(`{"schemas":["urn:ietf:params:scim:schemas:core:2.0:User"],"userName":"Changed"}`)
	if _, err := f.service.Execute(f.ctx, r); err == nil || protocolStatus(err) != 409 {
		t.Fatal("changed keyed body did not conflict", err)
	}
	r.IdempotencyKey = "duplicate-name"
	r.Body = body
	if _, err := f.service.Execute(f.ctx, r); err == nil || protocolStatus(err) != 409 {
		t.Fatal("username uniqueness missing", err)
	}
	r.IdempotencyKey = "casefold-duplicate"
	r.Body = []byte(`{"schemas":["urn:ietf:params:scim:schemas:core:2.0:User"],"userName":"PROVISIONED"}`)
	if _, err := f.service.Execute(f.ctx, r); err == nil || protocolStatus(err) != 409 {
		t.Fatal("schema-owned username comparison missing", err)
	}
	get.Credential = authentication.NewBearerCredential("wrong-bearer-with-enough-bytes-to-pass-shape")
	if _, err := f.service.Execute(f.ctx, get); err == nil || protocolStatus(err) != 401 {
		t.Fatal("wrong credential disclosed resource", err)
	}
	for _, operation := range []scim.Operation{scim.GroupCreate, scim.GroupGet, scim.GroupList, scim.GroupReplace, scim.GroupPatch, scim.GroupDelete, scim.Bulk} {
		if _, err := f.service.Execute(f.ctx, scim.Request{Operation: operation, Credential: f.bearer}); err == nil || protocolStatus(err) != 501 {
			t.Fatal("unsupported native profile advertised or executed", operation, err)
		}
	}
}

func TestNativeLostCommitReturnsOriginalResource(t *testing.T) {
	f := newNativeFixture(t)
	if _, err := f.service.InitializeConfiguredConnection(f.ctx); err != nil {
		t.Fatal(err)
	}
	var name string
	if err := f.pool.Raw().QueryRow(f.ctx, `SELECT current_database()`).Scan(&name); err != nil {
		t.Fatal(err)
	}
	fault := new(nativeCommitFault)
	pool, err := database.Connect(f.ctx, database.Config{DSN: os.Getenv("SCIM_POSTGRES_TEST_DSN"), MaxConns: 3, Configure: func(c *database.PoolConfig) error {
		c.ConnConfig.Database = name
		c.ConnConfig.DialFunc = fault.dial
		return nil
	}})
	if err != nil {
		t.Fatal("owned fault pool")
	}
	t.Cleanup(func() {
		ctx, stop := context.WithTimeout(context.Background(), 3*time.Second)
		defer stop()
		if err := pool.Close(ctx); err != nil {
			t.Error("fault pool cleanup")
		}
	})
	service, err := NewService(pool, f.config, f.keys)
	if err != nil {
		t.Fatal(err)
	}
	r := scim.Request{Operation: scim.UserCreate, Credential: f.bearer, IdempotencyKey: "lost-commit", ContentType: "application/scim+json", Body: []byte(`{"schemas":["urn:ietf:params:scim:schemas:core:2.0:User"],"userName":"LostAcknowledgement","displayName":"Retained original"}`)}
	if response, err := service.Execute(f.ctx, r); err == nil || protocolStatus(err) != 503 || len(response.Body) != 0 || !fault.hit.Load() {
		t.Fatal("actual lost COMMIT was not exercised", err, fault.hit.Load())
	}
	replayed, err := f.service.Execute(f.ctx, r)
	if err != nil || replayed.Status != 201 {
		t.Fatal("lost acknowledgement did not return original", err)
	}
	var resource struct {
		ID string `json:"id"`
	}
	if json.Unmarshal(replayed.Body, &resource) != nil || resource.ID == "" {
		t.Fatal("original metadata")
	}
	f.assertAtomicCreation(t, resource.ID, 1)
}

func TestNativeAuditAndOutboxFailureRollBackKernelAndProjection(t *testing.T) {
	for _, table := range []string{"audit.records", "public.outbox_messages"} {
		for _, operation := range []scim.Operation{scim.UserCreate, scim.UserReplace, scim.UserPatch, scim.UserDelete} {
			t.Run(table+"/"+string(operation), func(t *testing.T) {
				f := newNativeFixture(t)
				var id, originalProjection string
				var original scim.Response
				var originalUser identity.User
				if operation != scim.UserCreate {
					id = createNativeNamed(t, f, "RollbackBefore", "Before failure")
					var err error
					original, err = f.service.Execute(f.ctx, scim.Request{Operation: scim.UserGet, Credential: f.bearer, ResourceID: id})
					if err != nil {
						t.Fatal(err)
					}
					originalUser, err = f.service.directory.Get(f.ctx, identity.GetUserQuery{TenantID: f.config.Scope.TenantID, UserID: identity.UserID(id)})
					if err != nil {
						t.Fatal(err)
					}
					if err := f.pool.Raw().QueryRow(f.ctx, `SELECT to_jsonb(s)::text FROM scim.users s WHERE resource_id=$1`, id).Scan(&originalProjection); err != nil {
						t.Fatal("original complete projection state", err)
					}
				}
				type successCounts struct{ users, attributes, projections, messages, bindings, audits int }
				counts := func() successCounts {
					t.Helper()
					var value successCounts
					if err := f.pool.Raw().QueryRow(f.ctx, `SELECT
 (SELECT count(*) FROM identity.users),(SELECT count(*) FROM identity.user_attributes),
 (SELECT count(*) FROM scim.users),(SELECT count(*) FROM public.outbox_messages),
 (SELECT count(*) FROM public.identity_outbox_bindings),(SELECT count(*) FROM audit.records WHERE outcome=$1)`, int16(audit.OutcomeSucceeded)).Scan(&value.users, &value.attributes, &value.projections, &value.messages, &value.bindings, &value.audits); err != nil {
						t.Fatal("actual owned success effects", err)
					}
					return value
				}
				before := counts()
				var reached atomic.Bool
				pool, err := database.Connect(f.ctx, database.Config{DSN: os.Getenv("SCIM_POSTGRES_TEST_DSN"), MaxConns: 3, Configure: func(c *database.PoolConfig) error {
					c.ConnConfig.Database = f.pool.Raw().Config().ConnConfig.Database
					c.ConnConfig.RuntimeParams["client_min_messages"] = "notice"
					c.ConnConfig.OnNotice = func(_ *pgconn.PgConn, notice *pgconn.Notice) {
						if notice.Code == "PZ001" {
							reached.Store(true)
						}
					}
					return nil
				}})
				if err != nil {
					t.Fatal("owned failure-observation pool", err)
				}
				defer func() {
					cleanup, stop := context.WithTimeout(context.Background(), 3*time.Second)
					defer stop()
					if err := pool.Close(cleanup); err != nil {
						t.Error("failure-observation pool cleanup", err)
					}
				}()
				service, err := NewService(pool, f.config, f.keys)
				if err != nil {
					t.Fatal(err)
				}
				// The notice survives rollback and proves this actual required-owner
				// INSERT was reached, rather than accepting an unrelated early error.
				if _, err := f.pool.Raw().Exec(f.ctx, `CREATE FUNCTION public.scim_fixture_failure() RETURNS trigger LANGUAGE plpgsql AS $f$ BEGIN RAISE NOTICE USING ERRCODE='PZ001',MESSAGE='owned failure reached'; RAISE EXCEPTION 'fixture failure'; END $f$; CREATE TRIGGER scim_fixture_failure BEFORE INSERT ON `+table+` FOR EACH ROW EXECUTE FUNCTION public.scim_fixture_failure()`); err != nil {
					t.Fatal("owned failure boundary", err)
				}
				request := scim.Request{Operation: operation, Credential: f.bearer, ResourceID: id, IfMatch: original.ETag, IdempotencyKey: "must-rollback", ContentType: "application/scim+json"}
				switch operation {
				case scim.UserCreate, scim.UserReplace:
					request.Body = []byte(`{"schemas":["urn:ietf:params:scim:schemas:core:2.0:User"],"userName":"RollbackChanged","displayName":"Not durable"}`)
				case scim.UserPatch:
					request.Body = []byte(`{"schemas":["urn:ietf:params:scim:api:messages:2.0:PatchOp"],"Operations":[{"op":"replace","path":"userName","value":"RollbackChanged"},{"op":"replace","path":"displayName","value":"Not durable"}]}`)
				}
				if response, err := service.Execute(f.ctx, request); err == nil || len(response.Body) != 0 || !reached.Load() {
					t.Fatal("required owner failure was not reached or returned success", reached.Load(), err)
				}
				if after := counts(); after != before {
					t.Fatalf("required owner failure leaked success effects: before=%+v after=%+v", before, after)
				}
				var committed int
				if err := f.pool.Raw().QueryRow(f.ctx, `SELECT count(*) FROM identity.commands WHERE purpose=$1 AND state='committed'`, string(operation)).Scan(&committed); err != nil || committed != 0 {
					t.Fatal("failed mutation received a committed journal result", committed, err)
				}
				if operation != scim.UserCreate {
					user, err := f.service.directory.Get(f.ctx, identity.GetUserQuery{TenantID: f.config.Scope.TenantID, UserID: identity.UserID(id)})
					if err != nil || user != originalUser {
						t.Fatal("required owner failure changed core user version/status", err)
					}
					assertNativeMappedFields(t, f, id, "RollbackBefore", "Before failure")
					var projection string
					if err := f.pool.Raw().QueryRow(f.ctx, `SELECT to_jsonb(s)::text FROM scim.users s WHERE resource_id=$1`, id).Scan(&projection); err != nil || projection != originalProjection {
						t.Fatal("required owner failure changed native payload/generation/tombstone/keys", err)
					}
					response, err := f.service.Execute(f.ctx, scim.Request{Operation: scim.UserGet, Credential: f.bearer, ResourceID: id})
					if err != nil || response.ETag != original.ETag || !bytes.Equal(response.Body, original.Body) {
						t.Fatal("required owner failure changed the public resource/ETag", err)
					}
				}
			})
		}
	}
}

func TestNativeCurrentAuthorityWithdrawal(t *testing.T) {
	for _, boundary := range []string{"policy", "organization", "credential", "epoch"} {
		t.Run(boundary, func(t *testing.T) {
			f := newNativeFixture(t)
			if _, err := f.service.InitializeConfiguredConnection(f.ctx); err != nil {
				t.Fatal(err)
			}
			r := scim.Request{Operation: scim.UserCreate, Credential: f.bearer, IdempotencyKey: "authority-create", ContentType: "application/scim+json", Body: []byte(`{"schemas":["urn:ietf:params:scim:schemas:core:2.0:User"],"userName":"Authority"}`)}
			created, err := f.service.Execute(f.ctx, r)
			if err != nil {
				t.Fatal(err)
			}
			var view struct {
				ID string `json:"id"`
			}
			if json.Unmarshal(created.Body, &view) != nil || view.ID == "" {
				t.Fatal("projection")
			}
			var sql string
			switch boundary {
			case "policy":
				f.deny.Store(true)
			case "organization":
				sql = `UPDATE organization.organizations SET state='archived',version=version+1 WHERE tenant_id='tenant-a' AND organization_id='organization-a'`
			case "credential":
				sql = `UPDATE scim.connections SET state='revoked',version=version+1 WHERE tenant_id='tenant-a' AND connection_id='connection-a'`
			case "epoch":
				sql = `UPDATE authorization_subject_authorities SET version=version+1 WHERE tenant_id='tenant-a' AND policy_namespace='scim-test' AND subject_id='scim-service'`
			}
			if sql != "" {
				if _, err := f.pool.Raw().Exec(f.ctx, sql); err != nil {
					t.Fatal("withdrawal fixture", err)
				}
			}
			for _, request := range []scim.Request{r, {Operation: scim.UserGet, Credential: f.bearer, ResourceID: view.ID}} {
				if got, err := f.service.Execute(f.ctx, request); err == nil || len(got.Body) != 0 {
					t.Fatal("withdrawn current authority disclosed result", err)
				}
			}
			if _, err := f.service.InitializeConfiguredConnection(f.ctx); err == nil {
				t.Fatal("bootstrap resurrected withdrawn state")
			}
			if boundary == "organization" {
				if _, err := f.pool.Raw().Exec(f.ctx, `UPDATE organization.organizations SET state='active',version=version+1 WHERE tenant_id='tenant-a' AND organization_id='organization-a'`); err != nil {
					t.Fatal("organization restore fixture")
				}
				if _, err := f.service.Execute(f.ctx, r); err == nil {
					t.Fatal("organization restore resurrected old credential epoch")
				}
				if _, err := f.service.InitializeConfiguredConnection(f.ctx); err == nil {
					t.Fatal("bootstrap reset restored organization epoch")
				}
			}
		})
	}
}

func TestNativeConnectionPartitionAndCredential(t *testing.T) {
	f := newNativeFixture(t)
	if _, err := f.service.InitializeConfiguredConnection(f.ctx); err != nil {
		t.Fatal(err)
	}
	request := scim.Request{Operation: scim.UserCreate, Credential: f.bearer, IdempotencyKey: "same-key-two-connections", ContentType: "application/scim+json", Body: []byte(`{"schemas":["urn:ietf:params:scim:schemas:core:2.0:User"],"userName":"Partitioned","displayName":"Scoped"}`)}
	first, err := f.service.Execute(f.ctx, request)
	if err != nil {
		t.Fatal(err)
	}
	var view struct {
		ID string `json:"id"`
	}
	if json.Unmarshal(first.Body, &view) != nil || view.ID == "" {
		t.Fatal("first projection")
	}
	c := f.config
	c.Scope.ConnectionID = "connection-b"
	bearer := authentication.NewBearerCredential("different-native-scim-credential-with-admitted-length")
	configured, configErr := NewConfiguredCredential("credential-b", bearer, [32]byte{72})
	if configErr != nil {
		t.Fatal(configErr)
	}
	c.Credential = configured
	other, constructErr := NewService(f.pool, c, f.keys)
	if constructErr != nil {
		t.Fatal(constructErr)
	}
	if _, err := other.InitializeConfiguredConnection(f.ctx); err != nil {
		t.Fatal(err)
	}
	get := scim.Request{Operation: scim.UserGet, Credential: bearer, ResourceID: view.ID}
	if _, err := other.Execute(f.ctx, get); err == nil || protocolStatus(err) != 404 {
		t.Fatal("cross-connection resource disclosed", err)
	}
	if _, err := f.service.Execute(f.ctx, get); err == nil || protocolStatus(err) != 401 {
		t.Fatal("foreign connection credential accepted", err)
	}
	request.Credential = bearer
	second, err := other.Execute(f.ctx, request)
	if err != nil || second.Status != 201 {
		t.Fatal("scope-local key/username incorrectly conflicted", err)
	}
	var secondView struct {
		ID string `json:"id"`
	}
	if json.Unmarshal(second.Body, &secondView) != nil || secondView.ID == view.ID {
		t.Fatal("partition did not create independent native user")
	}
}

func TestNativeConcurrentUsernameIsOneAtomicCreation(t *testing.T) {
	f := newNativeFixture(t)
	if _, err := f.service.InitializeConfiguredConnection(f.ctx); err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	statuses := make(chan int, 2)
	for _, key := range []string{"writer-one", "writer-two"} {
		wg.Add(1)
		go func(key string) {
			defer wg.Done()
			got, err := f.service.Execute(f.ctx, scim.Request{Operation: scim.UserCreate, Credential: f.bearer, IdempotencyKey: key, ContentType: "application/scim+json", Body: []byte(`{"schemas":["urn:ietf:params:scim:schemas:core:2.0:User"],"userName":"SameName","displayName":"Concurrent"}`)})
			if err != nil {
				statuses <- protocolStatus(err)
			} else {
				statuses <- got.Status
			}
		}(key)
	}
	wg.Wait()
	close(statuses)
	created, conflict := 0, 0
	for status := range statuses {
		switch status {
		case 201:
			created++
		case 409:
			conflict++
		default:
			t.Error("unexpected concurrent outcome", status)
		}
	}
	if created != 1 || conflict != 1 {
		t.Fatal("concurrent uniqueness", created, conflict)
	}
	var resource string
	if err := f.pool.Raw().QueryRow(f.ctx, `SELECT resource_id FROM scim.users`).Scan(&resource); err != nil {
		t.Fatal(err)
	}
	f.assertAtomicCreation(t, resource, 1)
	ctx, cancel := context.WithCancel(f.ctx)
	cancel()
	if result, err := f.service.Execute(ctx, scim.Request{Operation: scim.UserGet, Credential: f.bearer, ResourceID: resource}); err == nil || len(result.Body) != 0 {
		t.Fatal("cancelled request disclosed result")
	}
}

func TestNativeHeaderlessCreateUsesOneOrdinaryCommand(t *testing.T) {
	f := newNativeFixture(t)
	if _, err := f.service.InitializeConfiguredConnection(f.ctx); err != nil {
		t.Fatal(err)
	}
	r := scim.Request{Operation: scim.UserCreate, Credential: f.bearer, ContentType: "application/scim+json", Body: []byte(`{"schemas":["urn:ietf:params:scim:schemas:core:2.0:User"],"userName":"Headerless","displayName":"No retry header"}`)}
	created, err := f.service.Execute(f.ctx, r)
	if err != nil || created.Status != 201 {
		t.Fatal("optional header became mandatory", err)
	}
	var view struct {
		ID string `json:"id"`
	}
	if json.Unmarshal(created.Body, &view) != nil || view.ID == "" {
		t.Fatal("headerless projection")
	}
	f.assertAtomicCreation(t, view.ID, 1)
	if _, err := f.service.Execute(f.ctx, r); err == nil || protocolStatus(err) != 409 {
		t.Fatal("fresh keyless retry duplicated username", err)
	}
	var mappings int
	if err := f.pool.Raw().QueryRow(f.ctx, `SELECT count(*) FROM identity.request_key_mappings WHERE route_id='identity.scim.user-create'`).Scan(&mappings); err != nil || mappings != 0 {
		t.Fatal("headerless path invented a client-key mapping", mappings, err)
	}
}

func TestNativeDisabledDirectoryDeniesCreateReplayReadAndBootstrap(t *testing.T) {
	f := newNativeFixture(t)
	r := scim.Request{Operation: scim.UserCreate, Credential: f.bearer, IdempotencyKey: "directory-original", ContentType: "application/scim+json", Body: []byte(`{"schemas":["urn:ietf:params:scim:schemas:core:2.0:User"],"userName":"DirectoryOriginal","displayName":"Original"}`)}
	created, err := f.service.Execute(f.ctx, r)
	if err != nil || created.Status != 201 {
		t.Fatal("initial actual create", err)
	}
	var view struct {
		ID string `json:"id"`
	}
	if json.Unmarshal(created.Body, &view) != nil || view.ID == "" {
		t.Fatal("original projection")
	}
	if _, err := f.pool.Raw().Exec(f.ctx, `UPDATE identity.tenant_authorities SET enabled=false,version=version+1 WHERE tenant_id='tenant-a'`); err != nil {
		t.Fatal("actual tenant authority fixture")
	}
	requests := []struct {
		name    string
		request scim.Request
	}{
		{"keyed replay", r},
		{"get", scim.Request{Operation: scim.UserGet, Credential: f.bearer, ResourceID: view.ID}},
	}
	fresh := r
	fresh.IdempotencyKey = "directory-fresh"
	fresh.Body = []byte(`{"schemas":["urn:ietf:params:scim:schemas:core:2.0:User"],"userName":"MustNotProvision","displayName":"Disabled tenant"}`)
	requests = append(requests, struct {
		name    string
		request scim.Request
	}{"fresh create", fresh})
	for _, entry := range requests {
		t.Run(entry.name, func(t *testing.T) {
			if result, err := f.service.Execute(f.ctx, entry.request); err == nil || len(result.Body) != 0 {
				t.Fatal("disabled tenant retained provisioning/disclosure", err)
			}
		})
	}
	t.Run("bootstrap", func(t *testing.T) {
		if _, err := f.service.InitializeConfiguredConnection(f.ctx); err == nil {
			t.Fatal("disabled tenant retained bootstrap authority")
		}
	})
}
