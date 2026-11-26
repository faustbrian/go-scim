//go:build integration

package scimpostgres

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	authentication "github.com/faustbrian/go-authentication/v2"
	identity "github.com/faustbrian/go-identity"
	database "github.com/faustbrian/go-postgres"
	scim "github.com/faustbrian/go-scim"
	"github.com/jackc/pgx/v5"
)

// Observe the actual native Group queries without replacing the Group store or
// retaining bearer/query arguments. Only the selected read pool uses this tracer.
type managedGroupReadTrace struct {
	allowed, precededGate atomic.Bool
	queries               atomic.Int64
}

func (r *managedGroupReadTrace) TraceQueryStart(ctx context.Context, _ *pgx.Conn, data pgx.TraceQueryStartData) context.Context {
	if strings.Contains(data.SQL, "FROM scim.groups") {
		r.queries.Add(1)
		if !r.allowed.Load() {
			r.precededGate.Store(true)
		}
	}
	return ctx
}

func (*managedGroupReadTrace) TraceQueryEnd(context.Context, *pgx.Conn, pgx.TraceQueryEndData) {}

func (r *managedGroupReadTrace) reset() {
	r.allowed.Store(false)
	r.precededGate.Store(false)
	r.queries.Store(0)
}

func TestManagedConnectionAdmittedGroupReadsUseIssuedBearerBeforeNativeIO(t *testing.T) {
	f := newManagedConnectionAdminFixture(t)
	service, _ := newManagedConnectionWriteFixture(t, f)
	history, err := (GroupsMigrationSource{Base: UsersMigrationSource{Base: MigrationSource{Version: 40}, Version: 41}, Version: 43}).Load(f.ctx)
	if err != nil {
		t.Fatal("load existing native Groups migration", err)
	}
	if _, err := f.pool.Raw().Exec(f.ctx, history[len(history)-1].UpSQL()); err != nil {
		t.Fatal("apply existing native Groups migration", err)
	}
	connection, err := service.ConnectionCreate(f.ctx, managedConnectionCreateRequest(t, f, "managed-group-read-provider", "managed-group-read-connection"))
	if err != nil || connection.Bearer.Token() == "" {
		t.Fatal("issue actual managed bearer before Group read", err)
	}
	other, err := service.ConnectionCreate(f.ctx, managedConnectionCreateRequest(t, f, "other-group-read-provider", "other-group-read-connection"))
	if err != nil || other.Bearer.Token() == "" {
		t.Fatal("issue independent connection bearer for isolation", err)
	}
	source, err := service.loadManagedProvisioning(f.ctx, f.tenant, connection.Bearer)
	if err != nil {
		t.Fatal("load actual managed provisioning scope for native fixture seed", err)
	}
	groups, err := NewGroupsService(source, scim.DefaultGroupMembers)
	if err != nil {
		t.Fatal("select existing native Group store for fixture seed", err)
	}
	create := func(name, key, members string) scim.Response {
		t.Helper()
		out, err := groups.Execute(f.ctx, scim.Request{Operation: scim.GroupCreate, Credential: connection.Bearer, IdempotencyKey: key, ContentType: "application/scim+json", Body: []byte(`{"schemas":["urn:ietf:params:scim:schemas:core:2.0:Group"],"displayName":"` + name + `"` + members + `}`)})
		if err != nil || out.Status != 201 {
			t.Fatal("seed native Group through existing authorized store", err)
		}
		return out
	}
	child := create("Other", "managed-group-read-child", "")
	created := create("Selected Zulu", "managed-group-read-zulu", `,"members":[{"value":"`+groupID(t, child)+`","type":"Group"}]`)
	create("Selected Alpha", "managed-group-read-alpha", "")
	id := groupID(t, created)
	user, err := service.ExecuteManagedProvisioning(f.ctx, f.tenant, scim.Request{Operation: scim.UserCreate, Credential: connection.Bearer, IdempotencyKey: "managed-group-read-user", ContentType: "application/scim+json", Body: []byte(`{"schemas":["urn:ietf:params:scim:schemas:core:2.0:User"],"userName":"managed-group-read-sibling"}`)})
	if err != nil || user.Status != 201 {
		t.Fatal("seed actual managed User for sibling preservation", err)
	}

	trace := new(managedGroupReadTrace)
	pool, err := database.Connect(f.ctx, database.Config{DSN: os.Getenv("SCIM_POSTGRES_TEST_DSN"), MaxConns: 3, Configure: func(c *database.PoolConfig) error {
		c.ConnConfig.Database = f.pool.Raw().Config().ConnConfig.Database
		c.ConnConfig.Tracer = trace
		return nil
	}})
	if err != nil {
		t.Fatal("fixture-owned Group read observation pool", err)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		if err := pool.Close(ctx); err != nil {
			t.Error("Group read observation pool cleanup", err)
		}
	})
	observed := *service
	observed.pool = pool
	selected, ok := any(&observed).(interface {
		ExecuteManagedAdmittedGroupRead(context.Context, identity.TenantID, scim.Request, int, scim.ProtocolAdmission) (scim.Response, error)
	})
	if !ok {
		t.Fatal("managed connection service has no explicit admitted Group Get/List selection")
	}
	snapshot := func() string {
		t.Helper()
		var state string
		if err := f.pool.Raw().QueryRow(f.ctx, `SELECT jsonb_build_object(
 'users',(SELECT count(*) FROM identity.users),
 'user_projections',(SELECT count(*) FROM scim.users),
 'groups',(SELECT jsonb_agg(jsonb_build_array(resource_id,generation,encode(resource,'base64')) ORDER BY resource_id) FROM scim.groups),
 'commands',(SELECT count(*) FROM identity.commands),
 'request_mappings',(SELECT count(*) FROM identity.request_key_mappings),
 'audits',(SELECT count(*) FROM audit.records),
 'outbox',(SELECT count(*) FROM public.outbox_messages))::text`).Scan(&state); err != nil {
			t.Fatal("read exact protected-effect state", err)
		}
		return state
	}
	before := snapshot()
	request := scim.Request{Operation: scim.GroupGet, Credential: connection.Bearer, ResourceID: id}
	assertNoEffects := func() {
		t.Helper()
		if snapshot() != before {
			t.Fatal("managed Group reads changed projections, commands, audit or outbox")
		}
	}
	assertGate := func(ctx context.Context, client scim.ProtocolClient) {
		t.Helper()
		deadline, bounded := ctx.Deadline()
		if ctx.Err() != nil || !bounded || !deadline.After(time.Now()) || time.Until(deadline) > f.config.MaximumDuration || client.ID != f.config.ActorID || client.TenantID != f.tenant || trace.queries.Load() != 0 {
			t.Fatal("Group gate lost exact configured client, tenant, original budget or native read ordering")
		}
	}

	t.Run("preflight denials do not charge or read Groups", func(t *testing.T) {
		for _, tc := range []struct {
			name      string
			operation scim.Operation
			tenant    identity.TenantID
			bearer    authentication.BearerCredential
			maximum   int
			nilGate   bool
			policy    bool
			canceled  bool
			status    int
		}{
			{name: "unissued bearer", bearer: authentication.NewBearerCredential("not-an-issued-managed-bearer"), status: 401},
			{name: "foreign tenant", tenant: "AAAAAAAAAAAAAAAAAAAAAQ", status: 401},
			{name: "native policy", policy: true, status: 403},
			{name: "missing gate", nilGate: true, status: 503},
			{name: "canceled parent", canceled: true, status: 503},
			{name: "invalid member ceiling", maximum: -1, status: 503},
			{name: "oversized member ceiling", maximum: scim.DefaultGroupMembers + 1, status: 503},
			{name: "Group search", operation: scim.GroupSearch, status: 501},
			{name: "Group create", operation: scim.GroupCreate, status: 501},
			{name: "Group replace", operation: scim.GroupReplace, status: 501},
			{name: "Group patch", operation: scim.GroupPatch, status: 501},
			{name: "Group delete", operation: scim.GroupDelete, status: 501},
			{name: "User get", operation: scim.UserGet, status: 501},
			{name: "User list", operation: scim.UserList, status: 501},
			{name: "discovery", operation: scim.ServiceProviderConfig, status: 501},
			{name: "root search", operation: scim.Search, status: 501},
			{name: "Bulk", operation: scim.Bulk, status: 501},
		} {
			t.Run(tc.name, func(t *testing.T) {
				trace.reset()
				candidate := request
				if tc.operation != "" {
					candidate.Operation = tc.operation
				}
				if tc.bearer.Token() != "" {
					candidate.Credential = tc.bearer
				}
				tenant := f.tenant
				if tc.tenant != "" {
					tenant = tc.tenant
				}
				maximum := scim.DefaultGroupMembers
				if tc.maximum != 0 {
					maximum = tc.maximum
				}
				f.deny.Store(tc.policy)
				defer f.deny.Store(false)
				ctx, cancel := context.WithCancel(f.ctx)
				defer cancel()
				if tc.canceled {
					cancel()
				}
				calls := 0
				var gate scim.ProtocolAdmission
				if !tc.nilGate {
					gate = func(context.Context, scim.ProtocolClient) *scim.Error { calls++; return nil }
				}
				out, err := selected.ExecuteManagedAdmittedGroupRead(ctx, tenant, candidate, maximum, gate)
				assertManagedReadDenial(t, out, err, tc.status)
				if calls != 0 || trace.queries.Load() != 0 {
					t.Fatal("preflight denial charged the gate or queried native Groups")
				}
				assertNoEffects()
			})
		}
	})

	t.Run("gate denials do not read or change Groups", func(t *testing.T) {
		for _, operation := range []scim.Operation{scim.GroupGet, scim.GroupList} {
			for _, denial := range []string{"quota", "policy", "unavailable", "panic", "cancel"} {
				t.Run(string(operation)+"/"+denial, func(t *testing.T) {
					trace.reset()
					candidate := request
					candidate.Operation = operation
					if operation == scim.GroupList {
						candidate.ResourceID = ""
					}
					ctx, cancel := context.WithCancel(f.ctx)
					defer cancel()
					calls, status := 0, 503
					out, err := selected.ExecuteManagedAdmittedGroupRead(ctx, f.tenant, candidate, scim.DefaultGroupMembers, func(ctx context.Context, client scim.ProtocolClient) *scim.Error {
						calls++
						assertGate(ctx, client)
						switch denial {
						case "quota":
							status = 429
							return scim.NewRateLimitedError(1250 * time.Millisecond)
						case "policy":
							status = 403
							return scim.NewError(403, "")
						case "panic":
							panic("private gate diagnostic")
						case "cancel":
							cancel()
							return scim.NewError(403, "")
						default:
							return scim.NewError(503, "")
						}
					})
					assertManagedReadDenial(t, out, err, status)
					var protocol *scim.Error
					if !errors.As(err, &protocol) || protocol.SCIMType() != "" || status == 429 && protocol.RetryAfterSeconds() != 2 || calls != 1 || trace.queries.Load() != 0 {
						t.Fatal("Group gate denial lost redaction, retry, exactly-once ordering or no-read fence")
					}
					assertNoEffects()
				})
			}
		}
	})

	t.Run("allowed Get and filtered paginated List use native Group reads", func(t *testing.T) {
		for _, operation := range []scim.Operation{scim.GroupGet, scim.GroupList} {
			trace.reset()
			calls := 0
			candidate := request
			candidate.Operation = operation
			if operation == scim.GroupList {
				count := 1
				candidate.ResourceID = ""
				candidate.Query = scim.Query{Filter: `displayName sw "Selected"`, SortBy: "displayName", StartIndex: 2, Count: &count, Attributes: "displayName"}
			}
			out, err := selected.ExecuteManagedAdmittedGroupRead(f.ctx, f.tenant, candidate, scim.DefaultGroupMembers, func(ctx context.Context, client scim.ProtocolClient) *scim.Error {
				calls++
				assertGate(ctx, client)
				trace.allowed.Store(true)
				return nil
			})
			if err != nil || out.Status != 200 || calls != 1 || trace.precededGate.Load() || trace.queries.Load() == 0 {
				t.Fatal("allowed Group read bypassed its once-before-native-I/O gate", operation, err)
			}
			if operation == scim.GroupGet {
				if !bytes.Equal(out.Body, created.Body) || out.ETag != created.ETag || out.Location != created.Location || trace.queries.Load() != 1 {
					t.Fatal("admitted managed Group Get changed the exact original projection or metadata")
				}
			} else {
				var page struct {
					TotalResults, StartIndex, ItemsPerPage int
					Resources                              []struct {
						ID, DisplayName string
						Members         []json.RawMessage
						Meta            struct{ Version string }
					}
				}
				if json.Unmarshal(out.Body, &page) != nil || page.TotalResults != 2 || page.StartIndex != 2 || page.ItemsPerPage != 1 || len(page.Resources) != 1 || page.Resources[0].ID != id || page.Resources[0].DisplayName != "Selected Zulu" || page.Resources[0].Meta.Version != string(created.ETag) || len(page.Resources[0].Members) != 0 || trace.queries.Load() != 2 {
					t.Fatal("admitted managed Group List lost filtering, exact count, sort/page, projection or version")
				}
			}
			assertNoEffects()
		}
	})

	t.Run("trusted zero member ceiling does not disclose a populated Group", func(t *testing.T) {
		trace.reset()
		calls := 0
		out, err := selected.ExecuteManagedAdmittedGroupRead(f.ctx, f.tenant, request, 0, func(ctx context.Context, client scim.ProtocolClient) *scim.Error {
			calls++
			assertGate(ctx, client)
			trace.allowed.Store(true)
			return nil
		})
		assertManagedReadDenial(t, out, err, 503)
		if calls != 1 || trace.queries.Load() != 1 || trace.precededGate.Load() {
			t.Fatal("explicit zero was replaced with a default member budget or bypassed the read gate")
		}
		assertNoEffects()
	})

	t.Run("another genuine managed bearer cannot read this connection's Groups", func(t *testing.T) {
		for _, operation := range []scim.Operation{scim.GroupGet, scim.GroupList} {
			trace.reset()
			calls := 0
			candidate := request
			candidate.Operation, candidate.Credential = operation, other.Bearer
			if operation == scim.GroupList {
				candidate.ResourceID = ""
				candidate.Query.Filter = `id eq "` + id + `"`
			}
			out, err := selected.ExecuteManagedAdmittedGroupRead(f.ctx, f.tenant, candidate, scim.DefaultGroupMembers, func(ctx context.Context, client scim.ProtocolClient) *scim.Error {
				calls++
				assertGate(ctx, client)
				trace.allowed.Store(true)
				return nil
			})
			if operation == scim.GroupGet {
				assertManagedReadDenial(t, out, err, 404)
			} else {
				var page struct {
					TotalResults, ItemsPerPage int
					Resources                  []json.RawMessage
				}
				if err != nil || json.Unmarshal(out.Body, &page) != nil || page.TotalResults != 0 || page.ItemsPerPage != 0 || len(page.Resources) != 0 {
					t.Fatal("List disclosed another managed connection's Group", err)
				}
			}
			if calls != 1 || trace.precededGate.Load() || trace.queries.Load() == 0 {
				t.Fatal("cross-connection read lost its own admitted native scope")
			}
			assertNoEffects()
		}
	})

	t.Run("ordinary managed User reads and operation selections are unchanged", func(t *testing.T) {
		userRequest := scim.Request{Operation: scim.UserGet, Credential: connection.Bearer, ResourceID: parseNativeUser(t, user).ID}
		out, err := service.ExecuteManagedProvisioning(f.ctx, f.tenant, userRequest)
		if err != nil || !bytes.Equal(out.Body, user.Body) || out.ETag != user.ETag {
			t.Fatal("Group admission changed ordinary managed User reads", err)
		}
		out, err = service.ExecuteManagedProvisioning(f.ctx, f.tenant, request)
		assertManagedReadDenial(t, out, err, 501)
		out, err = service.ExecuteManagedAdmittedRead(f.ctx, f.tenant, request, func(context.Context, scim.ProtocolClient) *scim.Error {
			t.Fatal("managed User admission selected a Group operation")
			return nil
		})
		assertManagedReadDenial(t, out, err, 501)
		assertNoEffects()
	})
}
