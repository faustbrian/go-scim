//go:build integration

package scimpostgres

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net"
	"os"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/faustbrian/go-audit"
	"github.com/faustbrian/go-authorization/v3"
	authoritypg "github.com/faustbrian/go-authorization/v3/postgres"
	identity "github.com/faustbrian/go-identity"
	organizationpg "github.com/faustbrian/go-organization/postgres"
	database "github.com/faustbrian/go-postgres"
	scim "github.com/faustbrian/go-scim"
	"github.com/jackc/pgx/v5/pgconn"
)

type managedRotationAPI interface {
	PrepareConnectionRotate(context.Context, ConnectionRotatePreparationRequest) (identity.Command, error)
	ConnectionRotate(context.Context, ConnectionRotateRequest) (ConnectionRotateResult, error)
}

func managedRotationSelection(t *testing.T, service *ManagedConnectionService) managedRotationAPI {
	t.Helper()
	selected, ok := any(service).(managedRotationAPI)
	if !ok {
		t.Fatal("native managed rotation preparation and exact-command execution are unavailable")
	}
	return selected
}

func prepareManagedRotation(t *testing.T, f *managedConnectionAdminFixture, service *ManagedConnectionService, connection scim.ConnectionRecord) ConnectionRotateRequest {
	t.Helper()
	command, err := managedRotationSelection(t, service).PrepareConnectionRotate(f.ctx, ConnectionRotatePreparationRequest{Authentication: f.admin, ConnectionID: connection.Scope().ProviderConnectionID, ExpectedVersion: connection.Version()})
	if err != nil || command == (identity.Command{}) {
		t.Fatal("prepare exact server-owned managed rotation", err)
	}
	return ConnectionRotateRequest{Authentication: f.admin, ConnectionID: connection.Scope().ProviderConnectionID, ExpectedVersion: connection.Version(), Command: command}
}

func TestManagedConnectionRotateWithdrawsPredecessorAndPreservesUserBindings(t *testing.T) {
	f := newManagedConnectionAdminFixture(t)
	service, _ := newManagedConnectionWriteFixture(t, f)
	selected := managedRotationSelection(t, service)
	installSource(t, f.ctx, f.pool, organizationpg.DirectoryMembershipMigrationSource{Version: 52})
	created, err := service.ConnectionCreate(f.ctx, managedConnectionCreateRequest(t, f, "rotation-provider", "rotation-create"))
	if err != nil {
		t.Fatal(err)
	}
	user, err := service.ExecuteManagedProvisioning(f.ctx, f.tenant, scim.Request{Operation: scim.UserCreate, Credential: created.Bearer, IdempotencyKey: "rotation-user", ContentType: "application/scim+json", Body: []byte(`{"schemas":["urn:ietf:params:scim:schemas:core:2.0:User"],"userName":"rotation-person"}`)})
	if err != nil || user.Status != 201 {
		t.Fatal("seed actual managed User", err)
	}
	id := parseNativeUser(t, user).ID
	var userID string
	if err := f.pool.Raw().QueryRow(f.ctx, `SELECT user_id FROM scim.users WHERE resource_id=$1`, id).Scan(&userID); err != nil {
		t.Fatal("read actual User-to-identity binding", err)
	}
	seedManagedWithdrawalMember(t, f, userID)
	seedManagedWithdrawalGrant(t, f, userID, string(created.Connection.Scope().ProviderID), string(created.Connection.Scope().ProviderConnectionID), id)
	snapshot := func() string {
		t.Helper()
		var wire string
		if err := f.pool.Raw().QueryRow(f.ctx, `SELECT jsonb_build_object('users',(SELECT jsonb_agg(to_jsonb(u)) FROM scim.users u WHERE resource_id=$1),'memberships',(SELECT jsonb_agg(to_jsonb(m)) FROM organization.memberships m),'grants',(SELECT jsonb_agg(to_jsonb(g)) FROM organization.directory_membership_grants g),'configured',(SELECT to_jsonb(c) FROM scim.connections c WHERE tenant_id='tenant-a' AND connection_id='connection-a'))::text`, id).Scan(&wire); err != nil {
			t.Fatal("snapshot existing bindings", err)
		}
		return wire
	}
	before := snapshot()
	request := prepareManagedRotation(t, f, service, created.Connection)
	get := scim.Request{Operation: scim.UserGet, Credential: created.Bearer, ResourceID: id}
	if out, err := service.ExecuteManagedProvisioning(f.ctx, f.tenant, get); err != nil || out.Status != 200 {
		t.Fatal("preparation withdrew predecessor", err)
	}
	rotated, err := selected.ConnectionRotate(f.ctx, request)
	_, oldCredential, valid := parseManagedBearer(created.Bearer)
	if err != nil || !valid || rotated.Bearer.Token() == "" || rotated.Bearer.Token() == created.Bearer.Token() || rotated.Connection.Scope() != created.Connection.Scope() || rotated.Connection.Version() != 2 || rotated.PreviousCredentialID != oldCredential || rotated.PreviousBearerDisposition != PreviousBearerRevoked {
		t.Fatal("rotation did not reveal one exact zero-overlap successor", err)
	}
	out, err := service.ExecuteManagedProvisioning(f.ctx, f.tenant, get)
	assertManagedReadDenial(t, out, err, 401)
	get.Credential = rotated.Bearer
	if out, err := service.ExecuteManagedProvisioning(f.ctx, f.tenant, get); err != nil || out.Status != 200 || parseNativeUser(t, out).ID != id || out.ETag != user.ETag {
		t.Fatal("successor lost original User/version", err)
	}
	get.Operation, get.ResourceID = scim.UserList, ""
	out, err = service.ExecuteManagedProvisioning(f.ctx, f.tenant, get)
	var page struct {
		TotalResults int
		Resources    []struct{ ID string }
	}
	if err != nil || json.Unmarshal(out.Body, &page) != nil || page.TotalResults != 1 || len(page.Resources) != 1 || page.Resources[0].ID != id {
		t.Fatal("successor lost exact source User list", err)
	}
	record, err := service.ConnectionGet(f.ctx, ConnectionGetRequest{Authentication: f.admin, ConnectionID: request.ConnectionID})
	if err != nil || record.Version() != 2 {
		t.Fatal("Get lost successor version", err)
	}
	listed, err := service.ConnectionList(f.ctx, ConnectionListRequest{Authentication: f.admin, OrganizationID: f.organization, Limit: 20})
	if err != nil || len(listed.Connections) != 1 || listed.Connections[0].Version() != 2 {
		t.Fatal("List lost successor version", err)
	}
	replay, err := selected.ConnectionRotate(f.ctx, request)
	if err != nil || replay.Connection.Version() != 2 || replay.Bearer.Token() != "" || replay.PreviousCredentialID != oldCredential || replay.PreviousBearerDisposition != PreviousBearerRevoked {
		t.Fatal("same original command revealed again or lost metadata", err)
	}
	if after := snapshot(); after != before {
		t.Fatal("rotation changed User, organization binding or configured version-one connection")
	}
	loaded, err := service.loadManagedProvisioning(f.ctx, f.tenant, rotated.Bearer)
	if err != nil || loaded == nil {
		t.Fatal("load exact durable successor", err)
	}
	if configured, err := NewService(f.pool, loaded.config(), f.keys); err == nil || configured != nil {
		t.Fatal("exported configured constructor enrolled a managed successor")
	}
	third, err := selected.ConnectionRotate(f.ctx, prepareManagedRotation(t, f, service, rotated.Connection))
	if err != nil || third.Connection.Version() != 3 || third.Bearer.Token() == "" {
		t.Fatal("a managed successor could not advance its exact next generation", err)
	}
	original, err := selected.ConnectionRotate(f.ctx, request)
	if err != nil || original.Connection.Version() != 2 || original.Bearer.Token() != "" {
		t.Fatal("later rotation replaced the retained original result or revealed again", err)
	}
}

func secondManagedRotationAdministrator(t *testing.T, f *managedConnectionAdminFixture) *managedConnectionAdminFixture {
	t.Helper()
	id, err := identity.NewSubjectID()
	if err != nil {
		t.Fatal(err)
	}
	other := *f
	other.actor = identity.UserID(id)
	if _, err := f.pool.Raw().Exec(f.ctx, `INSERT INTO identity.users(tenant_id,user_id,status,version) VALUES($1,$2,'active',1)`, string(f.tenant), string(other.actor)); err != nil {
		t.Fatal("second administrator native user", err)
	}
	if _, err := f.pool.Raw().Exec(f.ctx, `INSERT INTO identity.credential_references(tenant_id,user_id,credential_id,kind,owner,version,enabled) VALUES($1,$2,'password',1,'identity/password',1,true)`, string(f.tenant), string(other.actor)); err != nil {
		t.Fatal("second administrator native credential", err)
	}
	policy := authoritypg.AuthorityScope{TenantID: authorization.TenantID(f.tenant), PolicyNamespace: f.sessionProfile.PolicyNamespace, SubjectID: authorization.SubjectID(other.actor)}
	if _, err := authoritypg.InitializeAuthority(f.ctx, f.pool.Raw(), policy, time.Second); err != nil {
		t.Fatal("second administrator native policy", err)
	}
	organizationAuthority, err := organizationpg.OrganizationAuthorityScope(f.tenant, f.organization, other.actor)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := authoritypg.InitializeAuthority(f.ctx, f.pool.Raw(), organizationAuthority, time.Second); err != nil {
		t.Fatal("second administrator native organization authority", err)
	}
	if _, err := f.pool.Raw().Exec(f.ctx, `INSERT INTO organization.memberships(tenant_id,organization_id,user_id,role,state,version,authorization_version) VALUES($1,$2,$3,'administrator','active',1,1)`, string(f.tenant), string(f.organization), string(other.actor)); err != nil {
		t.Fatal("second active administrator membership", err)
	}
	if _, err := f.pool.Raw().Exec(f.ctx, `UPDATE organization.organizations SET member_count=member_count+1,version=version+1 WHERE tenant_id=$1 AND organization_id=$2`, string(f.tenant), string(f.organization)); err != nil {
		t.Fatal("align administrator aggregate", err)
	}
	other.seedCurrentAdminSession(t, policy)
	return &other
}

func TestManagedConnectionRotateDistinctOriginalsCompeteOnExactVersion(t *testing.T) {
	f := newManagedConnectionAdminFixture(t)
	service, _ := newManagedConnectionWriteFixture(t, f)
	selected := managedRotationSelection(t, service)
	other := secondManagedRotationAdministrator(t, f)
	created, err := service.ConnectionCreate(f.ctx, managedConnectionCreateRequest(t, f, "rotation-provider", "rotation-distinct"))
	if err != nil {
		t.Fatal(err)
	}
	requests := [2]ConnectionRotateRequest{prepareManagedRotation(t, f, service, created.Connection), prepareManagedRotation(t, other, service, created.Connection)}
	a, _ := requests[0].Command.Feature()
	b, _ := requests[1].Command.Feature()
	if a.Binding.CommandID == b.Binding.CommandID || a.Binding.ActorID == b.Binding.ActorID {
		t.Fatal("distinct authenticated administrators did not retain distinct originals")
	}
	var outputs [2]ConnectionRotateResult
	var failures [2]error
	var group sync.WaitGroup
	start := make(chan struct{})
	for i := range outputs {
		group.Go(func() { <-start; outputs[i], failures[i] = selected.ConnectionRotate(f.ctx, requests[i]) })
	}
	close(start)
	group.Wait()
	winners := 0
	conflicts := 0
	for i, out := range outputs {
		if failures[i] == nil && out.Bearer.Token() != "" && out.Connection.Version() == 2 {
			winners++
		}
		var conflict identity.ConflictError
		if errors.As(failures[i], &conflict) && out.Bearer.Token() == "" && out.Connection.Version() == 0 {
			conflicts++
		}
	}
	if winners != 1 || conflicts != 1 {
		t.Fatal("exact predecessor version did not have one winner and one redacted conflict", winners, conflicts, failures)
	}
	record, err := service.ConnectionGet(f.ctx, ConnectionGetRequest{Authentication: f.admin, ConnectionID: requests[0].ConnectionID})
	if err != nil || record.Version() != 2 {
		t.Fatal("competing originals advanced beyond one successor", err)
	}
}

func TestManagedConnectionRotateRejectsMismatchedOriginalAndCurrentAuthority(t *testing.T) {
	f := newManagedConnectionAdminFixture(t)
	service, _ := newManagedConnectionWriteFixture(t, f)
	selected := managedRotationSelection(t, service)
	created, err := service.ConnectionCreate(f.ctx, managedConnectionCreateRequest(t, f, "rotation-provider", "rotation-invalid"))
	if err != nil {
		t.Fatal(err)
	}
	request := prepareManagedRotation(t, f, service, created.Connection)
	stale, err := selected.PrepareConnectionRotate(f.ctx, ConnectionRotatePreparationRequest{Authentication: f.admin, ConnectionID: request.ConnectionID, ExpectedVersion: 2})
	if err == nil || stale != (identity.Command{}) {
		t.Fatal("stale predecessor preparation returned executable custody", err)
	}
	for _, change := range []func(*ConnectionRotateRequest){
		func(r *ConnectionRotateRequest) { r.Command = identity.Command{} },
		func(r *ConnectionRotateRequest) { r.ExpectedVersion++ },
		func(r *ConnectionRotateRequest) {
			id, _ := identity.NewSubjectID()
			r.ConnectionID = scim.ConnectionID(id)
		},
		func(r *ConnectionRotateRequest) {
			spec, ok := r.Command.Feature()
			if !ok {
				t.Fatal("missing native command projection")
			}
			spec.Fields[0].Value.Bytes[0] ^= 1
			r.Command, _ = identity.NewFeatureCommand(spec)
		},
	} {
		changed := request
		change(&changed)
		out, err := selected.ConnectionRotate(f.ctx, changed)
		if err == nil || out.Bearer.Token() != "" || out.Connection.Version() != 0 {
			t.Fatal("mismatched original produced result", err)
		}
	}
	f.deny.Store(true)
	out, err := selected.ConnectionRotate(f.ctx, request)
	f.deny.Store(false)
	if err == nil || out.Bearer.Token() != "" || out.Connection.Version() != 0 {
		t.Fatal("withdrawn current authority rotated", err)
	}
	record, err := service.ConnectionGet(f.ctx, ConnectionGetRequest{Authentication: f.admin, ConnectionID: request.ConnectionID})
	if err != nil || record.Version() != 1 {
		t.Fatal("rejected rotation altered predecessor", err)
	}
}

func TestManagedConnectionRotateCompetingExecutionsHaveOneReveal(t *testing.T) {
	f := newManagedConnectionAdminFixture(t)
	service, _ := newManagedConnectionWriteFixture(t, f)
	selected := managedRotationSelection(t, service)
	created, err := service.ConnectionCreate(f.ctx, managedConnectionCreateRequest(t, f, "rotation-provider", "rotation-race"))
	if err != nil {
		t.Fatal(err)
	}
	request := prepareManagedRotation(t, f, service, created.Connection)
	var group sync.WaitGroup
	var outputs [2]ConnectionRotateResult
	var failures [2]error
	start := make(chan struct{})
	for i := range outputs {
		group.Go(func() { <-start; outputs[i], failures[i] = selected.ConnectionRotate(f.ctx, request) })
	}
	close(start)
	group.Wait()
	reveals := 0
	for i, out := range outputs {
		if out.Bearer.Token() != "" {
			reveals++
		}
		if failures[i] != nil {
			var unknown identity.UnknownCommitError
			var conflict identity.ConflictError
			if !errors.As(failures[i], &unknown) && !errors.As(failures[i], &conflict) {
				t.Fatal("unexpected competition failure", failures[i])
			}
		}
	}
	if reveals != 1 {
		t.Fatal("competing rotation did not have exactly one newly committed reveal", reveals)
	}
	var committed, audits, events int
	if err := f.pool.Raw().QueryRow(f.ctx, `SELECT (SELECT count(*) FROM identity.commands WHERE purpose='identity.scim.connection-rotate' AND state='committed'),(SELECT count(*) FROM audit.identity_command_bindings a JOIN identity.commands c USING(command_id) WHERE c.purpose='identity.scim.connection-rotate' AND c.state='committed'),(SELECT count(*) FROM public.identity_outbox_bindings o JOIN identity.commands c USING(command_id) WHERE c.purpose='identity.scim.connection-rotate' AND c.state='committed')`).Scan(&committed, &audits, &events); err != nil || committed != 1 || audits != 1 || events != 1 {
		t.Fatal("competing rotation duplicated required atomic effects", err)
	}
}

func managedRotationOnPool(t *testing.T, f *managedConnectionAdminFixture, service *ManagedConnectionService, configure func(*database.PoolConfig) error) *ManagedConnectionService {
	t.Helper()
	pool, err := database.Connect(f.ctx, database.Config{DSN: os.Getenv("SCIM_POSTGRES_TEST_DSN"), MaxConns: 3, Configure: func(c *database.PoolConfig) error {
		c.ConnConfig.Database = f.pool.Raw().Config().ConnConfig.Database
		return configure(c)
	}})
	if err != nil {
		t.Fatal("owned rotation fault pool", err)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		if err := pool.Close(ctx); err != nil {
			t.Error("rotation fault pool cleanup", err)
		}
	})
	selected := *service
	selected.pool = pool
	return &selected
}

func TestManagedConnectionRotateRequiredEffectsRollBackTogether(t *testing.T) {
	for _, table := range []string{"scim.connections", "audit.records", "public.outbox_messages"} {
		t.Run(table, func(t *testing.T) {
			f := newManagedConnectionAdminFixture(t)
			service, _ := newManagedConnectionWriteFixture(t, f)
			created, err := service.ConnectionCreate(f.ctx, managedConnectionCreateRequest(t, f, "rotation-provider", "rotation-rollback"))
			if err != nil {
				t.Fatal(err)
			}
			request := prepareManagedRotation(t, f, service, created.Connection)
			snapshot := func() string {
				t.Helper()
				var state string
				if err := f.pool.Raw().QueryRow(f.ctx, `SELECT jsonb_build_object('bindings',(SELECT jsonb_agg(to_jsonb(c) ORDER BY connection_id) FROM scim.connections c),'committed',(SELECT count(*) FROM identity.commands WHERE state='committed'),'audits',(SELECT count(*) FROM audit.records WHERE outcome=$1),'events',(SELECT count(*) FROM public.outbox_messages))::text`, int16(audit.OutcomeSucceeded)).Scan(&state); err != nil {
					t.Fatal(err)
				}
				return state
			}
			before := snapshot()
			reached := new(atomic.Bool)
			failing := managedRotationOnPool(t, f, service, func(c *database.PoolConfig) error {
				c.ConnConfig.RuntimeParams["client_min_messages"] = "notice"
				c.ConnConfig.OnNotice = func(_ *pgconn.PgConn, n *pgconn.Notice) {
					if n.Code == "PZ001" {
						reached.Store(true)
					}
				}
				return nil
			})
			operation := "INSERT"
			if table == "scim.connections" {
				operation = "UPDATE"
			}
			if _, err := f.pool.Raw().Exec(f.ctx, `CREATE FUNCTION scim.fixture_rotate_failure() RETURNS trigger LANGUAGE plpgsql AS $f$ BEGIN RAISE NOTICE USING ERRCODE='PZ001',MESSAGE='owned rotation failure reached'; RAISE EXCEPTION 'owned rotation failure'; END $f$; CREATE TRIGGER fixture_rotate_failure BEFORE `+operation+` ON `+table+` FOR EACH ROW EXECUTE FUNCTION scim.fixture_rotate_failure()`); err != nil {
				t.Fatal(err)
			}
			out, err := managedRotationSelection(t, failing).ConnectionRotate(f.ctx, request)
			if err == nil || out.Bearer.Token() != "" || out.Connection.Version() != 0 || !reached.Load() {
				t.Fatal("required rotation effect failure not reached or revealed material", err)
			}
			if after := snapshot(); after != before {
				t.Fatal("failed required effect changed predecessor or committed audit/outbox")
			}
			source, err := service.loadManagedProvisioning(f.ctx, f.tenant, created.Bearer)
			if err != nil || source == nil {
				t.Fatal("rollback withdrew predecessor", err)
			}
		})
	}
}

type managedRotationFaultConn struct{ *nativeFaultConn }

func (c *managedRotationFaultConn) Write(wire []byte) (int, error) {
	if bytes.Contains(wire, []byte("UPDATE scim.connections SET")) {
		c.mutation.Store(true)
	}
	return c.nativeFaultConn.Write(wire)
}

func TestManagedConnectionRotateLostCommitRecoversMetadataWithoutBearer(t *testing.T) {
	f := newManagedConnectionAdminFixture(t)
	service, _ := newManagedConnectionWriteFixture(t, f)
	created, err := service.ConnectionCreate(f.ctx, managedConnectionCreateRequest(t, f, "rotation-provider", "rotation-lost"))
	if err != nil {
		t.Fatal(err)
	}
	request := prepareManagedRotation(t, f, service, created.Connection)
	fault := new(nativeCommitFault)
	uncertain := managedRotationOnPool(t, f, service, func(c *database.PoolConfig) error {
		c.ConnConfig.DialFunc = func(ctx context.Context, network, address string) (net.Conn, error) {
			connection, err := fault.dial(ctx, network, address)
			if err != nil {
				return nil, err
			}
			return &managedRotationFaultConn{connection.(*nativeFaultConn)}, nil
		}
		return nil
	})
	out, err := managedRotationSelection(t, uncertain).ConnectionRotate(f.ctx, request)
	if err == nil || out.Bearer.Token() != "" || out.Connection.Version() != 0 || !fault.hit.Load() {
		t.Fatal("actual rotation COMMIT acknowledgement was not lost or leaked bearer", err)
	}
	recovered, err := managedRotationSelection(t, service).ConnectionRotate(f.ctx, request)
	if err != nil || recovered.Connection.Version() != 2 || recovered.Bearer.Token() != "" || recovered.PreviousBearerDisposition != PreviousBearerRevoked {
		t.Fatal("lost rotation COMMIT did not recover metadata only", err)
	}
	if _, err := service.loadManagedProvisioning(f.ctx, f.tenant, created.Bearer); err == nil {
		t.Fatal("lost acknowledgement retained predecessor")
	}
	prepared, err := managedRotationSelection(t, service).PrepareConnectionRotate(f.ctx, ConnectionRotatePreparationRequest{Authentication: f.admin, ConnectionID: request.ConnectionID, ExpectedVersion: 1})
	first, _ := request.Command.Feature()
	again, _ := prepared.Feature()
	if err != nil || first.Binding != again.Binding {
		t.Fatal("lost acknowledgement allocated another original rotation", err)
	}
}

func TestManagedConnectionRotateLostReservationNeverReissuesDuringShortProvisioningLease(t *testing.T) {
	f := newManagedConnectionAdminFixture(t)
	service, _ := newManagedConnectionWriteFixture(t, f)
	created, err := service.ConnectionCreate(f.ctx, managedConnectionCreateRequest(t, f, "rotation-provider", "rotation-lost-reservation"))
	if err != nil {
		t.Fatal(err)
	}
	writer := *service.writer()
	writer.coordinator.LeaseDuration = 50 * time.Millisecond
	short := *service
	short.writer = func() *managedConnectionWriter { return &writer }
	request := prepareManagedRotation(t, f, &short, created.Connection)
	fault := &nativeCommitFault{reservation: true}
	uncertain := managedRotationOnPool(t, f, &short, func(c *database.PoolConfig) error {
		c.ConnConfig.DialFunc = fault.dial
		return nil
	})
	first, err := managedRotationSelection(t, uncertain).ConnectionRotate(f.ctx, request)
	if err == nil || first.Bearer.Token() != "" || !fault.hit.Load() {
		t.Fatal("actual original reservation acknowledgement was not lost", err)
	}
	// The provisioning template's short lease must not renew this rotation's
	// original admission or permit a retry to become a fresh bearer reveal.
	time.Sleep(75 * time.Millisecond)
	retry, _ := managedRotationSelection(t, &short).ConnectionRotate(f.ctx, request)
	if retry.Bearer.Token() != "" || retry.Connection.Version() != 0 {
		t.Fatal("lost reservation retry issued a new bearer under the still-live original authority")
	}
	record, err := service.ConnectionGet(f.ctx, ConnectionGetRequest{Authentication: f.admin, ConnectionID: request.ConnectionID})
	if err != nil || record.Version() != 1 {
		t.Fatal("unresolved original reservation changed the predecessor", err)
	}
}
