//go:build integration

package scimpostgres

import (
	"context"
	"encoding/json"
	"os"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	authentication "github.com/faustbrian/go-authentication/v2"
	database "github.com/faustbrian/go-postgres"
	scim "github.com/faustbrian/go-scim"
	"github.com/jackc/pgx/v5"
)

type nativeList struct {
	Schemas      []string          `json:"schemas"`
	Resources    []json.RawMessage `json:"Resources"`
	TotalResults int               `json:"totalResults"`
	StartIndex   int               `json:"startIndex"`
	ItemsPerPage int               `json:"itemsPerPage"`
}

func readNativeList(t *testing.T, response scim.Response) nativeList {
	t.Helper()
	var list nativeList
	if response.Status != 200 || json.Unmarshal(response.Body, &list) != nil || !slices.Equal(list.Schemas, []string{"urn:ietf:params:scim:api:messages:2.0:ListResponse"}) || list.ItemsPerPage != len(list.Resources) {
		t.Fatal("invalid native ListResponse", response.Status)
	}
	return list
}

func nativeListIDs(t *testing.T, list nativeList) []string {
	t.Helper()
	ids := make([]string, 0, len(list.Resources))
	for _, wire := range list.Resources {
		var resource struct {
			ID   string `json:"id"`
			Meta struct {
				Version string `json:"version"`
			} `json:"meta"`
		}
		if json.Unmarshal(wire, &resource) != nil || resource.ID == "" || resource.Meta.Version == "" {
			t.Fatal("list omitted resource identity or concurrency version")
		}
		ids = append(ids, resource.ID)
	}
	return ids
}

func createNativeNamed(t *testing.T, f *nativeFixture, name, display string) string {
	t.Helper()
	body, err := json.Marshal(map[string]any{"schemas": []string{"urn:ietf:params:scim:schemas:core:2.0:User"}, "userName": name, "displayName": display, "externalId": "shared-correlation"})
	if err != nil {
		t.Fatal(err)
	}
	response, err := f.service.Execute(f.ctx, scim.Request{Operation: scim.UserCreate, Credential: f.bearer, ContentType: "application/scim+json", Body: body})
	var resource struct {
		ID string `json:"id"`
	}
	if err != nil || response.Status != 201 || json.Unmarshal(response.Body, &resource) != nil || resource.ID == "" {
		t.Fatal("create native query fixture", response.Status, err)
	}
	return resource.ID
}

func TestNativeUsersDiscoveryListSearchAndPagination(t *testing.T) {
	f := newNativeFixture(t)
	ids := []string{createNativeNamed(t, f, "Alpha", "First"), createNativeNamed(t, f, "Bravo", "Same"), createNativeNamed(t, f, "Charlie", "Same")}
	slices.Sort(ids)
	for _, target := range []struct {
		operation scim.Operation
		id        string
	}{
		{scim.ServiceProviderConfig, ""},
		{scim.SchemasList, ""},
		{scim.SchemaGet, "urn:ietf:params:scim:schemas:core:2.0:User"},
		{scim.ResourceTypesList, ""},
		{scim.ResourceTypeGet, "User"},
	} {
		response, err := f.service.Execute(f.ctx, scim.Request{Operation: target.operation, ResourceID: target.id, Credential: f.bearer})
		if err != nil || response.Status != 200 || len(response.Body) == 0 {
			t.Fatal("authorized native discovery unavailable", target.operation, err)
		}
		if target.operation == scim.ResourceTypesList {
			list := readNativeList(t, response)
			if list.TotalResults != 1 || list.ItemsPerPage != 1 {
				t.Fatal("native Users discovery advertised another resource owner")
			}
		}
	}
	query := func(q scim.Query) nativeList {
		t.Helper()
		response, err := f.service.Execute(f.ctx, scim.Request{Operation: scim.UserList, Credential: f.bearer, Query: q})
		if err != nil {
			t.Fatal("native list", err)
		}
		return readNativeList(t, response)
	}
	list := query(scim.Query{})
	if list.TotalResults != 3 || list.StartIndex != 1 || !slices.Equal(nativeListIDs(t, list), ids) {
		t.Fatal("default native pagination did not use exact total and stable ID order")
	}
	count := 1
	page := query(scim.Query{StartIndex: 2, Count: &count, Attributes: "id,userName"})
	if page.TotalResults != 3 || page.StartIndex != 2 || !slices.Equal(nativeListIDs(t, page), ids[1:2]) {
		t.Fatal("native offset/projection changed transaction-consistent results")
	}
	for _, count := range []int{0, -1} {
		page := query(scim.Query{StartIndex: -10, Count: &count})
		if page.TotalResults != 3 || page.StartIndex != 1 || page.ItemsPerPage != 0 {
			t.Fatal("native count zero/negative lost exact total")
		}
	}
	filtered := query(scim.Query{Filter: `userName eq "ALPHA"`})
	if filtered.TotalResults != 1 {
		t.Fatal("native fallback ignored SCIM caseExact comparison")
	}
	external := query(scim.Query{Filter: `externalId eq "shared-correlation"`, SortBy: "displayName", SortOrder: "descending"})
	if external.TotalResults != 3 {
		t.Fatal("nonunique externalId was not a scoped correlation filter")
	}
	for _, operation := range []scim.Operation{scim.UserSearch, scim.Search} {
		response, err := f.service.Execute(f.ctx, scim.Request{Operation: operation, Credential: f.bearer, ContentType: "application/scim+json", Body: []byte(`{"schemas":["urn:ietf:params:scim:api:messages:2.0:SearchRequest"],"filter":"userName sw \"br\"","count":1}`)})
		if err != nil {
			t.Fatal("native POST search", operation, err)
		}
		searched := readNativeList(t, response)
		if searched.TotalResults != 1 || searched.ItemsPerPage != 1 || searched.StartIndex != 1 {
			t.Fatal("native POST search did not share list semantics")
		}
	}
}

func TestNativeUsersSnapshotBudgetDeniesWholeResultIncludingCountZero(t *testing.T) {
	for _, boundary := range []string{"resources", "bytes"} {
		t.Run(boundary, func(t *testing.T) {
			f := newNativeFixture(t)
			c := f.config
			c.Scope.ConnectionID = "bounded-" + boundary
			if boundary == "resources" {
				c.Limits.SnapshotResources = 1
			} else {
				c.Limits.SnapshotBytes = 128
			}
			service, err := NewService(f.pool, c, f.keys)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := service.InitializeConfiguredConnection(f.ctx); err != nil {
				t.Fatal(err)
			}
			f.service = service
			createNativeNamed(t, f, "One", "First")
			createNativeNamed(t, f, "Two", "Second")
			for _, count := range []int{0, 1} {
				response, err := service.Execute(f.ctx, scim.Request{Operation: scim.UserList, Credential: f.bearer, Query: scim.Query{Count: &count}})
				if err == nil || protocolStatus(err) != 400 || len(response.Body) != 0 {
					t.Fatal("snapshot exhaustion exposed partial values or a guessed count", count, err)
				}
			}
		})
	}
}

func TestNativeUsersListUsesExactConnectionAndCurrentAuthority(t *testing.T) {
	f := newNativeFixture(t)
	createNativeNamed(t, f, "PrivateA", "Connection A")
	c := f.config
	c.Scope.ConnectionID = "connection-b"
	bearer := authentication.NewBearerCredential("native-list-other-credential-with-sufficient-length")
	credential, err := NewConfiguredCredential("credential-b", bearer, [32]byte{87})
	if err != nil {
		t.Fatal(err)
	}
	c.Credential = credential
	other, err := NewService(f.pool, c, f.keys)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := other.InitializeConfiguredConnection(f.ctx); err != nil {
		t.Fatal(err)
	}
	request := scim.Request{Operation: scim.UserList, Credential: bearer}
	response, err := other.Execute(f.ctx, request)
	if err != nil || readNativeList(t, response).TotalResults != 0 {
		t.Fatal("native list disclosed another connection", err)
	}
	f.deny.Store(true)
	for _, operation := range []scim.Operation{scim.UserList, scim.ServiceProviderConfig, scim.SchemasList} {
		request.Operation = operation
		if response, err := other.Execute(f.ctx, request); err == nil || len(response.Body) != 0 {
			t.Fatal("current native policy withdrawal disclosed query/discovery", operation)
		}
	}
}

type snapshotQueryKey struct{}

type snapshotReadBarrier struct {
	once             sync.Once
	entered, release chan struct{}
}

func (*snapshotReadBarrier) TraceQueryStart(ctx context.Context, _ *pgx.Conn, data pgx.TraceQueryStartData) context.Context {
	return context.WithValue(ctx, snapshotQueryKey{}, data.SQL)
}

func (b *snapshotReadBarrier) TraceQueryEnd(ctx context.Context, _ *pgx.Conn, _ pgx.TraceQueryEndData) {
	sql, _ := ctx.Value(snapshotQueryKey{}).(string)
	if !strings.Contains(sql, "AS bounded_snapshot") {
		return
	}
	b.once.Do(func() {
		close(b.entered)
		select {
		case <-b.release:
		case <-ctx.Done():
		}
	})
}

func TestNativeUsersSnapshotDoesNotMixConcurrentCommittedRows(t *testing.T) {
	f := newNativeFixture(t)
	originalID := createNativeNamed(t, f, "BeforeSnapshot", "Original row")
	barrier := &snapshotReadBarrier{entered: make(chan struct{}), release: make(chan struct{})}
	var release sync.Once
	unblock := func() { release.Do(func() { close(barrier.release) }) }
	defer unblock()
	pool, err := database.Connect(f.ctx, database.Config{DSN: os.Getenv("SCIM_POSTGRES_TEST_DSN"), MaxConns: 3, Configure: func(c *database.PoolConfig) error {
		c.ConnConfig.Database = f.pool.Raw().Config().ConnConfig.Database
		c.ConnConfig.Tracer = barrier
		return nil
	}})
	if err != nil {
		t.Fatal("snapshot observation pool", err)
	}
	defer func() {
		cleanup, stop := context.WithTimeout(context.Background(), 3*time.Second)
		defer stop()
		if err := pool.Close(cleanup); err != nil {
			t.Error("snapshot observation pool cleanup", err)
		}
	}()
	service, err := NewService(pool, f.config, f.keys)
	if err != nil {
		t.Fatal(err)
	}
	result := make(chan executionResult, 1)
	finished := make(chan struct{})
	go func() {
		defer close(finished)
		response, err := service.Execute(f.ctx, scim.Request{Operation: scim.UserList, Credential: f.bearer})
		result <- executionResult{response, err}
	}()
	defer func() {
		unblock()
		select {
		case <-finished:
		case <-f.ctx.Done():
			t.Error("snapshot read goroutine did not terminate")
		}
	}()
	select {
	case <-barrier.entered:
	case got := <-result:
		t.Fatal("actual snapshot admission was not observed", got.err)
	case <-f.ctx.Done():
		t.Fatal("snapshot admission barrier did not arrive")
	}
	createNativeNamed(t, f, "AfterSnapshot", "Committed during read")
	unblock()
	var got executionResult
	select {
	case got = <-result:
	case <-f.ctx.Done():
		t.Fatal("snapshot read did not complete")
	}
	if got.err != nil {
		t.Fatal("concurrent commit invalidated a complete earlier snapshot", got.err)
	}
	list := readNativeList(t, got.response)
	if list.TotalResults != 1 || !slices.Equal(nativeListIDs(t, list), []string{originalID}) {
		t.Fatal("snapshot mixed a later commit into its original count/values")
	}
	response, err := f.service.Execute(f.ctx, scim.Request{Operation: scim.UserList, Credential: f.bearer})
	if err != nil || readNativeList(t, response).TotalResults != 2 {
		t.Fatal("new snapshot did not observe subsequent committed user", err)
	}
}
