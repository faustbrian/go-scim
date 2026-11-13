package scim_test

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	scim "github.com/faustbrian/go-scim"
)

func TestRootSearchPublicMixedResourceConsumer(t *testing.T) {
	fixture, config := newCombinedFixture(t)
	writer, err := scim.NewCombinedService(config)
	if err != nil {
		t.Fatal(err)
	}
	user := combinedCall(t, writer, scim.Request{Operation: scim.UserCreate, Body: []byte(fmt.Sprintf(`{"schemas":[%q],"userName":"root-user","displayName":"Zulu"}`, userURN))})
	userID := object(t, user.Body)["id"].(string)
	group := combinedCall(t, writer, scim.Request{Operation: scim.GroupCreate, Body: []byte(fmt.Sprintf(`{"schemas":[%q],"displayName":"Alpha","members":[{"value":%q}]}`, groupURN, userID))})
	groupID := object(t, group.Body)["id"].(string)
	root := freezeRootFixture(t, fixture)
	config.RootSnapshotter = root
	service, err := scim.NewCombinedService(config)
	if err != nil {
		t.Fatal(err)
	}
	for _, query := range []struct {
		name, fields string
		ids          []string
		total, start int
	}{
		{"both types", `"sortBy":"displayName"`, []string{groupID, userID}, 2, 1},
		{"type selection", `"filter":"meta.resourceType eq \"Group\""`, []string{groupID}, 1, 1},
		{"user-only attribute", `"filter":"userName pr"`, []string{userID}, 1, 1},
		{"group-only attribute", `"filter":"members[value eq \"` + userID + `\"]"`, []string{groupID}, 1, 1},
		{"one page", `"sortBy":"displayName","startIndex":2,"count":1`, []string{userID}, 2, 2},
		{"count zero", `"count":0`, nil, 2, 1},
	} {
		t.Run(query.name, func(t *testing.T) {
			response := rootSearchCall(t, service, query.fields)
			doc := object(t, response.Body)
			resources := doc["Resources"].([]any)
			if doc["totalResults"] != float64(query.total) || doc["startIndex"] != float64(query.start) || doc["itemsPerPage"] != float64(len(query.ids)) || len(resources) != len(query.ids) {
				t.Fatal("root search lost exact mixed counts or page boundaries")
			}
			for i, want := range query.ids {
				got := resources[i].(map[string]any)
				if got["id"] != want || got["meta"].(map[string]any)["version"] == "" {
					t.Fatal("root search lost stable ordering or resource version")
				}
			}
		})
	}
	all := object(t, rootSearchCall(t, service, "").Body)["Resources"].([]any)
	ids := []string{userID, groupID}
	sort.Strings(ids)
	for i, raw := range all {
		if raw.(map[string]any)["id"] != ids[i] {
			t.Fatal("default mixed-resource order is not server id ascending")
		}
	}
	projection := object(t, rootSearchCall(t, service, `"attributes":["userName","members.value"]`).Body)["Resources"].([]any)
	for _, raw := range projection {
		resource := raw.(map[string]any)
		if _, exists := resource["displayName"]; exists {
			t.Fatal("root projection disclosed an unselected default attribute")
		}
	}
	// The unselected legacy composition must not fabricate a cross-type read.
	response, err := writer.Execute(context.Background(), combinedRequest(scim.Request{Operation: scim.Search, Body: rootSearchBody("")}))
	assertProtocolError(t, response, err, 501, "")
}

// rootFixture is an immutable process-local read owner, not a native adapter.
// It publishes ONE complete frame; it never stitches calls to the typed stores.
type rootFixture struct{ snapshot scim.RootSnapshot }

func (f *rootFixture) SnapshotRoot(ctx context.Context, connection scim.Connection, budget scim.SnapshotBudget) (scim.RootSnapshot, error) {
	if err := boundedFixtureContext(ctx); err != nil {
		return scim.RootSnapshot{}, err
	}
	if connection.Scope != f.snapshot.Scope || budget.Resources < len(f.snapshot.Resources) {
		return scim.RootSnapshot{Scope: connection.Scope}, nil
	}
	remaining := budget.Bytes
	for _, resource := range f.snapshot.Resources {
		encoded, err := json.Marshal(resource.Resource)
		if err != nil || len(encoded) > remaining {
			return scim.RootSnapshot{Scope: connection.Scope}, nil
		}
		remaining -= len(encoded)
	}
	out := f.snapshot
	out.Resources = make([]scim.RootResource, len(f.snapshot.Resources))
	for i, resource := range f.snapshot.Resources {
		out.Resources[i] = resource
		out.Resources[i].Resource = cloneFixtureResource(resource.Resource)
	}
	return out, nil
}

func freezeRootFixture(t *testing.T, fixture *combinedFixture) *rootFixture {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	connection, err := (protocolAuthenticator{}).Authenticate(ctx, combinedRequest(scim.Request{}).Credential)
	if err != nil {
		t.Fatal(err)
	}
	root := &rootFixture{snapshot: scim.RootSnapshot{Scope: connection.Scope, Complete: true}}
	// Fixture writes are finished. Hold both fixture owners together to capture
	// one immutable frame rather than claiming two sequential snapshot calls agree.
	fixture.users.mu.Lock()
	fixture.groups.mu.Lock()
	defer fixture.users.mu.Unlock()
	defer fixture.groups.mu.Unlock()
	for key, resource := range fixture.users.resources {
		if key.scope == connection.Scope {
			root.snapshot.Resources = append(root.snapshot.Resources, scim.RootResource{Type: scim.RootUser, Resource: cloneFixtureResource(resource)})
		}
	}
	for key, resource := range fixture.groups.resources {
		if key.scope == connection.Scope {
			root.snapshot.Resources = append(root.snapshot.Resources, scim.RootResource{Type: scim.RootGroup, Resource: cloneFixtureResource(resource)})
		}
	}
	return root
}

func rootSearchBody(fields string) []byte {
	prefix := `{"schemas":["urn:ietf:params:scim:api:messages:2.0:SearchRequest"]`
	if fields != "" {
		prefix += "," + fields
	}
	return []byte(prefix + "}")
}

func rootSearchCall(t *testing.T, service *scim.CombinedService, fields string) scim.Response {
	t.Helper()
	body := rootSearchBody(fields)
	if !json.Valid(body) {
		t.Fatal("invalid search fixture body")
	}
	return combinedCall(t, service, scim.Request{Operation: scim.Search, Body: body})
}

func TestRootSearchDeniesInvalidSnapshotEvenForCountZero(t *testing.T) {
	for _, test := range []struct {
		name   string
		change func(*scim.RootSnapshot, *scim.CombinedConfig)
		status int
		kind   string
	}{
		{"incomplete", func(s *scim.RootSnapshot, _ *scim.CombinedConfig) { s.Complete = false }, 400, "tooMany"},
		{"foreign scope", func(s *scim.RootSnapshot, _ *scim.CombinedConfig) { s.Scope.ConnectionID = "other-connection" }, 503, ""},
		{"unknown kind", func(s *scim.RootSnapshot, _ *scim.CombinedConfig) { s.Resources[0].Type = "Other" }, 503, ""},
		{"zero kind", func(s *scim.RootSnapshot, _ *scim.CombinedConfig) { s.Resources[0].Type = "" }, 503, ""},
		{"type schema mismatch", func(s *scim.RootSnapshot, _ *scim.CombinedConfig) { s.Resources[0].Type = scim.RootGroup }, 503, ""},
		{"both core schemas", func(s *scim.RootSnapshot, _ *scim.CombinedConfig) {
			s.Resources[0].Resource.Schemas = []string{userURN, groupURN}
		}, 503, ""},
		{"undeclared extension", func(s *scim.RootSnapshot, _ *scim.CombinedConfig) {
			s.Resources[0].Resource.Schemas = append(s.Resources[0].Resource.Schemas, "urn:example:undeclared")
		}, 503, ""},
		{"duplicate id across types", func(s *scim.RootSnapshot, _ *scim.CombinedConfig) {
			s.Resources[1].Resource.ID = s.Resources[0].Resource.ID
		}, 503, ""},
		{"password projection", func(s *scim.RootSnapshot, _ *scim.CombinedConfig) {
			s.Resources[0].Resource.Attributes["password"] = "never-return-this"
		}, 503, ""},
		{"aggregate resource budget", func(_ *scim.RootSnapshot, c *scim.CombinedConfig) { c.Limits.SnapshotResources = 1 }, 400, "tooMany"},
		{"aggregate byte budget", func(_ *scim.RootSnapshot, c *scim.CombinedConfig) { c.Limits.SnapshotBytes = 1 }, 400, "tooMany"},
	} {
		t.Run(test.name, func(t *testing.T) {
			root, config := seededRootConfig(t)
			test.change(&root.snapshot, &config)
			// Deliberately violate a trusted read-owner contract to prove the
			// library rejects bad whole-snapshot inputs before returning counts.
			config.RootSnapshotter = rootReadFunc(func(context.Context, scim.Connection, scim.SnapshotBudget) (scim.RootSnapshot, error) {
				return root.snapshot, nil
			})
			service, err := scim.NewCombinedService(config)
			if err != nil {
				t.Fatal(err)
			}
			out, err := service.Execute(context.Background(), combinedRequest(scim.Request{Operation: scim.Search, Body: rootSearchBody(`"count":0`)}))
			assertProtocolError(t, out, err, test.status, test.kind)
		})
	}
}

func TestRootSearchOriginalAuthorityCancellationAndWithdrawal(t *testing.T) {
	for _, state := range []string{"expired original authority", "cancelled", "withdrawn policy", "read error", "read panic"} {
		t.Run(state, func(t *testing.T) {
			root, config := seededRootConfig(t)
			policy := &protocolAuthorizer{}
			config.Authorizer = policy
			now := fixtureNow
			config.Now = func() time.Time { return now }
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			config.RootSnapshotter = rootReadFunc(func(readCtx context.Context, connection scim.Connection, budget scim.SnapshotBudget) (scim.RootSnapshot, error) {
				if connection.AuthorityReadBeganAt != fixtureNow || connection.AuthorityValidUntil != fixtureNow.Add(20*time.Second) {
					t.Fatal("root read renewed original authority")
				}
				snapshot, err := root.SnapshotRoot(readCtx, connection, budget)
				switch state {
				case "expired original authority":
					now = fixtureNow.Add(21 * time.Second)
				case "cancelled":
					cancel()
				case "withdrawn policy":
					policy.err = errors.New("private withdrawn policy diagnostic")
				case "read error":
					return scim.RootSnapshot{}, errors.New("private root store diagnostic")
				case "read panic":
					panic("private root store diagnostic")
				}
				return snapshot, err
			})
			service, err := scim.NewCombinedService(config)
			if err != nil {
				t.Fatal(err)
			}
			out, err := service.Execute(ctx, combinedRequest(scim.Request{Operation: scim.Search, Body: rootSearchBody("")}))
			status := 503
			if state == "withdrawn policy" {
				status = 403
			}
			assertProtocolError(t, out, err, status, "")
			if strings.Contains(fmt.Sprint(err), "private") {
				t.Fatal("root search exposed a dependency diagnostic")
			}
		})
	}
}

func TestRootSearchTypedPathsSortProjectionAndGlobalResponseBound(t *testing.T) {
	root, config := seededRootConfig(t)
	service, err := scim.NewCombinedService(config)
	if err != nil {
		t.Fatal(err)
	}
	for _, query := range []struct {
		fields string
		ids    []string
	}{
		{`"filter":"` + userURN + `:displayName pr"`, []string{"user-one"}},
		{`"filter":"` + groupURN + `:displayName pr"`, []string{"group-one"}},
		{`"filter":"userName eq \"ALICE\" or members[value eq \"user-one\"]"`, []string{"group-one", "user-one"}},
		{`"sortBy":"userName"`, []string{"user-one", "group-one"}},
		{`"sortBy":"userName","sortOrder":"descending"`, []string{"group-one", "user-one"}},
		{`"startIndex":-5,"count":-1`, nil},
		{`"startIndex":9223372036854775807,"count":1`, nil},
	} {
		out := object(t, rootSearchCall(t, service, query.fields).Body)
		resources := out["Resources"].([]any)
		if len(resources) != len(query.ids) {
			t.Fatal("typed path, sort or pagination returned the wrong resource set")
		}
		for i, id := range query.ids {
			if resources[i].(map[string]any)["id"] != id {
				t.Fatal("typed root path or unassigned sort order crossed resource owners")
			}
		}
	}
	for _, fields := range []string{
		`"attributes":["` + userURN + `:displayName"]`,
		`"excludedAttributes":["` + groupURN + `:displayName"]`,
	} {
		resources := object(t, rootSearchCall(t, service, fields).Body)["Resources"].([]any)
		for _, raw := range resources {
			resource := raw.(map[string]any)
			_, displayed := resource["displayName"]
			if displayed != (resource["id"] == "user-one") {
				t.Fatal("core-qualified root projection crossed resource types")
			}
		}
	}
	rootSearchCall(t, service, `"attributes":["`+userURN+`:displayName","`+groupURN+`:displayName"]`)
	for _, bad := range []struct{ fields, kind string }{
		{`"filter":"notDeclared pr"`, "invalidFilter"},
		{`"filter":"password pr"`, "invalidFilter"},
		{`"sortBy":"password"`, "invalidValue"},
		{`"attributes":["password"]`, "invalidValue"},
		{`"filter":"userName pr","Filter":"userName pr"`, "invalidSyntax"},
	} {
		out, err := service.Execute(context.Background(), combinedRequest(scim.Request{Operation: scim.Search, Body: rootSearchBody(bad.fields)}))
		assertProtocolError(t, out, err, 400, bad.kind)
	}
	root.snapshot.Resources[0].Resource.Attributes["displayName"] = strings.Repeat("u", 10000)
	root.snapshot.Resources[1].Resource.Attributes["displayName"] = strings.Repeat("g", 10000)
	config.Limits.ResponseBytes = 16384
	service, err = scim.NewCombinedService(config)
	if err != nil {
		t.Fatal(err)
	}
	out, err := service.Execute(context.Background(), combinedRequest(scim.Request{Operation: scim.Search, Body: rootSearchBody("")}))
	assertProtocolError(t, out, err, 400, "tooMany")
}

func TestRootSearchConcurrentReadsAndSingleResourceCompatibility(t *testing.T) {
	_, config := seededRootConfig(t)
	service, err := scim.NewCombinedService(config)
	if err != nil {
		t.Fatal(err)
	}
	var readers sync.WaitGroup
	for range 8 {
		readers.Go(func() { rootSearchCall(t, service, `"filter":"userName pr or members pr"`) })
	}
	readers.Wait()
	newProtocolFixture(t).call(t, scim.Search, "", "", string(rootSearchBody("")))
	var nilReader *rootFixture
	config.RootSnapshotter = nilReader
	if service, err := scim.NewCombinedService(config); service != nil || err == nil {
		t.Fatal("typed-nil root snapshot owner was accepted")
	}
}

func TestRootSearchUsesExactPerTypeExtensionSemantics(t *testing.T) {
	root, config := seededRootConfig(t)
	userExtension := combinedExtension(combinedUserExtension, "UserExtra")
	userExtension.Attributes[0].CaseExact = true
	groupExtension := combinedExtension(combinedGroupExtension, "GroupExtra")
	config.UserExtensions = []scim.Schema{userExtension}
	config.GroupExtensions = []scim.Schema{groupExtension}
	root.snapshot.Resources[0].Resource.Schemas = append(root.snapshot.Resources[0].Resource.Schemas, userExtension.ID)
	root.snapshot.Resources[0].Resource.Attributes[userExtension.ID] = map[string]any{"note": "UPPER"}
	root.snapshot.Resources[1].Resource.Schemas = append(root.snapshot.Resources[1].Resource.Schemas, groupExtension.ID)
	root.snapshot.Resources[1].Resource.Attributes[groupExtension.ID] = map[string]any{"note": "UPPER"}
	service, err := scim.NewCombinedService(config)
	if err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		filter string
		ids    []string
	}{
		{userExtension.ID + `:note eq "upper"`, nil},
		{userExtension.ID + `:note eq "UPPER"`, []string{"user-one"}},
		{groupExtension.ID + `:note eq "upper"`, []string{"group-one"}},
		{userExtension.ID + `:note pr or ` + groupExtension.ID + `:note pr`, []string{"group-one", "user-one"}},
	} {
		filter, _ := json.Marshal(test.filter)
		response := object(t, rootSearchCall(t, service, `"filter":`+string(filter)).Body)
		resources := response["Resources"].([]any)
		if len(resources) != len(test.ids) {
			t.Fatal("root extension lookup lost type or caseExact semantics")
		}
		for i, id := range test.ids {
			if resources[i].(map[string]any)["id"] != id {
				t.Fatal("root extension comparison crossed schema ownership")
			}
		}
	}
	projected := object(t, rootSearchCall(t, service, `"attributes":["`+userExtension.ID+`:note"]`).Body)["Resources"].([]any)
	for _, raw := range projected {
		resource := raw.(map[string]any)
		_, hasUser := resource[userExtension.ID]
		_, hasGroup := resource[groupExtension.ID]
		if hasUser != (resource["id"] == "user-one") || hasGroup {
			t.Fatal("root extension projection disclosed another owner")
		}
	}
}

func TestRootSearchCorePrefixedSharedExtensionKeepsBothOwners(t *testing.T) {
	root, config := seededRootConfig(t)
	extension := combinedExtension(userURN+":Extra", "SharedExtra")
	config.UserExtensions = []scim.Schema{extension}
	config.GroupExtensions = []scim.Schema{extension}
	for i, note := range []string{"Zulu", "Alpha"} {
		resource := &root.snapshot.Resources[i].Resource
		resource.Schemas = append(resource.Schemas, extension.ID)
		resource.Attributes[extension.ID] = map[string]any{"note": note}
	}
	service, err := scim.NewCombinedService(config)
	if err != nil {
		t.Fatal(err)
	}
	t.Run("filter", func(t *testing.T) {
		resources := object(t, rootSearchCall(t, service, `"filter":"`+extension.ID+`:note pr"`).Body)["Resources"].([]any)
		if len(resources) != 2 {
			t.Fatal("shared extension filter silently excluded a matching Group")
		}
	})
	t.Run("sort", func(t *testing.T) {
		resources := object(t, rootSearchCall(t, service, `"sortBy":"`+extension.ID+`:note"`).Body)["Resources"].([]any)
		if resources[0].(map[string]any)["id"] != "group-one" {
			t.Fatal("shared extension sorting treated a Group value as unassigned")
		}
	})
	t.Run("projection", func(t *testing.T) {
		resources := object(t, rootSearchCall(t, service, `"attributes":["`+extension.ID+`:note"]`).Body)["Resources"].([]any)
		for _, raw := range resources {
			if _, present := raw.(map[string]any)[extension.ID]; !present {
				t.Fatal("shared extension projection silently discarded an owner's value")
			}
		}
	})
}

type rootReadFunc func(context.Context, scim.Connection, scim.SnapshotBudget) (scim.RootSnapshot, error)

func (f rootReadFunc) SnapshotRoot(ctx context.Context, connection scim.Connection, budget scim.SnapshotBudget) (scim.RootSnapshot, error) {
	return f(ctx, connection, budget)
}

func seededRootConfig(t *testing.T) (*rootFixture, scim.CombinedConfig) {
	t.Helper()
	fixture, config := newCombinedFixture(t)
	root := freezeRootFixture(t, fixture)
	root.snapshot.Resources = []scim.RootResource{
		{Type: scim.RootUser, Resource: scim.Resource{ID: "user-one", Version: `"user-v1"`, CreatedAt: fixtureNow, LastModified: fixtureNow, Schemas: []string{userURN}, Attributes: map[string]any{"userName": "alice", "displayName": "Same"}}},
		{Type: scim.RootGroup, Resource: scim.Resource{ID: "group-one", Version: `"group-v1"`, CreatedAt: fixtureNow, LastModified: fixtureNow, Schemas: []string{groupURN}, Attributes: map[string]any{"displayName": "same", "members": []any{map[string]any{"value": "user-one", "type": "User"}}}}},
	}
	config.RootSnapshotter = root
	return root, config
}

func FuzzRootSearchBoundary(f *testing.F) {
	for _, seed := range [][3]string{
		{"", "User", userURN},
		{"userName pr or members pr", "User", userURN},
		{"meta.resourceType eq \"Group\"", "User", userURN},
		{userURN + ":displayName pr", "User", userURN},
		{"password pr", "User", userURN},
		{"members[value eq \"user-one\"]", "User", userURN},
		{"", "Group", userURN},
		{"", "Other", userURN},
		{"", "User", groupURN},
	} {
		f.Add(seed[0], seed[1], seed[2])
	}
	f.Fuzz(func(t *testing.T, filter, kind, schema string) {
		if len(filter) > 9000 || len(kind) > 128 || len(schema) > 1024 {
			return
		}
		root, config := seededRootConfig(t)
		root.snapshot.Resources[0].Type = scim.RootResourceType(kind)
		root.snapshot.Resources[0].Resource.Schemas = []string{schema}
		service, err := scim.NewCombinedService(config)
		if err != nil {
			t.Fatal(err)
		}
		body, _ := json.Marshal(map[string]any{"schemas": []string{"urn:ietf:params:scim:api:messages:2.0:SearchRequest"}, "filter": filter})
		out, err := service.Execute(context.Background(), combinedRequest(scim.Request{Operation: scim.Search, Body: body}))
		if err != nil {
			if out.Status != 0 || len(out.Body) != 0 {
				t.Fatal("failed root search exposed partial output")
			}
			if _, ok := err.(*scim.Error); !ok {
				t.Fatal("root boundary returned an unstable error")
			}
			return
		}
		if kind != "User" || schema != userURN {
			t.Fatal("root boundary admitted type/schema confusion")
		}
		doc := object(t, out.Body)
		if total := doc["totalResults"].(float64); total < 0 || total > 2 {
			t.Fatal("root query escaped its complete bounded snapshot")
		}
	})
}
