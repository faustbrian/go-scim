package scim_test

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"

	authentication "github.com/faustbrian/go-authentication/v2"
	scim "github.com/faustbrian/go-scim"
)

const combinedUserExtension = "urn:example:scim:users"
const combinedGroupExtension = "urn:example:scim:groups"
const combinedSharedExtension = "urn:example:scim:shared"

func TestCombinedPublicDiscoveryAndResourceConsumer(t *testing.T) {
	f, config := newCombinedFixture(t)
	userExtension := combinedExtension(combinedUserExtension, "UserExtra")
	groupExtension := combinedExtension(combinedGroupExtension, "GroupExtra")
	shared := combinedExtension(combinedSharedExtension, "Shared")
	config.UserExtensions = []scim.Schema{userExtension, shared}
	config.GroupExtensions = []scim.Schema{groupExtension, shared}
	service, err := scim.NewCombinedService(config)
	if err != nil {
		t.Fatal(err)
	}
	call := func(r scim.Request) scim.Response { return combinedCall(t, service, r) }
	resourceTypes := object(t, call(scim.Request{Operation: scim.ResourceTypesList}).Body)
	if resourceTypes["totalResults"] != float64(2) || resourceTypes["itemsPerPage"] != float64(2) || resourceTypes["startIndex"] != float64(1) {
		t.Fatal("combined resource type collection is not exact")
	}
	types := resourceTypes["Resources"].([]any)
	seenTypes := map[string]bool{}
	for _, raw := range types {
		typ := raw.(map[string]any)
		name := typ["name"].(string)
		if seenTypes[name] {
			t.Fatal("resource type collection contains a duplicate owner")
		}
		seenTypes[name] = true
		if typ["endpoint"] != "/"+name+"s" || typ["schema"] != map[string]string{"User": userURN, "Group": groupURN}[name] {
			t.Fatal("discovery does not describe an actual resource owner")
		}
		for _, raw := range typ["schemaExtensions"].([]any) {
			if raw.(map[string]any)["required"] != false {
				t.Fatal("extension discovery omitted explicit required=false")
			}
		}
		one := object(t, call(scim.Request{Operation: scim.ResourceTypeGet, ResourceID: name}).Body)
		if one["schema"] != typ["schema"] {
			t.Fatal("resource type lookup differs from discovery")
		}
	}
	if !seenTypes["User"] || !seenTypes["Group"] {
		t.Fatal("resource type collection omitted a selected owner")
	}
	schemasBefore := call(scim.Request{Operation: scim.SchemasList})
	schemas := object(t, schemasBefore.Body)
	if schemas["totalResults"] != float64(5) || schemas["itemsPerPage"] != float64(5) {
		t.Fatal("shared schema was duplicated or a selected schema is missing")
	}
	seenSchemas := map[string]bool{}
	for _, raw := range schemas["Resources"].([]any) {
		id := raw.(map[string]any)["id"].(string)
		if seenSchemas[id] {
			t.Fatal("schema collection duplicated an identity")
		}
		seenSchemas[id] = true
	}
	for _, id := range []string{userURN, groupURN, combinedUserExtension, combinedGroupExtension, combinedSharedExtension} {
		if !seenSchemas[id] {
			t.Fatal("schema collection omitted a selected schema")
		}
		schema := object(t, call(scim.Request{Operation: scim.SchemaGet, ResourceID: id}).Body)
		if schema["id"] != id || schema["schemas"].([]any)[0] != "urn:ietf:params:scim:schemas:core:2.0:Schema" {
			t.Fatal("schema lookup lost exact RFC identity")
		}
	}
	config.UserExtensions[0].Attributes[0].Name = "changed"
	config.GroupExtensions[0].Attributes[0].Name = "changed"
	if after := call(scim.Request{Operation: scim.SchemasList}); string(after.Body) != string(schemasBefore.Body) {
		t.Fatal("caller schema mutation changed frozen discovery")
	}
	user := call(scim.Request{Operation: scim.UserCreate, Body: []byte(fmt.Sprintf(`{"schemas":[%q,%q],"userName":"combined-user",%q:{"note":"user-note"}}`, userURN, combinedUserExtension, combinedUserExtension))})
	userID := object(t, user.Body)["id"].(string)
	if user.Status != 201 || user.ETag == "" {
		t.Fatal("User create bypassed its established owner")
	}
	group := call(scim.Request{Operation: scim.GroupCreate, Body: []byte(fmt.Sprintf(`{"schemas":[%q,%q],"displayName":"combined-group","members":[{"value":%q}],%q:{"note":"group-note"}}`, groupURN, combinedGroupExtension, userID, combinedGroupExtension))})
	groupID := object(t, group.Body)["id"].(string)
	if group.Status != 201 || group.ETag == "" || object(t, group.Body)["members"].([]any)[0].(map[string]any)["value"] != userID {
		t.Fatal("Group create lost the actual User reference")
	}
	if read := call(scim.Request{Operation: scim.UserGet, ResourceID: userID}); string(read.Body) != string(user.Body) || read.ETag != user.ETag {
		t.Fatal("combined User read differs from its stored projection")
	}
	if read := call(scim.Request{Operation: scim.GroupGet, ResourceID: groupID}); string(read.Body) != string(group.Body) || read.ETag != group.ETag {
		t.Fatal("combined Group read differs from its stored projection")
	}
	for _, operation := range []scim.Operation{scim.UserList, scim.GroupList} {
		list := object(t, call(scim.Request{Operation: operation}).Body)
		if list["totalResults"] != float64(1) {
			t.Fatal("resource dispatcher merged typed storage partitions")
		}
	}
	discovery := object(t, call(scim.Request{Operation: scim.ServiceProviderConfig}).Body)
	if discovery["filter"].(map[string]any)["maxResults"] != float64(config.Limits.PageMax) || discovery["bulk"].(map[string]any)["supported"] != false || discovery["changePassword"].(map[string]any)["supported"] != false {
		t.Fatal("advertised capabilities differ from selected runtime")
	}
	for _, operation := range []scim.Operation{scim.Search, scim.Bulk, scim.Operation("identity.scim.connection-create")} {
		r, err := service.Execute(context.Background(), combinedRequest(scim.Request{Operation: operation}))
		assertProtocolError(t, r, err, 501, "")
	}
	if len(f.users.resources) != 1 || len(f.groups.resources) != 1 {
		t.Fatal("consumer did not reach both original typed stores")
	}
}

func TestCombinedRejectsSchemaConflictsAndUnencodableCollections(t *testing.T) {
	_, base := newCombinedFixture(t)
	for _, conflict := range []string{"descriptor", "case alias", "core collision"} {
		t.Run(conflict, func(t *testing.T) {
			c := base
			shared := combinedExtension(combinedSharedExtension, "Shared")
			c.UserExtensions = []scim.Schema{shared}
			other := combinedExtension(combinedSharedExtension, "Shared")
			switch conflict {
			case "descriptor":
				other.Attributes[0].Type = "boolean"
			case "case alias":
				other.ID = "urn:example:scim:SHARED"
			case "core collision":
				c.UserExtensions = []scim.Schema{combinedExtension(groupURN, "GroupCollision")}
				other = combinedExtension(combinedGroupExtension, "GroupExtra")
			}
			c.GroupExtensions = []scim.Schema{other}
			service, err := scim.NewCombinedService(c)
			if service != nil {
				t.Fatal("conflicting discovery returned a service")
			}
			assertProtocolError(t, scim.Response{}, err, 400, "invalidValue")
		})
	}
	userBytes := len(newProtocolFixture(t).call(t, scim.SchemasList, "", "", "").Body)
	groupBytes := len(newGroupFixture(t, nil).call(t, scim.SchemasList, "", "", "").Body)
	base.Limits.ResponseBytes = max(userBytes, groupBytes)
	service, err := scim.NewCombinedService(base)
	if service != nil {
		t.Fatal("service accepted limits unable to encode combined discovery")
	}
	assertProtocolError(t, scim.Response{}, err, 400, "invalidValue")
}

func TestCombinedAuthorityAndCompatibility(t *testing.T) {
	_, config := newCombinedFixture(t)
	policy := &protocolAuthorizer{}
	config.Authorizer = policy
	service, err := scim.NewCombinedService(config)
	if err != nil {
		t.Fatal(err)
	}
	policy.err = errors.New("private withdrawn policy")
	for _, operation := range []scim.Operation{scim.ResourceTypesList, scim.SchemasList, scim.UserList, scim.GroupList} {
		r, err := service.Execute(context.Background(), combinedRequest(scim.Request{Operation: operation}))
		assertProtocolError(t, r, err, 403, "")
	}
	policy.err = nil
	for _, operation := range []scim.Operation{scim.SchemasList, scim.GroupList} {
		r := combinedRequest(scim.Request{Operation: operation})
		r.Credential = authentication.NewBearerCredential("expired")
		out, err := service.Execute(context.Background(), r)
		assertProtocolError(t, out, err, 401, "")
	}
	newProtocolFixture(t).deny(t, scim.Request{Operation: scim.ResourceTypeGet, ResourceID: "Group"}, 404, "")
	newGroupFixture(t, nil).deny(t, scim.Request{Operation: scim.ResourceTypeGet, ResourceID: "User"}, 404, "")
	var group sync.WaitGroup
	for _, operation := range []scim.Operation{scim.SchemasList, scim.ResourceTypesList, scim.UserList, scim.GroupList} {
		group.Go(func() {
			_, err := service.Execute(context.Background(), combinedRequest(scim.Request{Operation: operation}))
			if err != nil {
				t.Error("concurrent combined read failed")
			}
		})
	}
	group.Wait()
}

func TestCombinedLateAuthorityExpiryWithholdsDiscoveryAndResources(t *testing.T) {
	for _, operation := range []scim.Operation{scim.ResourceTypesList, scim.SchemasList, scim.UserList, scim.GroupList} {
		_, config := newCombinedFixture(t)
		now := fixtureNow
		config.Now = func() time.Time { return now }
		config.Authorizer = combinedExpiringAuthorizer{advance: func() { now = fixtureNow.Add(20 * time.Second) }}
		service, err := scim.NewCombinedService(config)
		if err != nil {
			t.Fatal(err)
		}
		out, err := service.Execute(context.Background(), combinedRequest(scim.Request{Operation: operation}))
		assertProtocolError(t, out, err, 503, "")
	}
}

func FuzzCombinedDiscoverySelection(f *testing.F) {
	for _, id := range []string{combinedSharedExtension, "urn:example:SHARED", userURN, groupURN, "", "not a schema", "urn:example:é"} {
		f.Add(id, false)
		f.Add(id, true)
	}
	f.Fuzz(func(t *testing.T, id string, conflict bool) {
		if len(id) > 1024 {
			return
		}
		_, config := newCombinedFixture(t)
		config.UserExtensions = []scim.Schema{combinedExtension(id, "Shared")}
		config.GroupExtensions = []scim.Schema{combinedExtension(id, "Shared")}
		if conflict {
			config.GroupExtensions[0].Attributes[0].Type = "boolean"
		}
		service, err := scim.NewCombinedService(config)
		if err != nil {
			if service != nil {
				t.Fatal("failed selection returned partial runtime")
			}
			assertProtocolError(t, scim.Response{}, err, 400, "invalidValue")
			return
		}
		if conflict {
			t.Fatal("conflicting shared descriptor was admitted")
		}
		list := object(t, combinedCall(t, service, scim.Request{Operation: scim.SchemasList}).Body)
		if list["totalResults"] != float64(3) || list["itemsPerPage"] != float64(3) {
			t.Fatal("shared selected schema is not represented exactly once")
		}
		schema := object(t, combinedCall(t, service, scim.Request{Operation: scim.SchemaGet, ResourceID: id}).Body)
		if schema["id"] != id {
			t.Fatal("schema lookup substituted another identity")
		}
	})
}

type combinedExpiringAuthorizer struct{ advance func() }

func (a combinedExpiringAuthorizer) Authorize(ctx context.Context, c scim.Connection, op scim.Operation, id string) error {
	if err := (&protocolAuthorizer{}).Authorize(ctx, c, op, id); err != nil {
		return err
	}
	a.advance()
	return nil
}

func combinedExtension(id, name string) scim.Schema {
	return scim.Schema{ID: id, Name: name, Attributes: []scim.Attribute{{Name: "note", Type: "string", Mutability: "readWrite", Returned: "default", Uniqueness: "none"}}}
}

type combinedFixture struct {
	users  *protocolStore
	groups *groupProtocolStore
}

func newCombinedFixture(t *testing.T) (*combinedFixture, scim.CombinedConfig) {
	t.Helper()
	u := newProtocolFixture(t)
	g := newGroupFixture(t, nil)
	f := &combinedFixture{users: u.store, groups: g.store}
	// This boundary double mirrors actual User fixture commits into its member
	// existence index. It proves protocol routing only, not durable provisioning.
	users := combinedUserStore{Store: u.store, groups: g.store}
	return f, scim.CombinedConfig{UserStore: users, UserMapper: u.mapper, GroupStore: g.store, GroupMapper: g.mapper, Authenticator: protocolAuthenticator{}, Authorizer: &protocolAuthorizer{}, Limits: scim.DefaultLimits(), GroupMembers: scim.DefaultGroupMembers, BaseURL: "https://scim.example.test/v2", Now: func() time.Time { return fixtureNow }, RequestTimeout: time.Second}
}

type combinedUserStore struct {
	scim.Store
	groups *groupProtocolStore
}

func (s combinedUserStore) Commit(ctx context.Context, p scim.PreparedWrite, c scim.Change) (scim.WriteResult, error) {
	r, err := s.Store.Commit(ctx, p, c)
	if err == nil && r.Outcome == scim.WriteOutcomeCommitted {
		s.groups.mu.Lock()
		if r.Resource != nil {
			s.groups.users[fixtureResourceKey{p.Intent.Scope, r.Resource.ID}] = true
		} else if c.Delete {
			delete(s.groups.users, fixtureResourceKey{p.Intent.Scope, p.Intent.ResourceID})
		}
		s.groups.mu.Unlock()
	}
	return r, err
}

func combinedRequest(r scim.Request) scim.Request {
	r.Credential = authentication.NewBearerCredential("fixture-connection")
	if len(r.Body) > 0 {
		r.ContentType = "application/scim+json"
	}
	return r
}
func combinedCall(t *testing.T, s *scim.CombinedService, r scim.Request) scim.Response {
	t.Helper()
	out, err := s.Execute(context.Background(), combinedRequest(r))
	if err != nil {
		t.Fatalf("combined %s: %v", r.Operation, err)
	}
	if out.ContentType != "application/scim+json" {
		t.Fatal("wrong combined content type")
	}
	return out
}
