package scim_test

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	authentication "github.com/faustbrian/go-authentication/v2"
	scim "github.com/faustbrian/go-scim"
)

func TestGroupsRejectBaseURLDelimitersBeforeDependencies(t *testing.T) {
	for _, baseURL := range []string{"https://scim.example.test/v2?", "https://scim.example.test/v2#"} {
		t.Run(baseURL, func(t *testing.T) {
			dependencies := groupConstructorDependencyTrap{}
			config := scim.GroupsConfig{
				Store: dependencies, Mapper: dependencies, Authenticator: dependencies, Authorizer: dependencies,
				Limits: scim.DefaultLimits(), GroupMembers: scim.DefaultGroupMembers,
				BaseURL: baseURL, Now: func() time.Time { return fixtureNow }, RequestTimeout: time.Second,
			}
			service, err := scim.NewGroupsService(config)
			var protocol *scim.Error
			if service != nil || !errors.As(err, &protocol) || protocol.StatusCode() != 400 {
				t.Fatalf("ambiguous service root was not rejected: service=%v error=%v", service != nil, err)
			}
		})
	}
}

// Every promoted dependency method panics if invoked. Constructor admission
// must reject these roots without consulting any external policy or storage.
type groupConstructorDependencyTrap struct {
	scim.GroupStore
	scim.GroupMapper
	scim.Authenticator
	scim.Authorizer
}

func TestGroupsNestedMembershipReferencesAndTypeIsolation(t *testing.T) {
	f := newGroupFixture(t, nil)
	nested := f.call(t, scim.GroupCreate, "", "", groupBody("Nested", ""))
	nestedID := object(t, nested.Body)["id"].(string)
	parent := f.call(t, scim.GroupCreate, "", "", groupBody("Parent", `,"members":[{"value":"`+nestedID+`","$ref":"Groups/`+nestedID+`"}]`))
	member := object(t, parent.Body)["members"].([]any)[0].(map[string]any)
	if member["type"] != "Group" || member["$ref"] != nested.Location {
		t.Fatalf("relative Group ref did not retain type: %#v", member)
	}
	f.deny(t, scim.Request{Operation: scim.GroupCreate, Body: []byte(groupBody("not a User", `,"members":[{"value":"`+nestedID+`","type":"User"}]`))}, 400, "invalidValue")
	f.deny(t, scim.Request{Operation: scim.GroupCreate, Credential: authentication.NewBearerCredential("fixture-other-connection"), Body: []byte(groupBody("not this connection's Group", `,"members":[{"value":"`+nestedID+`","type":"Group"}]`))}, 400, "invalidValue")
	parentID := object(t, parent.Body)["id"].(string)
	f.call(t, scim.GroupDelete, parentID, parent.ETag, "")
	if stillThere := f.call(t, scim.GroupGet, nestedID, "", ""); stillThere.ETag != nested.ETag {
		t.Fatal("deleting parent modified its nested Group")
	}
}

func TestGroupsMemberReferenceUsesURICanonicalComparison(t *testing.T) {
	f := newGroupFixture(t, nil)
	f.addUser("a", "fixture-connection")
	created := f.call(t, scim.GroupCreate, "", "", groupBody("Canonical URI", `,"members":[{"value":"a","$ref":"https://SCIM.EXAMPLE.TEST/v2/Users/%61"}]`))
	member := object(t, created.Body)["members"].([]any)[0].(map[string]any)
	if member["$ref"] != "https://scim.example.test/v2/Users/a" {
		t.Fatalf("URI did not canonicalize to its exact owned target: %#v", member)
	}
}

func TestGroupsPatchBoundsAndExplicitRemoveAdd(t *testing.T) {
	f := newGroupFixture(t, func(c *scim.GroupsConfig) { c.GroupMembers = 1 })
	f.addUser("a", "fixture-connection")
	f.addUser("b", "fixture-connection")
	created := f.call(t, scim.GroupCreate, "", "", groupBody("Bounded", `,"members":[{"value":"a","display":"Before"}]`))
	id := object(t, created.Body)["id"].(string)
	f.deny(t, scim.Request{Operation: scim.GroupPatch, ResourceID: id, IfMatch: created.ETag, Body: []byte(patchBody(`{"op":"replace","path":"displayName","value":"must roll back"},{"op":"add","path":"members","value":[{"value":"b"}]}`))}, 400, "invalidValue")
	if read := f.call(t, scim.GroupGet, id, "", ""); string(read.Body) != string(created.Body) {
		t.Fatal("bounded PATCH committed an earlier operation")
	}
	changed := f.call(t, scim.GroupPatch, id, created.ETag, patchBody(`{"op":"remove","path":"members[value eq \"a\"]"},{"op":"add","path":"members","value":[{"value":"a","display":"After"}]}`))
	if object(t, changed.Body)["members"].([]any)[0].(map[string]any)["display"] != "After" || changed.ETag == created.ETag {
		t.Fatal("explicit remove then add did not create a new member value")
	}
	f.deny(t, scim.Request{Operation: scim.GroupReplace, ResourceID: id, IfMatch: changed.ETag, Body: []byte(groupBody("retained immutable", `,"members":[{"value":"a","display":"Modified"}]`))}, 400, "mutability")
	for _, path := range []string{"members", groupURN + ":members"} {
		noop := f.call(t, scim.GroupPatch, id, changed.ETag, patchBody(`{"op":"add","value":{"`+path+`":[{"value":"a"}]}}`))
		if noop.ETag != changed.ETag || string(noop.Body) != string(changed.Body) {
			t.Fatal("pathless existing membership addition was not a no-op")
		}
	}
}

func TestGroupsImmutableMemberDisplayUsesDeclaredComparison(t *testing.T) {
	f := newGroupFixture(t, nil)
	f.addUser("a", "fixture-connection")
	created := f.call(t, scim.GroupCreate, "", "", groupBody("Comparison", `,"members":[{"value":"a","display":"Alice"}]`))
	id := object(t, created.Body)["id"].(string)
	for _, operation := range []string{
		`{"op":"add","path":"members","value":[{"value":"a","display":"ALICE"}]}`,
		`{"op":"replace","path":"members[value eq \"a\"].display","value":"ALICE"}`,
	} {
		response := f.call(t, scim.GroupPatch, id, created.ETag, patchBody(operation))
		if response.ETag != created.ETag || string(response.Body) != string(created.Body) {
			t.Fatal("schema-equivalent immutable member display was not a no-op")
		}
	}
}

func TestGroupsExtensionReturnedAndMutabilityPolicies(t *testing.T) {
	requestOnly := reviewAttribute("note", "string")
	requestOnly.Returned = "request"
	immutable := reviewAttribute("code", "string")
	immutable.Mutability = "immutable"
	secret := reviewAttribute("secret", "string")
	secret.Mutability, secret.Returned = "writeOnly", "never"
	f := newGroupFixture(t, func(c *scim.GroupsConfig) {
		c.Extensions = []scim.Schema{{ID: extensionURN, Name: "GroupExtension", Attributes: []scim.Attribute{requestOnly, immutable, secret}}}
	})
	body := `{"schemas":["` + groupURN + `","` + extensionURN + `"],"displayName":"Extended","` + extensionURN + `":{"note":"supplied","code":"stable"}}`
	request := scim.Request{Operation: scim.GroupCreate, IdempotencyKey: "extension", Body: []byte(body)}
	created := f.execute(t, request)
	id := object(t, created.Body)["id"].(string)
	if object(t, created.Body)[extensionURN].(map[string]any)["note"] != "supplied" {
		t.Fatal("write-supplied request-only value omitted")
	}
	if replay := f.execute(t, request); string(replay.Body) != string(created.Body) {
		t.Fatal("request-only replay changed its disclosure context")
	}
	read := f.call(t, scim.GroupGet, id, "", "")
	if object(t, read.Body)[extensionURN].(map[string]any)["note"] != nil {
		t.Fatal("GET disclosed request-only value")
	}
	selected := f.execute(t, scim.Request{Operation: scim.GroupGet, ResourceID: id, Query: scim.Query{Attributes: extensionURN + ":note"}})
	if object(t, selected.Body)[extensionURN].(map[string]any)["note"] != "supplied" {
		t.Fatal("explicit Group projection lost request-only value")
	}
	for _, operation := range []string{
		`{"op":"replace","path":"` + extensionURN + `:code","value":"changed"}`,
		`{"op":"replace","path":"` + extensionURN + `:secret","value":"never-store"}`,
	} {
		f.deny(t, scim.Request{Operation: scim.GroupPatch, ResourceID: id, IfMatch: created.ETag, Body: []byte(patchBody(operation))}, 400, "mutability")
	}
	f.deny(t, scim.Request{Operation: scim.GroupList, Query: scim.Query{Filter: extensionURN + `:secret pr`}}, 400, "invalidFilter")
}

func TestGroupsRejectWrongTypeMapperAndStoreProjections(t *testing.T) {
	mapper := &wrongTypeGroupMapper{}
	f := newGroupFixture(t, func(c *scim.GroupsConfig) { c.Mapper = mapper })
	f.deny(t, scim.Request{Operation: scim.GroupCreate, Body: []byte(groupBody("wrong mapper", ""))}, 503, "")
	if len(f.store.resources) != 0 {
		t.Fatal("User mapper projection committed as Group")
	}
	f = newGroupFixture(t, nil)
	created := f.call(t, scim.GroupCreate, "", "", groupBody("wrong store", ""))
	id := object(t, created.Body)["id"].(string)
	for key, resource := range f.store.resources {
		resource.Schemas = []string{userURN}
		resource.Attributes = map[string]any{"userName": "not-a-group"}
		f.store.resources[key] = resource
	}
	f.deny(t, scim.Request{Operation: scim.GroupGet, ResourceID: id}, 503, "")
	f.deny(t, scim.Request{Operation: scim.GroupList}, 503, "")
	f.deny(t, scim.Request{Operation: scim.GroupPatch, ResourceID: id, IfMatch: created.ETag, Body: []byte(patchBody(`{"op":"replace","path":"displayName","value":"not allowed"}`))}, 503, "")
}

type wrongTypeGroupMapper struct{}

func (*wrongTypeGroupMapper) MapGroup(context.Context, scim.Scope, scim.WritableResource) (scim.WritableResource, error) {
	return scim.WritableResource{Schemas: []string{userURN}, Attributes: map[string]any{"userName": "wrong type"}}, nil
}

func TestGroupsLateReadAndCommitWithholdExpiredAuthority(t *testing.T) {
	for _, boundary := range []string{"read", "commit"} {
		t.Run(boundary, func(t *testing.T) {
			clock := fixtureNow
			var store *groupDeadlineStore
			f := newGroupFixture(t, func(c *scim.GroupsConfig) {
				store = &groupDeadlineStore{GroupStore: c.Store, now: &clock}
				c.Store = store
				c.Now = func() time.Time { return clock }
				c.Authenticator = currentGroupAuthenticator{now: &clock}
			})
			created := f.call(t, scim.GroupCreate, "", "", groupBody("deadline", ""))
			id := object(t, created.Body)["id"].(string)
			store.boundary = boundary
			request := scim.Request{Operation: scim.GroupGet, ResourceID: id}
			if boundary == "commit" {
				request = scim.Request{Operation: scim.GroupPatch, ResourceID: id, IfMatch: created.ETag, IdempotencyKey: "late-commit", Body: []byte(patchBody(`{"op":"replace","path":"displayName","value":"committed before expiry"}`))}
			}
			f.deny(t, request, 503, "")
			if boundary == "commit" {
				if f.store.lastOutcome != scim.WriteOutcomeCommitted || len(f.store.pending) != 0 {
					t.Fatal("late successful commit was aborted or called rollback")
				}
				store.boundary = ""
				replay := f.execute(t, request)
				if object(t, replay.Body)["displayName"] != "committed before expiry" {
					t.Fatal("retained commit result was not replayed")
				}
			}
		})
	}
}

type groupDeadlineStore struct {
	scim.GroupStore
	now      *time.Time
	boundary string
}

type currentGroupAuthenticator struct{ now *time.Time }

func (a currentGroupAuthenticator) Authenticate(ctx context.Context, credential authentication.BearerCredential) (scim.Connection, error) {
	c, err := (protocolAuthenticator{}).Authenticate(ctx, credential)
	c.AuthorityReadBeganAt = *a.now
	c.AuthorityValidUntil = a.now.Add(20 * time.Second)
	return c, err
}

func (s *groupDeadlineStore) GetGroup(ctx context.Context, scope scim.Scope, id string) (scim.Resource, error) {
	r, err := s.GroupStore.GetGroup(ctx, scope, id)
	if s.boundary == "read" {
		*s.now = s.now.Add(20 * time.Second)
	}
	return r, err
}

func (s *groupDeadlineStore) CommitGroup(ctx context.Context, prepared scim.PreparedWrite, change scim.Change) (scim.WriteResult, error) {
	r, err := s.GroupStore.CommitGroup(ctx, prepared, change)
	if s.boundary == "commit" {
		*s.now = s.now.Add(20 * time.Second)
	}
	return r, err
}

func TestGroupsConcurrentIfMatchAllowsOneWinner(t *testing.T) {
	f := newGroupFixture(t, nil)
	created := f.call(t, scim.GroupCreate, "", "", groupBody("race", ""))
	id := object(t, created.Body)["id"].(string)
	var wait sync.WaitGroup
	results := make(chan error, 8)
	for i := 0; i < 8; i++ {
		wait.Add(1)
		go func() {
			defer wait.Done()
			_, err := f.raw(scim.Request{Operation: scim.GroupPatch, ResourceID: id, IfMatch: created.ETag, Body: []byte(patchBody(`{"op":"replace","path":"displayName","value":"one winner"}`))})
			results <- err
		}()
	}
	wait.Wait()
	close(results)
	winners := 0
	for err := range results {
		if err == nil {
			winners++
			continue
		}
		var protocol *scim.Error
		if !errors.As(err, &protocol) || protocol.StatusCode() != 412 {
			t.Fatalf("unexpected concurrent result: %v", err)
		}
	}
	if winners != 1 {
		t.Fatalf("IfMatch committed %d winners", winners)
	}
	if current := f.call(t, scim.GroupGet, id, "", ""); current.ETag == created.ETag || object(t, current.Body)["displayName"] != "one winner" {
		t.Fatal("concurrent winner was not retained")
	}
}

func FuzzGroupsBoundedPublicProtocol(f *testing.F) {
	f.Add(`{"schemas":["`+groupURN+`"],"displayName":"group","members":[{"value":"member"}]}`, `members[value eq "member"]`, `{"op":"add","path":"members","value":[{"value":"member"}]}`)
	f.Add(`{"schemas":["`+groupURN+`"],"displayName":"group","DISPLAYNAME":"alias"}`, `members[$ref pr]`, `{"op":"replace","path":"members[value eq \"member\"].$ref","value":"https://elsewhere.test/Users/member"}`)
	f.Fuzz(func(t *testing.T, create, filter, patch string) {
		if len(create)+len(filter)+len(patch) > 4096 {
			t.Skip()
		}
		fixture := newGroupFixture(t, nil)
		fixture.addUser("member", "fixture-connection")
		for _, request := range []scim.Request{
			{Operation: scim.GroupCreate, Body: []byte(create)},
			{Operation: scim.GroupList, Query: scim.Query{Filter: filter}},
		} {
			response, err := fixture.raw(request)
			assertBoundedGroupOutcome(t, response, err)
		}
		created := fixture.call(t, scim.GroupCreate, "", "", groupBody("patch target", `,"members":[{"value":"member"}]`))
		id := object(t, created.Body)["id"].(string)
		response, err := fixture.raw(scim.Request{Operation: scim.GroupPatch, ResourceID: id, IfMatch: created.ETag, Body: []byte(patchBody(patch))})
		assertBoundedGroupOutcome(t, response, err)
		if err != nil {
			if current := fixture.call(t, scim.GroupGet, id, "", ""); string(current.Body) != string(created.Body) {
				t.Fatal("invalid fuzz PATCH partially mutated its Group")
			}
		}
	})
}

func assertBoundedGroupOutcome(t *testing.T, response scim.Response, err error) {
	t.Helper()
	if err == nil {
		if response.Status < 200 || response.Status > 299 || len(response.Body) > scim.DefaultLimits().ResponseBytes {
			t.Fatal("unbounded or invalid success")
		}
		return
	}
	var protocol *scim.Error
	if !errors.As(err, &protocol) || response.Status != 0 || len(response.Body) != 0 {
		t.Fatalf("partial or untyped failure: %#v %v", response, err)
	}
	encoded, marshalErr := json.Marshal(err)
	if marshalErr != nil || len(encoded) > 1024 || strings.Contains(string(encoded), "fixture-connection") {
		t.Fatal("unbounded or revealing error")
	}
}
