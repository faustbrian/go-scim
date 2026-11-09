package scim_test

import (
	"encoding/json"
	"strings"
	"testing"

	scim "github.com/faustbrian/go-scim"
)

func TestUsersProfilePrimaryReassignment(t *testing.T) {
	f := newProtocolFixture(t)
	created := f.call(t, scim.UserCreate, "", "", userBody("primary", `,"emails":[{"value":"work@example.test","type":"work","primary":true},{"value":"home@example.test","type":"home"}]`))
	id := object(t, created.Body)["id"].(string)
	r := f.call(t, scim.UserPatch, id, created.ETag, patchBody(`{"op":"replace","path":"emails[type eq \"home\"].primary","value":true}`))
	emails := object(t, r.Body)["emails"].([]any)
	if emails[0].(map[string]any)["primary"] != false || emails[1].(map[string]any)["primary"] != true {
		t.Fatalf("primary not reassigned atomically: %s", r.Body)
	}
	r = f.call(t, scim.UserPatch, id, r.ETag, patchBody(`{"op":"add","path":"emails","value":[{"value":"new@example.test","primary":true}]}`))
	emails = object(t, r.Body)["emails"].([]any)
	if emails[1].(map[string]any)["primary"] != false || emails[2].(map[string]any)["primary"] != true {
		t.Fatalf("added primary did not reset existing primary: %s", r.Body)
	}
}

const extensionURN = "urn:example:scim:schemas:extension:profile:2.0:User"

func extensionConfig(c *scim.Config) {
	c.Extensions = []scim.Schema{{ID: extensionURN, Name: "Profile", Attributes: []scim.Attribute{
		{Name: "code", Type: "string", CaseExact: true, Mutability: "immutable", Returned: "default", Uniqueness: "none"},
		{Name: "note", Type: "string", Mutability: "readWrite", Returned: "request", Uniqueness: "none"},
		{Name: "secret", Type: "string", Mutability: "writeOnly", Returned: "never", Uniqueness: "none"},
		{Name: "rank", Type: "integer", Mutability: "readWrite", Returned: "default", Uniqueness: "none"},
	}}}
}
func TestUsersProfileExtensionPolicies(t *testing.T) {
	f := configuredProtocolFixture(t, extensionConfig)
	body := `{"schemas":["` + userURN + `","` + extensionURN + `"],"userName":"extended","` + extensionURN + `":{"code":"CaseExact","note":"by request","rank":2}}`
	created := f.call(t, scim.UserCreate, "", "", body)
	id := object(t, created.Body)["id"].(string)
	extension := object(t, created.Body)[extensionURN].(map[string]any)
	if extension["note"] != "by request" || extension["code"] != "CaseExact" {
		t.Fatalf("returned policy ignored: %s", created.Body)
	}
	ordinary := object(t, f.call(t, scim.UserGet, id, "", "").Body)[extensionURN].(map[string]any)
	if ordinary["note"] != nil {
		t.Fatal("ordinary GET returned an unrequested request-only attribute")
	}
	read := f.execute(t, scim.Request{Operation: scim.UserGet, ResourceID: id, Query: scim.Query{Attributes: extensionURN + ":note"}})
	if object(t, read.Body)[extensionURN].(map[string]any)["note"] != "by request" {
		t.Fatalf("requested extension missing: %s", read.Body)
	}
	f.deny(t, scim.Request{Operation: scim.UserReplace, ResourceID: id, IfMatch: created.ETag, Body: []byte(userBody("extended", ""))}, 400, "mutability")
	f.deny(t, scim.Request{Operation: scim.UserPatch, ResourceID: id, IfMatch: created.ETag, Body: []byte(patchBody(`{"op":"replace","path":"` + extensionURN + `:code","value":"caseexact"}`))}, 400, "mutability")
	for _, q := range []scim.Query{{Filter: extensionURN + `:secret pr`}, {SortBy: extensionURN + ":secret"}, {Attributes: extensionURN + ":secret"}} {
		f.deny(t, scim.Request{Operation: scim.UserList, Query: q}, 400, "")
	}
	f.deny(t, scim.Request{Operation: scim.UserPatch, ResourceID: id, IfMatch: created.ETag, Body: []byte(patchBody(`{"op":"add","path":"` + extensionURN + `:secret","value":"NEVER-PERSIST"}`))}, 400, "")
	r := f.execute(t, scim.Request{Operation: scim.UserList, Query: scim.Query{Filter: extensionURN + `:code eq "caseexact"`}})
	if object(t, r.Body)["totalResults"] != float64(0) {
		t.Fatalf("caseExact comparison ignored: %s", r.Body)
	}
	r = f.execute(t, scim.Request{Operation: scim.UserList, Query: scim.Query{Filter: extensionURN + `:rank gt 1`}})
	if object(t, r.Body)["totalResults"] != float64(1) {
		t.Fatalf("typed numeric comparison failed: %s", r.Body)
	}
}
func TestUsersProfileImplicitExtensionPatch(t *testing.T) {
	f := configuredProtocolFixture(t, extensionConfig)
	created := f.call(t, scim.UserCreate, "", "", userBody("implicit", ""))
	id := object(t, created.Body)["id"].(string)
	r := f.call(t, scim.UserPatch, id, created.ETag, patchBody(`{"op":"add","path":"`+extensionURN+`:code","value":"added"}`))
	schemas := object(t, r.Body)["schemas"].([]any)
	if len(schemas) != 2 || schemas[1] != extensionURN {
		t.Fatalf("qualified PATCH did not add schema: %s", r.Body)
	}
}
func TestUsersProfileStrictParserBudgets(t *testing.T) {
	limits := scim.DefaultLimits()
	limits.FilterDepth = 3
	if _, err := scim.ParseFilter(strings.TrimSuffix(strings.Repeat(`userName pr and `, 8), " and "), nil, limits); err == nil {
		t.Fatal("flat boolean AST exceeded depth without rejection")
	}
	limits = scim.DefaultLimits()
	limits.FilterNodes = 2
	if _, err := scim.ParseFilter(`userName pr and active pr`, nil, limits); err == nil {
		t.Fatal("node budget not enforced")
	}
	limits = scim.DefaultLimits()
	limits.FilterTokens = 2
	if _, err := scim.ParseFilter(`userName eq "a"`, nil, limits); err == nil {
		t.Fatal("token budget not enforced")
	}
	if _, err := scim.ParseFilter(`userName eq"missing space"`, nil, scim.DefaultLimits()); err == nil {
		t.Fatal("invalid comparison grammar accepted")
	}
}
func TestUsersProfileErrorEnvelopeZeroValue(t *testing.T) {
	var empty scim.Error
	wire, err := json.Marshal(&empty)
	if err != nil {
		t.Fatal(err)
	}
	if object(t, wire)["status"] != "500" || empty.StatusCode() != 500 {
		t.Fatalf("zero error emitted invalid RFC status: %s", wire)
	}
}
func TestUsersProfileQueryErrorTypes(t *testing.T) {
	f := newProtocolFixture(t)
	e := f.deny(t, scim.Request{Operation: scim.UserList, Query: scim.Query{SortBy: "unknown"}}, 400, "")
	wire, _ := json.Marshal(e)
	if object(t, wire)["scimType"] == "invalidPath" {
		t.Fatal("PATCH-only invalidPath emitted on GET-list")
	}
}

func TestUsersProfileReadOnlyAndVersionProjection(t *testing.T) {
	f := configuredProtocolFixture(t, func(c *scim.Config) {
		extensionConfig(c)
		c.Extensions[0].Attributes = append(c.Extensions[0].Attributes, scim.Attribute{Name: "origin", Type: "string", Mutability: "readOnly", Returned: "default", Uniqueness: "none"})
	})
	created := f.call(t, scim.UserCreate, "", "", `{"schemas":["`+userURN+`","`+extensionURN+`"],"userName":"readonly"}`)
	id := object(t, created.Body)["id"].(string)
	// Only the trusted fixture store supplies the server-owned read-only value.
	for key, resource := range f.store.resources {
		resource.Attributes[extensionURN] = map[string]any{"origin": "trusted-source"}
		f.store.resources[key] = resource
	}
	patched := f.call(t, scim.UserPatch, id, created.ETag, patchBody(`{"op":"replace","path":"displayName","value":"changed"}`))
	if object(t, patched.Body)[extensionURN].(map[string]any)["origin"] != "trusted-source" {
		t.Fatalf("PATCH lost read-only data: %s", patched.Body)
	}
	replaced := f.call(t, scim.UserReplace, id, patched.ETag, `{"schemas":["`+userURN+`","`+extensionURN+`"],"userName":"readonly"}`)
	if object(t, replaced.Body)[extensionURN].(map[string]any)["origin"] != "trusted-source" {
		t.Fatalf("PUT lost read-only data: %s", replaced.Body)
	}
	r := f.execute(t, scim.Request{Operation: scim.UserList, Query: scim.Query{Attributes: "userName"}})
	meta, ok := object(t, r.Body)["Resources"].([]any)[0].(map[string]any)["meta"].(map[string]any)
	if !ok || meta["version"] != string(replaced.ETag) {
		t.Fatalf("projected list hid next-mutation version: %s", r.Body)
	}
}

func TestUsersProfileFailedMutationReplay(t *testing.T) {
	f := newProtocolFixture(t)
	created := f.call(t, scim.UserCreate, "", "", userBody("failed-retry", ""))
	id := object(t, created.Body)["id"].(string)
	request := scim.Request{Operation: scim.UserPatch, ResourceID: id, IfMatch: created.ETag, IdempotencyKey: "failed-command", Body: []byte(patchBody(`{"op":"remove","path":"emails[type eq \"work\"]"}`))}
	f.deny(t, request, 400, "noTarget")
	replacement := f.call(t, scim.UserReplace, id, created.ETag, userBody("failed-retry", `,"displayName":"later state"`))
	f.deny(t, request, 400, "noTarget")
	if f.call(t, scim.UserGet, id, "", "").ETag != replacement.ETag {
		t.Fatal("failed retry changed current resource")
	}
}

func TestUsersProfilePathlessAndOverlappingExtensionURNs(t *testing.T) {
	f := configuredProtocolFixture(t, func(c *scim.Config) {
		extensionConfig(c)
		short := c.Extensions[0]
		short.ID = "urn:example:scim:schemas:extension:profile"
		short.Name = "ShortProfile"
		c.Extensions = append([]scim.Schema{short}, c.Extensions...)
	})
	created := f.call(t, scim.UserCreate, "", "", userBody("extension-paths", ""))
	id := object(t, created.Body)["id"].(string)
	patched := f.call(t, scim.UserPatch, id, created.ETag, patchBody(`{"op":"add","value":{"`+extensionURN+`":{"rank":5}}}`))
	if object(t, patched.Body)[extensionURN].(map[string]any)["rank"] != float64(5) {
		t.Fatal("pathless extension addition missing")
	}
	listed := f.execute(t, scim.Request{Operation: scim.UserList, Query: scim.Query{Filter: extensionURN + `:rank eq 5`}})
	if object(t, listed.Body)["totalResults"] != float64(1) {
		t.Fatal("longest declared schema URN did not own its path")
	}
}
