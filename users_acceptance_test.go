package scim_test

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	authentication "github.com/faustbrian/go-authentication/v2"
	scim "github.com/faustbrian/go-scim"
)

const (
	userURN   = "urn:ietf:params:scim:schemas:core:2.0:User"
	listURN   = "urn:ietf:params:scim:api:messages:2.0:ListResponse"
	patchURN  = "urn:ietf:params:scim:api:messages:2.0:PatchOp"
	searchURN = "urn:ietf:params:scim:api:messages:2.0:SearchRequest"
	errorURN  = "urn:ietf:params:scim:api:messages:2.0:Error"
)

// These are protocol acceptance tests, not identity, organization, connection-
// token, database or provisioning evidence. Only the protocol service is real;
// the caller-owned authority, pure mapper and atomic store seams are doubles.
func TestUsersProfileDiscovery(t *testing.T) {
	f := newProtocolFixture(t)
	r := f.call(t, scim.ServiceProviderConfig, "", "", "")
	d := object(t, r.Body)
	assertSchemas(t, d, "urn:ietf:params:scim:schemas:core:2.0:ServiceProviderConfig")
	for _, name := range []string{"patch", "filter", "sort", "etag"} {
		if d[name].(map[string]any)["supported"] != true {
			t.Fatalf("%s not advertised: %s", name, r.Body)
		}
	}
	for _, name := range []string{"bulk", "changePassword"} {
		if d[name].(map[string]any)["supported"] != false {
			t.Fatalf("disabled %s advertised: %s", name, r.Body)
		}
	}
	if d["filter"].(map[string]any)["maxResults"] != float64(2) {
		t.Fatalf("discovery does not use effective page maximum: %s", r.Body)
	}
	schemes := d["authenticationSchemes"].([]any)
	if len(schemes) != 1 || schemes[0].(map[string]any)["type"] != "oauthbearertoken" {
		t.Fatalf("unexpected authentication catalog: %s", r.Body)
	}
	for _, op := range []scim.Operation{scim.SchemasList, scim.ResourceTypesList} {
		r = f.call(t, op, "", "", "")
		d = object(t, r.Body)
		assertSchemas(t, d, listURN)
		resources := d["Resources"].([]any)
		if len(resources) != 1 || d["totalResults"] != float64(1) || d["startIndex"] != float64(1) || d["itemsPerPage"] != float64(1) {
			t.Fatalf("invalid bounded discovery collection: %s", r.Body)
		}
		doc := resources[0].(map[string]any)
		if op == scim.ResourceTypesList {
			assertSchemas(t, doc, "urn:ietf:params:scim:schemas:core:2.0:ResourceType")
			if doc["endpoint"] != "/Users" || doc["schema"] != userURN {
				t.Fatalf("Users-only resource type mismatch: %s", r.Body)
			}
		} else {
			assertSchemas(t, doc, "urn:ietf:params:scim:schemas:core:2.0:Schema")
			if doc["id"] != userURN {
				t.Fatalf("unexpected schema: %s", r.Body)
			}
		}
	}
	assertSchemas(t, object(t, f.call(t, scim.SchemaGet, userURN, "", "").Body), "urn:ietf:params:scim:schemas:core:2.0:Schema")
	assertSchemas(t, object(t, f.call(t, scim.ResourceTypeGet, "User", "", "").Body), "urn:ietf:params:scim:schemas:core:2.0:ResourceType")
	f.deny(t, scim.Request{Operation: scim.SchemaGet, ResourceID: "urn:unknown"}, 404, "")
	for _, op := range []scim.Operation{scim.GroupCreate, scim.GroupGet, scim.GroupList, scim.GroupReplace, scim.GroupPatch, scim.GroupDelete, scim.GroupSearch, scim.Bulk} {
		f.deny(t, scim.Request{Operation: op, Body: []byte(`{}`)}, 501, "")
	}
}

func TestUsersProfileLifecycle(t *testing.T) {
	f := newProtocolFixture(t)
	created := f.call(t, scim.UserCreate, "", "", userBody("Alice", `,"externalId":"shared","displayName":"Alice Original","active":true,"name":{"givenName":"Alice","familyName":"Example"},"emails":[{"value":"alice@example.test","type":"work","primary":true}]`))
	if created.Status != 201 || created.ETag == "" || strings.HasPrefix(string(created.ETag), "W/") || !strings.HasPrefix(string(created.ETag), `"`) {
		t.Fatalf("missing strong create version: %#v", created)
	}
	d := object(t, created.Body)
	id := d["id"].(string)
	assertSchemas(t, d, userURN)
	meta := d["meta"].(map[string]any)
	if meta["version"] != string(created.ETag) || meta["resourceType"] != "User" || meta["location"] != created.Location || !strings.HasSuffix(created.Location, "/Users/"+id) {
		t.Fatalf("authoritative metadata missing: %s", created.Body)
	}
	got := f.call(t, scim.UserGet, id, "", "")
	if string(got.Body) != string(created.Body) || got.ETag != created.ETag {
		t.Fatalf("create/read disagree: %s / %s", created.Body, got.Body)
	}
	f.deny(t, scim.Request{Operation: scim.UserReplace, ResourceID: id, Body: []byte(userBody("Alice", ""))}, 428, "")
	f.deny(t, scim.Request{Operation: scim.UserReplace, ResourceID: id, IfMatch: `"stale"`, Body: []byte(userBody("Alice", ""))}, 412, "")
	replaced := f.call(t, scim.UserReplace, id, created.ETag, userBody("Alice", `,"externalId":"shared","displayName":"Replaced"`))
	if replaced.ETag == created.ETag || object(t, replaced.Body)["name"] != nil || object(t, replaced.Body)["emails"] != nil {
		t.Fatalf("replace did not remove omitted writable fields/version: %s", replaced.Body)
	}
	patched := f.call(t, scim.UserPatch, id, replaced.ETag, patchBody(`{"op":"add","path":"name","value":{"givenName":"Updated"}},{"op":"add","path":"emails","value":[{"value":"one@example.test","type":"work"},{"value":"two@example.test","type":"home"}]},{"op":"replace","path":"emails[type eq \"work\"].value","value":"new@example.test"},{"op":"remove","path":"emails[type eq \"home\"]"}`))
	if patched.ETag == replaced.ETag {
		t.Fatal("PATCH did not advance the version")
	}
	emails := object(t, patched.Body)["emails"].([]any)
	if len(emails) != 1 || emails[0].(map[string]any)["value"] != "new@example.test" {
		t.Fatalf("multi-value PATCH failed: %s", patched.Body)
	}
	f.deny(t, scim.Request{Operation: scim.UserPatch, ResourceID: id, IfMatch: patched.ETag, Body: []byte(patchBody(`{"op":"replace","path":"displayName","value":"must roll back"},{"op":"remove","path":"userName"}`))}, 400, "mutability")
	after := f.call(t, scim.UserGet, id, "", "")
	if string(after.Body) != string(patched.Body) || after.ETag != patched.ETag {
		t.Fatal("failed PATCH changed resource or version")
	}
	f.deny(t, scim.Request{Operation: scim.UserDelete, ResourceID: id}, 428, "")
	f.deny(t, scim.Request{Operation: scim.UserDelete, ResourceID: id, IfMatch: created.ETag}, 412, "")
	deleted := f.call(t, scim.UserDelete, id, patched.ETag, "")
	if deleted.Status != 204 || len(deleted.Body) != 0 {
		t.Fatalf("invalid delete result: %#v", deleted)
	}
	f.deny(t, scim.Request{Operation: scim.UserGet, ResourceID: id}, 404, "")
	// Headerless DELETE retry must replay before evaluating the tombstone.
	if retry := f.call(t, scim.UserDelete, id, patched.ETag, ""); retry.Status != 204 {
		t.Fatalf("DELETE replay failed: %#v", retry)
	}
	if retry := f.execute(t, scim.Request{Operation: scim.UserDelete, ResourceID: id, IfMatch: patched.ETag, IdempotencyKey: "new-delete-key"}); retry.Status != 204 {
		t.Fatalf("new optional key did not recover original DELETE: %#v", retry)
	}
	f.deny(t, scim.Request{Operation: scim.UserDelete, ResourceID: id, IfMatch: `"different"`}, 404, "")
	list := object(t, f.call(t, scim.UserList, "", "", "").Body)
	if list["totalResults"] != float64(0) || len(list["Resources"].([]any)) != 0 {
		t.Fatalf("deleted resource still listed: %#v", list)
	}
}

func TestUsersProfileListSearchAndProjection(t *testing.T) {
	f := newProtocolFixture(t)
	for _, name := range []string{"charlie", "Alice", "bob"} {
		f.call(t, scim.UserCreate, "", "", userBody(name, `,"externalId":"shared","active":true,"emails":[{"value":"`+name+`@example.test","type":"work","primary":true}]`))
	}
	// externalId is intentionally non-unique, but userName is not.
	f.deny(t, scim.Request{Operation: scim.UserCreate, Body: []byte(userBody("ALICE", ""))}, 409, "uniqueness")
	for _, tc := range []struct {
		name                 string
		query                scim.Query
		wantNames            []string
		wantStart, wantTotal int
	}{
		{"sorted", scim.Query{SortBy: "userName"}, []string{"Alice", "bob"}, 1, 3},
		{"descending", scim.Query{SortBy: "userName", SortOrder: "descending", StartIndex: 2}, []string{"bob", "Alice"}, 2, 3},
		{"negative-count", scim.Query{Count: intPtr(-1), StartIndex: -5}, nil, 1, 3},
		{"zero-count", scim.Query{Count: intPtr(0)}, nil, 1, 3},
		{"capped-count", scim.Query{Count: intPtr(9999), SortBy: "userName"}, []string{"Alice", "bob"}, 1, 3},
		{"past-end", scim.Query{StartIndex: 99}, nil, 99, 3},
		{"filter", scim.Query{Filter: `active eq true and (userName sw "a" or userName eq "BOB")`, SortBy: "userName"}, []string{"Alice", "bob"}, 1, 2},
		{"value-path", scim.Query{Filter: `emails[type eq "work" and value co "alice"]`}, []string{"Alice"}, 1, 1},
		{"qualified-path", scim.Query{Filter: userURN + `:userName eq "ALICE"`}, []string{"Alice"}, 1, 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := f.execute(t, scim.Request{Operation: scim.UserList, Query: tc.query})
			d := object(t, r.Body)
			assertSchemas(t, d, listURN)
			resources := d["Resources"].([]any)
			if d["totalResults"] != float64(tc.wantTotal) || d["startIndex"] != float64(tc.wantStart) || d["itemsPerPage"] != float64(len(tc.wantNames)) || len(resources) != len(tc.wantNames) {
				t.Fatalf("page metadata mismatch: %s", r.Body)
			}
			for i, name := range tc.wantNames {
				resource := resources[i].(map[string]any)
				if resource["userName"] != name || resource["meta"].(map[string]any)["version"] == "" {
					t.Fatalf("wrong ordered/versioned result: %s", r.Body)
				}
			}
		})
	}
	query := scim.Query{Filter: `userName eq "alice"`, Attributes: "userName,name.givenName"}
	get := f.execute(t, scim.Request{Operation: scim.UserList, Query: query})
	for _, op := range []scim.Operation{scim.UserSearch, scim.Search} {
		search := f.call(t, op, "", "", `{"schemas":["`+searchURN+`"],"filter":"userName eq \"alice\"","attributes":["userName","name.givenName"]}`)
		if string(search.Body) != string(get.Body) {
			t.Fatalf("POST search diverges from GET list: %s / %s", search.Body, get.Body)
		}
	}
	resource := object(t, get.Body)["Resources"].([]any)[0].(map[string]any)
	if resource["userName"] != "Alice" || resource["externalId"] != nil || resource["emails"] != nil || resource["id"] == nil || resource["schemas"] == nil {
		t.Fatalf("projection broke returned policy: %s", get.Body)
	}
	// Absent sort is stable server id ascending, not insertion order or userName.
	defaultPage := object(t, f.call(t, scim.UserList, "", "", "").Body)["Resources"].([]any)
	if defaultPage[0].(map[string]any)["id"].(string) >= defaultPage[1].(map[string]any)["id"].(string) {
		t.Fatalf("default ordering is not id ascending: %#v", defaultPage)
	}
}

func TestUsersProfileAdmissionAndSecretRedaction(t *testing.T) {
	f := newProtocolFixture(t)
	for _, body := range []string{
		userBody("x", `,"id":"client-owned"`),
		userBody("x", `,"meta":{"version":"client-owned"}`),
		userBody("x", `,"userName":"duplicate"`),
		userBody("x", `,"USERNAME":"collision"`),
		userBody("x", `,"name":{"givenName":"a","GivenName":"b"}`),
		userBody("x", `,"emails":[{"value":"a","VALUE":"b"}]`),
		`{"schemas":["` + userURN + `"],"displayName":"required username absent"}`,
		`{"schemas":["urn:unknown"],"userName":"x"}`,
	} {
		f.deny(t, scim.Request{Operation: scim.UserCreate, Body: []byte(body)}, 400, "")
	}
	const secret = "PASSWORD-MUST-NOT-ESCAPE"
	beforeMap, beforeStore := f.mapper.calls, f.store.prepares
	err := f.deny(t, scim.Request{Operation: scim.UserCreate, Body: []byte(userBody("secret-user", `,"password":"`+secret+`"`))}, 400, "mutability")
	if f.mapper.calls != beforeMap || f.store.prepares != beforeStore || strings.Contains(fmt.Sprintf("%#v %v", err, err), secret) {
		t.Fatal("password reached mapper/store or diagnostics")
	}
	for _, query := range []scim.Query{{Filter: `password pr`}, {Filter: `password eq "x"`}, {SortBy: "password"}, {Attributes: "password"}, {ExcludedAttributes: "password"}} {
		f.deny(t, scim.Request{Operation: scim.UserList, Query: query}, 400, "")
	}
	for _, filter := range []string{`userName eq`, `unknown eq "x"`, strings.Repeat("(", 17) + `userName pr` + strings.Repeat(")", 17), strings.Repeat("x", 8193)} {
		f.deny(t, scim.Request{Operation: scim.UserList, Query: scim.Query{Filter: filter}}, 400, "invalidFilter")
	}
	f.deny(t, scim.Request{Operation: scim.UserList, Query: scim.Query{SortBy: strings.Repeat("x", 1025)}}, 400, "")
	f.deny(t, scim.Request{Operation: scim.UserSearch, Body: []byte(`{"schemas":[],"filter":"userName pr"}`)}, 400, "")
	f.deny(t, scim.Request{Operation: scim.UserCreate, ContentEncoding: "gzip", Body: []byte(userBody("x", ""))}, 415, "")
	if len(f.store.resources) != 0 {
		t.Fatal("rejected admission mutated state")
	}
}

func TestUsersProfileAuthorityAndIsolation(t *testing.T) {
	f := newProtocolFixture(t)
	created := f.call(t, scim.UserCreate, "", "", userBody("scoped", ""))
	id := object(t, created.Body)["id"].(string)
	for _, token := range []string{"", "invalid", "expired", "unowned"} {
		r, err := f.service.Execute(context.Background(), scim.Request{Operation: scim.UserGet, Credential: authentication.NewBearerCredential(token), ResourceID: id})
		assertProtocolError(t, r, err, 401, "")
	}
	// A different verified connection cannot select this resource's scope.
	r, err := f.service.Execute(context.Background(), scim.Request{Operation: scim.UserGet, Credential: authentication.NewBearerCredential("fixture-other-connection"), ResourceID: id})
	assertProtocolError(t, r, err, 404, "")
	f.authorizer.err = errors.New("private policy backend diagnostic")
	f.deny(t, scim.Request{Operation: scim.UserDelete, ResourceID: id, IfMatch: created.ETag}, 403, "")
	f.authorizer.err = nil
	if f.call(t, scim.UserGet, id, "", "").ETag != created.ETag {
		t.Fatal("authorization failure changed the resource")
	}
	f.store.failure = errors.New("private database/provider diagnostic")
	f.deny(t, scim.Request{Operation: scim.UserGet, ResourceID: id}, 503, "")
	f.store.failure = nil
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	r, err = f.service.Execute(ctx, scim.Request{Operation: scim.UserGet, Credential: authentication.NewBearerCredential("fixture-connection"), ResourceID: id})
	if err == nil || len(r.Body) != 0 {
		t.Fatal("canceled operation returned a resource")
	}
}

func TestUsersProfileSnapshotBudgetAndAtomicVersion(t *testing.T) {
	f := newProtocolFixture(t)
	created := f.call(t, scim.UserCreate, "", "", userBody("before", ""))
	id := object(t, created.Body)["id"].(string)
	f.store.incomplete = true
	f.deny(t, scim.Request{Operation: scim.UserList}, 400, "tooMany")
	f.store.incomplete = false
	f.store.conflict = true
	f.deny(t, scim.Request{Operation: scim.UserPatch, ResourceID: id, IfMatch: created.ETag, Body: []byte(patchBody(`{"op":"replace","path":"userName","value":"after"}`))}, 412, "")
	f.store.conflict = false
	if f.call(t, scim.UserGet, id, "", "").ETag != created.ETag {
		t.Fatal("failed atomic commit changed the version")
	}
	f.store.unknown = true
	f.deny(t, scim.Request{Operation: scim.UserDelete, ResourceID: id, IfMatch: created.ETag}, 503, "")
	if f.store.lastOutcome != scim.WriteOutcomeUnknown {
		t.Fatal("store fixture did not exercise the unknown-outcome boundary")
	}
	// An unknown admission is not evidence of rollback or permission to retry.
	prepares := f.store.prepares
	f.store.unknown = false
	f.deny(t, scim.Request{Operation: scim.UserDelete, ResourceID: id, IfMatch: created.ETag}, 503, "")
	if f.store.prepares != prepares+1 || len(f.store.resources) != 1 {
		t.Fatal("unknown request was silently remapped or committed")
	}
}

func TestUsersProfileRequestReplay(t *testing.T) {
	f := newProtocolFixture(t)
	req := scim.Request{Operation: scim.UserCreate, IdempotencyKey: "client-key", Body: []byte(userBody("replayed", ""))}
	a := f.execute(t, req)
	b := f.execute(t, req)
	if string(a.Body) != string(b.Body) || a.ETag != b.ETag || len(f.store.resources) != 1 {
		t.Fatal("matching create retry did not recover its original semantic result")
	}
	req.Body = []byte(userBody("changed", ""))
	f.deny(t, req, 409, "")
	if len(f.store.resources) != 1 {
		t.Fatal("mismatched retry mutated state")
	}
}

func TestUsersProfileFilterOperatorsAndPrimarySort(t *testing.T) {
	f := newProtocolFixture(t)
	f.call(t, scim.UserCreate, "", "", userBody("Alice", `,"active":true,"emails":[{"value":"z@example.test","primary":false},{"value":"a@example.test","primary":true}]`))
	f.call(t, scim.UserCreate, "", "", userBody("Bob", `,"active":false,"emails":[{"value":"b@example.test","primary":true}]`))
	for _, tc := range []struct {
		filter string
		total  int
	}{
		{`userName eq "alice"`, 1},
		{`userName ne "ALICE"`, 1},
		{`userName co "li"`, 1},
		{`userName sw "AL"`, 1},
		{`userName ew "OB"`, 1},
		{`userName gt "Alice"`, 1},
		{`userName ge "Alice"`, 2},
		{`userName lt "Bob"`, 1},
		{`userName le "Bob"`, 2},
		{`userName pr`, 2},
		{`not (active eq true)`, 1},
		{`active eq true or active eq false and userName eq "nobody"`, 1},
		{`displayName eq null`, 2},
	} {
		t.Run(tc.filter, func(t *testing.T) {
			r := f.execute(t, scim.Request{Operation: scim.UserList, Query: scim.Query{Filter: tc.filter}})
			if object(t, r.Body)["totalResults"] != float64(tc.total) {
				t.Fatalf("schema comparison/operator mismatch: %s", r.Body)
			}
		})
	}
	r := f.execute(t, scim.Request{Operation: scim.UserList, Query: scim.Query{SortBy: "emails.value"}})
	resources := object(t, r.Body)["Resources"].([]any)
	if resources[0].(map[string]any)["userName"] != "Alice" {
		t.Fatalf("multi-value sort ignored primary value: %s", r.Body)
	}
	f.deny(t, scim.Request{Operation: scim.UserList, Query: scim.Query{Filter: `active gt true`}}, 400, "invalidFilter")
	f.deny(t, scim.Request{Operation: scim.UserList, Query: scim.Query{Filter: `active eq "true"`}}, 400, "invalidFilter")
}

func TestUsersProfilePatchAdmissionAndResourceLimits(t *testing.T) {
	f := newProtocolFixture(t)
	created := f.call(t, scim.UserCreate, "", "", userBody("bounded", `,"name":{"givenName":"Original","familyName":"Keep"}`))
	id := object(t, created.Body)["id"].(string)
	for _, operations := range []string{
		`{"op":"replace","path":"password","value":"PASSWORD-MUST-NOT-ESCAPE"}`,
		`{"op":"add","value":{"password":"PASSWORD-MUST-NOT-ESCAPE"}}`,
		`{"op":"replace","path":"id","value":"other"}`,
		`{"op":"remove","path":"meta"}`,
		`{"op":"remove","path":"name.missing"}`,
		`{"op":"remove","path":"emails[type eq \"missing\"]"}`,
		`{"op":"replace","OP":"add","path":"displayName","value":"collision"}`,
		strings.TrimSuffix(strings.Repeat(`{"op":"replace","path":"displayName","value":"x"},`, 101), ","),
	} {
		f.deny(t, scim.Request{Operation: scim.UserPatch, ResourceID: id, IfMatch: created.ETag, Body: []byte(patchBody(operations))}, 400, "")
		if f.call(t, scim.UserGet, id, "", "").ETag != created.ETag {
			t.Fatal("rejected PATCH advanced version")
		}
	}
	// Pathless add merges a complex attribute; it does not replace its siblings.
	r := f.call(t, scim.UserPatch, id, created.ETag, patchBody(`{"op":"add","value":{"name":{"givenName":"Changed"}}}`))
	name := object(t, r.Body)["name"].(map[string]any)
	if name["givenName"] != "Changed" || name["familyName"] != "Keep" {
		t.Fatalf("complex add discarded siblings: %s", r.Body)
	}
	// Explicit core schema-qualified paths use the same owning attribute.
	r = f.call(t, scim.UserPatch, id, r.ETag, patchBody(`{"op":"replace","path":"`+userURN+`:name.familyName","value":"Qualified"}`))
	if object(t, r.Body)["name"].(map[string]any)["familyName"] != "Qualified" {
		t.Fatalf("qualified PATCH path did not resolve: %s", r.Body)
	}
	f.deny(t, scim.Request{Operation: scim.UserCreate, Body: []byte(userBody("oversized", `,"displayName":"`+strings.Repeat("x", 65537)+`"`))}, 400, "")
	f.deny(t, scim.Request{Operation: scim.UserCreate, Body: []byte(userBody("nested", `,"name":`+strings.Repeat(`{"x":`, 17)+`"leaf"`+strings.Repeat("}", 17)))}, 400, "")
}

func userBody(name, suffix string) string {
	return `{"schemas":["` + userURN + `"],"userName":"` + name + `"` + suffix + `}`
}

func patchBody(operations string) string {
	return `{"schemas":["` + patchURN + `"],"Operations":[` + operations + `]}`
}

func intPtr(n int) *int { return &n }

func object(t *testing.T, body []byte) map[string]any {
	t.Helper()
	var out map[string]any
	if err := json.Unmarshal(body, &out); err != nil || out == nil {
		t.Fatalf("invalid object response: %q (%v)", body, err)
	}
	return out
}

func assertSchemas(t *testing.T, d map[string]any, urn string) {
	t.Helper()
	schemas, ok := d["schemas"].([]any)
	if !ok || len(schemas) != 1 || schemas[0] != urn {
		t.Fatalf("wrong schema envelope: %#v", d["schemas"])
	}
}

func assertProtocolError(t *testing.T, response scim.Response, err error, status int, scimType string) *scim.Error {
	t.Helper()
	var protocol *scim.Error
	if !errors.As(err, &protocol) || protocol.StatusCode() != status || len(response.Body) != 0 {
		t.Fatalf("want typed redacted status %d, got status=%d / %v", status, response.Status, err)
	}
	wire, marshalErr := json.Marshal(protocol)
	if marshalErr != nil {
		t.Fatalf("marshal protocol error: %v", marshalErr)
	}
	d := object(t, wire)
	assertSchemas(t, d, errorURN)
	if d["status"] != fmt.Sprint(status) || len(d["detail"].(string)) > 512 || strings.Contains(string(wire), "private") || strings.Contains(fmt.Sprintf("%#v", protocol), "private") {
		t.Fatalf("invalid or unredacted RFC error: %s", wire)
	}
	if scimType != "" && d["scimType"] != scimType {
		t.Fatalf("want scimType %s: %s", scimType, wire)
	}
	return protocol
}

var fixtureNow = time.Date(2026, 11, 2, 9, 0, 0, 0, time.UTC)
