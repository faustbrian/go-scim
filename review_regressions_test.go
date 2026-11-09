package scim_test

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	scim "github.com/faustbrian/go-scim"
)

func reviewAttribute(name, kind string) scim.Attribute {
	return scim.Attribute{Name: name, Type: kind, Mutability: "readWrite", Returned: "default", Uniqueness: "none"}
}

func reviewSchema(attributes ...scim.Attribute) func(*scim.Config) {
	return func(c *scim.Config) {
		c.Extensions = []scim.Schema{{ID: extensionURN, Name: "ReviewProfile", Attributes: attributes}}
	}
}

func reviewUser(name, extension string) string {
	return `{"schemas":["` + userURN + `","` + extensionURN + `"],"userName":"` + name + `","` + extensionURN + `":` + extension + `}`
}

func TestReviewF1ComplexReplacePreservesSiblings(t *testing.T) {
	for _, operations := range []string{
		`{"op":"replace","path":"name","value":{"givenName":"Updated"}}`,
		`{"op":"replace","value":{"name":{"givenName":"Updated"}}}`,
	} {
		f := newProtocolFixture(t)
		created := f.call(t, scim.UserCreate, "", "", userBody("complex-replace", `,"name":{"givenName":"Alice","familyName":"Keep"}`))
		id := object(t, created.Body)["id"].(string)
		updated := f.call(t, scim.UserPatch, id, created.ETag, patchBody(operations))
		name := object(t, updated.Body)["name"].(map[string]any)
		if name["givenName"] != "Updated" || name["familyName"] != "Keep" {
			t.Fatalf("complex replacement lost unspecified sibling: %s", updated.Body)
		}
	}
	// A selected multi-value record replacement is intentionally a different
	// RFC target from singular complex-subattribute replacement.
	f := newProtocolFixture(t)
	created := f.call(t, scim.UserCreate, "", "", userBody("record-replace", `,"emails":[{"value":"old@example.test","type":"work","display":"remove"}]`))
	id := object(t, created.Body)["id"].(string)
	updated := f.call(t, scim.UserPatch, id, created.ETag, patchBody(`{"op":"replace","path":"emails[type eq \"work\"]","value":{"value":"new@example.test","type":"work"}}`))
	if object(t, updated.Body)["emails"].([]any)[0].(map[string]any)["display"] != nil {
		t.Fatal("whole selected record was incorrectly merged")
	}
}

func TestReviewF2ImmutableDescendantCannotDisappear(t *testing.T) {
	code := reviewAttribute("code", "string")
	code.Mutability = "immutable"
	code.CaseExact = true
	parent := reviewAttribute("parent", "complex")
	parent.SubAttributes = []scim.Attribute{code, reviewAttribute("note", "string")}
	for _, kind := range []string{"put-omit-parent", "put-null-parent", "put-omit-extension", "patch-remove-parent", "patch-null-parent"} {
		t.Run(kind, func(t *testing.T) {
			f := configuredProtocolFixture(t, reviewSchema(parent))
			created := f.call(t, scim.UserCreate, "", "", reviewUser("immutable-child", `{"parent":{"code":"original","note":"keep"}}`))
			id := object(t, created.Body)["id"].(string)
			req := scim.Request{Operation: scim.UserReplace, ResourceID: id, IfMatch: created.ETag}
			switch kind {
			case "put-omit-parent":
				req.Body = []byte(reviewUser("immutable-child", `{}`))
			case "put-null-parent":
				req.Body = []byte(reviewUser("immutable-child", `{"parent":null}`))
			case "put-omit-extension":
				req.Body = []byte(userBody("immutable-child", ""))
			case "patch-remove-parent":
				req.Operation = scim.UserPatch
				req.Body = []byte(patchBody(`{"op":"remove","path":"` + extensionURN + `:parent"}`))
			case "patch-null-parent":
				req.Operation = scim.UserPatch
				req.Body = []byte(patchBody(`{"op":"replace","path":"` + extensionURN + `:parent","value":null}`))
			}
			calls := f.mapper.calls
			f.deny(t, req, 400, "mutability")
			if f.mapper.calls != calls || f.call(t, scim.UserGet, id, "", "").ETag != created.ETag {
				t.Fatal("immutable descendant removal crossed mapping or changed state")
			}
		})
	}
}

func TestReviewF4PatchExpansionRejectedBeforeMapper(t *testing.T) {
	tags := reviewAttribute("tags", "string")
	tags.MultiValued = true
	items := reviewAttribute("items", "complex")
	items.MultiValued = true
	items.SubAttributes = []scim.Attribute{reviewAttribute("label", "string"), tags}
	f := configuredProtocolFixture(t, func(c *scim.Config) {
		reviewSchema(items)(c)
		c.Limits.BodyBytes = 2048
	})
	created := f.call(t, scim.UserCreate, "", "", reviewUser("bounded-expansion", `{"items":[{"label":"a"},{"label":"b"},{"label":"c"},{"label":"d"}]}`))
	id := object(t, created.Body)["id"].(string)
	values := []string{}
	for i := 0; i < 16; i++ {
		values = append(values, fmt.Sprintf("%02d-%s", i, strings.Repeat("x", 37)))
	}
	encoded, err := json.Marshal(values)
	if err != nil {
		t.Fatal(err)
	}
	request := freshnessRequest(scim.UserPatch, id, created.ETag)
	request.Body = []byte(patchBody(`{"op":"add","path":"` + extensionURN + `:items.tags","value":` + string(encoded) + `}`))
	if len(request.Body) >= 2048 {
		t.Fatal("test ingress exceeds its small deterministic budget")
	}
	calls := f.mapper.calls
	response, err := f.service.Execute(context.Background(), request)
	var protocol *scim.Error
	if !errors.As(err, &protocol) || protocol.StatusCode() != 400 || f.mapper.calls != calls || len(response.Body) != 0 {
		t.Fatalf("expanded candidate crossed admission: error=%v mapper_delta=%d", err, f.mapper.calls-calls)
	}
	if f.call(t, scim.UserGet, id, "", "").ETag != created.ETag {
		t.Fatal("rejected expansion changed the stored resource")
	}
}

func TestReviewF3EscapedOutputBudgetBeforeMapper(t *testing.T) {
	f := configuredProtocolFixture(t, func(c *scim.Config) {
		c.Limits.ResponseBytes = 8192
	})
	request := freshnessRequest(scim.UserCreate, "", "")
	request.ContentType = "application/scim+json"
	request.Body = []byte(userBody("escaped-budget", `,"displayName":"`+strings.Repeat("<", 2000)+`"`))
	if len(request.Body) >= 8192 {
		t.Fatal("test payload must stay below its small configured output budget")
	}
	calls := f.mapper.calls
	response, err := f.service.Execute(context.Background(), request)
	var protocol *scim.Error
	if !errors.As(err, &protocol) || protocol.StatusCode() != 400 || f.mapper.calls != calls || len(response.Body) != 0 || len(f.store.resources) != 0 {
		t.Fatalf("escaped output crossed pre-materialization admission: error=%v mapper_delta=%d", err, f.mapper.calls-calls)
	}
}

type reviewBudgetStore struct {
	scim.Store
	rows          []scim.Resource
	materialized  int
	missingBudget bool
}

func (s *reviewBudgetStore) Snapshot(ctx context.Context, scope scim.Scope, budget scim.SnapshotBudget) (scim.Snapshot, error) {
	if err := boundedFixtureContext(ctx); err != nil {
		return scim.Snapshot{}, err
	}
	if budget.Bytes <= 0 || budget.Resources <= 0 {
		s.missingBudget = true
		return scim.Snapshot{Complete: false}, nil
	}
	result := scim.Snapshot{Complete: true}
	remaining := budget.Bytes
	for _, row := range s.rows {
		// These test rows are each small, already-owned fixture values. This is
		// not proof of a native adapter's allocation or SQL behavior.
		encoded, err := json.Marshal(row)
		if err != nil {
			return scim.Snapshot{}, err
		}
		if len(encoded) > remaining || len(result.Resources) >= budget.Resources {
			result.Complete = false
			break
		}
		remaining -= len(encoded)
		s.materialized++
		result.Resources = append(result.Resources, cloneFixtureResource(row))
	}
	return result, nil
}

func TestReviewF3SnapshotBudgetBeforeMaterialization(t *testing.T) {
	var bounded *reviewBudgetStore
	f := configuredProtocolFixture(t, func(c *scim.Config) {
		bounded = &reviewBudgetStore{Store: c.Store}
		c.Store = bounded
		c.Limits.SnapshotBytes = 1800
	})
	for i := 0; i < 6; i++ {
		f.call(t, scim.UserCreate, "", "", userBody(fmt.Sprintf("snapshot-%d", i), `,"displayName":"`+strings.Repeat("x", 300)+`"`))
	}
	for _, row := range f.store.resources {
		bounded.rows = append(bounded.rows, row)
	}
	response, err := f.service.Execute(context.Background(), freshnessRequest(scim.UserList, "", ""))
	if bounded.missingBudget {
		t.Fatal("Snapshot received no aggregate byte budget before materialization")
	}
	assertProtocolError(t, response, err, 400, "tooMany")
	if bounded.materialized >= len(bounded.rows) {
		t.Fatal("aggregate overflow was discovered only after full materialization")
	}
}

func TestReviewF5ExpiredErrorsDoNotDiscloseState(t *testing.T) {
	for _, kind := range []string{"present", "absent", "snapshot-error"} {
		t.Run(kind, func(t *testing.T) {
			f, h := newFreshnessFixture(t)
			created := f.call(t, scim.UserCreate, "", "", userBody("expired-error", ""))
			id := object(t, created.Body)["id"].(string)
			request := freshnessRequest(scim.UserGet, id, "")
			h.advanceAt, h.advanceTo = "get", h.effectiveExpiry()
			if kind == "absent" {
				request.ResourceID = "absent"
			}
			if kind == "snapshot-error" {
				request = freshnessRequest(scim.UserList, "", "")
				h.advanceAt = "snapshot"
				f.store.failure = scim.ErrNotFound
			}
			response, err := f.service.Execute(context.Background(), request)
			assertProtocolError(t, response, err, 503, "")
		})
	}
}

func TestReviewF6PrimarySelectorUsesOriginalValues(t *testing.T) {
	f := newProtocolFixture(t)
	created := f.call(t, scim.UserCreate, "", "", userBody("primary-selector", `,"emails":[{"value":"a@example.test","primary":true},{"value":"b@example.test","primary":false}]`))
	id := object(t, created.Body)["id"].(string)
	updated := f.call(t, scim.UserPatch, id, created.ETag, patchBody(`{"op":"replace","path":"emails[primary eq false].primary","value":true}`))
	emails := object(t, updated.Body)["emails"].([]any)
	if emails[0].(map[string]any)["primary"] != false || emails[1].(map[string]any)["primary"] != true {
		t.Fatalf("selector changed during primary reset: %s", updated.Body)
	}
}

func TestReviewF7SchemaScalarEquality(t *testing.T) {
	for _, kind := range []string{"decimal", "dateTime"} {
		t.Run(kind+"-duplicate", func(t *testing.T) {
			values := reviewAttribute("values", kind)
			values.MultiValued = true
			f := configuredProtocolFixture(t, reviewSchema(values))
			body := `{"values":[1.0,1.00]}`
			if kind == "dateTime" {
				body = `{"values":["2020-01-01T00:00:00Z","2019-12-31T23:00:00-01:00"]}`
			}
			calls := f.mapper.calls
			f.deny(t, scim.Request{Operation: scim.UserCreate, Body: []byte(reviewUser("duplicate-scalar", body))}, 400, "invalidValue")
			if f.mapper.calls != calls {
				t.Fatal("schema-equivalent duplicates reached Mapper")
			}
		})
		t.Run(kind+"-immutable", func(t *testing.T) {
			value := reviewAttribute("value", kind)
			value.Mutability = "immutable"
			f := configuredProtocolFixture(t, reviewSchema(value))
			first, second := `{"value":1.0}`, `{"value":1.00}`
			if kind == "dateTime" {
				first, second = `{"value":"2020-01-01T00:00:00Z"}`, `{"value":"2019-12-31T23:00:00-01:00"}`
			}
			created := f.call(t, scim.UserCreate, "", "", reviewUser("equivalent-scalar", first))
			id := object(t, created.Body)["id"].(string)
			f.call(t, scim.UserReplace, id, created.ETag, reviewUser("equivalent-scalar", second))
		})
	}
}

func TestReviewF8BinaryAndReferenceAdmission(t *testing.T) {
	for _, tc := range []struct{ kind, invalid, valid string }{
		{"binary", "%%%", "YQ=="},
		{"reference", "http://[", "../Users/canonical-id"},
	} {
		t.Run(tc.kind, func(t *testing.T) {
			value := reviewAttribute("value", tc.kind)
			value.CaseExact = true
			f := configuredProtocolFixture(t, reviewSchema(value))
			calls := f.mapper.calls
			f.deny(t, scim.Request{Operation: scim.UserCreate, Body: []byte(reviewUser("invalid-type", `{"value":"`+tc.invalid+`"}`))}, 400, "invalidValue")
			if f.mapper.calls != calls || len(f.store.resources) != 0 {
				t.Fatal("invalid representation crossed Mapper or persisted")
			}
			created := f.call(t, scim.UserCreate, "", "", reviewUser("valid-type", `{"value":"`+tc.valid+`"}`))
			if object(t, created.Body)[extensionURN].(map[string]any)["value"] != tc.valid {
				t.Fatal("supported valid type was narrowed or rewritten")
			}
		})
	}
}

func TestReviewF9StoredAliasesRespectReturnedAndFilter(t *testing.T) {
	origin := reviewAttribute("origin", "string")
	origin.Mutability, origin.Returned = "readOnly", "request"
	f := configuredProtocolFixture(t, reviewSchema(origin))
	created := f.call(t, scim.UserCreate, "", "", reviewUser("stored-alias", `{}`))
	id := object(t, created.Body)["id"].(string)
	for key, resource := range f.store.resources {
		resource.Attributes[extensionURN] = map[string]any{"Origin": "native-source"}
		f.store.resources[key] = resource
	}
	read := f.call(t, scim.UserGet, id, "", "")
	if extension, ok := object(t, read.Body)[extensionURN].(map[string]any); ok && len(extension) != 0 {
		t.Fatalf("stored alias bypassed returned=request: %s", read.Body)
	}
	list := f.execute(t, scim.Request{Operation: scim.UserList, Query: scim.Query{Filter: extensionURN + `:origin eq "native-source"`, Attributes: extensionURN + ":origin"}})
	doc := object(t, list.Body)
	if doc["totalResults"] != float64(1) || doc["Resources"].([]any)[0].(map[string]any)[extensionURN].(map[string]any)["origin"] != "native-source" {
		t.Fatalf("canonical filter/projection lost stored data: %s", list.Body)
	}
}

func TestReviewF10NoOpAddRetainsModificationTime(t *testing.T) {
	for _, kind := range []string{"scalar", "multi-value"} {
		t.Run(kind, func(t *testing.T) {
			now := fixtureNow
			f := configuredProtocolFixture(t, func(c *scim.Config) { c.Now = func() time.Time { return now } })
			created := f.call(t, scim.UserCreate, "", "", userBody("noop-add", `,"displayName":"same","emails":[{"value":"same@example.test"}]`))
			id := object(t, created.Body)["id"].(string)
			now = now.Add(time.Second)
			operation := `{"op":"add","path":"displayName","value":"same"}`
			if kind == "multi-value" {
				operation = `{"op":"add","path":"emails","value":[{"value":"same@example.test"}]}`
			}
			request := freshnessRequest(scim.UserPatch, id, created.ETag)
			request.IdempotencyKey = "noop-success"
			request.Body = []byte(patchBody(operation))
			updated := f.execute(t, request)
			if object(t, updated.Body)["meta"].(map[string]any)["lastModified"] != object(t, created.Body)["meta"].(map[string]any)["lastModified"] {
				t.Fatal("no-op add changed modification time")
			}
			if updated.ETag != created.ETag {
				t.Fatal("no-op add changed the unchanged resource version")
			}
			if replay := f.execute(t, request); string(replay.Body) != string(updated.Body) {
				t.Fatal("no-op success was not replayable")
			}
		})
	}
}

func TestReviewF10ExistingMemberDoesNotConsumeGrowthBudget(t *testing.T) {
	tags := reviewAttribute("tags", "string")
	tags.MultiValued = true
	f := configuredProtocolFixture(t, func(c *scim.Config) { reviewSchema(tags)(c); c.Limits.ResourceAttributes = 256 })
	values := make([]string, 256)
	for i := range values {
		values[i] = fmt.Sprintf("tag-%d", i)
	}
	encoded, err := json.Marshal(values)
	if err != nil {
		t.Fatal(err)
	}
	created := f.call(t, scim.UserCreate, "", "", reviewUser("full-noop", `{"tags":`+string(encoded)+`}`))
	id := object(t, created.Body)["id"].(string)
	updated := f.call(t, scim.UserPatch, id, created.ETag, patchBody(`{"op":"add","path":"`+extensionURN+`:tags","value":["tag-0"]}`))
	if updated.ETag != created.ETag {
		t.Fatal("existing member changed a full set")
	}
}

func TestReviewF11PathlessAliasCollisionRejected(t *testing.T) {
	for _, values := range []string{
		`{"displayName":"a","` + userURN + `:displayName":"b"}`,
		`{"name":{"givenName":"a"},"name.givenName":"b"}`,
	} {
		f := newProtocolFixture(t)
		created := f.call(t, scim.UserCreate, "", "", userBody("pathless-collision", ""))
		id := object(t, created.Body)["id"].(string)
		calls, prepares := f.mapper.calls, f.store.prepares
		f.deny(t, scim.Request{Operation: scim.UserPatch, ResourceID: id, IfMatch: created.ETag, Body: []byte(patchBody(`{"op":"replace","value":` + values + `}`))}, 400, "")
		if f.mapper.calls != calls || f.store.prepares != prepares || f.call(t, scim.UserGet, id, "", "").ETag != created.ETag {
			t.Fatal("pathless ambiguity crossed admission or changed state")
		}
	}
}

func FuzzReviewPatchBudgets(f *testing.F) {
	for _, operations := range []string{
		`{"op":"add","path":"displayName","value":"same"}`,
		`{"op":"replace","path":"name","value":{"givenName":"updated"}}`,
		`{"op":"replace","path":"emails[primary eq false].primary","value":true}`,
		`{"op":"add","path":"` + extensionURN + `:items.tags","value":["one","two"]}`,
		`{"op":"replace","value":{"displayName":"a","` + userURN + `:displayName":"b"}}`,
	} {
		f.Add(patchBody(operations))
	}
	f.Fuzz(func(t *testing.T, body string) {
		if len(body) > 2048 {
			return
		}
		tags := reviewAttribute("tags", "string")
		tags.MultiValued = true
		items := reviewAttribute("items", "complex")
		items.MultiValued = true
		items.SubAttributes = []scim.Attribute{reviewAttribute("label", "string"), tags}
		fixture := configuredProtocolFixture(t, func(c *scim.Config) {
			reviewSchema(items)(c)
			c.Limits.BodyBytes = 2048
			c.Limits.ResponseBytes = 8192
		})
		created := fixture.call(t, scim.UserCreate, "", "", `{"schemas":["`+userURN+`","`+extensionURN+`"],"userName":"patch-fuzz","displayName":"same","name":{"givenName":"before","familyName":"keep"},"emails":[{"value":"a@example.test","primary":true},{"value":"b@example.test","primary":false}],"`+extensionURN+`":{"items":[{"label":"a"},{"label":"b"},{"label":"c"},{"label":"d"}]}}`)
		id := object(t, created.Body)["id"].(string)
		request := freshnessRequest(scim.UserPatch, id, created.ETag)
		request.Body = []byte(body)
		response, err := fixture.service.Execute(context.Background(), request)
		if err != nil {
			var protocol *scim.Error
			if !errors.As(err, &protocol) || protocol.StatusCode() >= 500 || len(response.Body) != 0 {
				t.Fatalf("unexpected bounded PATCH failure: %v", err)
			}
			for _, resource := range fixture.store.resources {
				if resource.Version != created.ETag {
					t.Fatal("rejected PATCH changed state")
				}
			}
			return
		}
		if response.Status != 200 || response.ETag == "" || !json.Valid(response.Body) || len(response.Body) > 8192 {
			t.Fatal("invalid successful bounded PATCH response")
		}
	})
}
