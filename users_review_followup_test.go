package scim_test

import (
	"context"
	"encoding/json"
	"errors"
	"slices"
	"sort"
	"strings"
	"testing"

	scim "github.com/faustbrian/go-scim"
)

func followupQueryRequest(t *testing.T, operation scim.Operation, filter string) scim.Request {
	t.Helper()
	request := scim.Request{Operation: operation, Query: scim.Query{Filter: filter}}
	if operation != scim.UserList {
		body, err := json.Marshal(map[string]any{"schemas": []string{searchURN}, "filter": filter})
		if err != nil {
			t.Fatal(err)
		}
		request.Body = body
	}
	return request
}

func TestUsersReviewF1UsernamePRECISComparison(t *testing.T) {
	// RFC 8265 3.3 and 3.6 require width mapping, lowercase mapping and NFC;
	// full case folding would incorrectly merge sharp-s or final-sigma names.
	for _, names := range []struct {
		name, stored, operand string
		matches               bool
	}{
		{"canonical-composition", "José", "Jose\u0301", true},
		{"canonical-decomposition", "Jose\u0301", "JOSÉ", true},
		{"width-case-and-composition", "ＪＯＳＥ\u0301", "josé", true},
		{"lowercase-with-sharp-s", "Straße", "straße", true},
		{"sharp-s-is-not-ss", "straße", "strasse", false},
		{"capital-sigma", "Σ", "σ", true},
		{"final-sigma-is-distinct", "ς", "σ", false},
		{"valid-rtl", "אבג", "אבג", true},
		{"valid-contextual-middle-dot", "l·l", "l·l", true},
	} {
		for _, operation := range []scim.Operation{scim.UserList, scim.UserSearch, scim.Search} {
			t.Run(names.name+"/"+string(operation), func(t *testing.T) {
				fixture := newProtocolFixture(t)
				created := fixture.call(t, scim.UserCreate, "", "", userBody(names.stored, ""))
				id := object(t, created.Body)["id"].(string)
				if object(t, created.Body)["userName"] != names.stored {
					t.Fatal("username preparation rewrote the supplied representation")
				}
				operand, err := json.Marshal(names.operand)
				if err != nil {
					t.Fatal(err)
				}
				response := fixture.execute(t, followupQueryRequest(t, operation, "userName eq "+string(operand)))
				doc := object(t, response.Body)
				resources := doc["Resources"].([]any)
				want := 0
				if names.matches {
					want = 1
				}
				if doc["totalResults"] != float64(want) || len(resources) != want {
					t.Fatalf("PRECIS comparison returned total=%v resources=%d, want %d", doc["totalResults"], len(resources), want)
				}
				if want == 1 {
					resource := resources[0].(map[string]any)
					if resource["id"] != id || resource["userName"] != names.stored {
						t.Fatal("comparison changed the stored source username or stable resource ID")
					}
				}
				read := fixture.call(t, scim.UserGet, id, "", "")
				if read.ETag != created.ETag || string(read.Body) != string(created.Body) {
					t.Fatal("Unicode comparison mutated the resource")
				}
			})
		}
	}
}

func TestUsersReviewF1UsernameSubstringFragments(t *testing.T) {
	// RFC 7644 Table 3 defines these as substring predicates. The JSON
	// comparison literal is a fragment, not a request to register that username.
	for _, predicate := range []struct {
		label, username, operator, fragment string
		matches                             bool
	}{
		{"contains-contextual-fragment", "l·l", "co", "·", true},
		{"prefix-contextual-fragment", "l·l", "sw", "l·", true},
		{"suffix-contextual-fragment", "l·l", "ew", "·l", true},
		{"missing-contextual-fragment", "l·l", "co", "·m", false},
		{"fragment-not-at-start", "l·l", "sw", "·l", false},
		{"fragment-not-at-end", "l·l", "ew", "l·", false},
		{"empty-contains", "l·l", "co", "", true},
		{"empty-prefix", "l·l", "sw", "", true},
		{"empty-suffix", "l·l", "ew", "", true},
		{"width-case-nfc-contains", "ＪＯＳＥ\u0301", "co", "e\u0301", true},
		{"width-case-prefix", "ＪＯＳＥ\u0301", "sw", "ｊｏ", true},
		{"width-case-nfc-suffix", "ＪＯＳＥ\u0301", "ew", "ＳＥ\u0301", true},
		{"prepared-fragment-absent", "ＪＯＳＥ\u0301", "co", "Ａ\u0301", false},
		{"sharp-s-fragment", "straße", "co", "ß", true},
		{"fragment-does-not-full-fold-sharp-s", "straße", "co", "ss", false},
		{"fragment-does-not-full-fold-final-sigma", "ς", "co", "σ", false},
		{"fragment-lowercases-capital-sigma", "σ", "co", "Σ", true},
	} {
		for _, operation := range []scim.Operation{scim.UserList, scim.UserSearch, scim.Search} {
			t.Run(predicate.label+"/"+string(operation), func(t *testing.T) {
				fixture := newProtocolFixture(t)
				created := fixture.call(t, scim.UserCreate, "", "", userBody(predicate.username, ""))
				original := object(t, created.Body)
				id := original["id"].(string)
				if original["userName"] != predicate.username {
					t.Fatal("username admission rewrote the source spelling")
				}
				literal, err := json.Marshal(predicate.fragment)
				if err != nil {
					t.Fatal(err)
				}
				filter := "userName " + predicate.operator + " " + string(literal)
				response := fixture.execute(t, followupQueryRequest(t, operation, filter))
				doc := object(t, response.Body)
				resources := doc["Resources"].([]any)
				want := 0
				if predicate.matches {
					want = 1
				}
				if doc["totalResults"] != float64(want) || len(resources) != want {
					t.Fatalf("fragment predicate returned total=%v resources=%d, want %d", doc["totalResults"], len(resources), want)
				}
				if want == 1 {
					resource := resources[0].(map[string]any)
					if resource["id"] != id || resource["userName"] != predicate.username {
						t.Fatal("fragment matching changed the source username or stable resource ID")
					}
				}
				read := fixture.call(t, scim.UserGet, id, "", "")
				if read.ETag != created.ETag || string(read.Body) != string(created.Body) {
					t.Fatal("fragment predicate changed the stored resource bytes or version")
				}
			})
		}
	}
}

func TestUsersReviewF1FragmentsDoNotRelaxUsernameAdmissionOrUniqueness(t *testing.T) {
	fixture := newProtocolFixture(t)
	created := fixture.call(t, scim.UserCreate, "", "", userBody("l·l", ""))
	id := object(t, created.Body)["id"].(string)
	for _, fragment := range []struct{ label, value string }{
		{"middle-dot", "·"},
		{"prefix", "l·"},
		{"suffix", "·l"},
		{"empty", ""},
	} {
		t.Run(fragment.label, func(t *testing.T) {
			key, err := scim.UsernameComparisonKey(fragment.value)
			assertProtocolError(t, scim.Response{}, err, 400, "invalidValue")
			if key != "" {
				t.Fatal("standalone-invalid fragment became a usable uniqueness key")
			}
			calls, prepares := fixture.mapper.calls, fixture.store.prepares
			fixture.deny(t, scim.Request{Operation: scim.UserCreate, Body: []byte(userBody(fragment.value, ""))}, 400, "invalidValue")
			if fixture.mapper.calls != calls || fixture.store.prepares != prepares {
				t.Fatal("fragment rules relaxed actual username admission")
			}
		})
	}
	fixture.deny(t, scim.Request{Operation: scim.UserCreate, Body: []byte(userBody("Ｌ·Ｌ", ""))}, 409, "uniqueness")
	if read := fixture.call(t, scim.UserGet, id, "", ""); read.ETag != created.ETag || string(read.Body) != string(created.Body) || len(fixture.store.resources) != 1 {
		t.Fatal("fragment admission or uniqueness checks changed the original resource")
	}
}

func TestUsersReviewF1FragmentCaseExactControls(t *testing.T) {
	value := reviewAttribute("value", "string")
	value.CaseExact = true
	for _, operation := range []scim.Operation{scim.UserList, scim.UserSearch, scim.Search} {
		t.Run(string(operation), func(t *testing.T) {
			fixture := configuredProtocolFixture(t, reviewSchema(value))
			created := fixture.call(t, scim.UserCreate, "", "", reviewUser("fragment-controls", `{"value":"L·L"}`))
			id := object(t, created.Body)["id"].(string)
			for _, predicate := range []struct {
				filter string
				count  float64
			}{
				{extensionURN + `:value co "·"`, 1},
				{extensionURN + `:value sw "L·"`, 1},
				{extensionURN + `:value sw "l·"`, 0},
				{extensionURN + `:value ew "·L"`, 1},
				{extensionURN + `:value ew "·l"`, 0},
				{extensionURN + `:value co ""`, 1},
				{extensionURN + `:value sw ""`, 1},
				{extensionURN + `:value ew ""`, 1},
			} {
				response := fixture.execute(t, followupQueryRequest(t, operation, predicate.filter))
				doc := object(t, response.Body)
				if doc["totalResults"] != predicate.count || len(doc["Resources"].([]any)) != int(predicate.count) {
					t.Errorf("fragment changed caseExact semantics: %s", predicate.filter)
				}
			}
			if read := fixture.call(t, scim.UserGet, id, "", ""); read.ETag != created.ETag || string(read.Body) != string(created.Body) {
				t.Fatal("fragment controls changed the stored representation")
			}
		})
	}
}

func TestUsersReviewF1EmptyFragmentDistinguishesEmptyAndAbsentAttributes(t *testing.T) {
	for _, state := range []struct {
		label, suffix string
		count         float64
	}{
		{"absent", "", 0},
		{"null", `,"displayName":null`, 0},
		{"empty-string", `,"displayName":""`, 1},
	} {
		for _, operation := range []scim.Operation{scim.UserList, scim.UserSearch, scim.Search} {
			t.Run(state.label+"/"+string(operation), func(t *testing.T) {
				fixture := newProtocolFixture(t)
				created := fixture.call(t, scim.UserCreate, "", "", userBody("empty-fragment-control", state.suffix))
				id := object(t, created.Body)["id"].(string)
				for _, operator := range []string{"co", "sw", "ew"} {
					filter := "displayName " + operator + ` ""`
					response := fixture.execute(t, followupQueryRequest(t, operation, filter))
					doc := object(t, response.Body)
					if doc["totalResults"] != state.count || len(doc["Resources"].([]any)) != int(state.count) {
						t.Errorf("empty-fragment predicate confused empty with unassigned: %s", filter)
					}
				}
				if read := fixture.call(t, scim.UserGet, id, "", ""); read.ETag != created.ETag || string(read.Body) != string(created.Body) {
					t.Fatal("empty-fragment predicate mutated the resource")
				}
			})
		}
	}
}

func TestUsersReviewF1NullSubstringOperandIsNotEmptyFragment(t *testing.T) {
	for _, operation := range []scim.Operation{scim.UserList, scim.UserSearch, scim.Search} {
		for _, operator := range []string{"co", "sw", "ew"} {
			t.Run(string(operation)+"/"+operator, func(t *testing.T) {
				fixture := newProtocolFixture(t)
				created := fixture.call(t, scim.UserCreate, "", "", userBody("l·l", ""))
				id := object(t, created.Body)["id"].(string)
				fixture.deny(t, followupQueryRequest(t, operation, "userName "+operator+" null"), 400, "invalidFilter")
				if read := fixture.call(t, scim.UserGet, id, "", ""); read.ETag != created.ETag || string(read.Body) != string(created.Body) {
					t.Fatal("null substring operand mutated the resource")
				}
			})
		}
	}
}

func TestUsersReviewF1UsernamePRECISRejectsInvalidProfiles(t *testing.T) {
	for _, name := range []struct{ label, value string }{
		{"compatibility-numeral-not-width", "userⅣ"},
		{"identifier-space", "alice bob"},
		{"invalid-joiner-context", "ab\u200dcd"},
		{"invalid-middle-dot-context", "a·b"},
		{"mixed-directionality", "aא"},
	} {
		t.Run(name.label, func(t *testing.T) {
			fixture := newProtocolFixture(t)
			calls, prepares := fixture.mapper.calls, fixture.store.prepares
			fixture.deny(t, scim.Request{Operation: scim.UserCreate, Body: []byte(userBody(name.value, ""))}, 400, "invalidValue")
			if fixture.mapper.calls != calls || fixture.store.prepares != prepares || len(fixture.store.resources) != 0 {
				t.Fatal("invalid username profile reached representation mapping or store admission")
			}
		})
	}
}

func TestUsersReviewF1StoreUniquenessUsesPreparedUsernameKey(t *testing.T) {
	for _, names := range []struct {
		label, first, second string
		collision            bool
	}{
		{"canonical", "José", "Jose\u0301", true},
		{"width-and-case", "Ａlice", "alice", true},
		{"capital-sigma", "Σ", "σ", true},
		{"final-sigma-distinct", "σ", "ς", false},
		{"sharp-s-distinct", "straße", "strasse", false},
	} {
		t.Run(names.label, func(t *testing.T) {
			fixture := newProtocolFixture(t)
			created := fixture.call(t, scim.UserCreate, "", "", userBody(names.first, ""))
			id := object(t, created.Body)["id"].(string)
			if names.collision {
				fixture.deny(t, scim.Request{Operation: scim.UserCreate, Body: []byte(userBody(names.second, ""))}, 409, "uniqueness")
				if len(fixture.store.resources) != 1 {
					t.Fatal("prepared username collision persisted a second resource")
				}
			} else {
				other := fixture.call(t, scim.UserCreate, "", "", userBody(names.second, ""))
				if object(t, other.Body)["id"] == id || object(t, other.Body)["userName"] != names.second {
					t.Fatal("distinct PRECIS username lost its own source value or resource ID")
				}
			}
			read := fixture.call(t, scim.UserGet, id, "", "")
			if read.ETag != created.ETag || string(read.Body) != string(created.Body) {
				t.Fatal("uniqueness comparison rewrote the original resource")
			}
		})
	}
}

func TestUsersReviewF1UsernamePolicyDoesNotOverrideExtensionCaseExact(t *testing.T) {
	value := reviewAttribute("value", "string")
	value.CaseExact = true
	username := reviewAttribute("userName", "string")
	username.CaseExact = true
	fixture := configuredProtocolFixture(t, reviewSchema(value, username))
	fixture.call(t, scim.UserCreate, "", "", reviewUser("José", `{"value":"Jose\u0301","userName":"aא"}`))
	for _, query := range []struct {
		filter string
		count  float64
	}{
		{extensionURN + `:value eq "José"`, 0},
		{extensionURN + `:value eq "Jose\u0301"`, 1},
		{extensionURN + `:userName eq "aא"`, 1},
	} {
		response := fixture.execute(t, followupQueryRequest(t, scim.UserList, query.filter))
		if object(t, response.Body)["totalResults"] != query.count {
			t.Errorf("core username preparation changed an extension's declared caseExact policy: %s", query.filter)
		}
	}
}

func TestUsersReviewF1UsernameComparisonKeyBoundsAndRedaction(t *testing.T) {
	maximum := strings.Repeat("a", 65536)
	if key, err := scim.UsernameComparisonKey(maximum); err != nil || key != maximum {
		t.Fatal("maximum bounded valid username key was rejected or changed")
	}
	for _, input := range []string{"", string([]byte{0xff}), strings.Repeat("a", 65537), "private\x00diagnostic"} {
		key, err := scim.UsernameComparisonKey(input)
		assertProtocolError(t, scim.Response{}, err, 400, "invalidValue")
		if key != "" {
			t.Fatal("invalid username preparation returned a usable comparison key")
		}
	}
}

func TestUsersReviewF2EmptyStringRelationalFilters(t *testing.T) {
	for _, comparison := range []struct {
		filter string
		want   []string
	}{
		{`displayName gt "A"`, []string{"nonempty"}},
		{`displayName ge "A"`, []string{"nonempty"}},
		{`displayName lt "A"`, []string{"empty"}},
		{`displayName le "A"`, []string{"empty"}},
		{`displayName gt ""`, []string{"nonempty"}},
		{`displayName ge ""`, []string{"empty", "nonempty"}},
		{`displayName lt ""`, []string{}},
		{`displayName le ""`, []string{"empty"}},
		{`displayName eq ""`, []string{"empty"}},
	} {
		for _, operation := range []scim.Operation{scim.UserList, scim.UserSearch, scim.Search} {
			t.Run(comparison.filter+"/"+string(operation), func(t *testing.T) {
				fixture := configuredProtocolFixture(t, func(c *scim.Config) {
					c.Limits.PageDefault, c.Limits.PageMax = 3, 3
				})
				fixture.call(t, scim.UserCreate, "", "", userBody("empty", `,"displayName":""`))
				fixture.call(t, scim.UserCreate, "", "", userBody("absent", ""))
				fixture.call(t, scim.UserCreate, "", "", userBody("nonempty", `,"displayName":"B"`))
				response := fixture.execute(t, followupQueryRequest(t, operation, comparison.filter))
				doc := object(t, response.Body)
				got := []string{}
				for _, resource := range doc["Resources"].([]any) {
					got = append(got, resource.(map[string]any)["userName"].(string))
				}
				sort.Strings(got)
				if !slices.Equal(got, comparison.want) || doc["totalResults"] != float64(len(comparison.want)) {
					t.Fatalf("relational comparison returned %v total=%v, want %v", got, doc["totalResults"], comparison.want)
				}
			})
		}
	}
}

func TestUsersReviewF2SortRetainsUnassignedPlacementAndIDTieBreak(t *testing.T) {
	fixture := configuredProtocolFixture(t, func(c *scim.Config) {
		c.Limits.PageDefault, c.Limits.PageMax = 3, 3
	})
	empty := fixture.call(t, scim.UserCreate, "", "", userBody("empty-sort", `,"displayName":""`))
	absent := fixture.call(t, scim.UserCreate, "", "", userBody("absent-sort", ""))
	assigned := fixture.call(t, scim.UserCreate, "", "", userBody("assigned-sort", `,"displayName":"B"`))
	unassigned := []string{object(t, empty.Body)["id"].(string), object(t, absent.Body)["id"].(string)}
	sort.Strings(unassigned)
	assignedID := object(t, assigned.Body)["id"].(string)
	for _, order := range []string{"ascending", "descending"} {
		t.Run(order, func(t *testing.T) {
			response := fixture.execute(t, scim.Request{Operation: scim.UserList, Query: scim.Query{SortBy: "displayName", SortOrder: order}})
			doc := object(t, response.Body)
			got := []string{}
			for _, resource := range doc["Resources"].([]any) {
				got = append(got, resource.(map[string]any)["id"].(string))
			}
			want := []string{assignedID, unassigned[0], unassigned[1]}
			if order == "descending" {
				want = []string{unassigned[0], unassigned[1], assignedID}
			}
			if !slices.Equal(got, want) || doc["totalResults"] != float64(3) {
				t.Fatalf("sort lost unassigned placement or stable ID tie-break: got %v want %v", got, want)
			}
		})
	}
}

func TestUsersReviewF3OmittedPrimaryQueriesAsFalse(t *testing.T) {
	for _, primary := range []struct{ label, suffix string }{
		{"omitted", ""},
		{"explicit-false", `,"primary":false`},
		{"explicit-true", `,"primary":true`},
	} {
		for _, filter := range []string{`emails[primary eq false]`, `emails.primary eq false`, `emails[primary ne true]`} {
			for _, operation := range []scim.Operation{scim.UserList, scim.UserSearch, scim.Search} {
				t.Run(primary.label+"/"+filter+"/"+string(operation), func(t *testing.T) {
					fixture := newProtocolFixture(t)
					created := fixture.call(t, scim.UserCreate, "", "", userBody("primary-default", `,"emails":[{"value":"a@example.test"`+primary.suffix+`}]`))
					id := object(t, created.Body)["id"].(string)
					response := fixture.execute(t, followupQueryRequest(t, operation, filter))
					doc := object(t, response.Body)
					want := 1
					if primary.label == "explicit-true" {
						want = 0
					}
					resources := doc["Resources"].([]any)
					if doc["totalResults"] != float64(want) || len(resources) != want {
						t.Fatalf("effective primary=false returned total=%v resources=%d, want %d", doc["totalResults"], len(resources), want)
					}
					if want == 1 && resources[0].(map[string]any)["id"] != id {
						t.Fatal("primary query matched the wrong resource")
					}
					if read := fixture.call(t, scim.UserGet, id, "", ""); read.ETag != created.ETag {
						t.Fatal("default-value query mutated the resource")
					}
				})
			}
		}
	}
}

func TestUsersReviewF3OmittedPrimaryPatchSelectorReassignsPrimary(t *testing.T) {
	for _, primary := range []struct{ label, suffix string }{
		{"omitted", ""},
		{"explicit-false", `,"primary":false`},
	} {
		t.Run(primary.label, func(t *testing.T) {
			fixture := newProtocolFixture(t)
			created := fixture.call(t, scim.UserCreate, "", "", userBody("primary-default-patch", `,"emails":[{"value":"a@example.test"`+primary.suffix+`},{"value":"b@example.test","primary":true}]`))
			id := object(t, created.Body)["id"].(string)
			request := scim.Request{Operation: scim.UserPatch, ResourceID: id, IfMatch: created.ETag, IdempotencyKey: "primary-default-patch", Body: []byte(patchBody(`{"op":"replace","path":"emails[primary eq false].primary","value":true}`))}
			updated := fixture.execute(t, request)
			emails := object(t, updated.Body)["emails"].([]any)
			if len(emails) != 2 || emails[0].(map[string]any)["primary"] != true || emails[1].(map[string]any)["primary"] != false {
				t.Fatalf("default-false selection did not atomically reassign primary: %s", updated.Body)
			}
			if updated.ETag == created.ETag {
				t.Fatal("primary reassignment did not advance the resource version")
			}
			if replay := fixture.execute(t, request); replay.ETag != updated.ETag || string(replay.Body) != string(updated.Body) {
				t.Fatal("default-false primary reassignment was not replayable")
			}
		})
	}
}

func TestUsersReviewF3ExplicitTrueDoesNotMatchFalsePatchSelector(t *testing.T) {
	fixture := newProtocolFixture(t)
	created := fixture.call(t, scim.UserCreate, "", "", userBody("primary-true-control", `,"emails":[{"value":"a@example.test","primary":true}]`))
	id := object(t, created.Body)["id"].(string)
	fixture.deny(t, scim.Request{Operation: scim.UserPatch, ResourceID: id, IfMatch: created.ETag, Body: []byte(patchBody(`{"op":"replace","path":"emails[primary eq false].primary","value":true}`))}, 400, "noTarget")
	if read := fixture.call(t, scim.UserGet, id, "", ""); read.ETag != created.ETag || string(read.Body) != string(created.Body) {
		t.Fatal("unmatched primary selector changed the resource")
	}
}

func TestUsersReviewF3DefaultDoesNotInventMissingCollectionOrOtherBooleans(t *testing.T) {
	parent := reviewAttribute("parent", "complex")
	parent.SubAttributes = []scim.Attribute{reviewAttribute("primary", "boolean")}
	fixture := configuredProtocolFixture(t, reviewSchema(parent))
	fixture.call(t, scim.UserCreate, "", "", reviewUser("no-default-outside-email", `{"parent":{}}`))
	for _, filter := range []string{
		`emails[primary eq false]`,
		`emails.primary eq false`,
		`active eq false`,
		extensionURN + `:parent.primary eq false`,
	} {
		response := fixture.execute(t, followupQueryRequest(t, scim.UserList, filter))
		doc := object(t, response.Body)
		if doc["totalResults"] != float64(0) || len(doc["Resources"].([]any)) != 0 {
			t.Errorf("primary default fabricated a missing collection or unrelated Boolean: %s", filter)
		}
	}
}

// This wraps the existing trusted process-local Store double. It first performs
// the real fixture commit and terminal replay recording, then loses the reply.
// It does not stand in for a native durable adapter or introduce a journal.
type followupCommittedFailureStore struct {
	scim.Store
	mode            string
	failAfterCommit bool
	commits, aborts int
}

func (s *followupCommittedFailureStore) Commit(ctx context.Context, prepared scim.PreparedWrite, change scim.Change) (scim.WriteResult, error) {
	result, err := s.Store.Commit(ctx, prepared, change)
	if err != nil {
		return result, err
	}
	s.commits++
	if s.failAfterCommit {
		s.failAfterCommit = false
		if s.mode == "panic" {
			panic("private committed fixture diagnostic")
		}
		return scim.WriteResult{}, errors.New("private committed fixture diagnostic")
	}
	return result, nil
}

func (s *followupCommittedFailureStore) Abort(ctx context.Context, prepared scim.PreparedWrite) error {
	s.aborts++
	return s.Store.Abort(ctx, prepared)
}

func TestUsersReviewCommittedThenFailureRetainsEffectAndReplayWithoutAbort(t *testing.T) {
	for _, mode := range []string{"error", "panic"} {
		t.Run(mode, func(t *testing.T) {
			var store *followupCommittedFailureStore
			fixture := configuredProtocolFixture(t, func(c *scim.Config) {
				store = &followupCommittedFailureStore{Store: c.Store, mode: mode}
				c.Store = store
			})
			created := fixture.call(t, scim.UserCreate, "", "", userBody("committed-lost-reply", `,"displayName":"before"`))
			id := object(t, created.Body)["id"].(string)
			request := freshnessRequest(scim.UserPatch, id, created.ETag)
			request.IdempotencyKey = "committed-lost-reply"
			request.Body = []byte(patchBody(`{"op":"replace","path":"displayName","value":"committed"}`))
			calls, commits := fixture.mapper.calls, store.commits
			store.failAfterCommit = true
			response, err := fixture.service.Execute(context.Background(), request)
			assertProtocolError(t, response, err, 503, "")
			if store.aborts != 0 || store.commits != commits+1 || fixture.mapper.calls != calls+1 {
				t.Fatalf("post-commit %s misreported the effect boundary: commits=%d aborts=%d mapper_calls=%d", mode, store.commits-commits, store.aborts, fixture.mapper.calls-calls)
			}
			stored := fixture.call(t, scim.UserGet, id, "", "")
			if object(t, stored.Body)["displayName"] != "committed" || stored.ETag == created.ETag {
				t.Fatal("fixture did not persist the effect before losing the commit reply")
			}
			replay := fixture.execute(t, request)
			if replay.Status != 200 || replay.ETag != stored.ETag || string(replay.Body) != string(stored.Body) {
				t.Fatal("retry did not recover the committed semantic result")
			}
			if store.aborts != 0 || store.commits != commits+1 || fixture.mapper.calls != calls+1 {
				t.Fatal("committed retry aborted, remapped or committed the command again")
			}
		})
	}
}

func FuzzUsersReviewUsernameComparisonKey(f *testing.F) {
	for _, input := range []string{
		"José", "Jose\u0301", "Ａlice", "ς", "σ", "straße", "strasse",
		"aא", "ab\u200dcd", "userⅣ", "l·l", "a·b", string([]byte{0xff}),
	} {
		f.Add(input)
	}
	f.Fuzz(func(t *testing.T, input string) {
		if len(input) > 4096 {
			return
		}
		key, err := scim.UsernameComparisonKey(input)
		if err != nil {
			assertProtocolError(t, scim.Response{}, err, 400, "invalidValue")
			if key != "" {
				t.Fatal("rejected username returned a usable key")
			}
			return
		}
		if key == "" {
			t.Fatal("accepted username returned an empty key")
		}
		repeated, err := scim.UsernameComparisonKey(key)
		if err != nil || repeated != key {
			t.Fatal("bounded username preparation did not produce a stable comparison key")
		}
	})
}
