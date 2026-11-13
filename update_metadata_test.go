package scim_test

import (
	"context"
	"testing"
	"time"

	scim "github.com/faustbrian/go-scim"
)

type updateMetadataStore struct {
	scim.Store
	metadata *scim.UpdateMetadata
	commits  int
}

func (s *updateMetadataStore) Prepare(ctx context.Context, intent scim.WriteIntent) (scim.PreparedWrite, error) {
	p, err := s.Store.Prepare(ctx, intent)
	p.UpdateMetadata = s.metadata
	return p, err
}

func (s *updateMetadataStore) Commit(ctx context.Context, p scim.PreparedWrite, change scim.Change) (scim.WriteResult, error) {
	s.commits++
	return s.Store.Commit(ctx, p, change)
}

func TestPreparedUpdateMetadataPreservesOriginalServerVersionAndTime(t *testing.T) {
	for _, operation := range []scim.Operation{scim.UserReplace, scim.UserPatch} {
		t.Run(string(operation), func(t *testing.T) {
			var store *updateMetadataStore
			f := configuredProtocolFixture(t, func(c *scim.Config) {
				store = &updateMetadataStore{Store: c.Store}
				c.Store = store
			})
			created := f.call(t, scim.UserCreate, "", "", `{"schemas":["urn:ietf:params:scim:schemas:core:2.0:User"],"userName":"before"}`)
			id := object(t, created.Body)["id"].(string)
			store.metadata = &scim.UpdateMetadata{Version: `"retained-update-version"`, LastModified: fixtureNow.Add(time.Minute).In(time.FixedZone("store-offset", 3600))}
			body := `{"schemas":["urn:ietf:params:scim:schemas:core:2.0:User"],"userName":"after"}`
			if operation == scim.UserPatch {
				body = `{"schemas":["urn:ietf:params:scim:api:messages:2.0:PatchOp"],"Operations":[{"op":"replace","path":"userName","value":"after"}]}`
			}
			changed := f.call(t, operation, id, created.ETag, body)
			doc := object(t, changed.Body)
			meta := doc["meta"].(map[string]any)
			originalMeta := object(t, created.Body)["meta"].(map[string]any)
			if changed.ETag != store.metadata.Version || doc["id"] != id || doc["userName"] != "after" || meta["created"] != originalMeta["created"] || meta["lastModified"] != store.metadata.LastModified.UTC().Format(time.RFC3339Nano) {
				t.Fatal("protocol regenerated retained metadata or changed immutable identity")
			}
		})
	}
}

func TestPreparedUpdateMetadataCannotSelectCreateOrDelete(t *testing.T) {
	for _, operation := range []scim.Operation{scim.UserCreate, scim.UserDelete} {
		t.Run(string(operation), func(t *testing.T) {
			var store *updateMetadataStore
			f := configuredProtocolFixture(t, func(c *scim.Config) {
				store = &updateMetadataStore{Store: c.Store}
				c.Store = store
			})
			request := scim.Request{Operation: operation, Body: []byte(`{"schemas":["urn:ietf:params:scim:schemas:core:2.0:User"],"userName":"before"}`)}
			wantCommits := 0
			if operation == scim.UserDelete {
				created := f.call(t, scim.UserCreate, "", "", string(request.Body))
				request.ResourceID = object(t, created.Body)["id"].(string)
				request.IfMatch, request.Body = created.ETag, nil
				wantCommits = 1
			}
			store.metadata = &scim.UpdateMetadata{Version: `"retained-version"`, LastModified: fixtureNow}
			f.deny(t, request, 503, "")
			if store.commits != wantCommits {
				t.Fatal("update metadata selected another operation")
			}
		})
	}
}

func TestPreparedUpdateMetadataDoesNotChangeNoOpPatch(t *testing.T) {
	var store *updateMetadataStore
	f := configuredProtocolFixture(t, func(c *scim.Config) {
		store = &updateMetadataStore{Store: c.Store}
		c.Store = store
	})
	created := f.call(t, scim.UserCreate, "", "", `{"schemas":["urn:ietf:params:scim:schemas:core:2.0:User"],"userName":"same"}`)
	id := object(t, created.Body)["id"].(string)
	store.metadata = &scim.UpdateMetadata{Version: `"unused-new-version"`, LastModified: fixtureNow.Add(time.Minute)}
	patched := f.call(t, scim.UserPatch, id, created.ETag, `{"schemas":["urn:ietf:params:scim:api:messages:2.0:PatchOp"],"Operations":[{"op":"replace","path":"userName","value":"same"}]}`)
	if patched.ETag != created.ETag || string(patched.Body) != string(created.Body) {
		t.Fatal("no-op patch changed original version or timestamps")
	}
}

func TestMalformedPreparedUpdateMetadataDeniesBeforeCommit(t *testing.T) {
	for name, mutate := range map[string]func(*scim.UpdateMetadata, scim.Version){
		"missing version":   func(m *scim.UpdateMetadata, _ scim.Version) { m.Version = "" },
		"unquoted version":  func(m *scim.UpdateMetadata, _ scim.Version) { m.Version = "not-quoted" },
		"reused version":    func(m *scim.UpdateMetadata, old scim.Version) { m.Version = old },
		"zero modification": func(m *scim.UpdateMetadata, _ scim.Version) { m.LastModified = time.Time{} },
		"backwards time":    func(m *scim.UpdateMetadata, _ scim.Version) { m.LastModified = fixtureNow.Add(-time.Second) },
		"out of range time": func(m *scim.UpdateMetadata, _ scim.Version) {
			m.LastModified = time.Date(10000, 1, 1, 0, 0, 0, 0, time.UTC)
		},
	} {
		t.Run(name, func(t *testing.T) {
			var store *updateMetadataStore
			f := configuredProtocolFixture(t, func(c *scim.Config) {
				store = &updateMetadataStore{Store: c.Store}
				c.Store = store
			})
			created := f.call(t, scim.UserCreate, "", "", `{"schemas":["urn:ietf:params:scim:schemas:core:2.0:User"],"userName":"before"}`)
			id := object(t, created.Body)["id"].(string)
			store.metadata = &scim.UpdateMetadata{Version: `"retained-version"`, LastModified: fixtureNow.Add(time.Minute)}
			mutate(store.metadata, created.ETag)
			f.deny(t, scim.Request{Operation: scim.UserReplace, ResourceID: id, IfMatch: created.ETag, Body: []byte(`{"schemas":["urn:ietf:params:scim:schemas:core:2.0:User"],"userName":"after"}`)}, 503, "")
			if store.commits != 1 {
				t.Fatal("invalid metadata crossed the commit boundary")
			}
		})
	}
}

func TestUpdateMetadataValidatesItsCanonicalUTCSnapshot(t *testing.T) {
	for _, tc := range []struct {
		name     string
		modified time.Time
		denied   bool
	}{
		{"UTC year overflows", time.Date(9999, 12, 31, 23, 30, 0, 0, time.FixedZone("west", -3600)), true},
		{"UTC year remains valid", time.Date(10000, 1, 1, 0, 30, 0, 0, time.FixedZone("east", 3600)), false},
		{"non-RFC offset canonicalizes", fixtureNow.Add(48 * time.Hour).In(time.FixedZone("non-RFC-offset", 24*60*60)), false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var store *updateMetadataStore
			f := configuredProtocolFixture(t, func(c *scim.Config) {
				store = &updateMetadataStore{Store: c.Store}
				c.Store = store
			})
			created := f.call(t, scim.UserCreate, "", "", `{"schemas":["urn:ietf:params:scim:schemas:core:2.0:User"],"userName":"before"}`)
			id := object(t, created.Body)["id"].(string)
			store.metadata = &scim.UpdateMetadata{Version: `"retained-version"`, LastModified: tc.modified}
			request := scim.Request{Operation: scim.UserReplace, ResourceID: id, IfMatch: created.ETag, Body: []byte(`{"schemas":["urn:ietf:params:scim:schemas:core:2.0:User"],"userName":"after"}`)}
			if tc.denied {
				f.deny(t, request, 503, "")
				if store.commits != 1 || f.mapper.calls != 1 {
					t.Fatal("invalid canonical UTC metadata reached mapping or commit")
				}
				return
			}
			updated := f.execute(t, request)
			meta := object(t, updated.Body)["meta"].(map[string]any)
			if updated.ETag != store.metadata.Version || meta["lastModified"] != tc.modified.UTC().Format(time.RFC3339Nano) || store.commits != 2 {
				t.Fatal("canonical UTC metadata changed the instant or durable outcome")
			}
		})
	}
}

type updateMetadataMutationMapper struct {
	scim.Mapper
	store *updateMetadataStore
}

func (m updateMetadataMutationMapper) MapUser(ctx context.Context, scope scim.Scope, input scim.WritableResource) (scim.WritableResource, error) {
	if m.store.metadata != nil {
		m.store.metadata.Version = `"changed-during-mapping"`
		m.store.metadata.LastModified = fixtureNow.Add(2 * time.Minute)
	}
	return m.Mapper.MapUser(ctx, scope, input)
}

func TestPreparedUpdateMetadataIsFrozenBeforeMapping(t *testing.T) {
	var store *updateMetadataStore
	f := configuredProtocolFixture(t, func(c *scim.Config) {
		store = &updateMetadataStore{Store: c.Store}
		c.Store = store
		c.Mapper = updateMetadataMutationMapper{Mapper: c.Mapper, store: store}
	})
	created := f.call(t, scim.UserCreate, "", "", `{"schemas":["urn:ietf:params:scim:schemas:core:2.0:User"],"userName":"before"}`)
	id := object(t, created.Body)["id"].(string)
	store.metadata = &scim.UpdateMetadata{Version: `"retained-version"`, LastModified: fixtureNow.Add(time.Minute)}
	expected := *store.metadata
	updated := f.call(t, scim.UserReplace, id, created.ETag, `{"schemas":["urn:ietf:params:scim:schemas:core:2.0:User"],"userName":"after"}`)
	meta := object(t, updated.Body)["meta"].(map[string]any)
	if updated.ETag != expected.Version || meta["lastModified"] != expected.LastModified.Format(time.RFC3339Nano) || store.metadata.Version == expected.Version || store.metadata.LastModified.Equal(expected.LastModified) {
		t.Fatal("mapping changed admitted metadata or borrowed mutation did not run")
	}
}
