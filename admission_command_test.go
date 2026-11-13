package scim_test

import (
	"context"
	"testing"
	"time"

	authentication "github.com/faustbrian/go-authentication/v2"
	identity "github.com/faustbrian/go-identity"
	scim "github.com/faustbrian/go-scim"
)

// The trusted durable owner, not the protocol proposal, selects its original
// command. This deliberately uses the existing protocol store seam rather than
// pretending to implement the native kernel or connection authentication.
type ownerCommandStore struct {
	scim.Store
	chosen, proposed, committed identity.CommandID
	mutate                      func(*scim.PreparedWrite)
	aborts                      int
	commits                     int
	metadata                    *scim.CreateMetadata
}

func (s *ownerCommandStore) Prepare(ctx context.Context, intent scim.WriteIntent) (scim.PreparedWrite, error) {
	s.proposed = intent.CommandID
	intent.CommandID = s.chosen
	prepared, err := s.Store.Prepare(ctx, intent)
	prepared.CreateMetadata = s.metadata
	if err == nil && s.mutate != nil {
		s.mutate(&prepared)
	}
	return prepared, err
}

func (s *ownerCommandStore) Commit(ctx context.Context, prepared scim.PreparedWrite, change scim.Change) (scim.WriteResult, error) {
	s.commits++
	s.committed = prepared.Intent.CommandID
	return s.Store.Commit(ctx, prepared, change)
}

func (s *ownerCommandStore) Abort(ctx context.Context, prepared scim.PreparedWrite) error {
	s.aborts++
	return s.Store.Abort(ctx, prepared)
}

func TestUsersKeepDurableOwnersOriginalCommand(t *testing.T) {
	for _, key := range []string{"", "original-admission-key"} {
		t.Run(key, func(t *testing.T) {
			command, err := identity.NewCommandID()
			if err != nil {
				t.Fatal(err)
			}
			var owner *ownerCommandStore
			f := configuredProtocolFixture(t, func(c *scim.Config) {
				owner = &ownerCommandStore{Store: c.Store, chosen: command}
				c.Store = owner
			})
			request := scim.Request{Operation: scim.UserCreate, IdempotencyKey: key, Body: []byte(`{"schemas":["urn:ietf:params:scim:schemas:core:2.0:User"],"userName":"original-command"}`)}
			created := f.execute(t, request)
			if created.Status != 201 || owner.proposed == command || owner.committed != command || owner.aborts != 0 {
				t.Fatal("protocol replaced or rejected the durable owner's original command")
			}
			if key != "" {
				replayed := f.execute(t, request)
				if replayed.Status != created.Status || replayed.ETag != created.ETag || string(replayed.Body) != string(created.Body) || owner.commits != 1 {
					t.Fatal("original command replay allocated another resource or mutation")
				}
			}
		})
	}
}

func TestOwnerSelectedCommandDoesNotPermitChangedAdmission(t *testing.T) {
	for name, change := range map[string]func(*scim.PreparedWrite){
		"zero command":      func(p *scim.PreparedWrite) { p.Intent.CommandID = "" },
		"malformed command": func(p *scim.PreparedWrite) { p.Intent.CommandID = "not-a-command" },
		"scope":             func(p *scim.PreparedWrite) { p.Intent.Scope.ConnectionID = "another-connection" },
		"operation":         func(p *scim.PreparedWrite) { p.Intent.Operation = scim.UserReplace },
		"target":            func(p *scim.PreparedWrite) { p.Intent.ResourceID = "another-resource" },
		"precondition":      func(p *scim.PreparedWrite) { p.Intent.IfMatch = `"another-version"` },
		"canonical body":    func(p *scim.PreparedWrite) { p.Intent.CanonicalRequest = []byte("changed-body") },
		"idempotency key":   func(p *scim.PreparedWrite) { p.Intent.IdempotencyKey = "another-key" },
		"credential":        func(p *scim.PreparedWrite) { p.Intent.Connection.CredentialID = "another-credential" },
		"renewed freshness": func(p *scim.PreparedWrite) {
			p.Intent.Connection.AuthorityValidUntil = p.Intent.Connection.AuthorityValidUntil.Add(time.Second)
		},
	} {
		t.Run(name, func(t *testing.T) {
			command, err := identity.NewCommandID()
			if err != nil {
				t.Fatal(err)
			}
			var owner *ownerCommandStore
			f := configuredProtocolFixture(t, func(c *scim.Config) {
				owner = &ownerCommandStore{Store: c.Store, chosen: command, mutate: change}
				c.Store = owner
			})
			f.deny(t, scim.Request{Operation: scim.UserCreate, IdempotencyKey: "original-key", Body: []byte(`{"schemas":["urn:ietf:params:scim:schemas:core:2.0:User"],"userName":"no-substitution"}`)}, 503, "")
			if owner.committed != "" || owner.aborts != 0 || owner.commits != 0 {
				t.Fatal("changed admission reached mutation or unsafe cleanup")
			}
		})
	}
}

type ownerGroupCommandStore struct {
	scim.GroupStore
	chosen, proposed, committed identity.CommandID
	metadata                    *scim.CreateMetadata
}

func (s *ownerGroupCommandStore) PrepareGroup(ctx context.Context, intent scim.WriteIntent) (scim.PreparedWrite, error) {
	s.proposed = intent.CommandID
	intent.CommandID = s.chosen
	prepared, err := s.GroupStore.PrepareGroup(ctx, intent)
	prepared.CreateMetadata = s.metadata
	return prepared, err
}

func (s *ownerGroupCommandStore) CommitGroup(ctx context.Context, prepared scim.PreparedWrite, change scim.Change) (scim.WriteResult, error) {
	s.committed = prepared.Intent.CommandID
	return s.GroupStore.CommitGroup(ctx, prepared, change)
}

func TestGroupsKeepDurableOwnersOriginalCommand(t *testing.T) {
	command, err := identity.NewCommandID()
	if err != nil {
		t.Fatal(err)
	}
	var owner *ownerGroupCommandStore
	metadata := &scim.CreateMetadata{ID: "original-group", Version: `"original-group-version"`, CreatedAt: fixtureNow.Add(-time.Hour), LastModified: fixtureNow.Add(-time.Minute)}
	f := newGroupFixture(t, func(c *scim.GroupsConfig) {
		owner = &ownerGroupCommandStore{GroupStore: c.Store, chosen: command, metadata: metadata}
		c.Store = owner
	})
	created := f.call(t, scim.GroupCreate, "", "", groupBody("Original command", ""))
	if created.Status != 201 || owner.proposed == command || owner.committed != command || object(t, created.Body)["id"] != metadata.ID || created.ETag != metadata.Version {
		t.Fatal("Groups discarded durable original command custody")
	}
}

func TestPreparedCreateMetadataRemainsOriginal(t *testing.T) {
	command, err := identity.NewCommandID()
	if err != nil {
		t.Fatal(err)
	}
	metadata := &scim.CreateMetadata{ID: "original-user", Version: `"original-user-version"`, CreatedAt: fixtureNow.Add(-time.Hour), LastModified: fixtureNow.Add(-time.Minute)}
	var owner *ownerCommandStore
	f := configuredProtocolFixture(t, func(c *scim.Config) {
		owner = &ownerCommandStore{Store: c.Store, chosen: command, metadata: metadata}
		c.Store = owner
	})
	request := scim.Request{Operation: scim.UserCreate, IdempotencyKey: "stable-metadata-key", Body: []byte(`{"schemas":["urn:ietf:params:scim:schemas:core:2.0:User"],"userName":"stable-metadata"}`)}
	created := f.execute(t, request)
	document := object(t, created.Body)
	meta := document["meta"].(map[string]any)
	if document["id"] != metadata.ID || created.ETag != metadata.Version || meta["created"] != metadata.CreatedAt.Format(time.RFC3339Nano) || meta["lastModified"] != metadata.LastModified.Format(time.RFC3339Nano) {
		t.Fatal("prepared create metadata was replaced or refreshed")
	}
	replayed := f.execute(t, request)
	if string(replayed.Body) != string(created.Body) || replayed.ETag != created.ETag || owner.commits != 1 {
		t.Fatal("keyed retry regenerated original resource metadata")
	}
}

func TestMalformedCreateMetadataDeniesBeforeMappingOrCommit(t *testing.T) {
	for name, change := range map[string]func(*scim.CreateMetadata){
		"missing id":       func(m *scim.CreateMetadata) { m.ID = "" },
		"unsafe id":        func(m *scim.CreateMetadata) { m.ID = "../another" },
		"missing version":  func(m *scim.CreateMetadata) { m.Version = "" },
		"unquoted version": func(m *scim.CreateMetadata) { m.Version = "version" },
		"zero creation":    func(m *scim.CreateMetadata) { m.CreatedAt = time.Time{} },
		"out of range creation": func(m *scim.CreateMetadata) {
			m.CreatedAt = time.Date(10000, 1, 1, 0, 0, 0, 0, time.UTC)
			m.LastModified = m.CreatedAt
		},
		"out of range modification": func(m *scim.CreateMetadata) { m.LastModified = time.Date(10000, 1, 1, 0, 0, 0, 0, time.UTC) },
		"backwards modification":    func(m *scim.CreateMetadata) { m.LastModified = m.CreatedAt.Add(-time.Second) },
	} {
		t.Run(name, func(t *testing.T) {
			command, err := identity.NewCommandID()
			if err != nil {
				t.Fatal(err)
			}
			metadata := &scim.CreateMetadata{ID: "original-user", Version: `"original-version"`, CreatedAt: fixtureNow, LastModified: fixtureNow}
			change(metadata)
			var owner *ownerCommandStore
			f := configuredProtocolFixture(t, func(c *scim.Config) {
				owner = &ownerCommandStore{Store: c.Store, chosen: command, metadata: metadata}
				c.Store = owner
			})
			f.deny(t, scim.Request{Operation: scim.UserCreate, Body: []byte(`{"schemas":["urn:ietf:params:scim:schemas:core:2.0:User"],"userName":"invalid-metadata"}`)}, 503, "")
			if owner.commits != 0 || f.mapper.calls != 0 {
				t.Fatal("malformed prepared metadata reached mapping or mutation")
			}
		})
	}
}

type metadataMutationMapper struct {
	scim.Mapper
	metadata *scim.CreateMetadata
}

func (m metadataMutationMapper) MapUser(ctx context.Context, scope scim.Scope, input scim.WritableResource) (scim.WritableResource, error) {
	// A deterministic mutation fault at the callback boundary proves that
	// admitted metadata was copied, without a racing goroutine or held lock.
	m.metadata.ID = "changed-after-admission"
	m.metadata.Version = `"changed-after-admission"`
	return m.Mapper.MapUser(ctx, scope, input)
}

func TestPreparedMetadataIsFrozenBeforeMapping(t *testing.T) {
	command, err := identity.NewCommandID()
	if err != nil {
		t.Fatal(err)
	}
	metadata := &scim.CreateMetadata{ID: "original-user", Version: `"original-version"`, CreatedAt: fixtureNow, LastModified: fixtureNow}
	expected := *metadata
	f := configuredProtocolFixture(t, func(c *scim.Config) {
		c.Store = &ownerCommandStore{Store: c.Store, chosen: command, metadata: metadata}
		c.Mapper = metadataMutationMapper{Mapper: c.Mapper, metadata: metadata}
	})
	created := f.call(t, scim.UserCreate, "", "", `{"schemas":["urn:ietf:params:scim:schemas:core:2.0:User"],"userName":"frozen-metadata"}`)
	if object(t, created.Body)["id"] != expected.ID || created.ETag != expected.Version || metadata.ID == expected.ID {
		t.Fatal("mapping changed borrowed metadata or mutation fault did not run")
	}
}

func TestPreparedCreateMetadataCannotReplaceExistingResource(t *testing.T) {
	command, err := identity.NewCommandID()
	if err != nil {
		t.Fatal(err)
	}
	var owner *ownerCommandStore
	f := configuredProtocolFixture(t, func(c *scim.Config) {
		owner = &ownerCommandStore{Store: c.Store, chosen: command}
		c.Store = owner
	})
	body := `{"schemas":["urn:ietf:params:scim:schemas:core:2.0:User"],"userName":"existing-metadata"}`
	created := f.call(t, scim.UserCreate, "", "", body)
	id := object(t, created.Body)["id"].(string)
	owner.chosen, err = identity.NewCommandID()
	if err != nil {
		t.Fatal(err)
	}
	owner.metadata = &scim.CreateMetadata{ID: "another-user", Version: `"another-version"`, CreatedAt: fixtureNow, LastModified: fixtureNow}
	f.deny(t, scim.Request{Operation: scim.UserReplace, ResourceID: id, IfMatch: created.ETag, Body: []byte(body)}, 503, "")
	if owner.commits != 1 || f.mapper.calls != 1 {
		t.Fatal("create-only metadata reached replacement mapping or mutation")
	}
	if read := f.call(t, scim.UserGet, id, "", ""); string(read.Body) != string(created.Body) {
		t.Fatal("create metadata changed an existing resource")
	}
}

func TestCreateMetadataValidatesItsCanonicalUTCSnapshot(t *testing.T) {
	upper := time.Date(9999, 12, 31, 23, 30, 0, 0, time.FixedZone("west", -3600))
	lower := time.Date(1, 1, 1, 0, 30, 0, 0, time.FixedZone("east", 3600))
	largeOffset := time.Date(2026, 11, 13, 12, 0, 0, 0, time.FixedZone("non-RFC-offset", 24*60*60))
	for _, tc := range []struct {
		name              string
		created, modified time.Time
		denied            bool
	}{
		{"UTC creation overflow", upper, upper, true},
		{"UTC modification overflow", fixtureNow, upper, true},
		{"UTC year below one", lower, lower, true},
		{"non-RFC offset canonicalizes", largeOffset, largeOffset, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			command, err := identity.NewCommandID()
			if err != nil {
				t.Fatal(err)
			}
			metadata := &scim.CreateMetadata{ID: "utc-original-user", Version: `"utc-original-version"`, CreatedAt: tc.created, LastModified: tc.modified}
			var owner *ownerCommandStore
			f := configuredProtocolFixture(t, func(c *scim.Config) {
				owner = &ownerCommandStore{Store: c.Store, chosen: command, metadata: metadata}
				c.Store = owner
			})
			request := scim.Request{Operation: scim.UserCreate, Credential: authentication.NewBearerCredential("fixture-connection"), ContentType: "application/scim+json", Body: []byte(`{"schemas":["urn:ietf:params:scim:schemas:core:2.0:User"],"userName":"utc-original"}`)}
			response, err := f.service.Execute(context.Background(), request)
			if tc.denied {
				assertProtocolError(t, response, err, 503, "")
				if owner.commits != 0 || f.mapper.calls != 0 {
					t.Fatal("out-of-range UTC metadata reached mapping or commit")
				}
				return
			}
			if err != nil || response.Status != 201 {
				t.Fatalf("UTC canonicalization failed: status=%d committed=%d error=%T", response.Status, owner.commits, err)
			}
			meta := object(t, response.Body)["meta"].(map[string]any)
			if meta["created"] != tc.created.UTC().Format(time.RFC3339Nano) || meta["lastModified"] != tc.modified.UTC().Format(time.RFC3339Nano) || owner.commits != 1 || owner.aborts != 0 {
				t.Fatal("UTC normalization changed the instant or durable outcome")
			}
		})
	}
}
