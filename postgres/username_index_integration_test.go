//go:build integration

package scimpostgres

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/faustbrian/go-authorization/v3"
	authoritypg "github.com/faustbrian/go-authorization/v3/postgres"
	identity "github.com/faustbrian/go-identity"
	organization "github.com/faustbrian/go-organization"
	scim "github.com/faustbrian/go-scim"
	"github.com/jackc/pgx/v5/pgconn"
)

func TestNativeMaximumUsernameAndScope(t *testing.T) {
	for _, maximumScope := range []bool{false, true} {
		t.Run(fmt.Sprintf("maximum-scope=%t", maximumScope), func(t *testing.T) {
			f := newNativeFixture(t)
			if maximumScope {
				configureMaximumUsernameScope(t, f)
			}
			name := wideNativeUsername("boundary")
			request := nativeUsernameRequest(t, f, name, "maximum-username")
			created, err := f.service.Execute(f.ctx, request)
			if err != nil || created.Status != 201 {
				t.Fatalf("valid 4096-byte username did not provision: status=%d error=%v", created.Status, err)
			}
			var resource struct {
				ID       string `json:"id"`
				UserName string `json:"userName"`
			}
			if json.Unmarshal(created.Body, &resource) != nil || resource.ID == "" || resource.UserName != name {
				t.Fatal("complete admitted username was not returned")
			}
			f.assertAtomicCreation(t, resource.ID, 1)
			var stored string
			if err := f.pool.Raw().QueryRow(f.ctx, `SELECT username_key FROM scim.users WHERE resource_id=$1`, resource.ID).Scan(&stored); err != nil || stored != name {
				t.Fatal("complete canonical username was not retained", err)
			}
			read, err := f.service.Execute(f.ctx, scim.Request{Operation: scim.UserGet, ResourceID: resource.ID, Credential: f.bearer})
			if err != nil || string(read.Body) != string(created.Body) || read.ETag != created.ETag {
				t.Fatal("maximum username read changed original resource", err)
			}
			for _, duplicate := range []string{name, strings.ToUpper(name)} {
				if got, err := f.service.Execute(f.ctx, nativeUsernameRequest(t, f, duplicate, "duplicate-"+duplicate[:32])); err == nil || protocolStatus(err) != 409 || len(got.Body) != 0 {
					t.Fatal("maximum canonical duplicate was not rejected", err)
				}
			}
			other, err := f.service.Execute(f.ctx, nativeUsernameRequest(t, f, wideNativeUsername("distinct"), "distinct-maximum-username"))
			if err != nil || other.Status != 201 {
				t.Fatal("distinct maximum username incorrectly conflicted", err)
			}
			if maximumScope {
				assertMaximumSchemaUsernameScope(t, f, resource.ID)
			}
		})
	}
}

func TestNativeAuditScopeIDsRequireAuditableBound(t *testing.T) {
	f := newNativeFixture(t)
	for _, field := range []string{"tenant", "connection"} {
		for _, value := range []string{strings.Repeat("x", 65), strings.Repeat("x", 128), "audit.id", "audit:id", "audit@id", "audit+id"} {
			t.Run(fmt.Sprintf("%s/%s", field, value), func(t *testing.T) {
				c := f.config
				if field == "tenant" {
					c.Scope.TenantID = identity.TenantID(value)
				} else {
					c.Scope.ConnectionID = value
				}
				if service, err := NewService(f.pool, c, f.keys); service != nil || !errors.Is(err, ErrInvalidConfiguration) {
					t.Fatal("constructor admitted a scoped ID its required audit owner rejects")
				}
			})
		}
		for _, value := range []string{"A0_-", strings.Repeat("A0_-", 16)} {
			c := f.config
			if field == "tenant" {
				c.Scope.TenantID = identity.TenantID(value)
			} else {
				c.Scope.ConnectionID = value
			}
			if service, err := NewService(f.pool, c, f.keys); service == nil || err != nil {
				t.Fatal("constructor rejected an admitted audit ID", field, err)
			}
		}
	}
}

func TestNativeMaximumUsernameConcurrentCasefoldIsOneAtomicCreation(t *testing.T) {
	f := newNativeFixture(t)
	name := wideNativeUsername("concurrent")
	requests := []scim.Request{
		nativeUsernameRequest(t, f, name, "maximum-writer-one"),
		nativeUsernameRequest(t, f, strings.ToUpper(name), "maximum-writer-two"),
	}
	start := make(chan struct{})
	statuses := make(chan int, len(requests))
	var writers sync.WaitGroup
	for _, request := range requests {
		writers.Add(1)
		go func(request scim.Request) {
			defer writers.Done()
			<-start
			got, err := f.service.Execute(f.ctx, request)
			if err != nil {
				statuses <- protocolStatus(err)
				return
			}
			statuses <- got.Status
		}(request)
	}
	close(start)
	writers.Wait()
	close(statuses)
	counts := map[int]int{}
	for status := range statuses {
		counts[status]++
	}
	if counts[201] != 1 || counts[409] != 1 || len(counts) != 2 {
		t.Fatal("maximum canonical race did not have exactly one winner", counts)
	}
	var resource string
	if err := f.pool.Raw().QueryRow(f.ctx, `SELECT resource_id FROM scim.users`).Scan(&resource); err != nil {
		t.Fatal("one projection", err)
	}
	f.assertAtomicCreation(t, resource, 1)
}

func TestNativeUsernameDigestIntegrityAndCollisionDiscrimination(t *testing.T) {
	f := newNativeFixture(t)
	first := nativeUsernameRequest(t, f, "distinct-existing-name", "digest-existing")
	if got, err := f.service.Execute(f.ctx, first); err != nil || got.Status != 201 {
		t.Fatal("first real projection", err)
	}
	_, err := f.pool.Raw().Exec(f.ctx, `UPDATE scim.users SET username_digest=$1`, make([]byte, sha256.Size))
	var violation *pgconn.PgError
	if !errors.As(err, &violation) || violation.Code != "23514" || violation.ConstraintName != "users_username_digest_matches_key" {
		t.Fatal("database admitted a digest inconsistent with the full comparison key")
	}

	// A real SHA-256 collision is not constructible as a fixture. Remove only
	// this owned database's consistency check to model one: the exact-key
	// comparison must still distinguish different names in one digest bucket.
	if _, err := f.pool.Raw().Exec(f.ctx, `ALTER TABLE scim.users DROP CONSTRAINT users_username_digest_matches_key`); err != nil {
		t.Fatal("synthetic collision fixture", err)
	}
	const next = "different-canonical-name"
	digest := sha256.Sum256([]byte(next))
	if _, err := f.pool.Raw().Exec(f.ctx, `UPDATE scim.users SET username_digest=$1`, digest[:]); err != nil {
		t.Fatal("synthetic collision bucket", err)
	}
	if got, err := f.service.Execute(f.ctx, nativeUsernameRequest(t, f, next, "digest-distinct")); err != nil || got.Status != 201 {
		t.Fatal("digest collision was treated as canonical username equality", err)
	}
	if got, err := f.service.Execute(f.ctx, nativeUsernameRequest(t, f, strings.ToUpper(next), "digest-duplicate")); err == nil || protocolStatus(err) != 409 || len(got.Body) != 0 {
		t.Fatal("exact canonical duplicate was admitted in the collision bucket", err)
	}
	var bucket, users int
	if err := f.pool.Raw().QueryRow(f.ctx, `SELECT (SELECT count(*) FROM scim.users WHERE username_digest=$1),(SELECT count(*) FROM identity.users)`, digest[:]).Scan(&bucket, &users); err != nil || bucket != 2 || users != 2 {
		t.Fatal("collision bucket did not retain exactly the distinct users", bucket, users, err)
	}
}

func wideNativeUsername(seed string) string {
	var name strings.Builder
	for n := range 64 {
		digest := sha256.Sum256(fmt.Appendf(nil, "native-wide-username-%s-%d", seed, n))
		name.WriteString(hex.EncodeToString(digest[:]))
	}
	return name.String()
}

func nativeUsernameRequest(t *testing.T, f *nativeFixture, name, key string) scim.Request {
	t.Helper()
	wire, err := json.Marshal(map[string]any{"schemas": []string{"urn:ietf:params:scim:schemas:core:2.0:User"}, "userName": name, "displayName": "Complete native username"})
	if err != nil {
		t.Fatal(err)
	}
	return scim.Request{Operation: scim.UserCreate, Credential: f.bearer, IdempotencyKey: key, ContentType: "application/scim+json", Body: wire}
}

func configureMaximumUsernameScope(t *testing.T, f *nativeFixture) {
	t.Helper()
	c := f.config
	// The required native audit owner admits 64-byte tenant/context and
	// connection/subject IDs. Organization and provider retain 128-byte bounds.
	c.Scope = scim.Scope{TenantID: identity.TenantID(strings.Repeat("t", 64)), OrganizationID: organization.ID(strings.Repeat("o", 128)), ProviderID: strings.Repeat("p", 128), ConnectionID: strings.Repeat("c", 64)}
	if _, err := f.pool.Raw().Exec(f.ctx, `INSERT INTO identity.tenant_authorities(tenant_id,version,enabled) VALUES($1,1,true)`, string(c.Scope.TenantID)); err != nil {
		t.Fatal("maximum tenant authority", err)
	}
	if _, err := f.pool.Raw().Exec(f.ctx, `INSERT INTO organization.organizations(tenant_id,organization_id,slug,name,state,version,member_count,owner_count,credential_version) VALUES($1,$2,'maximum-scope','Maximum scope','active',1,1,1,1)`, string(c.Scope.TenantID), string(c.Scope.OrganizationID)); err != nil {
		t.Fatal("maximum organization", err)
	}
	if _, err := authoritypg.InitializeAuthority(f.ctx, f.pool.Raw(), authoritypg.AuthorityScope{TenantID: authorization.TenantID(c.Scope.TenantID), PolicyNamespace: c.AuthorityNamespace, SubjectID: authorization.SubjectID(c.ActorID)}, time.Second); err != nil {
		t.Fatal("maximum policy authority", err)
	}
	service, err := NewService(f.pool, c, f.keys)
	if err != nil {
		t.Fatal("maximum scope configuration", err)
	}
	if _, err := service.InitializeConfiguredConnection(f.ctx); err != nil {
		var invalid identity.InvalidInputError
		if errors.As(err, &invalid) {
			t.Fatal("maximum scope connection rejected field", invalid.Field)
		}
		t.Fatal("maximum scope connection", err)
	}
	f.config, f.service = c, service
}

func assertMaximumSchemaUsernameScope(t *testing.T, f *nativeFixture, resource string) {
	t.Helper()
	connectionCommand, err := identity.NewCommandID()
	if err != nil {
		t.Fatal(err)
	}
	projectionCommand, err := identity.NewCommandID()
	if err != nil {
		t.Fatal(err)
	}
	// This is raw fresh-schema capacity evidence, not public provisioning: it
	// preserves a real user's full key under all four 128-byte schema IDs. The
	// selected native service's tenant and connection remain bounded to 64 bytes.
	maximumScope := f.config.Scope
	maximumScope.TenantID = identity.TenantID(strings.Repeat("t", 128))
	maximumScope.ConnectionID = strings.Repeat("c", 128)
	if _, err := f.pool.Raw().Exec(f.ctx, `INSERT INTO organization.organizations(tenant_id,organization_id,slug,name,state,version,member_count,owner_count,credential_version) VALUES($1,$2,'maximum-schema','Maximum schema scope','active',1,1,1,1)`, string(maximumScope.TenantID), string(maximumScope.OrganizationID)); err != nil {
		t.Fatal("schema-only organization partition", err)
	}
	if _, err := f.pool.Raw().Exec(f.ctx, `INSERT INTO identity.users(tenant_id,user_id,status,version) SELECT $1,user_id,status,version FROM identity.users WHERE tenant_id=$2 AND user_id=$3`, string(maximumScope.TenantID), string(f.config.Scope.TenantID), resource); err != nil {
		t.Fatal("schema-only foreign-key fixture", err)
	}
	args := append(scopeArgs(f.config.Scope), string(maximumScope.TenantID), maximumScope.ConnectionID, string(connectionCommand))
	if _, err := f.pool.Raw().Exec(f.ctx, `INSERT INTO scim.connections(tenant_id,organization_id,provider_id,connection_id,credential_id,credential_digest,configuration_digest,version,state,expires_at,authority_version,organization_credential_version,command_id,effect_digest)
SELECT $5,organization_id,provider_id,$6,credential_id,credential_digest,configuration_digest,version,state,expires_at,authority_version,organization_credential_version,$7,effect_digest FROM scim.connections WHERE tenant_id=$1 AND organization_id=$2 AND provider_id=$3 AND connection_id=$4`, args...); err != nil {
		t.Fatal("four 128-byte schema connection IDs", err)
	}
	args = append(scopeArgs(f.config.Scope), string(maximumScope.TenantID), maximumScope.ConnectionID, string(projectionCommand), resource)
	if _, err := f.pool.Raw().Exec(f.ctx, `INSERT INTO scim.users(tenant_id,organization_id,provider_id,connection_id,resource_id,user_id,username_key,username_digest,external_id,resource,command_id,effect_digest)
SELECT $5,organization_id,provider_id,$6,resource_id,user_id,username_key,username_digest,external_id,resource,$7,effect_digest FROM scim.users WHERE tenant_id=$1 AND organization_id=$2 AND provider_id=$3 AND connection_id=$4 AND resource_id=$8`, args...); err != nil {
		t.Fatal("four 128-byte schema scope and 4096-byte key did not fit", err)
	}
	var count int
	if err := f.pool.Raw().QueryRow(f.ctx, `SELECT count(*) FROM scim.users WHERE tenant_id=$1 AND organization_id=$2 AND provider_id=$3 AND connection_id=$4 AND octet_length(tenant_id)=128 AND octet_length(organization_id)=128 AND octet_length(provider_id)=128 AND octet_length(connection_id)=128 AND octet_length(username_key)=4096 AND octet_length(username_digest)=32`, scopeArgs(maximumScope)...).Scan(&count); err != nil || count != 1 {
		t.Fatal("maximum schema tuple lost its full comparison key", count, err)
	}
}
