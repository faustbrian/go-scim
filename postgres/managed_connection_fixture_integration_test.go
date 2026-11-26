//go:build integration

package scimpostgres

import (
	"crypto/rand"
	"encoding/json"
	"testing"
	"time"

	authentication "github.com/faustbrian/go-authentication/v2"
	"github.com/faustbrian/go-authorization/v3"
	authoritypg "github.com/faustbrian/go-authorization/v3/postgres"
	"github.com/faustbrian/go-clock"
	identity "github.com/faustbrian/go-identity"
	kernel "github.com/faustbrian/go-identity/postgres"
	"github.com/faustbrian/go-identity/session"
	sessionpg "github.com/faustbrian/go-identity/session/postgres"
	organization "github.com/faustbrian/go-organization"
)

type managedConnectionAdminFixture struct {
	*nativeFixture
	tenant         identity.TenantID
	actor          identity.UserID
	organization   organization.ID
	sessions       *session.SessionService
	sessionConfig  sessionpg.Config
	sessionProfile sessionpg.IdentifierAdmissionConfig
	sessionKey     session.DigestKey
	admin          organization.Authentication
}

func newManagedConnectionAdminFixture(t *testing.T) *managedConnectionAdminFixture {
	t.Helper()
	tenantID, err := identity.NewSubjectID()
	if err != nil {
		t.Fatal(err)
	}
	tenant := identity.TenantID(tenantID)
	native := newNativeFixture(t, tenant)
	actor, err := identity.NewSubjectID()
	if err != nil {
		t.Fatal(err)
	}
	organizationID, err := identity.NewSubjectID()
	if err != nil {
		t.Fatal(err)
	}
	f := &managedConnectionAdminFixture{
		nativeFixture: native,
		tenant:        tenant,
		actor:         identity.UserID(actor),
		organization:  organization.ID(organizationID),
		sessionConfig: sessionpg.Config{Schema: "scim_admin_sessions", MaximumDuration: time.Second},
		sessionProfile: sessionpg.IdentifierAdmissionConfig{
			GlobalAuthorityID:    native.config.GlobalAuthorityID,
			PolicyNamespace:      native.config.AuthorityNamespace,
			Audience:             "scim-managed-admin",
			AuthenticationMethod: "password",
			CredentialKind:       identity.CredentialPassword,
			CredentialOwner:      "identity/password",
		},
	}

	// The native fixture already installed Base. Apply only the owner's new
	// credential step, preserving its configured tenant and SCIM connection.
	history, err := (kernel.CredentialMigrationSource{Base: nativeCanonicalFixtureHistory(tenant), Version: 50}).Load(f.ctx)
	if err != nil || len(history) == 0 || history[len(history)-1].Version() != 50 {
		t.Fatal("managed admin credential migration history", err)
	}
	if _, err := f.pool.Raw().Exec(f.ctx, history[len(history)-1].UpSQL()); err != nil {
		t.Fatal("managed admin credential schema", err)
	}
	installSource(t, f.ctx, f.pool, sessionpg.MigrationSource{Schema: f.sessionConfig.Schema, Version: 51})
	if _, err := f.pool.Raw().Exec(f.ctx, `INSERT INTO identity.users(tenant_id,user_id,status,version) VALUES($1,$2,'active',1)`, string(f.tenant), string(f.actor)); err != nil {
		t.Fatal("managed admin canonical user", err)
	}
	if _, err := f.pool.Raw().Exec(f.ctx, `INSERT INTO identity.credential_references(tenant_id,user_id,credential_id,kind,owner,version,enabled) VALUES($1,$2,'password',1,'identity/password',1,true)`, string(f.tenant), string(f.actor)); err != nil {
		t.Fatal("managed admin credential reference", err)
	}
	policyScope := authoritypg.AuthorityScope{TenantID: authorization.TenantID(f.tenant), PolicyNamespace: f.sessionProfile.PolicyNamespace, SubjectID: authorization.SubjectID(f.actor)}
	if _, err := authoritypg.InitializeAuthority(f.ctx, f.pool.Raw(), policyScope, time.Second); err != nil {
		t.Fatal("managed admin policy authority", err)
	}
	if _, err := f.pool.Raw().Exec(f.ctx, `INSERT INTO organization.organizations(tenant_id,organization_id,slug,name,state,version,member_count,owner_count,credential_version) VALUES($1,$2,'managed-admin','Managed admin fixture','active',1,1,1,1)`, string(f.tenant), string(f.organization)); err != nil {
		t.Fatal("managed admin organization", err)
	}
	if _, err := f.pool.Raw().Exec(f.ctx, `INSERT INTO organization.memberships(tenant_id,organization_id,user_id,role,state,version,authorization_version) VALUES($1,$2,$3,'owner','active',1,1)`, string(f.tenant), string(f.organization), string(f.actor)); err != nil {
		t.Fatal("managed admin owner membership", err)
	}
	material := make([]byte, 32)
	rand.Read(material)
	f.sessionKey, err = session.NewDigestKey(1, material)
	clear(material)
	if err != nil {
		t.Fatal(err)
	}
	f.sessions, err = sessionpg.NewSessionService(f.pool, sessionpg.SessionServiceConfig{
		Repository: f.sessionConfig,
		Profile:    f.sessionProfile,
		Validation: session.ServiceConfig{Profile: session.StorageStatefulOpaque, Audience: f.sessionProfile.Audience, Clock: clock.System{}, MaximumDuration: 2 * time.Second, ClockUncertainty: time.Millisecond, LookupKeys: []session.DigestKey{f.sessionKey}},
	})
	if err != nil {
		t.Fatal("managed admin session service", err)
	}
	f.seedCurrentAdminSession(t, policyScope)
	return f
}

func (f *managedConnectionAdminFixture) seedCurrentAdminSession(t *testing.T, policyScope authoritypg.AuthorityScope) {
	t.Helper()
	remember, err := session.ResolveRememberPolicy(session.BrowserSession, session.LifetimeConfig{Default: session.BrowserSession, AbsoluteTTL: time.Hour, IdleTTL: 30 * time.Minute, RefreshAfter: 5 * time.Minute, FreshFor: 15 * time.Minute})
	if err != nil {
		t.Fatal(err)
	}
	keys, err := kernel.KernelAuthorityKeys(kernel.DirectoryAuthorityQuery{GlobalAuthorityID: f.sessionProfile.GlobalAuthorityID, TenantID: f.tenant}, f.actor)
	if err != nil {
		t.Fatal(err)
	}
	sessionID, family := "session-"+string(f.actor), "family-"+string(f.actor)
	sessionKeys, err := sessionpg.SessionAuthorityKeys(f.tenant, f.actor, family, sessionID)
	if err != nil {
		t.Fatal(err)
	}
	policyKey, err := policyScope.Key()
	if err != nil {
		t.Fatal(err)
	}
	bind := func(key string) session.AuthorityBinding { return session.AuthorityBinding{ScopeKey: key, Version: 1} }
	authoritySpec := session.AuthoritySnapshotSpec{Global: bind(keys.Global), Tenant: bind(keys.Tenant), User: bind(keys.User), Identifier: bind(keys.Identifier), Credential: bind(keys.Credential), SessionFamily: bind(sessionKeys.Family), Session: bind(sessionKeys.Session), Authorization: bind(policyKey)}
	vector, err := session.NewAuthoritySnapshot(authoritySpec)
	if err != nil {
		t.Fatal(err)
	}
	token, err := session.NewToken(32)
	if err != nil {
		t.Fatal(err)
	}
	digest, err := token.Digest(f.sessionKey, string(f.tenant))
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Truncate(time.Microsecond)
	metadata := session.AuthenticationMetadata{Kind: session.AuthenticationVerified, Proof: authentication.Proof{ID: authentication.ProofID(f.actor), Tenant: string(f.tenant), Subject: string(f.actor), Method: "password", Assurance: authentication.AssuranceSingleFactor, Purpose: "session-issue", Audience: f.sessionProfile.Audience, IssuedAt: now.Add(-time.Second), ExpiresAt: now.Add(time.Minute)}, ProofVersion: 1, CredentialID: "password", CredentialVersion: 1}
	record, err := session.NewSession(session.SessionSpec{SessionID: sessionID, FamilyID: family, TenantID: f.tenant, UserID: f.actor, Audience: f.sessionProfile.Audience, Version: 1, FamilyVersion: 1, Remember: remember, Authority: vector, Lookup: digest, Authentication: metadata, IssuedAt: now, LastActivityAt: now})
	if err != nil {
		t.Fatal("managed admin session record", err)
	}
	lifetime, err := record.Lifetime(now)
	if err != nil {
		t.Fatal(err)
	}
	rememberSpec, err := remember.Bindings()
	if err != nil {
		t.Fatal(err)
	}
	// Match session/postgres' closed persisted record, as the organization
	// integration fixture does; only the real primary reader authenticates it.
	payload, err := json.Marshal(map[string]any{"Schema": 1, "SessionID": sessionID, "FamilyID": family, "TenantID": f.tenant, "UserID": f.actor, "Audience": f.sessionProfile.Audience, "Version": uint64(1), "FamilyVersion": uint64(1), "Remember": rememberSpec, "Authority": authoritySpec, "Lookup": digest, "Authentication": metadata, "IssuedAt": now, "LastActivityAt": now})
	if err != nil {
		t.Fatal(err)
	}
	const storedTimeLayout = "2006-01-02T15:04:05.000000000Z"
	if _, err := f.pool.Raw().Exec(f.ctx, `INSERT INTO scim_admin_sessions.families(tenant_id,family_id,user_id,version,state,issued_at) VALUES($1,$2,$3,1,'active',$4)`, string(f.tenant), family, string(f.actor), now.Format(storedTimeLayout)); err != nil {
		t.Fatal("managed admin session family", err)
	}
	if _, err := f.pool.Raw().Exec(f.ctx, `INSERT INTO scim_admin_sessions.sessions(tenant_id,session_id,user_id,family_id,version,family_version,state,digest_version,digest,expires_at,record) VALUES($1,$2,$3,$4,1,1,'active',1,$5,$6,$7)`, string(f.tenant), sessionID, string(f.actor), family, digest.Sum[:], lifetime.ExpiresAt.Format(storedTimeLayout), payload); err != nil {
		t.Fatal("managed admin current session", err)
	}
	wire, err := token.Reveal()
	if err != nil {
		t.Fatal(err)
	}
	f.admin = organization.Authentication{TenantID: f.tenant, Bearer: authentication.NewBearerCredential(wire)}
	parsed, err := session.ParseToken(wire)
	if err != nil {
		t.Fatal(err)
	}
	credential, err := session.NewCredential(session.CredentialBearer, parsed)
	if err != nil {
		t.Fatal(err)
	}
	authenticated, err := f.sessions.Get(f.ctx, session.GetRequest{TenantID: f.tenant, Credential: credential})
	if err != nil || !authenticated.Authenticated {
		t.Fatal("managed admin bearer must authenticate through current native authorities", err)
	}
	authenticatedSpec, err := authenticated.Session.Bindings()
	if err != nil || authenticatedSpec.UserID != f.actor || authenticatedSpec.TenantID != f.tenant {
		t.Fatal("managed admin authenticated scope", err)
	}
}
