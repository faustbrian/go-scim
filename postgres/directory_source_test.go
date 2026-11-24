package scimpostgres

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"testing"
	"time"

	identity "github.com/faustbrian/go-identity"
	kernel "github.com/faustbrian/go-identity/postgres"
	organization "github.com/faustbrian/go-organization"
	scim "github.com/faustbrian/go-scim"
)

func directorySourceTestObservation() (*GroupsService, DirectorySourceObservation) {
	start := time.Now().UTC().Add(-time.Second)
	c := Config{
		Scope:   scim.Scope{TenantID: "tenant-a", OrganizationID: "organization-a", ProviderID: "provider-a", ConnectionID: "connection-a"},
		ActorID: "service-a", ConnectionVersion: 1, GlobalAuthorityID: "deployment-a",
		CredentialExpiresAt: start.Add(time.Hour),
	}
	c.Credential.id = "private-credential-id"
	native := &Service{config: func() Config { return c }}
	i := invocation{
		connection:   scim.Connection{Scope: c.Scope, CredentialID: c.Credential.id, Version: 1, ExpiresAt: c.CredentialExpiresAt, AuthorityReadBeganAt: start, AuthorityValidUntil: start.Add(20 * time.Second)},
		organization: organization.CredentialAuthorityObservation{TenantID: c.Scope.TenantID, OrganizationID: c.Scope.OrganizationID, Version: 2, CredentialVersion: 3, ReadStartedAt: start, VerifiedAt: start.Add(time.Millisecond), ValidUntil: start.Add(20 * time.Second)},
		epoch:        4,
		directory:    kernel.DirectoryAuthorityAdmission{Query: c.directoryQuery(), GlobalVersion: 5, TenantVersion: 6},
	}
	return &GroupsService{native: native}, DirectorySourceObservation{source: native, admission: i}
}

func TestDirectorySourceBindingsPreserveOriginalScopeAndDeadline(t *testing.T) {
	service, observation := directorySourceTestObservation()
	bindings, err := observation.Bindings()
	if err != nil {
		t.Fatal(err)
	}
	c := service.native.config()
	if bindings.Scope != c.Scope || bindings.ActorID != c.ActorID || bindings.ConnectionVersion != c.ConnectionVersion || !bindings.ReadStartedAt.Equal(observation.admission.connection.AuthorityReadBeganAt) || !bindings.ValidUntil.Equal(observation.admission.connection.AuthorityValidUntil) {
		t.Fatal("source bindings changed original configured identity or deadline")
	}
	bindings.Scope.ConnectionID = "another-connection"
	bindings.ActorID = "another-service"
	bindings.ValidUntil = time.Now().Add(time.Hour)
	again, err := observation.Bindings()
	if err != nil || again.Scope != c.Scope || again.ActorID != c.ActorID || !again.ValidUntil.Equal(observation.admission.connection.AuthorityValidUntil) {
		t.Fatal("editing the projection changed source evidence")
	}
}

func TestDirectorySourceBindingsRejectMissingAndExpiredEvidence(t *testing.T) {
	_, original := directorySourceTestObservation()
	for _, test := range []struct {
		name   string
		change func(*DirectorySourceObservation)
	}{
		{"zero", func(o *DirectorySourceObservation) { *o = DirectorySourceObservation{} }},
		{"missing issuer", func(o *DirectorySourceObservation) { o.source = nil }},
		{"foreign scope", func(o *DirectorySourceObservation) { o.admission.connection.Scope.ConnectionID = "foreign" }},
		{"changed connection version", func(o *DirectorySourceObservation) { o.admission.connection.Version++ }},
		{"changed credential identity", func(o *DirectorySourceObservation) { o.admission.connection.CredentialID = "foreign" }},
		{"missing directory authority", func(o *DirectorySourceObservation) { o.admission.directory.GlobalVersion = 0 }},
		{"missing scoped authority", func(o *DirectorySourceObservation) { o.admission.epoch = 0 }},
		{"expired", func(o *DirectorySourceObservation) {
			o.admission.connection.AuthorityValidUntil = time.Now().Add(-time.Millisecond)
		}},
		{"extended deadline", func(o *DirectorySourceObservation) {
			o.admission.connection.AuthorityValidUntil = time.Now().Add(time.Hour)
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			observation := original
			test.change(&observation)
			if bindings, err := observation.Bindings(); err == nil || bindings != (DirectorySourceBindings{}) {
				t.Fatal("invalid source produced usable bindings")
			}
		})
	}
}

func TestDirectorySourceEvidenceCannotBeExported(t *testing.T) {
	_, observation := directorySourceTestObservation()
	for _, verb := range []string{"%v", "%+v", "%#v"} {
		if got := fmt.Sprintf(verb, observation); got != "scimpostgres.DirectorySourceObservation(redacted)" {
			t.Fatal("source evidence disclosed", verb)
		}
	}
	if _, err := json.Marshal(observation); err == nil {
		t.Fatal("source evidence exported")
	}
}

func TestDirectorySourceCommandCommitmentRejectsAnotherSourceWithSamePrincipal(t *testing.T) {
	service, original := directorySourceTestObservation()
	field, err := original.Field()
	if err != nil {
		t.Fatal(err)
	}
	if err := original.requireCommandField(context.Background(), []identity.FeatureField{field}); err != nil {
		t.Fatal("original source field rejected", err)
	}
	c := service.native.config()
	c.Scope.ConnectionID = "connection-b"
	other := original
	other.source = &Service{config: func() Config { return c }}
	other.admission.connection.Scope = c.Scope
	otherField, err := other.Field()
	if err != nil {
		t.Fatal("second configured source with same tenant/principal invalid", err)
	}
	if bytes.Equal(field.Value.Bytes, otherField.Value.Bytes) {
		t.Fatal("different configured connections share a source commitment")
	}
	if err := other.requireCommandField(context.Background(), []identity.FeatureField{field}); err == nil {
		t.Fatal("same-principal second source satisfied the first child's field")
	}
	if err := original.requireCommandField(context.Background(), []identity.FeatureField{otherField}); err == nil {
		t.Fatal("first source satisfied another connection's child field")
	}
	for _, fields := range [][]identity.FeatureField{
		nil,
		{field, field},
		{{Name: field.Name, Value: identity.FeatureValue{Kind: identity.FeatureText, Text: "not-source-evidence"}}},
		{{Name: field.Name, Value: identity.FeatureValue{Kind: identity.FeatureBytes, Bytes: []byte{1}}}},
	} {
		if err := original.requireCommandField(context.Background(), fields); err == nil {
			t.Fatal("missing, duplicate or invalid source commitment admitted")
		}
	}
	field.Value.Bytes[0] ^= 1
	again, err := original.Field()
	if err != nil || bytes.Equal(field.Value.Bytes, again.Value.Bytes) {
		t.Fatal("editing detached field changed original source commitment", err)
	}
}

func TestDirectorySourceCommandCommitmentRetainsOriginalAuthorityAndDeadline(t *testing.T) {
	_, original := directorySourceTestObservation()
	field, err := original.Field()
	if err != nil {
		t.Fatal(err)
	}
	for _, change := range []func(*DirectorySourceObservation){
		func(o *DirectorySourceObservation) { o.admission.epoch++ },
		func(o *DirectorySourceObservation) { o.admission.directory.GlobalVersion++ },
		func(o *DirectorySourceObservation) { o.admission.directory.TenantVersion++ },
		func(o *DirectorySourceObservation) { o.admission.organization.Version++ },
		func(o *DirectorySourceObservation) { o.admission.organization.CredentialVersion++ },
		func(o *DirectorySourceObservation) {
			o.admission.connection.AuthorityValidUntil = o.admission.connection.AuthorityValidUntil.Add(-time.Millisecond)
		},
	} {
		changed := original
		change(&changed)
		if _, err := changed.Field(); err != nil {
			t.Fatal("changed still-live source malformed", err)
		}
		if err := changed.requireCommandField(context.Background(), []identity.FeatureField{field}); err == nil {
			t.Fatal("changed original authority or deadline satisfied original child's field")
		}
	}
}

func TestDirectorySourceRequiresConfiguredScopeAndAuthenticatedWork(t *testing.T) {
	service, observation := directorySourceTestObservation()
	foreign := service.native.config().Scope
	foreign.ConnectionID = "foreign"
	if _, err := service.ObserveDirectorySource(context.Background(), foreign); err == nil {
		t.Fatal("foreign source admitted")
	}
	if _, err := (*GroupsService)(nil).ObserveDirectorySource(context.Background(), foreign); err == nil {
		t.Fatal("nil configured source admitted")
	}
	if _, err := service.ObserveDirectorySource(nil, service.native.config().Scope); err == nil {
		t.Fatal("nil source context admitted")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := service.ObserveDirectorySource(ctx, service.native.config().Scope); err == nil {
		t.Fatal("cancelled source context admitted")
	}
	if err := service.RequireDirectorySource(context.Background(), kernel.Work{}, nil, identity.Command{}, observation); err == nil {
		t.Fatal("source evidence substituted for authenticated Work")
	}
	if err := service.RequireDirectorySourceAtCommit(context.Background(), kernel.Work{}, nil, identity.Command{}, observation); err == nil {
		t.Fatal("final verifier substituted for authenticated Work")
	}
}
