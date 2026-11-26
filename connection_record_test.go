package scim_test

import (
	"fmt"
	"reflect"
	"strings"
	"testing"

	identity "github.com/faustbrian/go-identity"
	organization "github.com/faustbrian/go-organization"
	scim "github.com/faustbrian/go-scim"
)

func TestConnectionIDCanonicalNonzeroRepresentation(t *testing.T) {
	for _, raw := range []string{"AAAAAAAAAAAAAAAAAAAAAQ", "-gAAAAAAAAAAAAAAAAAAAA", "_____________________w"} {
		id, err := scim.ParseConnectionID(raw)
		if err != nil || string(id) != raw {
			t.Fatalf("canonical connection ID did not round trip: %v", err)
		}
	}
	for _, raw := range []string{
		"", "AAAAAAAAAAAAAAAAAAAAAA", "AAAAAAAAAAAAAAAAAAAAAQ==", "AAAAAAAAAAAAAAAAAAAAAR",
		" AAAAAAAAAAAAAAAAAAAAAQ", "AAAAAAAAAAAAAAAAAAAAA+", "AAAAAAAAAAAAAAAAAAAAA/",
		"AAAAAAAAAAAAAAAAAAAAA\n", strings.Repeat("connection-secret-probe", 100),
	} {
		id, err := scim.ParseConnectionID(raw)
		if err == nil || id != "" {
			t.Fatal("malformed, zero or noncanonical connection ID accepted")
		}
		assertConnectionErrorRedacted(t, err, raw)
	}
}

func TestMappingPathCanonicalReadableSources(t *testing.T) {
	extensions := connectionMappingExtensions()
	for _, tc := range []struct{ raw, canonical string }{
		{"USERNAME", "userName"},
		{userURN + ":USERNAME", "userName"},
		{"NAME.GIVENNAME", "name.givenName"},
		{"id", "id"},
		{"META.VERSION", "meta.version"},
		{`EMAILS[TYPE eq "work"].VALUE`, `emails[type eq "work"].value`},
		{userURN + `:emails[type eq "work"].value`, `emails[type eq "work"].value`},
		{connectionMappingExtensionURN + ":EMPLOYEENUMBER", connectionMappingExtensionURN + ":employeeNumber"},
		{connectionMappingExtensionURN + ":MANAGER.VALUE", connectionMappingExtensionURN + ":manager.value"},
	} {
		t.Run(tc.raw, func(t *testing.T) {
			path, err := scim.ParseMappingPath(tc.raw, extensions, scim.DefaultLimits())
			if err != nil || path.String() != tc.canonical {
				t.Fatalf("readable source = %q, %v; want %q", path.String(), err, tc.canonical)
			}
			again, err := scim.ParseMappingPath(path.String(), extensions, scim.DefaultLimits())
			if err != nil || again.String() != path.String() {
				t.Fatalf("canonical source is not stable: %q, %v", again.String(), err)
			}
		})
	}
}

func TestMappingPathRejectsHiddenUnknownAndUnboundedSources(t *testing.T) {
	extensions := connectionMappingExtensions()
	for _, raw := range []string{
		"", "password", "PASSWORD", userURN + ":password",
		connectionMappingExtensionURN + ":hidden", connectionMappingExtensionURN + ":secret",
		connectionMappingExtensionURN + ":private.value", connectionMappingExtensionURN + ":manager.hidden",
		"unknown-private-probe", "name.givenName.child", "name..givenName",
		"urn:example:unregistered:User:employeeNumber",
		strings.ToUpper(connectionMappingExtensionURN) + ":employeeNumber",
		`userName[type eq "work"].value`, `emails[unknownPrivateProbe eq "work"].value`,
		`emails[type eq "work"].unknownPrivateProbe`, `emails[type eq "work"`,
		strings.Repeat("oversized-private-probe", 100),
	} {
		path, err := scim.ParseMappingPath(raw, extensions, scim.DefaultLimits())
		if err == nil || path.String() != "" {
			t.Fatalf("invalid source disclosed a usable path: %q", path.String())
		}
		assertConnectionErrorRedacted(t, err, raw)
	}
	limits := scim.DefaultLimits()
	limits.PathBytes = len("userName") - 1
	if _, err := scim.ParseMappingPath("userName", nil, limits); err == nil {
		t.Fatal("configured path byte bound was ignored")
	}
	limits = scim.DefaultLimits()
	limits.FilterBytes = 5
	if _, err := scim.ParseMappingPath(`emails[type eq "work"].value`, nil, limits); err == nil {
		t.Fatal("configured selector byte bound was ignored")
	}
	limits.FilterBytes = len(`value eq "x&"`)
	if path, err := scim.ParseMappingPath(`emails[value eq "x&"].value`, nil, limits); err == nil {
		if _, err := scim.ParseMappingPath(path.String(), nil, limits); err != nil {
			t.Fatal("canonical encoding returned a path outside its original selector budget")
		}
	}
	if _, err := scim.ParseMappingPath("userName", nil, scim.Limits{}); err == nil {
		t.Fatal("zero limits accepted")
	}
}

func TestMappingPathCanonicalSelectorKeepsItsDepthBound(t *testing.T) {
	limits := scim.DefaultLimits()
	limits.FilterDepth = 4
	raw := `EMAILS[(TYPE pr and VALUE pr) and (TYPE pr and VALUE pr and PRIMARY pr)].VALUE`
	path, err := scim.ParseMappingPath(raw, nil, limits)
	if err != nil {
		t.Fatalf("depth-bounded selector was rejected: %v", err)
	}
	again, err := scim.ParseMappingPath(path.String(), nil, limits)
	if err != nil || again != path {
		t.Fatalf("canonical selector broke its original depth bound: %q, %v", path.String(), err)
	}
}

func FuzzMappingPathCanonicalRoundTrip(f *testing.F) {
	f.Add("USERNAME", uint16(1024), uint8(16))
	f.Add(`EMAILS[(TYPE eq "work" or TYPE eq "other") and VALUE pr].VALUE`, uint16(1024), uint8(16))
	f.Add(`emails[value eq "x&"].value`, uint16(len(`value eq "x&"`)), uint8(16))
	f.Add(`emails[not (value sw "<")].value`, uint16(1024), uint8(16))
	f.Add(`emails[(type pr and value pr) and (type pr and value pr and primary pr)].value`, uint16(1024), uint8(4))
	f.Fuzz(func(t *testing.T, raw string, filterBytes uint16, filterDepth uint8) {
		limits := scim.DefaultLimits()
		limits.FilterBytes = 1 + (int(filterBytes)-1+limits.FilterBytes)%limits.FilterBytes
		limits.FilterDepth = 1 + (int(filterDepth)-1+limits.FilterDepth)%limits.FilterDepth
		path, err := scim.ParseMappingPath(raw, nil, limits)
		if err != nil {
			if path.String() != "" {
				t.Fatal("invalid source returned a usable path")
			}
			return
		}
		again, err := scim.ParseMappingPath(path.String(), nil, limits)
		if err != nil || again != path {
			t.Fatal("canonical mapping path failed its original limits or was not idempotent", err)
		}
	})
}

func TestMappingSetRejectsDuplicateSourcesTargetsAndInvalidEntries(t *testing.T) {
	userName := connectionMappingPath(t, "userName", nil)
	userNameAlias := connectionMappingPath(t, userURN+":USERNAME", nil)
	displayName := connectionMappingPath(t, "displayName", nil)
	selected := connectionMappingPath(t, `emails[type eq "work"].value`, nil)
	selectedAlias := connectionMappingPath(t, `EMAILS[TYPE eq "work"].VALUE`, nil)
	for _, tc := range []struct {
		name    string
		entries []scim.Mapping
	}{
		{"empty", nil},
		{"zero source", []scim.Mapping{{Target: "name"}}},
		{"empty target", []scim.Mapping{{Source: userName}}},
		{"duplicate target", []scim.Mapping{{Source: userName, Target: "name"}, {Source: displayName, Target: "name"}}},
		{"duplicate resolved source", []scim.Mapping{{Source: userName, Target: "name"}, {Source: userNameAlias, Target: "other"}}},
		{"duplicate selected source", []scim.Mapping{{Source: selected, Target: "email"}, {Source: selectedAlias, Target: "other"}}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			set, err := scim.NewMappingSet(tc.entries)
			if err == nil || len(set.Entries()) != 0 {
				t.Fatal("invalid mapping set accepted or partially disclosed")
			}
		})
	}
}

func TestMappingSetCountAndEncodedByteBounds(t *testing.T) {
	entries := connectionMappingEntries(t, 129, "urn:example:mapping:User")
	if _, err := scim.NewMappingSet(entries[:128]); err != nil {
		t.Fatalf("128 distinct mappings rejected: %v", err)
	}
	if set, err := scim.NewMappingSet(entries); err == nil || len(set.Entries()) != 0 {
		t.Fatal("129 mappings accepted or partially disclosed")
	}

	longURN := "urn:example:" + strings.Repeat("namespace", 60) + ":User"
	entries = connectionMappingEntries(t, 128, longURN)
	if set, err := scim.NewMappingSet(entries); err == nil || len(set.Entries()) != 0 {
		t.Fatal("mapping encoding exceeding 65,536 bytes accepted or partially disclosed")
	}
}

func TestConnectionRecordRetainsExplicitPolicyVersionAndDetachedMappings(t *testing.T) {
	scope := validConnectionRecordScope()
	path := connectionMappingPath(t, "userName", nil)
	original := []scim.Mapping{{Source: path, Target: "identity.userName", Writable: true}}
	mappings, err := scim.NewMappingSet(original)
	if err != nil {
		t.Fatal(err)
	}
	original[0] = scim.Mapping{Source: connectionMappingPath(t, "displayName", nil), Target: "changed"}
	want := []scim.Mapping{{Source: path, Target: "identity.userName", Writable: true}}
	for _, policy := range []scim.DeprovisionPolicy{scim.Suspend, scim.RemoveMembership, scim.DeleteIdentity} {
		record, err := scim.NewConnectionRecord(scope, mappings, policy, 41)
		if err != nil {
			t.Fatalf("registered policy rejected by neutral record: %v", err)
		}
		if record.Scope() != scope || record.DeprovisionPolicy() != policy || record.Version() != 41 {
			t.Fatal("record changed its exact scope, explicit policy or version")
		}
		entries := mappings.Entries()
		entries[0].Target = "changed-direct-set"
		entries[0].Writable = false
		entries[0].Source = scim.Path{}
		fromRecord := record.Mappings().Entries()
		if !reflect.DeepEqual(fromRecord, want) {
			t.Fatal("input or mapping-set output mutation changed the record")
		}
		fromRecord[0] = scim.Mapping{}
		if !reflect.DeepEqual(record.Mappings().Entries(), want) || !reflect.DeepEqual(mappings.Entries(), want) {
			t.Fatal("record mapping output aliases retained mappings")
		}
		scopeCopy := record.Scope()
		scopeCopy.ProviderID = "changed-provider"
		if record.Scope() != scope {
			t.Fatal("scope output mutation changed record ownership")
		}
	}
}

func TestConnectionRecordRejectsInvalidScopePolicyMappingsAndVersion(t *testing.T) {
	mappings, err := scim.NewMappingSet([]scim.Mapping{{Source: connectionMappingPath(t, "userName", nil), Target: "identity.userName"}})
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name   string
		change func(*scim.ConnectionScope)
	}{
		{"empty tenant", func(s *scim.ConnectionScope) { s.TenantID = "" }},
		{"empty organization", func(s *scim.ConnectionScope) { s.OrganizationID = "" }},
		{"legacy tenant", func(s *scim.ConnectionScope) { s.TenantID = "tenant-one" }},
		{"legacy organization", func(s *scim.ConnectionScope) { s.OrganizationID = "organization-one" }},
		{"zero tenant", func(s *scim.ConnectionScope) { s.TenantID = "AAAAAAAAAAAAAAAAAAAAAA" }},
		{"zero organization", func(s *scim.ConnectionScope) { s.OrganizationID = "AAAAAAAAAAAAAAAAAAAAAA" }},
		{"noncanonical tenant", func(s *scim.ConnectionScope) { s.TenantID = "AAAAAAAAAAAAAAAAAAAAAR" }},
		{"noncanonical organization", func(s *scim.ConnectionScope) { s.OrganizationID = "AAAAAAAAAAAAAAAAAAAAAZ" }},
		{"empty provider", func(s *scim.ConnectionScope) { s.ProviderID = "" }},
		{"empty connection", func(s *scim.ConnectionScope) { s.ProviderConnectionID = "" }},
		{"zero connection", func(s *scim.ConnectionScope) { s.ProviderConnectionID = "AAAAAAAAAAAAAAAAAAAAAA" }},
		{"noncanonical connection", func(s *scim.ConnectionScope) { s.ProviderConnectionID = "AAAAAAAAAAAAAAAAAAAAAR" }},
		{"unicode tenant", func(s *scim.ConnectionScope) { s.TenantID = "tenant-\u00e9-private-probe" }},
		{"control organization", func(s *scim.ConnectionScope) { s.OrganizationID = "organization\nprivate-probe" }},
		{"whitespace provider", func(s *scim.ConnectionScope) { s.ProviderID = "provider private-probe" }},
		{"oversized tenant", func(s *scim.ConnectionScope) {
			s.TenantID = identity.TenantID(strings.Repeat("tenant-private-probe", 100))
		}},
		{"oversized organization", func(s *scim.ConnectionScope) {
			s.OrganizationID = organization.ID(strings.Repeat("organization-private-probe", 100))
		}},
		{"oversized provider", func(s *scim.ConnectionScope) {
			s.ProviderID = scim.ProviderID(strings.Repeat("provider-private-probe", 100))
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			scope := validConnectionRecordScope()
			tc.change(&scope)
			record, err := scim.NewConnectionRecord(scope, mappings, scim.RemoveMembership, 1)
			assertRejectedConnectionRecord(t, record, err)
			for _, rejected := range []string{string(scope.TenantID), string(scope.OrganizationID), string(scope.ProviderID), string(scope.ProviderConnectionID)} {
				assertConnectionErrorRedacted(t, err, rejected)
			}
		})
	}
	for _, policy := range []scim.DeprovisionPolicy{0, 255} {
		record, err := scim.NewConnectionRecord(validConnectionRecordScope(), mappings, policy, 1)
		assertRejectedConnectionRecord(t, record, err)
	}
	record, err := scim.NewConnectionRecord(validConnectionRecordScope(), scim.MappingSet{}, scim.RemoveMembership, 1)
	assertRejectedConnectionRecord(t, record, err)
	record, err = scim.NewConnectionRecord(validConnectionRecordScope(), mappings, scim.RemoveMembership, 0)
	assertRejectedConnectionRecord(t, record, err)
}

const connectionMappingExtensionURN = "urn:example:params:scim:schemas:extension:employment:2.0:User"

func connectionMappingExtensions() []scim.Schema {
	attribute := func(name, mutability, returned string) scim.Attribute {
		return scim.Attribute{Name: name, Type: "string", Mutability: mutability, Returned: returned, Uniqueness: "none"}
	}
	manager := attribute("manager", "readWrite", "default")
	manager.Type = "complex"
	manager.SubAttributes = []scim.Attribute{attribute("value", "readOnly", "default"), attribute("hidden", "readWrite", "never")}
	private := attribute("private", "readWrite", "never")
	private.Type = "complex"
	private.SubAttributes = []scim.Attribute{attribute("value", "readWrite", "default")}
	return []scim.Schema{{ID: connectionMappingExtensionURN, Name: "Employment", Attributes: []scim.Attribute{
		attribute("employeeNumber", "readOnly", "default"), attribute("hidden", "readWrite", "never"),
		attribute("secret", "writeOnly", "never"), manager, private,
	}}}
}

func connectionMappingPath(t *testing.T, raw string, extensions []scim.Schema) scim.Path {
	t.Helper()
	path, err := scim.ParseMappingPath(raw, extensions, scim.DefaultLimits())
	if err != nil {
		t.Fatalf("mapping source fixture rejected: %v", err)
	}
	return path
}

func connectionMappingEntries(t *testing.T, count int, urn string) []scim.Mapping {
	t.Helper()
	attributes := make([]scim.Attribute, count)
	for i := range attributes {
		attributes[i] = scim.Attribute{Name: fmt.Sprintf("field%03d", i), Type: "string", Mutability: "readWrite", Returned: "default", Uniqueness: "none"}
	}
	extensions := []scim.Schema{{ID: urn, Name: "MappingFields", Attributes: attributes}}
	entries := make([]scim.Mapping, count)
	for i, attribute := range attributes {
		entries[i] = scim.Mapping{Source: connectionMappingPath(t, urn+":"+attribute.Name, extensions), Target: fmt.Sprintf("target%03d", i)}
	}
	return entries
}

func validConnectionRecordScope() scim.ConnectionScope {
	return scim.ConnectionScope{TenantID: "AAAAAAAAAAAAAAAAAAAAAg", OrganizationID: "AAAAAAAAAAAAAAAAAAAAAw", ProviderID: "provider-one", ProviderConnectionID: "AAAAAAAAAAAAAAAAAAAAAQ"}
}

func assertRejectedConnectionRecord(t *testing.T, record scim.ConnectionRecord, err error) {
	t.Helper()
	if err == nil || record.Scope() != (scim.ConnectionScope{}) || record.Version() != 0 || record.DeprovisionPolicy() != 0 || len(record.Mappings().Entries()) != 0 {
		t.Fatal("invalid record accepted or rejected contents retained")
	}
}

func assertConnectionErrorRedacted(t *testing.T, err error, rejected string) {
	t.Helper()
	if err == nil {
		t.Fatal("expected a validation error")
	}
	if rejected != "" && strings.Contains(err.Error(), rejected) {
		t.Fatal("validation error disclosed rejected input")
	}
}
