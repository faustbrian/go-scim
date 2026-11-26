package scimpostgres

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	identity "github.com/faustbrian/go-identity"
	scim "github.com/faustbrian/go-scim"
)

func bulkMutationInputCodec(t testing.TB) (*nativePhase, originalInput, originalInput) {
	t.Helper()
	p, _, input := groupPreparationCodec(t)
	parentCommand, err := identity.NewCommandID()
	if err != nil {
		t.Fatal(err)
	}
	parent := originalInput{Command: parentCommand, At: input.At, Admission: input.Admission}
	p.intent.Scope = p.service.config().Scope
	p.bulkChild = &bulkChildExecution{parent: parentCommand, row: bulkChildRow{
		Ordinal: 2, Command: string(input.Command), Fingerprint: bytes.Repeat([]byte{41}, 32),
	}}
	return p, input, parent
}

func TestBulkMutationInputRetainsExactGroupOriginal(t *testing.T) {
	for _, operation := range []scim.Operation{scim.GroupReplace, scim.GroupPatch, scim.GroupDelete} {
		t.Run(string(operation), func(t *testing.T) {
			p, input, parent := bulkMutationInputCodec(t)
			p.intent.Operation, input.Operation = operation, operation
			wire, err := p.sealBulkMutationInput(context.Background(), input, parent)
			if err != nil {
				t.Fatal("seal original Group input", err)
			}
			if bytes.Contains(wire, []byte(input.ID)) {
				t.Fatal("Group projection was not encrypted")
			}
			got, err := p.openBulkMutationInput(context.Background(), wire, parent)
			if err != nil || got.Command != input.Command || got.Operation != operation || got.ID != input.ID || got.Version != input.Version || got.Generation != input.Generation || !got.At.Equal(input.At) || got.Current == nil || got.Current.Attributes["displayName"] != "Original group" {
				t.Fatal("exact original Group input was not retained", err)
			}
			got.Current.Attributes["displayName"] = "detached"
			if input.Current.Attributes["displayName"] != "Original group" {
				t.Fatal("opened projection aliases caller input")
			}
		})
	}
}

func TestBulkMutationInputRejectsChangedCustody(t *testing.T) {
	for name, change := range map[string]func(*nativePhase, *originalInput){
		"target":          func(p *nativePhase, _ *originalInput) { p.intent.ResourceID = "another-target" },
		"version":         func(p *nativePhase, _ *originalInput) { p.intent.IfMatch = `"another-version"` },
		"missing version": func(p *nativePhase, _ *originalInput) { p.intent.IfMatch = "" },
		"operation":       func(p *nativePhase, _ *originalInput) { p.intent.Operation = scim.GroupReplace },
		"ordinal":         func(p *nativePhase, _ *originalInput) { p.bulkChild.row.Ordinal++ },
		"fingerprint":     func(p *nativePhase, _ *originalInput) { p.bulkChild.row.Fingerprint[0]++ },
		"child command": func(p *nativePhase, _ *originalInput) {
			command, _ := identity.NewCommandID()
			p.bulkChild.row.Command = string(command)
		},
		"parent": func(p *nativePhase, parent *originalInput) {
			command, _ := identity.NewCommandID()
			p.bulkChild.parent, parent.Command = command, command
		},
		"parent time":      func(_ *nativePhase, parent *originalInput) { parent.At = parent.At.Add(time.Microsecond) },
		"parent admission": func(_ *nativePhase, parent *originalInput) { parent.Admission.AuthorizationEpoch++ },
		"profile":          func(p *nativePhase, _ *originalInput) { p.service.profile[0]++ },
		"scope":            func(p *nativePhase, _ *originalInput) { p.intent.Scope.ConnectionID = "another-connection" },
	} {
		t.Run(name, func(t *testing.T) {
			p, input, parent := bulkMutationInputCodec(t)
			wire, err := p.sealBulkMutationInput(context.Background(), input, parent)
			if err != nil {
				t.Fatal(err)
			}
			change(p, &parent)
			got, err := p.openBulkMutationInput(context.Background(), wire, parent)
			if !errors.Is(err, identity.UnavailableError{}) || got != (originalInput{}) {
				t.Fatal("changed custody did not fail closed", err)
			}
		})
	}
}

func TestBulkMutationInputRejectsInvalidOriginalAndBounds(t *testing.T) {
	for name, change := range map[string]func(*nativePhase, *originalInput, *originalInput){
		"missing child":     func(p *nativePhase, _, _ *originalInput) { p.bulkChild = nil },
		"short fingerprint": func(p *nativePhase, _, _ *originalInput) { p.bulkChild.row.Fingerprint = []byte{1} },
		"negative ordinal":  func(p *nativePhase, _, _ *originalInput) { p.bulkChild.row.Ordinal = -1 },
		"create": func(p *nativePhase, input, _ *originalInput) {
			p.intent.Operation, input.Operation = scim.GroupCreate, scim.GroupCreate
		},
		"wrong child command": func(_ *nativePhase, input, _ *originalInput) { input.Command, _ = identity.NewCommandID() },
		"wrong profile":       func(_ *nativePhase, input, _ *originalInput) { input.Profile[0]++ },
		"wrong target":        func(_ *nativePhase, input, _ *originalInput) { input.ID = "another-target" },
		"wrong operation":     func(_ *nativePhase, input, _ *originalInput) { input.Operation = scim.GroupDelete },
		"changed admission":   func(_ *nativePhase, input, _ *originalInput) { input.Admission.AuthorizationEpoch++ },
		"before parent":       func(_ *nativePhase, input, _ *originalInput) { input.At = input.At.Add(-time.Microsecond) },
		"after deadline": func(_ *nativePhase, input, parent *originalInput) {
			input.At = parent.Admission.ValidUntil.Add(time.Microsecond)
		},
		"submicrosecond time": func(_ *nativePhase, input, _ *originalInput) { input.At = input.At.Add(time.Nanosecond) },
		"non UTC time":        func(_ *nativePhase, input, _ *originalInput) { input.At = input.At.In(time.FixedZone("offset", 3600)) },
		"missing generation":  func(_ *nativePhase, input, _ *originalInput) { input.Generation = 0 },
		"user authority":      func(_ *nativePhase, input, _ *originalInput) { input.UserAuthority = 1 },
		"oversized projection": func(_ *nativePhase, input, _ *originalInput) {
			input.Current.Attributes["displayName"] = strings.Repeat("x", originalPlaintextBytes)
		},
	} {
		t.Run(name, func(t *testing.T) {
			p, input, parent := bulkMutationInputCodec(t)
			change(p, &input, &parent)
			if wire, err := p.sealBulkMutationInput(context.Background(), input, parent); !errors.Is(err, identity.UnavailableError{}) || len(wire) != 0 {
				t.Fatal("invalid original input did not fail closed", err)
			}
		})
	}
	p, _, parent := bulkMutationInputCodec(t)
	for _, wire := range [][]byte{nil, []byte("invalid envelope"), make([]byte, originalCiphertextBytes+1)} {
		if got, err := p.openBulkMutationInput(context.Background(), wire, parent); !errors.Is(err, identity.UnavailableError{}) || got != (originalInput{}) {
			t.Fatal("invalid envelope did not fail closed", err)
		}
	}
}

func TestBulkMutationInputRetainsAbsenceAndExactMissingVersion(t *testing.T) {
	p, input, parent := bulkMutationInputCodec(t)
	p.intent.IfMatch = ""
	input.Current, input.Generation = nil, 0
	wire, err := p.sealBulkMutationInput(context.Background(), input, parent)
	if err != nil {
		t.Fatal("original absence could not be retained for later denial", err)
	}
	got, err := p.openBulkMutationInput(context.Background(), wire, parent)
	if err != nil || got.Current != nil || got.Generation != 0 || got.ID != input.ID {
		t.Fatal("original absence changed", err)
	}
	p.intent.IfMatch = input.Version
	if _, err := p.openBulkMutationInput(context.Background(), wire, parent); !errors.Is(err, identity.UnavailableError{}) {
		t.Fatal("missing original If-Match acquired another version", err)
	}
}
