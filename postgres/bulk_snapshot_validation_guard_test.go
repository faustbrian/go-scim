package scimpostgres

import (
	"testing"
	"time"

	kernel "github.com/faustbrian/go-identity/postgres"
	scim "github.com/faustbrian/go-scim"
)

func snapshotValidationAbort(operation scim.Operation, kind string) (*invocation, scim.PreparedWrite) {
	scope := scim.Scope{TenantID: "tenant", OrganizationID: "organization", ProviderID: "provider", ConnectionID: "connection"}
	connection := scim.Connection{Scope: scope, CredentialID: "credential", Version: 1}
	current := &scim.Resource{ID: "resource", Version: `"original"`}
	original := originalInput{
		Command: "child-command", ID: current.ID, Operation: operation,
		Version: `"next"`, Current: current,
	}
	child := &bulkChildExecution{
		parent: "parent-command", row: bulkChildRow{Command: string(original.Command)},
		original: original, ifMatch: current.Version, retainTypedValidation: true,
	}
	i := &invocation{connection: connection, bulkChild: child, prepareStarted: true}
	intent := scim.WriteIntent{
		CommandID: original.Command, Scope: scope, Connection: connection, Operation: operation,
		ResourceID: current.ID, IfMatch: current.Version, CanonicalRequest: []byte("original-patch"),
	}
	i.phase = &nativePhase{admission: *i, bulkChild: child, original: original, intent: intent}
	prepared := scim.PreparedWrite{
		Intent: intent, Current: &scim.Resource{ID: current.ID, Version: current.Version},
		Failure: scim.NewError(400, kind),
	}
	prepared.Intent.CanonicalRequest = append([]byte(nil), intent.CanonicalRequest...)
	return i, prepared
}

func TestBulkSnapshotValidationAbortCapturesExactOriginalPatch(t *testing.T) {
	for _, operation := range []scim.Operation{scim.UserPatch, scim.GroupPatch} {
		for _, failure := range []struct {
			kind string
			code kernel.FeatureFailureCode
		}{
			{kind: "noTarget", code: kernel.FeatureFailureCode(18)},
			{kind: "mutability", code: kernel.FeatureFailureSCIMBulkMutability},
		} {
			t.Run(string(operation)+"/"+failure.kind, func(t *testing.T) {
				i, prepared := snapshotValidationAbort(operation, failure.kind)
				i.observeBulkValidationAbort(prepared)
				if i.snapshotFailure != failure.code {
					t.Fatalf("exact original snapshot denial = %d, want %d", i.snapshotFailure, failure.code)
				}
			})
		}
	}
}

func TestBulkSnapshotValidationAbortRejectsUnboundObservation(t *testing.T) {
	cases := []struct {
		name   string
		change func(*invocation, *scim.PreparedWrite)
	}{
		{"missing child", func(i *invocation, _ *scim.PreparedWrite) { i.bulkChild = nil }},
		{"missing phase", func(i *invocation, _ *scim.PreparedWrite) { i.phase = nil }},
		{"detached phase", func(i *invocation, _ *scim.PreparedWrite) { i.phase = &nativePhase{} }},
		{"detached child", func(i *invocation, _ *scim.PreparedWrite) {
			child := *i.bulkChild
			i.phase.bulkChild = &child
		}},
		{"missing phase child", func(i *invocation, _ *scim.PreparedWrite) { i.phase.bulkChild = nil }},
		{"different original", func(i *invocation, _ *scim.PreparedWrite) { i.phase.original.Command = "another-command" }},
		{"typed validation disabled", func(i *invocation, _ *scim.PreparedWrite) { i.bulkChild.retainTypedValidation = false }},
		{"cyclic child", func(i *invocation, _ *scim.PreparedWrite) { i.bulkChild.row.Cyclic = true }},
		{"planner denial", func(i *invocation, _ *scim.PreparedWrite) {
			i.bulkChild.plannerDenial = kernel.FeatureFailureSCIMBulkMutability
		}},
		{"prepare not started", func(i *invocation, _ *scim.PreparedWrite) { i.prepareStarted = false }},
		{"commit attempted", func(i *invocation, _ *scim.PreparedWrite) { i.commitStarted = true }},
		{"wrong canonical bytes", func(_ *invocation, p *scim.PreparedWrite) { p.Intent.CanonicalRequest[0]++ }},
		{"wrong command", func(_ *invocation, p *scim.PreparedWrite) { p.Intent.CommandID = "another-command" }},
		{"wrong scope", func(_ *invocation, p *scim.PreparedWrite) { p.Intent.Scope.ProviderID = "another-provider" }},
		{"wrong connection", func(_ *invocation, p *scim.PreparedWrite) { p.Intent.Connection.CredentialID = "another-credential" }},
		{"wrong operation", func(_ *invocation, p *scim.PreparedWrite) { p.Intent.Operation = scim.UserReplace }},
		{"wrong target", func(_ *invocation, p *scim.PreparedWrite) { p.Intent.ResourceID = "another-resource" }},
		{"wrong ETag", func(_ *invocation, p *scim.PreparedWrite) { p.Intent.IfMatch = `"another-version"` }},
		{"wrong request key", func(_ *invocation, p *scim.PreparedWrite) { p.Intent.IdempotencyKey = "another-key" }},
		{"missing prepared current", func(_ *invocation, p *scim.PreparedWrite) { p.Current = nil }},
		{"wrong prepared current ID", func(_ *invocation, p *scim.PreparedWrite) { p.Current.ID = "another-resource" }},
		{"wrong prepared current version", func(_ *invocation, p *scim.PreparedWrite) { p.Current.Version = `"another-version"` }},
		{"missing original current", func(i *invocation, _ *scim.PreparedWrite) {
			i.phase.original.Current = nil
			i.bulkChild.original = i.phase.original
		}},
		{"stale original current", func(i *invocation, p *scim.PreparedWrite) {
			current := &scim.Resource{ID: p.Current.ID, Version: `"stale"`}
			i.phase.original.Current = current
			i.bulkChild.original = i.phase.original
			p.Current = &scim.Resource{ID: current.ID, Version: current.Version}
		}},
		{"original target mismatch", func(i *invocation, p *scim.PreparedWrite) {
			current := &scim.Resource{ID: "another-resource", Version: p.Current.Version}
			i.phase.original.Current = current
			i.bulkChild.original = i.phase.original
			p.Current = &scim.Resource{ID: current.ID, Version: current.Version}
		}},
		{"missing failure", func(_ *invocation, p *scim.PreparedWrite) { p.Failure = nil }},
		{"unsupported type", func(_ *invocation, p *scim.PreparedWrite) { p.Failure = scim.NewError(400, "invalidPath") }},
		{"pre-prepare syntax error", func(_ *invocation, p *scim.PreparedWrite) { p.Failure = scim.NewError(400, "invalidSyntax") }},
		{"untyped bad request", func(_ *invocation, p *scim.PreparedWrite) { p.Failure = scim.NewError(400, "") }},
		{"unsupported status", func(_ *invocation, p *scim.PreparedWrite) { p.Failure = scim.NewError(404, "noTarget") }},
		{"server failure", func(_ *invocation, p *scim.PreparedWrite) { p.Failure = scim.NewError(503, "") }},
		{"replay input", func(_ *invocation, p *scim.PreparedWrite) { p.Replay = &scim.WriteResult{} }},
	}
	for _, operation := range []scim.Operation{scim.UserPatch, scim.GroupPatch} {
		for _, kind := range []string{"noTarget", "mutability"} {
			for _, scenario := range cases {
				t.Run(string(operation)+"/"+kind+"/"+scenario.name, func(t *testing.T) {
					i, prepared := snapshotValidationAbort(operation, kind)
					scenario.change(i, &prepared)
					i.observeBulkValidationAbort(prepared)
					if i.snapshotFailure != 0 {
						t.Fatalf("unbound snapshot denial captured failure %d", i.snapshotFailure)
					}
				})
			}
		}
	}
}

func TestBulkSnapshotValidationAbortRejectsNoTargetOutsidePatch(t *testing.T) {
	for _, operation := range []scim.Operation{
		scim.UserCreate, scim.GroupCreate, scim.UserGet, scim.GroupGet,
		scim.UserReplace, scim.GroupReplace, scim.UserDelete, scim.GroupDelete, scim.Bulk, bulkInvalidChild,
	} {
		t.Run(string(operation), func(t *testing.T) {
			i, prepared := snapshotValidationAbort(operation, "noTarget")
			i.observeBulkValidationAbort(prepared)
			if i.snapshotFailure != 0 {
				t.Fatalf("non-PATCH operation captured noTarget failure %d", i.snapshotFailure)
			}
		})
	}
}

func TestBulkSnapshotValidationAbortCapturesOnlyExactCreatePreviewFailure(t *testing.T) {
	cases := []struct {
		name   string
		change func(*invocation, *scim.PreparedWrite)
		want   kernel.FeatureFailureCode
	}{
		{name: "exact invalidValue", want: kernel.FeatureFailureCode(13)},
		{name: "substituted ID", change: func(_ *invocation, p *scim.PreparedWrite) { p.CreateMetadata.ID = "another-resource" }},
		{name: "substituted version", change: func(_ *invocation, p *scim.PreparedWrite) { p.CreateMetadata.Version = `"another-version"` }},
		{name: "substituted creation date", change: func(_ *invocation, p *scim.PreparedWrite) {
			p.CreateMetadata.CreatedAt = p.CreateMetadata.CreatedAt.Add(time.Second)
		}},
		{name: "substituted modification date", change: func(_ *invocation, p *scim.PreparedWrite) {
			p.CreateMetadata.LastModified = p.CreateMetadata.LastModified.Add(time.Second)
		}},
		{name: "missing metadata", change: func(_ *invocation, p *scim.PreparedWrite) { p.CreateMetadata = nil }},
		{name: "unexpected current", change: func(_ *invocation, p *scim.PreparedWrite) { p.Current = &scim.Resource{} }},
		{name: "unexpected update metadata", change: func(_ *invocation, p *scim.PreparedWrite) { p.UpdateMetadata = &scim.UpdateMetadata{} }},
		{name: "commit attempted", change: func(i *invocation, _ *scim.PreparedWrite) { i.commitStarted = true }},
		{name: "mutability", change: func(_ *invocation, p *scim.PreparedWrite) { p.Failure = scim.NewError(400, "mutability") }},
	}
	for _, operation := range []scim.Operation{scim.UserCreate, scim.GroupCreate} {
		for _, scenario := range cases {
			t.Run(string(operation)+"/"+scenario.name, func(t *testing.T) {
				i, prepared := snapshotValidationAbort(operation, "invalidValue")
				i.phase.original.Current = nil
				i.phase.original.At = time.Date(2026, time.November, 26, 12, 0, 0, 0, time.UTC)
				i.bulkChild.original = i.phase.original
				i.bulkChild.row.Resource = i.phase.original.ID
				i.bulkChild.ifMatch = ""
				i.phase.intent.ResourceID, i.phase.intent.IfMatch = "", ""
				i.phase.intent.CanonicalRequest = []byte("original-create")
				prepared.Intent = i.phase.intent
				prepared.Current = nil
				prepared.CreateMetadata = &scim.CreateMetadata{
					ID: i.phase.original.ID, Version: i.phase.original.Version,
					CreatedAt: i.phase.original.At, LastModified: i.phase.original.At,
				}
				if scenario.change != nil {
					scenario.change(i, &prepared)
				}
				i.observeBulkValidationAbort(prepared)
				if i.snapshotFailure != scenario.want {
					t.Fatalf("create preview failure = %d, want %d", i.snapshotFailure, scenario.want)
				}
			})
		}
	}
}
