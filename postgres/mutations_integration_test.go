//go:build integration

package scimpostgres

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	authentication "github.com/faustbrian/go-authentication/v2"
	"github.com/faustbrian/go-authorization/v3"
	identity "github.com/faustbrian/go-identity"
	kernel "github.com/faustbrian/go-identity/postgres"
	database "github.com/faustbrian/go-postgres"
	scim "github.com/faustbrian/go-scim"
)

type nativeUserDocument struct {
	ID          string `json:"id"`
	UserName    string `json:"userName"`
	DisplayName string `json:"displayName"`
	Active      *bool  `json:"active"`
	Meta        struct {
		Created, LastModified string
		Version               scim.Version
	} `json:"meta"`
}

func parseNativeUser(t *testing.T, response scim.Response) nativeUserDocument {
	t.Helper()
	var user nativeUserDocument
	if json.Unmarshal(response.Body, &user) != nil || user.ID == "" || user.Meta.Version == "" || user.Meta.Version != response.ETag {
		t.Fatal("invalid native user response", response.Status)
	}
	return user
}

func assertNativeMappedFields(t *testing.T, f *nativeFixture, id, name, display string) {
	t.Helper()
	reader, err := kernel.NewRepository(f.pool, kernel.Config{MaximumDuration: time.Second, AttributeSchemas: []identity.AttributeSchema{f.config.FieldSchema}, ProfileSchema: kernel.ProfileSchemaRef{ID: f.config.FieldSchema.ID, Version: f.config.FieldSchema.Version}})
	if err != nil {
		t.Fatal(err)
	}
	profile, err := reader.GetProfile(f.ctx, identity.ProfileQuery{TenantID: f.config.Scope.TenantID, UserID: identity.UserID(id)})
	if err != nil {
		t.Fatal("actual updated kernel profile", err)
	}
	fields := map[string]string{}
	for _, field := range profile.Profile.AdditionalFields {
		if field.Value.Kind != identity.AttributeString || field.Value.Scalar.Kind != identity.AttributeString {
			t.Fatal("mapped kernel field lost its declared type")
		}
		fields[field.Name] = field.Value.Scalar.String
	}
	if fields[f.config.UserNameField] != name || fields[f.config.DisplayNameField] != display {
		t.Fatal("SCIM mutation did not atomically update actual native fields")
	}
}

func TestNativeUsersReplacePatchReplayAndPreconditions(t *testing.T) {
	f := newNativeFixture(t)
	id := createNativeNamed(t, f, "OriginalName", "Original display")
	get := scim.Request{Operation: scim.UserGet, Credential: f.bearer, ResourceID: id}
	initial, err := f.service.Execute(f.ctx, get)
	if err != nil {
		t.Fatal(err)
	}
	before := parseNativeUser(t, initial)
	replace := scim.Request{Operation: scim.UserReplace, Credential: f.bearer, ResourceID: id, IfMatch: initial.ETag, IdempotencyKey: "replace-original", ContentType: "application/scim+json", Body: []byte(`{"schemas":["urn:ietf:params:scim:schemas:core:2.0:User"],"userName":"Renamed","displayName":"Replacement display","externalId":"correlation-after-replace"}`)}
	replaced, err := f.service.Execute(f.ctx, replace)
	if err != nil || replaced.Status != 200 || replaced.ETag == initial.ETag {
		t.Fatal("native replacement did not create a new strong version", err)
	}
	after := parseNativeUser(t, replaced)
	if after.ID != id || after.UserName != "Renamed" || after.DisplayName != "Replacement display" || after.Meta.Created != before.Meta.Created {
		t.Fatal("replacement changed identity/creation or omitted native fields")
	}
	assertNativeMappedFields(t, f, id, "Renamed", "Replacement display")
	if replayed, err := f.service.Execute(f.ctx, replace); err != nil || replayed.ETag != replaced.ETag || string(replayed.Body) != string(replaced.Body) {
		t.Fatal("replacement retry re-evaluated stale original precondition", err)
	}
	changedKey := replace
	changedKey.Body = []byte(`{"schemas":["urn:ietf:params:scim:schemas:core:2.0:User"],"userName":"ChangedSameKey"}`)
	if _, err := f.service.Execute(f.ctx, changedKey); protocolStatus(err) != 409 {
		t.Fatal("changed replacement input reused its admitted command", err)
	}
	for _, version := range []scim.Version{"", initial.ETag, `"valid-but-unknown"`} {
		stale := replace
		stale.IdempotencyKey = ""
		stale.IfMatch = version
		want := 412
		if version == "" {
			want = 428
		}
		if response, err := f.service.Execute(f.ctx, stale); protocolStatus(err) != want || len(response.Body) != 0 {
			t.Fatal("missing/stale If-Match did not deny without values", want, err)
		}
	}
	unknown := replace
	unknown.ResourceID, unknown.IdempotencyKey = "opaque-unknown-user", "unknown-target"
	for range 2 {
		if response, err := f.service.Execute(f.ctx, unknown); protocolStatus(err) != 404 || len(response.Body) != 0 {
			t.Fatal("unknown opaque target did not retain original not-found response", err)
		}
	}
	patch := scim.Request{Operation: scim.UserPatch, Credential: f.bearer, ResourceID: id, IfMatch: replaced.ETag, IdempotencyKey: "patch-original", ContentType: "application/scim+json", Body: []byte(`{"schemas":["urn:ietf:params:scim:api:messages:2.0:PatchOp"],"Operations":[{"op":"replace","path":"displayName","value":"Patched display"}]}`)}
	patched, err := f.service.Execute(f.ctx, patch)
	if err != nil || patched.Status != 200 || patched.ETag == replaced.ETag {
		t.Fatal("native patch did not commit a new version", err)
	}
	assertNativeMappedFields(t, f, id, "Renamed", "Patched display")
	if replayed, err := f.service.Execute(f.ctx, replace); err != nil || replayed.ETag != replaced.ETag || string(replayed.Body) != string(replaced.Body) {
		t.Fatal("later mutation overwrote original replacement semantic result", err)
	}
	if replayed, err := f.service.Execute(f.ctx, patch); err != nil || replayed.ETag != patched.ETag || string(replayed.Body) != string(patched.Body) {
		t.Fatal("patch replay changed original semantic result", err)
	}
	noop := patch
	noop.IfMatch, noop.IdempotencyKey = patched.ETag, "noop-patch"
	beforeNoop, err := f.service.directory.Get(f.ctx, identity.GetUserQuery{TenantID: f.config.Scope.TenantID, UserID: identity.UserID(id)})
	if err != nil {
		t.Fatal(err)
	}
	unchanged, err := f.service.Execute(f.ctx, noop)
	if err != nil || unchanged.ETag != patched.ETag || string(unchanged.Body) != string(patched.Body) {
		t.Fatal("no-op PATCH changed version/modification time", err)
	}
	afterNoop, err := f.service.directory.Get(f.ctx, identity.GetUserQuery{TenantID: f.config.Scope.TenantID, UserID: identity.UserID(id)})
	if err != nil || afterNoop.Version != beforeNoop.Version || afterNoop.Status != beforeNoop.Status {
		t.Fatal("no-op PATCH falsely incremented core user version or changed global status", err)
	}
	invalid := noop
	invalid.IdempotencyKey = "invalid-multi-operation"
	invalid.Body = []byte(`{"schemas":["urn:ietf:params:scim:api:messages:2.0:PatchOp"],"Operations":[{"op":"replace","path":"displayName","value":"Must not commit"},{"op":"remove","path":"userName"}]}`)
	if response, err := f.service.Execute(f.ctx, invalid); err == nil || len(response.Body) != 0 {
		t.Fatal("invalid later PATCH operation returned success", err)
	}
	read, err := f.service.Execute(f.ctx, get)
	if err != nil || read.ETag != patched.ETag || string(read.Body) != string(patched.Body) {
		t.Fatal("invalid PATCH partially changed protocol projection", err)
	}
	assertNativeMappedFields(t, f, id, "Renamed", "Patched display")
}

func TestNativeUsersLargePatchUsesRootRequestBudgetNotStoredResourceBudget(t *testing.T) {
	f := newNativeFixture(t)
	initial, err := f.service.Execute(f.ctx, scim.Request{Operation: scim.UserCreate, Credential: f.bearer, ContentType: "application/scim+json", Body: []byte(`{"schemas":["urn:ietf:params:scim:schemas:core:2.0:User"],"userName":"LargePatchBudget","displayName":"Unchanged mapped value","name":{"formatted":"Before"}}`)})
	if err != nil || initial.Status != 201 {
		t.Fatal(err)
	}
	id := parseNativeUser(t, initial).ID
	final := strings.Repeat("z", 50000)
	operations := []map[string]any{
		{"op": "replace", "path": "name.formatted", "value": strings.Repeat("x", 50000)},
		{"op": "replace", "path": "name.formatted", "value": strings.Repeat("y", 50000)},
		{"op": "replace", "path": "name.formatted", "value": final},
	}
	body, err := json.Marshal(map[string]any{"schemas": []string{"urn:ietf:params:scim:api:messages:2.0:PatchOp"}, "Operations": operations})
	if err != nil || len(body) <= 131072 || len(body) >= f.config.Limits.BodyBytes {
		t.Fatal("fixture did not distinguish request and stored-resource budgets", len(body), err)
	}
	request := scim.Request{Operation: scim.UserPatch, Credential: f.bearer, ResourceID: id, IfMatch: initial.ETag, IdempotencyKey: "large-valid-patch", ContentType: "application/scim+json", Body: body}
	response, err := f.service.Execute(f.ctx, request)
	if err != nil || response.Status != 200 || response.ETag == initial.ETag {
		t.Fatal("root-valid bounded PATCH was rejected by a stored-resource request cap", protocolStatus(err), err)
	}
	var document struct {
		ID   string                     `json:"id"`
		Name struct{ Formatted string } `json:"name"`
	}
	if json.Unmarshal(response.Body, &document) != nil || document.ID != id || document.Name.Formatted != final {
		t.Fatal("large PATCH did not retain its final bounded projection")
	}
	if replay, err := f.service.Execute(f.ctx, request); err != nil || replay.ETag != response.ETag || !bytes.Equal(replay.Body, response.Body) {
		t.Fatal("large canonical request did not retain its original response", err)
	}
	var storedBytes int
	var generation int64
	var deleted *time.Time
	if err := f.pool.Raw().QueryRow(f.ctx, `SELECT octet_length(resource),generation,deleted_at FROM scim.users WHERE resource_id=$1`, id).Scan(&storedBytes, &generation, &deleted); err != nil || storedBytes <= 50000 || storedBytes > 131072 || generation != 2 || deleted != nil {
		t.Fatal("large request bypassed the independent stored-resource bound", storedBytes, generation, err)
	}
	user, err := f.service.directory.Get(f.ctx, identity.GetUserQuery{TenantID: f.config.Scope.TenantID, UserID: identity.UserID(id)})
	if err != nil || user.Version != 1 || user.Status != identity.StatusActive {
		t.Fatal("projection-only large PATCH invented a core mutation", err)
	}
}

func TestNativeUsersDeleteReplaysAfterTombstonePurgeWithoutDeletingKernel(t *testing.T) {
	f := newNativeFixture(t)
	create := scim.Request{Operation: scim.UserCreate, Credential: f.bearer, IdempotencyKey: "create-before-delete", ContentType: "application/scim+json", Body: []byte(`{"schemas":["urn:ietf:params:scim:schemas:core:2.0:User"],"userName":"DeletedScopedUser","displayName":"Retained original"}`)}
	created, err := f.service.Execute(f.ctx, create)
	if err != nil {
		t.Fatal(err)
	}
	user := parseNativeUser(t, created)
	remove := scim.Request{Operation: scim.UserDelete, Credential: f.bearer, ResourceID: user.ID, IfMatch: created.ETag}
	assertRemoved := func(request scim.Request) {
		t.Helper()
		response, err := f.service.Execute(f.ctx, request)
		if err != nil || response.Status != 204 || len(response.Body) != 0 {
			t.Fatal("same original DELETE did not return its successful empty result", err)
		}
	}
	assertRemoved(remove)
	assertRemoved(remove)
	remove.IdempotencyKey = "late-delete-key"
	assertRemoved(remove)
	var deletes int
	if err := f.pool.Raw().QueryRow(f.ctx, `SELECT count(*) FROM identity.commands WHERE purpose=$1 AND state='committed'`, string(scim.UserDelete)).Scan(&deletes); err != nil || deletes != 1 {
		t.Fatal("canonical and late-key DELETE did not share one actual journal command", deletes, err)
	}
	var generation int64
	var wire []byte
	var external, username string
	var deleted *time.Time
	if err := f.pool.Raw().QueryRow(f.ctx, `SELECT generation,resource,external_id,username_key,deleted_at FROM scim.users WHERE resource_id=$1`, user.ID).Scan(&generation, &wire, &external, &username, &deleted); err != nil || generation != 2 || string(wire) != "null" || external != "" || username == user.UserName || deleted == nil {
		t.Fatal("DELETE did not leave a redacted nonresurrectable scoped tombstone", err)
	}
	kernelUser, err := f.service.directory.Get(f.ctx, identity.GetUserQuery{TenantID: f.config.Scope.TenantID, UserID: identity.UserID(user.ID)})
	if err != nil || kernelUser.Status != identity.StatusActive || kernelUser.Version != 1 {
		t.Fatal("SCIM DELETE performed unselected global identity lifecycle effects", err)
	}
	get := scim.Request{Operation: scim.UserGet, Credential: f.bearer, ResourceID: user.ID}
	if response, err := f.service.Execute(f.ctx, get); protocolStatus(err) != 404 || len(response.Body) != 0 {
		t.Fatal("deleted scoped projection remained readable", err)
	}
	response, err := f.service.Execute(f.ctx, scim.Request{Operation: scim.UserList, Credential: f.bearer})
	if err != nil || readNativeList(t, response).TotalResults != 0 {
		t.Fatal("deleted scoped projection remained in exact query totals", err)
	}
	changed := remove
	version, err := identity.NewCommandID()
	if err != nil {
		t.Fatal(err)
	}
	changed.IfMatch = scim.Version(`"` + string(version) + `"`)
	if _, err := f.service.Execute(f.ctx, changed); protocolStatus(err) != 409 {
		t.Fatal("late optional key accepted a changed DELETE precondition", err)
	}
	// This fixture alone owns these rows. Expire only its completed tombstone;
	// retained kernel command/admission remains the sole replay authority.
	if _, err := f.pool.Raw().Exec(f.ctx, `DELETE FROM scim.users WHERE resource_id=$1 AND deleted_at IS NOT NULL`, user.ID); err != nil {
		t.Fatal("expire owned terminal tombstone", err)
	}
	assertRemoved(remove)
	remove.IdempotencyKey = ""
	assertRemoved(remove)
	if replayed, err := f.service.Execute(f.ctx, create); err != nil || replayed.ETag != created.ETag || string(replayed.Body) != string(created.Body) {
		t.Fatal("tombstone expiry erased original committed create response", err)
	}
	if _, err := f.service.Execute(f.ctx, get); protocolStatus(err) != 404 {
		t.Fatal("historical replay resurrected deleted projection", err)
	}
	f.deny.Store(true)
	if response, err := f.service.Execute(f.ctx, remove); err == nil || len(response.Body) != 0 {
		t.Fatal("current policy withdrawal disclosed historical DELETE success")
	}
}

func TestNativeUsersCoreProjectionAndInactiveFlagAreNotGlobalDeprovisioning(t *testing.T) {
	f := newNativeFixture(t)
	request := scim.Request{Operation: scim.UserCreate, Credential: f.bearer, ContentType: "application/scim+json", Body: []byte(`{"schemas":["urn:ietf:params:scim:schemas:core:2.0:User"],"userName":"ScopedInactive","displayName":"Initial display","active":false,"name":{"givenName":"Initial","familyName":"Person"},"emails":[{"value":"projection@example.test","primary":true}]}`)}
	created, err := f.service.Execute(f.ctx, request)
	if err != nil || created.Status != 201 {
		t.Fatal("core SCIM projection/inactive creation was not supported", err)
	}
	user := parseNativeUser(t, created)
	if user.Active == nil || *user.Active {
		t.Fatal("SCIM inactive flag was discarded")
	}
	kernelUser, err := f.service.directory.Get(f.ctx, identity.GetUserQuery{TenantID: f.config.Scope.TenantID, UserID: identity.UserID(user.ID)})
	if err != nil || kernelUser.Status != identity.StatusActive {
		t.Fatal("SCIM flag silently selected global suspension", err)
	}
	var identifiers int
	if err := f.pool.Raw().QueryRow(f.ctx, `SELECT count(*) FROM identity.identifiers`).Scan(&identifiers); err != nil || identifiers != 0 {
		t.Fatal("SCIM email projection became an account/verified identifier", err)
	}
	patch := scim.Request{Operation: scim.UserPatch, Credential: f.bearer, ResourceID: user.ID, IfMatch: created.ETag, ContentType: "application/scim+json", Body: []byte(`{"schemas":["urn:ietf:params:scim:api:messages:2.0:PatchOp"],"Operations":[{"op":"replace","path":"active","value":true},{"op":"remove","path":"displayName"},{"op":"replace","path":"emails[primary eq true].value","value":"changed@example.test"}]}`)}
	updated, err := f.service.Execute(f.ctx, patch)
	if err != nil || updated.Status != 200 || updated.ETag == created.ETag {
		t.Fatal("native multi-valued/core PATCH did not complete", err)
	}
	view := parseNativeUser(t, updated)
	if view.Active == nil || !*view.Active || view.DisplayName != "" {
		t.Fatal("SCIM flag/removal did not match its accepted PATCH")
	}
	assertNativeMappedFields(t, f, user.ID, "ScopedInactive", "")
	filtered, err := f.service.Execute(f.ctx, scim.Request{Operation: scim.UserList, Credential: f.bearer, Query: scim.Query{Filter: `emails[value eq "changed@example.test"] and active eq true`}})
	if err != nil || readNativeList(t, filtered).TotalResults != 1 {
		t.Fatal("multi-valued SCIM comparison was not applied to stored native projections", err)
	}
}

func TestNativeUsersLostMutationCommitReplaysOriginalAfterLaterWrite(t *testing.T) {
	f := newNativeFixture(t)
	id := createNativeNamed(t, f, "AmbiguousMutation", "Before mutation")
	get := scim.Request{Operation: scim.UserGet, Credential: f.bearer, ResourceID: id}
	initial, err := f.service.Execute(f.ctx, get)
	if err != nil {
		t.Fatal(err)
	}
	fault := new(nativeCommitFault)
	pool, err := database.Connect(f.ctx, database.Config{DSN: os.Getenv("SCIM_POSTGRES_TEST_DSN"), MaxConns: 3, Configure: func(c *database.PoolConfig) error {
		c.ConnConfig.Database = f.pool.Raw().Config().ConnConfig.Database
		c.ConnConfig.DialFunc = fault.dial
		return nil
	}})
	if err != nil {
		t.Fatal("owned mutation fault pool", err)
	}
	defer func() {
		cleanup, stop := context.WithTimeout(context.Background(), 3*time.Second)
		defer stop()
		if err := pool.Close(cleanup); err != nil {
			t.Error("mutation fault pool cleanup", err)
		}
	}()
	service, err := NewService(pool, f.config, f.keys)
	if err != nil {
		t.Fatal(err)
	}
	patch := scim.Request{Operation: scim.UserPatch, Credential: f.bearer, ResourceID: id, IfMatch: initial.ETag, IdempotencyKey: "ambiguous-patch", ContentType: "application/scim+json", Body: []byte(`{"schemas":["urn:ietf:params:scim:api:messages:2.0:PatchOp"],"Operations":[{"op":"replace","path":"displayName","value":"First mutation"}]}`)}
	if response, err := service.Execute(f.ctx, patch); protocolStatus(err) != 503 || len(response.Body) != 0 || !fault.hit.Load() {
		t.Fatal("actual mutation domain COMMIT acknowledgement was not lost", err)
	}
	original, err := f.service.Execute(f.ctx, patch)
	if err != nil || original.Status != 200 || original.ETag == initial.ETag {
		t.Fatal("ambiguous mutation did not recover original committed response", err)
	}
	assertNativeMappedFields(t, f, id, "AmbiguousMutation", "First mutation")
	later := patch
	later.IfMatch, later.IdempotencyKey = original.ETag, "later-patch"
	later.Body = []byte(`{"schemas":["urn:ietf:params:scim:api:messages:2.0:PatchOp"],"Operations":[{"op":"replace","path":"displayName","value":"Later mutation"}]}`)
	current, err := f.service.Execute(f.ctx, later)
	if err != nil || current.ETag == original.ETag {
		t.Fatal("subsequent independent mutation", err)
	}
	if replay, err := f.service.Execute(f.ctx, patch); err != nil || replay.ETag != original.ETag || string(replay.Body) != string(original.Body) {
		t.Fatal("later state replaced ambiguous command's original response", err)
	}
	assertNativeMappedFields(t, f, id, "AmbiguousMutation", "Later mutation")
}

func TestNativeUsersKeyedDeleteAndHeaderlessRetryUseOneCanonicalCommand(t *testing.T) {
	f := newNativeFixture(t)
	id := createNativeNamed(t, f, "KeyedFirstDelete", "Scoped projection")
	read, err := f.service.Execute(f.ctx, scim.Request{Operation: scim.UserGet, Credential: f.bearer, ResourceID: id})
	if err != nil {
		t.Fatal(err)
	}
	request := scim.Request{Operation: scim.UserDelete, Credential: f.bearer, ResourceID: id, IfMatch: read.ETag, IdempotencyKey: "first-delete-key"}
	for _, key := range []string{"first-delete-key", "", "second-delete-alias", "first-delete-key"} {
		request.IdempotencyKey = key
		response, err := f.service.Execute(f.ctx, request)
		if err != nil || response.Status != 204 || len(response.Body) != 0 {
			t.Fatal("keyed-first and headerless DELETE did not recover one original response", err)
		}
	}
	var commands int
	if err := f.pool.Raw().QueryRow(f.ctx, `SELECT count(*) FROM identity.commands WHERE purpose=$1 AND state='committed'`, string(scim.UserDelete)).Scan(&commands); err != nil || commands != 1 {
		t.Fatal("DELETE lookup variants allocated more than one actual kernel command", commands, err)
	}
}

func TestNativeUsersDeleteChangedQueryConflictsWithinOriginalCanonicalTarget(t *testing.T) {
	f := newNativeFixture(t)
	id := createNativeNamed(t, f, "CanonicalTarget", "Original delete selector")
	initial, err := f.service.Execute(f.ctx, scim.Request{Operation: scim.UserGet, Credential: f.bearer, ResourceID: id})
	if err != nil {
		t.Fatal(err)
	}
	remove := scim.Request{Operation: scim.UserDelete, Credential: f.bearer, ResourceID: id, IfMatch: initial.ETag}
	if response, err := f.service.Execute(f.ctx, remove); err != nil || response.Status != 204 {
		t.Fatal("initial canonical DELETE", err)
	}
	changed := remove
	changed.Query.Attributes = "id"
	if response, err := f.service.Execute(f.ctx, changed); protocolStatus(err) != 409 || len(response.Body) != 0 {
		t.Fatal("changed full intent allocated another selector instead of conflicting with original target", protocolStatus(err), err)
	}
	if response, err := f.service.Execute(f.ctx, remove); err != nil || response.Status != 204 {
		t.Fatal("changed-intent conflict replaced original successful DELETE", err)
	}
	var mappings int
	if err := f.pool.Raw().QueryRow(f.ctx, `SELECT count(*) FROM identity.request_key_mappings WHERE route_id=$1`, string(scim.UserDelete)).Scan(&mappings); err != nil || mappings != 1 {
		t.Fatal("changed full intent created another original command mapping", mappings, err)
	}
}

func TestNativeUsersTerminalUniquenessFailureReplaysAfterConflictingResourceDeletion(t *testing.T) {
	f := newNativeFixture(t)
	id := createNativeNamed(t, f, "TerminalConflict", "Existing owner")
	duplicate := scim.Request{Operation: scim.UserCreate, Credential: f.bearer, IdempotencyKey: "terminal-conflict-original", ContentType: "application/scim+json", Body: []byte(`{"schemas":["urn:ietf:params:scim:schemas:core:2.0:User"],"userName":"TerminalConflict","displayName":"Rejected duplicate"}`)}
	var originalFailure []byte
	for attempt := range 2 {
		response, err := f.service.Execute(f.ctx, duplicate)
		t.Log("terminal uniqueness attempt/status", attempt+1, protocolStatus(err))
		if protocolStatus(err) != 409 || len(response.Body) != 0 {
			t.Fatal("original terminal uniqueness failure was not retained", "attempt", attempt+1, protocolStatus(err), err)
		}
		encoded, encodeErr := json.Marshal(err)
		if encodeErr != nil {
			t.Fatal("original protocol failure serialization", encodeErr)
		}
		if attempt == 0 {
			originalFailure = encoded
		} else if !bytes.Equal(originalFailure, encoded) {
			t.Fatal("terminal retry changed original protocol failure status/type")
		}
	}
	initial, err := f.service.Execute(f.ctx, scim.Request{Operation: scim.UserGet, Credential: f.bearer, ResourceID: id})
	if err != nil {
		t.Fatal(err)
	}
	if response, err := f.service.Execute(f.ctx, scim.Request{Operation: scim.UserDelete, Credential: f.bearer, ResourceID: id, IfMatch: initial.ETag}); err != nil || response.Status != 204 {
		t.Fatal("delete original conflicting resource", err)
	}
	response, err := f.service.Execute(f.ctx, duplicate)
	if protocolStatus(err) != 409 || len(response.Body) != 0 {
		t.Fatal("later availability erased original terminal failure", protocolStatus(err), err)
	}
	encoded, encodeErr := json.Marshal(err)
	if encodeErr != nil || !bytes.Equal(originalFailure, encoded) {
		t.Fatal("later resource deletion changed original protocol failure status/type", encodeErr)
	}
	var users, live int
	if err := f.pool.Raw().QueryRow(f.ctx, `SELECT (SELECT count(*) FROM identity.users),(SELECT count(*) FROM scim.users WHERE deleted_at IS NULL)`).Scan(&users, &live); err != nil || users != 1 || live != 0 {
		t.Fatal("terminal failure retry provisioned new effects", users, live, err)
	}
}

func TestNativeUsersLosingWriterRetainsPreconditionAfterTargetDeletion(t *testing.T) {
	f := newNativeFixture(t)
	id := createNativeNamed(t, f, "CompetingPatches", "Before writers")
	initial, err := f.service.Execute(f.ctx, scim.Request{Operation: scim.UserGet, Credential: f.bearer, ResourceID: id})
	if err != nil {
		t.Fatal(err)
	}
	prepared, release, finished := make(chan struct{}), make(chan struct{}), make(chan struct{})
	var entered, unblocked sync.Once
	unblock := func() { unblocked.Do(func() { close(release) }) }
	defer unblock()
	c := f.config
	underlying := c.Authorization
	c.Authorization = configuredPolicy(func(ctx context.Context, decision authorization.DecisionContext) (authorization.Decision, error) {
		i, _ := currentInvocation(ctx)
		if decision.Request.Action == authorization.Action(scim.UserPatch) && decision.Request.Resource.Type == "identity.scim.user" && i != nil && i.phase != nil {
			entered.Do(func() {
				close(prepared)
				select {
				case <-release:
				case <-ctx.Done():
				}
			})
		}
		return underlying.Decide(ctx, decision)
	})
	service, err := NewService(f.pool, c, f.keys)
	if err != nil {
		t.Fatal(err)
	}
	loser := scim.Request{Operation: scim.UserPatch, Credential: f.bearer, ResourceID: id, IfMatch: initial.ETag, IdempotencyKey: "original-losing-patch", ContentType: "application/scim+json", Body: []byte(`{"schemas":["urn:ietf:params:scim:api:messages:2.0:PatchOp"],"Operations":[{"op":"replace","path":"displayName","value":"Rejected loser"}]}`)}
	result := make(chan executionResult, 1)
	go func() {
		defer close(finished)
		response, err := service.Execute(f.ctx, loser)
		result <- executionResult{response, err}
	}()
	defer func() {
		unblock()
		select {
		case <-finished:
		case <-f.ctx.Done():
			t.Error("losing writer did not terminate")
		}
	}()
	select {
	case <-prepared:
	case got := <-result:
		t.Fatal("actual losing writer preparation was not reached", got.err)
	case <-f.ctx.Done():
		t.Fatal("losing writer preparation did not arrive")
	}
	winner := loser
	winner.IdempotencyKey = "winning-patch"
	winner.Body = []byte(`{"schemas":["urn:ietf:params:scim:api:messages:2.0:PatchOp"],"Operations":[{"op":"replace","path":"displayName","value":"Committed winner"}]}`)
	committed, err := f.service.Execute(f.ctx, winner)
	if err != nil || committed.Status != 200 || committed.ETag == initial.ETag {
		t.Fatal("competing genuine writer did not commit", err)
	}
	unblock()
	var originalFailure []byte
	select {
	case got := <-result:
		t.Log("prepared losing writer status", protocolStatus(got.err))
		if protocolStatus(got.err) != 412 || len(got.response.Body) != 0 {
			t.Fatal("prepared stale writer lost its actual precondition condition", protocolStatus(got.err), got.err)
		}
		originalFailure, err = json.Marshal(got.err)
		if err != nil {
			t.Fatal("original precondition serialization", err)
		}
	case <-f.ctx.Done():
		t.Fatal("losing writer did not finish")
	}
	assertRejected := func() {
		t.Helper()
		response, failure := f.service.Execute(f.ctx, loser)
		encoded, encodeErr := json.Marshal(failure)
		if protocolStatus(failure) != 412 || len(response.Body) != 0 || encodeErr != nil || !bytes.Equal(encoded, originalFailure) {
			t.Fatal("original losing-writer failure was not retained", protocolStatus(failure), failure)
		}
	}
	assertRejected()
	assertNativeMappedFields(t, f, id, "CompetingPatches", "Committed winner")
	if response, err := f.service.Execute(f.ctx, scim.Request{Operation: scim.UserDelete, Credential: f.bearer, ResourceID: id, IfMatch: committed.ETag}); err != nil || response.Status != 204 {
		t.Fatal("delete winning projection", err)
	}
	assertRejected()
	var committedPatches, rejectedPatches, notifications int
	if err := f.pool.Raw().QueryRow(f.ctx, `SELECT
 (SELECT count(*) FROM identity.commands WHERE purpose=$1 AND state='committed'),
 (SELECT count(*) FROM identity.commands WHERE purpose=$1 AND state='aborted'),
 (SELECT count(*) FROM public.identity_outbox_bindings o JOIN identity.commands c USING(command_id) WHERE c.purpose=$1)`, string(scim.UserPatch)).Scan(&committedPatches, &rejectedPatches, &notifications); err != nil || committedPatches != 1 || rejectedPatches != 1 || notifications != 1 {
		t.Fatal("losing writer duplicated or omitted actual command/effect ownership", committedPatches, rejectedPatches, notifications, err)
	}
	kernelUser, err := f.service.directory.Get(f.ctx, identity.GetUserQuery{TenantID: f.config.Scope.TenantID, UserID: identity.UserID(id)})
	if err != nil || kernelUser.Version != 2 || kernelUser.Status != identity.StatusActive {
		t.Fatal("losing writer or scoped deletion changed the winning core version/status", err)
	}
}

func TestNativeUsersLostDeleteCommitRecoversEmptyOriginalWithoutResurrection(t *testing.T) {
	f := newNativeFixture(t)
	id := createNativeNamed(t, f, "AmbiguousDelete", "Before deletion")
	get := scim.Request{Operation: scim.UserGet, Credential: f.bearer, ResourceID: id}
	initial, err := f.service.Execute(f.ctx, get)
	if err != nil {
		t.Fatal(err)
	}
	fault := new(nativeCommitFault)
	pool, err := database.Connect(f.ctx, database.Config{DSN: os.Getenv("SCIM_POSTGRES_TEST_DSN"), MaxConns: 3, Configure: func(c *database.PoolConfig) error {
		c.ConnConfig.Database = f.pool.Raw().Config().ConnConfig.Database
		c.ConnConfig.DialFunc = fault.dial
		return nil
	}})
	if err != nil {
		t.Fatal("owned delete fault pool", err)
	}
	defer func() {
		cleanup, stop := context.WithTimeout(context.Background(), 3*time.Second)
		defer stop()
		if err := pool.Close(cleanup); err != nil {
			t.Error("delete fault pool cleanup", err)
		}
	}()
	service, err := NewService(pool, f.config, f.keys)
	if err != nil {
		t.Fatal(err)
	}
	remove := scim.Request{Operation: scim.UserDelete, Credential: f.bearer, ResourceID: id, IfMatch: initial.ETag}
	if response, err := service.Execute(f.ctx, remove); protocolStatus(err) != 503 || len(response.Body) != 0 || !fault.hit.Load() {
		t.Fatal("actual DELETE domain COMMIT acknowledgement was not lost", err)
	}
	if _, err := f.service.Execute(f.ctx, get); protocolStatus(err) != 404 {
		t.Fatal("ambiguous committed deletion did not retain its atomic tombstone", err)
	}
	for _, key := range []string{"", "late-ambiguous-delete-key", ""} {
		remove.IdempotencyKey = key
		if response, err := f.service.Execute(f.ctx, remove); err != nil || response.Status != 204 || len(response.Body) != 0 {
			t.Fatal("ambiguous DELETE did not recover its original empty response", err)
		}
	}
	var commands, audits, notifications int
	if err := f.pool.Raw().QueryRow(f.ctx, `SELECT
 (SELECT count(*) FROM identity.commands WHERE purpose=$1 AND state='committed'),
 (SELECT count(*) FROM audit.identity_command_bindings a JOIN identity.commands c USING(command_id) WHERE c.purpose=$1 AND c.state='committed'),
 (SELECT count(*) FROM public.identity_outbox_bindings o JOIN identity.commands c USING(command_id) WHERE c.purpose=$1 AND c.state='committed')`, string(scim.UserDelete)).Scan(&commands, &audits, &notifications); err != nil || commands != 1 || audits != 1 || notifications != 1 {
		t.Fatal("ambiguous DELETE duplicated or omitted actual owned effects", commands, audits, notifications, err)
	}
	kernelUser, err := f.service.directory.Get(f.ctx, identity.GetUserQuery{TenantID: f.config.Scope.TenantID, UserID: identity.UserID(id)})
	if err != nil || kernelUser.Status != identity.StatusActive || kernelUser.Version != 1 {
		t.Fatal("recovered DELETE changed global kernel lifecycle", err)
	}
}

func TestNativeUsersDeleteCannotCrossConnectionOrCurrentPolicy(t *testing.T) {
	f := newNativeFixture(t)
	id := createNativeNamed(t, f, "PrivateDelete", "Connection A")
	get := scim.Request{Operation: scim.UserGet, Credential: f.bearer, ResourceID: id}
	initial, err := f.service.Execute(f.ctx, get)
	if err != nil {
		t.Fatal(err)
	}
	c := f.config
	c.Scope.ConnectionID = "delete-connection-b"
	bearer := authentication.NewBearerCredential("native-delete-other-credential-with-sufficient-length")
	c.Credential, err = NewConfiguredCredential("delete-credential-b", bearer, [32]byte{89})
	if err != nil {
		t.Fatal(err)
	}
	other, err := NewService(f.pool, c, f.keys)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := other.InitializeConfiguredConnection(f.ctx); err != nil {
		t.Fatal(err)
	}
	remove := scim.Request{Operation: scim.UserDelete, Credential: bearer, ResourceID: id, IfMatch: initial.ETag}
	for range 2 {
		if response, err := other.Execute(f.ctx, remove); protocolStatus(err) != 404 || len(response.Body) != 0 {
			t.Fatal("DELETE disclosed or changed another connection's resource", err)
		}
	}
	f.deny.Store(true)
	remove.Credential = f.bearer
	if response, err := f.service.Execute(f.ctx, remove); err == nil || len(response.Body) != 0 {
		t.Fatal("current policy withdrawal admitted a new deletion")
	}
	f.deny.Store(false)
	if response, err := f.service.Execute(f.ctx, get); err != nil || response.ETag != initial.ETag || string(response.Body) != string(initial.Body) {
		t.Fatal("denied or foreign DELETE changed the owned projection", err)
	}
	var mutations int
	if err := f.pool.Raw().QueryRow(f.ctx, `SELECT count(*) FROM identity.commands WHERE purpose=$1`, string(scim.UserDelete)).Scan(&mutations); err != nil || mutations != 0 {
		t.Fatal("foreign/current-policy denial created a domain command", mutations, err)
	}
}

func TestNativeUsersNoOpDoesNotStrandConcurrentCanonicalDelete(t *testing.T) {
	f := newNativeFixture(t)
	id := createNativeNamed(t, f, "NoOpBeforeDelete", "Unchanged display")
	get := scim.Request{Operation: scim.UserGet, Credential: f.bearer, ResourceID: id}
	initial, err := f.service.Execute(f.ctx, get)
	if err != nil {
		t.Fatal(err)
	}
	prepared, release, finished := make(chan struct{}), make(chan struct{}), make(chan struct{})
	var entered, unblocked sync.Once
	unblock := func() { unblocked.Do(func() { close(release) }) }
	defer unblock()
	c := f.config
	underlying := c.Authorization
	c.Authorization = configuredPolicy(func(ctx context.Context, decision authorization.DecisionContext) (authorization.Decision, error) {
		i, _ := currentInvocation(ctx)
		if decision.Request.Action == authorization.Action(scim.UserDelete) && decision.Request.Resource.Type == "identity.scim.user" && i != nil && i.phase != nil {
			entered.Do(func() {
				close(prepared)
				select {
				case <-release:
				case <-ctx.Done():
				}
			})
		}
		// Timing only: this wrapper preserves the exact configured policy's
		// genuine decision and runs before Work/row locks, never minting access.
		return underlying.Decide(ctx, decision)
	})
	service, err := NewService(f.pool, c, f.keys)
	if err != nil {
		t.Fatal(err)
	}
	remove := scim.Request{Operation: scim.UserDelete, Credential: f.bearer, ResourceID: id, IfMatch: initial.ETag}
	result := make(chan executionResult, 1)
	go func() {
		defer close(finished)
		response, err := service.Execute(f.ctx, remove)
		result <- executionResult{response, err}
	}()
	defer func() {
		unblock()
		select {
		case <-finished:
		case <-f.ctx.Done():
			t.Error("concurrent DELETE did not terminate")
		}
	}()
	select {
	case <-prepared:
	case got := <-result:
		t.Fatal("actual canonical DELETE preparation was not reached", got.err)
	case <-f.ctx.Done():
		t.Fatal("canonical DELETE preparation did not arrive")
	}
	noop := scim.Request{Operation: scim.UserPatch, Credential: f.bearer, ResourceID: id, IfMatch: initial.ETag, ContentType: "application/scim+json", Body: []byte(`{"schemas":["urn:ietf:params:scim:api:messages:2.0:PatchOp"],"Operations":[{"op":"replace","path":"displayName","value":"Unchanged display"}]}`)}
	response, err := f.service.Execute(f.ctx, noop)
	if err != nil || response.ETag != initial.ETag || string(response.Body) != string(initial.Body) {
		t.Fatal("concurrent no-op PATCH did not preserve its public representation", err)
	}
	var generation int64
	if err := f.pool.Raw().QueryRow(f.ctx, `SELECT generation FROM scim.users WHERE resource_id=$1`, id).Scan(&generation); err != nil || generation != 1 {
		t.Fatal("no-op PATCH changed private resource generation", generation, err)
	}
	var commands, audits, notifications int
	if err := f.pool.Raw().QueryRow(f.ctx, `SELECT
 (SELECT count(*) FROM identity.commands WHERE purpose=$1 AND state='committed'),
 (SELECT count(*) FROM audit.identity_command_bindings a JOIN identity.commands c USING(command_id) WHERE c.purpose=$1 AND c.state='committed'),
 (SELECT count(*) FROM public.identity_outbox_bindings o JOIN identity.commands c USING(command_id) WHERE c.purpose=$1 AND c.state='committed')`, string(scim.UserPatch)).Scan(&commands, &audits, &notifications); err != nil || commands != 1 || audits != 1 || notifications != 1 {
		t.Fatal("accepted no-op did not retain its actual journal/audit/outbox despite unchanged aggregate version", commands, audits, notifications, err)
	}
	var payload []byte
	if err := f.pool.Raw().QueryRow(f.ctx, `SELECT payload FROM public.outbox_messages WHERE topic='identity.scim.user_patch_noop.v1'`).Scan(&payload); err != nil {
		t.Fatal("actual no-op lifecycle notification was absent", err)
	}
	var event struct {
		Before string `json:"before_version"`
		After  string `json:"after_version"`
	}
	if json.Unmarshal(payload, &event) != nil || event.Before != "1" || event.After != "1" {
		t.Fatal("no-op notification falsely advanced the SCIM aggregate")
	}
	unblock()
	select {
	case got := <-result:
		if got.err != nil || got.response.Status != 204 {
			t.Fatal("unchanged ETag was permanently poisoned by concurrent no-op", got.err)
		}
	case <-f.ctx.Done():
		t.Fatal("canonical DELETE did not finish after unchanged resource")
	}
	if response, err := f.service.Execute(f.ctx, remove); err != nil || response.Status != 204 {
		t.Fatal("canonical DELETE retry was stranded after no-op", err)
	}
}

func TestNativeUsersPendingNoOpRetryFinishesOriginalCommand(t *testing.T) {
	f := newNativeFixture(t)
	id := createNativeNamed(t, f, "PendingNoOp", "Unchanged display")
	get := scim.Request{Operation: scim.UserGet, Credential: f.bearer, ResourceID: id}
	initial, err := f.service.Execute(f.ctx, get)
	if err != nil {
		t.Fatal(err)
	}
	fault := &nativeCommitFault{reservation: true}
	pool, err := database.Connect(f.ctx, database.Config{DSN: os.Getenv("SCIM_POSTGRES_TEST_DSN"), MaxConns: 3, Configure: func(c *database.PoolConfig) error {
		c.ConnConfig.Database = f.pool.Raw().Config().ConnConfig.Database
		c.ConnConfig.DialFunc = fault.dial
		return nil
	}})
	if err != nil {
		t.Fatal("owned pending no-op fault pool", err)
	}
	defer func() {
		cleanup, stop := context.WithTimeout(context.Background(), 3*time.Second)
		defer stop()
		if err := pool.Close(cleanup); err != nil {
			t.Error("pending no-op fault pool cleanup", err)
		}
	}()
	c := f.config
	c.Coordinator.LeaseDuration = 100 * time.Millisecond
	service, err := NewService(pool, c, f.keys)
	if err != nil {
		t.Fatal(err)
	}
	noop := scim.Request{Operation: scim.UserPatch, Credential: f.bearer, ResourceID: id, IfMatch: initial.ETag, IdempotencyKey: "pending-noop-original", ContentType: "application/scim+json", Body: []byte(`{"schemas":["urn:ietf:params:scim:api:messages:2.0:PatchOp"],"Operations":[{"op":"replace","path":"displayName","value":"Unchanged display"}]}`)}
	if response, err := service.Execute(f.ctx, noop); protocolStatus(err) != 503 || len(response.Body) != 0 || !fault.hit.Load() {
		t.Fatal("actual pending no-op reservation acknowledgement was not lost", err)
	}
	var command, state string
	if err := f.pool.Raw().QueryRow(f.ctx, `SELECT encode(command_id,'hex'),state FROM identity.commands WHERE purpose=$1`, string(scim.UserPatch)).Scan(&command, &state); err != nil || state != "pending" {
		t.Fatal("no-op crash did not leave the real original command pending", state, err)
	}
	timer := time.NewTimer(150 * time.Millisecond)
	defer timer.Stop()
	select {
	case <-timer.C:
	case <-f.ctx.Done():
		t.Fatal("pending no-op lease wait cancelled")
	}
	healthy, err := NewService(f.pool, c, f.keys)
	if err != nil {
		t.Fatal(err)
	}
	response, err := healthy.Execute(f.ctx, noop)
	if err != nil || response.ETag != initial.ETag || string(response.Body) != string(initial.Body) {
		t.Fatal("crashed pending no-op could not finish its unchanged original response", err)
	}
	var retained string
	var generation int64
	var commands, audits, notifications int
	if err := f.pool.Raw().QueryRow(f.ctx, `SELECT
 (SELECT encode(command_id,'hex') FROM identity.commands WHERE purpose=$1 AND state='committed'),
 (SELECT count(*) FROM identity.commands WHERE purpose=$1),
 (SELECT count(*) FROM audit.identity_command_bindings a JOIN identity.commands c USING(command_id) WHERE c.purpose=$1 AND c.state='committed'),
 (SELECT count(*) FROM public.identity_outbox_bindings o JOIN identity.commands c USING(command_id) WHERE c.purpose=$1 AND c.state='committed'),
 (SELECT generation FROM scim.users WHERE resource_id=$2)`, string(scim.UserPatch), id).Scan(&retained, &commands, &audits, &notifications, &generation); err != nil || retained != command || commands != 1 || audits != 1 || notifications != 1 || generation != 1 {
		t.Fatal("pending no-op retry changed command identity, resource generation or actual atomic effects", commands, audits, notifications, generation, err)
	}
	kernelUser, err := f.service.directory.Get(f.ctx, identity.GetUserQuery{TenantID: f.config.Scope.TenantID, UserID: identity.UserID(id)})
	if err != nil || kernelUser.Version != 1 || kernelUser.Status != identity.StatusActive {
		t.Fatal("pending no-op retry invented a core mutation", err)
	}
}
