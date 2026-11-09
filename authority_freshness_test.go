package scim_test

import (
	"context"
	"errors"
	"testing"
	"time"

	authentication "github.com/faustbrian/go-authentication/v2"
	scim "github.com/faustbrian/go-scim"
)

// The proposed Connection fields retain the trusted authenticator's original
// read-began time and earliest contributing authority deadline, separately from
// token expiry. They are metadata supplied at that existing trusted boundary,
// not authenticated proof, a signing scheme, or a new authority/replay engine.
// This fixture uses an injected clock; advancing it models elapsed dependency
// work without sleeping or borrowing the parent's Go/service slot.
type freshnessFixture struct {
	test               *testing.T
	now                time.Time
	connection         scim.Connection
	advanceAt          string
	advanceTo          time.Time
	visits             map[string]int
	policyCalls        int
	checkBudget        bool
	effectFence        bool
	advanceAfterCommit bool
}

func newFreshnessFixture(t *testing.T) (*protocolFixture, *freshnessFixture) {
	t.Helper()
	h := &freshnessFixture{
		test:   t,
		now:    fixtureNow,
		visits: make(map[string]int),
	}
	f := configuredProtocolFixture(t, func(c *scim.Config) {
		c.Now = func() time.Time { return h.now }
		c.RequestTimeout = time.Minute
		c.Authenticator = freshnessAuthenticator{state: h}
		c.Authorizer = freshnessAuthorizer{Authorizer: c.Authorizer, state: h}
		c.Mapper = freshnessMapper{Mapper: c.Mapper, state: h}
		c.Store = freshnessStore{Store: c.Store, state: h}
	})
	// Establish only the existing fixture credential/connection binding. Neither
	// this call nor the timestamps below prove real token or organization access.
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	connection, err := (protocolAuthenticator{}).Authenticate(ctx, authentication.NewBearerCredential("fixture-connection"))
	if err != nil {
		t.Fatal(err)
	}
	connection.AuthorityReadBeganAt = fixtureNow
	connection.AuthorityValidUntil = fixtureNow.Add(20 * time.Second)
	h.connection = connection
	return f, h
}

func (h *freshnessFixture) effectiveExpiry() time.Time {
	deadline := h.connection.AuthorityValidUntil
	if h.connection.ExpiresAt.Before(deadline) {
		deadline = h.connection.ExpiresAt
	}
	return deadline
}

func (h *freshnessFixture) visit(ctx context.Context, stage string) {
	h.test.Helper()
	h.visits[stage]++
	if h.checkBudget && stage != "authenticate" {
		deadline, ok := ctx.Deadline()
		remaining := h.effectiveExpiry().Sub(h.now)
		if !ok || time.Until(deadline) > remaining+100*time.Millisecond {
			h.test.Fatalf("%s did not receive the remaining original-authority budget", stage)
		}
	}
	if h.advanceAt == stage {
		h.now = h.advanceTo
	}
}

type freshnessAuthenticator struct{ state *freshnessFixture }

func (a freshnessAuthenticator) Authenticate(ctx context.Context, _ authentication.BearerCredential) (scim.Connection, error) {
	a.state.visit(ctx, "authenticate")
	// Each return is a cached value copy, not a new authoritative observation.
	return a.state.connection, nil
}

type freshnessAuthorizer struct {
	scim.Authorizer
	state *freshnessFixture
}

func (a freshnessAuthorizer) Authorize(ctx context.Context, connection scim.Connection, operation scim.Operation, id string) error {
	a.state.policyCalls++
	stage := "authorize"
	if a.state.policyCalls == 2 {
		stage = "authorize-before-commit"
	}
	a.state.visit(ctx, stage)
	return a.Authorizer.Authorize(ctx, connection, operation, id)
}

type freshnessMapper struct {
	scim.Mapper
	state *freshnessFixture
}

func (m freshnessMapper) MapUser(ctx context.Context, scope scim.Scope, resource scim.WritableResource) (scim.WritableResource, error) {
	m.state.visit(ctx, "map")
	return m.Mapper.MapUser(ctx, scope, resource)
}

type freshnessStore struct {
	scim.Store
	state *freshnessFixture
}

func (s freshnessStore) Get(ctx context.Context, scope scim.Scope, id string) (scim.Resource, error) {
	s.state.visit(ctx, "get")
	return s.Store.Get(ctx, scope, id)
}

func (s freshnessStore) Snapshot(ctx context.Context, scope scim.Scope, maximum scim.SnapshotBudget) (scim.Snapshot, error) {
	s.state.visit(ctx, "snapshot")
	return s.Store.Snapshot(ctx, scope, maximum)
}

func (s freshnessStore) Prepare(ctx context.Context, intent scim.WriteIntent) (scim.PreparedWrite, error) {
	s.state.visit(ctx, "prepare")
	return s.Store.Prepare(ctx, intent)
}

func (s freshnessStore) Commit(ctx context.Context, prepared scim.PreparedWrite, change scim.Change) (scim.WriteResult, error) {
	s.state.visit(ctx, "commit")
	connection := prepared.Intent.Connection
	if connection.AuthorityReadBeganAt != s.state.connection.AuthorityReadBeganAt || connection.AuthorityValidUntil != s.state.connection.AuthorityValidUntil {
		s.state.test.Fatal("commit did not retain the authenticator's original observation metadata")
	}
	if s.state.effectFence && (!s.state.now.Before(connection.AuthorityValidUntil) || !s.state.now.Before(connection.ExpiresAt)) {
		// This is explicitly a trusted fixture fence, not native atomicity proof.
		// Only the actual Store owner can fence real authority with durable effects.
		return scim.WriteResult{Outcome: scim.WriteOutcomeNotCommitted}, nil
	}
	result, err := s.Store.Commit(ctx, prepared, change)
	if s.state.advanceAfterCommit {
		s.state.now = s.state.effectiveExpiry()
	}
	return result, err
}

func freshnessDenied(t *testing.T, response scim.Response, err error) {
	t.Helper()
	var protocol *scim.Error
	if !errors.As(err, &protocol) || len(response.Body) != 0 || response.Status >= 200 && response.Status < 300 {
		t.Fatalf("expired original authority returned success or a resource: status=%d error=%v", response.Status, err)
	}
}

func freshnessRequest(operation scim.Operation, id string, version scim.Version) scim.Request {
	r := scim.Request{
		Operation:  operation,
		Credential: authentication.NewBearerCredential("fixture-connection"),
		ResourceID: id,
		IfMatch:    version,
	}
	if operation == scim.UserPatch {
		r.ContentType = "application/scim+json"
		r.Body = []byte(patchBody(`{"op":"replace","path":"displayName","value":"freshness candidate"}`))
	}
	return r
}

func TestUsersProfileAuthorityFreshnessCachedObservation(t *testing.T) {
	f, h := newFreshnessFixture(t)
	created := f.call(t, scim.UserCreate, "", "", userBody("original-read", ""))
	id := object(t, created.Body)["id"].(string)
	request := freshnessRequest(scim.UserGet, id, "")
	h.now = fixtureNow.Add(19 * time.Second)
	if response, err := f.service.Execute(context.Background(), request); err != nil || response.Status != 200 {
		t.Fatalf("still-current original observation was refused: %v", err)
	}
	gets := h.visits["get"]
	for _, elapsed := range []time.Duration{20 * time.Second, 21 * time.Second} {
		h.now = fixtureNow.Add(elapsed)
		response, err := f.service.Execute(context.Background(), request)
		freshnessDenied(t, response, err)
	}
	if h.visits["get"] != gets {
		t.Fatal("cached copies/retries renewed old authority and reached resource storage")
	}
}

func TestUsersProfileAuthorityFreshnessReplayNeedsCurrentObservation(t *testing.T) {
	f, h := newFreshnessFixture(t)
	request := freshnessRequest(scim.UserCreate, "", "")
	request.ContentType = "application/scim+json"
	request.IdempotencyKey = "original-authority-replay"
	request.Body = []byte(userBody("cached-replay", ""))
	if _, err := f.service.Execute(context.Background(), request); err != nil {
		t.Fatal(err)
	}
	prepares := h.visits["prepare"]
	h.now = fixtureNow.Add(20 * time.Second)
	response, err := f.service.Execute(context.Background(), request)
	freshnessDenied(t, response, err)
	if h.visits["prepare"] != prepares || len(f.store.resources) != 1 {
		t.Fatal("replay promoted expired authority or changed the original resource")
	}
}

func TestUsersProfileAuthorityFreshnessMissingOrOverlongObservation(t *testing.T) {
	for _, kind := range []string{"missing-read-began", "missing-valid-until", "beyond-original-twenty-seconds"} {
		t.Run(kind, func(t *testing.T) {
			f, h := newFreshnessFixture(t)
			switch kind {
			case "missing-read-began":
				h.connection.AuthorityReadBeganAt = time.Time{}
			case "missing-valid-until":
				h.connection.AuthorityValidUntil = time.Time{}
			case "beyond-original-twenty-seconds":
				h.connection.AuthorityValidUntil = fixtureNow.Add(21 * time.Second)
			}
			response, err := f.service.Execute(context.Background(), freshnessRequest(scim.UserList, "", ""))
			freshnessDenied(t, response, err)
			if h.visits["snapshot"] != 0 {
				t.Fatal("token TTL substituted for absent or overlong original-read validity")
			}
		})
	}
}

func TestUsersProfileAuthorityFreshnessEarliestExpiry(t *testing.T) {
	for _, owner := range []string{"original-read", "earlier-contributing-authority", "token"} {
		t.Run(owner, func(t *testing.T) {
			f, h := newFreshnessFixture(t)
			created := f.call(t, scim.UserCreate, "", "", userBody("earliest-expiry", ""))
			id := object(t, created.Body)["id"].(string)
			if owner == "earlier-contributing-authority" {
				// The authenticator aggregates its actual source observations and
				// carries their earliest deadline; this fixture supplies that seam.
				h.connection.AuthorityValidUntil = fixtureNow.Add(8 * time.Second)
			}
			if owner == "token" {
				h.connection.ExpiresAt = fixtureNow.Add(8 * time.Second)
			}
			h.now = h.effectiveExpiry().Add(-time.Second)
			h.policyCalls = 0
			h.checkBudget = true
			h.advanceAt, h.advanceTo = "get", h.effectiveExpiry()
			response, err := f.service.Execute(context.Background(), freshnessRequest(scim.UserGet, id, ""))
			freshnessDenied(t, response, err)
		})
	}
}

func TestUsersProfileAuthorityFreshnessSlowBoundaries(t *testing.T) {
	for _, stage := range []string{"authenticate", "authorize", "get", "snapshot", "prepare", "map", "authorize-before-commit"} {
		t.Run(stage, func(t *testing.T) {
			f, h := newFreshnessFixture(t)
			created := f.call(t, scim.UserCreate, "", "", userBody("slow-boundary", ""))
			id := object(t, created.Body)["id"].(string)
			h.policyCalls = 0
			h.visits = make(map[string]int)
			h.advanceAt, h.advanceTo = stage, fixtureNow.Add(20*time.Second)
			operation := scim.UserPatch
			if stage == "get" {
				operation = scim.UserGet
			}
			if stage == "snapshot" {
				operation = scim.UserList
			}
			response, err := f.service.Execute(context.Background(), freshnessRequest(operation, id, created.ETag))
			freshnessDenied(t, response, err)
			if h.visits[stage] == 0 {
				t.Fatalf("test did not reach the intended slow %s boundary", stage)
			}
			if h.visits["commit"] != 0 {
				t.Fatal("slow authority/read/mapping crossed the commit boundary after original expiry")
			}
			for _, resource := range f.store.resources {
				if resource.Version != created.ETag || resource.Attributes["displayName"] != nil {
					t.Fatal("expired authority changed the resource")
				}
			}
		})
	}
}

func TestUsersProfileAuthorityFreshnessStoreEffectAndReturnBoundaries(t *testing.T) {
	for _, stage := range []string{"expiry-at-protected-effect", "expiry-after-valid-commit"} {
		t.Run(stage, func(t *testing.T) {
			f, h := newFreshnessFixture(t)
			created := f.call(t, scim.UserCreate, "", "", userBody("effect-fence", ""))
			id := object(t, created.Body)["id"].(string)
			h.policyCalls = 0
			h.visits = make(map[string]int)
			if stage == "expiry-at-protected-effect" {
				h.advanceAt, h.advanceTo = "commit", h.effectiveExpiry()
				h.effectFence = true
			} else {
				h.advanceAfterCommit = true
			}
			response, err := f.service.Execute(context.Background(), freshnessRequest(scim.UserPatch, id, created.ETag))
			freshnessDenied(t, response, err)
			if h.visits["commit"] != 1 {
				t.Fatal("test did not reach the trusted store's protected effect boundary")
			}
			for _, resource := range f.store.resources {
				if stage == "expiry-at-protected-effect" && resource.Version != created.ETag {
					t.Fatal("trusted fixture fence permitted an expired effect")
				}
				if stage == "expiry-after-valid-commit" && resource.Version == created.ETag {
					t.Fatal("late response rejection falsely claimed to roll back an earlier valid commit")
				}
			}
		})
	}
}
