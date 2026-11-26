//go:build integration

package scimpostgres

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"

	authentication "github.com/faustbrian/go-authentication/v2"
	identity "github.com/faustbrian/go-identity"
	scim "github.com/faustbrian/go-scim"
)

func TestNativeBulkProtocolAdmitsOnceAfterAuthenticationAndBeforeWork(t *testing.T) {
	f, _, _ := nativeBulkExecutionFixture(t)
	requestPolicy := scim.BulkPolicy{MaxOperations: 12, MaxPayloadBytes: 32768, MaxOperationBytes: 4096}
	responsePolicy := scim.DefaultBulkResponsePolicy()
	service, err := NewBulkService(groupsOnPool(t, f, f.pool), requestPolicy, responsePolicy)
	if err != nil {
		t.Fatal(err)
	}
	selected, ok := any(service).(interface {
		BulkPolicies() (scim.BulkPolicy, scim.BulkResponsePolicy)
		ExecuteBulkProtocol(context.Context, scim.BulkRequest, scim.ProtocolAdmission) ([]byte, error)
		ReadBulkServiceProviderConfig(context.Context, authentication.BearerCredential, scim.ProtocolAdmission) (scim.Response, error)
	})
	if !ok {
		t.Fatal("native Bulk has no transport boundary sharing the executor's authority and policies")
	}
	if req, res := selected.BulkPolicies(); req != requestPolicy || res != responsePolicy {
		t.Fatal("transport did not receive the actual executor policies")
	}
	key, err := identity.NewIdempotencyKey([]byte("fixture-bulk-protocol-key"))
	if err != nil {
		t.Fatal(err)
	}
	request := scim.BulkRequest{Credential: f.bearer, Body: []byte(mixedCreateBulkFixture), IdempotencyKey: &key}
	attempts := 0
	var denial *scim.Error
	gate := func(ctx context.Context, client scim.ProtocolClient) *scim.Error {
		attempts++
		if deadline, ok := ctx.Deadline(); !ok || !deadline.After(time.Now()) || client.ID != f.config.ActorID || client.TenantID != f.config.Scope.TenantID {
			t.Error("admission did not receive bounded native client authority")
			return scim.NewError(503, "")
		}
		return denial
	}

	invalid := request
	invalid.Credential = authentication.NewBearerCredential("fixture-unknown")
	if wire, err := selected.ExecuteBulkProtocol(f.ctx, invalid, gate); len(wire) != 0 || protocolStatus(err) != 401 || attempts != 0 {
		t.Fatal("invalid credential reached the admission gate or exposed output", len(wire), attempts, err)
	}
	if out, err := selected.ReadBulkServiceProviderConfig(f.ctx, invalid.Credential, gate); len(out.Body) != 0 || protocolStatus(err) != 401 || attempts != 0 {
		t.Fatal("unauthenticated discovery reached the gate or exposed output", attempts, err)
	}
	if wire, err := selected.ExecuteBulkProtocol(f.ctx, request, nil); len(wire) != 0 || protocolStatus(err) != 503 {
		t.Fatal("missing gate must fail closed for transport", len(wire), err)
	}
	f.deny.Store(true)
	if wire, err := selected.ExecuteBulkProtocol(f.ctx, request, gate); len(wire) != 0 || protocolStatus(err) != 403 || attempts != 0 {
		t.Fatal("native policy denial reached the gate or exposed output", len(wire), attempts, err)
	}
	f.deny.Store(false)

	denial = scim.NewRateLimitedError(1100 * time.Millisecond)
	wire, err := selected.ExecuteBulkProtocol(f.ctx, request, gate)
	var protocolError *scim.Error
	if len(wire) != 0 || attempts != 1 || !errors.As(err, &protocolError) || protocolError.StatusCode() != 429 || protocolError.RetryAfterSeconds() != 2 {
		t.Fatal("limited transport did not preserve the native quota denial", len(wire), attempts, err)
	}
	requireMixedBulkCounts(t, f, [8]int{})
	if out, err := selected.ReadBulkServiceProviderConfig(f.ctx, f.bearer, gate); len(out.Body) != 0 || protocolStatus(err) != 429 || attempts != 2 {
		t.Fatal("limited discovery disclosed configuration", attempts, err)
	}

	denial = scim.NewError(403, "")
	if wire, err := selected.ExecuteBulkProtocol(f.ctx, request, gate); len(wire) != 0 || protocolStatus(err) != 403 || attempts != 3 {
		t.Fatal("a transport scope denial must be redacted, not retried or turned into success", len(wire), attempts, err)
	}
	requireMixedBulkCounts(t, f, [8]int{})
	denial = nil
	discovery, err := selected.ReadBulkServiceProviderConfig(f.ctx, f.bearer, gate)
	var document struct {
		Bulk struct {
			Supported                     bool
			MaxOperations, MaxPayloadSize int
		}
	}
	if err != nil || discovery.Status != 200 || json.Unmarshal(discovery.Body, &document) != nil ||
		!document.Bulk.Supported || document.Bulk.MaxOperations != 12 || document.Bulk.MaxPayloadSize != 32768 || attempts != 4 {
		t.Fatal("authorized discovery did not share the actual executor limits", document, attempts, err)
	}

	first, err := selected.ExecuteBulkProtocol(f.ctx, request, gate)
	if err != nil || len(first) == 0 || attempts != 5 {
		t.Fatal("admitted transport did not execute the complete Bulk once", len(first), attempts, err)
	}
	if replay, err := selected.ExecuteBulkProtocol(f.ctx, request, gate); err != nil || !bytes.Equal(first, replay) || attempts != 6 {
		t.Fatal("terminal retry must pay once and replay the original bytes", attempts, err)
	}
	denial = scim.NewError(503, "")
	if replay, err := selected.ExecuteBulkProtocol(f.ctx, request, gate); len(replay) != 0 || protocolStatus(err) != 503 || attempts != 7 {
		t.Fatal("quota outage must withhold already retained results", len(replay), attempts, err)
	}
	requireMixedBulkCounts(t, f, [8]int{1, 1, 1, 3, 3, 3, 1, 2})
}
