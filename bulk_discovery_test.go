package scim_test

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	authentication "github.com/faustbrian/go-authentication/v2"
	identity "github.com/faustbrian/go-identity"
	scim "github.com/faustbrian/go-scim"
)

func TestBulkRequestDoesNotExportBorrowedInputs(t *testing.T) {
	key, err := identity.NewIdempotencyKey([]byte("fixture-original-key"))
	if err != nil {
		t.Fatal(err)
	}
	req := scim.BulkRequest{
		Credential: authentication.NewBearerCredential("fixture-original-bearer"),
		Body:       []byte("fixture-original-body"), IdempotencyKey: &key,
	}
	for _, format := range []string{"%v", "%+v", "%#v", "%q"} {
		if got := fmt.Sprintf(format, req); strings.Contains(got, "fixture-original-") || !strings.Contains(got, "redacted") {
			t.Fatal("Bulk request formatting did not redact custody")
		}
	}
	if data, err := json.Marshal(req); err == nil || len(data) != 0 {
		t.Fatal("Bulk request was implicitly serialized")
	}
}

func TestBulkServiceProviderConfigUsesSelectedPolicyAndExistingAuthority(t *testing.T) {
	f := newProtocolFixture(t)
	selected, ok := any(f.service).(interface {
		ReadServiceProviderConfigWithBulk(context.Context, authentication.BearerCredential, scim.BulkPolicy, func(context.Context) *scim.Error) (scim.Response, error)
	})
	if !ok {
		t.Fatal("SCIM has no authorized discovery entry point for an explicitly selected Bulk executor")
	}
	ctx := context.Background()
	credential := authentication.NewBearerCredential("fixture-connection")
	policy := scim.BulkPolicy{MaxOperations: 27, MaxPayloadBytes: 32768, MaxOperationBytes: 4096}

	first, err := selected.ReadServiceProviderConfigWithBulk(ctx, credential, policy, nil)
	if err != nil || first.Status != 200 || first.ContentType != "application/scim+json" {
		t.Fatalf("selected discovery: status %d, media %q, error %v", first.Status, first.ContentType, err)
	}
	doc := object(t, first.Body)
	assertSchemas(t, doc, "urn:ietf:params:scim:schemas:core:2.0:ServiceProviderConfig")
	if got := doc["bulk"].(map[string]any); len(got) != 3 || got["supported"] != true || got["maxOperations"] != float64(27) || got["maxPayloadSize"] != float64(32768) {
		t.Fatalf("wrong selected Bulk capabilities: %v", got)
	}
	if doc["filter"].(map[string]any)["maxResults"] != float64(2) || doc["changePassword"].(map[string]any)["supported"] != false {
		t.Fatalf("Bulk discovery changed unrelated runtime capabilities: %s", first.Body)
	}
	ordinary := f.call(t, scim.ServiceProviderConfig, "", "", "")
	if got := object(t, ordinary.Body)["bulk"].(map[string]any); got["supported"] != false || got["maxOperations"] != float64(0) || got["maxPayloadSize"] != float64(0) {
		t.Fatalf("ordinary discovery must not inherit opted-in Bulk limits: %v", got)
	}

	attempts := 0
	rateGate := func(context.Context) *scim.Error {
		attempts++
		return scim.NewRateLimitedError(1250 * time.Millisecond)
	}
	out, err := selected.ReadServiceProviderConfigWithBulk(ctx, credential, policy, rateGate)
	limited := assertProtocolError(t, out, err, 429, "")
	if attempts != 1 || limited.RetryAfterSeconds() != 2 {
		t.Fatalf("rate gate calls %d or retry delay %d did not survive the discovery envelope", attempts, limited.RetryAfterSeconds())
	}
	out, err = selected.ReadServiceProviderConfigWithBulk(ctx, authentication.NewBearerCredential("unknown-fixture"), policy, rateGate)
	assertProtocolError(t, out, err, 401, "")
	f.authorizer.err = errors.New("fixture denied discovery")
	out, err = selected.ReadServiceProviderConfigWithBulk(ctx, credential, policy, rateGate)
	assertProtocolError(t, out, err, 403, "")
	out, err = selected.ReadServiceProviderConfigWithBulk(ctx, credential, scim.BulkPolicy{}, rateGate)
	assertProtocolError(t, out, err, 400, "invalidValue")
	if attempts != 1 {
		t.Fatalf("failed authorization or invalid selection called the rate gate: %d attempts", attempts)
	}
}
