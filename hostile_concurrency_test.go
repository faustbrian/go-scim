package scim_test

import (
	"context"
	"encoding/json"
	"errors"
	"sync"
	"testing"

	authentication "github.com/faustbrian/go-authentication/v2"
	scim "github.com/faustbrian/go-scim"
)

func TestUsersProfileConcurrentCAS(t *testing.T) {
	f := newProtocolFixture(t)
	created := f.call(t, scim.UserCreate, "", "", userBody("concurrent", ""))
	id := object(t, created.Body)["id"].(string)
	const callers = 16
	results := make(chan error, callers)
	var wg sync.WaitGroup
	for i := 0; i < callers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, err := f.service.Execute(context.Background(), scim.Request{Operation: scim.UserPatch, Credential: authentication.NewBearerCredential("fixture-connection"), ResourceID: id, IfMatch: created.ETag, ContentType: "application/scim+json", Body: []byte(patchBody(`{"op":"replace","path":"displayName","value":"one-winner"}`))})
			results <- err
		}()
	}
	wg.Wait()
	close(results)
	successes := 0
	for err := range results {
		if err == nil {
			successes++
			continue
		}
		var protocol *scim.Error
		if !errors.As(err, &protocol) || protocol.StatusCode() != 412 {
			t.Fatalf("unexpected concurrent result: %v", err)
		}
	}
	if successes != 1 {
		t.Fatalf("CAS allowed %d winners", successes)
	}
	got := f.call(t, scim.UserGet, id, "", "")
	if got.ETag == created.ETag || object(t, got.Body)["displayName"] != "one-winner" {
		t.Fatal("single atomic winner was not visible")
	}
}

func FuzzFilterBoundary(f *testing.F) {
	for _, seed := range []string{`userName eq "bjensen"`, `emails[type eq "work" and value co "@example.test"]`, `not (active eq false)`, `((((userName pr))))`, `userName eq"x"`, `userName eq "\""`} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, input string) {
		if len(input) > 16384 {
			return
		}
		ast, err := scim.ParseFilter(input, nil, scim.DefaultLimits())
		if err != nil {
			var protocol *scim.Error
			if !errors.As(err, &protocol) || protocol.StatusCode() != 400 {
				t.Fatalf("untyped parser failure: %v", err)
			}
			return
		}
		_ = ast.Operator()
		_ = ast.AttributePath()
		_ = ast.ComparisonValue()
		_ = ast.Children()
	})
}
func FuzzUsersProtocolJSON(f *testing.F) {
	for _, seed := range []string{userBody("fuzz", ""), userBody("x", `,"USERNAME":"alias"`), `null`, `[]`, `{"schemas":["` + userURN + `"],"userName":null}`, userBody("x", `,"name":{"givenName":"a","GivenName":"b"}`)} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, input string) {
		if len(input) > 65536 {
			return
		}
		fixture := newProtocolFixture(t)
		r, err := fixture.service.Execute(context.Background(), scim.Request{Operation: scim.UserCreate, Credential: authentication.NewBearerCredential("fixture-connection"), ContentType: "application/scim+json", Body: []byte(input)})
		if err != nil {
			var protocol *scim.Error
			if !errors.As(err, &protocol) || protocol.StatusCode() >= 500 || len(r.Body) > 0 {
				t.Fatalf("unexpected protocol failure: %v", err)
			}
			encoded, e := json.Marshal(protocol)
			if e != nil || !json.Valid(encoded) {
				t.Fatal("invalid error envelope")
			}
			return
		}
		if r.Status != 201 || !json.Valid(r.Body) || r.ETag == "" {
			t.Fatal("invalid successful create")
		}
	})
}
