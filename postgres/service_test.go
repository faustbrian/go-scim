package scimpostgres

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"

	scim "github.com/faustbrian/go-scim"
)

func TestNativeServiceRequiresActualOwnedComposition(t *testing.T) {
	if service, err := NewService(nil, Config{}, nil); service != nil || err == nil {
		t.Fatal("zero native composition admitted")
	}
	if _, err := (*Service)(nil).Execute(context.Background(), scim.Request{Operation: scim.UserCreate}); err == nil || protocolStatus(err) != 503 {
		t.Fatal("zero service produced an outcome", err)
	}
}

func protocolStatus(err error) int {
	var protocol *scim.Error
	if err != nil && errors.As(err, &protocol) && protocol != nil {
		return protocol.StatusCode()
	}
	return 0
}

func TestNativeServiceCustodyIsRedacted(t *testing.T) {
	service := Service{config: func() Config { return Config{IntentKey: [32]byte{93}} }}
	for _, verb := range []string{"%v", "%+v", "%#v"} {
		if got := fmt.Sprintf(verb, service); got != "scimpostgres.Service(redacted)" {
			t.Fatal("service runtime disclosed", verb)
		}
	}
	if _, err := json.Marshal(service); err == nil {
		t.Fatal("runtime composition serialized")
	}
	if got := fmt.Sprintf("%#v", struct{ Service Service }{service}); strings.Contains(got, "IntentKey") {
		t.Fatal("nested service disclosed")
	}
}
