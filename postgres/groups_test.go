package scimpostgres

import (
	"context"
	"encoding/json"
	"fmt"
	"testing"

	scim "github.com/faustbrian/go-scim"
)

func TestNativeGroupsRequiresConfiguredNativeService(t *testing.T) {
	for _, base := range []*Service{nil, {}} {
		if service, err := NewGroupsService(base, 0); service != nil || err == nil {
			t.Fatal("unconfigured Groups composition admitted")
		}
	}
	if _, err := (*GroupsService)(nil).Execute(context.Background(), scim.Request{Operation: scim.GroupCreate}); protocolStatus(err) != 503 {
		t.Fatal("zero Groups service produced an outcome", err)
	}
}

func TestNativeGroupsRuntimeCustodyIsNotExported(t *testing.T) {
	service := GroupsService{native: &Service{config: func() Config { return Config{IntentKey: [32]byte{93}} }}}
	for _, verb := range []string{"%v", "%+v", "%#v"} {
		if got := fmt.Sprintf(verb, service); got != "scimpostgres.GroupsService(redacted)" {
			t.Fatal("Groups borrowed custody disclosed")
		}
	}
	if _, err := json.Marshal(service); err == nil {
		t.Fatal("Groups borrowed custody serialized")
	}
}
