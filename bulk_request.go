package scim

import (
	"context"
	"errors"
	"fmt"
	"io"

	authentication "github.com/faustbrian/go-authentication/v2"
	identity "github.com/faustbrian/go-identity"
)

// ProtocolClient is the stable, authenticated client and resource tenant
// selected by the executor, independent of the original bearer material.
type ProtocolClient struct {
	ID       identity.ActorID
	TenantID identity.TenantID
}

// ProtocolAdmission admits a single transport attempt under its trusted
// network facts and the executor's authenticated client. A nil result permits
// execution; any other result denies. The owner must make one bounded atomic
// decision within ctx and not retain the invocation or start detached work.
type ProtocolAdmission func(context.Context, ProtocolClient) *Error

// BulkRequest carries the original decoded SCIM JSON and bearer for a single
// synchronous executor call. The executor borrows rather than retains these
// inputs; callers must not mutate them during the call. An optional key is a
// scoped alias for the canonical request, not a command identifier. No input
// selects the tenant, connection, actor or command.
type BulkRequest struct {
	Credential     authentication.BearerCredential
	Body           []byte
	IdempotencyKey *identity.IdempotencyKey
}

// Format redacts the body and credential custody.
func (BulkRequest) Format(s fmt.State, _ rune) {
	_, _ = io.WriteString(s, "scim.BulkRequest(redacted)")
}

// MarshalJSON rejects implicit serialization of request custody.
func (BulkRequest) MarshalJSON() ([]byte, error) {
	return nil, errors.New("scim: Bulk request serialization forbidden")
}
