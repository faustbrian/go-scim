package scim

import (
	"context"
	"time"
)

// ExecuteAdmittedRead explicitly selects UserGet or UserList with a required
// trusted admission gate. Other operations return 501; a nil service or gate
// returns 503. Ordinary Execute and other services are not changed.
//
// Inputs and admit are borrowed for this synchronous call only and must not be
// mutated concurrently. The gate is called once after current bearer
// authentication and operation authorization, before resource I/O or disclosure.
// It must honor ctx, retain no invocation state and start no detached work. Its
// context consumes the remaining original authority, request and parent budget;
// gate completion cannot renew authority. Cancellation, expiry and panics fail
// closed, including after the gate and at the final disclosure fence.
//
// A nil gate result allows the read. Only untyped 403, 503 and 429 with a known
// positive bounded retry delay can be returned as denials; other gate errors
// become 503. Errors and response metadata are redacted. Trusted composition
// binds its authenticated client privately in the gate: Connection is not actor
// authority, and neither this method nor request input selects a client identity.
func (s *UsersService) ExecuteAdmittedRead(parent context.Context, r Request, admit func(context.Context) *Error) (Response, error) {
	if s == nil || s.service == nil || admit == nil {
		return Response{}, failure(503, "")
	}
	if r.Operation != UserGet && r.Operation != UserList {
		return Response{}, failure(501, "")
	}
	return s.service.executeWithReadAdmission(parent, r, admit)
}

func (s *protocolService) admitUsersRead(ctx context.Context, c Connection, admit func(context.Context) *Error) *Error {
	gateCtx, cancel, err := s.authorityContext(ctx, c)
	if err != nil {
		return failure(503, "")
	}
	defer cancel()
	denial := admit(gateCtx)
	// A gate that exhausted its original authority cannot disclose a selected
	// denial any more than it can disclose a resource.
	if !s.authorityCurrent(gateCtx, c) {
		return failure(503, "")
	}
	if denial == nil {
		return nil
	}
	switch denial.StatusCode() {
	case 403:
		return failure(403, "")
	case 429:
		if retry := denial.RetryAfterSeconds(); retry != 0 {
			return NewRateLimitedError(time.Duration(retry) * time.Second)
		}
	}
	return failure(503, "")
}
