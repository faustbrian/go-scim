package scim

import (
	"context"
	"sync/atomic"
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
	return s.service.executeWithUsersAdmission(parent, r, admit)
}

// ExecuteAdmittedCreate explicitly selects UserCreate with a required trusted
// admission gate. Other operations return 501; a nil service or gate returns
// 503. Existing bounded request/schema validation, actual bearer authentication
// and operation authorization precede its one invocation. Mapping, command
// allocation and Store admission follow only an allowed, still-current result.
// Canonical input, Store-owned command/replay and write authority are unchanged.
//
// Inputs and admit are borrowed synchronously and must not be mutated
// concurrently. The gate consumes the remaining original authority, request and
// parent budget; only nil allows, and the denial rules of ExecuteAdmittedRead
// apply. Cancellation, expiry and panic fail closed before command effects.
// The final disclosure fence withholds late results without changing a committed
// Store outcome. The gate must retain no invocation state or context and start
// no detached work. It must not invoke protocol execution: attempted reentry
// using its context or a descendant denies the entire call. This context fence
// cannot police trusted code using unrelated contexts.
func (s *UsersService) ExecuteAdmittedCreate(parent context.Context, r Request, admit func(context.Context) *Error) (Response, error) {
	if s == nil || s.service == nil || admit == nil {
		return Response{}, failure(503, "")
	}
	if r.Operation != UserCreate {
		return Response{}, failure(501, "")
	}
	return s.service.executeWithUsersAdmission(parent, r, guardUsersWriteAdmission(admit))
}

// ExecuteAdmittedDelete explicitly selects UserDelete with a required trusted
// admission gate. Other operations return 501; a nil service or gate returns
// 503. Current bearer/operation authority and existing bounded target, required
// strong If-Match, empty-body and query validation precede its one invocation.
// Actual precondition comparison, deletion and original receipt replay remain
// with the existing Store, after admission; the gate grants none of that authority.
//
// Inputs and admit are borrowed synchronously. The original deadlines, redacted
// denial rules and descendant-context reentry fence of ExecuteAdmittedCreate
// apply. No command allocation or Store receipt/effect precedes the gate.
// A late result is withheld without changing the Store's committed or unknown
// outcome. The gate must honor ctx, retain no invocation/context and start no
// detached work. Native request-key behavior is unchanged; this selects no HTTP
// transport, new retry mechanism, other mutation or connection lifecycle.
func (s *UsersService) ExecuteAdmittedDelete(parent context.Context, r Request, admit func(context.Context) *Error) (Response, error) {
	if s == nil || s.service == nil || admit == nil {
		return Response{}, failure(503, "")
	}
	if r.Operation != UserDelete {
		return Response{}, failure(501, "")
	}
	return s.service.executeWithUsersAdmission(parent, r, guardUsersWriteAdmission(admit))
}

func guardUsersWriteAdmission(admit func(context.Context) *Error) func(context.Context) *Error {
	return func(ctx context.Context) *Error {
		state := &usersWriteAdmissionState{}
		denial := admit(context.WithValue(ctx, usersWriteAdmissionKey{}, state))
		if state.reentered.Load() {
			return failure(503, "")
		}
		return denial
	}
}

type usersWriteAdmissionKey struct{}

// One gate owns this invocation-local marker. The atomic flag also fails closed
// if trusted code attempts concurrent descendant calls before the gate returns.
type usersWriteAdmissionState struct{ reentered atomic.Bool }

func (s *protocolService) admitUsersOperation(ctx context.Context, c Connection, admit func(context.Context) *Error) *Error {
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
