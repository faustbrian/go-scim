package scim

import "context"

// ExecuteAdmittedCreate explicitly selects GroupCreate with a required synchronous
// trusted admission gate. Other operations return 501; a nil service or gate
// returns 503. Current bearer authentication, operation authorization and existing
// bounded Group/schema/member/target/query preflight precede its one invocation.
// Command allocation, mapping and GroupStore admission follow only an allowed,
// still-current result. Canonical input, Store-owned command/replay, exact-scope
// member integrity and atomic write authority are unchanged.
//
// Inputs and admit are borrowed for this call and must not be mutated concurrently.
// The gate consumes the remaining original authority, request and parent deadlines;
// only nil allows. The redacted denial rules of ExecuteAdmittedRead apply.
// Cancellation, expiry and panic fail closed before command effects; the final
// disclosure fence withholds late results without rewriting a committed outcome.
// The gate must honor ctx, retain no invocation state or context and start no
// detached work. It must not invoke protocol execution: calls to this entry point,
// even invalid ones, and calls reaching the shared executor using its context or
// a descendant deny the entire guarded call even if the nested error is ignored.
// Other wrappers' preflight failures and unrelated contexts are not policed.
//
// Trusted composition binds authenticated client identity privately in the gate;
// Connection is not actor authority. This selects no credential verifier, quota
// owner, Store, HTTP route, other operation or connection lifecycle. Ordinary
// Execute and sibling admission selections are unchanged.
func (s *GroupsService) ExecuteAdmittedCreate(parent context.Context, request Request, admit func(context.Context) *Error) (Response, error) {
	if markAdmissionReentry(parent) {
		return Response{}, failure(503, "")
	}
	if s == nil || s.service == nil || admit == nil {
		return Response{}, failure(503, "")
	}
	if request.Operation != GroupCreate {
		return Response{}, failure(501, "")
	}
	return s.service.executeWithUsersAdmission(parent, request, guardUsersWriteAdmission(admit))
}
