package scim

import "context"

// ExecuteAdmittedDelete explicitly selects GroupDelete with a required synchronous
// trusted admission gate. Other operations return 501; a nil service or gate
// returns 503. Current bearer/operation authority and existing bounded target,
// required strong If-Match, empty-body and query validation precede its one
// invocation. Command allocation and GroupStore admission follow only an allowed,
// still-current result. Canonical input, Store-owned original command, conditional
// deletion, headerless or optional-key replay and unknown outcomes are unchanged.
// Deletion affects only the owned Group projection, never its member resources.
//
// Inputs and admit are borrowed synchronously and must not be mutated concurrently.
// The gate consumes the original remaining authority, request and parent deadlines;
// only nil allows. The redacted denial rules of ExecuteAdmittedRead apply.
// Cancellation, expiry and panic fail closed before command effects; the final
// disclosure fence withholds late results without rewriting committed or unknown
// outcomes. The gate must honor ctx, retain no invocation state or context and
// start no detached work. It must not invoke protocol execution: calls to this
// entry point, even invalid ones, and calls reaching the shared executor using its
// context or a descendant deny the entire guarded call even if the nested error
// is ignored. Other wrappers' preflight failures and unrelated contexts are not
// policed by this fence.
//
// Trusted composition binds authenticated client identity privately in the gate;
// Connection is not actor authority. This selects no credential verifier, quota
// owner, Store, HTTP route, other operation or connection lifecycle. Ordinary
// Execute and sibling admission selections are unchanged.
func (s *GroupsService) ExecuteAdmittedDelete(parent context.Context, request Request, admit func(context.Context) *Error) (Response, error) {
	if markAdmissionReentry(parent) {
		return Response{}, failure(503, "")
	}
	if s == nil || s.service == nil || admit == nil {
		return Response{}, failure(503, "")
	}
	if request.Operation != GroupDelete {
		return Response{}, failure(501, "")
	}
	return s.service.executeWithUsersAdmission(parent, request, guardUsersWriteAdmission(admit))
}
