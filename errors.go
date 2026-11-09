package scim

import (
	"encoding/json"
	"fmt"
	"io"
	"strconv"
)

// Error is a stable redacted RFC 7644 error. Its fields are private: arbitrary
// provider diagnostics and unregistered scimType values cannot be serialized.
// Use StatusCode for transport and policy; Error and formatting never expose
// request, backend, credential or enumeration state.
type Error struct {
	code         int
	kind, detail string
}

// Error returns only a fixed safe diagnostic.
func (e *Error) Error() string {
	if e == nil {
		return "scim: error"
	}
	return "scim: " + e.detail
}

// StatusCode returns the actual HTTP status represented by the error.
func (e *Error) StatusCode() int {
	if e == nil || e.code < 400 || e.code > 599 {
		return 500
	}
	return e.code
}

// Format redacts every diagnostic verb, including %#v.
func (e *Error) Format(s fmt.State, _ rune) { _, _ = io.WriteString(s, e.Error()) }

// MarshalJSON emits exactly the Error schema and a three-digit string status.
func (e *Error) MarshalJSON() ([]byte, error) {
	if e == nil {
		return []byte("null"), nil
	}
	return json.Marshal(struct {
		Schemas []string `json:"schemas"`
		Status  string   `json:"status"`
		Type    string   `json:"scimType,omitempty"`
		Detail  string   `json:"detail"`
	}{[]string{errorSchema}, strconv.Itoa(e.StatusCode()), e.kind, e.detail})
}

func failure(code int, kind string) *Error {
	details := map[int]string{400: "Invalid request", 401: "Authentication required", 403: "Access denied", 404: "Resource not found", 409: "Request conflict", 412: "Resource version mismatch", 413: "Request too large", 415: "Unsupported representation", 428: "Resource version required", 500: "Request failed", 501: "Operation unsupported", 503: "Authority or outcome unavailable"}
	detail, ok := details[code]
	if !ok {
		code, kind, detail = 500, "", "Request failed"
	}
	return &Error{code, kind, detail}
}

// CredentialWrite identifies a schema-declared write-only/returned-never target
// without carrying its value. Values must not cross the mapper/store boundary.
type CredentialWrite struct{ AttributePath string }

// CredentialWriteDecision is closed: this profile supports no credential writes.
type CredentialWriteDecision uint8

const (
	CredentialWriteInvalid CredentialWriteDecision = iota
	CredentialWriteUnsupported
)

// DecideCredentialWrite is the reference profile's typed credential decision
// seam. RFC 7643 password is write-only; this profile deliberately refuses it.
// An approved future profile must use identity/password, not persist plaintext
// in a SCIM projection. This decision cannot be overridden by request input.
func DecideCredentialWrite(_ CredentialWrite) CredentialWriteDecision {
	return CredentialWriteUnsupported
}

// NewError reconstructs a stable redacted protocol condition from retained safe
// status/type metadata. It accepts no backend detail. Unsupported statuses map
// to 500; a type not registered for that status is omitted. Execute additionally
// checks the exact operation before exposing a scimType to transport.
func NewError(status int, scimType string) *Error {
	e := failure(status, "")
	if status == 400 && slicesContains([]string{"invalidFilter", "tooMany", "mutability", "invalidSyntax", "invalidPath", "noTarget", "invalidValue", "invalidVers"}, scimType) || status == 409 && scimType == "uniqueness" {
		e.kind = scimType
	}
	return e
}
func errorTypeForOperation(kind string, op Operation) bool {
	switch kind {
	case "":
		return true
	case "invalidFilter", "tooMany":
		return op == UserList || op == UserSearch || op == Search
	case "invalidPath", "noTarget":
		return op == UserPatch
	case "mutability":
		return op == UserCreate || op == UserReplace || op == UserPatch
	case "invalidSyntax":
		return op == UserCreate || op == UserReplace || op == UserSearch || op == Search
	case "uniqueness":
		return op == UserCreate || op == UserReplace || op == UserPatch
	case "invalidValue", "invalidVers":
		return true
	default:
		return false
	}
}
