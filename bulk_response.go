package scim

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/url"
	"strconv"
	"strings"
)

// BulkChildStatus is the closed set of durable child states. Invalid is the
// zero value and is never a durable or terminal child.
type BulkChildStatus uint8

const (
	BulkChildInvalid BulkChildStatus = iota
	BulkChildAdmitted
	BulkChildRunning
	BulkChildSucceeded
	BulkChildFailed
	BulkChildDependencyBlocked
	BulkChildSkipped
)

// BulkSkipReason is separate from status and is never sent to the client.
type BulkSkipReason uint8

const (
	BulkSkipNone BulkSkipReason = iota
	BulkSkipFailOnErrors
)

// ErrBulkIncomplete means the supplied durable checkpoints do not yet form a
// terminal response. It never carries a partial response or a child outcome.
var ErrBulkIncomplete = errors.New("scim: bulk checkpoints incomplete")

// BulkChildResult is the retained, safe semantic result for one original
// operation. Only succeeded or failed children may carry result fields.
// Only a persisted skipped child may carry the fail-on-errors skip reason.
// A processed child with a symbolic target needs its resolved ResourceID even
// on failure. A failed create must not carry its preallocated ID here.
type BulkChildResult struct {
	Status     BulkChildStatus
	SkipReason BulkSkipReason
	Code       int
	ResourceID string
	Version    Version
	SCIMType   string
}

// BulkResponsePolicy is the separate encoded-response budget and safe error
// detail limit. MaxBytes must be between 16 KiB and 4 MiB, inclusive.
type BulkResponsePolicy struct {
	MaxBytes         int
	ErrorDetailBytes int
}

// DefaultBulkResponsePolicy returns the reference response and detail limits.
func DefaultBulkResponsePolicy() BulkResponsePolicy {
	return BulkResponsePolicy{MaxBytes: 2 * 1024 * 1024, ErrorDetailBytes: DefaultLimits().ErrorDetailBytes}
}

// BulkResponsePlan binds the conservative bound to the same ordered request
// and trusted service location used by its terminal encoder. Its zero value
// is unusable. It retains neither request bodies nor credentials.
type BulkResponsePlan struct {
	ops                     []bulkResultShape
	maximum, cutoff, detail int
}

type bulkResultShape struct {
	method       string
	bulkID       *string
	locationRoot string
	literalID    string
	symbolicID   bool
	invalid      bool
}

type bulkWireResult struct {
	Method   string  `json:"method"`
	BulkID   *string `json:"bulkId,omitempty"`
	Location string  `json:"location,omitempty"`
	Version  Version `json:"version,omitempty"`
	Status   string  `json:"status"`
	Error    *Error  `json:"response,omitempty"`
}

const bulkResponseOpen = `{"schemas":["urn:ietf:params:scim:api:messages:2.0:BulkResponse"],"Operations":[`
const bulkResponseClose = `]}`

// PreflightBulkResponse proves the worst-case terminal byte bound before
// admission. It cannot assume a cutoff, an early failure, or a skipped child.
// baseURL is the trusted absolute HTTPS service root used for resource URIs.
func PreflightBulkResponse(plan BulkPlan, baseURL string, policy BulkResponsePolicy) (BulkResponsePlan, error) {
	if len(plan.operations) == 0 || policy.MaxBytes < 16*1024 || policy.MaxBytes > 4*1024*1024 ||
		policy.ErrorDetailBytes < 0 || policy.ErrorDetailBytes > DefaultLimits().ErrorDetailBytes || len(baseURL) > DefaultLimits().StringBytes {
		return BulkResponsePlan{}, failure(400, "invalidValue")
	}
	root, err := url.Parse(baseURL)
	if err != nil || root.Scheme != "https" || root.Hostname() == "" || root.User != nil || root.ForceQuery || root.RawQuery != "" || strings.Contains(baseURL, "#") {
		return BulkResponsePlan{}, failure(400, "invalidValue")
	}
	baseURL = strings.TrimRight(root.String(), "/")
	p := BulkResponsePlan{ops: make([]bulkResultShape, 0, len(plan.operations)), cutoff: plan.FailOnErrors(), detail: policy.ErrorDetailBytes}
	p.maximum = len(bulkResponseOpen) + len(bulkResponseClose) + len(plan.operations) - 1
	maxError := maximumBulkError(policy.ErrorDetailBytes)
	for i, op := range plan.operations {
		shape := bulkResultShape{
			method: op.Method, literalID: op.Target.ResourceID,
			symbolicID: op.Target.BulkID != "", invalid: op.Error != nil,
		}
		if plan.bulkIDPresent[i] {
			id := op.BulkID
			shape.bulkID = &id
		}
		switch op.Target.ResourceType {
		case "User":
			shape.locationRoot = baseURL + "/Users/"
		case "Group":
			shape.locationRoot = baseURL + "/Groups/"
		}
		p.maximum += shape.maximumBytes(maxError)
		if p.maximum > policy.MaxBytes {
			return BulkResponsePlan{}, failure(413, "")
		}
		p.ops = append(p.ops, shape)
	}
	return p, nil
}

// MaximumBytes is the conservative bound to retain with the admitted parent.
// Zero means no successful preflight.
func (p BulkResponsePlan) MaximumBytes() int { return p.maximum }

func (BulkResponsePlan) Format(w fmt.State, _ rune) {
	_, _ = io.WriteString(w, "scim.BulkResponsePlan(redacted)")
}

func (s bulkResultShape) maximumBytes(maxError *Error) int {
	location := s.locationRoot
	var dynamicLocationBytes int
	if location != "" {
		if s.literalID != "" {
			location += url.PathEscape(s.literalID)
		} else {
			// A path ID is at most 128 bytes (safeID); each original byte can
			// become a three-byte percent escape or a six-byte JSON escape.
			dynamicLocationBytes = 6 * 128
		}
	}
	entry := bulkWireResult{Method: s.method, BulkID: s.bulkID, Status: "503", Error: maxError, Location: location}
	failed, _ := json.Marshal(entry)
	if s.method == "POST" {
		// Failed creates never publish an identifier.
		entry.Location = ""
		failed, _ = json.Marshal(entry)
	}
	failedBytes := len(failed)
	if s.method != "POST" {
		failedBytes += dynamicLocationBytes
	}
	if s.invalid {
		return failedBytes
	}
	entry.Error, entry.Location = nil, location
	if s.method != "DELETE" {
		// validVersion admits 254 inner ASCII bytes; '<' maximizes JSON escaping.
		entry.Version = Version(`"` + strings.Repeat("<", 254) + `"`)
	}
	success, _ := json.Marshal(entry)
	return max(failedBytes, len(success)+dynamicLocationBytes)
}

// Write validates every original checkpoint before writing anything, then
// streams only processed results in original order. Callers must not mutate
// results concurrently. An I/O failure may leave a transport response partial;
// terminal state and its durable evidence are unchanged.
func (p BulkResponsePlan) Write(w io.Writer, results []BulkChildResult) error {
	if nilInterface(w) || len(p.ops) == 0 || len(results) != len(p.ops) {
		return failure(500, "")
	}
	processed, failed, skipped := 0, 0, false
	encodedBytes := len(bulkResponseOpen) + len(bulkResponseClose)
	for i, r := range results {
		wire, omit, err := p.wireChild(i, r)
		if err != nil {
			return err
		}
		if omit {
			skipped = true
			continue
		}
		if r.Status == BulkChildFailed {
			failed++
		}
		encodedBytes += len(wire)
		if processed != 0 {
			encodedBytes++
		}
		processed++
	}
	if skipped && (p.cutoff == 0 || failed < p.cutoff) || encodedBytes > p.maximum {
		return failure(500, "")
	}
	if err := writeBulkBytes(w, []byte(bulkResponseOpen)); err != nil {
		return err
	}
	first := true
	for i, r := range results {
		wire, omit, err := p.wireChild(i, r)
		if err != nil {
			return err
		}
		if omit {
			continue
		}
		if !first {
			if err := writeBulkBytes(w, []byte(",")); err != nil {
				return err
			}
		}
		first = false
		if err := writeBulkBytes(w, wire); err != nil {
			return err
		}
	}
	return writeBulkBytes(w, []byte(bulkResponseClose))
}

func (p BulkResponsePlan) wireChild(i int, r BulkChildResult) ([]byte, bool, error) {
	empty := r.Code == 0 && r.ResourceID == "" && r.Version == "" && r.SCIMType == ""
	if r.Status == BulkChildSkipped && empty && r.SkipReason == BulkSkipFailOnErrors {
		return nil, true, nil
	}
	if r.SkipReason != BulkSkipNone {
		return nil, false, failure(500, "")
	}
	switch r.Status {
	case BulkChildAdmitted, BulkChildRunning, BulkChildDependencyBlocked:
		if empty {
			return nil, false, ErrBulkIncomplete
		}
		return nil, false, failure(500, "")
	case BulkChildSucceeded, BulkChildFailed:
	default:
		return nil, false, failure(500, "")
	}
	shape := p.ops[i]
	w := bulkWireResult{Method: shape.method, BulkID: shape.bulkID, Status: strconv.Itoa(r.Code)}
	resourceID := r.ResourceID
	if r.Status == BulkChildSucceeded {
		if shape.invalid || r.SCIMType != "" || !shape.validSuccess(r) || resourceID == "" {
			return nil, false, failure(500, "")
		}
		w.Version = r.Version
	} else {
		w.Error = bulkChildError(r.Code, r.SCIMType, p.detail)
		if r.Code < 400 || w.Error.StatusCode() != r.Code || r.Version != "" || shape.method == "POST" && resourceID != "" {
			return nil, false, failure(500, "")
		}
		if resourceID == "" {
			resourceID = shape.literalID
		}
	}
	if shape.symbolicID && resourceID == "" {
		return nil, false, failure(500, "")
	}
	if resourceID != "" {
		if shape.locationRoot == "" || !safeID(resourceID) || resourceID == "." || resourceID == ".." ||
			shape.literalID != "" && shape.literalID != resourceID {
			return nil, false, failure(500, "")
		}
		w.Location = shape.locationRoot + url.PathEscape(resourceID)
	}
	wire, err := json.Marshal(w)
	return wire, false, err
}

func (s bulkResultShape) validSuccess(r BulkChildResult) bool {
	switch s.method {
	case "POST":
		return r.Code == 201 && validVersion(r.Version)
	case "PUT", "PATCH":
		return r.Code == 200 && validVersion(r.Version)
	case "DELETE":
		return r.Code == 204 && r.Version == ""
	default:
		return false
	}
}

func bulkChildError(code int, kind string, detail int) *Error {
	e := NewError(code, kind)
	if code == 424 {
		e = &Error{code: 424, detail: "Dependency failed"}
	}
	e.detail = e.detail[:min(len(e.detail), detail)]
	return e
}

func maximumBulkError(detail int) *Error {
	var largest *Error
	maxBytes := 0
	for _, entry := range []struct {
		code int
		kind string
	}{{400, "invalidSyntax"}, {401, ""}, {403, ""}, {404, ""}, {409, "uniqueness"}, {412, ""}, {413, ""}, {415, ""}, {424, ""}, {428, ""}, {500, ""}, {501, ""}, {503, ""}} {
		e := bulkChildError(entry.code, entry.kind, detail)
		wire, _ := json.Marshal(e)
		if len(wire) > maxBytes {
			largest, maxBytes = e, len(wire)
		}
	}
	return largest
}

func writeBulkBytes(w io.Writer, wire []byte) error {
	n, err := w.Write(wire)
	if err == nil && n != len(wire) {
		return io.ErrShortWrite
	}
	return err
}
