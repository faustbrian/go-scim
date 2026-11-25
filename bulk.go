package scim

import (
	"bytes"
	"encoding/json"
	"io"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"unicode/utf8"
)

const bulkRequestSchema = "urn:ietf:params:scim:api:messages:2.0:BulkRequest"

// BulkPolicy bounds pure request planning. Zero is invalid. The reference
// maxima are 1,000 operations, 2 MiB canonical request bytes and 1 MiB canonical
// child bytes; payload and child minima are 16 KiB and 1 KiB respectively.
// MaxOperationBytes cannot exceed MaxPayloadBytes. Limits independently bounds
// the raw input and each child resource. This policy does not enable Bulk.
type BulkPolicy struct {
	MaxOperations, MaxPayloadBytes, MaxOperationBytes int
}

// DefaultBulkPolicy returns the identity platform reference planning limits.
// It does not select execution, durable admission or discovery support.
func DefaultBulkPolicy() BulkPolicy {
	return BulkPolicy{MaxOperations: 1000, MaxPayloadBytes: 1048576, MaxOperationBytes: 262144}
}

func (p BulkPolicy) valid() bool {
	return p.MaxOperations >= 1 && p.MaxOperations <= 1000 &&
		p.MaxPayloadBytes >= 16384 && p.MaxPayloadBytes <= 2097152 &&
		p.MaxOperationBytes >= 1024 && p.MaxOperationBytes <= 1048576 && p.MaxOperationBytes <= p.MaxPayloadBytes
}

// BulkTarget identifies only an exact protocol resource partition and a literal
// ResourceID or request-local BulkID. POST has neither ID. It establishes no
// existence, connection scope, identity mapping or mutation authority.
type BulkTarget struct {
	ResourceType string
	ResourceID   string
	BulkID       string
}

// BulkOperation is a detached ordered child intent. Data is canonical JSON,
// not a validated resource or PATCH. Version retains the exact supplied ETag.
// Dependencies are unique original operation indexes in ascending order.
// Error records a redacted structural child failure; that child remains in the
// request and needs a durable failed result, not omission or execution.
type BulkOperation struct {
	Index        int
	Method       string
	Path         string
	Version      string
	BulkID       string
	Target       BulkTarget
	Data         json.RawMessage
	Dependencies []int
	Error        *Error
}

// BulkComponent is one SCC in dependency-first execution order. Operations are
// original indexes in ascending order. Cyclic includes a singleton self-loop.
// A future executor must commit cyclic components atomically; an acyclic
// singleton commits independently. Neither implies whole-request atomicity.
type BulkComponent struct {
	Operations []int
	Cyclic     bool
}

// BulkPlan is immutable, detached pure parsing/planning output. Its zero value
// is not admitted input. It allocates no resource/command IDs, persists nothing,
// checks no authority and does not enable Bulk on any service. Native admission
// must still prove response-size bounds, resource validity, connection scope,
// durable graph/child custody and the transaction contract before mutation.
type BulkPlan struct {
	failOnErrors  int
	bulkIDPresent []bool
	operations    []BulkOperation
	components    []BulkComponent
	canonical     []byte
	extensions    []Schema
	limits        Limits
}

// FailOnErrors returns the request threshold, with zero/omission meaning no
// cutoff. Only durable failed child results count; planning failures do not
// activate a cutoff. The selected reference request maximum is exactly 100.
func (p BulkPlan) FailOnErrors() int { return p.failOnErrors }

// Operations returns a deep copy in original request order, including failures.
func (p BulkPlan) Operations() []BulkOperation {
	out := slices.Clone(p.operations)
	for i := range out {
		out[i].Data = slices.Clone(out[i].Data)
		out[i].Dependencies = slices.Clone(out[i].Dependencies)
		if out[i].Error != nil {
			copy := *out[i].Error
			out[i].Error = &copy
		}
	}
	return out
}

// Components returns the detached deterministic SCC condensation plan. Among
// ready SCCs, the lowest original operation index wins each tie.
func (p BulkPlan) Components() []BulkComponent {
	out := slices.Clone(p.components)
	for i := range out {
		out[i].Operations = slices.Clone(out[i].Operations)
	}
	return out
}

// CanonicalRequest returns detached fingerprint input, not a digest or ledger.
// It preserves operation order, supplied fields, targets, bodies, bulk IDs and
// preconditions, including invalid child fields. JSON whitespace and object
// member order are insignificant; scalar spelling and field presence remain
// exact. Durable owners must additionally bind the authenticated connection.
func (p BulkPlan) CanonicalRequest() []byte { return slices.Clone(p.canonical) }

// ParseBulk strictly decodes a bounded BulkRequest and builds its complete
// request-local graph. Malformed JSON/envelopes, duplicate IDs, unknown or
// ambiguous references and exceeded admission limits reject the whole request.
// Invalid child methods/targets/data are retained as ordered child errors.
// Extension schemas define reference-valued slots; arbitrary string attributes
// containing "bulkId:" are never dependencies. This is not durable admission:
// resource/PATCH validation and conservative terminal-response preflight remain
// mandatory at the future native owner before it persists or executes children.
func ParseBulk(body []byte, extensions []Schema, policy BulkPolicy, limits Limits) (BulkPlan, error) {
	if !limits.valid() || !policy.valid() || !validGroupExtensions(extensions, limits) {
		return BulkPlan{}, failure(400, "invalidValue")
	}
	if len(body) > limits.BodyBytes {
		return BulkPlan{}, failure(413, "")
	}
	if !utf8.Valid(body) {
		return BulkPlan{}, failure(400, "invalidSyntax")
	}
	doc, children, err := decodeBulkEnvelope(body, policy.MaxOperations)
	if err != nil {
		return BulkPlan{}, err
	}
	if !exactEnvelope(doc, bulkRequestSchema) || len(children) == 0 {
		return BulkPlan{}, failure(400, "invalidValue")
	}
	plan := BulkPlan{bulkIDPresent: make([]bool, len(children)), operations: make([]BulkOperation, 0, len(children)), extensions: cloneSchemas(extensions), limits: limits}
	if raw, supplied := lookup(doc, "failOnErrors"); supplied {
		number, ok := raw.(json.Number)
		if !ok {
			return BulkPlan{}, failure(400, "invalidValue")
		}
		threshold, err := strconv.Atoi(string(number))
		// goals/scim.md fixes the selected request maximum at exactly 100.
		if err != nil || threshold < 0 || threshold > 100 {
			return BulkPlan{}, failure(400, "invalidValue")
		}
		plan.failOnErrors = threshold
	}
	canonicalChildren := make([]any, 0, len(children))
	for i, raw := range children {
		// The resource budget belongs to each data object, not the aggregate
		// Bulk envelope or its five operation metadata fields.
		childLimits := limits
		childLimits.ResourceDepth++
		childLimits.ResourceAttributes += 5
		child, err := decodeObject(raw, childLimits)
		if err != nil {
			return BulkPlan{}, err
		}
		canonical, err := json.Marshal(child)
		if err != nil {
			return BulkPlan{}, failure(400, "invalidSyntax")
		}
		if len(canonical) > policy.MaxOperationBytes {
			return BulkPlan{}, failure(413, "")
		}
		canonicalChildren = append(canonicalChildren, child)
		op := parseBulkOperation(i, child, limits)
		plan.operations = append(plan.operations, op)
		_, plan.bulkIDPresent[i] = bulkString(child, "bulkId")
	}
	for key := range doc {
		if strings.EqualFold(key, "Operations") {
			doc[key] = canonicalChildren
		}
	}
	plan.canonical, err = json.Marshal(doc)
	if err != nil {
		return BulkPlan{}, failure(400, "invalidSyntax")
	}
	if len(plan.canonical) > policy.MaxPayloadBytes {
		return BulkPlan{}, failure(413, "")
	}
	if err := plan.resolveBulkReferences(extensions, limits); err != nil {
		return BulkPlan{}, err
	}
	plan.components = planBulkComponents(plan.operations)
	return plan, nil
}

func decodeBulkEnvelope(body []byte, maxOperations int) (map[string]any, []json.RawMessage, error) {
	d := json.NewDecoder(bytes.NewReader(body))
	d.UseNumber()
	start, err := d.Token()
	if err != nil || start != json.Delim('{') {
		return nil, nil, failure(400, "invalidSyntax")
	}
	doc := map[string]any{}
	seen := map[string]bool{}
	var children []json.RawMessage
	for d.More() {
		rawKey, err := d.Token()
		key, ok := rawKey.(string)
		if err != nil || !ok || seen[foldString(key)] {
			return nil, nil, failure(400, "invalidSyntax")
		}
		seen[foldString(key)] = true
		switch strings.ToLower(key) {
		case "schemas":
			start, err := d.Token()
			if err != nil || start != json.Delim('[') {
				return nil, nil, failure(400, "invalidSyntax")
			}
			schema, err := d.Token()
			id, ok := schema.(string)
			if err != nil || !ok {
				return nil, nil, failure(400, "invalidSyntax")
			}
			if end, err := d.Token(); err != nil || end != json.Delim(']') {
				return nil, nil, failure(400, "invalidSyntax")
			}
			doc[key] = []any{id}
		case "failonerrors":
			raw, err := d.Token()
			number, ok := raw.(json.Number)
			if err != nil || !ok {
				return nil, nil, failure(400, "invalidValue")
			}
			doc[key] = number
		case "operations":
			start, err := d.Token()
			if err != nil || start != json.Delim('[') {
				return nil, nil, failure(400, "invalidValue")
			}
			for d.More() {
				if len(children) >= maxOperations {
					return nil, nil, failure(413, "")
				}
				var child json.RawMessage
				if err := d.Decode(&child); err != nil {
					return nil, nil, failure(400, "invalidSyntax")
				}
				children = append(children, child)
			}
			if end, err := d.Token(); err != nil || end != json.Delim(']') {
				return nil, nil, failure(400, "invalidSyntax")
			}
			doc[key] = nil
		default:
			return nil, nil, failure(400, "invalidValue")
		}
	}
	if end, err := d.Token(); err != nil || end != json.Delim('}') {
		return nil, nil, failure(400, "invalidSyntax")
	}
	if _, err := d.Token(); err != io.EOF {
		return nil, nil, failure(400, "invalidSyntax")
	}
	return doc, children, nil
}

func parseBulkOperation(index int, child map[string]any, limits Limits) BulkOperation {
	op := BulkOperation{Index: index}
	invalid := func() { op.Error = failure(400, "invalidValue") }
	for key := range child {
		if !slicesContains([]string{"method", "path", "version", "bulkid", "data"}, strings.ToLower(key)) {
			invalid()
		}
	}
	op.Method, _ = bulkString(child, "method")
	op.Path, _ = bulkString(child, "path")
	op.Version, _ = bulkString(child, "version")
	op.BulkID, _ = bulkString(child, "bulkId")
	if !slicesContains([]string{"POST", "PUT", "PATCH", "DELETE"}, op.Method) {
		invalid()
	}
	if raw, supplied := lookup(child, "bulkId"); supplied {
		id, ok := raw.(string)
		if !ok || !safeBulkID(id) {
			invalid()
		}
	}
	if op.Method == "POST" && op.BulkID == "" {
		invalid()
	}
	if _, supplied := lookup(child, "version"); supplied && (!validVersion(Version(op.Version)) || op.Method == "POST") {
		invalid()
	}
	target, ok := parseBulkTarget(op.Method, op.Path, limits.PathBytes)
	if !ok {
		invalid()
	} else {
		op.Target = target
	}
	data, supplied := lookup(child, "data")
	if supplied {
		op.Data, _ = json.Marshal(data)
		if _, err := decodeObject(op.Data, limits); err != nil || op.Method == "DELETE" {
			invalid()
		}
	} else if op.Method != "DELETE" {
		invalid()
	}
	return op
}

func bulkString(doc map[string]any, key string) (string, bool) {
	value, _ := lookup(doc, key)
	text, ok := value.(string)
	return text, ok
}

func safeBulkID(id string) bool { return safeID(id) }

func parseBulkTarget(method, path string, pathBytes int) (BulkTarget, bool) {
	if len(path) > pathBytes || strings.ContainsAny(path, "?#\\") {
		return BulkTarget{}, false
	}
	parsed, err := url.Parse(path)
	if err != nil || parsed.IsAbs() || parsed.Host != "" || parsed.User != nil || !unambiguousMemberPath(parsed.EscapedPath()) {
		return BulkTarget{}, false
	}
	parts := strings.Split(parsed.Path, "/")
	if len(parts) < 2 || parts[0] != "" || parts[1] != "Users" && parts[1] != "Groups" {
		return BulkTarget{}, false
	}
	target := BulkTarget{ResourceType: strings.TrimSuffix(parts[1], "s")}
	if method == "POST" {
		return target, len(parts) == 2
	}
	if len(parts) != 3 || parts[2] == "." || parts[2] == ".." {
		return BulkTarget{}, false
	}
	if strings.HasPrefix(parts[2], "bulkId:") {
		target.BulkID = strings.TrimPrefix(parts[2], "bulkId:")
		return target, safeBulkID(target.BulkID)
	}
	target.ResourceID = parts[2]
	return target, safeID(target.ResourceID)
}

type bulkReferenceForm uint8

const (
	bulkReferenceURI bulkReferenceForm = iota
	bulkReferenceID
)

type bulkReference struct {
	id, resourceType string
	// These transient slots belong only to the detached decoded body. Planning
	// and resolution share traversal, but never retain setters in the plan.
	set     func(string)
	setKind func(string)
	form    bulkReferenceForm
}

func (p *BulkPlan) resolveBulkReferences(extensions []Schema, limits Limits) error {
	ids := map[string]int{}
	for i, op := range p.operations {
		if op.BulkID == "" {
			continue
		}
		if _, duplicate := ids[op.BulkID]; duplicate {
			return failure(400, "invalidValue")
		}
		ids[op.BulkID] = i
	}
	for i := range p.operations {
		op := &p.operations[i]
		var references []bulkReference
		if op.Target.BulkID != "" {
			references = append(references, bulkReference{id: op.Target.BulkID, resourceType: op.Target.ResourceType})
		}
		if op.Error == nil && len(op.Data) != 0 {
			doc, err := decodeObject(op.Data, limits)
			if err != nil {
				return err
			}
			bodyRefs, err := bulkBodyReferences(doc, op, extensions, limits)
			if err != nil {
				return err
			}
			references = append(references, bodyRefs...)
		}
		dependencies := map[int]bool{}
		for _, ref := range references {
			predecessor, found := ids[ref.id]
			if !found {
				return failure(400, "invalidValue")
			}
			create := p.operations[predecessor]
			if create.Method != "POST" || create.Target.ResourceType == "" || ref.resourceType != "" && ref.resourceType != create.Target.ResourceType {
				return failure(400, "invalidValue")
			}
			dependencies[predecessor] = true
		}
		for predecessor := range dependencies {
			op.Dependencies = append(op.Dependencies, predecessor)
		}
		slices.Sort(op.Dependencies)
	}
	return nil
}

func bulkBodyReferences(doc map[string]any, op *BulkOperation, extensions []Schema, limits Limits) ([]bulkReference, error) {
	core := userProfile().schema
	if op.Target.ResourceType == "Group" {
		core = groupProfile().schema
	}
	if op.Method != "PATCH" {
		return bulkDocumentReferences(doc, core, extensions)
	}
	raw, _ := lookup(doc, "Operations")
	patchOps, ok := raw.([]any)
	if !ok || len(patchOps) == 0 || len(patchOps) > limits.PatchOperations {
		op.Error = failure(400, "invalidValue")
		return nil, nil
	}
	var out []bulkReference
	for _, raw := range patchOps {
		patchOp, ok := raw.(map[string]any)
		if !ok {
			op.Error = failure(400, "invalidValue")
			return nil, nil
		}
		path, supplied := bulkString(patchOp, "path")
		value, _ := lookup(patchOp, "value")
		if !supplied {
			if object, ok := value.(map[string]any); ok {
				refs, err := bulkPathlessReferences(object, op, core, extensions, limits)
				if err != nil {
					return nil, err
				}
				if op.Error != nil {
					return nil, nil
				}
				out = append(out, refs...)
			}
			continue
		}
		parsed, err := parsePatchPath(path, extensions, limits, core)
		if err != nil {
			op.Error = failure(400, "invalidPath")
			return nil, nil
		}
		// The path parser owns schema resolution; the final declared attribute
		// identifies reference values without interpreting unrelated strings.
		attribute := parsed.path.attribute()
		if len(parsed.tail.parts) != 0 {
			attribute = parsed.tail.attribute()
		}
		member := core.ID == groupSchema && len(parsed.path.parts) != 0 && strings.EqualFold(parsed.path.parts[0].Name, "members") && parsed.path.extension == ""
		refs, err := bulkAttributeReferences(value, attribute, member, bulkMapSetter(patchOp, "value"))
		if err != nil {
			return nil, err
		}
		out = append(out, refs...)
	}
	return out, nil
}

func bulkPathlessReferences(doc map[string]any, op *BulkOperation, core Schema, extensions []Schema, limits Limits) ([]bulkReference, error) {
	var out []bulkReference
	for name, value := range doc {
		if extension, found := extensionSchema(extensions, name); found {
			object, ok := value.(map[string]any)
			if !ok {
				op.Error = failure(400, "invalidValue")
				return nil, nil
			}
			refs, err := bulkDocumentReferences(object, extension, nil)
			if err != nil {
				return nil, err
			}
			out = append(out, refs...)
			continue
		}
		parsed, err := parsePatchPath(name, extensions, limits, core)
		if err != nil {
			op.Error = failure(400, "invalidPath")
			return nil, nil
		}
		attribute := parsed.path.attribute()
		if len(parsed.tail.parts) != 0 {
			attribute = parsed.tail.attribute()
		}
		member := core.ID == groupSchema && parsed.path.extension == "" && len(parsed.path.parts) != 0 && strings.EqualFold(parsed.path.parts[0].Name, "members")
		refs, err := bulkAttributeReferences(value, attribute, member, bulkMapSetter(doc, name))
		if err != nil {
			return nil, err
		}
		out = append(out, refs...)
	}
	return out, nil
}

func bulkDocumentReferences(doc map[string]any, schema Schema, extensions []Schema) ([]bulkReference, error) {
	var out []bulkReference
	for name, value := range doc {
		if extension, found := extensionSchema(extensions, name); found {
			if object, ok := value.(map[string]any); ok {
				refs, err := bulkDocumentReferences(object, extension, nil)
				if err != nil {
					return nil, err
				}
				out = append(out, refs...)
			}
			continue
		}
		attribute, found := findAttribute(schema.Attributes, name)
		if !found {
			continue
		}
		coreGroupMember := schema.ID == groupSchema && strings.EqualFold(name, "members")
		refs, err := bulkAttributeReferences(value, attribute, coreGroupMember, bulkMapSetter(doc, name))
		if err != nil {
			return nil, err
		}
		out = append(out, refs...)
	}
	return out, nil
}

func bulkAttributeReferences(value any, attribute Attribute, member bool, set func(string)) ([]bulkReference, error) {
	if values, ok := value.([]any); ok {
		var out []bulkReference
		for index, item := range values {
			refs, err := bulkAttributeReferences(item, attribute, member, func(text string) { values[index] = text })
			if err != nil {
				return nil, err
			}
			out = append(out, refs...)
		}
		return out, nil
	}
	if member {
		if object, ok := value.(map[string]any); ok {
			return bulkMemberReferences(object)
		}
		if strings.EqualFold(attribute.Name, "value") || attribute.Type == "reference" {
			form := bulkReferenceURI
			if strings.EqualFold(attribute.Name, "value") {
				form = bulkReferenceID
			}
			return bulkReferenceSlot(value, "", set, form)
		}
	}
	if attribute.Type == "reference" {
		return bulkReferenceSlot(value, "", set, bulkReferenceURI)
	}
	if attribute.Type == "complex" {
		if object, ok := value.(map[string]any); ok {
			return bulkDocumentReferences(object, Schema{Attributes: attribute.SubAttributes}, nil)
		}
	}
	return nil, nil
}

func bulkMemberReferences(member map[string]any) ([]bulkReference, error) {
	typ, _ := bulkString(member, "type")
	if raw, supplied := lookup(member, "type"); supplied && raw != nil {
		if _, ok := raw.(string); !ok {
			return nil, failure(400, "invalidValue")
		}
	}
	if strings.EqualFold(typ, "user") {
		typ = "User"
	}
	if strings.EqualFold(typ, "group") {
		typ = "Group"
	}
	var out []bulkReference
	for _, key := range []string{"value", "$ref"} {
		value, _ := lookup(member, key)
		form := bulkReferenceURI
		if key == "value" {
			form = bulkReferenceID
		}
		refs, err := bulkReferenceSlot(value, typ, bulkMapSetter(member, key), form)
		if err != nil {
			return nil, err
		}
		out = append(out, refs...)
	}
	if len(out) == 2 && (out[0].id != out[1].id || out[0].resourceType != "" && out[1].resourceType != "" && out[0].resourceType != out[1].resourceType) {
		return nil, failure(400, "invalidValue")
	}
	if len(out) == 1 {
		value, _ := bulkString(member, "value")
		ref, _ := bulkString(member, "$ref")
		if value != "" && ref != "" {
			// A persisted ID/URI cannot simultaneously identify a fresh local
			// create; waiting for execution would make graph custody ambiguous.
			return nil, failure(400, "invalidValue")
		}
	}
	if typ == "" {
		// Group normalization otherwise defaults a member with no type/$ref to
		// User. Preserve the referenced create's actual partition, including a
		// Group self-loop. Missing, null and empty type have the same semantics;
		// retain every supplied non-empty type string unchanged.
		setKind := bulkMapSetter(member, "type")
		if setKind == nil {
			setKind = func(kind string) { member["type"] = kind }
		}
		for index := range out {
			out[index].setKind = setKind
		}
	}
	return out, nil
}

func bulkMapSetter(doc map[string]any, name string) func(string) {
	for key := range doc {
		if strings.EqualFold(key, name) {
			return func(text string) { doc[key] = text }
		}
	}
	return nil
}

func bulkReferenceSlot(value any, resourceType string, set func(string), form bulkReferenceForm) ([]bulkReference, error) {
	if value != nil {
		if _, ok := value.(string); !ok {
			return nil, failure(400, "invalidValue")
		}
	}
	refs, err := bulkReferenceValue(value, resourceType)
	for index := range refs {
		refs[index].set, refs[index].form = set, form
	}
	return refs, err
}

func bulkReferenceValue(value any, resourceType string) ([]bulkReference, error) {
	text, ok := value.(string)
	if !ok {
		return nil, nil
	}
	if strings.HasPrefix(text, "/Users/bulkId:") || strings.HasPrefix(text, "/Groups/bulkId:") {
		target, ok := parseBulkTarget("PUT", text, len(text))
		if !ok || resourceType != "" && resourceType != target.ResourceType {
			return nil, failure(400, "invalidValue")
		}
		return []bulkReference{{id: target.BulkID, resourceType: target.ResourceType}}, nil
	}
	if strings.HasPrefix(text, "bulkId:") {
		id := strings.TrimPrefix(text, "bulkId:")
		if !safeBulkID(id) {
			return nil, failure(400, "invalidValue")
		}
		return []bulkReference{{id: id, resourceType: resourceType}}, nil
	}
	// Only the exact forms above establish request-local identity. Absolute,
	// foreign-relative and encoded placeholder paths cannot silently become
	// literal resource references outside this request's dependency graph.
	if parsed, err := url.Parse(text); err == nil && strings.Contains(parsed.Path, "/bulkId:") {
		return nil, failure(400, "invalidValue")
	}
	return nil, nil
}
