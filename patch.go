package scim

import (
	"strings"
)

// PatchOperation is a detached parsed operation. Value contains only bounded
// JSON values. Constructing it confers no write or storage authority.
type PatchOperation struct {
	Op, Path string
	Value    any
}

// Patch is an immutable validated RFC 7644 PatchOp intent, not a transaction.
// Zero is invalid. Only the trusted store can commit a resulting candidate.
type Patch struct{ operations []PatchOperation }

// Operations returns a deep copy, safe for callers to inspect or modify.
func (p Patch) Operations() []PatchOperation {
	out := make([]PatchOperation, len(p.operations))
	for i, op := range p.operations {
		out[i] = op
		out[i].Value = cloneValue(op.Value)
	}
	return out
}

// ParsePatch rejects duplicate/case-alias JSON, unsupported credentials and
// invalid bounded paths before any mapper or store can observe the request.
func ParsePatch(body []byte, extensions []Schema, limits Limits) (Patch, error) {
	if !limits.valid() || !validateSchemas(extensions, limits) {
		return Patch{}, failure(400, "invalidValue")
	}
	doc, e := decodeObject(body, limits)
	if e != nil {
		return Patch{}, failure(400, "invalidValue")
	}
	return parsePatchDocument(doc, extensions, limits)
}
func parsePatchDocument(doc map[string]any, ext []Schema, l Limits, core ...Schema) (Patch, error) {
	for key := range doc {
		if !strings.EqualFold(key, "schemas") && !strings.EqualFold(key, "Operations") {
			return Patch{}, failure(400, "invalidValue")
		}
	}
	if !exactEnvelope(doc, patchSchema) {
		return Patch{}, failure(400, "invalidValue")
	}
	raw, ok := lookup(doc, "Operations")
	if !ok {
		return Patch{}, failure(400, "invalidValue")
	}
	ops, ok := raw.([]any)
	if !ok || len(ops) == 0 || len(ops) > l.PatchOperations {
		return Patch{}, failure(400, "invalidValue")
	}
	p := Patch{}
	for _, item := range ops {
		obj, ok := item.(map[string]any)
		if !ok {
			return Patch{}, failure(400, "invalidValue")
		}
		for key := range obj {
			if !strings.EqualFold(key, "op") && !strings.EqualFold(key, "path") && !strings.EqualFold(key, "value") {
				return Patch{}, failure(400, "invalidValue")
			}
		}
		verb, _ := lookup(obj, "op")
		op, ok := verb.(string)
		op = strings.ToLower(op)
		if !ok || !slicesContains([]string{"add", "remove", "replace"}, op) {
			return Patch{}, failure(400, "invalidValue")
		}
		rawPath, hasPath := lookup(obj, "path")
		path := ""
		if hasPath {
			var ok bool
			path, ok = rawPath.(string)
			if !ok || path == "" {
				return Patch{}, failure(400, "invalidPath")
			}
		}
		value, hasValue := lookup(obj, "value")
		if op == "remove" {
			if path == "" || hasValue {
				return Patch{}, failure(400, "invalidValue")
			}
		} else if !hasValue {
			return Patch{}, failure(400, "invalidValue")
		}
		if path != "" {
			if _, e := parsePatchPath(path, ext, l, core...); e != nil {
				return Patch{}, e
			}
		} else {
			values, ok := value.(map[string]any)
			if !ok || len(values) == 0 {
				return Patch{}, failure(400, "invalidValue")
			}
			if err := pathlessTargets(values, ext, l, core...); err != nil {
				return Patch{}, err
			}
			for key, v := range values {
				if schema, ok := extensionSchema(ext, key); ok {
					m, ok := v.(map[string]any)
					if !ok {
						return Patch{}, failure(400, "invalidValue")
					}
					if e := checkWriteValues(m, schema.Attributes); e != nil {
						return Patch{}, e
					}
					continue
				}
				p, e := parsePatchPath(key, ext, l, core...)
				if e != nil {
					return Patch{}, e
				}
				if e = checkPatchValue(v, p.path.attribute()); e != nil {
					return Patch{}, e
				}
			}
		}
		// For a path-targeted complex value, reject credential subattributes before
		// admission too, even if a later schema validation would also reject them.
		if path != "" && hasValue {
			target, e := parsePatchPath(path, ext, l, core...)
			if e != nil {
				return Patch{}, e
			}
			a := target.path.attribute()
			if len(target.tail.parts) > 0 {
				a = target.tail.attribute()
			}
			if e = checkPatchValue(value, a); e != nil {
				return Patch{}, e
			}
		}
		p.operations = append(p.operations, PatchOperation{Op: op, Path: path, Value: cloneValue(value)})
	}
	return p, nil
}
func exactEnvelope(doc map[string]any, urn string) bool {
	v, ok := lookup(doc, "schemas")
	if !ok {
		return false
	}
	ids, ok := v.([]any)
	return ok && len(ids) == 1 && ids[0] == urn
}
func extensionSchema(ext []Schema, id string) (Schema, bool) {
	for _, s := range ext {
		if s.ID == id {
			return s, true
		}
	}
	return Schema{}, false
}
func checkWriteValues(doc map[string]any, attrs []Attribute) error {
	for name, v := range doc {
		a, ok := findAttribute(attrs, name)
		if !ok {
			return failure(400, "invalidValue")
		}
		if a.Mutability == "readOnly" {
			return failure(400, "mutability")
		}
		if e := checkPatchValue(v, a); e != nil {
			return e
		}
	}
	return nil
}
func checkPatchValue(v any, a Attribute) error {
	if a.Returned == "never" || a.Mutability == "writeOnly" {
		_ = DecideCredentialWrite(CredentialWrite{AttributePath: a.Name})
		return failure(400, "mutability")
	}
	if a.Type != "complex" {
		return nil
	}
	if a.MultiValued {
		if array, ok := v.([]any); ok {
			for _, element := range array {
				if obj, ok := element.(map[string]any); ok {
					if e := checkWriteValues(obj, a.SubAttributes); e != nil {
						return e
					}
				}
			}
			return nil
		}
	}
	if obj, ok := v.(map[string]any); ok {
		return checkWriteValues(obj, a.SubAttributes)
	}
	return nil
}

type patchPath struct {
	path     attributePath
	selector Filter
	selected bool
	tail     attributePath
}

func parsePatchPath(raw string, ext []Schema, l Limits, core ...Schema) (patchPath, error) {
	if len(raw) > l.PathBytes {
		return patchPath{}, failure(400, "invalidPath")
	}
	open := strings.IndexByte(raw, '[')
	prefix := raw
	selector := ""
	tail := ""
	if open >= 0 {
		prefix = raw[:open]
		quote, escape := false, false
		close := -1
		for i := open + 1; i < len(raw); i++ {
			c := raw[i]
			if escape {
				escape = false
				continue
			}
			if c == '\\' && quote {
				escape = true
				continue
			}
			if c == '"' {
				quote = !quote
			}
			if c == ']' && !quote {
				close = i
				break
			}
		}
		if close < 0 {
			return patchPath{}, failure(400, "invalidPath")
		}
		selector = raw[open+1 : close]
		tail = raw[close+1:]
		if tail != "" {
			if !strings.HasPrefix(tail, ".") {
				return patchPath{}, failure(400, "invalidPath")
			}
			tail = tail[1:]
			if tail == "" {
				return patchPath{}, failure(400, "invalidPath")
			}
		}
	}
	path, e := resolveAttributePath(prefix, ext, l, nil, true, core...)
	if e != nil {
		return patchPath{}, e
	}
	for _, a := range path.parts {
		if a.Mutability == "readOnly" {
			return patchPath{}, failure(400, "mutability")
		}
		if a.Returned == "never" || a.Mutability == "writeOnly" {
			_ = DecideCredentialWrite(CredentialWrite{AttributePath: a.Name})
			return patchPath{}, failure(400, "mutability")
		}
	}
	p := patchPath{path: path}
	if open >= 0 {
		a := path.attribute()
		if a.Type != "complex" || !a.MultiValued || selector == "" {
			return p, failure(400, "invalidPath")
		}
		f, e := parseFilter(selector, ext, l, a.SubAttributes, core...)
		if e != nil {
			return p, failure(400, "invalidPath")
		}
		p.selector = f
		p.selected = true
		if tail != "" {
			p.tail, e = resolveAttributePath(tail, ext, l, a.SubAttributes, true, core...)
			if e != nil {
				return p, e
			}
			for _, a := range p.tail.parts {
				if a.Mutability == "readOnly" || a.Returned == "never" || a.Mutability == "writeOnly" {
					return p, failure(400, "mutability")
				}
			}
		}
	}
	return p, nil
}

func (s *protocolService) applyPatch(current Resource, p Patch) (WritableResource, error) {
	doc := writableDoc(WritableResource{Schemas: current.Schemas, ExternalID: current.ExternalID, Attributes: s.writableAttributes(current.Attributes)})
	budget := patchBudget{root: doc, limits: s.config.Limits}
	if s.profile.schema.ID == groupSchema {
		budget.groupMembers = &s.groups.members
	}
	for _, op := range p.operations {
		previous := current.Attributes
		if s.profile.schema.ID == groupSchema {
			previous = cloneMap(doc)
			var err error
			op, err = s.canonicalGroupPatchOperation(op, doc)
			if err != nil {
				return WritableResource{}, err
			}
		}
		if op.Path == "" {
			values := op.Value.(map[string]any)
			for key, v := range values {
				if schema, ok := extensionSchema(s.config.Extensions, key); ok {
					obj, _ := doc[key].(map[string]any)
					if obj == nil {
						obj = map[string]any{}
						doc[key] = obj
						ids, _ := doc["schemas"].([]any)
						found := false
						for _, id := range ids {
							if id == key {
								found = true
							}
						}
						if !found {
							doc["schemas"] = append(ids, key)
						}
					}
					for name, value := range v.(map[string]any) {
						a, _ := findAttribute(schema.Attributes, name)
						if e := changeField(obj, a, op.Op, value, budget); e != nil {
							return WritableResource{}, e
						}
					}
					continue
				}
				path, e := parsePatchPath(key, s.config.Extensions, s.config.Limits, s.profile.schema)
				if e != nil {
					return WritableResource{}, e
				}
				if e = applyPath(doc, path, op.Op, v, budget); e != nil {
					return WritableResource{}, e
				}
			}
		} else {
			path, e := parsePatchPath(op.Path, s.config.Extensions, s.config.Limits, s.profile.schema)
			if e != nil {
				return WritableResource{}, e
			}
			if e = applyPath(doc, path, op.Op, op.Value, budget); e != nil {
				return WritableResource{}, e
			}
		}
		// Intermediate steps must be valid too; required/mutability rules cannot be
		// temporarily bypassed by removing an immutable value and re-adding it later.
		if err := checkTree(doc, s.config.Limits); err != nil {
			return WritableResource{}, failure(400, "invalidValue")
		}
		normalized, e := s.normalize(doc, previous)
		if e != nil {
			return WritableResource{}, e
		}
		doc = writableDoc(normalized)
		budget.root = doc
	}
	if s.profile.schema.ID == groupSchema {
		return s.normalize(doc, nil)
	}
	return s.normalize(doc, current.Attributes)
}
func applyPath(doc map[string]any, p patchPath, verb string, value any, budget patchBudget) error {
	root := doc
	if p.path.extension != "" {
		m, ok := doc[p.path.extension].(map[string]any)
		if !ok {
			if verb == "remove" {
				return failure(400, "noTarget")
			}
			m = map[string]any{}
			doc[p.path.extension] = m
			ids, _ := doc["schemas"].([]any)
			found := false
			for _, id := range ids {
				if id == p.path.extension {
					found = true
				}
			}
			if !found {
				doc["schemas"] = append(ids, p.path.extension)
			}
		}
		root = m
	}
	return walkChange(root, p.path.parts, p, verb, value, budget)
}
func walkChange(obj map[string]any, parts []Attribute, p patchPath, verb string, value any, budget patchBudget) error {
	a := parts[0]
	if len(parts) > 1 {
		if a.MultiValued {
			array, ok := obj[a.Name].([]any)
			if !ok || len(array) == 0 {
				return failure(400, "noTarget")
			}
			for _, v := range array {
				m, ok := v.(map[string]any)
				if !ok {
					return failure(400, "invalidValue")
				}
				if e := walkChange(m, parts[1:], p, verb, value, budget); e != nil {
					return e
				}
			}
			return nil
		}
		child, ok := obj[a.Name].(map[string]any)
		if !ok {
			if verb == "remove" {
				return failure(400, "noTarget")
			}
			child = map[string]any{}
			obj[a.Name] = child
		}
		return walkChange(child, parts[1:], p, verb, value, budget)
	}
	if !p.selected {
		return changeField(obj, a, verb, value, budget)
	}
	array, ok := obj[a.Name].([]any)
	if !ok {
		return failure(400, "noTarget")
	}
	out := []any{}
	selected := make([]bool, len(array))
	for i, element := range array {
		m, ok := element.(map[string]any)
		if !ok {
			return failure(400, "invalidValue")
		}
		selected[i] = p.selector.matches(m)
	}
	// RFC 7644 section 3.5.2 requires primary reassignment in the same PATCH.
	primary, hasPrimary := primaryAttribute(a)
	incomingPrimary := false
	if verb != "remove" && hasPrimary {
		if len(p.tail.parts) == 1 && p.tail.parts[0].Name == primary.Name && value == true {
			incomingPrimary = true
		}
		if len(p.tail.parts) == 0 {
			incomingPrimary = primaryTrue(value, primary)
		}
	}
	if incomingPrimary {
		for i, element := range array {
			if !selected[i] {
				demotePrimary(element, primary)
			}
		}
	}
	matched := false
	for index, element := range array {
		m, ok := element.(map[string]any)
		if !ok {
			return failure(400, "invalidValue")
		}
		if !selected[index] {
			out = append(out, m)
			continue
		}
		matched = true
		if len(p.tail.parts) > 0 {
			if e := walkChange(m, p.tail.parts, patchPath{}, verb, value, budget); e != nil {
				return e
			}
			out = append(out, m)
			continue
		}
		if verb == "remove" {
			continue
		}
		if verb == "replace" {
			// RFC 7644 3.5.2.3 replaces selected whole records, unlike a
			// singular complex attribute's supplied-subattribute merge.
			one := a
			one.MultiValued = false
			candidate, err := normalizeValue(value, one, m)
			if err != nil {
				return err
			}
			if err := budget.element(array, index, candidate); err != nil {
				return err
			}
			array[index] = cloneValue(candidate)
			out = append(out, array[index])
		} else {
			incoming, ok := value.(map[string]any)
			if !ok {
				return failure(400, "invalidValue")
			}
			for key, v := range incoming {
				sub, ok := findAttribute(a.SubAttributes, key)
				if !ok {
					return failure(400, "invalidValue")
				}
				if err := changeField(m, sub, verb, v, budget); err != nil {
					return err
				}
			}
			out = append(out, m)
		}
	}
	if !matched {
		return failure(400, "noTarget")
	}
	obj[a.Name] = out
	return nil
}
func changeField(obj map[string]any, a Attribute, verb string, value any, budget patchBudget) error {
	old, exists := obj[a.Name]
	if a.Mutability == "readOnly" {
		return failure(400, "mutability")
	}
	if verb != "remove" {
		var err error
		value, err = normalizePatchValue(value, a)
		if err != nil {
			return err
		}
	}
	if a.Mutability == "immutable" && present(old) && (verb == "remove" || a.Type != "complex" || a.MultiValued) {
		if verb == "remove" || !sameValue(old, value, a) {
			return failure(400, "mutability")
		}
	}
	if verb == "remove" {
		if a.Required {
			return failure(400, "mutability")
		}
		if !exists || !present(old) {
			return failure(400, "noTarget")
		}
		delete(obj, a.Name)
		return nil
	}
	if verb == "add" && sameValue(old, value, a) {
		return nil
	}
	if a.Type == "complex" && !a.MultiValued && value != nil {
		incoming, ok := value.(map[string]any)
		if !ok {
			return failure(400, "invalidValue")
		}
		prior, _ := old.(map[string]any)
		merged := cloneMap(prior)
		if prior == nil {
			if err := budget.field(obj, a.Name, merged); err != nil {
				return err
			}
		}
		obj[a.Name] = merged
		for key, v := range incoming {
			sub, ok := findAttribute(a.SubAttributes, key)
			if !ok {
				return failure(400, "invalidValue")
			}
			if e := changeField(merged, sub, verb, v, budget); e != nil {
				return e
			}
		}
		if a.Mutability == "immutable" && present(old) && !sameImmutableValue(old, merged, a) {
			return failure(400, "mutability")
		}
		obj[a.Name] = merged
		return nil
	}
	if a.MultiValued && verb == "add" {
		incoming, ok := value.([]any)
		if !ok {
			return failure(400, "invalidValue")
		}
		array, _ := old.([]any)
		one := a
		one.MultiValued = false
		// Input duplicates remain invalid, while adding a value already in the
		// target is a no-op (RFC 7644 3.5.2.1), not a duplicate persisted member.
		seen := map[string]bool{}
		for _, v := range incoming {
			key := valueKey(comparisonElement(v, a), one)
			if seen[key] {
				return failure(400, "invalidValue")
			}
			seen[key] = true
		}
		additions := []any{}
		existingKeys := make(map[string]bool, len(array))
		for _, v := range array {
			existingKeys[valueKey(comparisonElement(v, a), one)] = true
		}
		for _, v := range incoming {
			if !existingKeys[valueKey(comparisonElement(v, a), one)] {
				additions = append(additions, v)
			}
		}
		if len(additions) == 0 {
			return nil
		}
		incoming = additions
		// Measure actual growth, not members already present in the target.
		// The bounded input-reference plan precedes any expanded resource copy.
		if err := budget.field(obj, a.Name, patchConcat{before: array, added: incoming}); err != nil {
			return err
		}
		array = append([]any(nil), array...)
		if primary, ok := primaryAttribute(a); ok {
			for _, element := range incoming {
				if primaryTrue(element, primary) {
					for _, existing := range array {
						demotePrimary(existing, primary)
					}
				}
			}
		}
		obj[a.Name] = append(array, cloneValue(incoming).([]any)...)
		return nil
	}
	if err := budget.field(obj, a.Name, value); err != nil {
		return err
	}
	obj[a.Name] = cloneValue(value)
	return nil
}

// Reassignment changes only true members; omitted and explicit-false siblings
// retain their representations rather than acquiring comparison-only defaults.
func demotePrimary(element any, primary Attribute) {
	if obj, ok := element.(map[string]any); ok && primaryTrue(obj, primary) {
		obj[primary.Name] = false
	}
}

// Normalize supplied operands before equality or set-key construction. Singular
// complex PATCH values are partial (RFC 7644 3.5.2), so only their supplied
// children are validated here; the complete merged resource enforces required
// fields and immutable ancestors after application.
func normalizePatchValue(value any, a Attribute) (any, error) {
	if a.Type != "complex" || a.MultiValued || value == nil || a.Mutability == "readOnly" || a.Mutability == "writeOnly" || a.Returned == "never" {
		return normalizeValue(value, a, nil)
	}
	obj, ok := value.(map[string]any)
	if !ok {
		return nil, failure(400, "invalidValue")
	}
	out := make(map[string]any, len(obj))
	for key, v := range obj {
		sub, ok := findAttribute(a.SubAttributes, key)
		if !ok {
			return nil, failure(400, "invalidValue")
		}
		normalized, err := normalizePatchValue(v, sub)
		if err != nil {
			return nil, err
		}
		out[sub.Name] = normalized
	}
	return out, nil
}

func pathlessTargets(values map[string]any, ext []Schema, limits Limits, core ...Schema) error {
	targets := []string{}
	add := func(target string) error {
		for _, old := range targets {
			if old == target || strings.HasPrefix(old, target+".") || strings.HasPrefix(target, old+".") {
				return failure(400, "invalidValue")
			}
		}
		targets = append(targets, target)
		return nil
	}
	for key, value := range values {
		if schema, ok := extensionSchema(ext, key); ok {
			object, ok := value.(map[string]any)
			if !ok {
				return failure(400, "invalidValue")
			}
			for name := range object {
				a, ok := findAttribute(schema.Attributes, name)
				if !ok {
					return failure(400, "invalidValue")
				}
				if err := add(schema.ID + ":" + a.Name); err != nil {
					return err
				}
			}
			continue
		}
		path, err := parsePatchPath(key, ext, limits, core...)
		if err != nil {
			return err
		}
		target := path.path.text
		if !path.selected && len(path.tail.parts) > 0 {
			target += "." + path.tail.text
		}
		if err = add(target); err != nil {
			return err
		}
	}
	return nil
}
