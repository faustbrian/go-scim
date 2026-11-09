package scim

import (
	"encoding/base64"
	"encoding/json"
	"maps"
	"net/url"
	"slices"
	"strings"
	"time"
	"unicode/utf8"
)

const (
	userSchema         = "urn:ietf:params:scim:schemas:core:2.0:User"
	groupSchema        = "urn:ietf:params:scim:schemas:core:2.0:Group"
	schemaSchema       = "urn:ietf:params:scim:schemas:core:2.0:Schema"
	resourceTypeSchema = "urn:ietf:params:scim:schemas:core:2.0:ResourceType"
	configSchema       = "urn:ietf:params:scim:schemas:core:2.0:ServiceProviderConfig"
	listSchema         = "urn:ietf:params:scim:api:messages:2.0:ListResponse"
	patchSchema        = "urn:ietf:params:scim:api:messages:2.0:PatchOp"
	searchSchema       = "urn:ietf:params:scim:api:messages:2.0:SearchRequest"
	errorSchema        = "urn:ietf:params:scim:api:messages:2.0:Error"
)

// Attribute describes the supported RFC 7643 attribute characteristics. Unknown
// enum values are invalid. SubAttributes belong only to complex types. Caller
// configuration is deeply copied; it is not a mutable global schema registry.
type Attribute struct {
	Name          string      `json:"name"`
	Type          string      `json:"type"`
	MultiValued   bool        `json:"multiValued"`
	Required      bool        `json:"required"`
	CaseExact     bool        `json:"caseExact"`
	Mutability    string      `json:"mutability"`
	Returned      string      `json:"returned"`
	Uniqueness    string      `json:"uniqueness"`
	SubAttributes []Attribute `json:"subAttributes,omitempty"`
	// ReferenceTypes and CanonicalValues describe the fixed Group member
	// schema. Configured extension use is unsupported and fails construction.
	ReferenceTypes  []string `json:"referenceTypes,omitempty"`
	CanonicalValues []string `json:"canonicalValues,omitempty"`
}

// Schema is a named, bounded optional resource extension. The fixed core schema
// cannot be overridden. Extension schemas are explicit, not inferred from data.
type Schema struct {
	ID          string      `json:"id"`
	Name        string      `json:"name"`
	Description string      `json:"description,omitempty"`
	Attributes  []Attribute `json:"attributes"`
}

func scalar(name, typ string) Attribute {
	return Attribute{Name: name, Type: typ, Mutability: "readWrite", Returned: "default", Uniqueness: "none"}
}
func coreAttributes() []Attribute {
	uname := scalar("userName", "string")
	uname.Required = true
	uname.Uniqueness = "server"
	name := scalar("name", "complex")
	for _, key := range []string{"formatted", "familyName", "givenName", "middleName", "honorificPrefix", "honorificSuffix"} {
		name.SubAttributes = append(name.SubAttributes, scalar(key, "string"))
	}
	emails := scalar("emails", "complex")
	emails.MultiValued = true
	emails.SubAttributes = []Attribute{scalar("value", "string"), scalar("type", "string"), scalar("primary", "boolean"), scalar("display", "string")}
	password := scalar("password", "string")
	password.Mutability = "writeOnly"
	password.Returned = "never"
	return []Attribute{uname, name, scalar("displayName", "string"), scalar("active", "boolean"), emails, password}
}
func commonAttributes() []Attribute {
	id := scalar("id", "string")
	id.CaseExact = true
	id.Mutability = "readOnly"
	id.Returned = "always"
	id.Uniqueness = "server"
	schemas := scalar("schemas", "string")
	schemas.MultiValued = true
	schemas.Required = true
	schemas.CaseExact = true
	schemas.Returned = "always"
	external := scalar("externalId", "string")
	external.CaseExact = true
	meta := scalar("meta", "complex")
	meta.Mutability = "readOnly"
	for _, name := range []string{"resourceType", "created", "lastModified", "location", "version"} {
		a := scalar(name, "string")
		a.Mutability = "readOnly"
		a.CaseExact = true
		if name == "created" || name == "lastModified" {
			a.Type = "dateTime"
		}
		meta.SubAttributes = append(meta.SubAttributes, a)
	}
	return []Attribute{id, schemas, external, meta}
}
func findAttribute(attrs []Attribute, name string) (Attribute, bool) {
	for _, a := range attrs {
		if strings.EqualFold(a.Name, name) {
			return a, true
		}
	}
	return Attribute{}, false
}
func cloneSchemas(in []Schema) []Schema {
	out := slices.Clone(in)
	for i := range out {
		out[i].Attributes = cloneAttrs(out[i].Attributes)
	}
	return out
}
func cloneAttrs(in []Attribute) []Attribute {
	out := slices.Clone(in)
	for i := range out {
		out[i].ReferenceTypes = slices.Clone(in[i].ReferenceTypes)
		out[i].CanonicalValues = slices.Clone(in[i].CanonicalValues)
		if out[i].Type == "binary" || out[i].Type == "reference" {
			out[i].CaseExact = true
		}
		out[i].SubAttributes = cloneAttrs(out[i].SubAttributes)
	}
	return out
}

func safeID(s string) bool {
	if len(s) == 0 || len(s) > 128 || !utf8.ValidString(s) {
		return false
	}
	for _, r := range s {
		if r < 33 || r == 127 || strings.ContainsRune("/\\?#", r) {
			return false
		}
	}
	return true
}
func validName(s string) bool {
	if s == "" || len(s) > 128 {
		return false
	}
	// RFC 7643 2.4's standard reference sub-attribute is the reserved
	// exception to the ordinary ALPHA-leading attribute-name grammar.
	if strings.EqualFold(s, "$ref") {
		return true
	}
	for i, r := range s {
		if !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || i > 0 && (r >= '0' && r <= '9' || r == '_' || r == '-' || r == '$')) {
			return false
		}
	}
	return true
}
func validVersion(v Version) bool {
	s := string(v)
	if len(s) < 3 || len(s) > 256 || s[0] != '"' || s[len(s)-1] != '"' {
		return false
	}
	for _, b := range []byte(s[1 : len(s)-1]) {
		if b < 33 || b > 126 || b == '"' || b == '\\' {
			return false
		}
	}
	return true
}
func validURI(s string) bool {
	u, e := url.Parse(s)
	return e == nil && u.IsAbs() && u.User == nil && u.Fragment == ""
}

func validateSchemas(ext []Schema, l Limits) bool {
	seen := map[string]bool{strings.ToLower(userSchema): true}
	total := 0
	var attrs func([]Attribute, int) bool
	attrs = func(as []Attribute, depth int) bool {
		if depth > l.ResourceDepth {
			return false
		}
		names := map[string]bool{}
		for _, a := range as {
			total++
			key := strings.ToLower(a.Name)
			if total > l.ResourceAttributes || !validName(a.Name) || names[key] || !slices.Contains([]string{"string", "boolean", "integer", "decimal", "dateTime", "reference", "complex", "binary"}, a.Type) || !slices.Contains([]string{"readOnly", "readWrite", "immutable", "writeOnly"}, a.Mutability) || !slices.Contains([]string{"always", "never", "default", "request"}, a.Returned) || !slices.Contains([]string{"none", "server"}, a.Uniqueness) || a.Type != "complex" && len(a.SubAttributes) > 0 || a.Mutability == "writeOnly" && a.Returned != "never" || len(a.ReferenceTypes) > 0 || len(a.CanonicalValues) > 0 {
				return false
			}
			names[key] = true
			if a.Type == "complex" && (len(a.SubAttributes) == 0 || !attrs(a.SubAttributes, depth+1)) {
				return false
			}
		}
		return true
	}
	for _, s := range ext {
		k := strings.ToLower(s.ID)
		if !strings.HasPrefix(s.ID, "urn:") || !validURI(s.ID) || len(s.ID) > l.StringBytes || seen[k] || !validName(s.Name) || len(s.Description) > l.StringBytes || len(s.Attributes) == 0 || !attrs(s.Attributes, 1) || !supportedExtensionShape(s.Attributes, false) {
			return false
		}
		seen[k] = true
	}
	return true
}

func (s *protocolService) schema(id string) (Schema, bool) {
	if id == s.profile.schema.ID {
		return s.profile.schema, true
	}
	for _, schema := range s.config.Extensions {
		if schema.ID == id {
			return schema, true
		}
	}
	return Schema{}, false
}

// normalize validates writable data and canonicalizes attribute names only. It
// never normalizes identifiers, mutates caller input or infers account ownership.
func (s *protocolService) normalize(doc map[string]any, old map[string]any) (WritableResource, error) {
	raw, ok := lookup(doc, "schemas")
	if !ok {
		return WritableResource{}, failure(400, "invalidValue")
	}
	list, ok := raw.([]any)
	if !ok || len(list) == 0 {
		return WritableResource{}, failure(400, "invalidValue")
	}
	result := WritableResource{Attributes: map[string]any{}}
	declared := map[string]bool{}
	for _, v := range list {
		id, ok := v.(string)
		if !ok || declared[strings.ToLower(id)] {
			return WritableResource{}, failure(400, "invalidValue")
		}
		if _, ok := s.schema(id); !ok {
			return WritableResource{}, failure(400, "invalidValue")
		}
		declared[strings.ToLower(id)] = true
		result.Schemas = append(result.Schemas, id)
	}
	if !declared[strings.ToLower(s.profile.schema.ID)] {
		return WritableResource{}, failure(400, "invalidValue")
	}
	for name, value := range doc {
		if strings.EqualFold(name, "schemas") {
			continue
		}
		if strings.EqualFold(name, "id") || strings.EqualFold(name, "meta") {
			return WritableResource{}, failure(400, "mutability")
		}
		if strings.EqualFold(name, "externalId") {
			if value == nil {
				continue
			}
			v, ok := value.(string)
			if !ok {
				return WritableResource{}, failure(400, "invalidValue")
			}
			result.ExternalID = v
			continue
		}
		if schema, ok := s.schema(name); ok && name != s.profile.schema.ID {
			if !declared[strings.ToLower(name)] {
				return WritableResource{}, failure(400, "invalidValue")
			}
			obj, ok := value.(map[string]any)
			if !ok {
				return WritableResource{}, failure(400, "invalidValue")
			}
			prior, _ := old[name].(map[string]any)
			normalized, err := normalizeAttrs(obj, schema.Attributes, prior)
			if err != nil {
				return WritableResource{}, err
			}
			result.Attributes[name] = normalized
			continue
		}
		a, ok := findAttribute(s.profile.schema.Attributes, name)
		if !ok {
			return WritableResource{}, failure(400, "invalidValue")
		}
		v, err := normalizeValue(value, a, old[a.Name])
		if err != nil {
			return WritableResource{}, err
		}
		if v != nil {
			result.Attributes[a.Name] = v
		}
	}
	for _, a := range s.profile.schema.Attributes {
		if a.Required && !present(result.Attributes[a.Name]) {
			return WritableResource{}, failure(400, "invalidValue")
		}
	}
	if s.profile.schema.ID == groupSchema {
		members, err := s.normalizeGroupMembers(result.Attributes["members"], old["members"])
		if err != nil {
			return WritableResource{}, err
		}
		if members != nil {
			result.Attributes["members"] = members
		}
		if err := checkWritable(result, s.config.Limits); err != nil {
			return WritableResource{}, err
		}
	}
	// Immutable fields cannot be erased by omitting the extension or its
	// object in a replacement (RFC 7644 section 3.5.1).
	for _, schema := range s.config.Extensions {
		prior, _ := old[schema.ID].(map[string]any)
		next, _ := result.Attributes[schema.ID].(map[string]any)
		if _, e := normalizeAttrs(next, schema.Attributes, prior); e != nil {
			if declared[strings.ToLower(schema.ID)] || len(prior) > 0 {
				return WritableResource{}, e
			}
		}
	}
	return result, nil
}

func normalizeAttrs(doc map[string]any, attrs []Attribute, old map[string]any) (map[string]any, error) {
	out := map[string]any{}
	for key, value := range doc {
		a, ok := findAttribute(attrs, key)
		if !ok {
			return nil, failure(400, "invalidValue")
		}
		v, e := normalizeValue(value, a, old[a.Name])
		if e != nil {
			return nil, e
		}
		if v != nil {
			out[a.Name] = v
		}
	}
	for _, a := range attrs {
		if a.Required && a.Mutability != "readOnly" && !present(out[a.Name]) {
			return nil, failure(400, "invalidValue")
		}
		if a.Mutability == "immutable" && present(old[a.Name]) && !sameImmutableValue(old[a.Name], out[a.Name], a) {
			return nil, failure(400, "mutability")
		}
		if a.Type == "complex" && !a.MultiValued {
			prior, _ := old[a.Name].(map[string]any)
			next, _ := out[a.Name].(map[string]any)
			if err := immutableDescendants(prior, next, a.SubAttributes); err != nil {
				return nil, err
			}
		}
	}
	return out, nil
}
func normalizeValue(v any, a Attribute, old any) (any, error) {
	if a.Mutability == "readOnly" {
		return nil, failure(400, "mutability")
	}
	if a.Returned == "never" || a.Mutability == "writeOnly" {
		if DecideCredentialWrite(CredentialWrite{AttributePath: a.Name}) == CredentialWriteUnsupported {
			return nil, failure(400, "mutability")
		}
	}
	if v == nil {
		if a.Required {
			return nil, failure(400, "invalidValue")
		}
		if a.Mutability == "immutable" && present(old) {
			return nil, failure(400, "mutability")
		}
		return nil, nil
	}
	if a.MultiValued {
		values, ok := v.([]any)
		if !ok {
			return nil, failure(400, "invalidValue")
		}
		one := a
		one.MultiValued = false
		one.Mutability = "readWrite"
		out := make([]any, 0, len(values))
		seen := map[string]bool{}
		primary, hasPrimary := primaryAttribute(a)
		primarySeen := false
		for _, element := range values {
			normalized, e := normalizeValue(element, one, nil)
			if e != nil || normalized == nil {
				return nil, failure(400, "invalidValue")
			}
			if hasPrimary && primaryTrue(normalized, primary) {
				if primarySeen {
					return nil, failure(400, "invalidValue")
				}
				primarySeen = true
			}
			key := valueKey(comparisonElement(normalized, a), one)
			if seen[key] {
				return nil, failure(400, "invalidValue")
			}
			seen[key] = true
			out = append(out, normalized)
		}
		if a.Mutability == "immutable" && present(old) && !sameValue(old, out, a) {
			return nil, failure(400, "mutability")
		}
		return out, nil
	}
	valid := false
	switch a.Type {
	case "string":
		text, ok := v.(string)
		valid = ok
		if ok && isUsernameAttribute(a) {
			_, err := UsernameComparisonKey(text)
			valid = err == nil
		}
	case "binary":
		text, ok := v.(string)
		valid = ok && validBinary(text)
	case "reference":
		text, ok := v.(string)
		valid = ok && validReference(text)
	case "dateTime":
		value, ok := v.(string)
		if ok {
			_, e := time.Parse(time.RFC3339Nano, value)
			valid = e == nil
		}
	case "boolean":
		_, valid = v.(bool)
	case "integer":
		n, ok := v.(json.Number)
		if ok {
			_, e := n.Int64()
			valid = e == nil
		}
	case "decimal":
		n, ok := v.(json.Number)
		valid = ok && boundedNumber(n)
	case "complex":
		obj, ok := v.(map[string]any)
		if !ok {
			return nil, failure(400, "invalidValue")
		}
		prior, _ := old.(map[string]any)
		normalized, err := normalizeAttrs(obj, a.SubAttributes, prior)
		if err != nil {
			return nil, err
		}
		if a.Mutability == "immutable" && present(old) && !sameImmutableValue(old, normalized, a) {
			return nil, failure(400, "mutability")
		}
		return normalized, nil
	}
	if !valid || a.Required && !present(v) {
		return nil, failure(400, "invalidValue")
	}
	if a.Mutability == "immutable" && present(old) && !sameValue(old, v, a) {
		return nil, failure(400, "mutability")
	}
	return v, nil
}

// Immutable comparisons use canonical writable input plus the Store-owned
// read-only descendants. RFC 7644 3.5.1 does not require a client to echo those
// fields, and accepting such an echo would violate this profile's write policy.
func sameImmutableValue(old, next any, a Attribute) bool {
	if a.Type == "complex" && !a.MultiValued {
		before, ok := old.(map[string]any)
		after, ok2 := next.(map[string]any)
		if ok && ok2 {
			return sameValue(before, retainReadOnly(before, after, a.SubAttributes), a)
		}
	}
	return sameValue(old, next, a)
}

// RFC 7643 2.1 and 2.4 define primary case-insensitively as an immediate,
// singular Boolean child of a multi-valued complex attribute. Preserve the
// configured spelling so validation, comparison and PATCH use one descriptor.
func primaryAttribute(parent Attribute) (Attribute, bool) {
	if !parent.MultiValued || parent.Type != "complex" {
		return Attribute{}, false
	}
	primary, ok := findAttribute(parent.SubAttributes, "primary")
	return primary, ok && primary.Type == "boolean" && !primary.MultiValued
}

func primaryTrue(element any, primary Attribute) bool {
	obj, ok := element.(map[string]any)
	if !ok {
		return false
	}
	// Selected whole-record PATCH operands can still use a client alias here;
	// ordinary resource elements already have canonical schema names.
	value, _ := lookup(obj, primary.Name)
	return value == true
}

// RFC 7643 2.4 defaults primary to false only on an actual multi-valued
// complex element. Keep the parent context until this comparison-only view is
// made; neither persisted values nor singular descendants receive the default.
func comparisonElement(value any, parent Attribute) any {
	primary, ok := primaryAttribute(parent)
	if !ok {
		return value
	}
	obj, ok := value.(map[string]any)
	if !ok || obj == nil {
		return value
	}
	if field, _ := lookup(obj, primary.Name); field != nil {
		return value
	}
	view := maps.Clone(obj)
	view[primary.Name] = false
	return view
}

func sameValue(a, b any, attr Attribute) bool {
	if a == nil || b == nil {
		return a == nil && b == nil
	}
	if attr.MultiValued {
		x, ok := a.([]any)
		y, ok2 := b.([]any)
		if !ok || !ok2 || len(x) != len(y) {
			return false
		}
		one := attr
		one.MultiValued = false
		for i := range x {
			if !sameValue(comparisonElement(x[i], attr), comparisonElement(y[i], attr), one) {
				return false
			}
		}
		return true
	}
	if attr.Type == "complex" {
		x, ok := a.(map[string]any)
		y, ok2 := b.(map[string]any)
		if !ok || !ok2 {
			return false
		}
		for _, sub := range attr.SubAttributes {
			if !present(x[sub.Name]) && !present(y[sub.Name]) {
				continue
			}
			if !sameValue(x[sub.Name], y[sub.Name], sub) {
				return false
			}
		}
		return true
	}

	if attr.Type == "decimal" || attr.Type == "integer" {
		x, ok := numberValue(a, attr)
		y, ok2 := numberValue(b, attr)
		return ok && ok2 && x.Cmp(y) == 0
	}
	if attr.Type == "boolean" {
		x, ok := a.(bool)
		y, ok2 := b.(bool)
		return ok && ok2 && x == y
	}
	if attr.Type == "dateTime" {
		comparison, valid := compareValue(a, b, attr)
		return valid && comparison == 0
	}
	if x, ok := a.(string); ok {
		y, ok := b.(string)
		if !ok {
			return false
		}
		left, right, valid := comparisonStrings(x, y, attr)
		return valid && left == right
	}
	x, e := json.Marshal(a)
	y, f := json.Marshal(b)
	return e == nil && f == nil && string(x) == string(y)
}

// Set keys use the same scalar semantics as filtering, sorting and immutable
// comparison. This also avoids quadratic duplicate scans during normalization.
func valueKey(value any, a Attribute) string {
	var canonical any = value
	if a.MultiValued {
		one := a
		one.MultiValued = false
		if values, ok := value.([]any); ok {
			keys := make([]string, len(values))
			for i, v := range values {
				keys[i] = valueKey(comparisonElement(v, a), one)
			}
			canonical = keys
		}
	}
	if a.Type == "complex" && !a.MultiValued {
		if obj, ok := value.(map[string]any); ok {
			keys := []any{}
			for _, sub := range a.SubAttributes {
				v, _ := lookup(obj, sub.Name)
				if present(v) {
					keys = append(keys, sub.Name, valueKey(v, sub))
				}
			}
			canonical = keys
		}
	}
	if a.Type == "decimal" || a.Type == "integer" {
		if rational, valid := numberValue(value, a); valid {
			canonical = rational.RatString()
		}
	}
	if text, ok := value.(string); ok {
		switch a.Type {
		case "dateTime":
			if instant, err := time.Parse(time.RFC3339Nano, text); err == nil {
				canonical = instant.UTC().Format(time.RFC3339Nano)
			}
		case "string":
			if key, _, valid := comparisonStrings(text, text, a); valid {
				canonical = key
			}
		}
	}
	encoded, _ := json.Marshal(canonical)
	return string(encoded)
}

// A mutable ancestor cannot erase immutable descendants (RFC 7644 3.5.1 and
// 3.5.2). Recurse even when an omitted/null parent never reached normalizeValue.
func immutableDescendants(old, next map[string]any, attrs []Attribute) error {
	for _, a := range attrs {
		if a.Mutability == "immutable" && present(old[a.Name]) && !sameImmutableValue(old[a.Name], next[a.Name], a) {
			return failure(400, "mutability")
		}
		if a.Type == "complex" && !a.MultiValued {
			before, _ := old[a.Name].(map[string]any)
			after, _ := next[a.Name].(map[string]any)
			if err := immutableDescendants(before, after, a.SubAttributes); err != nil {
				return err
			}
		}
	}
	return nil
}

// RFC 7643 2.3.6 permits omitted standard-base64 padding, not arbitrary text.
func validBinary(text string) bool {
	if strings.ContainsAny(text, "\r\n") {
		return false
	}
	encoding := base64.StdEncoding.Strict()
	if !strings.Contains(text, "=") {
		encoding = base64.RawStdEncoding.Strict()
	}
	_, err := encoding.DecodeString(text)
	return err == nil
}

// RFC 7643 2.3.7 allows absolute and relative URI references. Syntax validation
// does not fetch the target or claim referential integrity/HTTP availability.
func validReference(text string) bool {
	if text == "" {
		return true
	}
	for i := 0; i < len(text); i++ {
		c := text[i]
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || strings.ContainsRune("-._~:/?#[]@!$&'()*+,;=%", rune(c))) {
			return false
		}
		if c == '%' {
			if i+2 >= len(text) || !hexByte(text[i+1]) || !hexByte(text[i+2]) {
				return false
			}
			i += 2
		}
	}
	u, err := url.Parse(text)
	if err != nil {
		return false
	}
	rest := text
	if u.Scheme != "" {
		rest = strings.TrimPrefix(rest, u.Scheme+":")
	}
	if strings.HasPrefix(rest, "//") {
		rest = rest[2:]
		if i := strings.IndexAny(rest, "/?#"); i >= 0 {
			rest = rest[i:]
		} else {
			rest = ""
		}
	}
	return !strings.ContainsAny(rest, "[]")
}

func hexByte(c byte) bool {
	return c >= '0' && c <= '9' || c >= 'a' && c <= 'f' || c >= 'A' && c <= 'F'
}
func present(v any) bool {
	if v == nil {
		return false
	}
	switch x := v.(type) {
	case string:
		return x != ""
	case []any:
		return len(x) > 0
	case map[string]any:
		return len(x) > 0
	}
	return true
}
func lookup(m map[string]any, key string) (any, bool) {
	for k, v := range m {
		if strings.EqualFold(k, key) {
			return v, true
		}
	}
	return nil, false
}
func writableDoc(w WritableResource) map[string]any {
	doc := cloneMap(w.Attributes)
	ids := make([]any, len(w.Schemas))
	for i, id := range w.Schemas {
		ids[i] = id
	}
	doc["schemas"] = ids
	if w.ExternalID != "" {
		doc["externalId"] = w.ExternalID
	}
	return doc
}

// A mutable multi-value extension needs a separate element identity contract to
// retain read-only/immutable child state across reordering and replacement. This
// profile does not invent such an identity: those schemas fail configuration.
func supportedExtensionShape(attrs []Attribute, inMulti bool) bool {
	for _, a := range attrs {
		if a.Uniqueness != "none" || strings.EqualFold(a.Name, "password") && (a.Returned != "never" || a.Mutability != "writeOnly") || a.Required && a.Mutability == "readOnly" || inMulti && (a.Mutability == "readOnly" || a.Mutability == "immutable") {
			return false
		}
		if !supportedExtensionShape(a.SubAttributes, inMulti || a.MultiValued) {
			return false
		}
	}
	return true
}
func stripReadOnly(doc map[string]any, attrs []Attribute) map[string]any {
	out := cloneMap(doc)
	for _, a := range attrs {
		v, exists := out[a.Name]
		if !exists {
			continue
		}
		if a.Mutability == "readOnly" {
			delete(out, a.Name)
			continue
		}
		if a.Type == "complex" {
			if m, ok := v.(map[string]any); ok {
				out[a.Name] = stripReadOnly(m, a.SubAttributes)
			}
		}
	}
	return out
}
func retainReadOnly(old, next map[string]any, attrs []Attribute) map[string]any {
	out := cloneMap(next)
	for _, a := range attrs {
		if a.Mutability == "readOnly" {
			if v, exists := old[a.Name]; exists {
				out[a.Name] = cloneValue(v)
			}
			continue
		}
		if a.Type == "complex" && !a.MultiValued {
			prior, _ := old[a.Name].(map[string]any)
			candidate, _ := out[a.Name].(map[string]any)
			merged := retainReadOnly(prior, candidate, a.SubAttributes)
			if len(merged) > 0 {
				out[a.Name] = merged
			}
		}
	}
	return out
}
func (s *protocolService) writableAttributes(doc map[string]any) map[string]any {
	out := stripReadOnly(doc, s.profile.schema.Attributes)
	for _, schema := range s.config.Extensions {
		if m, ok := out[schema.ID].(map[string]any); ok {
			out[schema.ID] = stripReadOnly(m, schema.Attributes)
		}
	}
	return out
}
func (s *protocolService) preserveReadOnly(current Resource, w WritableResource) WritableResource {
	w.Attributes = retainReadOnly(current.Attributes, w.Attributes, s.profile.schema.Attributes)
	for _, schema := range s.config.Extensions {
		prior, _ := current.Attributes[schema.ID].(map[string]any)
		next, _ := w.Attributes[schema.ID].(map[string]any)
		merged := retainReadOnly(prior, next, schema.Attributes)
		if len(merged) > 0 {
			w.Attributes[schema.ID] = merged
			if !slices.Contains(w.Schemas, schema.ID) {
				w.Schemas = append(w.Schemas, schema.ID)
			}
		}
	}
	return w
}
