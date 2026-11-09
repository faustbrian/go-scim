package scim

import (
	"encoding/json"
	"math/big"
	"strconv"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"
)

// Filter is an immutable bounded RFC 7644 expression. Zero matches everything.
// Accessors expose detached AST values; parsing grants neither query authority
// nor permission to perform an unbounded storage scan.
type Filter struct{ node *filterNode }
type filterNode struct {
	op          string
	path        attributePath
	value       any
	left, right *filterNode
	height      int
}

// Operator is and, or, not, valuePath, or a registered comparison, or empty.
func (f Filter) Operator() string {
	if f.node == nil {
		return ""
	}
	return f.node.op
}

// Children returns a detached list of the immediate expression children.
func (f Filter) Children() []Filter {
	if f.node == nil {
		return nil
	}
	out := []Filter{}
	if f.node.left != nil {
		out = append(out, Filter{f.node.left})
	}
	if f.node.right != nil {
		out = append(out, Filter{f.node.right})
	}
	return out
}

// AttributePath returns the canonical schema path of an attribute expression.
func (f Filter) AttributePath() string {
	if f.node == nil {
		return ""
	}
	return f.node.path.text
}

// ComparisonValue returns only a scalar parsed JSON value, never a resource.
func (f Filter) ComparisonValue() any {
	if f.node == nil {
		return nil
	}
	return f.node.value
}

// ParseFilter validates bounded RFC grammar and declared schema paths before
// producing an AST. Extensions are trusted schema configuration, not authority.
// Returned-never attributes cannot be read or compared, even by presence tests.
func ParseFilter(expression string, extensions []Schema, limits Limits) (Filter, error) {
	if !limits.valid() || !validateSchemas(extensions, limits) {
		return Filter{}, failure(400, "invalidFilter")
	}
	return parseFilter(expression, extensions, limits, nil)
}

type attributePath struct {
	text, extension string
	parts           []Attribute
	defaultPrimary  bool
}

func resolvePath(raw string, ext []Schema, l Limits, local []Attribute) (attributePath, error) {
	return resolveAttributePath(raw, ext, l, local, false)
}
func resolveAttributePath(raw string, ext []Schema, l Limits, local []Attribute, write bool) (attributePath, error) {
	if raw == "" || len(raw) > l.PathBytes || !utf8.ValidString(raw) {
		return attributePath{}, failure(400, "invalidPath")
	}
	attrs := append(commonAttributes(), coreAttributes()...)
	p := attributePath{}
	if local != nil {
		attrs = local
	}
	if strings.HasPrefix(strings.ToLower(raw), "urn:") {
		if local != nil {
			return p, failure(400, "invalidPath")
		}

		var owner Schema
		for _, schema := range append([]Schema{{ID: userSchema}}, ext...) {
			if strings.HasPrefix(raw, schema.ID+":") && len(schema.ID) > len(owner.ID) {
				owner = schema
			}
		}
		if owner.ID == "" {
			return p, failure(400, "invalidPath")
		}
		raw = strings.TrimPrefix(raw, owner.ID+":")
		if owner.ID != userSchema {
			p.extension = owner.ID
			attrs = owner.Attributes
		}

	}
	names := strings.Split(raw, ".")
	if len(names) > l.ResourceDepth {
		return p, failure(400, "invalidPath")
	}
	canonical := []string{}
	for i, name := range names {
		if !validName(name) {
			return p, failure(400, "invalidPath")
		}
		a, ok := findAttribute(attrs, name)
		if !ok || !write && (a.Returned == "never" || a.Mutability == "writeOnly") {
			return p, failure(400, "invalidPath")
		}
		p.parts = append(p.parts, a)
		canonical = append(canonical, a.Name)
		if i < len(names)-1 && a.Type != "complex" {
			return p, failure(400, "invalidPath")
		}
		attrs = a.SubAttributes
	}
	p.text = strings.Join(canonical, ".")
	if p.extension != "" {
		p.text = p.extension + ":" + p.text
	}
	last := p.parts[len(p.parts)-1]
	var parent Attribute
	if len(p.parts) > 1 {
		parent = p.parts[len(p.parts)-2]
	} else if local != nil {
		// Local read paths are evaluated only within a multi-valued
		// valuePath/PATCH selector, not against the whole User.
		parent = Attribute{Type: "complex", MultiValued: true, SubAttributes: local}
	}
	if primary, ok := primaryAttribute(parent); ok {
		p.defaultPrimary = last.Name == primary.Name
	}
	return p, nil
}
func (p attributePath) attribute() Attribute { return p.parts[len(p.parts)-1] }
func pathValues(doc map[string]any, p attributePath) []any {
	var value any = doc
	if p.extension != "" {
		value = doc[p.extension]
	}
	values := []any{value}
	for index, a := range p.parts {
		next := []any{}
		for _, v := range values {
			obj, ok := v.(map[string]any)
			if !ok {
				continue
			}
			field := obj[a.Name]
			if field == nil && p.defaultPrimary && index == len(p.parts)-1 {
				// RFC 7643 2.4 assumes omitted primary=false on an actual
				// multi-value object. Never synthesize a missing collection.
				field = false
			}
			if a.MultiValued {
				if array, ok := field.([]any); ok {
					next = append(next, array...)
				}
			} else {
				next = append(next, field)
			}
		}
		values = next
	}
	return values
}

type filterToken struct {
	start, end int
	kind, text string
	value      any
}

func lexFilter(expr string, l Limits) ([]filterToken, error) {
	if len(expr) > l.FilterBytes || !utf8.ValidString(expr) {
		return nil, failure(400, "invalidFilter")
	}
	out := []filterToken{}
	for i := 0; i < len(expr); {
		if expr[i] == ' ' || expr[i] == '\t' || expr[i] == '\r' || expr[i] == '\n' {
			i++
			continue
		}
		if len(out) >= l.FilterTokens {
			return nil, failure(400, "invalidFilter")
		}
		c := expr[i]
		if strings.ContainsRune("()[]", rune(c)) {
			out = append(out, filterToken{kind: string(c), text: string(c), start: i, end: i + 1})
			i++
			continue
		}
		if c == '"' {
			start := i
			i++
			closed := false
			for i < len(expr) {
				if expr[i] == '\\' {
					i += 2
					continue
				}
				if expr[i] == '"' {
					i++
					closed = true
					break
				}
				i++
			}
			if !closed || i > len(expr) {
				return nil, failure(400, "invalidFilter")
			}
			var v string
			if json.Unmarshal([]byte(expr[start:i]), &v) != nil || len(v) > l.StringBytes {
				return nil, failure(400, "invalidFilter")
			}
			out = append(out, filterToken{kind: "literal", value: v, start: start, end: i})
			continue
		}
		start := i
		for i < len(expr) && !strings.ContainsRune(" \t\r\n()[]\"", rune(expr[i])) {
			i++
		}
		if start == i {
			return nil, failure(400, "invalidFilter")
		}
		word := expr[start:i]
		lower := strings.ToLower(word)
		switch lower {
		case "true", "false":
			if word != lower {
				return nil, failure(400, "invalidFilter")
			}
			out = append(out, filterToken{kind: "literal", value: lower == "true", start: start, end: i})
		case "null":
			if word != lower {
				return nil, failure(400, "invalidFilter")
			}
			out = append(out, filterToken{kind: "literal", value: nil, start: start, end: i})
		default:
			if word[0] == '-' || word[0] >= '0' && word[0] <= '9' {
				var v any
				decoder := json.NewDecoder(strings.NewReader(word))
				decoder.UseNumber()
				if decoder.Decode(&v) != nil {
					return nil, failure(400, "invalidFilter")
				}
				n, ok := v.(json.Number)
				if !ok || string(n) != word {
					return nil, failure(400, "invalidFilter")
				}
				out = append(out, filterToken{kind: "literal", value: n, start: start, end: i})
			} else {
				out = append(out, filterToken{kind: "word", text: word, start: start, end: i})
			}
		}
	}
	return out, nil
}

type filterParser struct {
	tokens     []filterToken
	pos, nodes int
	limits     Limits
	extensions []Schema
	local      []Attribute
}

func parseFilter(expr string, ext []Schema, l Limits, local []Attribute) (Filter, error) {
	if expr == "" {
		return Filter{}, nil
	}
	tokens, e := lexFilter(expr, l)
	if e != nil {
		return Filter{}, e
	}
	p := filterParser{tokens: tokens, limits: l, extensions: ext, local: local}
	n, e := p.expression(1, 0)
	if e != nil || p.pos != len(tokens) {
		return Filter{}, failure(400, "invalidFilter")
	}
	return Filter{n}, nil
}
func (p *filterParser) is(word string) bool {
	return p.pos < len(p.tokens) && strings.EqualFold(p.tokens[p.pos].text, word)
}
func (p *filterParser) allocate(n filterNode) (*filterNode, error) {
	n.height = 1
	for _, child := range []*filterNode{n.left, n.right} {
		if child != nil && child.height+1 > n.height {
			n.height = child.height + 1
		}
	}
	if p.nodes >= p.limits.FilterNodes || n.height > p.limits.FilterDepth {
		return nil, failure(400, "invalidFilter")
	}
	p.nodes++
	return &n, nil
}

func (p *filterParser) expression(depth, min int) (*filterNode, error) {
	if depth > p.limits.FilterDepth {
		return nil, failure(400, "invalidFilter")
	}
	left, e := p.atom(depth)
	if e != nil {
		return nil, e
	}
	for p.pos < len(p.tokens) {
		op := strings.ToLower(p.tokens[p.pos].text)
		prec := 0
		if op == "or" {
			prec = 1
		}
		if op == "and" {
			prec = 2
		}
		if prec == 0 || prec < min {
			break
		}
		// RFC 7644 3.4.2.2 requires a gap on both sides of and/or,
		// including after quoted values, closing parentheses and value paths.
		operator := p.tokens[p.pos]
		if operator.start <= p.tokens[p.pos-1].end || p.pos+1 >= len(p.tokens) || p.tokens[p.pos+1].start <= operator.end {
			return nil, failure(400, "invalidFilter")
		}
		p.pos++
		right, e := p.expression(depth+1, prec+1)
		if e != nil {
			return nil, e
		}
		left, e = p.allocate(filterNode{op: op, left: left, right: right})
		if e != nil {
			return nil, e
		}
	}
	return left, nil
}
func (p *filterParser) atom(depth int) (*filterNode, error) {
	if depth > p.limits.FilterDepth || p.pos >= len(p.tokens) {
		return nil, failure(400, "invalidFilter")
	}
	if p.is("not") {
		p.pos++
		if !p.is("(") {
			return nil, failure(400, "invalidFilter")
		}
		p.pos++
		n, e := p.expression(depth+1, 0)
		if e != nil || !p.is(")") {
			return nil, failure(400, "invalidFilter")
		}
		p.pos++
		return p.allocate(filterNode{op: "not", left: n})
	}
	if p.is("(") {
		p.pos++
		n, e := p.expression(depth+1, 0)
		if e != nil || !p.is(")") {
			return nil, failure(400, "invalidFilter")
		}
		p.pos++
		return n, nil
	}
	token := p.tokens[p.pos]
	if token.kind != "word" {
		return nil, failure(400, "invalidFilter")
	}
	p.pos++
	path, e := resolvePath(token.text, p.extensions, p.limits, p.local)
	if e != nil {
		return nil, failure(400, "invalidFilter")
	}
	if p.is("[") {
		a := path.attribute()
		if !a.MultiValued || a.Type != "complex" || p.local != nil {
			return nil, failure(400, "invalidFilter")
		}
		p.pos++
		prior := p.local
		p.local = a.SubAttributes
		n, e := p.expression(depth+1, 0)
		p.local = prior
		if e != nil || !p.is("]") {
			return nil, failure(400, "invalidFilter")
		}
		p.pos++
		return p.allocate(filterNode{op: "valuePath", path: path, left: n})
	}
	if p.pos >= len(p.tokens) {
		return nil, failure(400, "invalidFilter")
	}
	operatorToken := p.tokens[p.pos]
	if operatorToken.start <= token.end {
		return nil, failure(400, "invalidFilter")
	}
	op := strings.ToLower(operatorToken.text)
	p.pos++
	if op == "pr" {
		return p.allocate(filterNode{op: op, path: path})
	}
	if !slicesContains([]string{"eq", "ne", "co", "sw", "ew", "gt", "ge", "lt", "le"}, op) || p.pos >= len(p.tokens) || p.tokens[p.pos].kind != "literal" {
		return nil, failure(400, "invalidFilter")
	}
	if p.tokens[p.pos].start <= operatorToken.end {
		return nil, failure(400, "invalidFilter")
	}
	value := p.tokens[p.pos].value
	p.pos++
	a := path.attribute()
	if !validComparison(a, op, value) {
		return nil, failure(400, "invalidFilter")
	}
	return p.allocate(filterNode{op: op, path: path, value: value})
}
func slicesContains(values []string, v string) bool {
	for _, s := range values {
		if s == v {
			return true
		}
	}
	return false
}
func validComparison(a Attribute, op string, value any) bool {
	if a.Type == "complex" {
		return false
	}
	if value == nil {
		return op == "eq" || op == "ne"
	}
	switch a.Type {
	case "boolean":
		_, ok := value.(bool)
		return ok && (op == "eq" || op == "ne")
	case "binary":
		_, ok := value.(string)
		// RFC 7644 Table 3 forbids ordering binary attributes.
		return ok && !slicesContains([]string{"gt", "ge", "lt", "le"}, op)
	case "integer", "decimal":
		n, ok := value.(json.Number)
		if !ok || !boundedNumber(n) {
			return false
		}
		if a.Type == "integer" {
			if _, e := n.Int64(); e != nil {
				return false
			}
		}
		return !slicesContains([]string{"co", "sw", "ew"}, op)
	case "dateTime":
		v, ok := value.(string)
		if !ok {
			return false
		}
		_, e := time.Parse(time.RFC3339Nano, v)
		return e == nil && !slicesContains([]string{"co", "sw", "ew"}, op)
	default:
		text, ok := value.(string)
		if !ok {
			return false
		}
		if isUsernameAttribute(a) {
			if slicesContains([]string{"co", "sw", "ew"}, op) {
				_, err := usernameFragmentKey(text)
				return err == nil
			}
			_, err := UsernameComparisonKey(text)
			return err == nil
		}
		return true
	}
}
func (f Filter) matches(doc map[string]any) bool { return matchNode(f.node, doc) }
func matchNode(n *filterNode, doc map[string]any) bool {
	if n == nil {
		return true
	}
	switch n.op {
	case "and":
		return matchNode(n.left, doc) && matchNode(n.right, doc)
	case "or":
		return matchNode(n.left, doc) || matchNode(n.right, doc)
	case "not":
		return !matchNode(n.left, doc)
	}
	values := pathValues(doc, n.path)
	if n.op == "valuePath" {
		for _, v := range values {
			if obj, ok := v.(map[string]any); ok && matchNode(n.left, obj) {
				return true
			}
		}
		return false
	}
	if n.op == "pr" {
		for _, v := range values {
			if present(v) {
				return true
			}
		}
		return false
	}
	if len(values) == 0 {
		values = []any{nil}
	}
	for _, v := range values {
		if n.value == nil || v == nil {
			same := !present(v) && n.value == nil
			if n.op == "eq" && same || n.op == "ne" && !same {
				return true
			}
			continue
		}
		a := n.path.attribute()
		if slicesContains([]string{"co", "sw", "ew"}, n.op) {
			x, ok := v.(string)
			y, ok2 := n.value.(string)
			if !ok || !ok2 {
				continue
			}
			x, y, valid := substringComparisonStrings(x, y, a)
			if !valid {
				continue
			}
			if n.op == "co" && strings.Contains(x, y) || n.op == "sw" && strings.HasPrefix(x, y) || n.op == "ew" && strings.HasSuffix(x, y) {
				return true
			}
			continue
		}
		cmp, valid := compareValue(v, n.value, a)
		if !valid {
			continue
		}
		switch n.op {
		case "eq":
			if cmp == 0 {
				return true
			}
		case "ne":
			if cmp != 0 {
				return true
			}
		case "gt":
			if cmp > 0 {
				return true
			}
		case "ge":
			if cmp >= 0 {
				return true
			}
		case "lt":
			if cmp < 0 {
				return true
			}
		case "le":
			if cmp <= 0 {
				return true
			}
		}
	}
	return false
}
func foldString(s string) string {
	return strings.Map(func(r rune) rune {
		minimum := r
		for next := unicode.SimpleFold(r); next != r; next = unicode.SimpleFold(next) {
			if next < minimum {
				minimum = next
			}
		}
		return minimum
	}, s)
}

// Predicate comparison is distinct from sorting's unassigned-value placement.
// Empty strings participate in lexical comparison; nil is handled by predicates
// before this function and must not turn into a fabricated typed value.
func compareValue(a, b any, attr Attribute) (int, bool) {
	if attr.Type == "boolean" {
		x, ok := a.(bool)
		y, ok2 := b.(bool)
		if !ok || !ok2 {
			return 0, false
		}
		if x == y {
			return 0, true
		}
		if !x {
			return -1, true
		}
		return 1, true
	}
	if attr.Type == "integer" || attr.Type == "decimal" {
		x, ok := numberValue(a, attr)
		y, ok2 := numberValue(b, attr)
		if ok && ok2 {
			return x.Cmp(y), true
		}
		return 0, false
	}
	x, ok := a.(string)
	y, ok2 := b.(string)
	if !ok || !ok2 {
		return 0, false
	}
	if attr.Type == "dateTime" {
		tx, err := time.Parse(time.RFC3339Nano, x)
		ty, err2 := time.Parse(time.RFC3339Nano, y)
		return tx.Compare(ty), err == nil && err2 == nil
	}
	x, y, valid := comparisonStrings(x, y, attr)
	if !valid {
		return 0, false
	}
	return strings.Compare(x, y), true
}
func numberValue(v any, a Attribute) (*big.Rat, bool) {
	n, ok := v.(json.Number)
	if !ok || !boundedNumber(n) {
		return nil, false
	}
	if a.Type == "integer" {
		if _, err := n.Int64(); err != nil {
			return nil, false
		}
	}
	return new(big.Rat).SetString(string(n))
}

// SCIM's numeric extensions use bounded exact decimal comparisons. Bound scale
// before big.Rat allocation: JSON exponents are otherwise an allocation attack.
func boundedNumber(n json.Number) bool {
	text := string(n)
	if len(text) == 0 || len(text) > 128 {
		return false
	}
	if i := strings.IndexAny(text, "eE"); i >= 0 {
		exponent, e := strconv.Atoi(text[i+1:])
		if e != nil || exponent < -308 || exponent > 308 {
			return false
		}
	}
	if (text[0] != '-' && (text[0] < '0' || text[0] > '9')) || !json.Valid([]byte(text)) {
		return false
	}
	_, ok := new(big.Rat).SetString(text)
	return ok
}
