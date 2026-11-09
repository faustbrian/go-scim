package scim

import (
	"encoding/json"
	"strconv"
	"time"
	"unicode/utf8"
)

// encodedSize counts the exact encoding/json representation before allocating
// its output. Stop at the budget, including HTML/control escaping. Only owned
// protocol JSON shapes are supported; no arbitrary MarshalJSON callback runs.
func encodedSize(value any, maximum int) (int, error) {
	remaining := maximum
	add := func(n int) bool {
		if n < 0 || n > remaining {
			return false
		}
		remaining -= n
		return true
	}
	var size func(any, int) bool
	var stringSize func(string) bool
	stringSize = func(text string) bool {
		if !add(2) {
			return false
		}
		for len(text) > 0 {
			r, width := utf8.DecodeRuneInString(text)
			text = text[width:]
			n := width
			switch {
			case r == '"' || r == '\\' || r == '\b' || r == '\f' || r == '\n' || r == '\r' || r == '\t':
				n = 2
			case r < 32 || r == '<' || r == '>' || r == '&' || r == '\u2028' || r == '\u2029' || r == utf8.RuneError && width == 1:
				n = 6
			}
			if !add(n) {
				return false
			}
		}
		return true
	}
	size = func(v any, depth int) bool {
		if depth > 64 {
			return false
		}
		switch x := v.(type) {
		case nil:
			return add(4)
		case bool:
			if x {
				return add(4)
			}
			return add(5)
		case string:
			return stringSize(x)
		case int:
			return add(len(strconv.Itoa(x)))
		case json.Number:
			return boundedNumber(x) && add(len(x))
		case map[string]any:
			if x == nil {
				return add(4)
			}
			if !add(2) {
				return false
			}
			first := true
			for key, value := range x {
				if !first && !add(1) {
					return false
				}
				first = false
				if !stringSize(key) || !add(1) || !size(value, depth+1) {
					return false
				}
			}
			return true
		case []any:
			if x == nil {
				return add(4)
			}
			if !add(2) {
				return false
			}
			for i, value := range x {
				if i > 0 && !add(1) {
					return false
				}
				if !size(value, depth+1) {
					return false
				}
			}
			return true
		case []string:
			if x == nil {
				return add(4)
			}
			if !add(2) {
				return false
			}
			for i, value := range x {
				if i > 0 && !add(1) {
					return false
				}
				if !stringSize(value) {
					return false
				}
			}
			return true
		case []Attribute:
			if x == nil {
				return add(4)
			}
			if !add(2) {
				return false
			}
			for i, a := range x {
				if i > 0 && !add(1) {
					return false
				}
				fields := map[string]any{"name": a.Name, "type": a.Type, "multiValued": a.MultiValued, "required": a.Required, "caseExact": a.CaseExact, "mutability": a.Mutability, "returned": a.Returned, "uniqueness": a.Uniqueness}
				if len(a.SubAttributes) > 0 {
					fields["subAttributes"] = a.SubAttributes
				}
				if !size(fields, depth+1) {
					return false
				}
			}
			return true
		case patchConcat:
			if !add(2) {
				return false
			}
			i := 0
			for _, part := range [][]any{x.before, x.added} {
				for _, value := range part {
					if i > 0 && !add(1) {
						return false
					}
					i++
					if !size(value, depth+1) {
						return false
					}
				}
			}
			return true
		default:
			return false
		}
	}
	if maximum < 0 || !size(value, 1) {
		return 0, failure(400, "tooMany")
	}
	return maximum - remaining, nil
}

func snapshotResourceSize(r Resource, maximum int) (int, error) {
	return encodedSize(map[string]any{"ID": r.ID, "Version": string(r.Version), "CreatedAt": r.CreatedAt.Format(time.RFC3339Nano), "LastModified": r.LastModified.Format(time.RFC3339Nano), "Schemas": r.Schemas, "ExternalID": r.ExternalID, "Attributes": r.Attributes}, maximum)
}

// patchConcat is only a prospective view. It must never reach normalization,
// Mapper, Store or output. It avoids allocating the expanded slice to measure it.
type patchConcat struct{ before, added []any }

type patchBudget struct {
	root   map[string]any
	limits Limits
}

func (b patchBudget) field(obj map[string]any, key string, proposed any) error {
	old, exists := obj[key]
	obj[key] = proposed
	defer func() {
		if exists {
			obj[key] = old
		} else {
			delete(obj, key)
		}
	}()
	if err := checkTree(b.root, b.limits); err != nil {
		return failure(400, "invalidValue")
	}
	if _, err := encodedSize(b.root, b.limits.BodyBytes); err != nil {
		return failure(400, "invalidValue")
	}
	return nil
}

func (b patchBudget) element(array []any, index int, proposed any) error {
	old := array[index]
	array[index] = proposed
	defer func() { array[index] = old }()
	if err := checkTree(b.root, b.limits); err != nil {
		return failure(400, "invalidValue")
	}
	if _, err := encodedSize(b.root, b.limits.BodyBytes); err != nil {
		return failure(400, "invalidValue")
	}
	return nil
}
