package scim

import (
	"bytes"
	"encoding/json"
	"io"
	"unicode/utf8"
)

// decodeObject checks every object before mapping or authorization, including
// JSON case aliases inside complex, extension, SearchRequest and PATCH values.
func decodeObject(body []byte, l Limits) (map[string]any, error) {
	if len(body) > l.BodyBytes {
		return nil, failure(413, "")
	}
	if !utf8.Valid(body) {
		return nil, failure(400, "invalidSyntax")
	}
	d := json.NewDecoder(bytes.NewReader(body))
	d.UseNumber()
	attrs := 0
	var read func(int) (any, error)
	read = func(depth int) (any, error) {
		if depth > l.ResourceDepth {
			return nil, failure(400, "invalidValue")
		}
		token, e := d.Token()
		if e != nil {
			return nil, failure(400, "invalidSyntax")
		}
		switch t := token.(type) {
		case json.Delim:
			switch t {
			case '{':
				out := map[string]any{}
				seen := map[string]bool{}
				for d.More() {
					key, e := d.Token()
					if e != nil {
						return nil, failure(400, "invalidSyntax")
					}
					k, ok := key.(string)
					if !ok || len(k) > l.StringBytes {
						return nil, failure(400, "invalidValue")
					}
					fold := foldString(k)
					if seen[fold] {
						return nil, failure(400, "invalidSyntax")
					}
					seen[fold] = true
					attrs++
					if attrs > l.ResourceAttributes {
						return nil, failure(400, "invalidValue")
					}
					v, e := read(depth + 1)
					if e != nil {
						return nil, e
					}
					out[k] = v
				}
				end, e := d.Token()
				if e != nil || end != json.Delim('}') {
					return nil, failure(400, "invalidSyntax")
				}
				return out, nil
			case '[':
				out := []any{}
				for d.More() {
					if len(out) >= l.ResourceAttributes {
						return nil, failure(400, "invalidValue")
					}
					v, e := read(depth + 1)
					if e != nil {
						return nil, e
					}
					out = append(out, v)
				}
				end, e := d.Token()
				if e != nil || end != json.Delim(']') {
					return nil, failure(400, "invalidSyntax")
				}
				return out, nil
			}
			return nil, failure(400, "invalidSyntax")
		case string:
			if len(t) > l.StringBytes {
				return nil, failure(400, "invalidValue")
			}
			return t, nil
		case json.Number, bool, nil:
			return t, nil
		default:
			return nil, failure(400, "invalidSyntax")
		}
	}
	v, e := read(1)
	if e != nil {
		return nil, e
	}
	if _, e = d.Token(); e != io.EOF {
		return nil, failure(400, "invalidSyntax")
	}
	out, ok := v.(map[string]any)
	if !ok {
		return nil, failure(400, "invalidSyntax")
	}
	return out, nil
}
func cloneValue(v any) any {
	switch x := v.(type) {
	case map[string]any:
		return cloneMap(x)
	case []any:
		r := make([]any, len(x))
		for i, v := range x {
			r[i] = cloneValue(v)
		}
		return r
	default:
		return v
	}
}
func cloneMap(m map[string]any) map[string]any {
	out := make(map[string]any, len(m))
	for k, v := range m {
		out[k] = cloneValue(v)
	}
	return out
}
func cloneResource(r Resource) Resource {
	r.Attributes = cloneMap(r.Attributes)
	r.Schemas = append([]string(nil), r.Schemas...)
	return r
}
