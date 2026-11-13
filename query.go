package scim

import (
	"context"
	"encoding/json"
	"sort"
	"strings"
)

type queryPlan struct {
	query            Query
	filter           Filter
	sort             *attributePath
	include, exclude []attributePath
	supplied         map[string]bool
}

func (s *protocolService) planQuery(q Query) (queryPlan, error) {
	return s.planResolvedQuery(q, func(raw string, local []Attribute) (attributePath, error) {
		return resolvePath(raw, s.config.Extensions, s.config.Limits, local, s.profile.schema)
	})
}

func (s *protocolService) planResolvedQuery(q Query, resolve pathResolver) (queryPlan, error) {
	p := queryPlan{query: q}
	l := s.config.Limits
	if len(q.Attributes) > l.BodyBytes || len(q.ExcludedAttributes) > l.BodyBytes {
		return p, failure(400, "invalidValue")
	}
	if q.Attributes != "" && q.ExcludedAttributes != "" {
		return p, failure(400, "invalidValue")
	}
	var e error
	p.filter, e = parseResolvedFilter(q.Filter, l, nil, resolve)
	if e != nil {
		return p, e
	}
	if q.SortOrder != "" && q.SortOrder != "ascending" && q.SortOrder != "descending" {
		return p, failure(400, "invalidValue")
	}
	if q.SortBy != "" {
		path, e := resolve(q.SortBy, nil)
		if e != nil {
			return p, failure(400, "invalidValue")
		}
		a := path.attribute()
		if a.Type == "complex" {
			sub, ok := findAttribute(a.SubAttributes, "value")
			if !ok {
				return p, failure(400, "invalidValue")
			}
			path.parts = append(path.parts, sub)
		}
		p.sort = &path
	}
	for _, list := range []struct {
		raw  string
		dest *[]attributePath
	}{{q.Attributes, &p.include}, {q.ExcludedAttributes, &p.exclude}} {
		if list.raw == "" {
			continue
		}
		// Bound the slot count before Split allocates one string per comma.
		if strings.Count(list.raw, ",") >= l.ResourceAttributes {
			return p, failure(400, "invalidValue")
		}
		names := strings.Split(list.raw, ",")
		seen := map[string]bool{}
		for _, name := range names {
			path, e := resolve(strings.TrimSpace(name), nil)
			if e != nil {
				return p, failure(400, "invalidValue")
			}
			identity := string(path.rootType) + ":" + path.text
			if seen[identity] {
				return p, failure(400, "invalidValue")
			}
			seen[identity] = true
			*list.dest = append(*list.dest, path)
		}
	}
	if p.query.StartIndex < 1 {
		p.query.StartIndex = 1
	}
	count := l.PageDefault
	if q.Count != nil {
		count = *q.Count
	}
	if count < 0 {
		count = 0
	}
	if count > l.PageMax {
		count = l.PageMax
	}
	p.query.Count = &count
	return p, nil
}
func searchQuery(doc map[string]any) (Query, error) {
	if !exactEnvelope(doc, searchSchema) {
		return Query{}, failure(400, "invalidValue")
	}
	q := Query{}
	for key, v := range doc {
		switch strings.ToLower(key) {
		case "schemas":
		case "filter", "sortby", "sortorder":
			value, ok := v.(string)
			if !ok {
				return q, failure(400, "invalidValue")
			}
			switch strings.ToLower(key) {
			case "filter":
				q.Filter = value
			case "sortby":
				q.SortBy = value
			case "sortorder":
				q.SortOrder = value
			}
		case "startindex", "count":
			n, ok := v.(json.Number)
			if !ok {
				return q, failure(400, "invalidValue")
			}
			i, e := n.Int64()
			if e != nil || int64(int(i)) != i {
				return q, failure(400, "invalidValue")
			}
			if strings.EqualFold(key, "count") {
				value := int(i)
				q.Count = &value
			} else {
				q.StartIndex = int(i)
			}
		case "attributes", "excludedattributes":
			values, ok := v.([]any)
			if !ok {
				return q, failure(400, "invalidValue")
			}
			names := []string{}
			for _, value := range values {
				name, ok := value.(string)
				if !ok || strings.Contains(name, ",") {
					return q, failure(400, "invalidValue")
				}
				names = append(names, name)
			}
			if strings.EqualFold(key, "attributes") {
				q.Attributes = strings.Join(names, ",")
			} else {
				q.ExcludedAttributes = strings.Join(names, ",")
			}
		default:
			return q, failure(400, "invalidSyntax")
		}
	}
	return q, nil
}

func (s *protocolService) list(ctx context.Context, c Connection, p queryPlan) (Response, error) {
	readCtx, readCancel, e := s.authorityContext(ctx, c)
	if e != nil {
		return Response{}, e
	}
	snap, e := s.snapshotResources(readCtx, c.Scope, SnapshotBudget{Resources: s.config.Limits.SnapshotResources, Bytes: s.config.Limits.SnapshotBytes})
	readCancel()
	if e != nil {
		return Response{}, storeError(e)
	}
	if !snap.Complete || len(snap.Resources) > s.config.Limits.SnapshotResources {
		return Response{}, failure(400, "tooMany")
	}
	remaining := s.config.Limits.SnapshotBytes
	for _, r := range snap.Resources {
		n, err := snapshotResourceSize(r, remaining)
		if err != nil {
			return Response{}, failure(400, "tooMany")
		}
		remaining -= n
	}
	type entry struct {
		resource Resource
		doc      map[string]any
	}
	entries := []entry{}
	seen := map[string]bool{}
	for _, r := range snap.Resources {
		if !s.authorityCurrent(ctx, c) {
			return Response{}, failure(503, "")
		}
		doc, e := s.resourceDocument(r)
		if e != nil {
			return Response{}, e
		}
		if seen[r.ID] {
			return Response{}, failure(503, "")
		}
		seen[r.ID] = true
		if p.filter.matches(doc) {
			entries = append(entries, entry{r, doc})
		}
	}
	validSort := true
	sort.Slice(entries, func(i, j int) bool {
		if p.sort != nil {
			a := sortValue(entries[i].doc, *p.sort)
			b := sortValue(entries[j].doc, *p.sort)
			cmp, valid := compareSortValue(a, b, p.sort.attribute())
			if !valid {
				validSort = false
			}
			if cmp != 0 {
				if p.query.SortOrder == "descending" {
					return cmp > 0
				}
				return cmp < 0
			}
		}
		return entries[i].resource.ID < entries[j].resource.ID
	})
	if !validSort {
		return Response{}, failure(503, "")
	}
	total := len(entries)
	resources := []any{}
	start := p.query.StartIndex - 1
	if start < total {
		end := start + *p.query.Count
		if end > total {
			end = total
		}
		for _, entry := range entries[start:end] {
			projected := s.project(entry.doc, p)
			resources = append(resources, projected)
			// Preflight each prospective page before encoding. Snapshot admission
			// separately bounds the resources that may be materialized at all.
			if _, err := encodedSize(listDocument(resources, total, p.query.StartIndex), s.config.Limits.ResponseBytes); err != nil {
				return Response{}, err
			}
		}
	}
	doc := listDocument(resources, total, p.query.StartIndex)
	body, e := s.encode(doc)
	if e != nil {
		return Response{}, e
	}
	return Response{Status: 200, ContentType: "application/scim+json", Body: body}, nil
}

func compareSortValue(a, b any, attr Attribute) (int, bool) {
	if !present(a) {
		if !present(b) {
			return 0, true
		}
		return 1, true
	}
	if !present(b) {
		return -1, true
	}
	return compareValue(a, b, attr)
}

func sortValue(doc map[string]any, path attributePath) any {
	if !path.appliesTo(doc) {
		return nil
	}
	var current any = doc
	if path.extension != "" {
		current = doc[path.extension]
	}
	for index, a := range path.parts {
		obj, ok := current.(map[string]any)
		if !ok {
			return nil
		}
		current = obj[a.Name]
		if current == nil && path.defaultPrimary && index == len(path.parts)-1 {
			current = false
		}
		if a.MultiValued {
			values, ok := current.([]any)
			if !ok || len(values) == 0 {
				return nil
			}
			current = values[0]
			if primary, ok := primaryAttribute(a); ok {
				for _, v := range values {
					if primaryTrue(v, primary) {
						current = v
						break
					}
				}
			}
		}
	}
	return current
}
func (s *protocolService) project(doc map[string]any, p queryPlan) map[string]any {
	out := cloneMap(doc)
	pruneReturned(out, append(commonAttributes(), s.profile.schema.Attributes...), "", p, true)
	for _, schema := range s.config.Extensions {
		if obj, ok := out[schema.ID].(map[string]any); ok {
			pruneReturned(obj, schema.Attributes, schema.ID+":", p, true)
			if len(obj) == 0 {
				delete(out, schema.ID)
			}
		}
	}
	// The selected profile always exposes the version needed for the next
	// mutation, including per-resource list projections. No whole-resource ETag
	// can replace these individual concurrency preconditions.
	originalMeta, _ := doc["meta"].(map[string]any)
	meta, _ := out["meta"].(map[string]any)
	if meta == nil {
		meta = map[string]any{}
		out["meta"] = meta
	}
	meta["version"] = originalMeta["version"]
	return out
}
func pruneReturned(doc map[string]any, attrs []Attribute, prefix string, p queryPlan, ancestorIncluded bool) {
	for _, a := range attrs {
		v, exists := doc[a.Name]
		if !exists {
			continue
		}
		path := prefix + a.Name
		if a.Returned == "never" || a.Mutability == "writeOnly" {
			delete(doc, a.Name)
			continue
		}
		keep := a.Returned == "always"
		if a.Returned != "always" {
			included := p.query.Attributes == "" && (ancestorIncluded && a.Returned != "request" || p.supplied[path])
			for _, q := range p.include {
				if q.text == path || strings.HasPrefix(path, q.text+".") || strings.HasPrefix(q.text, path+".") {
					included = true
				}
			}
			for _, q := range p.exclude {
				if q.text == path || strings.HasPrefix(path, q.text+".") {
					included = false
				}
			}
			keep = included
		}
		// Visit children before discarding an unselected parent. Always-returned
		// descendants need minimum ancestors, but never cross a privacy boundary
		// above. An unselected request-only parent cannot expose default children.
		hasChildren := false
		if a.Type == "complex" {
			if a.MultiValued {
				array, _ := v.([]any)
				for _, element := range array {
					if obj, ok := element.(map[string]any); ok {
						pruneReturned(obj, a.SubAttributes, path+".", p, keep)
						hasChildren = hasChildren || len(obj) > 0
					}
				}
			} else if obj, ok := v.(map[string]any); ok {
				pruneReturned(obj, a.SubAttributes, path+".", p, keep)
				hasChildren = len(obj) > 0
			}
		}
		if !keep && !hasChildren {
			delete(doc, a.Name)
		}
	}
}

// RFC 7643 section 7 returns request-only attributes supplied in a write, not
// all request-only values already stored. Derive that context from the validated
// command on every invocation, including Store replay; no new durable state or
// replay owner is needed. Paths are canonical and selectors identify attributes,
// not a separate query or disclosure authority.
func (s *protocolService) suppliedPaths(doc map[string]any, patch Patch) (map[string]bool, error) {
	out := map[string]bool{}
	var visit func(any, Attribute, string)
	visit = func(value any, a Attribute, path string) {
		out[path] = true
		if a.Type != "complex" {
			return
		}
		objects := []any{value}
		if values, ok := value.([]any); ok {
			objects = values
		}
		for _, element := range objects {
			if obj, ok := element.(map[string]any); ok {
				for key, v := range obj {
					if sub, ok := findAttribute(a.SubAttributes, key); ok {
						visit(v, sub, path+"."+sub.Name)
					}
				}
			}
		}
	}
	record := func(raw string, value any) error {
		if schema, ok := extensionSchema(s.config.Extensions, raw); ok {
			obj, _ := value.(map[string]any)
			for key, v := range obj {
				a, ok := findAttribute(schema.Attributes, key)
				if !ok {
					return failure(400, "invalidValue")
				}
				visit(v, a, schema.ID+":"+a.Name)
			}
			return nil
		}
		path, err := parsePatchPath(raw, s.config.Extensions, s.config.Limits, s.profile.schema)
		if err != nil {
			return err
		}
		a, text := path.path.attribute(), path.path.text
		if len(path.tail.parts) > 0 {
			a, text = path.tail.attribute(), text+"."+path.tail.text
		}
		visit(value, a, text)
		return nil
	}
	if len(patch.operations) > 0 {
		for _, op := range patch.operations {
			if op.Op == "remove" {
				continue
			}
			if op.Path != "" {
				if err := record(op.Path, op.Value); err != nil {
					return nil, err
				}
				continue
			}
			for key, v := range op.Value.(map[string]any) {
				if err := record(key, v); err != nil {
					return nil, err
				}
			}
		}
		return out, nil
	}
	for key, v := range doc {
		if strings.EqualFold(key, "schemas") {
			continue
		}
		if err := record(key, v); err != nil {
			return nil, err
		}
	}
	return out, nil
}
