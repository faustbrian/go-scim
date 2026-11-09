package scim

import (
	"context"
	"encoding/json"
	"errors"
	"mime"
	"net/url"
	"strings"
	"time"
	"unicode/utf8"

	identity "github.com/faustbrian/go-identity"
)

// Execute performs one selected protocol operation. Inputs are borrowed only
// during the call, with no concurrent caller mutation. It authenticates raw
// credentials, authorizes the derived connection, then uses only that scope.
// Every dependency receives a bounded context. Errors expose no partial resource
// or provider diagnostic. A failed/uncertain mutation is never called success.
func (s *UsersService) Execute(parent context.Context, r Request) (out Response, err error) {
	defer func() {
		if recover() != nil {
			out = Response{}
			err = failure(503, "")
		}
		if err != nil {
			out = Response{}
			if e, ok := err.(*Error); ok && s != nil {
				copy := *e
				if !errorTypeForOperation(copy.kind, r.Operation) {
					copy.kind = ""
				}
				if len(copy.detail) > s.config.Limits.ErrorDetailBytes {
					copy.detail = copy.detail[:s.config.Limits.ErrorDetailBytes]
					for !utf8.ValidString(copy.detail) {
						copy.detail = copy.detail[:len(copy.detail)-1]
					}
				}
				err = &copy
			}
		}
	}()
	if s == nil || parent == nil {
		return Response{}, failure(503, "")
	}
	ctx, cancel := context.WithTimeout(parent, s.config.RequestTimeout)
	defer cancel()
	if ctx.Err() != nil {
		return Response{}, failure(503, "")
	}
	if len(r.ResourceID) > s.config.Limits.StringBytes || len(r.IdempotencyKey) > 256 || !utf8.ValidString(r.IdempotencyKey) {
		return Response{}, failure(400, "invalidValue")
	}
	if r.ContentEncoding != "" && !strings.EqualFold(r.ContentEncoding, "identity") {
		return Response{}, failure(415, "")
	}
	var doc map[string]any
	if len(r.Body) > 0 {
		typ, params, e := mime.ParseMediaType(r.ContentType)
		if e != nil || typ != "application/scim+json" {
			return Response{}, failure(415, "")
		}
		for key, value := range params {
			if key != "charset" || !strings.EqualFold(value, "utf-8") {
				return Response{}, failure(415, "")
			}
		}
		var e2 error
		doc, e2 = decodeObject(r.Body, s.config.Limits)
		if e2 != nil {
			return Response{}, e2
		}
	}
	if !validBearer(r.Credential.Token()) {
		return Response{}, failure(401, "")
	}
	c, e := s.config.Authenticator.Authenticate(ctx, r.Credential)
	if e != nil || !validConnection(c, s.config.Now()) {
		return Response{}, failure(401, "")
	}
	connectionCtx, connectionCancel, e := s.authorityContext(ctx, c)
	if e != nil {
		return Response{}, e
	}
	defer connectionCancel()
	ctx = connectionCtx
	// Apply the same disclosure fence to successful values AND state-dependent
	// errors. Register after cancellation cleanup so it sees the live context.
	// This never changes a Store outcome or aborts an already committed write.
	defer func() {
		if !s.authorityCurrent(ctx, c) {
			out = Response{}
			err = failure(503, "")
		}
	}()
	// Duplicate/case-alias decoding above always precedes policy, mapping and IO.
	policyCtx, policyCancel, e := s.authorityContext(ctx, c)
	if e != nil {
		return Response{}, e
	}
	e = s.config.Authorizer.Authorize(policyCtx, c, r.Operation, r.ResourceID)
	policyCancel()
	if e != nil {
		return Response{}, failure(403, "")
	}
	if !s.authorityCurrent(ctx, c) {
		return Response{}, failure(503, "")
	}
	switch r.Operation {
	case ServiceProviderConfig, SchemasList, SchemaGet, ResourceTypesList, ResourceTypeGet:
		d, e := s.discovery(r.Operation, r.ResourceID)
		if e != nil {
			return Response{}, e
		}
		b, e := s.encodeDiscovery(d)
		if e != nil {
			return Response{}, e
		}
		out = Response{Status: 200, ContentType: "application/scim+json", Body: b}
	case UserList, UserSearch, Search:
		q := r.Query
		if r.Operation != UserList {
			if doc == nil {
				return Response{}, failure(400, "invalidSyntax")
			}
			q, e = searchQuery(doc)
			if e != nil {
				return Response{}, e
			}
		}
		p, e := s.planQuery(q)
		if e != nil {
			return Response{}, e
		}
		out, err = s.list(ctx, c, p)
	case UserGet:
		if !safeID(r.ResourceID) {
			return Response{}, failure(404, "")
		}
		p, e := s.planQuery(r.Query)
		if e != nil {
			return Response{}, e
		}
		readCtx, readCancel, e := s.authorityContext(ctx, c)
		if e != nil {
			return Response{}, e
		}
		resource, e := s.config.Store.Get(readCtx, c.Scope, r.ResourceID)
		readCancel()
		if e != nil {
			return Response{}, storeError(e)
		}
		if resource.ID != r.ResourceID {
			return Response{}, failure(503, "")
		}
		out, err = s.resourceResponse(resource, 200, p)
	case UserCreate, UserReplace, UserPatch, UserDelete:
		out, err = s.write(ctx, c, r, doc)
	default:
		return Response{}, failure(501, "")
	}
	if err == nil && !s.authorityCurrent(ctx, c) {
		return Response{}, failure(503, "")
	}
	return out, err
}
func validBearer(token string) bool {
	if len(token) == 0 || len(token) > 8192 {
		return false
	}
	padding := false
	for _, b := range []byte(token) {
		if b == '=' {
			padding = true
			continue
		}
		if padding || !(b >= 'a' && b <= 'z' || b >= 'A' && b <= 'Z' || b >= '0' && b <= '9' || strings.ContainsRune("-._~+/", rune(b))) {
			return false
		}
	}
	return token[0] != '='
}
func validConnection(c Connection, now time.Time) bool {
	// Shared-issuer authority expires within twenty seconds of the ORIGINAL
	// read beginning (the same bound as authentication.DimensionValidity).
	// Cache retrieval, request timeout and token lifetime cannot renew it.
	return safeID(string(c.Scope.TenantID)) && safeID(string(c.Scope.OrganizationID)) && safeID(c.Scope.ProviderID) && safeID(c.Scope.ConnectionID) && safeID(c.CredentialID) && c.Version > 0 && !now.IsZero() && c.ExpiresAt.After(now) &&
		!c.AuthorityReadBeganAt.IsZero() && !c.AuthorityReadBeganAt.After(now) &&
		c.AuthorityValidUntil.After(c.AuthorityReadBeganAt) && c.AuthorityValidUntil.Sub(c.AuthorityReadBeganAt) <= 20*time.Second && now.Before(c.AuthorityValidUntil)
}

func authorityExpiry(c Connection) time.Time {
	if c.ExpiresAt.Before(c.AuthorityValidUntil) {
		return c.ExpiresAt
	}
	return c.AuthorityValidUntil
}

func (s *UsersService) authorityCurrent(ctx context.Context, c Connection) bool {
	return ctx.Err() == nil && validConnection(c, s.config.Now())
}

// A new child context consumes the ORIGINAL remaining budget; it never creates
// a new authority observation. Parent cancellation/deadlines remain controlling.
func (s *UsersService) authorityContext(ctx context.Context, c Connection) (context.Context, context.CancelFunc, error) {
	now := s.config.Now()
	if ctx.Err() != nil || !validConnection(c, now) {
		return nil, nil, failure(503, "")
	}
	child, cancel := context.WithTimeout(ctx, authorityExpiry(c).Sub(now))
	return child, cancel, nil
}

func sameConnection(a, b Connection) bool {
	return a.Scope == b.Scope && a.CredentialID == b.CredentialID && a.Version == b.Version &&
		a.ExpiresAt.Equal(b.ExpiresAt) && a.AuthorityReadBeganAt.Equal(b.AuthorityReadBeganAt) && a.AuthorityValidUntil.Equal(b.AuthorityValidUntil)
}
func storeError(e error) error {
	switch {
	case errors.Is(e, ErrNotFound):
		return failure(404, "")
	case errors.Is(e, ErrConflict):
		return failure(409, "")
	case errors.Is(e, ErrPreconditionFailed):
		return failure(412, "")
	case errors.Is(e, ErrUniqueness):
		return failure(409, "uniqueness")
	default:
		return failure(503, "")
	}
}
func (s *UsersService) canonicalResource(r Resource) (Resource, error) {
	if !safeID(r.ID) || !validVersion(r.Version) || r.CreatedAt.IsZero() || r.LastModified.Before(r.CreatedAt) || len(r.Schemas) == 0 || len(r.Schemas) > len(s.config.Extensions)+1 {
		return Resource{}, failure(503, "")
	}
	if e := checkTree(r.Attributes, s.config.Limits); e != nil {
		return Resource{}, failure(503, "")
	}
	canonical := make(map[string]any, len(r.Attributes))
	// Store projections may contain declared read-only attributes, but never
	// credentials. Validate those with their original type/returned descriptors.
	for key, value := range r.Attributes {
		if schema, ok := s.schema(key); ok && schema.ID != userSchema {
			obj, ok := value.(map[string]any)
			if !ok {
				return Resource{}, failure(503, "")
			}
			normalized, e := normalizeAttrs(obj, readableAttrs(schema.Attributes), nil)
			if e != nil {
				return Resource{}, failure(503, "")
			}
			canonical[schema.ID] = normalized
			continue
		}
		a, ok := findAttribute(coreAttributes(), key)
		if !ok {
			return Resource{}, failure(503, "")
		}
		normalized, e := normalizeValue(value, a, nil)
		if e != nil {
			return Resource{}, failure(503, "")
		}
		if normalized != nil {
			canonical[a.Name] = normalized
		}
	}
	r.Attributes = canonical
	declared := map[string]bool{}
	for _, id := range r.Schemas {
		if _, ok := s.schema(id); !ok || declared[id] {
			return Resource{}, failure(503, "")
		}
		declared[id] = true
	}
	if !declared[userSchema] {
		return Resource{}, failure(503, "")
	}
	for _, a := range coreAttributes() {
		if a.Required && !present(r.Attributes[a.Name]) {
			return Resource{}, failure(503, "")
		}
	}
	for key := range r.Attributes {
		if schema, ok := s.schema(key); ok && schema.ID != userSchema && !declared[key] {
			return Resource{}, failure(503, "")
		}
	}
	return r, nil
}

func (s *UsersService) resourceDocument(r Resource) (map[string]any, error) {
	r, e := s.canonicalResource(r)
	if e != nil {
		return nil, e
	}
	doc := writableDoc(WritableResource{Schemas: r.Schemas, ExternalID: r.ExternalID, Attributes: r.Attributes})
	doc["id"] = r.ID
	doc["meta"] = map[string]any{"resourceType": "User", "created": r.CreatedAt.UTC().Format(time.RFC3339Nano), "lastModified": r.LastModified.UTC().Format(time.RFC3339Nano), "version": string(r.Version), "location": s.location(r.ID)}
	if _, e := s.encodeResource(doc); e != nil {
		return nil, e
	}
	return doc, nil
}
func readableAttrs(attrs []Attribute) []Attribute {
	out := cloneAttrs(attrs)
	for i := range out {
		if out[i].Mutability == "readOnly" || out[i].Mutability == "immutable" {
			out[i].Mutability = "readWrite"
		}
		out[i].SubAttributes = readableAttrs(out[i].SubAttributes)
	}
	return out
}
func (s *UsersService) location(id string) string {
	return s.config.BaseURL + "/Users/" + url.PathEscape(id)
}
func (s *UsersService) resourceResponse(r Resource, status int, p queryPlan) (Response, error) {
	doc, e := s.resourceDocument(r)
	if e != nil {
		return Response{}, e
	}
	body, e := s.encodeResource(s.project(doc, p))
	if e != nil {
		return Response{}, e
	}
	return Response{Status: status, ContentType: "application/scim+json", Body: body, ETag: r.Version, Location: s.location(r.ID)}, nil
}

func (s *UsersService) write(ctx context.Context, c Connection, r Request, doc map[string]any) (out Response, err error) {
	p, e := s.planQuery(r.Query)
	if e != nil {
		return Response{}, e
	}
	if r.Operation != UserCreate {
		if !safeID(r.ResourceID) {
			return Response{}, failure(404, "")
		}
		if r.IfMatch == "" {
			return Response{}, failure(428, "")
		}
		if !validVersion(r.IfMatch) {
			return Response{}, failure(400, "invalidValue")
		}
	} else if r.ResourceID != "" || r.IfMatch != "" {
		return Response{}, failure(400, "invalidValue")
	}
	var input WritableResource
	var patch Patch
	switch r.Operation {
	case UserCreate, UserReplace:
		if doc == nil {
			return Response{}, failure(400, "invalidSyntax")
		}
		input, e = s.normalize(doc, nil)
		if e != nil {
			return Response{}, e
		}
		doc = writableDoc(input)
	case UserPatch:
		if doc == nil {
			return Response{}, failure(400, "invalidSyntax")
		}
		patch, e = parsePatchDocument(doc, s.config.Extensions, s.config.Limits)
		if e != nil {
			return Response{}, e
		}
	case UserDelete:
		if len(r.Body) > 0 {
			return Response{}, failure(400, "invalidSyntax")
		}
	}
	p.supplied, e = s.suppliedPaths(doc, patch)
	if e != nil {
		return Response{}, e
	}
	// The store owns keyed fingerprints and admission. This is only the bounded,
	// credential-free canonical protocol input, not a second journal/fingerprint.
	canonical, e := json.Marshal(struct {
		Operation Operation
		ID        string
		IfMatch   Version
		Body      any
		Query     Query
	}{r.Operation, r.ResourceID, r.IfMatch, doc, r.Query})
	if e != nil {
		return Response{}, failure(400, "invalidSyntax")
	}
	command, e := identity.NewCommandID()
	if e != nil {
		return Response{}, failure(503, "")
	}
	intent := WriteIntent{CommandID: command, Scope: c.Scope, Connection: c, Operation: r.Operation, ResourceID: r.ResourceID, IfMatch: r.IfMatch, IdempotencyKey: r.IdempotencyKey, CanonicalRequest: canonical}
	prepareCtx, prepareCancel, e := s.authorityContext(ctx, c)
	if e != nil {
		return Response{}, e
	}
	prepared, e := s.config.Store.Prepare(prepareCtx, intent)
	prepareCancel()
	if e != nil {
		return Response{}, storeError(e)
	}
	// Keep the original admission identity, including replay, and reject malformed
	// backend substitutions before using a current snapshot or invoking mapping.
	_, commandErr := identity.ParseCommandID(string(prepared.Intent.CommandID))
	if commandErr != nil || prepared.Replay == nil && prepared.Intent.CommandID != intent.CommandID || prepared.Intent.Scope != intent.Scope || prepared.Intent.Operation != intent.Operation || prepared.Intent.ResourceID != intent.ResourceID || prepared.Intent.IfMatch != intent.IfMatch || string(prepared.Intent.CanonicalRequest) != string(intent.CanonicalRequest) {
		return Response{}, failure(503, "")
	}
	if prepared.Replay != nil {
		return s.writeResponse(*prepared.Replay, r.Operation, p)
	}
	if !sameConnection(prepared.Intent.Connection, c) {
		// An invalid admission observation cannot establish that abort is safe.
		// Preserve uncertainty rather than passing renewed/substituted authority.
		return Response{}, failure(503, "")
	}
	abort := true
	defer func() {
		if !abort {
			return
		}
		cleanup, cancel := context.WithTimeout(context.WithoutCancel(ctx), s.config.RequestTimeout)
		defer cancel()
		if protocol, ok := err.(*Error); ok {
			copy := *protocol
			prepared.Failure = &copy
		} else {
			prepared.Failure = failure(503, "")
		}
		if e := s.config.Store.Abort(cleanup, prepared); e != nil {
			out = Response{}
			err = failure(503, "")
		}
	}()
	current := prepared.Current
	if r.Operation != UserCreate {
		if current == nil {
			return Response{}, failure(404, "")
		}
		if current.ID != r.ResourceID {
			return Response{}, failure(503, "")
		}
		canonical, err := s.canonicalResource(*current)
		if err != nil {
			return Response{}, err
		}
		current = &canonical
		if _, e = s.resourceDocument(*current); e != nil {
			return Response{}, e
		}
		if current.Version != r.IfMatch {
			return Response{}, failure(412, "")
		}
	} else if current != nil {
		return Response{}, failure(409, "uniqueness")
	}
	if r.Operation == UserReplace {
		input, e = s.normalize(doc, current.Attributes)
		if e != nil {
			return Response{}, e
		}
	}
	if r.Operation == UserPatch {
		input, e = s.applyPatch(*current, patch)
		if e != nil {
			return Response{}, e
		}
	}
	change := Change{Delete: r.Operation == UserDelete}
	if !change.Delete {
		// Validate the prospective escaped output before invoking representation
		// policy. Metadata has bounded server-owned shapes, not attacker lengths.
		previewID := r.ResourceID
		if previewID == "" {
			previewID = "0000000000000000000000"
		}
		preview := writableDoc(input)
		preview["id"] = previewID
		preview["meta"] = map[string]any{"resourceType": "User", "created": s.config.Now().UTC().Format(time.RFC3339Nano), "lastModified": s.config.Now().UTC().Format(time.RFC3339Nano), "location": s.location(previewID), "version": "\"0000000000000000000000\""}
		if _, err := encodedSize(s.project(preview, p), s.config.Limits.ResponseBytes); err != nil {
			return Response{}, failure(400, "invalidValue")
		}
		mapCtx, mapCancel, e := s.authorityContext(ctx, c)
		if e != nil {
			return Response{}, e
		}
		mapped, e := s.config.Mapper.MapUser(mapCtx, c.Scope, input)
		mapCancel()
		if e != nil {
			return Response{}, failure(409, "")
		}
		if e = checkWritable(mapped, s.config.Limits); e != nil {
			return Response{}, failure(503, "")
		}
		old := map[string]any{}
		if current != nil {
			old = current.Attributes
		}
		mapped, e = s.normalize(writableDoc(mapped), old)
		if e != nil {
			return Response{}, failure(503, "")
		}
		if current != nil {
			mapped = s.preserveReadOnly(*current, mapped)
		}
		now := s.config.Now()
		id := r.ResourceID
		created := now
		if current == nil {
			newID, e := identity.NewSubjectID()
			if e != nil {
				return Response{}, failure(503, "")
			}
			id = identity.FormatSubjectID(newID)
		} else {
			created = current.CreatedAt
			if now.Before(current.LastModified) {
				now = current.LastModified
			}
		}
		version, e := identity.NewCommandID()
		if e != nil {
			return Response{}, failure(503, "")
		}
		resource := Resource{ID: id, Version: Version(`"` + string(version) + `"`), CreatedAt: created, LastModified: now, Schemas: append([]string(nil), mapped.Schemas...), ExternalID: mapped.ExternalID, Attributes: cloneMap(mapped.Attributes)}
		if r.Operation == UserPatch && current != nil && s.sameProjection(*current, mapped) {
			resource = cloneResource(*current)
		}
		// A response that cannot fit is rejected before commit, not after mutation.
		if _, e = s.resourceResponse(resource, 200, p); e != nil {
			return Response{}, e
		}
		change.Resource = &resource
	}
	if !s.authorityCurrent(ctx, c) {
		return Response{}, failure(503, "")
	}
	// Recheck policy immediately before crossing the commit boundary; Store still
	// owns the atomic current-authority fence with the actual protected effects.
	policyCtx, policyCancel, e := s.authorityContext(ctx, c)
	if e != nil {
		return Response{}, e
	}
	e = s.config.Authorizer.Authorize(policyCtx, c, r.Operation, r.ResourceID)
	policyCancel()
	if e != nil {
		return Response{}, failure(403, "")
	}
	commitCtx, commitCancel, e := s.authorityContext(ctx, c)
	if e != nil {
		return Response{}, e
	}
	abort = false // From Commit invocation onward, arbitrary errors are UNKNOWN.
	result, e := s.config.Store.Commit(commitCtx, prepared, change)
	commitCancel()
	if e != nil {
		if errors.Is(e, ErrPreconditionFailed) || errors.Is(e, ErrConflict) || errors.Is(e, ErrUniqueness) || errors.Is(e, ErrNotFound) {
			abort = true
		}
		return Response{}, storeError(e)
	}
	if result.Outcome == WriteOutcomeNotCommitted {
		abort = true
	}
	if result.Outcome == WriteOutcomeCommitted && change.Resource != nil {
		if result.Resource != nil {
			canonical, err := s.canonicalResource(*result.Resource)
			if err != nil {
				return Response{}, err
			}
			result.Resource = &canonical
		}
		if result.Resource == nil || !sameResource(*result.Resource, *change.Resource) {
			return Response{}, failure(503, "")
		}
	}
	return s.writeResponse(result, r.Operation, p)
}

func (s *UsersService) sameProjection(current Resource, next WritableResource) bool {
	if current.ExternalID != next.ExternalID || len(current.Schemas) != len(next.Schemas) {
		return false
	}
	for _, id := range current.Schemas {
		found := false
		for _, other := range next.Schemas {
			if id == other {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}
	attrs := append(coreAttributes(), commonAttributes()...)
	for _, a := range attrs {
		old, new := current.Attributes[a.Name], next.Attributes[a.Name]
		if !present(old) && !present(new) {
			continue
		}
		if !sameValue(old, new, a) {
			return false
		}
	}
	for _, schema := range s.config.Extensions {
		old, new := current.Attributes[schema.ID], next.Attributes[schema.ID]
		if !present(old) && !present(new) {
			continue
		}
		if !sameValue(old, new, Attribute{Type: "complex", SubAttributes: schema.Attributes}) {
			return false
		}
	}
	return true
}
func (s *UsersService) writeResponse(result WriteResult, op Operation, p queryPlan) (Response, error) {
	if result.Outcome == WriteOutcomeNotCommitted && result.Resource == nil && result.Failure != nil {
		return Response{}, NewError(result.Failure.StatusCode(), result.Failure.kind)
	}
	if result.Outcome != WriteOutcomeCommitted || result.Failure != nil {
		return Response{}, failure(503, "")
	}
	if op == UserDelete {
		if result.Resource != nil {
			return Response{}, failure(503, "")
		}
		return Response{Status: 204}, nil
	}
	if result.Resource == nil {
		return Response{}, failure(503, "")
	}
	status := 200
	if op == UserCreate {
		status = 201
	}
	return s.resourceResponse(*result.Resource, status, p)
}
func sameResource(a, b Resource) bool {
	x, e := json.Marshal(a)
	y, f := json.Marshal(b)
	return e == nil && f == nil && string(x) == string(y)
}
func checkWritable(w WritableResource, l Limits) error {
	if len(w.Schemas) > l.ResourceAttributes || len(w.ExternalID) > l.StringBytes {
		return failure(400, "invalidValue")
	}
	for _, id := range w.Schemas {
		if len(id) > l.StringBytes {
			return failure(400, "invalidValue")
		}
	}
	return checkTree(w.Attributes, l)
}
func checkTree(value any, l Limits) error {
	attributes := 0
	budget := 0
	var walk func(any, int) bool
	walk = func(v any, depth int) bool {
		if depth > l.ResourceDepth {
			return false
		}
		switch x := v.(type) {
		case map[string]any:
			if len(x) > l.ResourceAttributes {
				return false
			}
			seen := map[string]bool{}
			for key, v := range x {
				attributes++
				budget += len(key)
				fold := foldString(key)
				if seen[fold] || attributes > l.ResourceAttributes || len(key) > l.StringBytes {
					return false
				}
				seen[fold] = true
				if !walk(v, depth+1) {
					return false
				}
			}
		case []any:
			if len(x) > l.ResourceAttributes {
				return false
			}
			for _, v := range x {
				if !walk(v, depth+1) {
					return false
				}
			}
		case patchConcat:
			if len(x.before)+len(x.added) > l.ResourceAttributes {
				return false
			}
			for _, part := range [][]any{x.before, x.added} {
				for _, v := range part {
					if !walk(v, depth+1) {
						return false
					}
				}
			}
		case string:
			if len(x) > l.StringBytes || !utf8.ValidString(x) {
				return false
			}
			budget += len(x)
		case json.Number:
			if !boundedNumber(x) {
				return false
			}
			budget += len(x)
		case bool, nil:
			budget++
		default:
			return false
		}
		return budget <= l.BodyBytes
	}
	if !walk(value, 1) {
		return failure(400, "invalidValue")
	}
	return nil
}
