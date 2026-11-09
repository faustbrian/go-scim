package scim

import "encoding/json"

func (s *UsersService) discovery(op Operation, id string) (any, error) {
	switch op {
	case ServiceProviderConfig:
		d := map[string]any{"schemas": []string{configSchema}, "patch": map[string]any{"supported": true}, "bulk": map[string]any{"supported": false, "maxOperations": 0, "maxPayloadSize": 0}, "filter": map[string]any{"supported": true, "maxResults": s.config.Limits.PageMax}, "changePassword": map[string]any{"supported": false}, "sort": map[string]any{"supported": true}, "etag": map[string]any{"supported": true}, "authenticationSchemes": []any{map[string]any{"type": "oauthbearertoken", "name": "OAuth Bearer Token", "description": "Scoped bearer token", "specUri": "https://www.rfc-editor.org/rfc/rfc6750", "primary": true}}}
		if s.config.DocumentationURI != "" {
			d["documentationUri"] = s.config.DocumentationURI
		}
		return d, nil
	case ResourceTypeGet, ResourceTypesList:
		if op == ResourceTypeGet && id != "User" {
			return nil, failure(404, "")
		}
		extensions := []any{}
		for _, schema := range s.config.Extensions {
			extensions = append(extensions, map[string]any{"schema": schema.ID, "required": false})
		}
		d := map[string]any{"schemas": []string{resourceTypeSchema}, "id": "User", "name": "User", "endpoint": "/Users", "schema": userSchema, "schemaExtensions": extensions}
		if op == ResourceTypeGet {
			return d, nil
		}
		return listDocument([]any{d}, 1, 1), nil
	case SchemaGet, SchemasList:
		schemas := append([]Schema{{ID: userSchema, Name: "User", Description: "Selected Users profile", Attributes: coreAttributes()}}, s.config.Extensions...)
		docs := []any{}
		for _, schema := range schemas {
			doc := map[string]any{"schemas": []string{schemaSchema}, "id": schema.ID, "name": schema.Name, "description": schema.Description, "attributes": schema.Attributes}
			if op == SchemaGet && id == schema.ID {
				return doc, nil
			}
			docs = append(docs, doc)
		}
		if op == SchemaGet {
			return nil, failure(404, "")
		}
		return listDocument(docs, len(docs), 1), nil
	}
	return nil, failure(501, "")
}
func listDocument(resources []any, total, start int) map[string]any {
	return map[string]any{"schemas": []string{listSchema}, "Resources": resources, "totalResults": total, "startIndex": start, "itemsPerPage": len(resources)}
}
func (s *UsersService) encode(doc any) ([]byte, error) {
	if _, err := encodedSize(doc, s.config.Limits.ResponseBytes); err != nil {
		return nil, err
	}
	body, e := json.Marshal(doc)
	if e != nil {
		return nil, failure(503, "")
	}
	if len(body) > s.config.Limits.ResponseBytes {
		return nil, failure(400, "tooMany")
	}
	// Discovery and individual resources obey the same structural admission bounds.
	// List containers have their own byte/page bounds; each item is checked apart.
	return body, nil
}
func (s *UsersService) encodeResource(doc any) ([]byte, error) {
	b, e := s.encode(doc)
	if e != nil {
		return nil, e
	}
	l := s.config.Limits
	l.BodyBytes = l.ResponseBytes
	if _, e = decodeObject(b, l); e != nil {
		return nil, failure(503, "")
	}
	return b, nil
}

func (s *UsersService) encodeDiscovery(doc any) ([]byte, error) {
	// Collections are bounded as documents too, rather than bypassing structural
	// limits simply because their items were derived from trusted configuration.
	body, e := s.encode(doc)
	if e != nil {
		return nil, e
	}
	limits := s.config.Limits
	limits.BodyBytes = limits.ResponseBytes
	if _, e = decodeObject(body, limits); e != nil {
		return nil, failure(503, "")
	}
	return body, nil
}
