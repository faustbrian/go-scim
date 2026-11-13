package scimpostgres

import (
	"context"

	identity "github.com/faustbrian/go-identity"
)

// Prepare only changed native-mapped strings, outside every transaction/lock.
// Other SCIM attributes remain protocol projection data, never verified email,
// membership or status authority. An unassigned displayName explicitly clears
// its optional mapped string; leaving the old personal value is not removal.
func (p *nativePhase) prepareChangedAttributes(ctx context.Context) ([]identity.AttributeUpdate, error) {
	if p.original.Current == nil {
		return nil, identity.InvalidInputError{Field: "scim_current_resource"}
	}
	c := p.service.config()
	updates := make([]identity.AttributeUpdate, 0, 2)
	for _, field := range []struct {
		protocol, native string
	}{{"userName", c.UserNameField}, {"displayName", c.DisplayNameField}} {
		if field.native == "" {
			continue
		}
		previous, err := mappedString(p.original.Current.Attributes, field.protocol)
		if err != nil {
			return nil, err
		}
		current, err := mappedString(p.resource.Attributes, field.protocol)
		if err != nil {
			return nil, err
		}
		if previous == current {
			continue
		}
		updates = append(updates, identity.AttributeUpdate{Name: field.native, Value: identity.AttributeValue{Kind: identity.AttributeString, Scalar: identity.AttributeScalar{Kind: identity.AttributeString, String: current}}})
	}
	return c.Fields.Prepare(ctx, identity.AttributePrepareRequest{TenantID: c.Scope.TenantID, UserID: identity.UserID(p.original.ID), SchemaVersion: c.FieldSchema.Version, Updates: updates, Context: p.service.caller(p.operation().OperationID, p.original.ID, "identity.user")})
}

func mappedString(attributes map[string]any, name string) (string, error) {
	value, present := attributes[name]
	if !present && name == "displayName" {
		return "", nil
	}
	text, ok := value.(string)
	if !ok || len(text) > 4096 || name == "userName" && text == "" {
		return "", identity.InvalidInputError{Field: "scim_mapped_attribute"}
	}
	return text, nil
}
