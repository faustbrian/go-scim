package scim

import (
	"encoding/json"
	"slices"
	"strings"

	identity "github.com/faustbrian/go-identity"
	organization "github.com/faustbrian/go-organization"
)

// ConnectionID is the canonical 22-character, nonzero managed connection ID.
// Possession grants no authority. Store owners must bind it to the exact tenant.
type ConnectionID string

// ParseConnectionID validates a managed ID without rewriting its spelling.
func ParseConnectionID(raw string) (ConnectionID, error) {
	id, err := identity.ParseSubjectID(raw)
	if err != nil {
		return "", failure(400, "invalidValue")
	}
	return ConnectionID(id), nil
}

// ProviderID is the exact bounded provider identity in a managed connection.
type ProviderID string

// ConnectionScope is the exact tenant, organization, provider and managed ID.
// Tenant, organization and connection IDs use the canonical nonzero 128-bit
// encoding. Scope describes ownership; it does not authenticate a requester.
type ConnectionScope struct {
	TenantID             identity.TenantID
	OrganizationID       organization.ID
	ProviderID           ProviderID
	ProviderConnectionID ConnectionID
}

// DeprovisionPolicy names a configured disposition. Recording a policy does
// not enable it; lifecycle owners must reject unsupported dispositions.
type DeprovisionPolicy uint8

const (
	// Suspend selects the identity owner's suspension lifecycle.
	Suspend DeprovisionPolicy = iota + 1
	// RemoveMembership selects withdrawal of the owned directory membership.
	RemoveMembership
	// DeleteIdentity selects the identity owner's deletion lifecycle.
	DeleteIdentity
)

// Path is an immutable canonical readable SCIM mapping path. Zero is invalid.
type Path struct{ canonical string }

// String returns the canonical path, or an empty string for the zero value.
func (p Path) String() string { return p.canonical }

// ParseMappingPath resolves a bounded User path against the core and supplied
// extension schemas. It supports readable attributes and value selection, but
// never grants access to write-only or returned-never attributes. Core aliases
// resolve to the unqualified spelling; extension ownership remains explicit.
func ParseMappingPath(raw string, extensions []Schema, limits Limits) (Path, error) {
	if !limits.valid() || !validateSchemas(extensions, limits) {
		return Path{}, failure(400, "invalidPath")
	}
	parsed, err := parseResourcePath(raw, extensions, limits, false)
	if err != nil {
		return Path{}, failure(400, "invalidPath")
	}
	canonical := parsed.path.text
	if parsed.selected {
		var text strings.Builder
		text.WriteString(canonical)
		text.WriteByte('[')
		start := text.Len()
		if !appendMappingFilter(&text, parsed.selector.node, 0) || text.Len()-start > limits.FilterBytes {
			return Path{}, failure(400, "invalidPath")
		}
		text.WriteByte(']')
		if parsed.tail.text != "" {
			text.WriteByte('.')
			text.WriteString(parsed.tail.text)
		}
		canonical = text.String()
	}
	if len(canonical) > limits.PathBytes {
		return Path{}, failure(400, "invalidPath")
	}
	return Path{canonical: canonical}, nil
}

func appendMappingFilter(text *strings.Builder, node *filterNode, parentPrecedence int) bool {
	if node == nil {
		return false
	}
	switch node.op {
	case "or", "and":
		precedence := 1
		if node.op == "and" {
			precedence = 2
		}
		group := precedence < parentPrecedence
		if group {
			text.WriteByte('(')
		}
		if !appendMappingFilter(text, node.left, precedence) {
			return false
		}
		text.WriteString(" " + node.op + " ")
		// The parser associates equally ranked operators to the left. Group an
		// equally ranked right child so normalization preserves the tree height.
		if !appendMappingFilter(text, node.right, precedence+1) {
			return false
		}
		if group {
			text.WriteByte(')')
		}
	case "not":
		text.WriteString("not (")
		if !appendMappingFilter(text, node.left, 0) {
			return false
		}
		text.WriteByte(')')
	case "pr":
		text.WriteString(node.path.text + " pr")
	case "eq", "ne", "co", "sw", "ew", "gt", "ge", "lt", "le":
		value, err := json.Marshal(node.value)
		if err != nil {
			return false
		}
		text.WriteString(node.path.text + " " + node.op + " ")
		text.Write(value)
	default:
		return false
	}
	return true
}

// Mapping describes one resolved source and the planned target field. The
// owning write path still validates the target schema and writable policy.
type Mapping struct {
	Source   Path
	Target   string
	Writable bool
}

// MappingSet is an immutable ordered set of 1–128 distinct mappings with a
// bounded canonical storage encoding. Use Entries to obtain a detached copy.
type MappingSet struct{ entries []Mapping }

// NewMappingSet validates the bounded entries and rejects repeated canonical
// sources or repeated exact targets. It never retains the caller's slice.
func NewMappingSet(mappings []Mapping) (MappingSet, error) {
	const maxEntries, maxEncodedBytes = 128, 65536
	invalid := func() (MappingSet, error) { return MappingSet{}, failure(400, "invalidValue") }
	if len(mappings) == 0 || len(mappings) > maxEntries {
		return invalid()
	}
	sources, targets := make(map[string]bool, len(mappings)), make(map[string]bool, len(mappings))
	encodedBytes := 2 + len(mappings) - 1 // JSON array and separating commas.
	for _, mapping := range mappings {
		source := mapping.Source.String()
		if source == "" || !boundedConnectionASCII(mapping.Target) || sources[source] || targets[mapping.Target] {
			return invalid()
		}
		sources[source], targets[mapping.Target] = true, true
		wire, err := json.Marshal(struct {
			Source   string `json:"source"`
			Target   string `json:"target"`
			Writable bool   `json:"writable"`
		}{source, mapping.Target, mapping.Writable})
		if err != nil {
			return invalid()
		}
		encodedBytes += len(wire)
		if encodedBytes > maxEncodedBytes {
			return invalid()
		}
	}
	return MappingSet{entries: slices.Clone(mappings)}, nil
}

// Entries returns a detached copy. Nothing is returned for the zero value.
func (s MappingSet) Entries() []Mapping { return slices.Clone(s.entries) }

// ConnectionRecord is an immutable administrative projection, separate from
// the released credential observation Connection. It carries no bearer,
// credential digest or authority freshness. The zero record is invalid.
type ConnectionRecord struct {
	scope    ConnectionScope
	mappings MappingSet
	policy   DeprovisionPolicy
	version  uint64
}

// NewConnectionRecord validates a detached managed snapshot. Durable binding,
// permission, and enforcement of its selected policy remain owner operations.
func NewConnectionRecord(scope ConnectionScope, mappings MappingSet, policy DeprovisionPolicy, version uint64) (ConnectionRecord, error) {
	for _, id := range [...]string{string(scope.TenantID), string(scope.OrganizationID), string(scope.ProviderConnectionID)} {
		if _, err := identity.ParseSubjectID(id); err != nil {
			return ConnectionRecord{}, failure(400, "invalidValue")
		}
	}
	provider := string(scope.ProviderID)
	if !boundedConnectionASCII(provider) || !safeID(provider) || len(mappings.entries) == 0 || version == 0 ||
		(policy != Suspend && policy != RemoveMembership && policy != DeleteIdentity) {
		return ConnectionRecord{}, failure(400, "invalidValue")
	}
	return ConnectionRecord{scope: scope, mappings: mappings, policy: policy, version: version}, nil
}

// Scope returns the exact managed ownership partition.
func (r ConnectionRecord) Scope() ConnectionScope { return r.scope }

// Mappings returns the immutable configured mappings.
func (r ConnectionRecord) Mappings() MappingSet { return r.mappings }

// DeprovisionPolicy returns the declared disposition, not proof of execution.
func (r ConnectionRecord) DeprovisionPolicy() DeprovisionPolicy { return r.policy }

// Version returns the exact concurrency version supplied by the owner.
func (r ConnectionRecord) Version() uint64 { return r.version }

func boundedConnectionASCII(value string) bool {
	if len(value) == 0 || len(value) > 128 {
		return false
	}
	for i := 0; i < len(value); i++ {
		if value[i] < 33 || value[i] > 126 {
			return false
		}
	}
	return true
}
