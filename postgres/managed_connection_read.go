package scimpostgres

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"time"

	"github.com/faustbrian/go-authorization/v3"
	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/session"
	organization "github.com/faustbrian/go-organization"
	organizationpg "github.com/faustbrian/go-organization/postgres"
	database "github.com/faustbrian/go-postgres"
	scim "github.com/faustbrian/go-scim"
	"github.com/jackc/pgx/v5"
)

// ManagedConnectionServiceConfig selects authoritative native administrator
// sessions, policy, and the core User mapping profile. CursorKey is a dedicated
// deployment key; changing it invalidates previous continuations.
type ManagedConnectionServiceConfig struct {
	Sessions        *session.SessionService
	Authorization   authorization.Service
	PolicyVersion   uint64
	MaximumDuration time.Duration
	CursorKey       [32]byte
	Limits          scim.Limits
	Writes          *ManagedConnectionWriteConfig
}

func (ManagedConnectionServiceConfig) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("scimpostgres.ManagedConnectionServiceConfig(redacted)"))
}

func (ManagedConnectionServiceConfig) MarshalJSON() ([]byte, error) {
	return nil, ErrInvalidConfiguration
}

// ManagedConnectionService is safe for concurrent bounded calls. It borrows
// the primary pool and authority readers; it does not own their lifetimes.
type ManagedConnectionService struct {
	pool          *database.Pool
	organizations *organizationpg.Repository
	config        ManagedConnectionServiceConfig
	writer        func() *managedConnectionWriter
}

func (*ManagedConnectionService) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("scimpostgres.ManagedConnectionService(redacted)"))
}

// NewManagedConnectionService validates the selected authority composition
// without IO. Install ManagedConnectionsMigrationSource before using it.
func NewManagedConnectionService(pool *database.Pool, c ManagedConnectionServiceConfig) (*ManagedConnectionService, error) {
	if pool == nil || pool.Raw() == nil || c.Sessions == nil || c.Authorization == nil || c.PolicyVersion == 0 || c.MaximumDuration <= 0 || c.MaximumDuration > 5*time.Second || c.CursorKey == ([32]byte{}) {
		return nil, ErrInvalidConfiguration
	}
	if _, err := scim.ParseMappingPath("userName", nil, c.Limits); err != nil {
		return nil, ErrInvalidConfiguration
	}
	organizations, err := organizationpg.NewRepository(pool, organizationpg.Config{MaximumDuration: c.MaximumDuration})
	if err != nil {
		return nil, ErrInvalidConfiguration
	}
	service := &ManagedConnectionService{pool: pool, organizations: organizations, config: c}
	service.config.Writes = nil
	if c.Writes != nil {
		if err := service.configureWriter(*c.Writes); err != nil {
			return nil, err
		}
	}
	return service, nil
}

// ConnectionGetRequest names one canonical ID within the authenticated tenant.
// The record's organization is resolved from the primary, not caller input.
type ConnectionGetRequest struct {
	Authentication organization.Authentication
	ConnectionID   scim.ConnectionID
}

// ConnectionListRequest lists the exact organization's managed records in
// bytewise connection-ID order. Limit is 1 to 200; the cursor is opaque.
type ConnectionListRequest struct {
	Authentication organization.Authentication
	OrganizationID organization.ID
	Cursor         string
	Limit          uint16
}

// ConnectionListResult returns detached redacted records. NextCursor is empty
// at the end. Pages are live primary reads rather than a retained snapshot.
type ConnectionListResult struct {
	Connections []scim.ConnectionRecord
	NextCursor  string
}

// ConnectionGet returns only the stored administrative projection after
// current session, organization role and org:scim-read policy decisions.
// Missing and unauthorized connections disclose the same denial.
func (s *ManagedConnectionService) ConnectionGet(ctx context.Context, request ConnectionGetRequest) (scim.ConnectionRecord, error) {
	if s == nil || ctx == nil {
		return scim.ConnectionRecord{}, ErrInvalidConfiguration
	}
	if _, err := scim.ParseConnectionID(string(request.ConnectionID)); err != nil {
		return scim.ConnectionRecord{}, identity.InvalidInputError{Field: "connection_id"}
	}
	ctx, cancel := context.WithTimeout(ctx, s.config.MaximumDuration)
	defer cancel()
	actor, err := s.authenticateManagedAdmin(ctx, request.Authentication)
	if err != nil {
		return scim.ConnectionRecord{}, err
	}
	var org organization.ID
	err = s.pool.Raw().QueryRow(ctx, managedConnectionOrganizationSQL, string(actor.tenant), string(request.ConnectionID)).Scan(&org)
	if err != nil {
		return scim.ConnectionRecord{}, managedConnectionReadError(ctx, err)
	}
	view, err := s.authorizeManagedAdmin(ctx, actor, org, "org:scim-read")
	if err != nil {
		return scim.ConnectionRecord{}, err
	}
	row := s.pool.Raw().QueryRow(ctx, managedConnectionGetSQL, string(actor.tenant), string(org), string(request.ConnectionID))
	record, err := s.scanManagedConnection(row, actor.tenant, org)
	if err != nil {
		return scim.ConnectionRecord{}, managedConnectionReadError(ctx, err)
	}
	if err := s.recheckManagedAdmin(ctx, request.Authentication, actor, view, "org:scim-read"); err != nil {
		return scim.ConnectionRecord{}, err
	}
	return record, nil
}

// ConnectionList requires current administrator access to the exact tenant
// and organization. Invalid cursors and any failed row or authority check
// return no partial page or continuation.
func (s *ManagedConnectionService) ConnectionList(ctx context.Context, request ConnectionListRequest) (ConnectionListResult, error) {
	if s == nil || ctx == nil {
		return ConnectionListResult{}, ErrInvalidConfiguration
	}
	if request.Limit < 1 || request.Limit > 200 {
		return ConnectionListResult{}, identity.InvalidInputError{Field: "limit"}
	}
	after, ok := decodeManagedConnectionCursor(request.Cursor, request.Authentication.TenantID, request.OrganizationID, s.config.CursorKey)
	if !ok {
		return ConnectionListResult{}, identity.InvalidInputError{Field: "cursor_or_scope"}
	}
	ctx, cancel := context.WithTimeout(ctx, s.config.MaximumDuration)
	defer cancel()
	actor, err := s.authenticateManagedAdmin(ctx, request.Authentication)
	if err != nil {
		return ConnectionListResult{}, err
	}
	view, err := s.authorizeManagedAdmin(ctx, actor, request.OrganizationID, "org:scim-read")
	if err != nil {
		return ConnectionListResult{}, err
	}
	page, err := s.readManagedConnectionPage(ctx, actor.tenant, request.OrganizationID, after, int(request.Limit))
	if err != nil {
		return ConnectionListResult{}, err
	}
	if err := s.recheckManagedAdmin(ctx, request.Authentication, actor, view, "org:scim-read"); err != nil {
		return ConnectionListResult{}, err
	}
	return page, nil
}

const managedConnectionOrganizationSQL = `SELECT organization_id FROM scim.managed_connections WHERE tenant_id=$1 AND connection_id=$2`

const managedConnectionColumnsSQL = `SELECT m.provider_id,m.connection_id,m.mappings,m.deprovision_policy,c.version::text
 FROM scim.managed_connections m JOIN scim.connections c USING(tenant_id,organization_id,provider_id,connection_id)
 WHERE m.tenant_id=$1 AND m.organization_id=$2 AND c.state <> 'deleted'`

const managedConnectionGetSQL = managedConnectionColumnsSQL + ` AND m.connection_id=$3`

// Both tuple endpoints fix the tenant/organization prefix; '~' sorts after
// every canonical connection-ID byte. Ordering the full tuple retains the
// organization-page access path even for an empty organization in a busy tenant.
// The lateral LIMIT keeps binding reads as per-key probes, but the page LIMIT
// remains after deletion filtering so retained deleted rows cannot hide a page.
const managedConnectionListSQL = `SELECT m.provider_id,m.connection_id,m.mappings,m.deprovision_policy,c.version::text
 FROM scim.managed_connections m
 JOIN LATERAL (
   SELECT c.version FROM scim.connections c
   WHERE c.tenant_id=m.tenant_id AND c.organization_id=m.organization_id
     AND c.provider_id=m.provider_id AND c.connection_id=m.connection_id
     AND c.state <> 'deleted'
   LIMIT 1
 ) c ON true
 WHERE (m.tenant_id,m.organization_id,m.connection_id) > ($1,$2,$3)
   AND (m.tenant_id,m.organization_id,m.connection_id) < ($1,$2,'~')
 ORDER BY m.tenant_id,m.organization_id,m.connection_id LIMIT $4`

func (s *ManagedConnectionService) readManagedConnectionPage(ctx context.Context, tenant identity.TenantID, org organization.ID, after scim.ConnectionID, limit int) (ConnectionListResult, error) {
	rows, err := s.pool.Raw().Query(ctx, managedConnectionListSQL, string(tenant), string(org), string(after), limit+1)
	if err != nil {
		return ConnectionListResult{}, managedConnectionReadError(ctx, err)
	}
	defer rows.Close()
	result := ConnectionListResult{Connections: make([]scim.ConnectionRecord, 0, limit)}
	for rows.Next() {
		if len(result.Connections) == limit {
			id := result.Connections[limit-1].Scope().ProviderConnectionID
			result.NextCursor = encodeManagedConnectionCursor(tenant, org, id, s.config.CursorKey)
			if result.NextCursor == "" {
				return ConnectionListResult{}, identity.UnavailableError{}
			}
			continue
		}
		record, err := s.scanManagedConnection(rows, tenant, org)
		if err != nil {
			return ConnectionListResult{}, managedConnectionReadError(ctx, err)
		}
		result.Connections = append(result.Connections, record)
	}
	if err := rows.Err(); err != nil {
		return ConnectionListResult{}, managedConnectionReadError(ctx, err)
	}
	return result, nil
}

type managedMappingWire struct {
	Source   string `json:"source"`
	Target   string `json:"target"`
	Writable bool   `json:"writable"`
}

func (s *ManagedConnectionService) scanManagedConnection(row pgx.Row, tenant identity.TenantID, org organization.ID) (scim.ConnectionRecord, error) {
	scope := scim.ConnectionScope{TenantID: tenant, OrganizationID: org}
	var mappingBytes []byte
	var policy, versionText string
	if err := row.Scan(&scope.ProviderID, &scope.ProviderConnectionID, &mappingBytes, &policy, &versionText); err != nil {
		return scim.ConnectionRecord{}, err
	}
	version, err := strconv.ParseUint(versionText, 10, 64)
	if err != nil || version == 0 || policy != "remove-membership" {
		return scim.ConnectionRecord{}, identity.UnavailableError{}
	}
	mappings, err := decodeManagedMappings(mappingBytes, s.config.Limits)
	if err != nil {
		return scim.ConnectionRecord{}, err
	}
	return scim.NewConnectionRecord(scope, mappings, scim.RemoveMembership, version)
}

func decodeManagedMappings(wire []byte, limits scim.Limits) (scim.MappingSet, error) {
	var entries []managedMappingWire
	if len(wire) < 2 || len(wire) > 65536 || json.Unmarshal(wire, &entries) != nil || len(entries) < 1 || len(entries) > 128 {
		return scim.MappingSet{}, identity.UnavailableError{}
	}
	canonical, err := json.Marshal(entries)
	if err != nil || !bytes.Equal(wire, canonical) {
		return scim.MappingSet{}, identity.UnavailableError{}
	}
	mappings := make([]scim.Mapping, 0, len(entries))
	for _, entry := range entries {
		path, err := scim.ParseMappingPath(entry.Source, nil, limits)
		if err != nil || path.String() != entry.Source {
			return scim.MappingSet{}, identity.UnavailableError{}
		}
		mappings = append(mappings, scim.Mapping{Source: path, Target: entry.Target, Writable: entry.Writable})
	}
	return scim.NewMappingSet(mappings)
}

func managedConnectionReadError(ctx context.Context, err error) error {
	if ctx.Err() != nil {
		return ctx.Err()
	}
	if errors.Is(err, pgx.ErrNoRows) {
		return identity.ForbiddenError{}
	}
	return identity.UnavailableError{}
}
