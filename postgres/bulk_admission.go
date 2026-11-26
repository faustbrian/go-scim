package scimpostgres

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/faustbrian/go-authentication/v2"
	"github.com/faustbrian/go-authorization/v3"
	identity "github.com/faustbrian/go-identity"
	kernel "github.com/faustbrian/go-identity/postgres"
	scim "github.com/faustbrian/go-scim"
)

// GroupBulkService explicitly selects durable admission for the configured
// Group projection. It does not enable discovery or an HTTP route.
// Its pool and authority remain borrowed from the ordinary Group service.
type GroupBulkService struct {
	native   *Service
	groups   *scim.GroupsService
	request  scim.BulkPolicy
	response scim.BulkResponsePolicy
	profile  [32]byte
}

// NewGroupBulkService performs no I/O. Install BulkAdmissionMigrationSource
// and the kernel's canonical Bulk alias schema before admitting requests.
func NewGroupBulkService(groups *GroupsService, request scim.BulkPolicy, response scim.BulkResponsePolicy) (*GroupBulkService, error) {
	if groups == nil || groups.native == nil || groups.protocol == nil ||
		request.MaxOperations < 1 || request.MaxOperations > 1000 || request.MaxPayloadBytes < 16384 || request.MaxPayloadBytes > 2097152 ||
		request.MaxOperationBytes < 1024 || request.MaxOperationBytes > 1048576 || request.MaxOperationBytes > request.MaxPayloadBytes ||
		response.MaxBytes < 16384 || response.MaxBytes > 4194304 || response.ErrorDetailBytes < 0 || response.ErrorDetailBytes > scim.DefaultLimits().ErrorDetailBytes {
		return nil, ErrInvalidConfiguration
	}
	if response.ErrorDetailBytes > groups.native.config().Limits.ErrorDetailBytes {
		return nil, ErrInvalidConfiguration
	}
	wire, err := json.Marshal(struct {
		Configuration  [32]byte
		MaximumMembers int
		Request        scim.BulkPolicy
		Response       scim.BulkResponsePolicy
	}{groups.native.profile, groups.maximumMembers, request, response})
	if err != nil {
		return nil, ErrInvalidConfiguration
	}
	return &GroupBulkService{native: groups.native, groups: groups.protocol, request: request, response: response, profile: sha256.Sum256(wire)}, nil
}

// Format redacts the selected connection and its borrowed runtime.
func (GroupBulkService) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("scimpostgres.GroupBulkService(redacted)"))
}

// MarshalJSON rejects accidental export of the service.
func (GroupBulkService) MarshalJSON() ([]byte, error) { return nil, ErrInvalidConfiguration }

// BulkAdmissionRequest borrows decoded JSON and credential custody for one
// synchronous call. The optional key aliases the canonical request; no field
// selects a tenant, connection, actor or server command identity.
type BulkAdmissionRequest struct {
	Credential     authentication.BearerCredential
	Body           []byte
	IdempotencyKey *identity.IdempotencyKey
}

// Format keeps the request body and bearer out of diagnostics.
func (BulkAdmissionRequest) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("scimpostgres.BulkAdmissionRequest(redacted)"))
}

// MarshalJSON rejects implicit persistence of request custody.
func (BulkAdmissionRequest) MarshalJSON() ([]byte, error) { return nil, ErrInvalidConfiguration }

// BulkAdmission identifies the committed graph, not any child outcome or a
// terminal response. A matching retry returns the same parent and byte bound.
type BulkAdmission struct {
	CommandID            identity.CommandID
	ChildCount           int
	ResponseMaximumBytes int
}

// Admit authorizes the configured Groups connection, plans and bounds the
// complete request, then commits every child and its dependencies together.
// It never executes a child. A non-nil error returns no admission; retry the
// exact original request after an ambiguous outcome.
func (s *GroupBulkService) Admit(ctx context.Context, request BulkAdmissionRequest) (result BulkAdmission, err error) {
	if s == nil || s.native == nil || ctx == nil {
		return BulkAdmission{}, scim.NewError(503, "")
	}
	c := s.native.config()
	ctx, cancel := context.WithTimeout(ctx, c.MaximumDuration)
	defer cancel()
	defer func() {
		if recover() != nil || ctx.Err() != nil {
			result, err = BulkAdmission{}, scim.NewError(503, "")
		} else if err != nil {
			result, err = BulkAdmission{}, bulkProtocolError(err)
		}
	}()
	p, _, err := s.admitGraph(ctx, request, nil)
	if err != nil {
		return BulkAdmission{}, err
	}
	return BulkAdmission{CommandID: p.original.Command, ChildCount: len(p.bulk.children), ResponseMaximumBytes: p.bulk.maximum}, nil
}

func (s *GroupBulkService) admitGraph(ctx context.Context, request BulkAdmissionRequest, ordinal *int) (*nativePhase, scim.BulkPlan, error) {
	prepared, err := s.prepareBulkGraph(ctx, request, ordinal)
	if err != nil {
		return nil, scim.BulkPlan{}, err
	}
	p, plan := prepared.phase, prepared.plan
	canonical := plan.CanonicalRequest()
	defer clear(canonical)
	if err := p.loadBulkOriginal(ctx, canonical, request.IdempotencyKey, bulkAdmitCustody); err != nil {
		return nil, scim.BulkPlan{}, err
	}
	receipt, err := p.execute(ctx)
	if err != nil {
		return nil, scim.BulkPlan{}, err
	}
	if receipt.Outcome != identity.CommitOutcomeCommitted {
		return nil, scim.BulkPlan{}, scim.NewError(503, "")
	}
	if err := p.requireCommittedBulkAdmission(ctx); err != nil {
		return nil, scim.BulkPlan{}, err
	}
	if err := s.native.recheckRead(ctx, &p.admission); err != nil {
		return nil, scim.BulkPlan{}, err
	}
	return p, plan, nil
}

type preparedBulkGraph struct {
	phase    *nativePhase
	plan     scim.BulkPlan
	response scim.BulkResponsePlan
}

func (s *GroupBulkService) prepareBulkGraph(ctx context.Context, request BulkAdmissionRequest, ordinal *int) (preparedBulkGraph, error) {
	c := s.native.config()
	i := new(invocation)
	ctx = context.WithValue(ctx, invocationKey{}, i)
	bridge := protocolBridge{service: s.native, groups: true}
	if _, err := bridge.Authenticate(ctx, request.Credential); err != nil {
		return preparedBulkGraph{}, scim.NewError(401, "")
	}
	operation := string(scim.Bulk)
	if err := s.native.decide(ctx, operation, c.Scope.ConnectionID, "identity.scim.bulk"); err != nil {
		return preparedBulkGraph{}, err
	}
	plan, err := scim.ParseBulk(request.Body, nil, s.request, c.Limits)
	if err != nil {
		return preparedBulkGraph{}, err
	}
	response, err := scim.PreflightBulkResponse(plan, c.BaseURL, s.response)
	if err != nil {
		return preparedBulkGraph{}, err
	}
	children := plan.Operations()
	if ordinal != nil && (*ordinal < 0 || *ordinal >= len(children)) {
		return preparedBulkGraph{}, scim.NewError(400, "invalidValue")
	}
	for _, child := range children {
		if child.Target.ResourceType == "User" {
			return preparedBulkGraph{}, scim.NewError(501, "")
		}
	}
	p := &nativePhase{service: s.native, admission: *i, bulk: &bulkAdmissionPhase{
		children: children, components: plan.Components(), cutoff: plan.FailOnErrors(), maximum: response.MaximumBytes(), profile: s.profile,
	}}
	return preparedBulkGraph{phase: p, plan: plan, response: response}, nil
}

func bulkProtocolError(err error) error {
	var protocol *scim.Error
	var conflict identity.ConflictError
	var forbidden identity.ForbiddenError
	var invalid identity.InvalidInputError
	switch {
	case errors.As(err, &protocol) && protocol != nil:
		return protocol
	case errors.As(err, &conflict):
		return scim.NewError(409, "")
	case errors.As(err, &forbidden):
		return scim.NewError(403, "")
	case errors.As(err, &invalid):
		return scim.NewError(400, "invalidValue")
	default:
		return scim.NewError(503, "")
	}
}

type bulkCustodyAccess uint8

const (
	bulkAdmitCustody bulkCustodyAccess = iota
	bulkReadCustody
)

func (p *nativePhase) loadBulkOriginal(ctx context.Context, canonical []byte, optional *identity.IdempotencyKey, access bulkCustodyAccess) error {
	c := p.service.config()
	op := p.operation().OperationID
	intent, err := p.service.requestIntent(canonical, op)
	if err != nil {
		return err
	}
	fields, ok := intent.Fields()
	if !ok {
		return identity.UnavailableError{}
	}
	fields = append(fields, identity.FeatureField{Name: "scim.bulk.profile", Value: identity.FeatureValue{Kind: identity.FeatureBytes, Bytes: p.bulk.profile[:]}})
	intent, err = identity.NewRequestIntent(fields)
	if err != nil {
		return err
	}
	digest := sha256.Sum256(canonical)
	selector, err := kernel.NewCanonicalRequestKey(append([]byte("scim-native-bulk-selector-v1\x00"), digest[:]...))
	if err != nil {
		return err
	}
	p.coordinator, p.registry, err = p.service.coordinator(p)
	if err != nil {
		return err
	}
	scope := kernel.RequestKeyScope{TenantID: c.Scope.TenantID, ActorID: c.ActorID, ActorKind: authorization.SubjectServiceAccount, Method: "POST", RouteID: op}
	caller := p.service.caller(op, op, "identity.request-admission")
	var binding kernel.RequestKeyPreparationBinding
	var wire []byte
	switch access {
	case bulkAdmitCustody:
		binding, wire, err = p.coordinator.ResolvePreparedCanonicalRequest(ctx, scope, selector, optional, intent, caller, p.registration(), p)
	case bulkReadCustody:
		var found bool
		binding, wire, found, err = p.coordinator.ReadPreparedCanonicalRequest(ctx, scope, selector, optional, intent, caller, p.registration(), p)
		if err == nil && !found {
			return scim.ErrBulkIncomplete
		}
	default:
		return identity.UnavailableError{}
	}
	defer clear(wire)
	if err != nil {
		return err
	}
	return p.restoreBulkRequest(ctx, binding, wire, fields)
}
