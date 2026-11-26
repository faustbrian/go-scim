package scimpostgres

import (
	"context"
	"fmt"

	scim "github.com/faustbrian/go-scim"
)

// BulkService selects native Bulk for Group operations and acyclic User
// writes on one configured connection. It does not expose an HTTP endpoint.
// Its zero value does not execute requests.
type BulkService struct {
	graph *GroupBulkService
}

// NewBulkService borrows both protocols from the same configured Groups
// service. Install the Users, Groups, Bulk child execution and Bulk mutation
// migrations before use. Cycles containing Users are not selected.
func NewBulkService(groups *GroupsService, request scim.BulkPolicy, response scim.BulkResponsePolicy) (*BulkService, error) {
	graph, err := NewGroupBulkService(groups, request, response)
	if err != nil {
		return nil, err
	}
	graph.allowUsers = true
	return &BulkService{graph: graph}, nil
}

func (s *BulkService) executor() *GroupBulkService {
	if s == nil {
		return nil
	}
	return s.graph
}

// Admit durably allocates the complete graph without executing children.
func (s *BulkService) Admit(ctx context.Context, request BulkAdmissionRequest) (BulkAdmission, error) {
	return s.executor().Admit(ctx, request)
}

// ExecuteChild settles the selected original ordinal when its dependencies
// permit execution. Retry the same request and ordinal after an unknown result.
func (s *BulkService) ExecuteChild(ctx context.Context, request BulkAdmissionRequest, ordinal int) (scim.BulkChildResult, error) {
	return s.executor().ExecuteChild(ctx, request, ordinal)
}

// ReadResult returns the original ordered terminal response, without
// executing missing children or returning a partial response.
func (s *BulkService) ReadResult(ctx context.Context, request BulkAdmissionRequest) ([]byte, error) {
	return s.executor().ReadResult(ctx, request)
}

// Format redacts the selected connection and its borrowed runtime.
func (BulkService) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("scimpostgres.BulkService(redacted)"))
}

// MarshalJSON rejects accidental export of the service.
func (BulkService) MarshalJSON() ([]byte, error) { return nil, ErrInvalidConfiguration }
