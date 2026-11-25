//go:build integration

package scimpostgres

import (
	"bytes"
	"context"
	"crypto/sha256"
	"slices"
	"testing"

	"github.com/faustbrian/go-audit"
	auditpg "github.com/faustbrian/go-audit/postgres"
	"github.com/faustbrian/go-authorization/v3"
	identity "github.com/faustbrian/go-identity"
	kernel "github.com/faustbrian/go-identity/postgres"
	scim "github.com/faustbrian/go-scim"
	lifecyclepg "github.com/faustbrian/go-transactional-outbox/postgres/identity"
)

// Only preparation uses this owner. Execution switches back to the actual
// native owner so every protected Work check still requires its exact identity.
type bulkUpgradePreparationOwner struct {
	*nativePhase
	schema uint8
}

func (p *bulkUpgradePreparationOwner) PrepareRequestKey(ctx context.Context, binding kernel.RequestKeyPreparationBinding, _ identity.RequestIntent) ([]byte, error) {
	return p.prepareBulkRequestVersion(ctx, binding, p.schema)
}

func TestNativeBulkAdmissionUpgradeRetainsV1ParentCustody(t *testing.T) {
	for _, checkpoint := range []string{"committed", "preparation-only"} {
		t.Run(checkpoint, func(t *testing.T) {
			f, service := bulkAdmissionFixture(t, scim.DefaultBulkResponsePolicy())
			request := BulkAdmissionRequest{Credential: f.bearer, Body: []byte(cyclicGroupBulkFixture)}
			legacy, binding, wire, fields := retainBulkUpgradePreparation(t, f, service, request, 1)
			if err := legacy.restoreBulkRequest(f.ctx, binding, wire, fields); err != nil {
				t.Fatal("restore authentic original v1 allocation", err)
			}
			original := BulkAdmission{CommandID: legacy.original.Command, ChildCount: len(legacy.bulk.children), ResponseMaximumBytes: legacy.bulk.maximum}
			allocations := slices.Clone(legacy.bulk.allocation)
			preparationIdentity, preparation := readLegacyBulkPreparation(t, f, original.CommandID)
			var originalPlan, originalAudit []byte
			if checkpoint == "committed" {
				result, err := legacy.execute(f.ctx)
				if err != nil || result.Outcome != identity.CommitOutcomeCommitted {
					t.Fatal("commit the genuine v1 native parent through the kernel", err)
				}
				originalPlan, originalAudit = readLegacyBulkCommit(t, f, original.CommandID)
				requireLegacyBulkAllocations(t, f, original.CommandID, allocations)
				requireNativeBulkCounts(t, f, [5]int{1, 2, 1, 1, 1})
			} else {
				requireNativeBulkCounts(t, f, [5]int{})
				var commands int
				if err := f.pool.Raw().QueryRow(f.ctx, `SELECT count(*) FROM identity.commands WHERE purpose=$1`, string(scim.Bulk)).Scan(&commands); err != nil || commands != 0 {
					t.Fatal("preparation-only custody fabricated a command plan or execution", commands, err)
				}
			}

			for replay := range 2 {
				reconstructed, err := NewGroupBulkService(groupsOnPool(t, f, f.pool), scim.DefaultBulkPolicy(), scim.DefaultBulkResponsePolicy())
				if err != nil {
					t.Fatal("reconstruct upgraded native Bulk service", err)
				}
				admitted, err := reconstructed.Admit(f.ctx, request)
				if err != nil || admitted != original {
					t.Fatal("upgraded replay changed the original v1 parent admission", replay, err)
				}
				identityAfter, preparationAfter := readLegacyBulkPreparation(t, f, original.CommandID)
				if !bytes.Equal(identityAfter, preparationIdentity) || !bytes.Equal(preparationAfter, preparation) {
					t.Fatal("upgraded replay replaced the original authenticated v1 preparation")
				}
				plan, record := readLegacyBulkCommit(t, f, original.CommandID)
				if originalPlan == nil {
					originalPlan, originalAudit = plan, record
				} else if !bytes.Equal(plan, originalPlan) || !bytes.Equal(record, originalAudit) {
					t.Fatal("upgraded replay rewrote the original committed plan or audit")
				}
				requireLegacyBulkAllocations(t, f, original.CommandID, allocations)
				requireNativeBulkCounts(t, f, [5]int{1, 2, 1, 1, 1})
			}
		})
	}
}

func TestNativeBulkAdmissionRejectsAuthenticatedUnknownPreparation(t *testing.T) {
	f, service := bulkAdmissionFixture(t, scim.DefaultBulkResponsePolicy())
	request := BulkAdmissionRequest{Credential: f.bearer, Body: []byte(cyclicGroupBulkFixture)}
	_, binding, _, _ := retainBulkUpgradePreparation(t, f, service, request, 3)
	parent := binding.Admission.CommandID
	commitment, preparation := readLegacyBulkPreparation(t, f, parent)

	admitted, err := service.Admit(f.ctx, request)
	if protocolStatus(err) != 503 || admitted != (BulkAdmission{}) {
		t.Fatal("unknown authenticated preparation must fail closed", err)
	}
	requireNativeBulkCounts(t, f, [5]int{})
	var commands int
	if err := f.pool.Raw().QueryRow(f.ctx, `SELECT count(*) FROM identity.commands WHERE purpose=$1`, string(scim.Bulk)).Scan(&commands); err != nil || commands != 0 {
		t.Fatal("unknown preparation reached command reservation", commands, err)
	}
	identityAfter, preparationAfter := readLegacyBulkPreparation(t, f, parent)
	if !bytes.Equal(identityAfter, commitment) || !bytes.Equal(preparationAfter, preparation) {
		t.Fatal("unknown preparation was overwritten")
	}
}

func retainBulkUpgradePreparation(t *testing.T, f *nativeFixture, service *GroupBulkService, request BulkAdmissionRequest, schema uint8) (*nativePhase, kernel.RequestKeyPreparationBinding, []byte, []identity.FeatureField) {
	t.Helper()
	i := new(invocation)
	ctx := context.WithValue(f.ctx, invocationKey{}, i)
	bridge := protocolBridge{service: service.native, groups: true}
	if _, err := bridge.Authenticate(ctx, request.Credential); err != nil {
		t.Fatal("authenticate original native Bulk request", err)
	}
	c := service.native.config()
	if err := service.native.decide(ctx, string(scim.Bulk), c.Scope.ConnectionID, "identity.scim.bulk"); err != nil {
		t.Fatal("authorize original native Bulk request", err)
	}
	graph, err := scim.ParseBulk(request.Body, nil, service.request, c.Limits)
	if err != nil {
		t.Fatal("parse original native Bulk graph", err)
	}
	response, err := scim.PreflightBulkResponse(graph, c.BaseURL, service.response)
	if err != nil {
		t.Fatal("bound original native Bulk response", err)
	}
	p := &nativePhase{service: service.native, admission: *i, bulk: &bulkAdmissionPhase{
		children: graph.Operations(), components: graph.Components(), cutoff: graph.FailOnErrors(), maximum: response.MaximumBytes(), profile: service.profile,
	}}
	canonical := graph.CanonicalRequest()
	defer clear(canonical)
	intent, err := service.native.requestIntent(canonical, p.operation().OperationID)
	if err != nil {
		t.Fatal("build original native Bulk intent", err)
	}
	fields, ok := intent.Fields()
	if !ok {
		t.Fatal("original Bulk intent has no canonical fields")
	}
	fields = append(fields, identity.FeatureField{Name: "scim.bulk.profile", Value: identity.FeatureValue{Kind: identity.FeatureBytes, Bytes: p.bulk.profile[:]}})
	intent, err = identity.NewRequestIntent(fields)
	if err != nil {
		t.Fatal("bind original native Bulk profile", err)
	}
	digest := sha256.Sum256(canonical)
	selector, err := kernel.NewCanonicalRequestKey(append([]byte("scim-native-bulk-selector-v1\x00"), digest[:]...))
	if err != nil {
		t.Fatal("build original native Bulk selector", err)
	}
	audits, err := auditpg.NewIdentityContributor(auditpg.Config{})
	if err != nil {
		t.Fatal(err)
	}
	outbox, err := lifecyclepg.NewContributor()
	if err != nil {
		t.Fatal(err)
	}
	owner := &bulkUpgradePreparationOwner{nativePhase: p, schema: schema}
	registry, err := kernel.NewContributorRegistry([]kernel.Contributor{service.native.directory, audits, outbox, owner})
	if err != nil {
		t.Fatal("register exact legacy preparation owner", err)
	}
	coordinator, err := kernel.NewCoordinatorWithCanonicalSCIMBulkRequestKeys(f.pool, registry, c.Coordinator, service.native.requestKeys(p))
	if err != nil {
		t.Fatal("construct actual legacy preparation coordinator", err)
	}
	scope := kernel.RequestKeyScope{TenantID: c.Scope.TenantID, ActorID: c.ActorID, ActorKind: authorization.SubjectServiceAccount, Method: "POST", RouteID: p.operation().OperationID}
	caller := service.native.caller(scope.RouteID, scope.RouteID, "identity.request-admission")
	binding, wire, err := coordinator.ResolvePreparedCanonicalRequest(ctx, scope, selector, request.IdempotencyKey, intent, caller, p.registration(), owner)
	if err != nil {
		t.Fatal("retain authentic sealed canonical preparation", err)
	}
	t.Cleanup(func() { clear(wire) })
	p.coordinator, p.registry, err = service.native.coordinator(p)
	if err != nil {
		t.Fatal("restore exact native execution owner", err)
	}
	return p, binding, wire, fields
}

func readLegacyBulkPreparation(t *testing.T, f *nativeFixture, parent identity.CommandID) ([]byte, []byte) {
	t.Helper()
	var commitment, ciphertext []byte
	err := f.pool.Raw().QueryRow(f.ctx, `SELECT request_preparation_identity,request_preparation_ciphertext
 FROM identity.request_key_mappings WHERE command_id=decode(translate($1,'-_','+/')||'==','base64') AND route_id=$2`, string(parent), string(scim.Bulk)).Scan(&commitment, &ciphertext)
	if err != nil || len(commitment) != 32 || len(ciphertext) == 0 {
		t.Fatal("original authenticated preparation custody is absent", err)
	}
	return commitment, ciphertext
}

func readLegacyBulkCommit(t *testing.T, f *nativeFixture, parent identity.CommandID) ([]byte, []byte) {
	t.Helper()
	var plan, wire []byte
	err := f.pool.Raw().QueryRow(f.ctx, `SELECT c.command_plan,r.canonical_record
 FROM identity.commands c JOIN audit.identity_command_bindings b USING(command_id)
 JOIN audit.records r ON r.record_id=b.event_id
 WHERE c.command_id=decode(translate($1,'-_','+/')||'==','base64') AND c.purpose=$2 AND c.state='committed'`, string(parent), string(scim.Bulk)).Scan(&plan, &wire)
	if err != nil || len(plan) == 0 || len(wire) == 0 {
		t.Fatal("original committed v1 plan or bound audit is absent", err)
	}
	record, err := audit.ParseCanonicalJSON(wire, audit.DefaultLimits())
	if err != nil || record.Action() != "identity.scim.bulk" || record.Outcome() != audit.OutcomeSucceeded || record.Subject().Type() != "scim_bulk" ||
		record.Subject().ID() != string(parent) || record.Context().CorrelationID() != string(parent) || record.Attributes()["retention.class"] != "protected" {
		t.Fatal("upgraded replay reclassified the original v1 parent audit", err)
	}
	var total, upgraded int
	err = f.pool.Raw().QueryRow(f.ctx, `SELECT count(*),count(*) FILTER (WHERE action='identity.scim.bulk_admit') FROM audit.records WHERE correlation_id=$1`, string(parent)).Scan(&total, &upgraded)
	if err != nil || total != 1 || upgraded != 0 {
		t.Fatal("upgraded replay duplicated or replaced the original v1 parent audit", total, upgraded, err)
	}
	return plan, wire
}

func requireLegacyBulkAllocations(t *testing.T, f *nativeFixture, parent identity.CommandID, want []bulkAllocation) {
	t.Helper()
	rows, err := f.pool.Raw().Query(f.ctx, `SELECT ordinal,command_id,resource_id FROM scim.bulk_children WHERE parent_id=$1 ORDER BY ordinal`, string(parent))
	if err != nil {
		t.Fatal("read upgraded parent child allocations", err)
	}
	defer rows.Close()
	var got []bulkAllocation
	for rows.Next() {
		var ordinal int
		var allocated bulkAllocation
		if err := rows.Scan(&ordinal, &allocated.Command, &allocated.Resource); err != nil || ordinal != len(got) {
			t.Fatal("upgraded replay changed original child ordering", err)
		}
		got = append(got, allocated)
	}
	if rows.Err() != nil || !slices.Equal(got, want) {
		t.Fatal("upgraded replay changed original child command or resource allocation", rows.Err())
	}
}
