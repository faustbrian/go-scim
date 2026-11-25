//go:build integration

package scimpostgres

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"slices"
	"strconv"
	"strings"
	"testing"

	"github.com/faustbrian/go-audit"
	scim "github.com/faustbrian/go-scim"
)

func TestNativeBulkAdmissionAuditProfileNewParentAndReconstructedRetry(t *testing.T) {
	f, service := bulkAdmissionFixture(t, scim.DefaultBulkResponsePolicy())
	const firstBulkID = "parent-audit-private-bulk-first"
	const secondBulkID = "parent-audit-private-bulk-second"
	const firstName = "Parent audit private resource first"
	const secondName = "Parent audit private resource second"
	const body = `{"schemas":["urn:ietf:params:scim:api:messages:2.0:BulkRequest"],"Operations":[` +
		`{"method":"POST","path":"/Groups","bulkId":"` + firstBulkID + `","data":{"displayName":"` + firstName + `"}},` +
		`{"method":"POST","path":"/Groups","bulkId":"` + secondBulkID + `","data":{"displayName":"` + secondName + `"}}]}`
	request := BulkAdmissionRequest{Credential: f.bearer, Body: []byte(body)}
	first, err := service.Admit(f.ctx, request)
	if err != nil || first.CommandID == "" || first.ChildCount != 2 || first.ResponseMaximumBytes <= 0 {
		t.Fatal("new parent did not admit both original children", err)
	}

	type allocation struct {
		command  string
		resource string
	}
	readAllocations := func() []allocation {
		t.Helper()
		rows, err := f.pool.Raw().Query(f.ctx, `SELECT ordinal,command_id,resource_id FROM scim.bulk_children WHERE parent_id=$1 ORDER BY ordinal`, string(first.CommandID))
		if err != nil {
			t.Fatal("read original child allocations", err)
		}
		defer rows.Close()
		var allocations []allocation
		for rows.Next() {
			var ordinal int
			var child allocation
			if err := rows.Scan(&ordinal, &child.command, &child.resource); err != nil {
				t.Fatal("read admitted child allocation", err)
			}
			if ordinal != len(allocations) || child.command == "" || child.resource == "" || child.command == string(first.CommandID) {
				t.Fatal("child lost its independent original allocation")
			}
			allocations = append(allocations, child)
		}
		if rows.Err() != nil || len(allocations) != 2 || allocations[0].command == allocations[1].command || allocations[0].resource == allocations[1].resource {
			t.Fatal("admission did not retain exactly two distinct child allocations", rows.Err())
		}
		return allocations
	}
	original := readAllocations()

	readAudit := func() []byte {
		t.Helper()
		var total, successfulAdmissions, legacySiblings int
		err := f.pool.Raw().QueryRow(f.ctx, `SELECT count(*),
 count(*) FILTER (WHERE action='identity.scim.bulk_admit' AND outcome=$2),
 count(*) FILTER (WHERE action='identity.scim.bulk')
 FROM audit.records WHERE correlation_id=$1`, string(first.CommandID), int16(audit.OutcomeSucceeded)).Scan(&total, &successfulAdmissions, &legacySiblings)
		if err != nil || total != 1 || successfulAdmissions != 1 || legacySiblings != 0 {
			t.Fatal("parent must have one successful bulk_admit event and no legacy sibling", total, successfulAdmissions, legacySiblings, err)
		}
		var wire []byte
		err = f.pool.Raw().QueryRow(f.ctx, `SELECT r.canonical_record
 FROM audit.identity_command_bindings b JOIN audit.records r ON r.record_id=b.event_id
 WHERE b.command_id=decode(translate($1,'-_','+/')||'==','base64')`, string(first.CommandID)).Scan(&wire)
		if err != nil || len(wire) == 0 || len(wire) > 16384 {
			t.Fatal("parent audit is missing, unbound or exceeds the security record bound", err)
		}
		record, err := audit.ParseCanonicalJSON(wire, audit.DefaultLimits())
		if err != nil {
			t.Fatal("parent audit is not a canonical record", err)
		}
		if record.Action() != "identity.scim.bulk_admit" || record.Outcome() != audit.OutcomeSucceeded || record.ReasonCode() != "completed" ||
			record.Subject().Type() != "scim_bulk" || record.Subject().ID() != string(first.CommandID) || record.Context().CorrelationID() != string(first.CommandID) {
			t.Fatal("parent audit lost the admission action, outcome or original command scope")
		}
		changes := record.Changes()
		// The pre-persistence redaction marker is not part of canonical JSON.
		context := record.Context()
		if record.Description() != "" || !changes.Redacted() || len(changes.Before()) != 0 || len(changes.After()) != 0 ||
			context.NetworkOrigin() != "" || context.UserAgent() != "" || context.RequestID() != "" || context.TraceID() != "" || context.IdempotencyID() != "" {
			t.Fatal("parent audit retained resource, response or caller detail")
		}
		attributes := record.Attributes()
		if attributes["command.id"] != string(first.CommandID) || attributes["aggregate.id"] != string(first.CommandID) || attributes["aggregate.type"] != "scim_bulk" || attributes["identity.profile"] != "identity.security.v1" || attributes["retention.class"] != "protected" {
			t.Fatal("parent audit metadata is not bound to the original parent")
		}
		for key, value := range attributes {
			switch key {
			case "command.id", "aggregate.id", "aggregate.type", "identity.profile", "retention.class":
			case "aggregate.before_version", "aggregate.after_version":
				version, err := strconv.ParseUint(value, 10, 64)
				if err != nil || strconv.FormatUint(version, 10) != value {
					t.Fatal("parent audit retained an unbounded aggregate version")
				}
			default:
				t.Fatal("parent audit retained metadata outside the bounded admission profile")
			}
		}
		for _, forbidden := range []string{firstBulkID, secondBulkID, firstName, secondName, "/Groups", "displayName", "BulkRequest", original[0].resource, original[1].resource} {
			if strings.Contains(string(wire), forbidden) {
				t.Fatal("parent audit disclosed a bulk ID, path or resource payload")
			}
		}
		for _, bulkID := range []string{firstBulkID, secondBulkID} {
			digest := sha256.Sum256([]byte(bulkID))
			for _, encoded := range []string{hex.EncodeToString(digest[:]), base64.StdEncoding.EncodeToString(digest[:]), base64.RawURLEncoding.EncodeToString(digest[:])} {
				if strings.Contains(string(wire), encoded) {
					t.Fatal("parent audit disclosed a digested bulk ID")
				}
			}
		}
		return wire
	}
	originalAudit := readAudit()

	reconstructed, err := NewGroupBulkService(groupsOnPool(t, f, f.pool), scim.DefaultBulkPolicy(), scim.DefaultBulkResponsePolicy())
	if err != nil {
		t.Fatal("reconstruct the native parent admission service", err)
	}
	if replayed, err := reconstructed.Admit(f.ctx, request); err != nil || replayed != first {
		t.Fatal("reconstructed exact retry changed the original parent admission", err)
	}
	if !slices.Equal(readAllocations(), original) {
		t.Fatal("reconstructed exact retry changed original child command or resource IDs")
	}
	if !bytes.Equal(readAudit(), originalAudit) {
		t.Fatal("reconstructed exact retry rewrote or replaced the original parent audit")
	}
	requireNativeBulkCounts(t, f, [5]int{1, 2, 1, 1, 1})
}
