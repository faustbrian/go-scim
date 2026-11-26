//go:build integration

package scimpostgres

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"testing"

	identity "github.com/faustbrian/go-identity"
	database "github.com/faustbrian/go-postgres"
	scim "github.com/faustbrian/go-scim"
)

func TestNativeBulkExecuteWithholdsUnknownAndRecoversOriginal(t *testing.T) {
	f, fixture := bulkChildExecutionFixture(t)
	mixed := &BulkService{graph: fixture}
	type executor interface {
		ExecuteBulk(context.Context, BulkAdmissionRequest) ([]byte, error)
	}
	run, ok := any(mixed).(executor)
	if !ok {
		t.Fatal("native Bulk cannot execute an admitted graph in one call")
	}
	request := BulkAdmissionRequest{Credential: f.bearer, Body: []byte(dependentGroupBulkFixture)}
	parent, err := mixed.Admit(f.ctx, request)
	if err != nil {
		t.Fatal("admit the original dependency graph", err)
	}
	first := originalBulkChild(t, f, parent, 0)
	second := originalBulkChild(t, f, parent, 1)
	fault := new(nativeCommitFault)
	uncertain := &BulkService{graph: bulkOnFixturePool(t, f, func(c *database.PoolConfig) { c.ConnConfig.DialFunc = fault.dial })}
	if wire, err := any(uncertain).(executor).ExecuteBulk(f.ctx, request); len(wire) != 0 || protocolStatus(err) != 503 || !fault.hit.Load() {
		t.Fatal("lost child acknowledgement must not disclose terminal success", len(wire), fault.hit.Load(), err)
	}
	if wire, err := mixed.ReadResult(f.ctx, request); len(wire) != 0 || !errors.Is(err, scim.ErrBulkIncomplete) {
		t.Fatal("a dependent child must not execute after the original attempt became uncertain", len(wire), err)
	}
	var projectionCount int
	if err := f.pool.Raw().QueryRow(f.ctx, `SELECT count(*) FROM scim.groups`).Scan(&projectionCount); err != nil || projectionCount != 1 {
		t.Fatal("only the first Group committed before acknowledgement was lost", projectionCount, err)
	}
	wire, err := run.ExecuteBulk(f.ctx, request)
	if err != nil || bytes.Count(wire, []byte(`"status":"201"`)) != 2 {
		t.Fatal("exact retry must recover both original Group results", err)
	}
	for ordinal, original := range []admittedBulkChild{first, second} {
		result, err := mixed.ExecuteChild(f.ctx, request, ordinal)
		if err != nil {
			t.Fatal("recover an original child", ordinal, err)
		}
		requireCommittedBulkChild(t, f, parent, ordinal, original, result)
	}
	if replay, err := run.ExecuteBulk(f.ctx, request); err != nil || !bytes.Equal(replay, wire) {
		t.Fatal("terminal retry must emit the original ordered bytes", err)
	}
}

func TestNativeBulkExecuteRetainsCutoffAndRejectsChangedRetry(t *testing.T) {
	f, service, runner := nativeBulkExecutionFixture(t)
	key, err := identity.NewIdempotencyKey([]byte("bulk-runner-cutoff-example"))
	if err != nil {
		t.Fatal(err)
	}
	request := BulkAdmissionRequest{Credential: f.bearer, IdempotencyKey: &key,
		Body: []byte(strings.Replace(failedThenIndependentGroupBulk, `"failOnErrors":0`, `"failOnErrors":1`, 1))}
	wire, err := runner.ExecuteBulk(f.ctx, request)
	if err != nil || bytes.Count(wire, []byte(`"method":"POST"`)) != 1 ||
		!bytes.Contains(wire, []byte(`"bulkId":"missing-member","status":"400"`)) || bytes.Contains(wire, []byte("independent")) {
		t.Fatal("synchronous admission and execution must omit the skipped sibling from the original response", err)
	}
	parent, err := service.Admit(f.ctx, request)
	if err != nil {
		t.Fatal("recover the same admitted graph", err)
	}
	skipped, err := service.ExecuteChild(f.ctx, request, 1)
	if err != nil || skipped != (scim.BulkChildResult{Status: scim.BulkChildSkipped, SkipReason: scim.BulkSkipFailOnErrors}) {
		t.Fatal("cutoff must persist a skip rather than hiding an unprocessed result in transport", skipped, err)
	}
	changed := request
	changed.Body = []byte(failedThenIndependentGroupBulk)
	if disclosed, err := runner.ExecuteBulk(f.ctx, changed); len(disclosed) != 0 || protocolStatus(err) != 409 {
		t.Fatal("changed cutoff with the same key must not mutate or disclose the original response", len(disclosed), err)
	}
	var parentCount, groupCount, failed int
	if err := f.pool.Raw().QueryRow(f.ctx, `SELECT (SELECT count(*) FROM scim.bulk_requests), (SELECT count(*) FROM scim.groups), failed_count FROM scim.bulk_requests WHERE parent_id=$1`, string(parent.CommandID)).Scan(&parentCount, &groupCount, &failed); err != nil || parentCount != 1 || groupCount != 0 || failed != 1 {
		t.Fatal("changed retry or cutoff wrote another graph, Group, or child failure", parentCount, groupCount, failed, err)
	}
	if replay, err := runner.ExecuteBulk(f.ctx, request); err != nil || !bytes.Equal(replay, wire) {
		t.Fatal("exact keyed retry must replay the one processed child", err)
	}
}
