//go:build integration

package scimpostgres

import (
	"context"
	"testing"
	"time"

	"github.com/faustbrian/go-audit"
	identity "github.com/faustbrian/go-identity"
	kernel "github.com/faustbrian/go-identity/postgres"
	scim "github.com/faustbrian/go-scim"
)

type directoryGroupEdgeExpiryOwner struct {
	directoryGroupEdgeWorkOwner
	deadline time.Time
}

func (p *directoryGroupEdgeExpiryOwner) ApplyFeature(ctx context.Context, w kernel.Work, command identity.Command) (identity.FeatureReceipt, error) {
	p.applyCalls++
	if err := p.groups.RequireDirectoryGroupEdge(ctx, w, p, command, p.observation, p.edge); err != nil {
		return identity.FeatureReceipt{}, err
	}
	spec, _ := command.Feature()
	if _, err := w.Exec(ctx, `INSERT INTO public.directory_source_test_effects(command_id) VALUES($1)`, string(spec.Binding.CommandID)); err != nil {
		return identity.FeatureReceipt{}, err
	}
	return identity.FeatureReceipt{Operation: p.FeatureOperations()[0], BeforeVersion: 0, AfterVersion: 1}, nil
}

func (p *directoryGroupEdgeExpiryOwner) CheckFeatureCommit(ctx context.Context, w kernel.Work, command identity.Command) error {
	p.finalCalls++
	if command != p.command {
		return identity.ForbiddenError{}
	}
	// Only this final invocation enables the owned view's bounded read delay.
	// No source fact, domain row or authority is changed by this fault injection.
	rows, err := w.Query(ctx, `SELECT set_config('scim.test_final_read_until',$1,true)`, p.deadline.Format(time.RFC3339Nano))
	if err != nil {
		return err
	}
	for rows.Next() {
		var setting string
		if err := rows.Scan(&setting); err != nil {
			rows.Close()
			return err
		}
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return err
	}
	return p.groups.RequireDirectoryGroupEdgeAtCommit(ctx, w, p, command, p.observation, p.edge)
}

func TestDirectoryGroupEdgeFinalReadCannotOutliveOriginalSource(t *testing.T) {
	f, groups := nativeGroupsFixture(t)
	user := createNativeNamed(t, f, "FinalExpiryUser", "Exact member")
	created, err := groups.Execute(f.ctx, groupRequest(f, scim.GroupCreate, "", "", "final-expiry-group", `{"schemas":["urn:ietf:params:scim:schemas:core:2.0:Group"],"displayName":"Expiry group","members":[{"value":"`+user+`","type":"User"}]}`))
	if err != nil {
		t.Fatal(err)
	}
	group := groupID(t, created)
	if _, err := f.pool.Raw().Exec(f.ctx, `ALTER TABLE scim.groups RENAME TO directory_edge_expiry_groups;
 CREATE FUNCTION scim.directory_edge_test_delay(value bytea) RETURNS bytea LANGUAGE plpgsql VOLATILE AS $$
 DECLARE deadline text;
 BEGIN
  deadline := current_setting('scim.test_final_read_until',true);
  IF deadline IS NOT NULL AND deadline<>'' THEN
   PERFORM pg_sleep(LEAST(2.5,GREATEST(0,extract(epoch FROM (deadline::timestamptz-clock_timestamp())))+0.05));
  END IF;
  RETURN value;
 END $$;
 CREATE VIEW scim.groups AS SELECT tenant_id,organization_id,provider_id,connection_id,resource_id,
 scim.directory_edge_test_delay(resource) AS resource,generation,deleted_at,command_id,effect_digest
 FROM scim.directory_edge_expiry_groups`); err != nil {
		t.Fatal("install harmless owned final-read delay", err)
	}
	observation, err := groups.ObserveDirectorySource(f.ctx, f.config.Scope)
	if err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().UTC().Add(2 * time.Second)
	observation.admission.connection.AuthorityValidUntil = deadline
	sourceField, err := observation.Field()
	if err != nil {
		t.Fatal(err)
	}
	edge := DirectoryGroupEdge{GroupID: group, UserID: user, Present: true}
	edgeField, err := edge.Field()
	if err != nil {
		t.Fatal(err)
	}
	owner := &directoryGroupEdgeExpiryOwner{directoryGroupEdgeWorkOwner: directoryGroupEdgeWorkOwner{directorySourceWorkOwner: directorySourceWorkOwner{groups: groups, observation: observation}, edge: edge}, deadline: deadline}
	coordinator, registry := directorySourceWorkCoordinator(t, f, owner)
	command, plan := directoryGroupEdgeWorkCommand(t, f, coordinator, registry, &owner.directoryGroupEdgeWorkOwner, user, []identity.FeatureField{sourceField, edgeField})
	var eventsBefore int
	if err := f.pool.Raw().QueryRow(f.ctx, `SELECT count(*) FROM public.outbox_messages`).Scan(&eventsBefore); err != nil {
		t.Fatal(err)
	}
	result, err := executeDirectorySourceWork(f.ctx, coordinator, command, plan)
	if owner.applyCalls != 1 || owner.finalCalls != 1 {
		t.Fatal("expiry must be crossed inside the actual final lookup, not before Apply", owner.applyCalls, owner.finalCalls, err)
	}
	if err == nil || result.Outcome == identity.CommitOutcomeCommitted {
		t.Fatal("edge committed after original source freshness expired inside its final lookup", result.Outcome, err)
	}
	spec, _ := command.Feature()
	var effects, eventsAfter, successAudits, committed int
	var expired bool
	if err := f.pool.Raw().QueryRow(f.ctx, `SELECT
 (SELECT count(*) FROM public.directory_source_test_effects),
 (SELECT count(*) FROM public.outbox_messages),
 (SELECT count(*) FROM audit.identity_command_bindings b JOIN audit.records r ON r.record_id=b.event_id WHERE b.command_id=decode(translate($1,'-_','+/')||'==','base64') AND r.outcome=$3),
 (SELECT count(*) FROM identity.commands WHERE command_id=decode(translate($1,'-_','+/')||'==','base64') AND state='committed'),
 clock_timestamp()>$2`, string(spec.Binding.CommandID), deadline, int16(audit.OutcomeSucceeded)).Scan(&effects, &eventsAfter, &successAudits, &committed, &expired); err != nil {
		t.Fatal(err)
	}
	if effects != 0 || eventsAfter != eventsBefore || successAudits != 0 || committed != 0 || !expired {
		t.Fatal("final expiry escaped rollback or did not cross original deadline", effects, eventsAfter-eventsBefore, successAudits, committed, expired)
	}
}
