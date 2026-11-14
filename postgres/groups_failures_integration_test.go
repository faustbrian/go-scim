//go:build integration

package scimpostgres

import (
	"bytes"
	"context"
	"os"
	"sync/atomic"
	"testing"
	"time"

	"github.com/faustbrian/go-audit"
	database "github.com/faustbrian/go-postgres"
	scim "github.com/faustbrian/go-scim"
	"github.com/jackc/pgx/v5/pgconn"
)

func groupsOnPool(t *testing.T, f *nativeFixture, pool *database.Pool) *GroupsService {
	t.Helper()
	base, err := NewService(pool, f.config, f.keys)
	if err != nil {
		t.Fatal(err)
	}
	groups, err := NewGroupsService(base, scim.DefaultGroupMembers)
	if err != nil {
		t.Fatal(err)
	}
	return groups
}

func TestNativeGroupsRequiredOwnerFailuresRollBackProjection(t *testing.T) {
	for _, table := range []string{"audit.records", "public.outbox_messages"} {
		for _, operation := range []scim.Operation{scim.GroupCreate, scim.GroupReplace, scim.GroupPatch, scim.GroupDelete} {
			t.Run(table+"/"+string(operation), func(t *testing.T) {
				f, groups := nativeGroupsFixture(t)
				seed, err := groups.Execute(f.ctx, groupRequest(f, scim.GroupCreate, "", "", "seed", `{"schemas":["urn:ietf:params:scim:schemas:core:2.0:Group"],"displayName":"Before"}`))
				if err != nil {
					t.Fatal(err)
				}
				id := groupID(t, seed)
				state := func() string {
					t.Helper()
					var snapshot string
					if err := f.pool.Raw().QueryRow(f.ctx, `SELECT jsonb_build_object(
 'projections',(SELECT jsonb_agg(to_jsonb(g) ORDER BY resource_id) FROM scim.groups g),
 'users',(SELECT count(*) FROM identity.users),
 'committed',(SELECT count(*) FROM identity.commands WHERE state='committed'),
 'audits',(SELECT count(*) FROM audit.records WHERE outcome=$1),
 'outbox',(SELECT count(*) FROM public.outbox_messages))::text`, int16(audit.OutcomeSucceeded)).Scan(&snapshot); err != nil {
						t.Fatal(err)
					}
					return snapshot
				}
				before := state()
				reached := new(atomic.Bool)
				pool, err := database.Connect(f.ctx, database.Config{DSN: os.Getenv("SCIM_POSTGRES_TEST_DSN"), MaxConns: 3, Configure: func(c *database.PoolConfig) error {
					c.ConnConfig.Database = f.pool.Raw().Config().ConnConfig.Database
					c.ConnConfig.RuntimeParams["client_min_messages"] = "notice"
					c.ConnConfig.OnNotice = func(_ *pgconn.PgConn, notice *pgconn.Notice) {
						if notice.Code == "PZ001" {
							reached.Store(true)
						}
					}
					return nil
				}})
				if err != nil {
					t.Fatal(err)
				}
				defer func() {
					ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
					defer cancel()
					if err := pool.Close(ctx); err != nil {
						t.Error("owned Group failure pool cleanup", err)
					}
				}()
				failing := groupsOnPool(t, f, pool)
				if _, err := f.pool.Raw().Exec(f.ctx, `CREATE FUNCTION public.scim_group_fixture_failure() RETURNS trigger LANGUAGE plpgsql AS $f$ BEGIN RAISE NOTICE USING ERRCODE='PZ001',MESSAGE='owned failure reached'; RAISE EXCEPTION 'fixture failure'; END $f$; CREATE TRIGGER scim_group_fixture_failure BEFORE INSERT ON `+table+` FOR EACH ROW EXECUTE FUNCTION public.scim_group_fixture_failure()`); err != nil {
					t.Fatal(err)
				}
				request := groupRequest(f, operation, id, seed.ETag, "must-rollback", "")
				switch operation {
				case scim.GroupCreate:
					request.ResourceID, request.IfMatch = "", ""
					fallthrough
				case scim.GroupReplace:
					request.Body = []byte(`{"schemas":["urn:ietf:params:scim:schemas:core:2.0:Group"],"displayName":"Not durable"}`)
				case scim.GroupPatch:
					request.Body = []byte(`{"schemas":["urn:ietf:params:scim:api:messages:2.0:PatchOp"],"Operations":[{"op":"replace","path":"displayName","value":"Not durable"}]}`)
				}
				if response, err := failing.Execute(f.ctx, request); err == nil || len(response.Body) != 0 || !reached.Load() {
					t.Fatal("actual required owner failure was not reached or returned a resource", reached.Load(), err)
				}
				if after := state(); after != before {
					t.Fatal("required owner failure leaked Group metadata/projection/journal/audit/outbox or foreign effects")
				}
				if response, err := groups.Execute(f.ctx, groupRequest(f, scim.GroupGet, id, "", "", "")); err != nil || response.ETag != seed.ETag || !bytes.Equal(response.Body, seed.Body) {
					t.Fatal("failed write changed public Group", err)
				}
			})
		}
	}
}

func TestNativeGroupsLostCommitReplaysOnlyOriginalOwnedEffects(t *testing.T) {
	for _, operation := range []scim.Operation{scim.GroupCreate, scim.GroupReplace, scim.GroupPatch, scim.GroupDelete} {
		t.Run(string(operation), func(t *testing.T) {
			f, groups := nativeGroupsFixture(t)
			request := groupRequest(f, operation, "", "", "lost-group-commit", `{"schemas":["urn:ietf:params:scim:schemas:core:2.0:Group"],"displayName":"After lost acknowledgement"}`)
			if operation != scim.GroupCreate {
				seed, err := groups.Execute(f.ctx, groupRequest(f, scim.GroupCreate, "", "", "seed", `{"schemas":["urn:ietf:params:scim:schemas:core:2.0:Group"],"displayName":"Before"}`))
				if err != nil {
					t.Fatal(err)
				}
				request.ResourceID, request.IfMatch = groupID(t, seed), seed.ETag
			}
			if operation == scim.GroupPatch {
				request.Body = []byte(`{"schemas":["urn:ietf:params:scim:api:messages:2.0:PatchOp"],"Operations":[{"op":"replace","path":"displayName","value":"After lost acknowledgement"}]}`)
			} else if operation == scim.GroupDelete {
				request.Body, request.IdempotencyKey = nil, ""
			}
			fault := new(nativeCommitFault)
			pool, err := database.Connect(f.ctx, database.Config{DSN: os.Getenv("SCIM_POSTGRES_TEST_DSN"), MaxConns: 3, Configure: func(c *database.PoolConfig) error {
				c.ConnConfig.Database = f.pool.Raw().Config().ConnConfig.Database
				c.ConnConfig.DialFunc = fault.dial
				return nil
			}})
			if err != nil {
				t.Fatal(err)
			}
			defer func() {
				ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
				defer cancel()
				if err := pool.Close(ctx); err != nil {
					t.Error("owned lost Group COMMIT pool cleanup", err)
				}
			}()
			uncertain := groupsOnPool(t, f, pool)
			if response, err := uncertain.Execute(f.ctx, request); protocolStatus(err) != 503 || len(response.Body) != 0 || !fault.hit.Load() {
				t.Fatal("actual Group domain COMMIT acknowledgement was not lost", fault.hit.Load(), err)
			}
			original, err := groups.Execute(f.ctx, request)
			if err != nil {
				t.Fatal("original Group committed result not recovered", err)
			}
			if operation == scim.GroupDelete {
				if original.Status != 204 || len(original.Body) != 0 || original.ETag != "" {
					t.Fatal("ambiguous Group delete resurrected values")
				}
			} else if groupID(t, original) == "" {
				t.Fatal("recovered Group has no stable identity")
			}
			if replayed, err := groups.Execute(f.ctx, request); err != nil || replayed.Status != original.Status || replayed.ETag != original.ETag || !bytes.Equal(replayed.Body, original.Body) {
				t.Fatal("retry changed original Group response", err)
			}
			var commands, audits, events, users int
			if err := f.pool.Raw().QueryRow(f.ctx, `SELECT
 (SELECT count(*) FROM identity.commands WHERE purpose=$1 AND state='committed'),
 (SELECT count(*) FROM audit.identity_command_bindings a JOIN identity.commands c USING(command_id) WHERE c.purpose=$1 AND c.state='committed'),
 (SELECT count(*) FROM public.identity_outbox_bindings o JOIN identity.commands c USING(command_id) WHERE c.purpose=$1 AND c.state='committed'),
 (SELECT count(*) FROM identity.users)`, string(operation)).Scan(&commands, &audits, &events, &users); err != nil || commands != 1 || audits != 1 || events != 1 || users != 0 {
				t.Fatal("ambiguous Group retry duplicated or skipped actual owned effects", commands, audits, events, users, err)
			}
		})
	}
}

func TestNativeGroupsPendingRecoveryUsesExactOriginalProjection(t *testing.T) {
	for _, mode := range []string{"noop", "advancing", "overwritten"} {
		t.Run(mode, func(t *testing.T) {
			f, groups := nativeGroupsFixture(t)
			seed, err := groups.Execute(f.ctx, groupRequest(f, scim.GroupCreate, "", "", "seed", `{"schemas":["urn:ietf:params:scim:schemas:core:2.0:Group"],"displayName":"Before"}`))
			if err != nil {
				t.Fatal(err)
			}
			id := groupID(t, seed)
			name := "After"
			if mode == "noop" {
				name = "Before"
			}
			request := groupRequest(f, scim.GroupPatch, id, seed.ETag, "pending-original", `{"schemas":["urn:ietf:params:scim:api:messages:2.0:PatchOp"],"Operations":[{"op":"replace","path":"displayName","value":"`+name+`"}]}`)
			fault := &nativeCommitFault{reservation: true}
			pool, err := database.Connect(f.ctx, database.Config{DSN: os.Getenv("SCIM_POSTGRES_TEST_DSN"), MaxConns: 3, Configure: func(c *database.PoolConfig) error {
				c.ConnConfig.Database = f.pool.Raw().Config().ConnConfig.Database
				c.ConnConfig.DialFunc = fault.dial
				return nil
			}})
			if err != nil {
				t.Fatal(err)
			}
			defer func() {
				ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
				defer cancel()
				if err := pool.Close(ctx); err != nil {
					t.Error("pending Group pool cleanup", err)
				}
			}()
			f.config.Coordinator.LeaseDuration = 100 * time.Millisecond
			uncertain := groupsOnPool(t, f, pool)
			if response, err := uncertain.Execute(f.ctx, request); protocolStatus(err) != 503 || len(response.Body) != 0 || !fault.hit.Load() {
				t.Fatal("actual pending Group reservation COMMIT acknowledgement was not lost", err)
			}
			var original string
			if err := f.pool.Raw().QueryRow(f.ctx, `SELECT encode(command_id,'hex') FROM identity.commands WHERE purpose=$1 AND state='pending'`, string(scim.GroupPatch)).Scan(&original); err != nil {
				t.Fatal("original pending command absent", err)
			}
			var winnerResult scim.Response
			if mode == "overwritten" {
				winner := groupRequest(f, scim.GroupReplace, id, seed.ETag, "winner", `{"schemas":["urn:ietf:params:scim:schemas:core:2.0:Group"],"displayName":"Winner"}`)
				winnerResult, err = groups.Execute(f.ctx, winner)
				if err != nil {
					t.Fatal("genuine advancing competitor", err)
				}
			}
			timer := time.NewTimer(150 * time.Millisecond)
			defer timer.Stop()
			select {
			case <-timer.C:
			case <-f.ctx.Done():
				t.Fatal("pending Group lease wait cancelled")
			}
			healthy := groupsOnPool(t, f, f.pool)
			response, err := healthy.Execute(f.ctx, request)
			if mode == "overwritten" {
				if protocolStatus(err) != 503 || len(response.Body) != 0 {
					t.Fatal("lost correlation/advanced projection became rollback proof", err)
				}
				if current, err := groups.Execute(f.ctx, groupRequest(f, scim.GroupGet, id, "", "", "")); err != nil || current.ETag != winnerResult.ETag || !bytes.Equal(current.Body, winnerResult.Body) {
					t.Fatal("uncertain original overwrote the actual winning Group", err)
				}
				return
			}
			if err != nil || response.Status != 200 || mode == "noop" && (response.ETag != seed.ETag || !bytes.Equal(response.Body, seed.Body)) || mode == "advancing" && response.ETag == seed.ETag {
				t.Fatal("unchanged original projection/no-write declaration could not finish", err)
			}
			var retained string
			var commands, audits, events, generation, users int
			if err := f.pool.Raw().QueryRow(f.ctx, `SELECT
 (SELECT encode(command_id,'hex') FROM identity.commands WHERE purpose=$1 AND state='committed'),
 (SELECT count(*) FROM identity.commands WHERE purpose=$1),
 (SELECT count(*) FROM audit.identity_command_bindings a JOIN identity.commands c USING(command_id) WHERE c.purpose=$1 AND c.state='committed'),
 (SELECT count(*) FROM public.identity_outbox_bindings o JOIN identity.commands c USING(command_id) WHERE c.purpose=$1 AND c.state='committed'),
 (SELECT generation FROM scim.groups WHERE resource_id=$2),
 (SELECT count(*) FROM identity.users)`, string(scim.GroupPatch), id).Scan(&retained, &commands, &audits, &events, &generation, &users); err != nil || retained != original || commands != 1 || audits != 1 || events != 1 || users != 0 || mode == "noop" && generation != 1 || mode == "advancing" && generation != 2 {
				t.Fatal("pending recovery changed original custody, projection generation or atomic effects", commands, audits, events, generation, users, err)
			}
		})
	}
}
