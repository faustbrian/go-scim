//go:build integration

package scimpostgres

import (
	"context"
	"sync"
	"testing"

	"github.com/faustbrian/go-authorization/v3"
	scim "github.com/faustbrian/go-scim"
)

func TestNativeGroupsLosingWriterRetainsExactPrecondition(t *testing.T) {
	f, groups := nativeGroupsFixture(t)
	seed, err := groups.Execute(f.ctx, groupRequest(f, scim.GroupCreate, "", "", "seed", `{"schemas":["urn:ietf:params:scim:schemas:core:2.0:Group"],"displayName":"Before writers"}`))
	if err != nil {
		t.Fatal(err)
	}
	id := groupID(t, seed)
	prepared, release, finished := make(chan struct{}), make(chan struct{}), make(chan struct{})
	var entered, unblocked sync.Once
	unblock := func() { unblocked.Do(func() { close(release) }) }
	defer unblock()
	c := f.config
	underlying := c.Authorization
	c.Authorization = configuredPolicy(func(ctx context.Context, decision authorization.DecisionContext) (authorization.Decision, error) {
		i, _ := currentInvocation(ctx)
		if decision.Request.Action == authorization.Action(scim.GroupPatch) && decision.Request.Resource.Type == "identity.scim.group" && i != nil && i.phase != nil {
			entered.Do(func() {
				close(prepared)
				select {
				case <-release:
				case <-ctx.Done():
				}
			})
		}
		return underlying.Decide(ctx, decision)
	})
	base, err := NewService(f.pool, c, f.keys)
	if err != nil {
		t.Fatal(err)
	}
	paused, err := NewGroupsService(base, scim.DefaultGroupMembers)
	if err != nil {
		t.Fatal(err)
	}
	loser := groupRequest(f, scim.GroupPatch, id, seed.ETag, "original-loser", `{"schemas":["urn:ietf:params:scim:api:messages:2.0:PatchOp"],"Operations":[{"op":"replace","path":"displayName","value":"Rejected loser"}]}`)
	result := make(chan executionResult, 1)
	go func() {
		defer close(finished)
		response, err := paused.Execute(f.ctx, loser)
		result <- executionResult{response, err}
	}()
	defer func() {
		unblock()
		select {
		case <-finished:
		case <-f.ctx.Done():
			t.Error("losing Group writer did not terminate")
		}
	}()
	select {
	case <-prepared:
	case got := <-result:
		t.Fatal("actual Group preparation not reached", got.err)
	case <-f.ctx.Done():
		t.Fatal("Group writer preparation did not arrive")
	}
	winner := loser
	winner.IdempotencyKey = "winning-writer"
	winner.Body = []byte(`{"schemas":["urn:ietf:params:scim:api:messages:2.0:PatchOp"],"Operations":[{"op":"replace","path":"displayName","value":"Winner"}]}`)
	committed, err := groups.Execute(f.ctx, winner)
	if err != nil || committed.ETag == seed.ETag {
		t.Fatal("actual winning Group writer did not commit", err)
	}
	unblock()
	select {
	case got := <-result:
		if protocolStatus(got.err) != 412 || len(got.response.Body) != 0 {
			t.Fatal("frozen losing Group writer did not retain precondition", got.err)
		}
	case <-f.ctx.Done():
		t.Fatal("losing Group writer did not finish")
	}
	if _, err := groups.Execute(f.ctx, groupRequest(f, scim.GroupDelete, id, committed.ETag, "", "")); err != nil {
		t.Fatal(err)
	}
	for range 2 {
		if response, err := groups.Execute(f.ctx, loser); protocolStatus(err) != 412 || len(response.Body) != 0 {
			t.Fatal("target deletion changed retained losing-writer denial", err)
		}
	}
	var committedPatches, abortedPatches, events int
	if err := f.pool.Raw().QueryRow(f.ctx, `SELECT
 (SELECT count(*) FROM identity.commands WHERE purpose=$1 AND state='committed'),
 (SELECT count(*) FROM identity.commands WHERE purpose=$1 AND state='aborted'),
 (SELECT count(*) FROM public.identity_outbox_bindings o JOIN identity.commands c USING(command_id) WHERE c.purpose=$1)`, string(scim.GroupPatch)).Scan(&committedPatches, &abortedPatches, &events); err != nil || committedPatches != 1 || abortedPatches != 1 || events != 1 {
		t.Fatal("losing Group writer duplicated/omitted actual owners", committedPatches, abortedPatches, events, err)
	}
}
