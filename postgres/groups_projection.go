package scimpostgres

import (
	"context"
	"encoding/json"
	"errors"

	identity "github.com/faustbrian/go-identity"
	kernel "github.com/faustbrian/go-identity/postgres"
	scim "github.com/faustbrian/go-scim"
	"github.com/jackc/pgx/v5"
)

func (b *protocolBridge) GetGroup(ctx context.Context, scope scim.Scope, id string) (scim.Resource, error) {
	i, err := currentInvocation(ctx)
	if err != nil || !b.groups || scope != i.connection.Scope || !liveConnection(ctx, i.connection) {
		return scim.Resource{}, identity.ForbiddenError{}
	}
	if _, err := identity.ParseSubjectID(id); err != nil {
		return scim.Resource{}, scim.ErrNotFound
	}
	var wire []byte
	err = b.service.pool.Raw().QueryRow(ctx, `SELECT resource FROM scim.groups WHERE tenant_id=$1 AND organization_id=$2 AND provider_id=$3 AND connection_id=$4 AND resource_id=$5 AND deleted_at IS NULL AND octet_length(resource)<=131072`, append(scopeArgs(scope), id)...).Scan(&wire)
	if errors.Is(err, pgx.ErrNoRows) {
		return scim.Resource{}, scim.ErrNotFound
	}
	var resource scim.Resource
	if err != nil || len(wire) > 131072 || json.Unmarshal(wire, &resource) != nil || resource.ID != id {
		return scim.Resource{}, identity.UnavailableError{}
	}
	if err := b.service.recheckRead(ctx, i); err != nil {
		return scim.Resource{}, err
	}
	return resource, nil
}

func (b *protocolBridge) SnapshotGroups(ctx context.Context, scope scim.Scope, budget scim.SnapshotBudget) (scim.Snapshot, error) {
	return b.Snapshot(ctx, scope, budget)
}

func (p *nativePhase) requireGroupMembers(ctx context.Context, w kernel.Work) error {
	raw, ok := p.resource.Attributes["members"].([]any)
	if !ok || len(raw) == 0 {
		return nil
	}
	if len(raw) > scim.DefaultGroupMembers {
		return identity.InvalidInputError{Field: "scim_group_members"}
	}
	for _, item := range raw {
		member, ok := item.(map[string]any)
		if !ok {
			return identity.InvalidInputError{Field: "scim_group_members"}
		}
		id, _ := member["value"].(string)
		kind, _ := member["type"].(string)
		if id == "" || kind != "User" && kind != "Group" {
			return identity.InvalidInputError{Field: "scim_group_members"}
		}
	}
	members, err := json.Marshal(raw)
	if err != nil || len(members) > 131072 {
		return identity.InvalidInputError{Field: "scim_group_members"}
	}
	defer clear(members)
	// checkCurrent has locked this exact connection FOR UPDATE. All supported
	// User/Group mutations take that same fence, so existence and the Group
	// write cannot race a member deletion. No nested payload or URI is fetched.
	// Work deliberately accepts scalar primitives, not driver arrays/codecs.
	// One bounded text binding carries the already validated member records.
	rows, err := w.Query(ctx, `SELECT count(*) FROM jsonb_to_recordset($5::jsonb) AS requested(type text,value text)
 WHERE (type='User' AND EXISTS(SELECT 1 FROM scim.users s WHERE s.tenant_id=$1 AND s.organization_id=$2 AND s.provider_id=$3 AND s.connection_id=$4 AND s.resource_id=requested.value AND s.deleted_at IS NULL))
 OR (type='Group' AND EXISTS(SELECT 1 FROM scim.groups s WHERE s.tenant_id=$1 AND s.organization_id=$2 AND s.provider_id=$3 AND s.connection_id=$4 AND s.resource_id=requested.value AND s.deleted_at IS NULL))`, append(scopeArgs(p.service.config().Scope), string(members))...)
	if err != nil {
		return identity.UnavailableError{}
	}
	defer rows.Close()
	var count int64
	if !rows.Next() || rows.Scan(&count) != nil || rows.Next() || rows.Err() != nil {
		return identity.UnavailableError{}
	}
	rows.Close()
	if count != int64(len(raw)) {
		return w.DenyFeature(ctx, p, p.command, kernel.FeatureFailureInvalidGroupMember)
	}
	return nil
}

func (p *nativePhase) applyGroupProjection(ctx context.Context, w kernel.Work) (identity.FeatureReceipt, error) {
	if nativeMutation(p.intent.Operation) {
		if err := p.requireOriginalProjection(ctx, w); err != nil {
			return identity.FeatureReceipt{}, err
		}
	}
	if !nativeDelete(p.intent.Operation) {
		if err := p.requireGroupMembers(ctx, w); err != nil {
			return identity.FeatureReceipt{}, err
		}
	}
	if p.noOpPatch() {
		generation := uint64(p.original.Generation)
		return identity.FeatureReceipt{Operation: p.operation(), BeforeVersion: generation, AfterVersion: generation}, nil
	}
	var count int64
	var err error
	if nativeDelete(p.intent.Operation) {
		count, err = w.Exec(ctx, `UPDATE scim.groups SET resource=convert_to('null','UTF8'),generation=generation+1,deleted_at=$6,command_id=$7,effect_digest=$8 WHERE tenant_id=$1 AND organization_id=$2 AND provider_id=$3 AND connection_id=$4 AND resource_id=$5 AND generation=$9 AND deleted_at IS NULL`, append(scopeArgs(p.service.config().Scope), p.original.ID, p.original.At, string(p.original.Command), p.effect[:], p.original.Generation)...)
	} else {
		wire, encodeErr := json.Marshal(p.resource)
		if encodeErr != nil || len(wire) > 131072 {
			return identity.FeatureReceipt{}, identity.InvalidInputError{Field: "scim_resource"}
		}
		defer clear(wire)
		args := append(scopeArgs(p.service.config().Scope), p.original.ID, wire, string(p.original.Command), p.effect[:])
		if p.intent.Operation == scim.GroupCreate {
			count, err = w.Exec(ctx, `INSERT INTO scim.groups(tenant_id,organization_id,provider_id,connection_id,resource_id,resource,command_id,effect_digest) VALUES($1,$2,$3,$4,$5,$6,$7,$8) ON CONFLICT DO NOTHING`, args...)
		} else {
			count, err = w.Exec(ctx, `UPDATE scim.groups SET resource=$6,generation=generation+1,command_id=$7,effect_digest=$8 WHERE tenant_id=$1 AND organization_id=$2 AND provider_id=$3 AND connection_id=$4 AND resource_id=$5 AND generation=$9 AND deleted_at IS NULL`, append(args, p.original.Generation)...)
		}
	}
	if err != nil {
		return identity.FeatureReceipt{}, identity.UnavailableError{}
	}
	if count != 1 {
		if p.intent.Operation == scim.GroupCreate {
			return identity.FeatureReceipt{}, w.DenyFeature(ctx, p, p.command, kernel.FeatureFailureConflict)
		}
		return identity.FeatureReceipt{}, w.DenyFeature(ctx, p, p.command, kernel.FeatureFailurePrecondition)
	}
	lifecycle := p.lifecycle()
	return identity.FeatureReceipt{Operation: p.operation(), BeforeVersion: lifecycle.BeforeVersion, AfterVersion: lifecycle.AfterVersion}, nil
}
