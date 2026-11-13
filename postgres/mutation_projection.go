package scimpostgres

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"math"
	"time"

	identity "github.com/faustbrian/go-identity"
	kernel "github.com/faustbrian/go-identity/postgres"
	scim "github.com/faustbrian/go-scim"
)

func (p *nativePhase) originalUserStatus() identity.UserStatusRecord {
	c := p.service.config()
	return identity.UserStatusRecord{User: identity.User{ID: identity.UserID(p.original.ID), TenantID: c.Scope.TenantID, Status: identity.StatusActive, Version: p.original.KernelVersion}, AuthorityVersion: p.original.UserAuthority}
}

func (p *nativePhase) recoverOriginalProjection(ctx context.Context, w kernel.RecoveryWork) (kernel.RecoveryStatus, error) {
	// Later writes can replace command_id, and a terminal tombstone can expire.
	// Absence of that correlation is not rollback proof. An advancing mutation
	// cannot have committed if its exact original live row/generation remains.
	// No-op uses its separately validated frozen no-write declaration instead.
	if p.original.Current == nil {
		return kernel.RecoveryUnknown, nil
	}
	args := append(scopeArgs(p.service.config().Scope), p.original.ID)
	rows, err := w.Query(ctx, `SELECT generation,resource,deleted_at FROM scim.users WHERE tenant_id=$1 AND organization_id=$2 AND provider_id=$3 AND connection_id=$4 AND resource_id=$5 FOR SHARE`, args...)
	if err != nil {
		return kernel.RecoveryUnknown, err
	}
	defer rows.Close()
	if !rows.Next() {
		if err := rows.Err(); err != nil {
			return kernel.RecoveryUnknown, err
		}
		return kernel.RecoveryUnknown, nil
	}
	var generation int64
	var wire []byte
	var deleted *time.Time
	if rows.Scan(&generation, &wire, &deleted) != nil || rows.Next() || rows.Err() != nil {
		return kernel.RecoveryUnknown, identity.UnavailableError{}
	}
	original, err := json.Marshal(p.original.Current)
	if err != nil {
		return kernel.RecoveryUnknown, identity.UnavailableError{}
	}
	defer clear(original)
	if deleted == nil && generation == p.original.Generation && bytes.Equal(wire, original) {
		return kernel.RecoveryNotCommitted, nil
	}
	return kernel.RecoveryUnknown, nil
}

// The original projection and its generation are ordinary resource CAS, not a
// second command claim. This runs only in the existing feature Work, after its
// connection/target authority fences and before the kernel-owned attribute CAS.
func (p *nativePhase) requireOriginalProjection(ctx context.Context, w kernel.Work) error {
	if p.original.Current == nil || p.original.Generation < 1 || p.original.Generation == math.MaxInt64 && !p.noOpPatch() {
		return identity.InvalidInputError{Field: "scim_projection_generation"}
	}
	if err := w.RequireFeatureCommand(ctx, p, p.command); err != nil {
		return err
	}
	args := append(scopeArgs(p.service.config().Scope), p.original.ID)
	rows, err := w.Query(ctx, `SELECT generation,resource,deleted_at FROM scim.users WHERE tenant_id=$1 AND organization_id=$2 AND provider_id=$3 AND connection_id=$4 AND resource_id=$5 FOR UPDATE`, args...)
	if err != nil {
		return identity.UnavailableError{}
	}
	defer rows.Close()
	if !rows.Next() {
		if rows.Err() != nil {
			return identity.UnavailableError{}
		}
		rows.Close()
		return w.DenyFeature(ctx, p, p.command, kernel.FeatureFailurePrecondition)
	}
	var generation int64
	var wire []byte
	var deleted *time.Time
	if rows.Scan(&generation, &wire, &deleted) != nil || rows.Next() || rows.Err() != nil {
		return identity.UnavailableError{}
	}
	rows.Close()
	original, err := json.Marshal(p.original.Current)
	if err != nil || len(original) > 131072 {
		return identity.UnavailableError{}
	}
	defer clear(original)
	if deleted != nil || generation != p.original.Generation || !bytes.Equal(wire, original) || p.original.Current.Version != p.intent.IfMatch {
		return w.DenyFeature(ctx, p, p.command, kernel.FeatureFailurePrecondition)
	}
	return nil
}

// The caller has already fenced the original row and applied any required
// kernel-owned attributes in this same Work. No authoritative identity state is
// written here. No-op PATCH leaves the projection generation unchanged too:
// otherwise a concurrent canonical DELETE could be stranded with valid If-Match
// but a permanently obsolete private generation in its immutable preparation.
func (p *nativePhase) applyProjectionMutation(ctx context.Context, w kernel.Work) (identity.FeatureReceipt, error) {
	if err := w.RequireFeatureCommand(ctx, p, p.command); err != nil {
		return identity.FeatureReceipt{}, err
	}
	if p.original.Current == nil || p.original.Generation < 1 || p.original.Generation == math.MaxInt64 && !p.noOpPatch() {
		return identity.FeatureReceipt{}, identity.InvalidInputError{Field: "scim_projection_generation"}
	}
	if p.noOpPatch() {
		version := uint64(p.original.Generation)
		return identity.FeatureReceipt{Operation: p.operation(), BeforeVersion: version, AfterVersion: version}, nil
	}
	var count int64
	var err error
	if p.intent.Operation == scim.UserDelete {
		// Clear the live payload/correlation fields so an older binary, which
		// does not know deleted_at, fails decoding rather than exposing a deleted
		// projection. Original response reconstruction uses existing encrypted
		// request preparation plus the authoritative committed kernel journal.
		retiredKey := p.original.ID
		digest := sha256.Sum256([]byte(retiredKey))
		args := append(scopeArgs(p.service.config().Scope), p.original.ID, p.original.At, retiredKey, digest[:], string(p.original.Command), p.effect[:], p.original.Generation)
		count, err = w.Exec(ctx, `UPDATE scim.users SET generation=generation+1,deleted_at=$6,username_key=$7,username_digest=$8,external_id='',resource=convert_to('null','UTF8'),command_id=$9,effect_digest=$10 WHERE tenant_id=$1 AND organization_id=$2 AND provider_id=$3 AND connection_id=$4 AND resource_id=$5 AND generation=$11 AND deleted_at IS NULL`, args...)
	} else {
		username, e := scim.UsernameComparisonKey(p.resource.Attributes["userName"].(string))
		if e != nil {
			return identity.FeatureReceipt{}, identity.InvalidInputError{Field: "scim_username"}
		}
		digest := sha256.Sum256([]byte(username))
		wire, e := json.Marshal(p.resource)
		if e != nil || len(wire) > 131072 {
			return identity.FeatureReceipt{}, identity.InvalidInputError{Field: "scim_resource"}
		}
		defer clear(wire)
		args := append(scopeArgs(p.service.config().Scope), p.original.ID, username, digest[:], p.resource.ExternalID, wire, string(p.original.Command), p.effect[:], p.original.Generation)
		count, err = w.Exec(ctx, `UPDATE scim.users SET username_key=$6,username_digest=$7,external_id=$8,resource=$9,generation=generation+1,command_id=$10,effect_digest=$11 WHERE tenant_id=$1 AND organization_id=$2 AND provider_id=$3 AND connection_id=$4 AND resource_id=$5 AND generation=$12 AND deleted_at IS NULL`, args...)
	}
	if err != nil {
		return identity.FeatureReceipt{}, identity.UnavailableError{}
	}
	if count != 1 {
		return identity.FeatureReceipt{}, w.DenyFeature(ctx, p, p.command, kernel.FeatureFailurePrecondition)
	}
	return identity.FeatureReceipt{Operation: p.operation(), BeforeVersion: uint64(p.original.Generation), AfterVersion: uint64(p.original.Generation + 1)}, nil
}
