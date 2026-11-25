package scimpostgres

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"

	identity "github.com/faustbrian/go-identity"
	kernel "github.com/faustbrian/go-identity/postgres"
)

const bulkParentInsert = `INSERT INTO scim.bulk_requests
(tenant_id,organization_id,provider_id,connection_id,parent_id,intent_digest,configuration_digest,response_bytes,child_count,fail_on_errors,created_at)
VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)`

const bulkChildrenInsert = `INSERT INTO scim.bulk_children
(parent_id,ordinal,command_id,bulk_id,request_fingerprint,resource_id,component_id,component_order,cyclic,dependency_ids)
SELECT $1,i.ordinal,i.command_id,decode(i.bulk_id,'base64'),decode(i.fingerprint,'base64'),i.resource_id,i.component_id,i.component_order,i.cyclic,i.dependency_ids
FROM jsonb_to_recordset(convert_from($2,'UTF8')::jsonb) AS i
(ordinal smallint,command_id text,bulk_id text,fingerprint text,resource_id text,component_id smallint,component_order smallint,cyclic boolean,dependency_ids text[])`

const bulkCommittedSelect = `SELECT EXISTS(SELECT 1 FROM scim.bulk_requests
WHERE tenant_id=$1 AND organization_id=$2 AND provider_id=$3 AND connection_id=$4 AND parent_id=$5
AND intent_digest=$6 AND configuration_digest=$7 AND response_bytes=$8 AND child_count=$9 AND fail_on_errors=$10 AND created_at=$11)`

const bulkRecoverySelect = `SELECT intent_digest FROM scim.bulk_requests WHERE parent_id=$1`

type bulkChildRow struct {
	Ordinal        int      `json:"ordinal"`
	Command        string   `json:"command_id"`
	BulkID         []byte   `json:"bulk_id"`
	Fingerprint    []byte   `json:"fingerprint"`
	Resource       string   `json:"resource_id"`
	ComponentID    int      `json:"component_id"`
	ComponentOrder int      `json:"component_order"`
	Cyclic         bool     `json:"cyclic"`
	Dependencies   []string `json:"dependency_ids"`
}

func (p *nativePhase) bulkParentArgs() []any {
	g := p.bulk
	return append(scopeArgs(p.service.config().Scope), string(p.original.Command), g.intent[:], g.profile[:], g.maximum, len(g.children), g.cutoff, p.original.At)
}

func (p *nativePhase) applyBulkAdmission(ctx context.Context, work kernel.Work) (identity.FeatureReceipt, error) {
	rows, err := p.bulk.childRows()
	if err != nil {
		return identity.FeatureReceipt{}, err
	}
	if count, err := work.Exec(ctx, bulkParentInsert, p.bulkParentArgs()...); err != nil || count != 1 {
		return identity.FeatureReceipt{}, identity.UnavailableError{}
	}
	if err := writeBulkChildren(ctx, work, p.original.Command, rows); err != nil {
		return identity.FeatureReceipt{}, err
	}
	return identity.FeatureReceipt{Operation: p.operation(), AfterVersion: 1}, nil
}

func (p *bulkAdmissionPhase) childRows() ([]bulkChildRow, error) {
	rows := make([]bulkChildRow, len(p.children))
	for i, child := range p.children {
		allocated := p.allocation[i]
		row := bulkChildRow{Ordinal: i, Command: string(allocated.Command), BulkID: []byte(child.BulkID), Resource: allocated.Resource,
			Fingerprint: bulkChildFingerprint(p.intent, i), ComponentOrder: -1, Dependencies: make([]string, len(child.Dependencies))}
		for j, predecessor := range child.Dependencies {
			if predecessor < 0 || predecessor >= len(rows) {
				return nil, identity.UnavailableError{}
			}
			row.Dependencies[j] = string(p.allocation[predecessor].Command)
		}
		rows[i] = row
	}
	for ordinal, component := range p.components {
		if len(component.Operations) == 0 {
			return nil, identity.UnavailableError{}
		}
		// The planner orders members by original index. The smallest member
		// identifies the SCC independently of its condensation-graph position.
		id := component.Operations[0]
		for _, index := range component.Operations {
			if index < 0 || index >= len(rows) || rows[index].ComponentOrder != -1 {
				return nil, identity.UnavailableError{}
			}
			rows[index].ComponentID, rows[index].ComponentOrder, rows[index].Cyclic = id, ordinal, component.Cyclic
		}
	}
	for _, row := range rows {
		if row.ComponentOrder == -1 {
			return nil, identity.UnavailableError{}
		}
	}
	return rows, nil
}

// The keyed parent's original intent commits the complete ordered request.
// Frame each index separately so a retained child cannot be relabelled or
// moved between requests, even when two child descriptions are identical.
func bulkChildFingerprint(parent [32]byte, index int) []byte {
	frame := binary.BigEndian.AppendUint32(append([]byte("scim-native-bulk-child-v1\x00"), parent[:]...), uint32(index))
	digest := sha256.Sum256(frame)
	return digest[:]
}

// Stay below the kernel's per-statement 1 MiB scalar limit without a round
// trip per edge. All statements still belong to the same protected Work.
const bulkChildBatchBytes = 512 * 1024

func writeBulkChildren(ctx context.Context, work kernel.Work, command identity.CommandID, rows []bulkChildRow) error {
	batch := make([]byte, 1, bulkChildBatchBytes)
	batch[0] = '['
	entries := 0
	flush := func() error {
		if entries == 0 {
			return nil
		}
		batch = append(batch, ']')
		count, err := work.Exec(ctx, bulkChildrenInsert, string(command), batch)
		if err != nil || count != int64(entries) {
			return identity.UnavailableError{}
		}
		batch, entries = batch[:1], 0
		return nil
	}
	for _, row := range rows {
		wire, err := json.Marshal(row)
		if err != nil || len(wire)+2 > bulkChildBatchBytes {
			return identity.UnavailableError{}
		}
		if len(batch)+len(wire)+2 > bulkChildBatchBytes {
			if err := flush(); err != nil {
				return err
			}
		}
		if entries != 0 {
			batch = append(batch, ',')
		}
		batch = append(batch, wire...)
		entries++
	}
	return flush()
}

func (p *nativePhase) requireCommittedBulkAdmission(ctx context.Context) error {
	var exists bool
	err := p.service.pool.Raw().QueryRow(ctx, bulkCommittedSelect, p.bulkParentArgs()...).Scan(&exists)
	if err != nil || !exists {
		return identity.UnavailableError{}
	}
	return nil
}
