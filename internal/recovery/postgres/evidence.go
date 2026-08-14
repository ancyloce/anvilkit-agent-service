// Package postgres persists an append-only operational restore evidence log.
// It supplements, but never replaces, the independently protected audit sink.
package postgres

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/ancyloce/anvilkit-agent-service/internal/canonical"
	"github.com/ancyloce/anvilkit-agent-service/internal/problem"
	"github.com/ancyloce/anvilkit-agent-service/internal/recovery"
)

type RestoreEvidence struct{ database *pgxpool.Pool }

func NewRestoreEvidence(database *pgxpool.Pool) (*RestoreEvidence, error) {
	if database == nil {
		return nil, fmt.Errorf("restore evidence database required")
	}
	return &RestoreEvidence{database: database}, nil
}

func (s *RestoreEvidence) BeginRestore(ctx context.Context, request recovery.RestoreRequest, startedAt time.Time) error {
	if err := recovery.ValidateRestoreRequest(request); err != nil || startedAt.IsZero() || request.RestorePoint.After(startedAt) || startedAt.Sub(request.RestorePoint) > 5*time.Minute {
		return problem.New(problem.CodeRequestInvalid, "")
	}
	tag, err := s.database.Exec(ctx, `
		INSERT INTO agent_workflow.restore_drills(
			drill_id,actor,workload,reason,ticket,traceparent,restore_point,started_at,state
		) VALUES($1,$2,$3,$4,$5,$6,$7,$8,'isolated')
		ON CONFLICT DO NOTHING`, request.DrillID, request.Actor, request.Workload,
		request.Reason, request.Ticket, request.Traceparent, request.RestorePoint, startedAt)
	if err != nil {
		return err
	}
	if tag.RowsAffected() != 1 {
		return problem.New(problem.CodeIdempotencyConflict, "")
	}
	return nil
}

func (s *RestoreEvidence) RecordRestoreStage(ctx context.Context, record recovery.StageRecord) error {
	if err := recovery.ValidateStageRecord(record); err != nil {
		return err
	}
	raw, digest, err := encodeEvidence(record)
	if err != nil {
		return err
	}
	tx, err := s.database.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.Serializable})
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	var state string
	if err := tx.QueryRow(ctx, `SELECT state FROM agent_workflow.restore_drills WHERE drill_id=$1 FOR UPDATE`, record.DrillID).Scan(&state); err != nil {
		return err
	}
	if state == "verified" || state == "failed" {
		return problem.New(problem.CodeInvalidTransition, "")
	}
	var sequence int
	if err := tx.QueryRow(ctx, `SELECT count(*)+1 FROM agent_workflow.restore_stages WHERE drill_id=$1`, record.DrillID).Scan(&sequence); err != nil {
		return err
	}
	expected := int(record.Stage)*2 - 1
	if record.Outcome == "completed" || record.Outcome == "failed" {
		expected++
	}
	if sequence != expected || (record.Outcome != "starting" && record.Outcome != "completed" && record.Outcome != "failed") {
		return problem.New(problem.CodeInvalidTransition, "")
	}
	_, err = tx.Exec(ctx, `
		INSERT INTO agent_workflow.restore_stages(
			drill_id,sequence,stage_sequence,stage,outcome,external_epoch,record,evidence_digest,recorded_at
		) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9)`, record.DrillID, sequence,
		record.Stage, record.Stage.String(), record.Outcome, record.Epoch, string(raw), digest, record.At)
	if err != nil {
		return err
	}
	if record.Outcome == "completed" {
		_, err = tx.Exec(ctx, `UPDATE agent_workflow.restore_drills SET state='reconciling' WHERE drill_id=$1 AND state='isolated'`, record.DrillID)
	} else if record.Outcome == "failed" {
		_, err = tx.Exec(ctx, `UPDATE agent_workflow.restore_drills SET state='failed',failure_stage=$2,failure_code='stage-failed',completed_at=$3 WHERE drill_id=$1`, record.DrillID, record.Stage, record.At)
	}
	if err != nil {
		return err
	}
	return tx.Commit(ctx)
}

func (s *RestoreEvidence) CompleteRestore(ctx context.Context, report recovery.RestoreReport) error {
	if err := recovery.ValidateRestoreReport(report, false); err != nil {
		return err
	}
	raw, err := json.Marshal(report)
	if err != nil {
		return err
	}
	tag, err := s.database.Exec(ctx, `
		UPDATE agent_workflow.restore_drills
		SET state='verified',completed_at=$2,external_epoch=$3,report=$4
		WHERE drill_id=$1 AND state='reconciling'
		  AND (SELECT count(*) FROM agent_workflow.restore_stages WHERE drill_id=$1)=26`,
		report.DrillID, report.CompletedAt, report.Epoch, string(raw))
	if err != nil {
		return err
	}
	if tag.RowsAffected() != 1 {
		return problem.New(problem.CodeInvalidTransition, "")
	}
	return nil
}

func (s *RestoreEvidence) FailRestore(ctx context.Context, report recovery.RestoreReport) error {
	if err := recovery.ValidateRestoreReport(report, true); err != nil {
		return err
	}
	raw, err := json.Marshal(report)
	if err != nil {
		return err
	}
	tag, err := s.database.Exec(ctx, `
		UPDATE agent_workflow.restore_drills
		SET state='failed',completed_at=$2,failure_stage=$3,failure_code=$4,report=$5
		WHERE drill_id=$1 AND state<>'verified'`, report.DrillID, report.CompletedAt,
		report.FailedStage, report.FailureCode, string(raw))
	if err != nil {
		return err
	}
	if tag.RowsAffected() != 1 {
		return problem.New(problem.CodeInvalidTransition, "")
	}
	return nil
}

func encodeEvidence(record recovery.StageRecord) ([]byte, string, error) {
	raw, err := json.Marshal(record)
	if err != nil {
		return nil, "", err
	}
	encoded, err := canonical.Bytes(raw)
	if err != nil {
		return nil, "", err
	}
	sum := sha256.Sum256(encoded)
	return raw, "sha256:" + hex.EncodeToString(sum[:]), nil
}

var _ recovery.RestoreEvidence = (*RestoreEvidence)(nil)
