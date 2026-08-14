// Package postgres persists queue delivery, inbox, acknowledgement, and DLQ state.
package postgres

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/ancyloce/anvilkit-agent-service/internal/problem"
	"github.com/ancyloce/anvilkit-agent-service/internal/queue"
)

type Store struct{ database *pgxpool.Pool }

func New(database *pgxpool.Pool) (*Store, error) {
	if database == nil {
		return nil, fmt.Errorf("queue database required")
	}
	return &Store{database: database}, nil
}

func (s *Store) Publish(ctx context.Context, message queue.Message) error {
	_, err := s.begin(ctx, message)
	return err
}

func (s *Store) Begin(ctx context.Context, message queue.Message) (bool, error) {
	return s.begin(ctx, message)
}

func (s *Store) begin(ctx context.Context, message queue.Message) (bool, error) {
	if err := queue.Validate(message); err != nil {
		return false, err
	}
	digest := payloadDigest(message.Payload)
	tag, err := s.database.Exec(ctx, `
		INSERT INTO agent_events.queue_deliveries(
			workspace_id,project_id,message_id,run_id,task_id,topic,payload,payload_digest,attempts,available_at
		) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,COALESCE($10,transaction_timestamp()))
		ON CONFLICT DO NOTHING`,
		message.WorkspaceID, message.ProjectID, message.ID, message.RunID, message.TaskID,
		message.Topic, message.Payload, digest, message.Attempts, nullableTime(message.AvailableAt))
	if err != nil {
		return false, err
	}
	if tag.RowsAffected() == 1 {
		return true, nil
	}
	var priorDigest, priorTopic, priorRun, priorTask string
	var priorPayload []byte
	var effectRecorded bool
	if err := s.database.QueryRow(ctx, `
		SELECT payload_digest,topic,run_id,task_id,payload,effect_recorded
		FROM agent_events.queue_deliveries
		WHERE workspace_id=$1 AND project_id=$2 AND message_id=$3`,
		message.WorkspaceID, message.ProjectID, message.ID).Scan(&priorDigest, &priorTopic, &priorRun, &priorTask, &priorPayload, &effectRecorded); err != nil {
		return false, err
	}
	if priorDigest != digest || priorTopic != message.Topic || priorRun != message.RunID || priorTask != message.TaskID || string(priorPayload) != string(message.Payload) {
		return false, problem.New(problem.CodeIdempotencyConflict, "")
	}
	return !effectRecorded, nil
}

func (s *Store) Commit(ctx context.Context, message queue.Message) error {
	tag, err := s.database.Exec(ctx, `
		UPDATE agent_events.queue_deliveries
		SET effect_recorded=true,updated_at=transaction_timestamp()
		WHERE workspace_id=$1 AND project_id=$2 AND message_id=$3
		  AND payload_digest=$4`,
		message.WorkspaceID, message.ProjectID, message.ID, payloadDigest(message.Payload))
	if err != nil {
		return err
	}
	if tag.RowsAffected() != 1 {
		return problem.New(problem.CodeIdempotencyConflict, "")
	}
	return nil
}

func (s *Store) Ack(ctx context.Context, message queue.Message) error {
	tag, err := s.database.Exec(ctx, `
		UPDATE agent_events.queue_deliveries
		SET acknowledged=true,updated_at=transaction_timestamp()
		WHERE workspace_id=$1 AND project_id=$2 AND message_id=$3
		  AND payload_digest=$4 AND (effect_recorded=true OR dead_lettered=true)`,
		message.WorkspaceID, message.ProjectID, message.ID, payloadDigest(message.Payload))
	if err != nil {
		return err
	}
	if tag.RowsAffected() != 1 {
		return problem.New(problem.CodeWorkerFenceStale, "")
	}
	return nil
}

func (s *Store) DeadLetter(ctx context.Context, value queue.DLQ) error {
	if err := queue.Validate(value.Message); err != nil {
		return err
	}
	if value.RunID != value.Message.RunID || value.Code == "" || value.Stage == "" || len(value.Code) > 128 || len(value.Stage) > 128 || len(value.Detail) > 2048 || value.CreatedAt.IsZero() {
		return problem.New(problem.CodeRequestInvalid, "")
	}
	tx, err := s.database.Begin(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	tag, err := tx.Exec(ctx, `
		INSERT INTO agent_workflow.worker_dlq(
			workspace_id,project_id,dlq_id,task_id,run_id,code,failed_stage,detail,created_at
		) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9)
		ON CONFLICT DO NOTHING`,
		value.Message.WorkspaceID, value.Message.ProjectID, "queue-"+value.Message.ID,
		value.Message.TaskID, value.RunID, value.Code, value.Stage, value.Detail, value.CreatedAt)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		var exact bool
		err = tx.QueryRow(ctx, `SELECT exists(
			SELECT 1 FROM agent_workflow.worker_dlq
			WHERE workspace_id=$1 AND project_id=$2 AND dlq_id=$3
			  AND task_id=$4 AND run_id=$5 AND code=$6 AND failed_stage=$7
			  AND detail=$8 AND created_at=$9)`,
			value.Message.WorkspaceID, value.Message.ProjectID, "queue-"+value.Message.ID,
			value.Message.TaskID, value.RunID, value.Code, value.Stage, value.Detail, value.CreatedAt).Scan(&exact)
		if err != nil {
			return err
		}
		if !exact {
			return problem.New(problem.CodeIdempotencyConflict, "")
		}
	}
	tag, err = tx.Exec(ctx, `
		UPDATE agent_events.queue_deliveries
		SET dead_lettered=true,updated_at=transaction_timestamp()
		WHERE workspace_id=$1 AND project_id=$2 AND message_id=$3 AND payload_digest=$4`,
		value.Message.WorkspaceID, value.Message.ProjectID, value.Message.ID, payloadDigest(value.Message.Payload))
	if err != nil {
		return err
	}
	if tag.RowsAffected() != 1 {
		return problem.New(problem.CodeIdempotencyConflict, "")
	}
	return tx.Commit(ctx)
}

// Replay redelivers the original durable bytes through the normal processor.
// Inbox deduplication and all worker fences remain active during replay.
func (s *Store) Replay(ctx context.Context, workspace, project, messageID string, processor *queue.Processor) error {
	if processor == nil {
		return fmt.Errorf("queue replay processor required")
	}
	var message queue.Message
	var replayed, deadLettered bool
	err := s.database.QueryRow(ctx, `
		SELECT q.message_id,q.workspace_id,q.project_id,q.run_id,q.task_id,q.topic,
		       q.payload,q.attempts,q.available_at,d.replayed,q.dead_lettered
		FROM agent_events.queue_deliveries q
		JOIN agent_workflow.worker_dlq d
		  ON d.workspace_id=q.workspace_id AND d.project_id=q.project_id
		 AND d.dlq_id='queue-' || q.message_id
		WHERE q.workspace_id=$1 AND q.project_id=$2 AND q.message_id=$3`, workspace, project, messageID).Scan(
		&message.ID, &message.WorkspaceID, &message.ProjectID, &message.RunID,
		&message.TaskID, &message.Topic, &message.Payload, &message.Attempts,
		&message.AvailableAt, &replayed, &deadLettered)
	if errors.Is(err, pgx.ErrNoRows) {
		return problem.New(problem.CodeResourceNotFound, "")
	}
	if err != nil {
		return err
	}
	if replayed {
		return nil
	}
	if !deadLettered {
		return problem.New(problem.CodeInvalidTransition, "")
	}
	message.Attempts = 0
	if err := processor.Handle(ctx, message); err != nil {
		return err
	}
	tx, err := s.database.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.Serializable})
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	tag, err := tx.Exec(ctx, `
		UPDATE agent_workflow.worker_dlq
		SET replayed=true
		WHERE workspace_id=$1 AND project_id=$2 AND dlq_id='queue-' || $3
		  AND replayed=false`, workspace, project, messageID)
	if err != nil {
		return err
	}
	if tag.RowsAffected() != 1 {
		return problem.New(problem.CodeVersionConflict, "")
	}
	tag, err = tx.Exec(ctx, `
		UPDATE agent_events.queue_deliveries
		SET dead_lettered=false,updated_at=transaction_timestamp()
		WHERE workspace_id=$1 AND project_id=$2 AND message_id=$3
		  AND dead_lettered=true`, workspace, project, messageID)
	if err != nil {
		return err
	}
	if tag.RowsAffected() != 1 {
		return problem.New(problem.CodeVersionConflict, "")
	}
	return tx.Commit(ctx)
}

func payloadDigest(payload []byte) string {
	sum := sha256.Sum256(payload)
	return "sha256:" + hex.EncodeToString(sum[:])
}

func nullableTime(value time.Time) any {
	if value.IsZero() {
		return nil
	}
	return value
}

var _ queue.Broker = (*Store)(nil)
var _ queue.Inbox = (*Store)(nil)
