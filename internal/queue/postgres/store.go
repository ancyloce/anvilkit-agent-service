// Package postgres persists queue delivery, inbox, acknowledgement, and DLQ state.
package postgres

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"

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
	digest := payloadDigest(message.Payload)
	tag, err := s.database.Exec(ctx, `
		INSERT INTO agent_events.queue_deliveries(
			workspace_id,project_id,message_id,topic,payload_digest,attempts
		) VALUES($1,$2,$3,$4,$5,$6)
		ON CONFLICT DO NOTHING`,
		message.WorkspaceID, message.ProjectID, message.ID, message.Topic, digest, message.Attempts)
	if err != nil {
		return false, err
	}
	if tag.RowsAffected() == 1 {
		return true, nil
	}
	var priorDigest, priorTopic string
	var effectRecorded bool
	if err := s.database.QueryRow(ctx, `
		SELECT payload_digest,topic,effect_recorded
		FROM agent_events.queue_deliveries
		WHERE workspace_id=$1 AND project_id=$2 AND message_id=$3`,
		message.WorkspaceID, message.ProjectID, message.ID).Scan(&priorDigest, &priorTopic, &effectRecorded); err != nil {
		return false, err
	}
	if priorDigest != digest || priorTopic != message.Topic {
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
	tx, err := s.database.Begin(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	_, err = tx.Exec(ctx, `
		INSERT INTO agent_workflow.worker_dlq(
			workspace_id,project_id,dlq_id,task_id,run_id,code,failed_stage,detail,created_at
		) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9)
		ON CONFLICT DO NOTHING`,
		value.Message.WorkspaceID, value.Message.ProjectID, "queue-"+value.Message.ID,
		"unknown", value.RunID, value.Code, value.Stage, "queue delivery exhausted", value.CreatedAt)
	if err != nil {
		return err
	}
	tag, err := tx.Exec(ctx, `
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

func payloadDigest(payload []byte) string {
	sum := sha256.Sum256(payload)
	return "sha256:" + hex.EncodeToString(sum[:])
}

var _ queue.Broker = (*Store)(nil)
var _ queue.Inbox = (*Store)(nil)
