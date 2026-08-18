package postgres

import (
	"context"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/ancyloce/anvilkit-agent-service/internal/events"
)

type OutboxStore struct{ database *pgxpool.Pool }

func NewOutboxStore(database *pgxpool.Pool) (*OutboxStore, error) {
	if database == nil {
		return nil, fmt.Errorf("outbox database required")
	}
	return &OutboxStore{database: database}, nil
}

func (s *OutboxStore) DispatchReady(ctx context.Context, publisher events.Publisher, batchSize int) (int, error) {
	if publisher == nil || batchSize < 1 || batchSize > 1000 {
		return 0, fmt.Errorf("outbox publisher and bounded batch size are required")
	}
	tx, err := s.database.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
	if err != nil {
		return 0, fmt.Errorf("begin outbox dispatch: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	rows, err := tx.Query(ctx, `
		SELECT outbox_id,workspace_id,project_id,run_id,event_sequence,topic,payload,attempts
		FROM agent_events.outbox
		WHERE published_at IS NULL AND available_at <= transaction_timestamp()
		ORDER BY available_at,event_sequence
		FOR UPDATE SKIP LOCKED
		LIMIT $1`, batchSize)
	if err != nil {
		return 0, fmt.Errorf("claim outbox batch: %w", err)
	}
	messages, err := pgx.CollectRows(rows, func(row pgx.CollectableRow) (events.OutboxMessage, error) {
		var message events.OutboxMessage
		err := row.Scan(&message.ID, &message.WorkspaceID, &message.ProjectID, &message.RunID, &message.Sequence, &message.Topic, &message.Payload, &message.Attempts)
		return message, err
	})
	if err != nil {
		return 0, fmt.Errorf("read outbox batch: %w", err)
	}

	published := 0
	var publishErrors []error
	for _, message := range messages {
		if err := publisher.Publish(ctx, message); err != nil {
			backoffSeconds := 1 << min(message.Attempts, 6)
			if _, updateErr := tx.Exec(ctx, `UPDATE agent_events.outbox SET attempts=attempts+1,available_at=transaction_timestamp()+$4*interval '1 second' WHERE workspace_id=$1 AND project_id=$2 AND outbox_id=$3 AND published_at IS NULL`, message.WorkspaceID, message.ProjectID, message.ID, backoffSeconds); updateErr != nil {
				return published, fmt.Errorf("defer outbox message %s: %w", message.ID, updateErr)
			}
			publishErrors = append(publishErrors, fmt.Errorf("publish outbox message %s: %w", message.ID, err))
			continue
		}
		if _, err := tx.Exec(ctx, `UPDATE agent_events.outbox SET attempts=attempts+1,published_at=transaction_timestamp() WHERE workspace_id=$1 AND project_id=$2 AND outbox_id=$3 AND published_at IS NULL`, message.WorkspaceID, message.ProjectID, message.ID); err != nil {
			return published, fmt.Errorf("complete outbox message %s: %w", message.ID, err)
		}
		published++
	}
	if err := tx.Commit(ctx); err != nil {
		return 0, fmt.Errorf("commit outbox dispatch: %w", err)
	}
	return published, errors.Join(publishErrors...)
}

var _ events.OutboxStore = (*OutboxStore)(nil)
