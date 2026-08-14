// Package postgres implements lifecycle operations against the workflow store.
package postgres

import (
	"context"
	"fmt"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// LeaseCleaner relinquishes only leases owned by one executor. It never
// extends expiry or changes business retry counters during shutdown.
type LeaseCleaner struct {
	database   *pgxpool.Pool
	executorID string
}

func NewLeaseCleaner(database *pgxpool.Pool, executorID string) (*LeaseCleaner, error) {
	if database == nil || executorID == "" {
		return nil, fmt.Errorf("workflow database and executor identity are required")
	}
	return &LeaseCleaner{database: database, executorID: executorID}, nil
}

func (c *LeaseCleaner) Cleanup(ctx context.Context) error {
	tx, err := c.database.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return fmt.Errorf("begin lease cleanup: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if _, err := tx.Exec(ctx, `DELETE FROM agent_workflow.executor_leases WHERE executor_id=$1`, c.executorID); err != nil {
		return fmt.Errorf("relinquish workflow executor leases: %w", err)
	}
	if _, err := tx.Exec(ctx, `WITH released AS (
		UPDATE agent_workflow.worker_attempts
		SET state='lost'
		WHERE owner=$1 AND state='active'
		RETURNING workspace_id,project_id,task_id
	)
	UPDATE agent_workflow.agent_tasks AS task
	SET state='queued',version=version+1,updated_at=transaction_timestamp()
	FROM released
	WHERE task.workspace_id=released.workspace_id
	  AND task.project_id=released.project_id
	  AND task.task_id=released.task_id
	  AND task.state='leased'`, c.executorID); err != nil {
		return fmt.Errorf("relinquish worker attempts: %w", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("commit lease cleanup: %w", err)
	}
	return nil
}
