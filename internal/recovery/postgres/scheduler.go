// Package postgres persists only the scheduler mirror of the external recovery epoch.
package postgres

import (
	"context"
	"fmt"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/ancyloce/anvilkit-agent-service/internal/problem"
	"github.com/ancyloce/anvilkit-agent-service/internal/recovery"
)

const registerName = "platform-recovery-epoch"

type Scheduler struct{ database *pgxpool.Pool }

func NewScheduler(database *pgxpool.Pool) (*Scheduler, error) {
	if database == nil {
		return nil, fmt.Errorf("recovery scheduler database required")
	}
	return &Scheduler{database: database}, nil
}

// Rotate adopts an externally incremented epoch while all processing is
// isolated. Every restored state-changing credential is invalidated in the
// same serializable transaction.
func (s *Scheduler) Rotate(ctx context.Context, epoch recovery.Epoch) error {
	if epoch == 0 {
		return problem.New(problem.CodeRequestInvalid, "")
	}
	tx, err := s.database.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.Serializable})
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	var prior uint64
	err = tx.QueryRow(ctx, `
		SELECT mirrored_epoch FROM agent_workflow.recovery_state
		WHERE register_name=$1 FOR UPDATE`, registerName).Scan(&prior)
	if err != nil && err != pgx.ErrNoRows {
		return err
	}
	if err == nil && uint64(epoch) <= prior {
		return problem.New(problem.CodeVersionConflict, "")
	}
	if _, err := tx.Exec(ctx, `
		INSERT INTO agent_workflow.recovery_state(
			register_name,mirrored_epoch,result_intake_enabled,dispatch_enabled,ingress_enabled
		) VALUES($1,$2,false,false,false)
		ON CONFLICT(register_name) DO UPDATE
		SET mirrored_epoch=excluded.mirrored_epoch,result_intake_enabled=false,
		    dispatch_enabled=false,ingress_enabled=false,
		    version=agent_workflow.recovery_state.version+1,
		    updated_at=transaction_timestamp()`, registerName, epoch); err != nil {
		return err
	}
	if _, err := tx.Exec(ctx, `
		UPDATE agent_workflow.worker_attempts
		SET state='superseded'
		WHERE state='active'`); err != nil {
		return err
	}
	if _, err := tx.Exec(ctx, `
		UPDATE agent_workflow.agent_tasks
		SET recovery_epoch=$1,
		    state=CASE WHEN state='leased' THEN 'queued' ELSE state END,
		    lease_epoch=lease_epoch+1,version=version+1,
		    updated_at=transaction_timestamp()
		WHERE state IN ('queued','leased')`, epoch); err != nil {
		return err
	}
	if _, err := tx.Exec(ctx, `DELETE FROM agent_workflow.executor_leases`); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

func (s *Scheduler) EnableDualResultFence(ctx context.Context, epoch recovery.Epoch) error {
	tag, err := s.database.Exec(ctx, `
		UPDATE agent_workflow.recovery_state
		SET result_intake_enabled=true,version=version+1,updated_at=transaction_timestamp()
		WHERE register_name=$1 AND mirrored_epoch=$2
		  AND dispatch_enabled=false AND ingress_enabled=false`, registerName, epoch)
	if err != nil {
		return err
	}
	if tag.RowsAffected() != 1 {
		return problem.New(problem.CodeWorkerFenceStale, "")
	}
	return nil
}

var _ recovery.SchedulerRecovery = (*Scheduler)(nil)
