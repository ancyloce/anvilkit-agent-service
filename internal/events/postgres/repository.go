// Package postgres implements event authority with one Postgres transaction.
package postgres

import (
	"bytes"
	"context"
	"fmt"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	contractguard "github.com/ancyloce/anvilkit-agent-service/internal/contracts"
	"github.com/ancyloce/anvilkit-agent-service/internal/events"
)

type FailurePoint string

const (
	AfterRunUpdate        FailurePoint = "after-run-update"
	AfterEventInsert      FailurePoint = "after-event-insert"
	AfterOutboxInsert     FailurePoint = "after-outbox-insert"
	AfterCheckpointInsert FailurePoint = "after-checkpoint-insert"
)

type FailureInjector func(FailurePoint) error

type Repository struct {
	database *pgxpool.Pool
	inject   FailureInjector
	guard    *contractguard.Guard
	bounds   events.Bounds
}

func New(database *pgxpool.Pool, inject FailureInjector, guard *contractguard.Guard, configured ...events.Bounds) *Repository {
	bounds := events.DefaultBounds()
	if len(configured) == 1 {
		bounds = configured[0]
	}
	return &Repository{database: database, inject: inject, guard: guard, bounds: bounds}
}

func (r *Repository) Commit(ctx context.Context, change events.Transition) (events.Committed, error) {
	if err := change.Scope.Validate(); err != nil {
		return events.Committed{}, err
	}
	if change.RunID == "" || change.EventID == "" || change.OutboxID == "" || change.WorkflowID == "" || change.WorkflowVersion < 1 || change.Checkpoint == "" {
		return events.Committed{}, fmt.Errorf("commit event transition: stable identities are required")
	}
	if r.guard == nil {
		return events.Committed{}, fmt.Errorf("commit event transition: contract guard is required")
	}
	if err := events.ValidateEnvelope(change.EventBytes, r.bounds, change.EventID, change.RunID, 0); err != nil {
		return events.Committed{}, fmt.Errorf("commit event transition: %w", err)
	}
	if err := r.guard.Require(ctx, contractguard.EventIn, agentEventSchema, change.EventBytes); err != nil {
		return events.Committed{}, err
	}
	tx, err := r.database.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.Serializable})
	if err != nil {
		return events.Committed{}, fmt.Errorf("begin event transition: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	var committed events.Committed
	err = tx.QueryRow(ctx, `UPDATE agent_control.agent_runs SET state=$4, snapshot=$5, version=version+1, next_event_sequence=next_event_sequence+1, updated_at=transaction_timestamp() WHERE workspace_id=$1 AND project_id=$2 AND run_id=$3 AND version=$6 RETURNING version, next_event_sequence-1`, change.Scope.WorkspaceID, change.Scope.ProjectID, change.RunID, change.NextState, change.Snapshot, change.ExpectedVersion).Scan(&committed.Version, &committed.Sequence)
	if err != nil {
		if err == pgx.ErrNoRows {
			return events.Committed{}, fmt.Errorf("event transition: stale or missing run")
		}
		return events.Committed{}, fmt.Errorf("update run and allocate sequence: %w", err)
	}
	if err := r.fail(AfterRunUpdate); err != nil {
		return events.Committed{}, err
	}
	if err := events.ValidateEnvelope(change.EventBytes, r.bounds, change.EventID, change.RunID, uint64(committed.Sequence)); err != nil {
		return events.Committed{}, fmt.Errorf("commit event transition: allocated sequence mismatch: %w", err)
	}
	_, err = tx.Exec(ctx, `INSERT INTO agent_events.agent_events(workspace_id, project_id, run_id, sequence, event_id, event_bytes) VALUES($1,$2,$3,$4,$5,$6)`, change.Scope.WorkspaceID, change.Scope.ProjectID, change.RunID, committed.Sequence, change.EventID, change.EventBytes)
	if err != nil {
		return events.Committed{}, fmt.Errorf("insert allocated event: %w", err)
	}
	if err := r.fail(AfterEventInsert); err != nil {
		return events.Committed{}, err
	}
	_, err = tx.Exec(ctx, `INSERT INTO agent_events.outbox(workspace_id, project_id, outbox_id, run_id, event_sequence, topic, payload) VALUES($1,$2,$3,$4,$5,$6,$7)`, change.Scope.WorkspaceID, change.Scope.ProjectID, change.OutboxID, change.RunID, committed.Sequence, change.Topic, change.OutboxBytes)
	if err != nil {
		return events.Committed{}, fmt.Errorf("insert transactional outbox: %w", err)
	}
	if err := r.fail(AfterOutboxInsert); err != nil {
		return events.Committed{}, err
	}
	_, err = tx.Exec(ctx, `INSERT INTO agent_workflow.checkpoints(workspace_id,project_id,workflow_id,workflow_version,step_name,state_bytes,problem_bytes) VALUES($1,$2,$3,$4,$5,$6,$7) ON CONFLICT(workspace_id,project_id,workflow_id,workflow_version,step_name) DO UPDATE SET state_bytes=EXCLUDED.state_bytes,problem_bytes=EXCLUDED.problem_bytes,updated_at=transaction_timestamp()`, change.Scope.WorkspaceID, change.Scope.ProjectID, change.WorkflowID, change.WorkflowVersion, change.Checkpoint, change.CheckpointBytes, change.ProblemBytes)
	if err != nil {
		return events.Committed{}, fmt.Errorf("persist workflow checkpoint: %w", err)
	}
	if err := r.fail(AfterCheckpointInsert); err != nil {
		return events.Committed{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return events.Committed{}, fmt.Errorf("commit run event and outbox: %w", err)
	}
	return committed, nil
}

func (r *Repository) Accept(ctx context.Context, message events.InboxMessage) (events.InboxResult, error) {
	if err := message.Scope.Validate(); err != nil {
		return "", err
	}
	result, err := r.database.Exec(ctx, `INSERT INTO agent_events.inbox(workspace_id, project_id, consumer, message_id, payload_digest) VALUES($1,$2,$3,$4,$5) ON CONFLICT DO NOTHING`, message.Scope.WorkspaceID, message.Scope.ProjectID, message.Consumer, message.MessageID, message.Digest)
	if err != nil {
		return "", fmt.Errorf("record inbox message: %w", err)
	}
	if result.RowsAffected() == 1 {
		return events.InboxAccepted, nil
	}
	var existing []byte
	if err := r.database.QueryRow(ctx, `SELECT payload_digest FROM agent_events.inbox WHERE workspace_id=$1 AND project_id=$2 AND consumer=$3 AND message_id=$4`, message.Scope.WorkspaceID, message.Scope.ProjectID, message.Consumer, message.MessageID).Scan(&existing); err != nil {
		return "", fmt.Errorf("read inbox duplicate: %w", err)
	}
	if !bytes.Equal(existing, message.Digest) {
		return "", fmt.Errorf("inbox conflict: message ID reused with different digest")
	}
	return events.InboxDuplicate, nil
}

func (r *Repository) fail(point FailurePoint) error {
	if r.inject == nil {
		return nil
	}
	if err := r.inject(point); err != nil {
		return fmt.Errorf("injected failure at %s: %w", point, err)
	}
	return nil
}

var _ events.Repository = (*Repository)(nil)
var _ events.Inbox = (*Repository)(nil)

const agentEventSchema = "anvilkit://schema/agent-event.v1@1.0.0?digest=sha256:f19775b8dfdd34cac0318fce8067460988671840987a2b9aaeaa3c85710591ab"
