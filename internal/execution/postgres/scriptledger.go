// Package postgres holds the durable, process-external stores the execution
// pipeline depends on.
package postgres

import (
	"context"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/ancyloce/anvilkit-agent-service/internal/execution"
)

// ScriptLedger is the durable record of the controlled model adapter's
// settled provider operations. It is what makes provider idempotency survive
// a process or adapter restart: the settled outcome, the script position, and
// the usage each operation caused are rows, not adapter memory.
type ScriptLedger struct {
	database *pgxpool.Pool
	name     string
}

// NewScriptLedger opens the durable ledger under one bounded name. The name
// separates independent controlled deployments and test runs that share a
// database; it is never derived from request data.
func NewScriptLedger(database *pgxpool.Pool, name string) (*ScriptLedger, error) {
	if database == nil {
		return nil, fmt.Errorf("provider ledger: a database is required")
	}
	if name == "" || len(name) > 128 {
		return nil, fmt.Errorf("provider ledger: a bounded ledger name is required")
	}
	return &ScriptLedger{database: database, name: name}, nil
}

func (l *ScriptLedger) Settled(ctx context.Context, key string) (execution.ScriptOperation, bool, error) {
	if key == "" {
		return execution.ScriptOperation{}, false, fmt.Errorf("provider ledger: an operation identity is required")
	}
	operation := execution.ScriptOperation{Key: key}
	err := l.database.QueryRow(ctx, `SELECT script_position,failure,input_tokens,output_tokens,cost_micros FROM agent_workflow.controlled_provider_operations WHERE ledger=$1 AND operation_key=$2`, l.name, key).
		Scan(&operation.Position, &operation.Failure, &operation.InputTokens, &operation.OutputTokens, &operation.CostMicros)
	if errors.Is(err, pgx.ErrNoRows) {
		return execution.ScriptOperation{}, false, nil
	}
	if err != nil {
		return execution.ScriptOperation{}, false, fmt.Errorf("read settled provider operation: %w", err)
	}
	return operation, true, nil
}

func (l *ScriptLedger) Settle(ctx context.Context, proposal execution.ScriptProposal) (execution.ScriptOperation, error) {
	if proposal.Key == "" || proposal.ScriptLength < 1 {
		return execution.ScriptOperation{}, fmt.Errorf("provider ledger: an operation identity and a loaded script are required")
	}
	tx, err := l.database.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
	if err != nil {
		return execution.ScriptOperation{}, fmt.Errorf("begin provider settlement: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	// Position assignment is a read-then-write over the whole ledger, so two
	// concurrent settlements are serialized against each other rather than
	// both taking the same script position.
	if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtext($1))`, l.name); err != nil {
		return execution.ScriptOperation{}, fmt.Errorf("lock provider ledger: %w", err)
	}
	operation := execution.ScriptOperation{Key: proposal.Key}
	err = tx.QueryRow(ctx, `SELECT script_position,failure,input_tokens,output_tokens,cost_micros FROM agent_workflow.controlled_provider_operations WHERE ledger=$1 AND operation_key=$2`, l.name, proposal.Key).
		Scan(&operation.Position, &operation.Failure, &operation.InputTokens, &operation.OutputTokens, &operation.CostMicros)
	if err == nil {
		return operation, tx.Commit(ctx)
	}
	if !errors.Is(err, pgx.ErrNoRows) {
		return execution.ScriptOperation{}, fmt.Errorf("read settled provider operation: %w", err)
	}
	var failures, advanced int
	if err := tx.QueryRow(ctx, `SELECT count(*) FILTER (WHERE failure), count(*) FILTER (WHERE NOT failure) FROM agent_workflow.controlled_provider_operations WHERE ledger=$1`, l.name).Scan(&failures, &advanced); err != nil {
		return execution.ScriptOperation{}, fmt.Errorf("read provider ledger state: %w", err)
	}
	settled := execution.SettlementFor(proposal, failures, advanced)
	if _, err := tx.Exec(ctx, `INSERT INTO agent_workflow.controlled_provider_operations(ledger,operation_key,script_position,failure,input_tokens,output_tokens,cost_micros) VALUES($1,$2,$3,$4,$5,$6,$7)`,
		l.name, settled.Key, settled.Position, settled.Failure, settled.InputTokens, settled.OutputTokens, settled.CostMicros); err != nil {
		return execution.ScriptOperation{}, fmt.Errorf("record settled provider operation: %w", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return execution.ScriptOperation{}, fmt.Errorf("commit provider settlement: %w", err)
	}
	return settled, nil
}

func (l *ScriptLedger) Count(ctx context.Context) (int, error) {
	var count int
	if err := l.database.QueryRow(ctx, `SELECT count(*) FROM agent_workflow.controlled_provider_operations WHERE ledger=$1`, l.name).Scan(&count); err != nil {
		return 0, fmt.Errorf("count settled provider operations: %w", err)
	}
	return count, nil
}

var _ execution.ScriptLedger = (*ScriptLedger)(nil)
