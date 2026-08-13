package persistence

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

type RunRecord struct {
	RunID, State                 string
	Version, ExecutionGeneration int64
	Snapshot                     json.RawMessage
}

type RunRepository struct{ database *pgxpool.Pool }

func NewRunRepository(database *pgxpool.Pool) *RunRepository {
	return &RunRepository{database: database}
}

func (r *RunRepository) Insert(ctx context.Context, scope Scope, record RunRecord) error {
	if err := scope.Validate(); err != nil {
		return err
	}
	_, err := r.database.Exec(ctx, `INSERT INTO agent_control.agent_runs (workspace_id, project_id, run_id, state, version, execution_generation, snapshot) VALUES ($1,$2,$3,$4,$5,$6,$7)`, scope.WorkspaceID, scope.ProjectID, record.RunID, record.State, record.Version, record.ExecutionGeneration, record.Snapshot)
	if err != nil {
		return fmt.Errorf("insert scoped run: %w", err)
	}
	return nil
}

func (r *RunRepository) Get(ctx context.Context, scope Scope, runID string) (RunRecord, error) {
	if err := scope.Validate(); err != nil {
		return RunRecord{}, err
	}
	var result RunRecord
	err := r.database.QueryRow(ctx, `SELECT run_id, state, version, execution_generation, snapshot FROM agent_control.agent_runs WHERE workspace_id=$1 AND project_id=$2 AND run_id=$3`, scope.WorkspaceID, scope.ProjectID, runID).Scan(&result.RunID, &result.State, &result.Version, &result.ExecutionGeneration, &result.Snapshot)
	if err != nil {
		if err == pgx.ErrNoRows {
			return RunRecord{}, err
		}
		return RunRecord{}, fmt.Errorf("get scoped run: %w", err)
	}
	return result, nil
}
