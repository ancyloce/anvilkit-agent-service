package postgres

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/ancyloce/anvilkit-agent-service/internal/execution"
)

// ToolReservations records the standing zero-cost reservation a run's tool
// dispatch runs under, insert-once per run, in the same durable reservation
// ledger every other budget reservation lives in. Current means the row is
// unreleased and unexpired.
type ToolReservations struct {
	database *pgxpool.Pool
	horizon  time.Duration
}

func NewToolReservations(database *pgxpool.Pool, horizon time.Duration) (*ToolReservations, error) {
	if database == nil {
		return nil, fmt.Errorf("tool reservations: a database is required")
	}
	if horizon <= 0 {
		return nil, fmt.Errorf("tool reservations: a positive reservation horizon is required")
	}
	return &ToolReservations{database: database, horizon: horizon}, nil
}

var _ execution.ToolReservations = (*ToolReservations)(nil)

func (r *ToolReservations) Ensure(ctx context.Context, workspaceID, projectID, rootRunID, runID, reservationID string, now time.Time) (bool, error) {
	if workspaceID == "" || projectID == "" || rootRunID == "" || runID == "" || reservationID == "" || now.IsZero() {
		return false, fmt.Errorf("tool reservations: a complete reservation identity is required")
	}
	if _, err := r.database.Exec(ctx, `INSERT INTO agent_control.budget_reservations(workspace_id,project_id,root_run_id,run_id,reservation_id,controller_generation,policy_version,budget_version,upper_bound_micros,expires_at,created_at,updated_at) VALUES($1,$2,$3,$4,$5,1,'run-pinned','run-pinned',0,$6,$7,$7) ON CONFLICT (workspace_id,project_id,reservation_id) DO NOTHING`,
		workspaceID, projectID, rootRunID, runID, reservationID, now.Add(r.horizon), now); err != nil {
		return false, fmt.Errorf("record standing tool reservation: %w", err)
	}
	var released bool
	var expiresAt time.Time
	err := r.database.QueryRow(ctx, `SELECT released,expires_at FROM agent_control.budget_reservations WHERE workspace_id=$1 AND project_id=$2 AND reservation_id=$3`, workspaceID, projectID, reservationID).Scan(&released, &expiresAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return false, fmt.Errorf("record standing tool reservation: the recorded row is unreadable")
	}
	if err != nil {
		return false, fmt.Errorf("read standing tool reservation: %w", err)
	}
	return !released && now.Before(expiresAt), nil
}
