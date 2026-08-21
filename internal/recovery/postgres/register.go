package postgres

import (
	"context"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/ancyloce/anvilkit-agent-service/internal/problem"
	"github.com/ancyloce/anvilkit-agent-service/internal/recovery"
)

// MirrorEpochSource serves the controlled fabric's recovery epoch from the
// durable scheduler mirror (agent_workflow.recovery_state). The authoritative
// non-rollback register stays external to Platform Postgres by decision
// (design 0005 §13) and is deliberately absent from the Platform schema; the
// mirror keeps the controlled topology's epoch durable across process
// restarts instead of process memory, and production rejects the controlled
// fabric entirely.
type MirrorEpochSource struct{ database *pgxpool.Pool }

func NewMirrorEpochSource(database *pgxpool.Pool) (*MirrorEpochSource, error) {
	if database == nil {
		return nil, fmt.Errorf("recovery epoch source database required")
	}
	return &MirrorEpochSource{database: database}, nil
}

// EnsureBaseline initializes the scheduler's recovery-state mirror at epoch
// one with processing enabled. The insert is insert-once: an existing state —
// including one a restore advanced and isolated — is never touched.
func (s *MirrorEpochSource) EnsureBaseline(ctx context.Context) error {
	if _, err := s.database.Exec(ctx, `INSERT INTO agent_workflow.recovery_state(register_name,mirrored_epoch,result_intake_enabled,dispatch_enabled,ingress_enabled) VALUES($1,1,true,true,true) ON CONFLICT (register_name) DO NOTHING`, registerName); err != nil {
		return fmt.Errorf("initialize recovery state mirror: %w", err)
	}
	return nil
}

func (s *MirrorEpochSource) Current(ctx context.Context) (recovery.Epoch, error) {
	var epoch uint64
	err := s.database.QueryRow(ctx, `SELECT mirrored_epoch FROM agent_workflow.recovery_state WHERE register_name=$1`, registerName).Scan(&epoch)
	if errors.Is(err, pgx.ErrNoRows) {
		return 0, problem.New(problem.CodeInfrastructureUnavailable, "")
	}
	if err != nil {
		return 0, fmt.Errorf("read recovery epoch mirror: %w", err)
	}
	return recovery.Epoch(epoch), nil
}
