package postgres

import (
	"context"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/ancyloce/anvilkit-agent-service/internal/execution"
	"github.com/ancyloce/anvilkit-agent-service/internal/problem"
)

// RedemptionStore is the durable redeem-once record of the kernel's
// authoritative domain owner: one operation redeems exactly one authorization,
// exactly once, atomically with the recorded outcome. The immutability trigger
// keeps a recorded redemption from ever changing, so a replay across any
// process restart reads the original decision.
type RedemptionStore struct {
	database *pgxpool.Pool
}

func NewRedemptionStore(database *pgxpool.Pool) (*RedemptionStore, error) {
	if database == nil {
		return nil, fmt.Errorf("redemption store: a database is required")
	}
	return &RedemptionStore{database: database}, nil
}

var _ execution.DomainRedemptionStore = (*RedemptionStore)(nil)

func (s *RedemptionStore) Redeem(ctx context.Context, redemption execution.DomainRedemption) (execution.RedemptionResult, error) {
	tag, err := s.database.Exec(ctx, `INSERT INTO agent_control.domain_redemptions(workspace_id,project_id,operation_id,authorization_id,token_digest,run_id,artifact_digest,outcome,redeemed_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9) ON CONFLICT (workspace_id,project_id,operation_id) DO NOTHING`,
		redemption.WorkspaceID, redemption.ProjectID, redemption.OperationID, redemption.AuthorizationID, redemption.TokenDigest, redemption.RunID, redemption.ArtifactDigest, redemption.Outcome, redemption.RedeemedAt)
	if err != nil {
		var postgresError *pgconn.PgError
		if errors.As(err, &postgresError) && postgresError.Code == "23505" {
			// The authorization was already redeemed by a different operation.
			return execution.RedemptionResult{}, problem.New(problem.CodeIdempotencyConflict, "")
		}
		return execution.RedemptionResult{}, fmt.Errorf("record domain redemption: %w", err)
	}
	recorded, found, err := s.Redeemed(ctx, redemption.WorkspaceID, redemption.ProjectID, redemption.OperationID)
	if err != nil {
		return execution.RedemptionResult{}, err
	}
	if !found {
		return execution.RedemptionResult{}, fmt.Errorf("record domain redemption: the recorded row is unreadable")
	}
	if recorded.AuthorizationID != redemption.AuthorizationID || recorded.TokenDigest != redemption.TokenDigest || recorded.RunID != redemption.RunID || recorded.ArtifactDigest != redemption.ArtifactDigest {
		return execution.RedemptionResult{}, problem.New(problem.CodeIdempotencyConflict, "")
	}
	return execution.RedemptionResult{Outcome: recorded.Outcome, Replayed: tag.RowsAffected() == 0}, nil
}

func (s *RedemptionStore) Redeemed(ctx context.Context, workspaceID, projectID, operationID string) (execution.DomainRedemption, bool, error) {
	record := execution.DomainRedemption{WorkspaceID: workspaceID, ProjectID: projectID, OperationID: operationID}
	err := s.database.QueryRow(ctx, `SELECT authorization_id,token_digest,run_id,artifact_digest,outcome,redeemed_at FROM agent_control.domain_redemptions WHERE workspace_id=$1 AND project_id=$2 AND operation_id=$3`, workspaceID, projectID, operationID).
		Scan(&record.AuthorizationID, &record.TokenDigest, &record.RunID, &record.ArtifactDigest, &record.Outcome, &record.RedeemedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return execution.DomainRedemption{}, false, nil
	}
	if err != nil {
		return execution.DomainRedemption{}, false, fmt.Errorf("read domain redemption: %w", err)
	}
	return record, true, nil
}
