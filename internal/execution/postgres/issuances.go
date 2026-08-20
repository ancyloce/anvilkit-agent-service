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

// IssuanceStore reads the durable insert-once record binding one durable
// commit operation to exactly one issued apply authorization, including the
// complete signed token. The record is written only inside the issuer's
// atomic audit transaction; the immutability trigger keeps a recorded
// issuance from ever changing.
type IssuanceStore struct {
	database *pgxpool.Pool
}

func NewIssuanceStore(database *pgxpool.Pool) (*IssuanceStore, error) {
	if database == nil {
		return nil, fmt.Errorf("issuance store: a database is required")
	}
	return &IssuanceStore{database: database}, nil
}

var _ execution.IssuanceStore = (*IssuanceStore)(nil)

func (s *IssuanceStore) Recorded(ctx context.Context, workspaceID, projectID, operationKey string) (execution.IssuanceRecord, bool, error) {
	if workspaceID == "" || projectID == "" || operationKey == "" {
		return execution.IssuanceRecord{}, false, fmt.Errorf("issuance store: scope and operation identity are required")
	}
	record := execution.IssuanceRecord{WorkspaceID: workspaceID, ProjectID: projectID, OperationKey: operationKey}
	var expires *time.Time
	err := s.database.QueryRow(ctx, `SELECT run_id,authorization_id,authorization_jws,expires_at FROM agent_control.commit_issuances WHERE workspace_id=$1 AND project_id=$2 AND operation_key=$3`, workspaceID, projectID, operationKey).
		Scan(&record.RunID, &record.AuthorizationID, &record.AuthorizationJWS, &expires)
	if errors.Is(err, pgx.ErrNoRows) {
		return execution.IssuanceRecord{}, false, nil
	}
	if err != nil {
		return execution.IssuanceRecord{}, false, fmt.Errorf("read recorded issuance: %w", err)
	}
	if expires != nil {
		record.ExpiresAt = *expires
	}
	return record, true, nil
}
