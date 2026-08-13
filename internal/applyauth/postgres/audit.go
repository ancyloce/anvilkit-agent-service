// Package postgres persists apply-authorization issuance audit without private keys.
package postgres

import (
	"context"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/ancyloce/anvilkit-agent-service/internal/applyauth"
	"github.com/ancyloce/anvilkit-agent-service/internal/problem"
)

type Audit struct{ database *pgxpool.Pool }

func New(database *pgxpool.Pool) (*Audit, error) {
	if database == nil {
		return nil, fmt.Errorf("authorization audit database is required")
	}
	return &Audit{database: database}, nil
}
func (a *Audit) Record(ctx context.Context, value applyauth.AuditRecord) error {
	tag, err := a.database.Exec(ctx, `INSERT INTO agent_control.apply_authorizations(workspace_id,project_id,run_id,authorization_id,key_id,payload_digest,token_digest,issued_at,expires_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9) ON CONFLICT (workspace_id,project_id,authorization_id) DO NOTHING`, value.WorkspaceID, value.ProjectID, value.RunID, value.AuthorizationID, value.KeyID, value.PayloadDigest, value.TokenDigest, value.IssuedAt, value.ExpiresAt)
	if err != nil {
		return fmt.Errorf("persist authorization audit: %w", err)
	}
	if tag.RowsAffected() == 0 {
		var runID, keyID, payloadDigest, tokenDigest string
		var issuedAt, expiresAt time.Time
		if err := a.database.QueryRow(ctx, `SELECT run_id,key_id,payload_digest,token_digest,issued_at,expires_at FROM agent_control.apply_authorizations WHERE workspace_id=$1 AND project_id=$2 AND authorization_id=$3`, value.WorkspaceID, value.ProjectID, value.AuthorizationID).Scan(&runID, &keyID, &payloadDigest, &tokenDigest, &issuedAt, &expiresAt); err != nil {
			return fmt.Errorf("read authorization audit replay: %w", err)
		}
		if runID != value.RunID || keyID != value.KeyID || payloadDigest != value.PayloadDigest || tokenDigest != value.TokenDigest || !issuedAt.Equal(value.IssuedAt) || !expiresAt.Equal(value.ExpiresAt) {
			return problem.New(problem.CodeIdempotencyConflict, "")
		}
	}
	return nil
}

var _ applyauth.Audit = (*Audit)(nil)
