// Package postgres persists apply-authorization issuance audit without private keys.
package postgres

import (
	"context"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
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

// Record persists the issuance audit row and the operation→authorization
// mapping (with the complete signed token) in one transaction. Signing, audit
// storage, issuance identity, and operation mapping are therefore one semantic
// write: a crash before commit leaves no durable trace of the minted token,
// and a racing replica that loses the operation insert rolls its audit row
// back too — its token was never audited and can never be redeemed.
func (a *Audit) Record(ctx context.Context, value applyauth.AuditRecord) error {
	if value.OperationKey == "" || value.Token == "" {
		return fmt.Errorf("authorization audit requires the durable operation identity and the signed token")
	}
	tx, err := a.database.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
	if err != nil {
		return fmt.Errorf("begin authorization audit: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	tag, err := tx.Exec(ctx, `INSERT INTO agent_control.apply_authorizations(workspace_id,project_id,run_id,authorization_id,key_id,payload_digest,token_digest,issued_at,expires_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9) ON CONFLICT (workspace_id,project_id,authorization_id) DO NOTHING`, value.WorkspaceID, value.ProjectID, value.RunID, value.AuthorizationID, value.KeyID, value.PayloadDigest, value.TokenDigest, value.IssuedAt, value.ExpiresAt)
	if err != nil {
		return fmt.Errorf("persist authorization audit: %w", err)
	}
	if tag.RowsAffected() == 0 {
		var runID, keyID, payloadDigest, tokenDigest string
		var issuedAt, expiresAt time.Time
		if err := tx.QueryRow(ctx, `SELECT run_id,key_id,payload_digest,token_digest,issued_at,expires_at FROM agent_control.apply_authorizations WHERE workspace_id=$1 AND project_id=$2 AND authorization_id=$3`, value.WorkspaceID, value.ProjectID, value.AuthorizationID).Scan(&runID, &keyID, &payloadDigest, &tokenDigest, &issuedAt, &expiresAt); err != nil {
			return fmt.Errorf("read authorization audit replay: %w", err)
		}
		if runID != value.RunID || keyID != value.KeyID || payloadDigest != value.PayloadDigest || tokenDigest != value.TokenDigest || !issuedAt.Equal(value.IssuedAt) || !expiresAt.Equal(value.ExpiresAt) {
			return problem.New(problem.CodeIdempotencyConflict, "")
		}
	}
	issuance, err := tx.Exec(ctx, `INSERT INTO agent_control.commit_issuances(workspace_id,project_id,run_id,operation_key,authorization_id,authorization_jws,issued_at,expires_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8) ON CONFLICT (workspace_id,project_id,operation_key) DO NOTHING`, value.WorkspaceID, value.ProjectID, value.RunID, value.OperationKey, value.AuthorizationID, value.Token, value.IssuedAt, value.ExpiresAt)
	if err != nil {
		return fmt.Errorf("persist issuance operation mapping: %w", err)
	}
	if issuance.RowsAffected() == 0 {
		var winner string
		if err := tx.QueryRow(ctx, `SELECT authorization_id FROM agent_control.commit_issuances WHERE workspace_id=$1 AND project_id=$2 AND operation_key=$3`, value.WorkspaceID, value.ProjectID, value.OperationKey).Scan(&winner); err != nil {
			return fmt.Errorf("read recorded issuance winner: %w", err)
		}
		if winner != string(value.AuthorizationID) {
			// A racing execution recorded first. Rolling back drops this
			// token's audit row with the mapping, so exactly one durably
			// audited capability exists for the operation.
			return problem.New(problem.CodeIdempotencyConflict, "")
		}
	}
	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("commit authorization audit: %w", err)
	}
	return nil
}

var _ applyauth.Audit = (*Audit)(nil)
