// Package idempotency owns operation-scoped write replay semantics.
package idempotency

import (
	"bytes"
	"context"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

type Request struct {
	WorkspaceID, ProjectID, Operation, Key, RunID string
	Digest                                        []byte
	VersionBound                                  int64
}
type Response struct {
	Status       int
	ContentType  string
	Body         []byte
	Replayed     bool
	VersionBound int64
}
type Handler func(context.Context, pgx.Tx) (Response, error)
type Config struct{ Retention, MinimumLifetime time.Duration }
type Store struct {
	database  *pgxpool.Pool
	retention time.Duration
}

func New(database *pgxpool.Pool, cfg Config) (*Store, error) {
	if cfg.Retention <= 0 || cfg.Retention < cfg.MinimumLifetime {
		return nil, fmt.Errorf("idempotency retention must cover replay, artifact, and audit lifetime")
	}
	return &Store{database: database, retention: cfg.Retention}, nil
}

func (s *Store) Execute(ctx context.Context, request Request, handler Handler) (Response, error) {
	if request.WorkspaceID == "" || request.ProjectID == "" || request.Operation == "" || request.Key == "" || len(request.Digest) == 0 {
		return Response{}, fmt.Errorf("idempotency request: scope, operation, key, and digest are required")
	}
	tx, err := s.database.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
	if err != nil {
		return Response{}, fmt.Errorf("begin idempotent write: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	insert, err := tx.Exec(ctx, `INSERT INTO agent_control.write_idempotency(workspace_id, project_id, operation, idempotency_key, request_digest, version_bound, response_status, response_content_type, response_body, expires_at) VALUES($1,$2,$3,$4,$5,$6,0,'',decode('','hex'),$7) ON CONFLICT DO NOTHING`, request.WorkspaceID, request.ProjectID, request.Operation, request.Key, request.Digest, request.VersionBound, time.Now().Add(s.retention))
	if err != nil {
		return Response{}, fmt.Errorf("reserve idempotency outcome: %w", err)
	}
	if insert.RowsAffected() == 0 {
		var existing Response
		var digest []byte
		if err := tx.QueryRow(ctx, `SELECT request_digest, version_bound, response_status, response_content_type, response_body FROM agent_control.write_idempotency WHERE workspace_id=$1 AND project_id=$2 AND operation=$3 AND idempotency_key=$4`, request.WorkspaceID, request.ProjectID, request.Operation, request.Key).Scan(&digest, &existing.VersionBound, &existing.Status, &existing.ContentType, &existing.Body); err != nil {
			return Response{}, fmt.Errorf("read idempotency outcome: %w", err)
		}
		if !bytes.Equal(digest, request.Digest) {
			return Response{}, fmt.Errorf("idempotency conflict: key reused with a different canonical digest")
		}
		if existing.VersionBound != request.VersionBound {
			return Response{}, fmt.Errorf("idempotency conflict: version bound differs from original request")
		}
		existing.Replayed = true
		if err := tx.Commit(ctx); err != nil {
			return Response{}, fmt.Errorf("commit idempotency replay: %w", err)
		}
		return existing, nil
	}
	if request.RunID != "" {
		var current int64
		if err := tx.QueryRow(ctx, `SELECT version FROM agent_control.agent_runs WHERE workspace_id=$1 AND project_id=$2 AND run_id=$3 FOR UPDATE`, request.WorkspaceID, request.ProjectID, request.RunID).Scan(&current); err != nil {
			return Response{}, fmt.Errorf("lock idempotent run version: %w", err)
		}
		if current != request.VersionBound {
			return Response{}, fmt.Errorf("idempotency conflict: stale version precondition")
		}
	}
	response, err := handler(ctx, tx)
	if err != nil {
		return Response{}, err
	}
	response.VersionBound = request.VersionBound
	_, err = tx.Exec(ctx, `UPDATE agent_control.write_idempotency SET response_status=$5,response_content_type=$6,response_body=$7 WHERE workspace_id=$1 AND project_id=$2 AND operation=$3 AND idempotency_key=$4`, request.WorkspaceID, request.ProjectID, request.Operation, request.Key, response.Status, response.ContentType, response.Body)
	if err != nil {
		return Response{}, fmt.Errorf("record idempotency response: %w", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return Response{}, fmt.Errorf("commit idempotent write: %w", err)
	}
	return response, nil
}
