// Package idempotency owns operation-scoped write replay semantics.
package idempotency

import (
	"bytes"
	"context"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/ancyloce/anvilkit-agent-service/internal/problem"
)

// Request identifies one idempotent write. Key isolation follows ADR-021 §4:
// the authenticated subject, HTTP method, and canonical route/operation scope
// every key together with workspace and project, so one actor's recorded
// response can never be replayed to another actor, another method, or another
// route.
type Request struct {
	WorkspaceID, ProjectID, Subject, Method, Operation, Key, RunID string
	Digest                                                         []byte
	VersionBound                                                   int64
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

// MethodInternal scopes durable writes that originate inside the service —
// workflow-driven interrupt opens, expiries, and reconciliations — which have
// no HTTP method of their own.
const MethodInternal = "INTERNAL"

func New(database *pgxpool.Pool, cfg Config) (*Store, error) {
	if cfg.Retention <= 0 || cfg.Retention < cfg.MinimumLifetime {
		return nil, fmt.Errorf("idempotency retention must cover replay, artifact, and audit lifetime")
	}
	return &Store{database: database, retention: cfg.Retention}, nil
}

// KeyReused is the governed conflict a key replayed with different canonical
// bytes raises (ADR-021 §4). It is a distinct code from every other
// idempotency conflict because it says something no other one does: the caller
// changed the command under a key it had already committed to, so no recorded
// outcome can honestly answer the request.
func KeyReused() error {
	value := problem.New(problem.CodeIdempotencyKeyReused, "")
	value.Detail = "the idempotency key was already used with different canonical request bytes"
	return value
}

// revisionConflict is the unrelated conflict of the same key replayed against
// a different observed resource revision. The bytes match; the precondition
// the first request was made under does not, so it stays the general
// idempotency conflict rather than borrowing the reuse code.
func revisionConflict() error {
	value := problem.New(problem.CodeIdempotencyConflict, "")
	value.Detail = "the idempotency key was already used against a different resource revision"
	return value
}

func (s *Store) Execute(ctx context.Context, request Request, handler Handler) (Response, error) {
	if request.WorkspaceID == "" || request.ProjectID == "" || request.Subject == "" || request.Method == "" || request.Operation == "" || request.Key == "" || len(request.Digest) == 0 {
		return Response{}, fmt.Errorf("idempotency request: scope, subject, method, operation, key, and digest are required")
	}
	tx, err := s.database.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
	if err != nil {
		return Response{}, fmt.Errorf("begin idempotent write: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	insert, err := tx.Exec(ctx, `INSERT INTO agent_control.write_idempotency(workspace_id, project_id, subject, method, operation, idempotency_key, request_digest, version_bound, response_status, response_content_type, response_body, expires_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8,0,'',decode('','hex'),$9) ON CONFLICT DO NOTHING`, request.WorkspaceID, request.ProjectID, request.Subject, request.Method, request.Operation, request.Key, request.Digest, request.VersionBound, time.Now().Add(s.retention))
	if err != nil {
		return Response{}, fmt.Errorf("reserve idempotency outcome: %w", err)
	}
	if insert.RowsAffected() == 0 {
		var existing Response
		var digest []byte
		if err := tx.QueryRow(ctx, `SELECT request_digest, version_bound, response_status, response_content_type, response_body FROM agent_control.write_idempotency WHERE workspace_id=$1 AND project_id=$2 AND subject=$3 AND method=$4 AND operation=$5 AND idempotency_key=$6`, request.WorkspaceID, request.ProjectID, request.Subject, request.Method, request.Operation, request.Key).Scan(&digest, &existing.VersionBound, &existing.Status, &existing.ContentType, &existing.Body); err != nil {
			return Response{}, fmt.Errorf("read idempotency outcome: %w", err)
		}
		if !bytes.Equal(digest, request.Digest) {
			return Response{}, KeyReused()
		}
		if existing.VersionBound != request.VersionBound {
			return Response{}, revisionConflict()
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
			return Response{}, problem.New(problem.CodeVersionConflict, "")
		}
	}
	response, err := handler(ctx, tx)
	if err != nil {
		return Response{}, err
	}
	response.VersionBound = request.VersionBound
	_, err = tx.Exec(ctx, `UPDATE agent_control.write_idempotency SET response_status=$7,response_content_type=$8,response_body=$9 WHERE workspace_id=$1 AND project_id=$2 AND subject=$3 AND method=$4 AND operation=$5 AND idempotency_key=$6`, request.WorkspaceID, request.ProjectID, request.Subject, request.Method, request.Operation, request.Key, response.Status, response.ContentType, response.Body)
	if err != nil {
		return Response{}, fmt.Errorf("record idempotency response: %w", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return Response{}, fmt.Errorf("commit idempotent write: %w", err)
	}
	return response, nil
}
