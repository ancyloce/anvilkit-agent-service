// Package postgres persists the write-ahead domain-operation identity.
package postgres

import (
	"context"
	"fmt"
	"github.com/ancyloce/anvilkit-agent-service/internal/domaincommit"
	"github.com/ancyloce/anvilkit-agent-service/internal/problem"
	"github.com/ancyloce/anvilkit-agent-service/internal/runs"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"time"
)

type Store struct{ database *pgxpool.Pool }

func New(database *pgxpool.Pool) (*Store, error) {
	if database == nil {
		return nil, fmt.Errorf("domain operation database is required")
	}
	return &Store{database: database}, nil
}
func (s *Store) ActiveForRun(ctx context.Context, scope domaincommit.Scope, runID runs.ID) (domaincommit.Operation, bool, error) {
	row := s.database.QueryRow(ctx, `SELECT operation_id,authorization_id,authorization_jws,action_digest,artifact_digest,expected_revision,status,authorization_consumed,created_at,updated_at FROM agent_control.domain_operations WHERE workspace_id=$1 AND project_id=$2 AND run_id=$3 AND status IN ('recorded','issued','awaiting-domain-confirmation')`, scope.WorkspaceID, scope.ProjectID, runID)
	value, err := scan(row, scope, runID)
	if err == pgx.ErrNoRows {
		return domaincommit.Operation{}, false, nil
	}
	if err != nil {
		return domaincommit.Operation{}, false, fmt.Errorf("load active domain operation: %w", err)
	}
	return value, true, nil
}
func (s *Store) Create(ctx context.Context, value domaincommit.Operation) error {
	_, err := s.database.Exec(ctx, `INSERT INTO agent_control.domain_operations(workspace_id,project_id,run_id,operation_id,authorization_id,authorization_jws,action_digest,artifact_digest,expected_revision,status,authorization_consumed,created_at,updated_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13)`, value.Scope.WorkspaceID, value.Scope.ProjectID, value.RunID, value.ID, value.AuthorizationID, value.AuthorizationJWS, value.ActionDigest, value.ArtifactDigest, value.ExpectedRevision, value.Status, value.AuthorizationConsumed, value.CreatedAt, value.UpdatedAt)
	if err != nil {
		return fmt.Errorf("persist domain operation: %w", err)
	}
	return nil
}
func (s *Store) MarkIssued(ctx context.Context, scope domaincommit.Scope, id string, now time.Time) error {
	return s.update(ctx, scope, id, domaincommit.Issued, false, now)
}
func (s *Store) MarkAwaiting(ctx context.Context, scope domaincommit.Scope, id string, now time.Time) error {
	return s.update(ctx, scope, id, domaincommit.Awaiting, false, now)
}
func (s *Store) Finalize(ctx context.Context, scope domaincommit.Scope, id string, status domaincommit.Status, now time.Time) error {
	return s.update(ctx, scope, id, status, true, now)
}
func (s *Store) update(ctx context.Context, scope domaincommit.Scope, id string, status domaincommit.Status, consumed bool, now time.Time) error {
	tag, err := s.database.Exec(ctx, `UPDATE agent_control.domain_operations SET status=$4,authorization_consumed=authorization_consumed OR $5,updated_at=$6 WHERE workspace_id=$1 AND project_id=$2 AND operation_id=$3`, scope.WorkspaceID, scope.ProjectID, id, status, consumed, now)
	if err != nil {
		return fmt.Errorf("update domain operation: %w", err)
	}
	if tag.RowsAffected() != 1 {
		return problem.New(problem.CodeResourceNotFound, "")
	}
	return nil
}
func (s *Store) Get(ctx context.Context, scope domaincommit.Scope, id string) (domaincommit.Operation, error) {
	row := s.database.QueryRow(ctx, `SELECT run_id,operation_id,authorization_id,authorization_jws,action_digest,artifact_digest,expected_revision,status,authorization_consumed,created_at,updated_at FROM agent_control.domain_operations WHERE workspace_id=$1 AND project_id=$2 AND operation_id=$3`, scope.WorkspaceID, scope.ProjectID, id)
	var runID runs.ID
	var value domaincommit.Operation
	value.Scope = scope
	if err := row.Scan(&runID, &value.ID, &value.AuthorizationID, &value.AuthorizationJWS, &value.ActionDigest, &value.ArtifactDigest, &value.ExpectedRevision, &value.Status, &value.AuthorizationConsumed, &value.CreatedAt, &value.UpdatedAt); err != nil {
		if err == pgx.ErrNoRows {
			return domaincommit.Operation{}, problem.New(problem.CodeResourceNotFound, "")
		}
		return domaincommit.Operation{}, err
	}
	value.RunID = runID
	return value, nil
}

type scanner interface{ Scan(...any) error }

func scan(row scanner, scope domaincommit.Scope, runID runs.ID) (domaincommit.Operation, error) {
	value := domaincommit.Operation{Scope: scope, RunID: runID}
	err := row.Scan(&value.ID, &value.AuthorizationID, &value.AuthorizationJWS, &value.ActionDigest, &value.ArtifactDigest, &value.ExpectedRevision, &value.Status, &value.AuthorizationConsumed, &value.CreatedAt, &value.UpdatedAt)
	return value, err
}

var _ domaincommit.Store = (*Store)(nil)
