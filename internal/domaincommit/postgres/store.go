// Package postgres persists the write-ahead domain-operation identity.
package postgres

import (
	"context"
	"fmt"
	"time"

	"github.com/ancyloce/anvilkit-agent-service/internal/domaincommit"
	"github.com/ancyloce/anvilkit-agent-service/internal/problem"
	"github.com/ancyloce/anvilkit-agent-service/internal/runs"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

type Store struct{ database *pgxpool.Pool }

func New(database *pgxpool.Pool) (*Store, error) {
	if database == nil {
		return nil, fmt.Errorf("domain operation database is required")
	}
	return &Store{database: database}, nil
}

const operationColumns = `operation_id,authorization_id,authorization_jws,action_digest,artifact_digest,expected_revision,idempotency_key,request_digest,status,authorization_consumed,reconcile_attempts,first_uncertain_at,escalated_at,resolved_by,resolution_basis,created_at,updated_at`

func (s *Store) ActiveForRun(ctx context.Context, scope domaincommit.Scope, runID runs.ID) (domaincommit.Operation, bool, error) {
	row := s.database.QueryRow(ctx, `SELECT `+operationColumns+` FROM agent_control.domain_operations WHERE workspace_id=$1 AND project_id=$2 AND run_id=$3 AND status IN ('recorded','issued','awaiting-domain-confirmation','escalated')`, scope.WorkspaceID, scope.ProjectID, runID)
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
	_, err := s.database.Exec(ctx, `INSERT INTO agent_control.domain_operations(workspace_id,project_id,run_id,operation_id,authorization_id,authorization_jws,action_digest,artifact_digest,expected_revision,idempotency_key,request_digest,status,authorization_consumed,created_at,updated_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15)`, value.Scope.WorkspaceID, value.Scope.ProjectID, value.RunID, value.ID, value.AuthorizationID, value.AuthorizationJWS, value.ActionDigest, value.ArtifactDigest, value.ExpectedRevision, value.IdempotencyKey, value.RequestDigest, value.Status, value.AuthorizationConsumed, value.CreatedAt, value.UpdatedAt)
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
	if status != domaincommit.Applied && status != domaincommit.Conflicted && status != domaincommit.Rejected {
		return problem.New(problem.CodeInvalidTransition, "")
	}
	return s.update(ctx, scope, id, status, true, now)
}

// RecordReconcile durably counts one uncertain reconciliation of a submitted
// operation and stamps when uncertainty began. Only a submitted, undecided
// operation is countable; the database trigger keeps the count monotonic.
func (s *Store) RecordReconcile(ctx context.Context, scope domaincommit.Scope, id string, now time.Time) (domaincommit.Operation, error) {
	tag, err := s.database.Exec(ctx, `UPDATE agent_control.domain_operations SET reconcile_attempts=reconcile_attempts+1,first_uncertain_at=COALESCE(first_uncertain_at,$4),updated_at=$4 WHERE workspace_id=$1 AND project_id=$2 AND operation_id=$3 AND status IN ('issued','awaiting-domain-confirmation')`, scope.WorkspaceID, scope.ProjectID, id, now)
	if err != nil {
		return domaincommit.Operation{}, fmt.Errorf("record uncertain reconciliation: %w", err)
	}
	if tag.RowsAffected() != 1 {
		if _, getErr := s.Get(ctx, scope, id); getErr != nil {
			return domaincommit.Operation{}, problem.New(problem.CodeResourceNotFound, "")
		}
		return domaincommit.Operation{}, problem.New(problem.CodeInvalidTransition, "")
	}
	return s.Get(ctx, scope, id)
}

// Escalate marks a bounded-out submitted operation as requiring operator
// resolution. Escalating an already-escalated operation converges.
func (s *Store) Escalate(ctx context.Context, scope domaincommit.Scope, id string, now time.Time) error {
	tag, err := s.database.Exec(ctx, `UPDATE agent_control.domain_operations SET status='escalated',escalated_at=COALESCE(escalated_at,$4),updated_at=$4 WHERE workspace_id=$1 AND project_id=$2 AND operation_id=$3 AND status IN ('issued','awaiting-domain-confirmation')`, scope.WorkspaceID, scope.ProjectID, id, now)
	if err != nil {
		return fmt.Errorf("escalate domain operation: %w", err)
	}
	if tag.RowsAffected() == 1 {
		return nil
	}
	current, getErr := s.Get(ctx, scope, id)
	if getErr != nil {
		return getErr
	}
	if current.Status == domaincommit.Escalated {
		return nil
	}
	return problem.New(problem.CodeInvalidTransition, "")
}

// Resolve records an audited operator resolution of an escalated operation.
// The resolving operator and the evidence reference are mandatory, the
// outcome must be terminal, and the operation must actually be escalated —
// an owner-decided operation is never operator-overridden.
func (s *Store) Resolve(ctx context.Context, scope domaincommit.Scope, id string, outcome domaincommit.Status, resolvedBy, basis string, now time.Time) (domaincommit.Operation, error) {
	if outcome != domaincommit.Applied && outcome != domaincommit.Conflicted && outcome != domaincommit.Rejected {
		return domaincommit.Operation{}, problem.New(problem.CodeInvalidTransition, "")
	}
	if resolvedBy == "" || len(resolvedBy) > 128 || basis == "" || len(basis) > 1024 {
		return domaincommit.Operation{}, problem.New(problem.CodeRequestInvalid, "")
	}
	tag, err := s.database.Exec(ctx, `UPDATE agent_control.domain_operations SET status=$4,authorization_consumed=true,resolved_by=$5,resolution_basis=$6,updated_at=$7 WHERE workspace_id=$1 AND project_id=$2 AND operation_id=$3 AND status='escalated'`, scope.WorkspaceID, scope.ProjectID, id, outcome, resolvedBy, basis, now)
	if err != nil {
		return domaincommit.Operation{}, fmt.Errorf("resolve escalated domain operation: %w", err)
	}
	if tag.RowsAffected() != 1 {
		current, getErr := s.Get(ctx, scope, id)
		if getErr != nil {
			return domaincommit.Operation{}, problem.New(problem.CodeResourceNotFound, "")
		}
		// Two operators submitting the identical audited decision converge on
		// the one that landed; anything else lost the compare-and-set to a
		// different decision and is refused rather than overwriting it.
		if current.Status == outcome && current.ResolvedBy == resolvedBy && current.ResolutionBasis == basis {
			return current, nil
		}
		return domaincommit.Operation{}, problem.New(problem.CodeInvalidTransition, "")
	}
	return s.Get(ctx, scope, id)
}

// LatestForRun answers the most recently created operation for the run,
// decided or not.
func (s *Store) LatestForRun(ctx context.Context, scope domaincommit.Scope, runID runs.ID) (domaincommit.Operation, bool, error) {
	row := s.database.QueryRow(ctx, `SELECT `+operationColumns+` FROM agent_control.domain_operations WHERE workspace_id=$1 AND project_id=$2 AND run_id=$3 ORDER BY created_at DESC LIMIT 1`, scope.WorkspaceID, scope.ProjectID, runID)
	value, err := scan(row, scope, runID)
	if err == pgx.ErrNoRows {
		return domaincommit.Operation{}, false, nil
	}
	if err != nil {
		return domaincommit.Operation{}, false, fmt.Errorf("load latest domain operation: %w", err)
	}
	return value, true, nil
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
	row := s.database.QueryRow(ctx, `SELECT run_id,`+operationColumns+` FROM agent_control.domain_operations WHERE workspace_id=$1 AND project_id=$2 AND operation_id=$3`, scope.WorkspaceID, scope.ProjectID, id)
	var runID runs.ID
	var value domaincommit.Operation
	var firstUncertain, escalated *time.Time
	var resolvedBy, resolutionBasis *string
	value.Scope = scope
	if err := row.Scan(&runID, &value.ID, &value.AuthorizationID, &value.AuthorizationJWS, &value.ActionDigest, &value.ArtifactDigest, &value.ExpectedRevision, &value.IdempotencyKey, &value.RequestDigest, &value.Status, &value.AuthorizationConsumed, &value.ReconcileAttempts, &firstUncertain, &escalated, &resolvedBy, &resolutionBasis, &value.CreatedAt, &value.UpdatedAt); err != nil {
		if err == pgx.ErrNoRows {
			return domaincommit.Operation{}, problem.New(problem.CodeResourceNotFound, "")
		}
		return domaincommit.Operation{}, err
	}
	value.RunID = runID
	applyNullable(&value, firstUncertain, escalated, resolvedBy, resolutionBasis)
	return value, nil
}

type scanner interface{ Scan(...any) error }

func scan(row scanner, scope domaincommit.Scope, runID runs.ID) (domaincommit.Operation, error) {
	value := domaincommit.Operation{Scope: scope, RunID: runID}
	var firstUncertain, escalated *time.Time
	var resolvedBy, resolutionBasis *string
	err := row.Scan(&value.ID, &value.AuthorizationID, &value.AuthorizationJWS, &value.ActionDigest, &value.ArtifactDigest, &value.ExpectedRevision, &value.IdempotencyKey, &value.RequestDigest, &value.Status, &value.AuthorizationConsumed, &value.ReconcileAttempts, &firstUncertain, &escalated, &resolvedBy, &resolutionBasis, &value.CreatedAt, &value.UpdatedAt)
	if err != nil {
		return value, err
	}
	applyNullable(&value, firstUncertain, escalated, resolvedBy, resolutionBasis)
	return value, nil
}

func applyNullable(value *domaincommit.Operation, firstUncertain, escalated *time.Time, resolvedBy, resolutionBasis *string) {
	if firstUncertain != nil {
		value.FirstUncertainAt = *firstUncertain
	}
	if escalated != nil {
		value.EscalatedAt = *escalated
	}
	if resolvedBy != nil {
		value.ResolvedBy = *resolvedBy
	}
	if resolutionBasis != nil {
		value.ResolutionBasis = *resolutionBasis
	}
}

var _ domaincommit.Store = (*Store)(nil)
