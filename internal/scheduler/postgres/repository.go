// Package postgres supplies the durable winning-result transaction.
package postgres

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/ancyloce/anvilkit-agent-service/internal/problem"
	recoverypkg "github.com/ancyloce/anvilkit-agent-service/internal/recovery"
	"github.com/ancyloce/anvilkit-agent-service/internal/scheduler"
)

type FailurePoint string

const (
	AfterResult      FailurePoint = "after-result"
	AfterPromotion   FailurePoint = "after-promotion"
	AfterRun         FailurePoint = "after-run"
	AfterReservation FailurePoint = "after-reservation"
)

type Repository struct {
	database *pgxpool.Pool
	register interface {
		Current(context.Context) (recoverypkg.Epoch, error)
	}
	inject func(FailurePoint) error
}

func New(database *pgxpool.Pool, register interface {
	Current(context.Context) (recoverypkg.Epoch, error)
}, inject func(FailurePoint) error) (*Repository, error) {
	if database == nil || register == nil {
		return nil, fmt.Errorf("scheduler database and recovery register required")
	}
	return &Repository{database: database, register: register, inject: inject}, nil
}

// AcceptResult commits the immutable result, artifact promotion, run advance,
// reservation release, task completion, and attempt acceptance atomically.
// Every non-current result is retained as a diagnostic and changes no state.
func (r *Repository) AcceptResult(ctx context.Context, scope scheduler.Scope, result scheduler.Result) (bool, error) {
	registerEpoch, err := r.register.Current(ctx)
	if err != nil {
		return false, fmt.Errorf("read non-rollback recovery epoch: %w", err)
	}
	tx, err := r.database.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.Serializable})
	if err != nil {
		return false, err
	}
	defer func() { _ = tx.Rollback(ctx) }()

	var anyResult, exactResult bool
	err = tx.QueryRow(ctx, `
		SELECT
			exists(SELECT 1 FROM agent_workflow.worker_results
			       WHERE workspace_id=$1 AND project_id=$2 AND task_id=$3),
			exists(SELECT 1 FROM agent_workflow.worker_results
			       WHERE workspace_id=$1 AND project_id=$2 AND task_id=$3
			         AND physical_attempt_id=$4 AND recovery_epoch=$5
			         AND execution_generation=$6 AND lease_epoch=$7
			         AND fence_token=$8 AND capability=$9 AND build_identity=$10
			         AND artifact_id=$11 AND artifact_digest=$12
			         AND pending_object_key=$13 AND completed_at=$14)`,
		scope.WorkspaceID, scope.ProjectID, result.TaskID, result.PhysicalAttemptID,
		result.RecoveryEpoch, result.ExecutionGeneration, result.LeaseEpoch,
		result.FenceToken, result.Capability, result.BuildIdentity, result.ArtifactID,
		result.ArtifactDigest, result.PendingObjectKey, result.CompletedAt,
	).Scan(&anyResult, &exactResult)
	if err != nil {
		return false, err
	}
	if exactResult {
		var mirrored uint64
		var enabled bool
		if err := tx.QueryRow(ctx, `SELECT mirrored_epoch,result_intake_enabled FROM agent_workflow.recovery_state WHERE register_name='platform-recovery-epoch'`).Scan(&mirrored, &enabled); err != nil {
			return false, fmt.Errorf("read scheduler recovery mirror: %w", err)
		}
		confirmed, err := r.register.Current(ctx)
		if err != nil {
			return false, fmt.Errorf("confirm non-rollback recovery epoch: %w", err)
		}
		if !enabled || confirmed != registerEpoch || mirrored != result.RecoveryEpoch || uint64(registerEpoch) != mirrored {
			return r.recordDiagnostic(ctx, tx, scope, result, "duplicate-recovery-epoch")
		}
		return true, tx.Commit(ctx)
	}
	if anyResult {
		return r.recordDiagnostic(ctx, tx, scope, result, "result-conflict")
	}

	var runID, state, capability, attempt, fence string
	var recovery, generation, lease uint64
	var mirroredRecovery uint64
	var resultIntakeEnabled bool
	var issued, expires, databaseNow time.Time
	err = tx.QueryRow(ctx, `
		SELECT t.run_id,t.state,t.capability,t.recovery_epoch,t.execution_generation,
		       a.lease_epoch,a.physical_attempt_id,a.fence_token,a.issued_at,a.expires_at,
		       rs.mirrored_epoch,rs.result_intake_enabled,transaction_timestamp()
		FROM agent_workflow.agent_tasks t
		JOIN agent_workflow.worker_attempts a
		  ON a.workspace_id=t.workspace_id AND a.project_id=t.project_id
		 AND a.task_id=t.task_id AND a.state='active'
		JOIN agent_workflow.recovery_state rs
		  ON rs.register_name='platform-recovery-epoch'
		WHERE t.workspace_id=$1 AND t.project_id=$2 AND t.task_id=$3
		FOR UPDATE OF t,a`,
		scope.WorkspaceID, scope.ProjectID, result.TaskID,
	).Scan(&runID, &state, &capability, &recovery, &generation, &lease, &attempt, &fence, &issued, &expires, &mirroredRecovery, &resultIntakeEnabled, &databaseNow)
	if errors.Is(err, pgx.ErrNoRows) {
		// Resolve a wrong task ID through its physical attempt so the loser is
		// still retained without exposing the actual task to the caller.
		err = tx.QueryRow(ctx, `
			SELECT t.run_id
			FROM agent_workflow.worker_attempts a
			JOIN agent_workflow.agent_tasks t USING(workspace_id,project_id,task_id)
			WHERE a.workspace_id=$1 AND a.project_id=$2 AND a.physical_attempt_id=$3`,
			scope.WorkspaceID, scope.ProjectID, result.PhysicalAttemptID,
		).Scan(&runID)
		if errors.Is(err, pgx.ErrNoRows) {
			return false, problem.New(problem.CodeResourceNotFound, "")
		}
		if err != nil {
			return false, err
		}
		return r.recordDiagnosticWithRun(ctx, tx, scope, result, runID, "task")
	}
	if err != nil {
		return false, err
	}
	if !resultIntakeEnabled {
		return r.recordDiagnosticWithRun(ctx, tx, scope, result, runID, "result-intake-disabled")
	}
	if mirroredRecovery != recovery {
		return r.recordDiagnosticWithRun(ctx, tx, scope, result, runID, "scheduler-recovery-epoch")
	}
	if uint64(registerEpoch) != recovery {
		return r.recordDiagnosticWithRun(ctx, tx, scope, result, runID, "external-recovery-epoch")
	}
	confirmedEpoch, err := r.register.Current(ctx)
	if err != nil {
		return false, fmt.Errorf("confirm non-rollback recovery epoch: %w", err)
	}
	if confirmedEpoch != registerEpoch {
		return r.recordDiagnosticWithRun(ctx, tx, scope, result, runID, "recovery-epoch-changed")
	}

	reason := ""
	switch {
	case state != "leased":
		reason = "task-state"
	case recovery != result.RecoveryEpoch:
		reason = "recovery-epoch"
	case generation != result.ExecutionGeneration:
		reason = "execution-generation"
	case lease != result.LeaseEpoch:
		reason = "lease-epoch"
	case attempt != string(result.PhysicalAttemptID):
		reason = "physical-attempt"
	case fence != result.FenceToken:
		reason = "fence-token"
	case capability != result.Capability:
		reason = "capability"
	case result.CompletedAt.IsZero() || result.CompletedAt.Before(issued) || result.CompletedAt.After(databaseNow) || !databaseNow.Before(expires) || !result.CompletedAt.Before(expires):
		reason = "expired"
	}
	if reason != "" {
		return r.recordDiagnosticWithRun(ctx, tx, scope, result, runID, reason)
	}

	prefix := fmt.Sprintf("pending/%s/r%d/g%d/%s/", result.TaskID, result.RecoveryEpoch, result.ExecutionGeneration, result.PhysicalAttemptID)
	if result.ArtifactID == "" || len(result.ArtifactID) > 128 || result.BuildIdentity == "" || len(result.BuildIdentity) > 128 || !validDigest(result.ArtifactDigest) || len(result.PendingObjectKey) > 1024 || strings.Contains(result.PendingObjectKey, "..") || strings.ContainsAny(result.PendingObjectKey, "\x00\r\n") || !strings.HasPrefix(result.PendingObjectKey, prefix) {
		return false, problem.New(problem.CodeArtifactInvalid, "")
	}
	_, err = tx.Exec(ctx, `
		INSERT INTO agent_workflow.worker_results(
			workspace_id,project_id,task_id,physical_attempt_id,recovery_epoch,
			execution_generation,lease_epoch,fence_token,capability,build_identity,
			artifact_id,artifact_digest,pending_object_key,completed_at
		) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14)`,
		scope.WorkspaceID, scope.ProjectID, result.TaskID, result.PhysicalAttemptID,
		result.RecoveryEpoch, result.ExecutionGeneration, result.LeaseEpoch,
		result.FenceToken, result.Capability, result.BuildIdentity, result.ArtifactID,
		result.ArtifactDigest, result.PendingObjectKey, result.CompletedAt)
	if err != nil {
		return false, err
	}
	if err := r.fail(AfterResult); err != nil {
		return false, err
	}

	tag, err := tx.Exec(ctx, `
		UPDATE agent_artifacts.metadata
		SET state='scanning',version=version+1,updated_at=transaction_timestamp()
		WHERE workspace_id=$1 AND project_id=$2 AND artifact_id=$3
		  AND digest=$4 AND state='pending'`,
		scope.WorkspaceID, scope.ProjectID, result.ArtifactID, result.ArtifactDigest)
	if err != nil {
		return false, fmt.Errorf("promote winning artifact: %w", err)
	}
	if tag.RowsAffected() != 1 {
		return false, problem.New(problem.CodeArtifactInvalid, "")
	}
	if err := r.fail(AfterPromotion); err != nil {
		return false, err
	}

	tag, err = tx.Exec(ctx, `
		UPDATE agent_control.agent_runs
		SET state='validating',version=version+1,updated_at=transaction_timestamp()
		WHERE workspace_id=$1 AND project_id=$2 AND run_id=$3
		  AND state='executing' AND execution_generation=$4`,
		scope.WorkspaceID, scope.ProjectID, runID, result.ExecutionGeneration)
	if err != nil || tag.RowsAffected() != 1 {
		return false, affectedError("advance run", tag.RowsAffected(), err)
	}
	if err := r.fail(AfterRun); err != nil {
		return false, err
	}

	tag, err = tx.Exec(ctx, `
		UPDATE agent_control.budget_reservations
		SET released=attempt_final,updated_at=transaction_timestamp()
		WHERE workspace_id=$1 AND project_id=$2
		  AND reservation_id=(
		      SELECT reservation_id FROM agent_workflow.agent_tasks
		      WHERE workspace_id=$1 AND project_id=$2 AND task_id=$3)`,
		scope.WorkspaceID, scope.ProjectID, result.TaskID)
	if err != nil || tag.RowsAffected() != 1 {
		return false, affectedError("release reservation", tag.RowsAffected(), err)
	}
	if err := r.fail(AfterReservation); err != nil {
		return false, err
	}

	tag, err = tx.Exec(ctx, `
		UPDATE agent_workflow.agent_tasks
		SET state='completed',version=version+1,updated_at=transaction_timestamp()
		WHERE workspace_id=$1 AND project_id=$2 AND task_id=$3 AND state='leased'`,
		scope.WorkspaceID, scope.ProjectID, result.TaskID)
	if err != nil || tag.RowsAffected() != 1 {
		return false, affectedError("complete task", tag.RowsAffected(), err)
	}
	tag, err = tx.Exec(ctx, `
		UPDATE agent_workflow.worker_attempts
		SET state='accepted'
		WHERE workspace_id=$1 AND project_id=$2 AND physical_attempt_id=$3 AND state='active'`,
		scope.WorkspaceID, scope.ProjectID, result.PhysicalAttemptID)
	if err != nil || tag.RowsAffected() != 1 {
		return false, affectedError("accept physical attempt", tag.RowsAffected(), err)
	}
	return true, tx.Commit(ctx)
}

func validDigest(value string) bool {
	if len(value) != 71 || !strings.HasPrefix(value, "sha256:") {
		return false
	}
	for _, character := range value[7:] {
		if !strings.ContainsRune("0123456789abcdef", character) {
			return false
		}
	}
	return true
}

func (r *Repository) recordDiagnostic(ctx context.Context, tx pgx.Tx, scope scheduler.Scope, result scheduler.Result, reason string) (bool, error) {
	var runID string
	if err := tx.QueryRow(ctx, `
		SELECT run_id FROM agent_workflow.agent_tasks
		WHERE workspace_id=$1 AND project_id=$2 AND task_id=$3`,
		scope.WorkspaceID, scope.ProjectID, result.TaskID).Scan(&runID); err != nil {
		return false, err
	}
	return r.recordDiagnosticWithRun(ctx, tx, scope, result, runID, reason)
}

func (r *Repository) recordDiagnosticWithRun(ctx context.Context, tx pgx.Tx, scope scheduler.Scope, result scheduler.Result, runID, reason string) (bool, error) {
	_, err := tx.Exec(ctx, `
		INSERT INTO agent_workflow.result_diagnostics(
			workspace_id,project_id,task_id,run_id,physical_attempt_id,code,reason,recorded_at
		) VALUES($1,$2,$3,$4,$5,$6,$7,transaction_timestamp())`,
		scope.WorkspaceID, scope.ProjectID, result.TaskID, runID,
		result.PhysicalAttemptID, problem.CodeWorkerFenceStale, reason)
	if err != nil {
		return false, err
	}
	return false, tx.Commit(ctx)
}

func affectedError(action string, affected int64, err error) error {
	if err != nil {
		return fmt.Errorf("%s: %w", action, err)
	}
	return fmt.Errorf("%s: expected one row, affected %d", action, affected)
}

func (r *Repository) fail(point FailurePoint) error {
	if r.inject == nil {
		return nil
	}
	return r.inject(point)
}
