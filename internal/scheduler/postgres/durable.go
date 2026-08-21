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

// DurableScheduler is the fenced tool-dispatch record over the durable
// agent_workflow tables: immutable tasks, monotonic leases with fence tokens,
// insert-once accepted results, and the replayable output bytes. Nothing about
// a dispatch lives in process memory, so a replay or a service restart reads
// what already happened instead of executing again. It is the read-only
// tool-capability counterpart of the artifact-producing worker acceptance in
// Repository: kernel tools promote no artifact and advance no run, so their
// acceptance records the result and output and completes the task, nothing
// more.
type DurableScheduler struct {
	database *pgxpool.Pool
	register interface {
		Current(context.Context) (recoverypkg.Epoch, error)
	}
	ids           scheduler.IDs
	clock         scheduler.Clock
	prerequisites scheduler.Prerequisites
	ttl           time.Duration
}

func NewDurableScheduler(database *pgxpool.Pool, register interface {
	Current(context.Context) (recoverypkg.Epoch, error)
}, ids scheduler.IDs, clock scheduler.Clock, prerequisites scheduler.Prerequisites, ttl time.Duration) (*DurableScheduler, error) {
	if database == nil || register == nil || ids == nil || clock == nil || prerequisites == nil || ttl <= 0 || ttl > time.Hour {
		return nil, fmt.Errorf("durable scheduler: database, recovery register, identities, clock, prerequisites, and a bounded lease TTL are required")
	}
	return &DurableScheduler{database: database, register: register, ids: ids, clock: clock, prerequisites: prerequisites, ttl: ttl}, nil
}

func (s *DurableScheduler) Create(ctx context.Context, input scheduler.Create) (scheduler.Task, error) {
	if !input.Validate() {
		return scheduler.Task{}, problem.New(problem.CodeTaskDispatchDenied, "")
	}
	if err := s.prerequisites.AuthorizeTask(ctx, input); err != nil {
		return scheduler.Task{}, problem.New(problem.CodeTaskDispatchDenied, "")
	}
	tag, err := s.database.Exec(ctx, `INSERT INTO agent_workflow.agent_tasks(workspace_id,project_id,task_id,run_id,root_run_id,recovery_epoch,execution_generation,capability,reservation_id,input_digest,input_object_key,state,created_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,'queued',$12) ON CONFLICT (workspace_id,project_id,task_id) DO NOTHING`,
		input.Scope.WorkspaceID, input.Scope.ProjectID, input.TaskID, input.RunID, input.RootRunID, input.RecoveryEpoch, input.ExecutionGeneration, input.Capability, input.ReservationID, input.InputDigest, input.InputObjectKey, input.CreatedAt)
	if err != nil {
		return scheduler.Task{}, fmt.Errorf("record fenced task: %w", err)
	}
	task, err := s.Get(ctx, input.Scope, input.TaskID)
	if err != nil {
		return scheduler.Task{}, err
	}
	if tag.RowsAffected() == 0 {
		recorded := task.Create
		if recorded.RunID != input.RunID || recorded.RootRunID != input.RootRunID || recorded.ExecutionGeneration != input.ExecutionGeneration || recorded.Capability != input.Capability || recorded.ReservationID != input.ReservationID || recorded.InputDigest != input.InputDigest || recorded.InputObjectKey != input.InputObjectKey {
			return scheduler.Task{}, problem.New(problem.CodeIdempotencyConflict, "")
		}
	}
	return task, nil
}

func (s *DurableScheduler) Get(ctx context.Context, scope scheduler.Scope, id scheduler.TaskID) (scheduler.Task, error) {
	task := scheduler.Task{Create: scheduler.Create{Scope: scope, TaskID: id}}
	err := s.database.QueryRow(ctx, `SELECT run_id,root_run_id,recovery_epoch,execution_generation,capability,reservation_id,input_digest,input_object_key,state,lease_epoch,physical_attempts,version,created_at FROM agent_workflow.agent_tasks WHERE workspace_id=$1 AND project_id=$2 AND task_id=$3`, scope.WorkspaceID, scope.ProjectID, id).
		Scan(&task.RunID, &task.RootRunID, &task.RecoveryEpoch, &task.ExecutionGeneration, &task.Capability, &task.ReservationID, &task.InputDigest, &task.InputObjectKey, &task.State, &task.LeaseEpoch, &task.PhysicalAttempts, &task.Version, &task.CreatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return scheduler.Task{}, problem.New(problem.CodeResourceNotFound, "")
	}
	if err != nil {
		return scheduler.Task{}, fmt.Errorf("read fenced task: %w", err)
	}
	var lease scheduler.Lease
	err = s.database.QueryRow(ctx, `SELECT physical_attempt_id,attempt_number,lease_epoch,owner,issued_at,expires_at,fence_token FROM agent_workflow.worker_attempts WHERE workspace_id=$1 AND project_id=$2 AND task_id=$3 AND state='active'`, scope.WorkspaceID, scope.ProjectID, id).
		Scan(&lease.PhysicalAttemptID, &lease.AttemptNumber, &lease.LeaseEpoch, &lease.Owner, &lease.IssuedAt, &lease.ExpiresAt, &lease.FenceToken)
	if err == nil {
		lease.TaskID = id
		lease.RecoveryEpoch = task.RecoveryEpoch
		lease.ExecutionGeneration = task.ExecutionGeneration
		task.Lease = &lease
	} else if !errors.Is(err, pgx.ErrNoRows) {
		return scheduler.Task{}, fmt.Errorf("read active attempt: %w", err)
	}
	var result scheduler.Result
	err = s.database.QueryRow(ctx, `SELECT physical_attempt_id,recovery_epoch,execution_generation,lease_epoch,fence_token,capability,build_identity,artifact_id,artifact_digest,pending_object_key,completed_at FROM agent_workflow.worker_results WHERE workspace_id=$1 AND project_id=$2 AND task_id=$3`, scope.WorkspaceID, scope.ProjectID, id).
		Scan(&result.PhysicalAttemptID, &result.RecoveryEpoch, &result.ExecutionGeneration, &result.LeaseEpoch, &result.FenceToken, &result.Capability, &result.BuildIdentity, &result.ArtifactID, &result.ArtifactDigest, &result.PendingObjectKey, &result.CompletedAt)
	if err == nil {
		result.TaskID = id
		task.Result = &result
	} else if !errors.Is(err, pgx.ErrNoRows) {
		return scheduler.Task{}, fmt.Errorf("read accepted result: %w", err)
	}
	return task, nil
}

func (s *DurableScheduler) Lease(ctx context.Context, scope scheduler.Scope, id scheduler.TaskID, owner string) (scheduler.Lease, error) {
	// Lease timestamps are truncated to the microsecond resolution the durable
	// record stores, so the issued lease and its stored row stay byte-equal
	// through later renewal comparisons.
	now := s.clock.Now().UTC().Truncate(time.Microsecond)
	if now.IsZero() {
		return scheduler.Lease{}, problem.New(problem.CodeInfrastructureUnavailable, "")
	}
	if owner == "" || len(owner) > 128 {
		return scheduler.Lease{}, problem.New(problem.CodeRequestInvalid, "")
	}
	tx, err := s.database.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
	if err != nil {
		return scheduler.Lease{}, err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	var state string
	var leaseEpoch, attempts, version, recoveryEpoch, generation uint64
	err = tx.QueryRow(ctx, `SELECT state,lease_epoch,physical_attempts,version,recovery_epoch,execution_generation FROM agent_workflow.agent_tasks WHERE workspace_id=$1 AND project_id=$2 AND task_id=$3 FOR UPDATE`, scope.WorkspaceID, scope.ProjectID, id).
		Scan(&state, &leaseEpoch, &attempts, &version, &recoveryEpoch, &generation)
	if errors.Is(err, pgx.ErrNoRows) {
		return scheduler.Lease{}, problem.New(problem.CodeResourceNotFound, "")
	}
	if err != nil {
		return scheduler.Lease{}, fmt.Errorf("lock fenced task: %w", err)
	}
	if state == "leased" {
		var expires time.Time
		err := tx.QueryRow(ctx, `SELECT expires_at FROM agent_workflow.worker_attempts WHERE workspace_id=$1 AND project_id=$2 AND task_id=$3 AND state='active' FOR UPDATE`, scope.WorkspaceID, scope.ProjectID, id).Scan(&expires)
		if err == nil {
			if now.Before(expires) {
				return scheduler.Lease{}, problem.New(problem.CodeVersionConflict, "")
			}
			if _, err := tx.Exec(ctx, `UPDATE agent_workflow.worker_attempts SET state='expired' WHERE workspace_id=$1 AND project_id=$2 AND task_id=$3 AND state='active'`, scope.WorkspaceID, scope.ProjectID, id); err != nil {
				return scheduler.Lease{}, fmt.Errorf("expire stale attempt: %w", err)
			}
		} else if !errors.Is(err, pgx.ErrNoRows) {
			return scheduler.Lease{}, fmt.Errorf("read active attempt: %w", err)
		}
	} else if state != "queued" {
		return scheduler.Lease{}, problem.New(problem.CodeInvalidTransition, "")
	}
	attempt, err := s.ids.PhysicalAttemptID()
	if err != nil {
		return scheduler.Lease{}, fmt.Errorf("allocate physical attempt: %w", err)
	}
	token, err := s.ids.FenceToken()
	if err != nil {
		return scheduler.Lease{}, fmt.Errorf("allocate fence token: %w", err)
	}
	if len(token) < 16 || len(token) > 512 || strings.ContainsAny(token, "\x00\r\n") {
		return scheduler.Lease{}, fmt.Errorf("allocate fence token: token is invalid")
	}
	lease := scheduler.Lease{TaskID: id, RecoveryEpoch: recoveryEpoch, ExecutionGeneration: generation, PhysicalAttemptID: attempt, AttemptNumber: attempts + 1, LeaseEpoch: leaseEpoch + 1, Owner: owner, IssuedAt: now, ExpiresAt: now.Add(s.ttl), FenceToken: token}
	if _, err := tx.Exec(ctx, `INSERT INTO agent_workflow.worker_attempts(workspace_id,project_id,task_id,physical_attempt_id,recovery_epoch,execution_generation,attempt_number,lease_epoch,owner,issued_at,expires_at,fence_token,state) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,'active')`,
		scope.WorkspaceID, scope.ProjectID, id, lease.PhysicalAttemptID, lease.RecoveryEpoch, lease.ExecutionGeneration, lease.AttemptNumber, lease.LeaseEpoch, owner, lease.IssuedAt, lease.ExpiresAt, token); err != nil {
		return scheduler.Lease{}, fmt.Errorf("record fenced attempt: %w", err)
	}
	if _, err := tx.Exec(ctx, `UPDATE agent_workflow.agent_tasks SET state='leased',lease_epoch=$4,physical_attempts=$5,version=version+1,updated_at=transaction_timestamp() WHERE workspace_id=$1 AND project_id=$2 AND task_id=$3`,
		scope.WorkspaceID, scope.ProjectID, id, lease.LeaseEpoch, lease.AttemptNumber); err != nil {
		return scheduler.Lease{}, fmt.Errorf("record fenced lease: %w", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return scheduler.Lease{}, err
	}
	return lease, nil
}

func (s *DurableScheduler) ReclaimExpired(ctx context.Context, scope scheduler.Scope, id scheduler.TaskID) (bool, error) {
	now := s.clock.Now().UTC()
	if now.IsZero() {
		return false, problem.New(problem.CodeInfrastructureUnavailable, "")
	}
	tx, err := s.database.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
	if err != nil {
		return false, err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	var state string
	err = tx.QueryRow(ctx, `SELECT state FROM agent_workflow.agent_tasks WHERE workspace_id=$1 AND project_id=$2 AND task_id=$3 FOR UPDATE`, scope.WorkspaceID, scope.ProjectID, id).Scan(&state)
	if errors.Is(err, pgx.ErrNoRows) {
		return false, problem.New(problem.CodeResourceNotFound, "")
	}
	if err != nil {
		return false, fmt.Errorf("lock fenced task: %w", err)
	}
	if state != "leased" {
		return false, nil
	}
	var expires time.Time
	err = tx.QueryRow(ctx, `SELECT expires_at FROM agent_workflow.worker_attempts WHERE workspace_id=$1 AND project_id=$2 AND task_id=$3 AND state='active' FOR UPDATE`, scope.WorkspaceID, scope.ProjectID, id).Scan(&expires)
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return false, fmt.Errorf("read active attempt: %w", err)
	}
	if err == nil && now.Before(expires) {
		return false, nil
	}
	if err == nil {
		if _, err := tx.Exec(ctx, `UPDATE agent_workflow.worker_attempts SET state='expired' WHERE workspace_id=$1 AND project_id=$2 AND task_id=$3 AND state='active'`, scope.WorkspaceID, scope.ProjectID, id); err != nil {
			return false, fmt.Errorf("expire stale attempt: %w", err)
		}
	}
	if _, err := tx.Exec(ctx, `UPDATE agent_workflow.agent_tasks SET state='queued',version=version+1,updated_at=transaction_timestamp() WHERE workspace_id=$1 AND project_id=$2 AND task_id=$3`, scope.WorkspaceID, scope.ProjectID, id); err != nil {
		return false, fmt.Errorf("requeue fenced task: %w", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return false, err
	}
	return true, nil
}

// Heartbeat extends the active lease's expiry under the full lease identity.
// Renewal is a fenced compare-and-set: the exact physical attempt, lease
// epoch, fence token, owner, and expected expiry must all still be current,
// and an expired, reclaimed, or superseded lease is never revived. Timestamps
// are compared at microsecond precision, the resolution the durable record
// stores.
func (s *DurableScheduler) Heartbeat(ctx context.Context, scope scheduler.Scope, lease scheduler.Lease, expectedExpiry time.Time) (scheduler.Lease, error) {
	now := s.clock.Now().UTC()
	if now.IsZero() {
		return scheduler.Lease{}, problem.New(problem.CodeInfrastructureUnavailable, "")
	}
	tx, err := s.database.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
	if err != nil {
		return scheduler.Lease{}, err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	var state string
	err = tx.QueryRow(ctx, `SELECT state FROM agent_workflow.agent_tasks WHERE workspace_id=$1 AND project_id=$2 AND task_id=$3 FOR UPDATE`, scope.WorkspaceID, scope.ProjectID, lease.TaskID).Scan(&state)
	if errors.Is(err, pgx.ErrNoRows) {
		return scheduler.Lease{}, problem.New(problem.CodeWorkerFenceStale, "")
	}
	if err != nil {
		return scheduler.Lease{}, fmt.Errorf("lock fenced task for renewal: %w", err)
	}
	var attempt, fence, owner string
	var leaseEpoch uint64
	var issued, expires time.Time
	err = tx.QueryRow(ctx, `SELECT physical_attempt_id,lease_epoch,owner,issued_at,expires_at,fence_token FROM agent_workflow.worker_attempts WHERE workspace_id=$1 AND project_id=$2 AND task_id=$3 AND state='active' FOR UPDATE`, scope.WorkspaceID, scope.ProjectID, lease.TaskID).
		Scan(&attempt, &leaseEpoch, &owner, &issued, &expires, &fence)
	if errors.Is(err, pgx.ErrNoRows) {
		return scheduler.Lease{}, problem.New(problem.CodeWorkerFenceStale, "")
	}
	if err != nil {
		return scheduler.Lease{}, fmt.Errorf("read active attempt for renewal: %w", err)
	}
	if state != "leased" ||
		attempt != string(lease.PhysicalAttemptID) ||
		leaseEpoch != lease.LeaseEpoch ||
		owner != lease.Owner ||
		fence != lease.FenceToken ||
		!expires.Equal(expectedExpiry.UTC().Truncate(time.Microsecond)) ||
		!now.Before(expires) {
		return scheduler.Lease{}, problem.New(problem.CodeWorkerFenceStale, "")
	}
	renewed := now.Add(s.ttl).Truncate(time.Microsecond)
	if _, err := tx.Exec(ctx, `UPDATE agent_workflow.worker_attempts SET expires_at=$4 WHERE workspace_id=$1 AND project_id=$2 AND physical_attempt_id=$3 AND state='active'`,
		scope.WorkspaceID, scope.ProjectID, attempt, renewed); err != nil {
		return scheduler.Lease{}, fmt.Errorf("renew fenced lease: %w", err)
	}
	if _, err := tx.Exec(ctx, `UPDATE agent_workflow.agent_tasks SET version=version+1,updated_at=transaction_timestamp() WHERE workspace_id=$1 AND project_id=$2 AND task_id=$3`,
		scope.WorkspaceID, scope.ProjectID, lease.TaskID); err != nil {
		return scheduler.Lease{}, fmt.Errorf("record fenced renewal: %w", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return scheduler.Lease{}, err
	}
	next := lease
	next.IssuedAt = issued
	next.ExpiresAt = renewed
	return next, nil
}

// AcceptResult commits the immutable result, the replayable output, task
// completion, and attempt acceptance atomically under the full fence:
// recovery epoch (mirror and external register), execution generation, lease
// epoch, physical attempt, fence token, capability, and lease window. Every
// non-current result is retained as a diagnostic and changes no state.
func (s *DurableScheduler) AcceptResult(ctx context.Context, scope scheduler.Scope, result scheduler.Result, output []byte) (scheduler.Acceptance, error) {
	if scheduler.OutputDigest(output) != result.ArtifactDigest {
		return scheduler.Acceptance{}, problem.New(problem.CodeArtifactInvalid, "")
	}
	registerEpoch, err := s.register.Current(ctx)
	if err != nil {
		return scheduler.Acceptance{}, fmt.Errorf("read non-rollback recovery epoch: %w", err)
	}
	tx, err := s.database.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.Serializable})
	if err != nil {
		return scheduler.Acceptance{}, err
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
			         AND pending_object_key=$13)`,
		scope.WorkspaceID, scope.ProjectID, result.TaskID, result.PhysicalAttemptID,
		result.RecoveryEpoch, result.ExecutionGeneration, result.LeaseEpoch,
		result.FenceToken, result.Capability, result.BuildIdentity, result.ArtifactID,
		result.ArtifactDigest, result.PendingObjectKey,
	).Scan(&anyResult, &exactResult)
	if err != nil {
		return scheduler.Acceptance{}, err
	}
	if exactResult {
		if err := tx.Commit(ctx); err != nil {
			return scheduler.Acceptance{}, err
		}
		return scheduler.Acceptance{Duplicate: true}, nil
	}
	if anyResult {
		return s.diagnose(ctx, tx, scope, result, "result-conflict")
	}
	var state, capability, attempt, fence string
	var recovery, generation, lease uint64
	var mirroredRecovery uint64
	var resultIntakeEnabled bool
	var issued, expires, databaseNow time.Time
	err = tx.QueryRow(ctx, `
		SELECT t.state,t.capability,t.recovery_epoch,t.execution_generation,
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
	).Scan(&state, &capability, &recovery, &generation, &lease, &attempt, &fence, &issued, &expires, &mirroredRecovery, &resultIntakeEnabled, &databaseNow)
	if errors.Is(err, pgx.ErrNoRows) {
		return scheduler.Acceptance{}, problem.New(problem.CodeResourceNotFound, "")
	}
	if err != nil {
		return scheduler.Acceptance{}, err
	}
	reason := ""
	switch {
	case !resultIntakeEnabled:
		reason = "result-intake-disabled"
	case mirroredRecovery != recovery:
		reason = "scheduler-recovery-epoch"
	case uint64(registerEpoch) != recovery:
		reason = "external-recovery-epoch"
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
		return s.diagnose(ctx, tx, scope, result, reason)
	}
	prefix := fmt.Sprintf("pending/%s/r%d/g%d/%s/", result.TaskID, result.RecoveryEpoch, result.ExecutionGeneration, result.PhysicalAttemptID)
	if result.ArtifactID == "" || len(result.ArtifactID) > 128 || result.BuildIdentity == "" || len(result.BuildIdentity) > 128 || len(result.PendingObjectKey) > 1024 || strings.Contains(result.PendingObjectKey, "..") || strings.ContainsAny(result.PendingObjectKey, "\x00\r\n") || !strings.HasPrefix(result.PendingObjectKey, prefix) {
		return scheduler.Acceptance{}, problem.New(problem.CodeArtifactInvalid, "")
	}
	if _, err := tx.Exec(ctx, `
		INSERT INTO agent_workflow.worker_results(
			workspace_id,project_id,task_id,physical_attempt_id,recovery_epoch,
			execution_generation,lease_epoch,fence_token,capability,build_identity,
			artifact_id,artifact_digest,pending_object_key,completed_at
		) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14)`,
		scope.WorkspaceID, scope.ProjectID, result.TaskID, result.PhysicalAttemptID,
		result.RecoveryEpoch, result.ExecutionGeneration, result.LeaseEpoch,
		result.FenceToken, result.Capability, result.BuildIdentity, result.ArtifactID,
		result.ArtifactDigest, result.PendingObjectKey, result.CompletedAt); err != nil {
		return scheduler.Acceptance{}, err
	}
	if _, err := tx.Exec(ctx, `INSERT INTO agent_workflow.worker_outputs(workspace_id,project_id,task_id,output,output_digest) VALUES($1,$2,$3,$4,$5)`,
		scope.WorkspaceID, scope.ProjectID, result.TaskID, output, result.ArtifactDigest); err != nil {
		return scheduler.Acceptance{}, fmt.Errorf("record replayable output: %w", err)
	}
	if _, err := tx.Exec(ctx, `UPDATE agent_workflow.agent_tasks SET state='completed',version=version+1,updated_at=transaction_timestamp() WHERE workspace_id=$1 AND project_id=$2 AND task_id=$3 AND state='leased'`,
		scope.WorkspaceID, scope.ProjectID, result.TaskID); err != nil {
		return scheduler.Acceptance{}, fmt.Errorf("complete fenced task: %w", err)
	}
	if _, err := tx.Exec(ctx, `UPDATE agent_workflow.worker_attempts SET state='accepted' WHERE workspace_id=$1 AND project_id=$2 AND physical_attempt_id=$3 AND state='active'`,
		scope.WorkspaceID, scope.ProjectID, result.PhysicalAttemptID); err != nil {
		return scheduler.Acceptance{}, fmt.Errorf("accept physical attempt: %w", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return scheduler.Acceptance{}, err
	}
	return scheduler.Acceptance{Accepted: true}, nil
}

func (s *DurableScheduler) diagnose(ctx context.Context, tx pgx.Tx, scope scheduler.Scope, result scheduler.Result, reason string) (scheduler.Acceptance, error) {
	var runID string
	if err := tx.QueryRow(ctx, `SELECT run_id FROM agent_workflow.agent_tasks WHERE workspace_id=$1 AND project_id=$2 AND task_id=$3`, scope.WorkspaceID, scope.ProjectID, result.TaskID).Scan(&runID); err != nil {
		return scheduler.Acceptance{}, err
	}
	if _, err := tx.Exec(ctx, `
		INSERT INTO agent_workflow.result_diagnostics(
			workspace_id,project_id,task_id,run_id,physical_attempt_id,code,reason,recorded_at
		) VALUES($1,$2,$3,$4,$5,$6,$7,transaction_timestamp())`,
		scope.WorkspaceID, scope.ProjectID, result.TaskID, runID,
		result.PhysicalAttemptID, problem.CodeWorkerFenceStale, reason); err != nil {
		return scheduler.Acceptance{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return scheduler.Acceptance{}, err
	}
	return scheduler.Acceptance{}, problem.New(problem.CodeWorkerFenceStale, "")
}

// AcceptedOutput answers the accepted result and its recorded replayable
// output for one completed task.
func (s *DurableScheduler) AcceptedOutput(ctx context.Context, scope scheduler.Scope, id scheduler.TaskID) ([]byte, scheduler.Result, error) {
	result := scheduler.Result{TaskID: id}
	var output []byte
	err := s.database.QueryRow(ctx, `
		SELECT r.physical_attempt_id,r.recovery_epoch,r.execution_generation,r.lease_epoch,r.fence_token,r.capability,r.build_identity,r.artifact_id,r.artifact_digest,r.pending_object_key,r.completed_at,o.output
		FROM agent_workflow.worker_results r
		JOIN agent_workflow.worker_outputs o
		  ON o.workspace_id=r.workspace_id AND o.project_id=r.project_id AND o.task_id=r.task_id
		WHERE r.workspace_id=$1 AND r.project_id=$2 AND r.task_id=$3`,
		scope.WorkspaceID, scope.ProjectID, id).
		Scan(&result.PhysicalAttemptID, &result.RecoveryEpoch, &result.ExecutionGeneration, &result.LeaseEpoch, &result.FenceToken, &result.Capability, &result.BuildIdentity, &result.ArtifactID, &result.ArtifactDigest, &result.PendingObjectKey, &result.CompletedAt, &output)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, scheduler.Result{}, problem.New(problem.CodeResourceNotFound, "")
	}
	if err != nil {
		return nil, scheduler.Result{}, fmt.Errorf("read accepted output: %w", err)
	}
	return output, result, nil
}
