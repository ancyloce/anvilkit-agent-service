// Package postgres is the durable record of logical tasks and physical
// attempts. Every transition a dispatched turn depends on happens inside one
// serializable transaction here, because each of them is a decision two
// processes could otherwise make at the same time: which execution is current,
// and which result is allowed to change state.
package postgres

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/ancyloce/anvilkit-agent-service/internal/dispatch"
	"github.com/ancyloce/anvilkit-agent-service/internal/problem"
)

// Repository implements the dispatch record over the workflow database.
type Repository struct{ database *pgxpool.Pool }

func New(database *pgxpool.Pool) (*Repository, error) {
	if database == nil {
		return nil, fmt.Errorf("dispatch repository: the workflow database is required")
	}
	return &Repository{database: database}, nil
}

// serializationAttempts bounds how many times one transaction is re-run after
// PostgreSQL aborts it for a conflict with a concurrent transaction.
const serializationAttempts = 4

// serializable runs one operation inside a serializable transaction and
// re-runs it when PostgreSQL aborts the transaction for a serialization or
// deadlock conflict (SQLSTATE 40001 or 40P01).
//
// Every transaction in this file is safe to re-run from the top: each reads
// the authoritative rows under lock before deciding anything, so a re-run
// either reaches the decision the aborted run would have reached or observes
// what the concurrent writer did and decides against it — EnsureTask finds the
// task it would have created, Commit finds the registration or the transition
// that beat it and records evidence, MarkDispatched and CloseAttempt find the
// attempt no longer open. What must not happen is the conflict itself being
// reported as the outcome of the dispatch: a result that would have settled
// on a re-read failing the turn instead is a run failed for a reason that had
// nothing to do with the work.
func (r *Repository) serializable(ctx context.Context, operation func(tx pgx.Tx) error) error {
	var err error
	for attempt := 1; attempt <= serializationAttempts; attempt++ {
		err = r.once(ctx, operation)
		if err == nil || !serializationFailure(err) || ctx.Err() != nil {
			return err
		}
	}
	return err
}

func (r *Repository) once(ctx context.Context, operation func(tx pgx.Tx) error) error {
	tx, err := r.database.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.Serializable})
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if err := operation(tx); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

// serializationFailure reports whether PostgreSQL aborted the transaction for
// a conflict a re-run resolves, as distinct from an error the re-run would
// simply repeat.
func serializationFailure(err error) bool {
	var postgresError *pgconn.PgError
	if !errors.As(err, &postgresError) {
		return false
	}
	return postgresError.Code == "40001" || postgresError.Code == "40P01"
}

func (r *Repository) EnsureTask(ctx context.Context, task dispatch.Task) (dispatch.Task, error) {
	if err := task.Validate(); err != nil {
		return dispatch.Task{}, err
	}
	var stored dispatch.Task
	err := r.serializable(ctx, func(tx pgx.Tx) error {
		existing, found, err := readTask(ctx, tx, task.Scope, task.TaskID, true)
		if err != nil {
			return err
		}
		if found {
			if err := sameWork(existing, task); err != nil {
				return err
			}
			stored = existing
			return nil
		}
		if _, err := tx.Exec(ctx, `
			INSERT INTO agent_workflow.runtime_tasks(
				workspace_id,project_id,task_id,run_id,root_run_id,execution_generation,definition_digest,
				runtime_unit_id,runtime_manifest_digest,runtime_image_digest,invocation_protocol_digest,runtime_audience,
				capability,request_digest,status,attempts,lease_epoch,expires_at,created_at,updated_at)
			VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,0,0,$16,$17,$17)`,
			task.Scope.WorkspaceID, task.Scope.ProjectID, task.TaskID, task.RunID, task.RootRunID,
			int64(task.ExecutionGeneration), task.DefinitionDigest,
			task.Runtime.RuntimeUnitID, task.Runtime.RuntimeManifestDigest, task.Runtime.RuntimeImageDigest,
			task.Runtime.InvocationProtocolDigest, task.Runtime.RuntimeAudience,
			task.Capability, task.RequestDigest, string(dispatch.Accepted), task.ExpiresAt, task.CreatedAt,
		); err != nil {
			return fmt.Errorf("create logical task: %w", err)
		}
		stored, _, err = readTask(ctx, tx, task.Scope, task.TaskID, false)
		return err
	})
	if err != nil {
		return dispatch.Task{}, err
	}
	return stored, nil
}

// sameWork proves a repeated creation is the same work rather than a reused
// identity. The comparison is deliberately field by field: a task that agrees
// on identity and disagrees on which release may execute it is the case where
// silently returning the stored row would dispatch work somewhere nobody
// approved.
func sameWork(existing, offered dispatch.Task) error {
	for _, comparison := range []struct {
		field            string
		wanted, observed string
	}{
		{"run", existing.RunID, offered.RunID},
		{"definition digest", existing.DefinitionDigest, offered.DefinitionDigest},
		{"request digest", existing.RequestDigest, offered.RequestDigest},
		{"runtime unit", existing.Runtime.RuntimeUnitID, offered.Runtime.RuntimeUnitID},
		{"runtime manifest digest", existing.Runtime.RuntimeManifestDigest, offered.Runtime.RuntimeManifestDigest},
		{"runtime image digest", existing.Runtime.RuntimeImageDigest, offered.Runtime.RuntimeImageDigest},
		{"capability", existing.Capability, offered.Capability},
	} {
		if comparison.wanted != comparison.observed {
			details := problem.New(problem.CodeIdempotencyKeyReused, "")
			details.Detail = "the task identity was reused with a different " + comparison.field
			return details
		}
	}
	if existing.ExecutionGeneration != offered.ExecutionGeneration {
		details := problem.New(problem.CodeIdempotencyKeyReused, "")
		details.Detail = "the task identity was reused under a different execution generation"
		return details
	}
	return nil
}

func (r *Repository) OpenAttempt(ctx context.Context, open dispatch.Open) (dispatch.Task, dispatch.Attempt, error) {
	if !dispatch.ValidReasonCode(open.SupersededReason) {
		return dispatch.Task{}, dispatch.Attempt{}, fmt.Errorf("dispatch attempt: a stable supersession reason code is required")
	}
	var task dispatch.Task
	var attempt dispatch.Attempt
	err := r.serializable(ctx, func(tx pgx.Tx) error {
		stored, found, err := readTask(ctx, tx, open.Scope, open.TaskID, true)
		if err != nil {
			return err
		}
		if !found {
			return notFound("the task does not exist")
		}
		if stored.Status.Terminal() {
			return refused("the task already reached a terminal state and admits no further execution")
		}
		// The supersession runs first and in the same transaction as the insert:
		// the partial unique index admits one current attempt per task, so an open
		// that did not close the previous one would be rejected by the database
		// rather than producing two live executions.
		//
		// An attempt found past its own deadline expired; it was not replaced by a
		// decision anyone made, and the record says which of the two happened.
		if _, err := tx.Exec(ctx, `
			UPDATE agent_workflow.runtime_attempts
			   SET dispatch_status = CASE WHEN expires_at < $6 THEN $7 ELSE $4 END,
			       failure_reason  = CASE WHEN expires_at < $6 THEN $8 ELSE $5 END,
			       finished_at=$6, updated_at=$6
			 WHERE workspace_id=$1 AND project_id=$2 AND task_id=$3
			   AND dispatch_status IN ('accepted','running')`,
			open.Scope.WorkspaceID, open.Scope.ProjectID, open.TaskID,
			string(dispatch.Superseded), open.SupersededReason, open.At,
			string(dispatch.Expired), dispatch.ReasonDeadlineExceeded,
		); err != nil {
			return fmt.Errorf("supersede the current attempt: %w", err)
		}
		number := stored.Attempts + 1
		epoch := stored.LeaseEpoch + 1
		attemptID := dispatch.AttemptID(stored.TaskID, number)
		// The logical task lives as long as the execution it currently has. A task
		// whose deadline stayed at its first attempt's would make every
		// replacement uncommittable the moment the first lease ran out, which is
		// exactly when replacements are needed.
		if _, err := tx.Exec(ctx, `
			UPDATE agent_workflow.runtime_tasks
			   SET attempts=$4, lease_epoch=$5, expires_at=$7, updated_at=$6
			 WHERE workspace_id=$1 AND project_id=$2 AND task_id=$3`,
			open.Scope.WorkspaceID, open.Scope.ProjectID, open.TaskID, int64(number), int64(epoch), open.At, open.ExpiresAt,
		); err != nil {
			return fmt.Errorf("advance the task lease: %w", err)
		}
		if _, err := tx.Exec(ctx, `
			INSERT INTO agent_workflow.runtime_attempts(
				workspace_id,project_id,physical_attempt_id,task_id,attempt_number,lease_epoch,
				fence_token_digest,runtime_unit_id,dispatch_status,expires_at,created_at,updated_at)
			VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$11)`,
			open.Scope.WorkspaceID, open.Scope.ProjectID, attemptID, open.TaskID, int64(number), int64(epoch),
			open.FenceTokenDigest, open.RuntimeUnitID, string(dispatch.Accepted), open.ExpiresAt, open.At,
		); err != nil {
			return fmt.Errorf("open a physical attempt: %w", err)
		}
		// The returned task is the record as this transaction left it, deadline
		// included: a caller reading the task's expiry must see the lease the
		// attempt it was just handed runs under, not the previous one.
		stored.Attempts, stored.LeaseEpoch, stored.UpdatedAt, stored.ExpiresAt = number, epoch, open.At, open.ExpiresAt
		opened, _, err := readAttempt(ctx, tx, open.Scope, attemptID, false)
		if err != nil {
			return err
		}
		task, attempt = stored, opened
		return nil
	})
	if err != nil {
		return dispatch.Task{}, dispatch.Attempt{}, err
	}
	return task, attempt, nil
}

func (r *Repository) MarkDispatched(ctx context.Context, scope dispatch.Scope, attemptID string, at time.Time) error {
	return r.serializable(ctx, func(tx pgx.Tx) error {
		tag, err := tx.Exec(ctx, `
			UPDATE agent_workflow.runtime_attempts
			   SET dispatch_status=$4, dispatched_at=$5, started_at=$5, updated_at=$5
			 WHERE workspace_id=$1 AND project_id=$2 AND physical_attempt_id=$3
			   AND dispatch_status='accepted'`,
			scope.WorkspaceID, scope.ProjectID, attemptID, string(dispatch.Running), at)
		if err != nil {
			return fmt.Errorf("record the dispatch: %w", err)
		}
		if tag.RowsAffected() == 0 {
			return refused("the attempt is no longer accepting a dispatch")
		}
		if _, err := tx.Exec(ctx, `
			UPDATE agent_workflow.runtime_tasks t
			   SET status=$4, updated_at=$5
			  FROM agent_workflow.runtime_attempts a
			 WHERE a.workspace_id=t.workspace_id AND a.project_id=t.project_id AND a.task_id=t.task_id
			   AND a.workspace_id=$1 AND a.project_id=$2 AND a.physical_attempt_id=$3
			   AND t.status='accepted'`,
			scope.WorkspaceID, scope.ProjectID, attemptID, string(dispatch.Running), at,
		); err != nil {
			return fmt.Errorf("advance the task to running: %w", err)
		}
		return nil
	})
}

// CloseAttempt ends an open attempt as failed with a stable reason, and
// touches nothing else: the task stays open, exactly as it does for an
// execution the runtime itself reported failed, because whether the work is
// tried again is the workflow's decision. Closing an attempt that already
// reached a terminal state changes nothing — whatever ended it first stands.
func (r *Repository) CloseAttempt(ctx context.Context, scope dispatch.Scope, attemptID, reason string, at time.Time) error {
	if !dispatch.ValidReasonCode(reason) {
		return fmt.Errorf("dispatch attempt: a stable close reason code is required")
	}
	return r.serializable(ctx, func(tx pgx.Tx) error {
		attempt, found, err := readAttempt(ctx, tx, scope, attemptID, true)
		if err != nil {
			return err
		}
		if !found {
			return notFound("the attempt does not exist")
		}
		if attempt.Status.Terminal() {
			return nil
		}
		if _, err := tx.Exec(ctx, `
			UPDATE agent_workflow.runtime_attempts
			   SET dispatch_status=$4, failure_reason=$5, finished_at=$6, updated_at=$6
			 WHERE workspace_id=$1 AND project_id=$2 AND physical_attempt_id=$3
			   AND dispatch_status IN ('accepted','running')`,
			scope.WorkspaceID, scope.ProjectID, attemptID, string(dispatch.Failed), reason, at,
		); err != nil {
			return fmt.Errorf("close the physical attempt: %w", err)
		}
		return nil
	})
}

// Commit is the fenced conditional commit. It reads the authoritative task,
// attempt, and registered result under row locks, evaluates the canonical
// predicate against them, and then either registers the outcome and transitions
// both records, or records evidence — never both, and never neither.
func (r *Repository) Commit(ctx context.Context, request dispatch.Settle) (dispatch.Result, error) {
	var result dispatch.Result
	err := r.serializable(ctx, func(tx pgx.Tx) error {
		task, found, err := readTask(ctx, tx, request.Scope, request.Predicate.TaskID, true)
		if err != nil {
			return err
		}
		if !found {
			return notFound("the task does not exist")
		}
		attempt, attemptFound, err := readAttempt(ctx, tx, request.Scope, request.Predicate.PhysicalAttemptID, true)
		if err != nil {
			return err
		}
		if !attemptFound || attempt.TaskID != task.TaskID {
			if err := writeEvidence(ctx, tx, evidenceOf(request, dispatch.DispositionUnbound, "the attempt does not exist", request.Outcome.ObservedAt)); err != nil {
				return err
			}
			result = dispatch.Result{Disposition: dispatch.DispositionUnbound, Reason: "the attempt does not exist", Task: task}
			return nil
		}
		registration, settled, err := readRegistration(ctx, tx, request.Scope, task.TaskID)
		if err != nil {
			return err
		}
		var committed *dispatch.Registration
		if settled {
			committed = &registration
		}
		disposition, reason := dispatch.Evaluate(task, attempt, committed, request, request.Outcome.ObservedAt)
		if !disposition.Committed() {
			if err := writeEvidence(ctx, tx, evidenceOf(request, disposition, reason, request.Outcome.ObservedAt)); err != nil {
				return err
			}
			// An expiry discovered here is also recorded as one: the attempt, and
			// the task if its own deadline has passed, stop being open work rather
			// than staying accepted for ever.
			if disposition == dispatch.DispositionExpired {
				if err := expire(ctx, tx, request.Scope, task, attempt, request.Outcome.ObservedAt); err != nil {
					return err
				}
			}
			result = dispatch.Result{Disposition: disposition, Reason: reason, Task: task, Attempt: attempt}
			return nil
		}
		outcome := dispatch.Succeeded
		failureReason := ""
		if request.Outcome.Failed {
			outcome, failureReason = dispatch.Failed, request.Outcome.ReasonCode
		}
		if _, err := tx.Exec(ctx, `
			UPDATE agent_workflow.runtime_attempts
			   SET dispatch_status=$4, result_statement_digest=$5, signature_key_id=$6,
			       failure_reason=NULLIF($7,''), finished_at=$8, updated_at=$8
			 WHERE workspace_id=$1 AND project_id=$2 AND physical_attempt_id=$3`,
			request.Scope.WorkspaceID, request.Scope.ProjectID, attempt.PhysicalAttemptID,
			string(outcome), request.Outcome.ResultStatementDigest, request.Outcome.SignatureKeyID,
			failureReason, request.Outcome.ObservedAt,
		); err != nil {
			return fmt.Errorf("settle the physical attempt: %w", err)
		}
		attempt.Status = outcome
		attempt.ResultStatementDigest = request.Outcome.ResultStatementDigest
		attempt.SignatureKeyID = request.Outcome.SignatureKeyID
		attempt.FailureReason = failureReason
		attempt.FinishedAt, attempt.UpdatedAt = request.Outcome.ObservedAt, request.Outcome.ObservedAt
		if request.Outcome.Failed {
			// A failed execution closes the attempt and nothing else. Whether the
			// work is tried again is the workflow's decision, not this record's,
			// so the task stays open for a replacement and registers no outcome —
			// a failure is not the task's answer. A task nobody tries again stops
			// being committable at its own deadline.
			result = dispatch.Result{Task: task, Attempt: attempt}
			return nil
		}
		if _, err := tx.Exec(ctx, `
			UPDATE agent_workflow.runtime_tasks SET status=$4, updated_at=$5
			 WHERE workspace_id=$1 AND project_id=$2 AND task_id=$3`,
			request.Scope.WorkspaceID, request.Scope.ProjectID, task.TaskID, string(outcome), request.Outcome.ObservedAt,
		); err != nil {
			return fmt.Errorf("settle the logical task: %w", err)
		}
		if _, err := tx.Exec(ctx, `
			INSERT INTO agent_workflow.runtime_results(
				workspace_id,project_id,task_id,physical_attempt_id,attempt_number,lease_epoch,execution_generation,
				result_statement_digest,signature_key_id,statement,status,reason_code,committed_at)
			VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13)`,
			request.Scope.WorkspaceID, request.Scope.ProjectID, task.TaskID, attempt.PhysicalAttemptID,
			int64(attempt.AttemptNumber), int64(attempt.LeaseEpoch), int64(task.ExecutionGeneration),
			request.Outcome.ResultStatementDigest, request.Outcome.SignatureKeyID, request.Outcome.Statement,
			request.Outcome.Status, request.Outcome.ReasonCode, request.Outcome.ObservedAt,
		); err != nil {
			return fmt.Errorf("register the result statement: %w", err)
		}
		task.Status, task.UpdatedAt = outcome, request.Outcome.ObservedAt
		result = dispatch.Result{Task: task, Attempt: attempt}
		return nil
	})
	if err != nil {
		return dispatch.Result{}, err
	}
	return result, nil
}

func (r *Repository) RecordEvidence(ctx context.Context, evidence dispatch.Evidence) error {
	return r.serializable(ctx, func(tx pgx.Tx) error {
		return writeEvidence(ctx, tx, evidence)
	})
}

// CancelRun revokes every open task and attempt of one run. It reports how many
// executions were still open, because a cancellation that arrived while a
// runtime was mid-execution is not the same event as one that arrived when
// nothing was running, and the caller decides what to do about the difference.
func (r *Repository) CancelRun(ctx context.Context, scope dispatch.Scope, runID, reason string, at time.Time) (int, error) {
	if !dispatch.ValidReasonCode(reason) {
		return 0, fmt.Errorf("dispatch cancellation: a stable reason code is required")
	}
	open := 0
	err := r.serializable(ctx, func(tx pgx.Tx) error {
		tag, err := tx.Exec(ctx, `
			UPDATE agent_workflow.runtime_attempts a
			   SET dispatch_status=$4, failure_reason=$5, finished_at=$6, updated_at=$6
			  FROM agent_workflow.runtime_tasks t
			 WHERE t.workspace_id=a.workspace_id AND t.project_id=a.project_id AND t.task_id=a.task_id
			   AND a.workspace_id=$1 AND a.project_id=$2 AND t.run_id=$3
			   AND a.dispatch_status IN ('accepted','running')`,
			scope.WorkspaceID, scope.ProjectID, runID, string(dispatch.Canceled), reason, at)
		if err != nil {
			return fmt.Errorf("revoke runtime leases: %w", err)
		}
		if _, err := tx.Exec(ctx, `
			UPDATE agent_workflow.runtime_tasks SET status=$4, updated_at=$5
			 WHERE workspace_id=$1 AND project_id=$2 AND run_id=$3 AND status IN ('accepted','running')`,
			scope.WorkspaceID, scope.ProjectID, runID, string(dispatch.Canceled), at,
		); err != nil {
			return fmt.Errorf("cancel runtime tasks: %w", err)
		}
		open = int(tag.RowsAffected())
		return nil
	})
	if err != nil {
		return 0, err
	}
	return open, nil
}

func (r *Repository) Load(ctx context.Context, scope dispatch.Scope, taskID string) (dispatch.Task, []dispatch.Attempt, bool, error) {
	task, found, err := readTask(ctx, r.database, scope, taskID, false)
	if err != nil || !found {
		return dispatch.Task{}, nil, found, err
	}
	rows, err := r.database.Query(ctx, attemptColumns+` WHERE workspace_id=$1 AND project_id=$2 AND task_id=$3 ORDER BY attempt_number`,
		scope.WorkspaceID, scope.ProjectID, taskID)
	if err != nil {
		return dispatch.Task{}, nil, false, fmt.Errorf("read physical attempts: %w", err)
	}
	defer rows.Close()
	attempts := make([]dispatch.Attempt, 0, 4)
	for rows.Next() {
		attempt, err := scanAttempt(scope, rows)
		if err != nil {
			return dispatch.Task{}, nil, false, err
		}
		attempts = append(attempts, attempt)
	}
	if err := rows.Err(); err != nil {
		return dispatch.Task{}, nil, false, fmt.Errorf("read physical attempts: %w", err)
	}
	return task, attempts, true, nil
}

// querier is the shared surface of a pool and a transaction, so the readers
// below serve both the locked path inside a transaction and the plain read.
type querier interface {
	Query(context.Context, string, ...any) (pgx.Rows, error)
	QueryRow(context.Context, string, ...any) pgx.Row
}

const taskColumns = `
	SELECT task_id,run_id,root_run_id,execution_generation,definition_digest,
	       runtime_unit_id,runtime_manifest_digest,runtime_image_digest,invocation_protocol_digest,runtime_audience,
	       capability,request_digest,status,attempts,lease_epoch,expires_at,created_at,updated_at
	  FROM agent_workflow.runtime_tasks`

const attemptColumns = `
	SELECT physical_attempt_id,task_id,attempt_number,lease_epoch,fence_token_digest,runtime_unit_id,
	       dispatch_status,COALESCE(result_statement_digest,''),COALESCE(signature_key_id,''),COALESCE(failure_reason,''),
	       dispatched_at,started_at,finished_at,expires_at,created_at,updated_at
	  FROM agent_workflow.runtime_attempts`

func readTask(ctx context.Context, from querier, scope dispatch.Scope, taskID string, lock bool) (dispatch.Task, bool, error) {
	query := taskColumns + ` WHERE workspace_id=$1 AND project_id=$2 AND task_id=$3`
	if lock {
		query += ` FOR UPDATE`
	}
	task := dispatch.Task{Scope: scope}
	var status string
	var generation, attempts, epoch int64
	err := from.QueryRow(ctx, query, scope.WorkspaceID, scope.ProjectID, taskID).Scan(
		&task.TaskID, &task.RunID, &task.RootRunID, &generation, &task.DefinitionDigest,
		&task.Runtime.RuntimeUnitID, &task.Runtime.RuntimeManifestDigest, &task.Runtime.RuntimeImageDigest,
		&task.Runtime.InvocationProtocolDigest, &task.Runtime.RuntimeAudience,
		&task.Capability, &task.RequestDigest, &status, &attempts, &epoch,
		&task.ExpiresAt, &task.CreatedAt, &task.UpdatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return dispatch.Task{}, false, nil
	}
	if err != nil {
		return dispatch.Task{}, false, fmt.Errorf("read logical task: %w", err)
	}
	task.Status = dispatch.State(status)
	task.ExecutionGeneration, task.Attempts, task.LeaseEpoch = uint64(generation), uint64(attempts), uint64(epoch)
	return task, true, nil
}

func readAttempt(ctx context.Context, from querier, scope dispatch.Scope, attemptID string, lock bool) (dispatch.Attempt, bool, error) {
	query := attemptColumns + ` WHERE workspace_id=$1 AND project_id=$2 AND physical_attempt_id=$3`
	if lock {
		query += ` FOR UPDATE`
	}
	rows, err := from.Query(ctx, query, scope.WorkspaceID, scope.ProjectID, attemptID)
	if err != nil {
		return dispatch.Attempt{}, false, fmt.Errorf("read physical attempt: %w", err)
	}
	defer rows.Close()
	if !rows.Next() {
		if err := rows.Err(); err != nil {
			return dispatch.Attempt{}, false, fmt.Errorf("read physical attempt: %w", err)
		}
		return dispatch.Attempt{}, false, nil
	}
	attempt, err := scanAttempt(scope, rows)
	if err != nil {
		return dispatch.Attempt{}, false, err
	}
	return attempt, true, nil
}

func scanAttempt(scope dispatch.Scope, rows pgx.Rows) (dispatch.Attempt, error) {
	attempt := dispatch.Attempt{Scope: scope}
	var status string
	var number, epoch int64
	var dispatched, started, finished *time.Time
	if err := rows.Scan(&attempt.PhysicalAttemptID, &attempt.TaskID, &number, &epoch, &attempt.FenceTokenDigest,
		&attempt.RuntimeUnitID, &status, &attempt.ResultStatementDigest, &attempt.SignatureKeyID, &attempt.FailureReason,
		&dispatched, &started, &finished, &attempt.ExpiresAt, &attempt.CreatedAt, &attempt.UpdatedAt); err != nil {
		return dispatch.Attempt{}, fmt.Errorf("read physical attempt: %w", err)
	}
	attempt.Status = dispatch.State(status)
	attempt.AttemptNumber, attempt.LeaseEpoch = uint64(number), uint64(epoch)
	// A null timestamp stays the zero time: an attempt that was never
	// dispatched has no dispatch time, and inventing one would make the record
	// claim something happened.
	if dispatched != nil {
		attempt.DispatchedAt = *dispatched
	}
	if started != nil {
		attempt.StartedAt = *started
	}
	if finished != nil {
		attempt.FinishedAt = *finished
	}
	return attempt, nil
}

// Registration reads the committed outcome of a logical task.
func (r *Repository) Registration(ctx context.Context, scope dispatch.Scope, taskID string) (dispatch.Registration, bool, error) {
	return readRegistration(ctx, r.database, scope, taskID)
}

// readRegistration takes no row lock, and deliberately.
//
// The registration is append-only — one per task, never updated — and every
// write to it happens while the transaction holds the task row it belongs to,
// so the task lock already serializes it. Locking it as well would need UPDATE
// privilege on a table the schema grants only SELECT and INSERT on, which is
// the grant that makes "append-only" a property of the database rather than a
// convention of the code above it.
func readRegistration(ctx context.Context, from querier, scope dispatch.Scope, taskID string) (dispatch.Registration, bool, error) {
	registration := dispatch.Registration{TaskID: taskID}
	var number, epoch, generation int64
	query := `
		SELECT physical_attempt_id,attempt_number,lease_epoch,execution_generation,
		       result_statement_digest,signature_key_id,statement,status,reason_code,committed_at
		  FROM agent_workflow.runtime_results
		 WHERE workspace_id=$1 AND project_id=$2 AND task_id=$3`
	err := from.QueryRow(ctx, query,
		scope.WorkspaceID, scope.ProjectID, taskID).Scan(
		&registration.PhysicalAttemptID, &number, &epoch, &generation,
		&registration.ResultStatementDigest, &registration.SignatureKeyID, &registration.Statement,
		&registration.Status, &registration.ReasonCode, &registration.CommittedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return dispatch.Registration{}, false, nil
	}
	if err != nil {
		return dispatch.Registration{}, false, fmt.Errorf("read the registered result: %w", err)
	}
	registration.AttemptNumber, registration.LeaseEpoch, registration.ExecutionGeneration = uint64(number), uint64(epoch), uint64(generation)
	return registration, true, nil
}

// expire closes work whose deadline passed. It runs inside the same
// transaction as the evidence, so a record that says a result expired is a
// record whose attempt says the same.
func expire(ctx context.Context, tx pgx.Tx, scope dispatch.Scope, task dispatch.Task, attempt dispatch.Attempt, at time.Time) error {
	if !attempt.Status.Terminal() {
		if _, err := tx.Exec(ctx, `
			UPDATE agent_workflow.runtime_attempts
			   SET dispatch_status=$4, failure_reason=$5, finished_at=$6, updated_at=$6
			 WHERE workspace_id=$1 AND project_id=$2 AND physical_attempt_id=$3
			   AND dispatch_status IN ('accepted','running')`,
			scope.WorkspaceID, scope.ProjectID, attempt.PhysicalAttemptID,
			string(dispatch.Expired), dispatch.ReasonDeadlineExceeded, at,
		); err != nil {
			return fmt.Errorf("expire the physical attempt: %w", err)
		}
	}
	if at.After(task.ExpiresAt) && !task.Status.Terminal() {
		if _, err := tx.Exec(ctx, `
			UPDATE agent_workflow.runtime_tasks SET status=$4, updated_at=$5
			 WHERE workspace_id=$1 AND project_id=$2 AND task_id=$3 AND status IN ('accepted','running')`,
			scope.WorkspaceID, scope.ProjectID, task.TaskID, string(dispatch.Expired), at,
		); err != nil {
			return fmt.Errorf("expire the logical task: %w", err)
		}
	}
	return nil
}

func writeEvidence(ctx context.Context, tx pgx.Tx, evidence dispatch.Evidence) error {
	if _, err := tx.Exec(ctx, `
		INSERT INTO agent_workflow.runtime_result_evidence(
			workspace_id,project_id,task_id,run_id,physical_attempt_id,attempt_number,lease_epoch,
			result_statement_digest,signature_key_id,disposition,reason,recorded_at)
		VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)`,
		evidence.Scope.WorkspaceID, evidence.Scope.ProjectID, evidence.TaskID, evidence.RunID,
		evidence.PhysicalAttemptID, int64(evidence.AttemptNumber), int64(evidence.LeaseEpoch),
		evidence.ResultStatementDigest, evidence.SignatureKeyID, string(evidence.Disposition),
		evidence.Reason, evidence.RecordedAt,
	); err != nil {
		return fmt.Errorf("record runtime result evidence: %w", err)
	}
	return nil
}

func evidenceOf(request dispatch.Settle, disposition dispatch.Disposition, reason string, at time.Time) dispatch.Evidence {
	return dispatch.Evidence{
		Scope:                 request.Scope,
		TaskID:                request.Predicate.TaskID,
		RunID:                 request.RunID,
		PhysicalAttemptID:     request.Predicate.PhysicalAttemptID,
		AttemptNumber:         request.Predicate.AttemptNumber,
		LeaseEpoch:            request.Predicate.LeaseEpoch,
		ResultStatementDigest: request.Outcome.ResultStatementDigest,
		SignatureKeyID:        request.Outcome.SignatureKeyID,
		Disposition:           disposition,
		Reason:                reason,
		RecordedAt:            at,
	}
}

func notFound(detail string) error {
	details := problem.New(problem.CodeResourceNotFound, "")
	details.Detail = detail
	return details
}

func refused(detail string) error {
	details := problem.New(problem.CodeTaskDispatchDenied, "")
	details.Detail = detail
	return details
}
