// Package postgres persists the Platform budget controller's reservation
// ledger and resolves the active budget generation from the run aggregate.
package postgres

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/ancyloce/anvilkit-agent-service/internal/budget"
	"github.com/ancyloce/anvilkit-agent-service/internal/problem"
)

// Ledger is the durable budget reservation record over
// agent_control.budget_reservations and agent_control.budget_observations.
// Every statement is scoped by workspace and project: a reservation identity
// is only ever resolved inside the tenant that owns it. Reservations converge
// under replay by their deterministic identity, observations are insert-once
// and immutable, and settlement runs under the monotonic database guard.
type Ledger struct {
	database *pgxpool.Pool
	now      func() time.Time
}

func NewLedger(database *pgxpool.Pool, now func() time.Time) (*Ledger, error) {
	if database == nil || now == nil {
		return nil, fmt.Errorf("budget ledger: a database and clock are required")
	}
	return &Ledger{database: database, now: now}, nil
}

var _ budget.Ledger = (*Ledger)(nil)

const reservationColumns = `root_run_id,run_id,workspace_id,project_id,policy_version,budget_version,upper_bound_micros,observed_micros,controller_generation,attempt_final,released,expired,cancelled,expires_at`

// expiryTaskID names the fence an elapsed reservation records, and
// cancellationTaskID the fence a cancelled one records.
const (
	expiryTaskID       = "budget-expiry"
	cancellationTaskID = "budget-cancellation"
)

// rootLockKey renders the tenant half of the advisory lock a root aggregate's
// reservations serialize on. The separator is a printable character because
// the key crosses the wire as a text parameter; a hash collision between two
// tenants would only serialize them together, never let either past the bound.
func rootLockKey(scope budget.Scope) string {
	return scope.WorkspaceID + "/" + scope.ProjectID
}

func scanReservation(row pgx.Row, id budget.ReservationID) (budget.Reservation, error) {
	value := budget.Reservation{ID: id}
	var generation uint64
	err := row.Scan(&value.RootRunID, &value.RunID, &value.WorkspaceID, &value.ProjectID, &value.PolicyVersion, &value.BudgetVersion, &value.UpperBoundMicros, &value.ObservedMicros, &generation, &value.AttemptFinal, &value.Released, &value.Expired, &value.Cancelled, &value.ExpiresAt)
	if err != nil {
		return budget.Reservation{}, err
	}
	value.Generation = budget.Generation(generation)
	return value, nil
}

// Reserve enforces the root headroom bound and records the reservation inside
// one transaction serialized per root-run scope by a transaction-scoped
// advisory lock. The lock is what makes the bound real: without it two
// concurrent reservations both read the pre-insertion total, both find room,
// and the configured maximum is exceeded by their combined upper bounds. A
// row lock cannot serve here — the rows that would breach the bound do not
// exist yet, so there is nothing to lock but the scope itself.
func (l *Ledger) Reserve(ctx context.Context, estimate budget.Estimate, generation budget.Generation, maximumReservedMicros int64) (budget.Reservation, error) {
	scope := estimate.Scope()
	if !scope.Valid() || estimate.ReservationID == "" || estimate.RootRunID == "" {
		return budget.Reservation{}, fmt.Errorf("budget ledger: a scoped reservation identity is required")
	}
	if maximumReservedMicros < 1 {
		return budget.Reservation{}, fmt.Errorf("budget ledger: a positive reserved-exposure bound is required")
	}
	now := l.now().UTC()
	tx, err := l.database.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
	if err != nil {
		return budget.Reservation{}, err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtext($1), hashtext($2))`, rootLockKey(scope), estimate.RootRunID); err != nil {
		return budget.Reservation{}, fmt.Errorf("serialize root budget reservation: %w", err)
	}
	// Elapsed holds are fenced first, inside the same critical section, so
	// neither the replay answer below nor the headroom sum can be computed
	// from a hold the clock has already invalidated. Fencing keeps the
	// worst-case bound, so the sum is never understated either.
	if _, err := fenceExpiredTx(ctx, tx, scope, estimate.RootRunID, now); err != nil {
		return budget.Reservation{}, err
	}
	recorded, err := scanReservation(tx.QueryRow(ctx, `SELECT `+reservationColumns+` FROM agent_control.budget_reservations WHERE workspace_id=$1 AND project_id=$2 AND reservation_id=$3`, scope.WorkspaceID, scope.ProjectID, estimate.ReservationID), estimate.ReservationID)
	switch {
	case err == nil:
		// A replayed durable operation converges on the reservation it
		// already made; any identity drift is a conflict, never a second hold.
		if recorded.RootRunID != estimate.RootRunID || recorded.RunID != estimate.RunID || recorded.PolicyVersion != estimate.PolicyVersion || recorded.BudgetVersion != estimate.BudgetVersion || recorded.Generation != generation || recorded.UpperBoundMicros != estimate.MaximumCostMicros {
			return budget.Reservation{}, problem.New(problem.CodeIdempotencyConflict, "")
		}
		if recorded.Expired || recorded.Cancelled || recorded.Released {
			// Answering this replay with the recorded reservation would tell
			// the caller it holds budget it does not: the fence already
			// withdrew its authority to dispatch. The replay is refused so the
			// fence is handled rather than skipped, and so no replayed durable
			// operation can hand cancelled work its dispatch authority back.
			return budget.Reservation{}, budgetProblem("the reservation is fenced and must reconcile to authoritative finality")
		}
		if err := tx.Commit(ctx); err != nil {
			return budget.Reservation{}, err
		}
		return recorded, nil
	case errors.Is(err, pgx.ErrNoRows):
	default:
		return budget.Reservation{}, fmt.Errorf("read recorded budget reservation: %w", err)
	}
	var held int64
	if err := tx.QueryRow(ctx, `SELECT COALESCE(SUM(upper_bound_micros),0) FROM agent_control.budget_reservations WHERE workspace_id=$1 AND project_id=$2 AND root_run_id=$3 AND released=false`, scope.WorkspaceID, scope.ProjectID, estimate.RootRunID).Scan(&held); err != nil {
		return budget.Reservation{}, fmt.Errorf("sum held root budget reservations: %w", err)
	}
	if held < 0 || estimate.MaximumCostMicros < 1 || held > maximumReservedMicros-estimate.MaximumCostMicros {
		return budget.Reservation{}, budgetProblem("budget headroom requires review")
	}
	if _, err := tx.Exec(ctx, `INSERT INTO agent_control.budget_reservations(workspace_id,project_id,root_run_id,run_id,reservation_id,controller_generation,policy_version,budget_version,upper_bound_micros,expires_at,created_at,updated_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$11)`,
		scope.WorkspaceID, scope.ProjectID, estimate.RootRunID, estimate.RunID, estimate.ReservationID, uint64(generation), estimate.PolicyVersion, estimate.BudgetVersion, estimate.MaximumCostMicros, estimate.ExpiresAt, now); err != nil {
		return budget.Reservation{}, fmt.Errorf("record budget reservation: %w", err)
	}
	inserted, err := scanReservation(tx.QueryRow(ctx, `SELECT `+reservationColumns+` FROM agent_control.budget_reservations WHERE workspace_id=$1 AND project_id=$2 AND reservation_id=$3`, scope.WorkspaceID, scope.ProjectID, estimate.ReservationID), estimate.ReservationID)
	if err != nil {
		return budget.Reservation{}, fmt.Errorf("read recorded budget reservation: %w", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return budget.Reservation{}, err
	}
	return inserted, nil
}

// FenceExpired fences every elapsed unreleased hold of one root aggregate
// inside its own transaction.
func (l *Ledger) FenceExpired(ctx context.Context, scope budget.Scope, rootRunID string, now time.Time) ([]budget.Reservation, error) {
	if !scope.Valid() || rootRunID == "" || now.IsZero() {
		return nil, budgetProblem("expiry fencing requires a scoped root run and authoritative time")
	}
	tx, err := l.database.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
	if err != nil {
		return nil, err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtext($1), hashtext($2))`, rootLockKey(scope), rootRunID); err != nil {
		return nil, fmt.Errorf("serialize root budget expiry: %w", err)
	}
	fenced, err := fenceExpiredTx(ctx, tx, scope, rootRunID, now.UTC())
	if err != nil {
		return nil, err
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, err
	}
	return fenced, nil
}

// Every fencing and settlement statement stamps updated_at with
// GREATEST(updated_at, now): the monotonic guard raises if a write moves the
// timestamp backwards, and a fence computed from a clock read taken before the
// transaction can otherwise lose that race to a concurrent usage observation
// that already stamped a later value. The write itself is what must be
// monotonic, not the caller's clock.
//
// fenceExpiredTx fences every elapsed unreleased hold of the root aggregate
// and leaves an immutable expiry observation behind. It changes exactly one
// thing: the hold may no longer authorize a dispatch. It does not write an
// observed cost, does not mark the attempt final, and does not release — a
// clock cannot witness what a physical attempt spent, and recording its
// silence as a final cost would both understate real exposure and take away
// the headroom a still-running attempt is entitled to. The immutable record
// carries no cost and is not final, for the same reason.
func fenceExpiredTx(ctx context.Context, tx pgx.Tx, scope budget.Scope, rootRunID string, now time.Time) ([]budget.Reservation, error) {
	rows, err := tx.Query(ctx, `UPDATE agent_control.budget_reservations SET expired=true,updated_at=GREATEST(updated_at,$4)
		WHERE workspace_id=$1 AND project_id=$2 AND root_run_id=$3 AND released=false AND expired=false AND expires_at<=$4
		RETURNING reservation_id,`+reservationColumns, scope.WorkspaceID, scope.ProjectID, rootRunID, now)
	if err != nil {
		return nil, fmt.Errorf("fence expired budget reservations: %w", err)
	}
	fenced, err := collectReservations(rows)
	if err != nil {
		return nil, err
	}
	for _, value := range fenced {
		if _, err := tx.Exec(ctx, `INSERT INTO agent_control.budget_observations(workspace_id,project_id,observation_id,reservation_id,root_run_id,run_id,task_id,physical_attempt_id,recovery_epoch,execution_generation,meter_sequence,cost_micros,final,observed_at) VALUES($1,$2,$3,$4,$5,$6,$7,$3,0,$8,0,0,false,$9) ON CONFLICT (workspace_id,project_id,observation_id) DO NOTHING`,
			scope.WorkspaceID, scope.ProjectID, budget.ExpiryObservationID(value.ID), string(value.ID), value.RootRunID, value.RunID, expiryTaskID, uint64(value.Generation), now); err != nil {
			return nil, fmt.Errorf("record budget expiry fence: %w", err)
		}
	}
	return fenced, nil
}

// FenceCancelled withdraws one hold's authority to dispatch because the work
// it funds was cancelled, and records the immutable cancellation fence. The
// statement is a conditional update rather than a read-then-write, so two
// concurrent cancellations of the same run converge instead of racing. It
// writes no observed cost, marks no attempt final, and releases nothing: a
// cancellation request cannot witness what a billed model, tool, or worker
// operation already in flight will report.
func (l *Ledger) FenceCancelled(ctx context.Context, scope budget.Scope, id budget.ReservationID, now time.Time) (budget.Reservation, error) {
	if !scope.Valid() || id == "" || now.IsZero() {
		return budget.Reservation{}, budgetProblem("cancellation fencing requires a scoped reservation and authoritative time")
	}
	tx, err := l.database.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
	if err != nil {
		return budget.Reservation{}, err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	current, err := scanReservation(tx.QueryRow(ctx, `SELECT `+reservationColumns+` FROM agent_control.budget_reservations WHERE workspace_id=$1 AND project_id=$2 AND reservation_id=$3 FOR UPDATE`, scope.WorkspaceID, scope.ProjectID, id), id)
	if errors.Is(err, pgx.ErrNoRows) {
		return budget.Reservation{}, problem.New(problem.CodeResourceNotFound, "")
	}
	if err != nil {
		return budget.Reservation{}, fmt.Errorf("lock budget reservation for cancellation: %w", err)
	}
	if current.Cancelled || current.Released {
		// Already fenced, or already settled against an authoritative final
		// cost. Either way there is no dispatch authority left to withdraw.
		return current, tx.Commit(ctx)
	}
	if _, err := tx.Exec(ctx, `UPDATE agent_control.budget_reservations SET cancelled=true,updated_at=GREATEST(updated_at,$4) WHERE workspace_id=$1 AND project_id=$2 AND reservation_id=$3`, scope.WorkspaceID, scope.ProjectID, id, now.UTC()); err != nil {
		return budget.Reservation{}, fmt.Errorf("fence cancelled budget reservation: %w", err)
	}
	if _, err := tx.Exec(ctx, `INSERT INTO agent_control.budget_observations(workspace_id,project_id,observation_id,reservation_id,root_run_id,run_id,task_id,physical_attempt_id,recovery_epoch,execution_generation,meter_sequence,cost_micros,final,observed_at) VALUES($1,$2,$3,$4,$5,$6,$7,$3,0,$8,0,0,false,$9) ON CONFLICT (workspace_id,project_id,observation_id) DO NOTHING`,
		scope.WorkspaceID, scope.ProjectID, budget.CancellationObservationID(id), string(id), current.RootRunID, current.RunID, cancellationTaskID, uint64(current.Generation), now.UTC()); err != nil {
		return budget.Reservation{}, fmt.Errorf("record budget cancellation fence: %w", err)
	}
	fenced, err := scanReservation(tx.QueryRow(ctx, `SELECT `+reservationColumns+` FROM agent_control.budget_reservations WHERE workspace_id=$1 AND project_id=$2 AND reservation_id=$3`, scope.WorkspaceID, scope.ProjectID, id), id)
	if err != nil {
		return budget.Reservation{}, fmt.Errorf("read fenced budget reservation: %w", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return budget.Reservation{}, err
	}
	return fenced, nil
}

func (l *Ledger) Observe(ctx context.Context, value budget.Observation) error {
	if !value.Scope.Valid() {
		return budgetProblem("observation scope is required")
	}
	tx, err := l.database.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	var rootRunID string
	var upper, observed int64
	var released bool
	err = tx.QueryRow(ctx, `SELECT root_run_id,upper_bound_micros,observed_micros,released FROM agent_control.budget_reservations WHERE workspace_id=$1 AND project_id=$2 AND reservation_id=$3 FOR UPDATE`, value.Scope.WorkspaceID, value.Scope.ProjectID, value.ReservationID).
		Scan(&rootRunID, &upper, &observed, &released)
	if errors.Is(err, pgx.ErrNoRows) {
		return budgetProblem("observation reservation mismatch")
	}
	if err != nil {
		return fmt.Errorf("lock budget reservation: %w", err)
	}
	if rootRunID != value.RootRunID {
		return budgetProblem("observation reservation mismatch")
	}
	tag, err := tx.Exec(ctx, `INSERT INTO agent_control.budget_observations(workspace_id,project_id,observation_id,reservation_id,root_run_id,run_id,task_id,physical_attempt_id,recovery_epoch,execution_generation,meter_sequence,cost_micros,final,observed_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14) ON CONFLICT (workspace_id,project_id,observation_id) DO NOTHING`,
		value.Scope.WorkspaceID, value.Scope.ProjectID, value.ID, value.ReservationID, value.RootRunID, value.RunID, value.TaskID, value.AttemptID, value.RecoveryEpoch, value.ExecutionGeneration, value.MeterSequence, value.CostMicros, value.Final, l.now().UTC())
	if err != nil {
		return fmt.Errorf("record budget observation: %w", err)
	}
	if tag.RowsAffected() == 0 {
		// The observation was already recorded; converge only on an
		// identical record.
		var reservationID, runID, taskID, attemptID string
		var cost int64
		var final bool
		if err := tx.QueryRow(ctx, `SELECT reservation_id,run_id,task_id,physical_attempt_id,cost_micros,final FROM agent_control.budget_observations WHERE workspace_id=$1 AND project_id=$2 AND observation_id=$3`, value.Scope.WorkspaceID, value.Scope.ProjectID, value.ID).
			Scan(&reservationID, &runID, &taskID, &attemptID, &cost, &final); err != nil {
			return fmt.Errorf("read recorded budget observation: %w", err)
		}
		if reservationID != string(value.ReservationID) || runID != value.RunID || taskID != value.TaskID || attemptID != string(value.AttemptID) || cost != value.CostMicros || final != value.Final {
			return problem.New(problem.CodeIdempotencyConflict, "")
		}
		return tx.Commit(ctx)
	}
	// A fenced reservation still accepts usage: the physical attempt whose
	// lifetime elapsed can still be running, and its cost is exactly the fact
	// the fence is waiting for. Only a released reservation — one already
	// settled against an authoritative final cost — is closed to new usage.
	if released || value.CostMicros > upper-observed {
		return budgetProblem("observed usage exceeds reservation")
	}
	if _, err := tx.Exec(ctx, `UPDATE agent_control.budget_reservations SET observed_micros=observed_micros+$4,attempt_final=attempt_final OR $5,updated_at=GREATEST(updated_at,$6) WHERE workspace_id=$1 AND project_id=$2 AND reservation_id=$3`,
		value.Scope.WorkspaceID, value.Scope.ProjectID, value.ReservationID, value.CostMicros, value.Final, l.now().UTC()); err != nil {
		return fmt.Errorf("accumulate budget observation: %w", err)
	}
	return tx.Commit(ctx)
}

func (l *Ledger) Settle(ctx context.Context, value budget.Settlement) (budget.Reservation, error) {
	if !value.Scope.Valid() {
		return budget.Reservation{}, budgetProblem("settlement scope is required")
	}
	tx, err := l.database.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
	if err != nil {
		return budget.Reservation{}, err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	var generation uint64
	var attemptFinal, released bool
	var upper, observed int64
	err = tx.QueryRow(ctx, `SELECT controller_generation,attempt_final,released,upper_bound_micros,observed_micros FROM agent_control.budget_reservations WHERE workspace_id=$1 AND project_id=$2 AND reservation_id=$3 FOR UPDATE`, value.Scope.WorkspaceID, value.Scope.ProjectID, value.ReservationID).
		Scan(&generation, &attemptFinal, &released, &upper, &observed)
	if errors.Is(err, pgx.ErrNoRows) {
		return budget.Reservation{}, problem.New(problem.CodeResourceNotFound, "")
	}
	if err != nil {
		return budget.Reservation{}, fmt.Errorf("lock budget reservation for settlement: %w", err)
	}
	if budget.Generation(generation) != value.Generation || !attemptFinal {
		return budget.Reservation{}, budgetProblem("settlement fence failed")
	}
	if observed == value.FinalCost && upper == value.FinalCost && released == value.Release {
		// The intended outcome already stands. Converging here is what makes a
		// replayed durable settlement a no-op instead of a conflict.
		settled, err := scanReservation(tx.QueryRow(ctx, `SELECT `+reservationColumns+` FROM agent_control.budget_reservations WHERE workspace_id=$1 AND project_id=$2 AND reservation_id=$3`, value.Scope.WorkspaceID, value.Scope.ProjectID, value.ReservationID), value.ReservationID)
		if err != nil {
			return budget.Reservation{}, fmt.Errorf("read settled budget reservation: %w", err)
		}
		if err := tx.Commit(ctx); err != nil {
			return budget.Reservation{}, err
		}
		return settled, nil
	}
	if released {
		return budget.Reservation{}, budgetProblem("released budget reservation is immutable")
	}
	// The compare-and-set is decided before the settlement is judged on its
	// merits. A settlement computed from usage the row no longer holds is
	// stale, not wrong, and reporting it as a rejection would send the caller
	// looking for a defect instead of re-reading and settling again.
	if observed != value.ExpectedObservedMicros || attemptFinal != value.ExpectedAttemptFinal {
		return budget.Reservation{}, budget.Conflict{ReservationID: value.ReservationID, ObservedMicros: observed, AttemptFinal: attemptFinal}
	}
	if value.FinalCost < observed || value.FinalCost > upper {
		return budget.Reservation{}, budgetProblem("final usage is inconsistent")
	}
	// The predicate is carried in the statement as well, so the write is
	// refused by the database itself if the usage or finality the caller read
	// is no longer what the row holds. It never overwrites usage that arrived
	// while the settlement was being computed.
	tag, err := tx.Exec(ctx, `UPDATE agent_control.budget_reservations SET observed_micros=$4,upper_bound_micros=$4,released=$5,updated_at=GREATEST(updated_at,$6) WHERE workspace_id=$1 AND project_id=$2 AND reservation_id=$3 AND observed_micros=$7 AND attempt_final=$8`,
		value.Scope.WorkspaceID, value.Scope.ProjectID, value.ReservationID, value.FinalCost, value.Release, l.now().UTC(), value.ExpectedObservedMicros, value.ExpectedAttemptFinal)
	if err != nil {
		return budget.Reservation{}, fmt.Errorf("settle budget reservation: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return budget.Reservation{}, budget.Conflict{ReservationID: value.ReservationID, ObservedMicros: observed, AttemptFinal: attemptFinal}
	}
	settled, err := scanReservation(tx.QueryRow(ctx, `SELECT `+reservationColumns+` FROM agent_control.budget_reservations WHERE workspace_id=$1 AND project_id=$2 AND reservation_id=$3`, value.Scope.WorkspaceID, value.Scope.ProjectID, value.ReservationID), value.ReservationID)
	if err != nil {
		return budget.Reservation{}, fmt.Errorf("read settled budget reservation: %w", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return budget.Reservation{}, err
	}
	return settled, nil
}

func (l *Ledger) Reservation(ctx context.Context, scope budget.Scope, id budget.ReservationID) (budget.Reservation, error) {
	if !scope.Valid() {
		return budget.Reservation{}, budgetProblem("reservation read requires workspace and project identity")
	}
	value, err := scanReservation(l.database.QueryRow(ctx, `SELECT `+reservationColumns+` FROM agent_control.budget_reservations WHERE workspace_id=$1 AND project_id=$2 AND reservation_id=$3`, scope.WorkspaceID, scope.ProjectID, id), id)
	if errors.Is(err, pgx.ErrNoRows) {
		return budget.Reservation{}, problem.New(problem.CodeResourceNotFound, "")
	}
	if err != nil {
		return budget.Reservation{}, fmt.Errorf("read budget reservation: %w", err)
	}
	return value, nil
}

func (l *Ledger) RootReservations(ctx context.Context, scope budget.Scope, rootRunID string) ([]budget.Reservation, error) {
	if !scope.Valid() {
		return nil, budgetProblem("root aggregation requires workspace and project identity")
	}
	rows, err := l.database.Query(ctx, `SELECT reservation_id,`+reservationColumns+` FROM agent_control.budget_reservations WHERE workspace_id=$1 AND project_id=$2 AND root_run_id=$3 ORDER BY reservation_id`, scope.WorkspaceID, scope.ProjectID, rootRunID)
	if err != nil {
		return nil, fmt.Errorf("list root budget reservations: %w", err)
	}
	return collectReservations(rows)
}

// collectReservations scans a reservation_id-prefixed reservation row set and
// closes it.
func collectReservations(rows pgx.Rows) ([]budget.Reservation, error) {
	defer rows.Close()
	var values []budget.Reservation
	for rows.Next() {
		var id string
		value := budget.Reservation{}
		var generation uint64
		if err := rows.Scan(&id, &value.RootRunID, &value.RunID, &value.WorkspaceID, &value.ProjectID, &value.PolicyVersion, &value.BudgetVersion, &value.UpperBoundMicros, &value.ObservedMicros, &generation, &value.AttemptFinal, &value.Released, &value.Expired, &value.Cancelled, &value.ExpiresAt); err != nil {
			return nil, fmt.Errorf("scan budget reservation: %w", err)
		}
		value.ID = budget.ReservationID(id)
		value.Generation = budget.Generation(generation)
		values = append(values, value)
	}
	return values, rows.Err()
}

func budgetProblem(detail string) problem.Details {
	value := problem.New(problem.CodeBudgetDenied, "")
	value.Detail = detail
	return value
}

// RunGenerations resolves the active budget generation from the root run
// aggregate's durable execution generation — the one generation authority.
// Restart recovery is inherent: a fresh process reads the same durable value
// every boundary fences on.
type RunGenerations struct {
	database *pgxpool.Pool
}

func NewRunGenerations(database *pgxpool.Pool) (*RunGenerations, error) {
	if database == nil {
		return nil, fmt.Errorf("budget generations: a database is required")
	}
	return &RunGenerations{database: database}, nil
}

var _ budget.Generations = (*RunGenerations)(nil)

func (g *RunGenerations) Current(ctx context.Context, workspaceID, projectID, rootRunID string) (budget.Generation, error) {
	var generation uint64
	err := g.database.QueryRow(ctx, `SELECT execution_generation FROM agent_control.agent_runs WHERE workspace_id=$1 AND project_id=$2 AND run_id=$3`, workspaceID, projectID, rootRunID).Scan(&generation)
	if errors.Is(err, pgx.ErrNoRows) {
		return 0, problem.New(problem.CodeResourceNotFound, "")
	}
	if err != nil {
		return 0, fmt.Errorf("read root run generation: %w", err)
	}
	return budget.Generation(generation), nil
}
