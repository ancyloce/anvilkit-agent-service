package persistence_test

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/ancyloce/anvilkit-agent-service/internal/applyauth"
	applyauthpg "github.com/ancyloce/anvilkit-agent-service/internal/applyauth/postgres"
	"github.com/ancyloce/anvilkit-agent-service/internal/budget"
	budgetpg "github.com/ancyloce/anvilkit-agent-service/internal/budget/postgres"
	"github.com/ancyloce/anvilkit-agent-service/internal/domaincommit"
	commitpg "github.com/ancyloce/anvilkit-agent-service/internal/domaincommit/postgres"
	"github.com/ancyloce/anvilkit-agent-service/internal/execution"
	"github.com/ancyloce/anvilkit-agent-service/internal/problem"
	recoverypg "github.com/ancyloce/anvilkit-agent-service/internal/recovery/postgres"
	"github.com/ancyloce/anvilkit-agent-service/internal/runapp"
	runapppg "github.com/ancyloce/anvilkit-agent-service/internal/runapp/postgres"
	"github.com/ancyloce/anvilkit-agent-service/internal/scheduler"
	schedulerpg "github.com/ancyloce/anvilkit-agent-service/internal/scheduler/postgres"
)

// assertDomainEscalationJournal proves the durable recovery bookkeeping of a
// submitted-but-uncertain governed effect: uncertain reconciliations are
// counted monotonically, the bounded window escalates the operation, the
// escalated state still fences every mutation, and only an audited operator
// resolution — immutable once recorded — decides it.
func assertDomainEscalationJournal(t *testing.T, ctx context.Context, pool *pgxpool.Pool) {
	t.Helper()
	now := time.Unix(900, 0).UTC()
	digest := func(character byte) string { return "sha256:" + strings.Repeat(string(character), 64) }
	audit, err := applyauthpg.New(pool)
	if err != nil {
		t.Fatal(err)
	}
	if err := audit.Record(ctx, applyauth.AuditRecord{AuthorizationID: "authorization-escalate", WorkspaceID: "workspace-escalate", ProjectID: "project-escalate", RunID: "run-escalate", KeyID: "urn:anvilkit:key:escalate-synthetic", PayloadDigest: digest('a'), TokenDigest: digest('b'), IssuedAt: now, ExpiresAt: now.Add(2 * time.Minute), OperationKey: "workflow-escalate:commit", Token: "escalate.compact.token"}); err != nil {
		t.Fatal(err)
	}
	store, err := commitpg.New(pool)
	if err != nil {
		t.Fatal(err)
	}
	scope := domaincommit.Scope{WorkspaceID: "workspace-escalate", ProjectID: "project-escalate"}
	operation := domaincommit.Operation{Scope: scope, RunID: "run-escalate", ID: "operation-escalate", AuthorizationID: "authorization-escalate", AuthorizationJWS: "escalate.header.signature", ActionDigest: digest('c'), ArtifactDigest: digest('d'), ExpectedRevision: "revision-1", IdempotencyKey: "apply-escalate", RequestDigest: digest('e'), Status: domaincommit.Recorded, CreatedAt: now, UpdatedAt: now}
	if err := store.Create(ctx, operation); err != nil {
		t.Fatal(err)
	}
	// Reconciliation counting applies only to a submitted operation.
	if _, err := store.RecordReconcile(ctx, scope, operation.ID, now.Add(time.Second)); err == nil {
		t.Fatal("a not-submitted operation must not count reconciliations")
	}
	if err := store.MarkIssued(ctx, scope, operation.ID, now.Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	first, err := store.RecordReconcile(ctx, scope, operation.ID, now.Add(2*time.Second))
	if err != nil || first.ReconcileAttempts != 1 || first.FirstUncertainAt.IsZero() {
		t.Fatalf("first reconcile=%+v err=%v", first, err)
	}
	second, err := store.RecordReconcile(ctx, scope, operation.ID, now.Add(3*time.Second))
	if err != nil || second.ReconcileAttempts != 2 || !second.FirstUncertainAt.Equal(first.FirstUncertainAt) {
		t.Fatalf("second reconcile=%+v err=%v, want a monotone count with a stable onset", second, err)
	}
	// Resolution before escalation is refused; an owner-decided operation is
	// never operator-overridden.
	if _, err := store.Resolve(ctx, scope, operation.ID, domaincommit.Rejected, "operator.oncall", "ticket OPS-9", now.Add(4*time.Second)); err == nil {
		t.Fatal("resolving an unescalated operation must be refused")
	}
	if err := store.Escalate(ctx, scope, operation.ID, now.Add(4*time.Second)); err != nil {
		t.Fatal(err)
	}
	if err := store.Escalate(ctx, scope, operation.ID, now.Add(5*time.Second)); err != nil {
		t.Fatalf("escalation replay must converge: %v", err)
	}
	escalated, err := store.Get(ctx, scope, operation.ID)
	if err != nil || escalated.Status != domaincommit.Escalated || escalated.EscalatedAt.IsZero() || escalated.AuthorizationConsumed {
		t.Fatalf("escalated=%+v err=%v", escalated, err)
	}
	// The escalated operation is still the run's one active operation.
	if active, ok, err := store.ActiveForRun(ctx, scope, "run-escalate"); err != nil || !ok || active.Status != domaincommit.Escalated {
		t.Fatalf("active=%+v ok=%v err=%v", active, ok, err)
	}
	// The durable guards hold under direct mutation: no reverse transition,
	// no escalation-time rewrite, no unaudited terminal exit.
	if _, err := pool.Exec(ctx, `UPDATE agent_control.domain_operations SET status='issued',updated_at=$4 WHERE workspace_id=$1 AND project_id=$2 AND operation_id=$3`, scope.WorkspaceID, scope.ProjectID, operation.ID, now.Add(6*time.Second)); err == nil {
		t.Fatal("an escalated operation moved backward")
	}
	if _, err := pool.Exec(ctx, `UPDATE agent_control.domain_operations SET escalated_at=$4,updated_at=$4 WHERE workspace_id=$1 AND project_id=$2 AND operation_id=$3`, scope.WorkspaceID, scope.ProjectID, operation.ID, now.Add(7*time.Second)); err == nil {
		t.Fatal("the escalation time was mutable")
	}
	if _, err := pool.Exec(ctx, `UPDATE agent_control.domain_operations SET status='rejected',authorization_consumed=true,updated_at=$4 WHERE workspace_id=$1 AND project_id=$2 AND operation_id=$3`, scope.WorkspaceID, scope.ProjectID, operation.ID, now.Add(7*time.Second)); err == nil {
		t.Fatal("an escalated operation was decided without an audited resolution")
	}
	if _, err := store.Resolve(ctx, scope, operation.ID, domaincommit.Rejected, "", "", now.Add(8*time.Second)); err == nil {
		t.Fatal("an unaudited resolution must be refused")
	}
	resolved, err := store.Resolve(ctx, scope, operation.ID, domaincommit.Rejected, "operator.oncall", "domain-owner audit ticket OPS-9", now.Add(8*time.Second))
	if err != nil || resolved.Status != domaincommit.Rejected || !resolved.AuthorizationConsumed || resolved.ResolvedBy != "operator.oncall" {
		t.Fatalf("resolved=%+v err=%v", resolved, err)
	}
	// The recorded resolution audit is immutable, and a decided operation
	// counts no further reconciliations.
	if _, err := pool.Exec(ctx, `UPDATE agent_control.domain_operations SET resolved_by='someone-else',updated_at=$4 WHERE workspace_id=$1 AND project_id=$2 AND operation_id=$3`, scope.WorkspaceID, scope.ProjectID, operation.ID, now.Add(9*time.Second)); err == nil {
		t.Fatal("the resolution audit was mutable")
	}
	if _, err := store.RecordReconcile(ctx, scope, operation.ID, now.Add(9*time.Second)); err == nil {
		t.Fatal("a decided operation must not count reconciliations")
	}
	// A successor process resolves the decided record for the run.
	successor, err := commitpg.New(pool)
	if err != nil {
		t.Fatal(err)
	}
	latest, found, err := successor.LatestForRun(ctx, scope, "run-escalate")
	if err != nil || !found || latest.ID != operation.ID || latest.Status != domaincommit.Rejected || latest.ResolutionBasis != "domain-owner audit ticket OPS-9" {
		t.Fatalf("latest=%+v found=%v err=%v", latest, found, err)
	}
}

// assertBudgetControllerLedger proves the durable Platform budget controller:
// convergent deterministic reservations, insert-once immutable observations,
// generation fencing against the run aggregate's durable execution
// generation, monotonic settlement, and full restart recovery.
func assertBudgetControllerLedger(t *testing.T, ctx context.Context, pool *pgxpool.Pool) {
	t.Helper()
	if _, err := pool.Exec(ctx, `INSERT INTO agent_control.agent_runs(workspace_id,project_id,run_id,state,version,execution_generation,next_event_sequence,snapshot) VALUES('workspace-budget','project-budget','run-budget-root','created',1,1,2,'{}')`); err != nil {
		t.Fatal(err)
	}
	newController := func() (*budget.Controller, *budgetpg.Ledger) {
		t.Helper()
		ledger, err := budgetpg.NewLedger(pool, func() time.Time { return time.Now().UTC() })
		if err != nil {
			t.Fatal(err)
		}
		generations, err := budgetpg.NewRunGenerations(pool)
		if err != nil {
			t.Fatal(err)
		}
		controller, err := budget.New(ledger, generations, discardExposure{}, realClock{}, budget.HeadroomPolicy{MaximumReservedMicros: 1_000_000, ReviewAtBasisPoints: 8000})
		if err != nil {
			t.Fatal(err)
		}
		return controller, ledger
	}
	budgetScope := budget.Scope{WorkspaceID: "workspace-budget", ProjectID: "project-budget"}
	controller, _ := newController()
	estimate := budget.Estimate{
		ReservationID:     "budget:run-budget-root:g1",
		RootRunID:         "run-budget-root",
		RunID:             "run-budget-root",
		WorkspaceID:       "workspace-budget",
		ProjectID:         "project-budget",
		PolicyVersion:     "policy-v1",
		BudgetVersion:     "budget-v1",
		MaximumCostMicros: 1000,
		ExpiresAt:         time.Now().Add(time.Hour).UTC(),
	}
	reserved, err := controller.ReserveInitial(ctx, estimate, 1)
	if err != nil {
		t.Fatal(err)
	}
	// A replayed durable operation converges on the recorded reservation; a
	// drifted identity is a conflict, never a second hold.
	replayed, err := controller.ReserveInitial(ctx, estimate, 1)
	if err != nil || replayed.ID != reserved.ID || !replayed.ExpiresAt.Equal(reserved.ExpiresAt) {
		t.Fatalf("replayed=%+v err=%v", replayed, err)
	}
	drifted := estimate
	drifted.MaximumCostMicros = 2000
	if _, err := controller.ReserveInitial(ctx, drifted, 1); err == nil {
		t.Fatal("a drifted reservation replay was accepted")
	}
	observation := budget.Observation{ID: "budget-obs-1", Scope: budgetScope, ReservationID: reserved.ID, RootRunID: "run-budget-root", RunID: "run-budget-root", TaskID: "model:turn-0000", AttemptID: "attempt-budget-1", ExecutionGeneration: 1, MeterSequence: 0, CostMicros: 300}
	if err := controller.Observe(ctx, observation); err != nil {
		t.Fatal(err)
	}
	if err := controller.Observe(ctx, observation); err != nil {
		t.Fatalf("identical observation replay must converge: %v", err)
	}
	conflicting := observation
	conflicting.CostMicros = 400
	if err := controller.Observe(ctx, conflicting); err == nil {
		t.Fatal("a drifted observation replay was accepted")
	}
	if _, err := pool.Exec(ctx, `UPDATE agent_control.budget_observations SET cost_micros=0 WHERE workspace_id='workspace-budget'`); err == nil {
		t.Fatal("a recorded budget observation was mutable")
	}
	if _, err := pool.Exec(ctx, `DELETE FROM agent_control.budget_observations WHERE workspace_id='workspace-budget'`); err == nil {
		t.Fatal("a recorded budget observation was deletable")
	}
	if current, err := controller.Reservation(ctx, budgetScope, reserved.ID); err != nil || current.ObservedMicros != 300 {
		t.Fatalf("reservation=%+v err=%v, want the accumulated observation", current, err)
	}
	// The run aggregate's execution generation is the one generation
	// authority: advancing it durably fences the superseded generation out of
	// dispatch and settlement in every process.
	if _, err := pool.Exec(ctx, `UPDATE agent_control.agent_runs SET execution_generation=2,version=version+1 WHERE workspace_id='workspace-budget' AND project_id='project-budget' AND run_id='run-budget-root'`); err != nil {
		t.Fatal(err)
	}
	if err := controller.Dispatch(ctx, budgetScope, reserved.ID, 1, func(context.Context, budget.Reservation) error { return nil }); err == nil {
		t.Fatal("a superseded generation dispatched")
	}
	final := budget.Observation{ID: "budget-obs-final", Scope: budgetScope, ReservationID: reserved.ID, RootRunID: "run-budget-root", RunID: "run-budget-root", TaskID: "settlement", AttemptID: "attempt-budget-final", ExecutionGeneration: 1, Final: true}
	if err := controller.Observe(ctx, final); err != nil {
		t.Fatal(err)
	}
	// Late finality on a superseded generation settles against the durable
	// ledger rather than stranding the hold — but on superseded terms only:
	// reduced to reported usage, never released, generation untouched.
	late, err := controller.Reconcile(ctx, budgetScope, reserved.ID, 1, ptrMicros(300), false, budget.SettlementActor)
	if err != nil {
		t.Fatalf("late finality on a superseded generation was refused: %v", err)
	}
	if late.Released || late.UpperBoundMicros != 300 || late.ObservedMicros != 300 || late.Generation != 1 {
		t.Fatalf("late settlement = %+v, want a non-releasing reduction on the generation that made the hold", late)
	}
	// The replacement generation reserves against the still-open prior hold —
	// in a fresh controller, as a restarted process would.
	restarted, _ := newController()
	replacement := estimate
	replacement.ReservationID = "budget:run-budget-root:g2"
	replacement.MaximumCostMicros = 500
	if _, err := restarted.ReserveReplacement(ctx, replacement, 2, reserved.ID); err != nil {
		t.Fatal(err)
	}
	finalReplacement := budget.Observation{ID: "budget-obs-g2-final", Scope: budgetScope, ReservationID: replacement.ReservationID, RootRunID: "run-budget-root", RunID: "run-budget-root", TaskID: "settlement", AttemptID: "attempt-budget-g2", ExecutionGeneration: 2, Final: true}
	if err := restarted.Observe(ctx, finalReplacement); err != nil {
		t.Fatal(err)
	}
	settled, err := restarted.Reconcile(ctx, budgetScope, replacement.ReservationID, 2, ptrMicros(0), true, budget.SettlementActor)
	if err != nil || !settled.Released {
		t.Fatalf("settled=%+v err=%v", settled, err)
	}
	if _, err := pool.Exec(ctx, `UPDATE agent_control.budget_reservations SET released=false WHERE workspace_id='workspace-budget' AND reservation_id='budget:run-budget-root:g2'`); err == nil {
		t.Fatal("a released reservation was revivable")
	}
}

// assertLateSupersededFinalityRecovers proves the durable behaviour of the
// window between an attempt's finality being recorded and its hold being
// settled against it.
//
// The window is real: a replacement generation can start while the attempt it
// replaces is still running, so finality arrives for a generation that is
// already superseded. Settlement has to complete when that happens, and a
// crash inside the window has to converge afterwards without any journal of
// its own — nothing re-drives a hold whose generation is gone.
func assertLateSupersededFinalityRecovers(t *testing.T, ctx context.Context, pool *pgxpool.Pool) {
	t.Helper()
	const workspace = "workspace-late-final"
	const project = "project-late-final"
	const root = "run-late-final-root"
	const worstCase = int64(400_000)
	const actual = int64(3_000)
	for _, tenant := range []string{workspace, "workspace-late-final-foreign"} {
		if _, err := pool.Exec(ctx, `INSERT INTO agent_control.agent_runs(workspace_id,project_id,run_id,state,version,execution_generation,next_event_sequence,snapshot) VALUES($1,$2,$3,'created',1,1,2,'{}')`, tenant, project, root); err != nil {
			t.Fatal(err)
		}
	}
	newController := func() *budget.Controller {
		t.Helper()
		ledger, err := budgetpg.NewLedger(pool, func() time.Time { return time.Now().UTC() })
		if err != nil {
			t.Fatal(err)
		}
		generations, err := budgetpg.NewRunGenerations(pool)
		if err != nil {
			t.Fatal(err)
		}
		controller, err := budget.New(ledger, generations, discardExposure{}, realClock{}, budget.HeadroomPolicy{MaximumReservedMicros: 1_000_000, ReviewAtBasisPoints: 8000})
		if err != nil {
			t.Fatal(err)
		}
		return controller
	}
	scope := budget.Scope{WorkspaceID: workspace, ProjectID: project}
	controller := newController()
	estimate := budget.Estimate{
		ReservationID:     "budget:" + root + ":g1",
		RootRunID:         root,
		RunID:             root,
		WorkspaceID:       workspace,
		ProjectID:         project,
		PolicyVersion:     "policy-v1",
		BudgetVersion:     "budget-v1",
		MaximumCostMicros: worstCase,
		ExpiresAt:         time.Now().Add(time.Hour).UTC(),
	}
	prior, err := controller.ReserveInitial(ctx, estimate, 1)
	if err != nil {
		t.Fatal(err)
	}
	// The aggregate retries while the first attempt is still running, and the
	// replacement reserves against the still-open prior hold.
	if _, err := pool.Exec(ctx, `UPDATE agent_control.agent_runs SET execution_generation=2,version=version+1 WHERE workspace_id=$1 AND project_id=$2 AND run_id=$3`, workspace, project, root); err != nil {
		t.Fatal(err)
	}
	replacement := estimate
	replacement.ReservationID = "budget:" + root + ":g2"
	replacement.MaximumCostMicros = 500
	if _, err := controller.ReserveReplacement(ctx, replacement, 2, prior.ID); err != nil {
		t.Fatal(err)
	}
	// Finality for the superseded attempt is recorded durably, and the process
	// dies before settling against it.
	if err := controller.Observe(ctx, budget.Observation{ID: "late-final-observation", Scope: scope, ReservationID: prior.ID, RootRunID: root, RunID: root, TaskID: "settlement", AttemptID: "attempt-late-final", ExecutionGeneration: 1, CostMicros: actual, Final: true}); err != nil {
		t.Fatal(err)
	}
	var stranded int64
	var strandedFinal bool
	if err := pool.QueryRow(ctx, `SELECT upper_bound_micros,attempt_final FROM agent_control.budget_reservations WHERE workspace_id=$1 AND project_id=$2 AND reservation_id=$3`, workspace, project, prior.ID).Scan(&stranded, &strandedFinal); err != nil {
		t.Fatal(err)
	}
	if stranded != worstCase || !strandedFinal {
		t.Fatalf("crash window row = bound %d final %t, want a final hold still carrying its worst case", stranded, strandedFinal)
	}

	// A foreign tenant owning a root run of the very same identity, and itself
	// a legitimate settlement authority, reaches nothing here.
	foreign := budget.Scope{WorkspaceID: "workspace-late-final-foreign", ProjectID: project}
	if swept, err := newController().RecoverSupersededFinality(ctx, foreign, root, budget.SettlementActor); err != nil || len(swept) != 0 {
		t.Fatalf("foreign tenant sweep = %+v err=%v, want no reach across the tenant boundary", swept, err)
	}
	// Neither may an unauthorized actor, nor a caller whose view of the
	// current generation is not the authority's own.
	if _, err := newController().RecoverSupersededFinality(ctx, scope, root, "operator"); err == nil {
		t.Fatal("an unauthorized actor ran the durable recovery sweep")
	}
	if _, err := newController().ReconcileSuperseded(ctx, scope, root, 1, budget.SettlementActor); err == nil {
		t.Fatal("a stale view of the current generation settled superseded holds")
	}

	// A successor process recovers from durable state alone.
	recovered, err := newController().RecoverSupersededFinality(ctx, scope, root, budget.SettlementActor)
	if err != nil {
		t.Fatal(err)
	}
	if len(recovered) != 1 || recovered[0].ID != prior.ID || recovered[0].UpperBoundMicros != actual || recovered[0].Released {
		t.Fatalf("recovered = %+v, want a single non-releasing reduction to reported usage", recovered)
	}
	// Recovery is idempotent, and replay of the interrupted settlement step
	// converges on the same answer rather than failing on the settled hold.
	if again, err := newController().RecoverSupersededFinality(ctx, scope, root, budget.SettlementActor); err != nil || len(again) != 0 {
		t.Fatalf("repeat recovery = %+v err=%v, want a no-op", again, err)
	}
	replayed := newController()
	if err := replayed.Observe(ctx, budget.Observation{ID: "late-final-observation", Scope: scope, ReservationID: prior.ID, RootRunID: root, RunID: root, TaskID: "settlement", AttemptID: "attempt-late-final", ExecutionGeneration: 1, CostMicros: actual, Final: true}); err != nil {
		t.Fatalf("replayed final observation was refused: %v", err)
	}
	converged, err := replayed.Reconcile(ctx, scope, prior.ID, 1, ptrMicros(actual), true, budget.SettlementActor)
	if err != nil || converged.UpperBoundMicros != actual || converged.Released {
		t.Fatalf("replayed settlement = %+v err=%v, want convergence with no release", converged, err)
	}

	// The durable row proves what the recovery did and did not do: the unspent
	// worst case is back, the attempt's real cost is still counted, the hold
	// still belongs to the generation that made it, and it is not released.
	var bound, observed int64
	var generation uint64
	var released bool
	if err := pool.QueryRow(ctx, `SELECT upper_bound_micros,observed_micros,controller_generation,released FROM agent_control.budget_reservations WHERE workspace_id=$1 AND project_id=$2 AND reservation_id=$3`, workspace, project, prior.ID).Scan(&bound, &observed, &generation, &released); err != nil {
		t.Fatal(err)
	}
	if bound != actual || observed != actual || generation != 1 || released {
		t.Fatalf("recovered row = bound %d observed %d generation %d released %t", bound, observed, generation, released)
	}
	// And the hold has no authority to dispatch under any generation.
	for name, attempt := range map[string]budget.Generation{"own-generation": 1, "current-generation": 2} {
		if err := controller.Dispatch(ctx, scope, prior.ID, attempt, func(context.Context, budget.Reservation) error {
			t.Fatalf("%s dispatched a recovered superseded reservation", name)
			return nil
		}); err == nil {
			t.Fatalf("%s dispatch was permitted", name)
		}
	}
}

func ptrMicros(value int64) *int64 { return &value }

type discardExposure struct{}

func (discardExposure) ObserveExposure(context.Context, string, int64, int64, bool) error {
	return nil
}

// assertWorkerLeaseRenewal proves the durable lease renewal fence: a correct
// heartbeat extends the active lease; a stale expectation, a foreign fence
// token, an expired lease, and a reclaimed lease are all refused; a late
// result under a reclaimed lease is fenced out with a diagnostic; and the
// current lease's result is accepted.
func assertWorkerLeaseRenewal(t *testing.T, ctx context.Context, pool *pgxpool.Pool) {
	t.Helper()
	register, err := recoverypg.NewMirrorEpochSource(pool)
	if err != nil {
		t.Fatal(err)
	}
	if err := register.EnsureBaseline(ctx); err != nil {
		t.Fatal(err)
	}
	epoch, err := register.Current(ctx)
	if err != nil {
		t.Fatal(err)
	}
	ttl := 400 * time.Millisecond
	dispatch, err := schedulerpg.NewDurableScheduler(pool, register, execution.DispatchIDs{}, realClock{}, scheduler.PrerequisiteFunc(func(context.Context, scheduler.Create) error { return nil }), ttl)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO agent_control.budget_reservations(workspace_id,project_id,root_run_id,run_id,reservation_id,controller_generation,policy_version,budget_version,upper_bound_micros,expires_at) VALUES('workspace-renewal','project-renewal','run-renewal','run-renewal','reservation-renewal',1,'run-pinned','run-pinned',0,$1)`, time.Now().Add(time.Hour).UTC()); err != nil {
		t.Fatal(err)
	}
	scope := scheduler.Scope{WorkspaceID: "workspace-renewal", ProjectID: "project-renewal"}
	create := scheduler.Create{
		Scope:               scope,
		TaskID:              "task-renewal",
		RunID:               "run-renewal",
		RootRunID:           "run-renewal",
		RecoveryEpoch:       uint64(epoch),
		ExecutionGeneration: 1,
		Capability:          "fake.execute",
		ReservationID:       "reservation-renewal",
		ReservationCurrent:  true,
		PolicyAllowed:       true,
		InputDigest:         "sha256:" + strings.Repeat("a", 64),
		InputObjectKey:      "inputs/task-renewal",
		CreatedAt:           time.Now().UTC(),
	}
	if _, err := dispatch.Create(ctx, create); err != nil {
		t.Fatal(err)
	}
	lease, err := dispatch.Lease(ctx, scope, "task-renewal", "renewal-executor-a")
	if err != nil {
		t.Fatal(err)
	}
	renewed, err := dispatch.Heartbeat(ctx, scope, lease, lease.ExpiresAt)
	if err != nil {
		t.Fatal(err)
	}
	if !renewed.ExpiresAt.After(lease.ExpiresAt) || renewed.FenceToken != lease.FenceToken || renewed.LeaseEpoch != lease.LeaseEpoch {
		t.Fatalf("renewed=%+v, want the same lease identity with an extended expiry", renewed)
	}
	// A stale expected expiry — the renewal the caller missed — is refused.
	if _, err := dispatch.Heartbeat(ctx, scope, lease, lease.ExpiresAt); err == nil {
		t.Fatal("a stale expected expiry renewed the lease")
	}
	forged := renewed
	forged.FenceToken = "fence." + strings.Repeat("0", 32)
	if _, err := dispatch.Heartbeat(ctx, scope, forged, renewed.ExpiresAt); err == nil {
		t.Fatal("a foreign fence token renewed the lease")
	}
	// The renewal keeps a long execution alive past the original TTL.
	deadline := time.Now().Add(5 * time.Second)
	current := renewed
	for time.Now().Before(lease.ExpiresAt.Add(ttl / 2)) {
		if time.Now().After(deadline) {
			t.Fatal("renewal loop never crossed the original expiry")
		}
		next, err := dispatch.Heartbeat(ctx, scope, current, current.ExpiresAt)
		if err != nil {
			t.Fatal(err)
		}
		current = next
		time.Sleep(ttl / 8)
	}
	// Now the lease expires for real: no renewal arrives, a successor
	// reclaims, and the late owner can neither renew nor land its result.
	for time.Now().Before(current.ExpiresAt.Add(50 * time.Millisecond)) {
		time.Sleep(20 * time.Millisecond)
	}
	if _, err := dispatch.Heartbeat(ctx, scope, current, current.ExpiresAt); err == nil {
		t.Fatal("an expired lease was renewed")
	}
	reclaimed, err := dispatch.ReclaimExpired(ctx, scope, "task-renewal")
	if err != nil || !reclaimed {
		t.Fatalf("reclaim=%v err=%v", reclaimed, err)
	}
	successor, err := dispatch.Lease(ctx, scope, "task-renewal", "renewal-executor-b")
	if err != nil {
		t.Fatal(err)
	}
	if successor.LeaseEpoch <= current.LeaseEpoch {
		t.Fatalf("successor lease epoch=%d, want monotonic over %d", successor.LeaseEpoch, current.LeaseEpoch)
	}
	if _, err := dispatch.Heartbeat(ctx, scope, current, current.ExpiresAt); err == nil {
		t.Fatal("a reclaimed lease was renewed by its late owner")
	}
	output := []byte(`{"echo":"renewal"}`)
	lateResult := scheduler.Result{
		TaskID:              "task-renewal",
		RecoveryEpoch:       uint64(epoch),
		ExecutionGeneration: 1,
		PhysicalAttemptID:   current.PhysicalAttemptID,
		LeaseEpoch:          current.LeaseEpoch,
		FenceToken:          current.FenceToken,
		Capability:          "fake.execute",
		BuildIdentity:       "sha256:" + strings.Repeat("b", 64),
		ArtifactID:          "tool-output.renewal",
		ArtifactDigest:      scheduler.OutputDigest(output),
		PendingObjectKey:    "pending/task-renewal/r" + itoa(uint64(epoch)) + "/g1/" + string(current.PhysicalAttemptID) + "/output.json",
		CompletedAt:         time.Now().UTC(),
	}
	_, lateErr := dispatch.AcceptResult(ctx, scope, lateResult, output)
	var details problem.Details
	if !errors.As(lateErr, &details) || details.Code != string(problem.CodeWorkerFenceStale) {
		t.Fatalf("late result = %v, want the stale fence", lateErr)
	}
	var diagnostics int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM agent_workflow.result_diagnostics WHERE workspace_id='workspace-renewal' AND task_id='task-renewal'`).Scan(&diagnostics); err != nil || diagnostics != 1 {
		t.Fatalf("diagnostics=%d err=%v, want the late result recorded", diagnostics, err)
	}
	winning := lateResult
	winning.PhysicalAttemptID = successor.PhysicalAttemptID
	winning.LeaseEpoch = successor.LeaseEpoch
	winning.FenceToken = successor.FenceToken
	winning.PendingObjectKey = "pending/task-renewal/r" + itoa(uint64(epoch)) + "/g1/" + string(successor.PhysicalAttemptID) + "/output.json"
	winning.CompletedAt = time.Now().UTC()
	acceptance, err := dispatch.AcceptResult(ctx, scope, winning, output)
	if err != nil || !acceptance.Accepted {
		t.Fatalf("acceptance=%+v err=%v", acceptance, err)
	}
}

func itoa(value uint64) string {
	if value == 0 {
		return "0"
	}
	var digits []byte
	for value > 0 {
		digits = append([]byte{byte('0' + value%10)}, digits...)
		value /= 10
	}
	return string(digits)
}

// assertBudgetHeadroomIsAtomicAndScoped proves the durable ledger's headroom
// bound against real concurrency and real tenancy. Racing reservations against
// one root can never together exceed the configured maximum, an elapsed hold
// is settled explicitly rather than silently dropped from the sum, and a
// reservation identity never resolves outside the tenant that owns it.
func assertBudgetHeadroomIsAtomicAndScoped(t *testing.T, ctx context.Context, pool *pgxpool.Pool) {
	t.Helper()
	const (
		racers  = 24
		cost    = int64(100)
		maximum = int64(1000)
	)
	for _, scope := range []budget.Scope{{WorkspaceID: "workspace-headroom", ProjectID: "project-headroom"}, {WorkspaceID: "workspace-headroom", ProjectID: "project-neighbour"}, {WorkspaceID: "workspace-neighbour", ProjectID: "project-headroom"}} {
		if _, err := pool.Exec(ctx, `INSERT INTO agent_control.agent_runs(workspace_id,project_id,run_id,state,version,execution_generation,next_event_sequence,snapshot) VALUES($1,$2,'run-headroom','created',1,1,2,'{}')`, scope.WorkspaceID, scope.ProjectID); err != nil {
			t.Fatal(err)
		}
	}
	newController := func() *budget.Controller {
		t.Helper()
		ledger, err := budgetpg.NewLedger(pool, func() time.Time { return time.Now().UTC() })
		if err != nil {
			t.Fatal(err)
		}
		generations, err := budgetpg.NewRunGenerations(pool)
		if err != nil {
			t.Fatal(err)
		}
		controller, err := budget.New(ledger, generations, discardExposure{}, realClock{}, budget.HeadroomPolicy{MaximumReservedMicros: maximum, ReviewAtBasisPoints: 8000})
		if err != nil {
			t.Fatal(err)
		}
		return controller
	}
	scope := budget.Scope{WorkspaceID: "workspace-headroom", ProjectID: "project-headroom"}
	estimateFor := func(scope budget.Scope, identity string, upper int64, expires time.Time) budget.Estimate {
		return budget.Estimate{
			ReservationID:     budget.ReservationID(identity),
			RootRunID:         "run-headroom",
			RunID:             "run-headroom",
			WorkspaceID:       scope.WorkspaceID,
			ProjectID:         scope.ProjectID,
			PolicyVersion:     "policy-v1",
			BudgetVersion:     "budget-v1",
			MaximumCostMicros: upper,
			ExpiresAt:         expires,
		}
	}

	// Each racer runs on its own controller over its own pooled connections,
	// which is what a fleet of replicas actually looks like to the ledger.
	var start sync.WaitGroup
	var finished sync.WaitGroup
	start.Add(1)
	accepted := make([]bool, racers)
	for index := 0; index < racers; index++ {
		finished.Add(1)
		go func(index int) {
			defer finished.Done()
			controller := newController()
			start.Wait()
			_, err := controller.ReserveInitial(ctx, estimateFor(scope, fmt.Sprintf("budget:headroom:%02d", index), cost, time.Now().Add(time.Hour).UTC()), 1)
			accepted[index] = err == nil
		}(index)
	}
	start.Done()
	finished.Wait()
	granted := 0
	for _, ok := range accepted {
		if ok {
			granted++
		}
	}
	if int64(granted)*cost > maximum {
		t.Fatalf("granted %d concurrent reservations of %d against a %d maximum", granted, cost, maximum)
	}
	if granted != int(maximum/cost) {
		t.Fatalf("granted %d reservations, want the maximum fully but exactly used", granted)
	}
	var held int64
	if err := pool.QueryRow(ctx, `SELECT COALESCE(SUM(upper_bound_micros),0) FROM agent_control.budget_reservations WHERE workspace_id=$1 AND project_id=$2 AND root_run_id='run-headroom' AND released=false`, scope.WorkspaceID, scope.ProjectID).Scan(&held); err != nil {
		t.Fatal(err)
	}
	if held != maximum {
		t.Fatalf("durable held exposure=%d, want exactly the configured maximum", held)
	}

	// A neighbouring tenant has its own headroom and its own identities: the
	// same reservation identity there is a different row, and it is invisible
	// from here.
	controller := newController()
	for _, neighbour := range []budget.Scope{{WorkspaceID: "workspace-headroom", ProjectID: "project-neighbour"}, {WorkspaceID: "workspace-neighbour", ProjectID: "project-headroom"}} {
		if _, err := controller.ReserveInitial(ctx, estimateFor(neighbour, "budget:headroom:00", maximum, time.Now().Add(time.Hour).UTC()), 1); err != nil {
			t.Fatalf("neighbour %+v could not use its own headroom: %v", neighbour, err)
		}
		reservations, err := controller.RootTotal(ctx, neighbour, "run-headroom")
		if err != nil || reservations != maximum {
			t.Fatalf("neighbour %+v aggregated %d err=%v, want only its own reservation", neighbour, reservations, err)
		}
	}
	if _, err := controller.Reservation(ctx, budget.Scope{WorkspaceID: "workspace-headroom", ProjectID: "project-absent"}, "budget:headroom:00"); err == nil {
		t.Fatal("a reservation identity resolved outside its tenant")
	}

	// An elapsed hold is fenced durably, with its own immutable record. It
	// keeps its worst-case bound, claims no finality, and is not released:
	// the clock proves the lifetime elapsed, never what the attempt spent.
	elapsed := estimateFor(scope, "budget:headroom:expiring", 500, time.Now().Add(-time.Minute).UTC())
	if _, err := pool.Exec(ctx, `INSERT INTO agent_control.budget_reservations(workspace_id,project_id,root_run_id,run_id,reservation_id,controller_generation,policy_version,budget_version,upper_bound_micros,expires_at,created_at,updated_at) VALUES($1,$2,$3,$4,$5,1,'policy-v1','budget-v1',$6,$7,now(),now())`,
		elapsed.WorkspaceID, elapsed.ProjectID, elapsed.RootRunID, elapsed.RunID, elapsed.ReservationID, elapsed.MaximumCostMicros, elapsed.ExpiresAt); err != nil {
		t.Fatal(err)
	}
	fenced, err := controller.FenceExpired(ctx, scope, "run-headroom")
	if err != nil || len(fenced) != 1 || fenced[0].ID != elapsed.ReservationID {
		t.Fatalf("fenced=%+v err=%v, want exactly the elapsed hold", fenced, err)
	}
	if !fenced[0].Expired || fenced[0].Released || fenced[0].AttemptFinal || fenced[0].UpperBoundMicros != 500 {
		t.Fatalf("fenced=%+v, want a fence that keeps the worst-case hold and claims no finality", fenced[0])
	}
	var recorded, final int
	if err := pool.QueryRow(ctx, `SELECT count(*), count(*) FILTER (WHERE final OR cost_micros<>0) FROM agent_control.budget_observations WHERE workspace_id=$1 AND project_id=$2 AND observation_id=$3`, scope.WorkspaceID, scope.ProjectID, budget.ExpiryObservationID(elapsed.ReservationID)).Scan(&recorded, &final); err != nil {
		t.Fatal(err)
	}
	if recorded != 1 || final != 0 {
		t.Fatalf("expiry records=%d asserting cost or finality=%d, want one record asserting neither", recorded, final)
	}
	// The physical attempt that outlived its lifetime is still spending: its
	// late usage lands additively on the fenced hold, and replaying the same
	// observation identity counts it exactly once.
	late := budget.Observation{ID: "usage:late", Scope: scope, ReservationID: elapsed.ReservationID, RootRunID: elapsed.RootRunID, RunID: elapsed.RunID, TaskID: "model", AttemptID: "attempt-late", CostMicros: 120}
	for attempt := 0; attempt < 2; attempt++ {
		if err := controller.Observe(ctx, late); err != nil {
			t.Fatalf("late usage from an expired attempt was rejected on attempt %d: %v", attempt, err)
		}
	}
	accrued, err := controller.Reservation(ctx, scope, elapsed.ReservationID)
	if err != nil || accrued.ObservedMicros != 120 || accrued.UpperBoundMicros != 500 || accrued.Released {
		t.Fatalf("reservation after late usage=%+v err=%v, want 120 observed against the retained bound", accrued, err)
	}
	// Replaying the elapsed reservation identity is refused rather than
	// answered with a reservation that can no longer authorize anything.
	if _, err := controller.ReserveInitial(ctx, estimateFor(scope, "budget:headroom:expiring", 500, elapsed.ExpiresAt), 1); err == nil {
		t.Fatal("an expired reservation replayed as a successful reservation")
	}
	// The durable guard refuses a release that is not backed by authoritative
	// finality, whoever attempts it.
	if _, err := pool.Exec(ctx, `UPDATE agent_control.budget_reservations SET released=true,updated_at=now() WHERE workspace_id=$1 AND project_id=$2 AND reservation_id=$3`, scope.WorkspaceID, scope.ProjectID, elapsed.ReservationID); err == nil {
		t.Fatal("the durable guard released a reservation before attempt finality")
	}
	// The fence is irreversible.
	if _, err := pool.Exec(ctx, `UPDATE agent_control.budget_reservations SET expired=false,updated_at=now() WHERE workspace_id=$1 AND project_id=$2 AND reservation_id=$3`, scope.WorkspaceID, scope.ProjectID, elapsed.ReservationID); err == nil {
		t.Fatal("the durable guard un-fenced an expired reservation")
	}
	// Sweeping again converges: a hold is fenced once.
	again, err := controller.FenceExpired(ctx, scope, "run-headroom")
	if err != nil || len(again) != 0 {
		t.Fatalf("second sweep fenced=%d err=%v, want nothing left", len(again), err)
	}
	// Authoritative finality releases the hold and returns the headroom.
	if err := controller.Observe(ctx, budget.Observation{ID: "usage:final", Scope: scope, ReservationID: elapsed.ReservationID, RootRunID: elapsed.RootRunID, RunID: elapsed.RunID, TaskID: "settlement", AttemptID: "attempt-final", Final: true}); err != nil {
		t.Fatal(err)
	}
	finalCost := int64(120)
	settled, err := controller.Reconcile(ctx, scope, elapsed.ReservationID, 1, &finalCost, true, budget.SettlementActor)
	if err != nil || !settled.Released || settled.UpperBoundMicros != 120 {
		t.Fatalf("settled=%+v err=%v, want release at the authoritative final cost", settled, err)
	}
}

// receiptClock is one movable authoritative time the durable receipt store
// reads, so a test can move past a claim lease without waiting.
type receiptClock struct {
	lock  sync.Mutex
	value time.Time
}

func (c *receiptClock) Now() time.Time {
	c.lock.Lock()
	defer c.lock.Unlock()
	return c.value
}
func (c *receiptClock) advance(by time.Duration) {
	c.lock.Lock()
	defer c.lock.Unlock()
	c.value = c.value.Add(by)
}

// assertCommandReceipts proves the durable ADR-021 §4 receipt store keeps the
// assertCommandReceipts proves the durable ADR-021 §4 receipt store keeps the
// whole contract: an exact replay returns the recorded representation, every
// form of key misuse is a stable conflict under its governed code, the
// verified credential subject isolates one caller's keys from another's,
// concurrent duplicates resolve to exactly one claimant, a released claim
// stays retryable without forgetting its bytes, a claim whose process died
// becomes reclaimable once its lease elapses, and the claim token fences
// ownership so a timed-out claimant can neither record over nor abandon the
// claim that replaced it.
func assertCommandReceipts(t *testing.T, ctx context.Context, pool *pgxpool.Pool) {
	t.Helper()
	clock := &receiptClock{value: time.Now().UTC()}
	receipts, err := runapppg.NewReceipts(pool, time.Hour, time.Minute, clock.Now)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := runapppg.NewReceipts(pool, time.Minute, time.Hour, clock.Now); err == nil {
		t.Fatal("a claim lease longer than the receipt retention was accepted")
	}
	base := runapp.CommandReceiptRequest{
		WorkspaceID: "workspace-receipts",
		ProjectID:   "project-receipts",
		Subject:     "operator.one",
		Method:      runapp.ReceiptMethod,
		Route:       runapp.ResolveDomainOperationRoute,
		Key:         "receipt-key",
		RunID:       "run-receipts",
		Digest:      "sha256:" + strings.Repeat("a", 64),
		Version:     3,
	}
	recorded := runapp.CommandReceipt{Body: []byte(`{"runId":"run-receipts","status":"failed"}`), ETag: `"run:run-receipts:4"`}

	// The first claim executes; nothing is replayed, and it is issued a claim
	// token the later phases have to present.
	value, claim, replayed, err := receipts.Begin(ctx, base)
	if err != nil || replayed || value.Body != nil || !claim.Held() {
		t.Fatalf("first claim = %+v claim=%+v replayed=%v err=%v, want a fresh held claim", value, claim, replayed, err)
	}
	// A concurrent duplicate is told the key is in flight rather than running
	// the command alongside it, and is issued no claim.
	if _, duplicate, _, err := receipts.Begin(ctx, base); !isReceiptConflict(err, runapp.ReceiptInFlight) || duplicate.Held() {
		t.Fatalf("in-flight duplicate = claim %+v err=%v, want the in-flight conflict and no claim", duplicate, err)
	}
	// Recording without the claim Begin issued is refused outright.
	if err := receipts.Record(ctx, base, runapp.ReceiptClaim{}, recorded); err == nil {
		t.Fatal("recording without a claim token was accepted")
	}
	if err := receipts.Record(ctx, base, claim, recorded); err != nil {
		t.Fatal(err)
	}
	// An exact replay returns the recorded representation and its ETag, and
	// carries no claim: there is nothing left to record.
	replayValue, replayClaim, replayed, err := receipts.Begin(ctx, base)
	if err != nil || !replayed || string(replayValue.Body) != string(recorded.Body) || replayValue.ETag != recorded.ETag || replayClaim.Held() {
		t.Fatalf("replay = %+v claim=%+v replayed=%v err=%v, want the recorded representation and no claim", replayValue, replayClaim, replayed, err)
	}

	// Every form of key misuse is its own stable conflict under its own
	// governed code: changed canonical bytes is IDEMPOTENCY_KEY_REUSED, the
	// unrelated semantic conflicts stay IDEMPOTENCY_CONFLICT.
	for name, mutate := range map[string]func(runapp.CommandReceiptRequest) (runapp.CommandReceiptRequest, string){
		"different-bytes": func(r runapp.CommandReceiptRequest) (runapp.CommandReceiptRequest, string) {
			r.Digest = "sha256:" + strings.Repeat("b", 64)
			return r, runapp.ReceiptBytesReused
		},
		"different-run": func(r runapp.CommandReceiptRequest) (runapp.CommandReceiptRequest, string) {
			r.RunID = "run-other"
			return r, runapp.ReceiptResourceReused
		},
		"different-revision": func(r runapp.CommandReceiptRequest) (runapp.CommandReceiptRequest, string) {
			r.Version = 9
			return r, runapp.ReceiptRevisionReused
		},
	} {
		request, detail := mutate(base)
		if _, _, _, err := receipts.Begin(ctx, request); !isReceiptConflict(err, detail) {
			t.Fatalf("%s = %v, want %q", name, err, detail)
		}
		if err := receipts.Record(ctx, request, claim, recorded); !isReceiptConflict(err, detail) {
			t.Fatalf("%s recording = %v, want %q", name, err, detail)
		}
	}
	// The governed code is the whole point of the split: a client can tell
	// "you changed the command" from "the command cannot run right now".
	reusedBytes := base
	reusedBytes.Digest = "sha256:" + strings.Repeat("b", 64)
	if _, _, _, err := receipts.Begin(ctx, reusedBytes); !isProblemCode(err, problem.CodeIdempotencyKeyReused) {
		t.Fatalf("changed canonical bytes = %v, want IDEMPOTENCY_KEY_REUSED", err)
	}
	staleRevision := base
	staleRevision.Version = 9
	if !isProblemCode(mustBeginError(ctx, receipts, staleRevision), problem.CodeIdempotencyConflict) {
		t.Fatal("a different observed revision must stay IDEMPOTENCY_CONFLICT")
	}

	// A different verified credential subject holds its own key space, even
	// when everything else about the request is identical.
	other := base
	other.Subject = "operator.two"
	if _, otherClaim, replayed, err := receipts.Begin(ctx, other); err != nil || replayed || !otherClaim.Held() {
		t.Fatalf("second subject = replayed %v claim=%+v err=%v, want its own fresh claim", replayed, otherClaim, err)
	}

	// Concurrent duplicates on one unclaimed key resolve to exactly one
	// claimant; every other caller is told the key is in flight.
	concurrent := base
	concurrent.Key = "receipt-key-concurrent"
	const racers = 8
	var start sync.WaitGroup
	var finished sync.WaitGroup
	start.Add(1)
	claims := make([]bool, racers)
	conflicts := make([]bool, racers)
	for index := 0; index < racers; index++ {
		finished.Add(1)
		go func(index int) {
			defer finished.Done()
			start.Wait()
			_, held, replayed, err := receipts.Begin(ctx, concurrent)
			claims[index] = err == nil && !replayed && held.Held()
			conflicts[index] = isReceiptConflict(err, runapp.ReceiptInFlight)
		}(index)
	}
	start.Done()
	finished.Wait()
	claimed, refused := 0, 0
	for index := 0; index < racers; index++ {
		if claims[index] {
			claimed++
		}
		if conflicts[index] {
			refused++
		}
	}
	if claimed != 1 || claimed+refused != racers {
		t.Fatalf("concurrent claims=%d in-flight=%d of %d, want exactly one claimant and the rest refused", claimed, refused, racers)
	}

	// A released claim stays retryable under the same bytes without becoming a
	// fresh key: reuse with different bytes is still a conflict.
	released := base
	released.Key = "receipt-key-released"
	_, releasedClaim, _, err := receipts.Begin(ctx, released)
	if err != nil {
		t.Fatal(err)
	}
	if err := receipts.Abandon(ctx, released, releasedClaim); err != nil {
		t.Fatal(err)
	}
	// The releasing holder's token dies with the release, so it cannot come
	// back and record onto the claim it let go.
	if err := receipts.Record(ctx, released, releasedClaim, recorded); !isReceiptConflict(err, runapp.ReceiptClaimLost) {
		t.Fatalf("recording after releasing the claim = %v, want the lost-claim conflict", err)
	}
	_, retryClaim, replayed, err := receipts.Begin(ctx, released)
	if err != nil || replayed || !retryClaim.Held() {
		t.Fatalf("retry after release = replayed %v claim=%+v err=%v, want a reclaimed execution", replayed, retryClaim, err)
	}
	reused := released
	reused.Digest = "sha256:" + strings.Repeat("c", 64)
	if _, _, _, err := receipts.Begin(ctx, reused); !isReceiptConflict(err, runapp.ReceiptBytesReused) {
		t.Fatalf("released key reused with different bytes = %v, want a conflict", err)
	}

	// A claim whose process died is refused inside its lease and reclaimable
	// after it — and the claim token is what stops the timed-out claimant from
	// interfering with its successor.
	crashed := base
	crashed.Key = "receipt-key-crashed"
	_, staleClaim, _, err := receipts.Begin(ctx, crashed)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, _, err := receipts.Begin(ctx, crashed); !isReceiptConflict(err, runapp.ReceiptInFlight) {
		t.Fatalf("claim inside its lease = %v, want the in-flight conflict", err)
	}
	clock.advance(2 * time.Minute)
	_, successor, replayed, err := receipts.Begin(ctx, crashed)
	if err != nil || replayed || !successor.Held() {
		t.Fatalf("reclaim after the lease = replayed %v claim=%+v err=%v, want a reclaimed execution", replayed, successor, err)
	}
	if successor == staleClaim {
		t.Fatal("the takeover reused the timed-out claimant's token")
	}
	// The timed-out claimant finishes late. It may neither record its outcome
	// over its successor's claim nor release the claim its successor holds.
	if err := receipts.Record(ctx, crashed, staleClaim, runapp.CommandReceipt{Body: []byte(`{"runId":"run-receipts","status":"stale"}`), ETag: `"run:run-receipts:99"`}); !isReceiptConflict(err, runapp.ReceiptClaimLost) {
		t.Fatalf("stale record = %v, want the lost-claim conflict", err)
	}
	if err := receipts.Abandon(ctx, crashed, staleClaim); err != nil {
		t.Fatal(err)
	}
	if _, _, _, err := receipts.Begin(ctx, crashed); !isReceiptConflict(err, runapp.ReceiptInFlight) {
		t.Fatalf("the stale claimant's abandon released its successor's claim: %v", err)
	}
	// The successor records the only outcome the key ever answers with.
	if err := receipts.Record(ctx, crashed, successor, recorded); err != nil {
		t.Fatal(err)
	}
	replayCrashed, _, replayed, err := receipts.Begin(ctx, crashed)
	if err != nil || !replayed || string(replayCrashed.Body) != string(recorded.Body) {
		t.Fatalf("reclaimed outcome = %+v replayed=%v err=%v, want the successor's recorded replay", replayCrashed, replayed, err)
	}

	// Recording against a claim that no longer exists is reported, never
	// silently ignored.
	lost := base
	lost.Key = "receipt-key-lost"
	if err := receipts.Record(ctx, lost, runapp.ReceiptClaim{Epoch: 1}, recorded); !isReceiptConflict(err, runapp.ReceiptClaimLost) {
		t.Fatalf("recording without a claim = %v, want the lost-claim conflict", err)
	}
}

// mustBeginError returns only the error one Begin produced, for the assertions
// that care about nothing else.
func mustBeginError(ctx context.Context, receipts *runapppg.Receipts, request runapp.CommandReceiptRequest) error {
	_, _, _, err := receipts.Begin(ctx, request)
	return err
}

func isProblemCode(err error, code problem.Code) bool {
	var details problem.Details
	return errors.As(err, &details) && details.Code == string(code)
}

// isReceiptConflict matches one conflict by its stable detail and the governed
// code that detail carries. Changed canonical bytes answers under
// IDEMPOTENCY_KEY_REUSED (ADR-021 §4); every other conflict answers under the
// general idempotency conflict.
func isReceiptConflict(err error, detail string) bool {
	code := problem.CodeIdempotencyConflict
	if detail == runapp.ReceiptBytesReused {
		code = problem.CodeIdempotencyKeyReused
	}
	var details problem.Details
	return errors.As(err, &details) && details.Code == string(code) && details.Detail == detail
}

// assertBudgetSettlementIsConcurrencySafe proves the durable settlement is a
// compare-and-set against the usage and finality the caller read, and that
// cancellation fencing is a durable, irreversible property of the row rather
// than a decision one writer makes.
//
// The defect it stands against loses money: a settlement that writes a cost
// derived from a stale read silently overwrites usage that committed inside
// the window, and the attempt's real spend disappears from the ledger. The
// database is the enforcement point, so the proof is here rather than only
// over the in-memory ledger.
func assertBudgetSettlementIsConcurrencySafe(t *testing.T, ctx context.Context, pool *pgxpool.Pool) {
	t.Helper()
	if _, err := pool.Exec(ctx, `INSERT INTO agent_control.agent_runs(workspace_id,project_id,run_id,state,version,execution_generation,next_event_sequence,snapshot) VALUES('workspace-cas','project-cas','run-cas','created',1,1,2,'{}')`); err != nil {
		t.Fatal(err)
	}
	ledger, err := budgetpg.NewLedger(pool, func() time.Time { return time.Now().UTC() })
	if err != nil {
		t.Fatal(err)
	}
	generations, err := budgetpg.NewRunGenerations(pool)
	if err != nil {
		t.Fatal(err)
	}
	controller, err := budget.New(ledger, generations, discardExposure{}, realClock{}, budget.HeadroomPolicy{MaximumReservedMicros: 1_000_000, ReviewAtBasisPoints: 8000})
	if err != nil {
		t.Fatal(err)
	}
	scope := budget.Scope{WorkspaceID: "workspace-cas", ProjectID: "project-cas"}
	reserved, err := controller.ReserveInitial(ctx, budget.Estimate{
		ReservationID:     "budget:run-cas:g1",
		RootRunID:         "run-cas",
		RunID:             "run-cas",
		WorkspaceID:       "workspace-cas",
		ProjectID:         "project-cas",
		PolicyVersion:     "policy-v1",
		BudgetVersion:     "budget-v1",
		MaximumCostMicros: 10_000,
		ExpiresAt:         time.Now().Add(time.Hour).UTC(),
	}, 1)
	if err != nil {
		t.Fatal(err)
	}
	usage := func(id string, cost int64, final bool) budget.Observation {
		return budget.Observation{ID: id, Scope: scope, ReservationID: reserved.ID, RootRunID: "run-cas", RunID: "run-cas", TaskID: "model:turn-0000", AttemptID: budget.AttemptID("attempt-" + id), ExecutionGeneration: 1, CostMicros: cost, Final: final}
	}
	if err := controller.Observe(ctx, usage("cas-first", 400, true)); err != nil {
		t.Fatal(err)
	}
	// The usage a settling caller read, and the usage that commits after it.
	read, err := controller.Reservation(ctx, scope, reserved.ID)
	if err != nil {
		t.Fatal(err)
	}
	if err := controller.Observe(ctx, usage("cas-late", 250, false)); err != nil {
		t.Fatal(err)
	}
	stale, err := ledger.Settle(ctx, budget.Settlement{Scope: scope, ReservationID: reserved.ID, Generation: 1, FinalCost: read.ObservedMicros, ExpectedObservedMicros: read.ObservedMicros, ExpectedAttemptFinal: read.AttemptFinal, Release: true, Actor: budget.SettlementActor})
	var conflict budget.Conflict
	if !errors.As(err, &conflict) {
		t.Fatalf("stale durable settlement returned %+v err=%v, want a typed conflict", stale, err)
	}
	if !conflict.Retryable() || conflict.ObservedMicros != 650 {
		t.Fatalf("durable conflict = %+v, want a retryable conflict carrying the usage the row now holds", conflict)
	}
	intact, err := controller.Reservation(ctx, scope, reserved.ID)
	if err != nil || intact.ObservedMicros != 650 || intact.Released {
		t.Fatalf("reservation after the losing settlement = %+v err=%v, want the concurrent usage intact and unreleased", intact, err)
	}
	// Cancellation fencing withdraws dispatch authority durably and settles
	// nothing: the hold keeps its worst-case bound and claims no finality.
	fenced, err := controller.FenceCancelledRun(ctx, scope, "run-cas", "run-cas")
	if err != nil || len(fenced) != 1 || !fenced[0].Cancelled || fenced[0].Released || fenced[0].UpperBoundMicros != 10_000 {
		t.Fatalf("durable cancellation fence = %+v err=%v, want the worst case held and no manufactured finality", fenced, err)
	}
	if _, err := pool.Exec(ctx, `UPDATE agent_control.budget_reservations SET cancelled=false WHERE workspace_id='workspace-cas' AND reservation_id='budget:run-cas:g1'`); err == nil {
		t.Fatal("a durable cancellation fence was reversible")
	}
	if err := controller.Dispatch(ctx, scope, reserved.ID, 1, func(context.Context, budget.Reservation) error {
		t.Fatal("a cancelled durable reservation authorized a dispatch")
		return nil
	}); err == nil {
		t.Fatal("a cancelled durable reservation authorized a dispatch")
	}
	// A fenced hold still accepts the usage its interrupted attempt reports.
	if err := controller.Observe(ctx, usage("cas-after-fence", 125, false)); err != nil {
		t.Fatalf("a cancelled durable hold refused the usage its attempt reported: %v", err)
	}
	concluded, err := controller.ConcludeCancelledRun(ctx, scope, "run-cas", "run-cas", budget.SettlementActor)
	if err != nil || len(concluded) != 1 {
		t.Fatalf("durable conclusion settled %v err=%v, want the fenced hold settled", concluded, err)
	}
	if concluded[0].ObservedMicros != 775 || concluded[0].UpperBoundMicros != 775 || !concluded[0].Released || !concluded[0].Cancelled {
		t.Fatalf("durable concluded hold = %+v, want it settled at the full reported usage, released, and still fenced", concluded[0])
	}
	// Replay and restart converge: a fresh controller over the same durable
	// rows settles nothing further and charges nothing more.
	restarted, err := budget.New(ledger, generations, discardExposure{}, realClock{}, budget.HeadroomPolicy{MaximumReservedMicros: 1_000_000, ReviewAtBasisPoints: 8000})
	if err != nil {
		t.Fatal(err)
	}
	again, err := restarted.RecoverCancelledFinality(ctx, scope, "run-cas", budget.SettlementActor)
	if err != nil || len(again) != 0 {
		t.Fatalf("durable recovery after restart settled %v err=%v, want nothing further", again, err)
	}
	total, err := restarted.RootTotal(ctx, scope, "run-cas")
	if err != nil || total != 775 {
		t.Fatalf("durable root total = %d err=%v, want exactly the usage the attempt reported once", total, err)
	}
}
