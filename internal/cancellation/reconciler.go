// Package cancellation reconciles the external effects a cancelled run may
// still have outstanding. Cancellation is only safe once every effect the run
// caused outside this service is known to be settled, so the reconciler
// inspects the authoritative records rather than inferring safety from the
// run's own phase.
package cancellation

import (
	"context"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/ancyloce/anvilkit-agent-service/internal/runs"
)

// Pools are the durable stores the reconciler reads. Every one is required:
// a reconciler that cannot see an effect domain cannot report that domain
// clear, and reporting "clear" for an unread domain is exactly the failure
// this component exists to prevent.
type Pools struct {
	Control   *pgxpool.Pool
	Workflow  *pgxpool.Pool
	Artifacts *pgxpool.Pool
	Events    *pgxpool.Pool
}

// Reconciler answers whether a cancelled run still has an unresolved external
// effect. It inspects, in order, the authoritative domain effect, the provider
// invocations the run disclosed to, the runtime attempts it dispatched, the
// worker tasks and leases it holds, the tool dispatches its executor leases may
// still be running, and the artifacts it left behind.
type Reconciler struct{ pools Pools }

// New builds the reconciler. It fails closed when any store is missing.
func New(pools Pools) (*Reconciler, error) {
	if pools.Control == nil || pools.Workflow == nil || pools.Artifacts == nil || pools.Events == nil {
		return nil, fmt.Errorf("cancellation reconciler: control, workflow, artifact, and event stores are all required")
	}
	return &Reconciler{pools: pools}, nil
}

// Reconcile reports whether cancellation may be projected as settled and, when
// an authoritative outcome already exists, which terminal state the run
// actually reached. commitPhase says the run was inside the commit boundary
// when cancellation arrived; it never by itself decides the answer, because a
// run outside the commit boundary can still hold an in-flight provider call, a
// leased worker task, or an unsettled artifact.
func (r *Reconciler) Reconcile(ctx context.Context, scope runs.Scope, id runs.ID, commitPhase bool) (bool, *runs.State, error) {
	authoritative, unresolved, err := r.domainEffect(ctx, scope, id)
	if err != nil {
		return false, nil, err
	}
	if authoritative != nil {
		// The domain owner already settled the effect. Cancellation cannot
		// undo it, so the run's real outcome is reported instead.
		return false, authoritative, nil
	}
	if unresolved {
		return false, nil, nil
	}
	if commitPhase {
		// Inside the commit boundary with no settled domain record, the effect
		// may be in flight at the domain owner. Nothing here can prove it is
		// not, so cancellation stays visibly unreconciled.
		return false, nil, nil
	}
	for _, check := range []struct {
		name  string
		query func(context.Context, runs.Scope, runs.ID) (bool, error)
	}{
		{"provider", r.providerInFlight},
		{"runtime", r.runtimeInFlight},
		{"worker", r.workerInFlight},
		{"tool", r.toolInFlight},
		{"artifact", r.artifactInFlight},
	} {
		inFlight, err := check.query(ctx, scope, id)
		if err != nil {
			return false, nil, fmt.Errorf("reconcile %s state: %w", check.name, err)
		}
		if inFlight {
			return false, nil, nil
		}
	}
	return true, nil, nil
}

// domainEffect reads the authoritative governed-effect record. An applied,
// conflicting, or rejected effect is a settled outcome cancellation must not
// overwrite; a recorded, issued, or awaiting effect is unresolved.
func (r *Reconciler) domainEffect(ctx context.Context, scope runs.Scope, id runs.ID) (*runs.State, bool, error) {
	rows, err := r.pools.Control.Query(ctx, `SELECT status FROM agent_control.domain_operations WHERE workspace_id=$1 AND project_id=$2 AND run_id=$3`, scope.WorkspaceID, scope.ProjectID, string(id))
	if err != nil {
		return nil, false, fmt.Errorf("read domain operations: %w", err)
	}
	defer rows.Close()
	var settled *runs.State
	unresolved := false
	for rows.Next() {
		var status string
		if err := rows.Scan(&status); err != nil {
			return nil, false, fmt.Errorf("read domain operation status: %w", err)
		}
		switch status {
		case "applied":
			state := runs.Completed
			settled = &state
		case "conflict":
			state := runs.Conflict
			settled = &state
		case "rejected":
			state := runs.Failed
			settled = &state
		default:
			unresolved = true
		}
	}
	if err := rows.Err(); err != nil {
		return nil, false, fmt.Errorf("read domain operations: %w", err)
	}
	return settled, unresolved, nil
}

// providerInFlight reports whether any provider invocation this run opened is
// still without a completion record.
func (r *Reconciler) providerInFlight(ctx context.Context, scope runs.Scope, id runs.ID) (bool, error) {
	return r.exists(ctx, r.pools.Workflow, `SELECT 1 FROM agent_workflow.provider_invocations WHERE workspace_id=$1 AND project_id=$2 AND run_id=$3 AND completed_at IS NULL LIMIT 1`, scope, id)
}

// workerInFlight reports whether the run still owns a queued or leased worker
// task, an active worker lease, or a queue delivery nothing has acknowledged.
func (r *Reconciler) workerInFlight(ctx context.Context, scope runs.Scope, id runs.ID) (bool, error) {
	for _, source := range []struct {
		pool  *pgxpool.Pool
		query string
	}{
		{r.pools.Workflow, `SELECT 1 FROM agent_workflow.agent_tasks WHERE workspace_id=$1 AND project_id=$2 AND run_id=$3 AND state IN ('queued','leased') LIMIT 1`},
		{r.pools.Workflow, `SELECT 1 FROM agent_workflow.worker_attempts a JOIN agent_workflow.agent_tasks t ON t.workspace_id=a.workspace_id AND t.project_id=a.project_id AND t.task_id=a.task_id WHERE a.workspace_id=$1 AND a.project_id=$2 AND t.run_id=$3 AND a.state='active' LIMIT 1`},
		{r.pools.Events, `SELECT 1 FROM agent_events.queue_deliveries WHERE workspace_id=$1 AND project_id=$2 AND run_id=$3 AND NOT acknowledged AND NOT dead_lettered LIMIT 1`},
	} {
		found, err := r.exists(ctx, source.pool, source.query, scope, id)
		if err != nil || found {
			return found, err
		}
	}
	return false, nil
}

// runtimeInFlight reports whether the run still has an execution outstanding on
// a runtime release. An attempt that is accepted or running is work in another
// process: cancellation cannot claim to be settled while a release may still be
// executing on the run's behalf, whether or not its answer will be allowed to
// commit.
func (r *Reconciler) runtimeInFlight(ctx context.Context, scope runs.Scope, id runs.ID) (bool, error) {
	return r.exists(ctx, r.pools.Workflow, `SELECT 1 FROM agent_workflow.runtime_attempts a JOIN agent_workflow.runtime_tasks t ON t.workspace_id=a.workspace_id AND t.project_id=a.project_id AND t.task_id=a.task_id WHERE a.workspace_id=$1 AND a.project_id=$2 AND t.run_id=$3 AND a.dispatch_status IN ('accepted','running') LIMIT 1`, scope, id)
}

// toolInFlight reports whether a tool dispatch may still be running. Tool
// calls happen inside durable workflow steps, so an executor lease that
// outlived cancellation is exactly the state in which a tool call may still
// be executing against an external system.
func (r *Reconciler) toolInFlight(ctx context.Context, scope runs.Scope, id runs.ID) (bool, error) {
	return r.exists(ctx, r.pools.Workflow, `SELECT 1 FROM agent_workflow.executor_leases WHERE workspace_id=$1 AND project_id=$2 AND workflow_id LIKE $3 || ':g%' LIMIT 1`, scope, id)
}

// artifactInFlight reports whether the run left an artifact that is neither
// settled nor withdrawn. A pending or scanning artifact is still being acted
// on somewhere.
func (r *Reconciler) artifactInFlight(ctx context.Context, scope runs.Scope, id runs.ID) (bool, error) {
	return r.exists(ctx, r.pools.Artifacts, `SELECT 1 FROM agent_artifacts.metadata WHERE workspace_id=$1 AND project_id=$2 AND run_id=$3 AND state IN ('pending','scanning') LIMIT 1`, scope, id)
}

func (r *Reconciler) exists(ctx context.Context, pool *pgxpool.Pool, query string, scope runs.Scope, id runs.ID) (bool, error) {
	var marker int
	err := pool.QueryRow(ctx, query, scope.WorkspaceID, scope.ProjectID, string(id)).Scan(&marker)
	if errors.Is(err, pgx.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return true, nil
}
