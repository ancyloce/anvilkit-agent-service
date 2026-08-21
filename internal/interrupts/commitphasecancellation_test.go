package interrupts

import (
	"context"
	"sync"
	"testing"

	"github.com/ancyloce/anvilkit-agent-service/internal/runs"
)

// perRunReconciler answers reconciliation per run and records the commit-phase
// question it was asked, so a test can prove the sweep reconciles each member
// of a hierarchy on that member's own terms rather than its parent's.
type perRunReconciler struct {
	lock        sync.Mutex
	clear       map[runs.ID]bool
	commitPhase map[runs.ID]bool
}

func (r *perRunReconciler) Reconcile(_ context.Context, _ runs.Scope, id runs.ID, commit bool) (bool, *runs.State, error) {
	r.lock.Lock()
	defer r.lock.Unlock()
	if r.commitPhase == nil {
		r.commitPhase = map[runs.ID]bool{}
	}
	r.commitPhase[id] = commit
	return r.clear[id], nil, nil
}

func (r *perRunReconciler) set(id runs.ID, clear bool) {
	r.lock.Lock()
	defer r.lock.Unlock()
	r.clear[id] = clear
}

// terminalRepository reports the run as having finished its lifecycle while
// leaving everything else the memory repository does intact, so the sweep's
// behaviour for a cancellation whose run is already over can be exercised
// without inventing a whole repository.
type terminalRepository struct {
	*MemoryRepository
	state runs.State
}

func (r *terminalRepository) Current(ctx context.Context, scope runs.Scope, id runs.ID) (runs.Snapshot, error) {
	snapshot, err := r.MemoryRepository.Current(ctx, scope, id)
	if err != nil {
		return snapshot, err
	}
	snapshot.Status = r.state
	return snapshot, nil
}

// seedCancelledHierarchy seeds a parent with one child, moves the parent into
// the commit boundary, and requests cancellation there.
func seedCancelledHierarchy(t *testing.T, repository *MemoryRepository) {
	t.Helper()
	ctx := context.Background()
	_ = repository.Seed(scope(), snapshot("run", runs.Executing, 3))
	if _, err := repository.CreateChild(ctx, write("run", 3, "child"), Child{RunID: "child", ParentRunID: "run", WorkspaceID: scope().WorkspaceID, ProjectID: scope().ProjectID, ActorID: scope().ActorID, Mode: ChildRequired, Depth: 1, CreatedAt: testNow}, "sha256:child"); err != nil {
		t.Fatal(err)
	}
	// The parent enters the commit boundary before the cancellation arrives,
	// which is what makes this a commit-phase cancellation.
	_ = repository.Seed(scope(), snapshot("run", runs.Committing, 4))
	cancellation, _, err := repository.RequestCancellation(ctx, write("run", 4, "cancel"), "sha256:cancel", testNow)
	if err != nil {
		t.Fatal(err)
	}
	if !cancellation.CommitPhase {
		t.Fatal("the fixture did not produce a commit-phase cancellation")
	}
	if current, err := repository.Current(ctx, scope(), "run"); err != nil || current.Status != runs.Committing {
		t.Fatalf("run state = %s (err %v), want the commit boundary left intact", current.Status, err)
	}
}

// TestCommitPhaseCancellationConcludesDescendantHolds is the regression for a
// hold that nothing could ever release. Cancelling inside the commit boundary
// deliberately leaves the run in its committing state under the domain owner's
// authority — so a recovery sweep whose subject was "runs in the cancelling
// state" never came back to it, and a descendant whose own effects were still
// unresolved when the cancellation arrived kept its fenced worst-case hold
// against root headroom for ever.
//
// The sweep's subject is the cancellation, not the run's state. Here the child
// is unresolved when the cancellation lands, resolves later, and is concluded
// by a subsequent scan — while the parent, still inside the commit boundary,
// is never projected as cancelled.
func TestCommitPhaseCancellationConcludesDescendantHolds(t *testing.T) {
	ctx := context.Background()
	repository := NewMemoryRepository()
	seedCancelledHierarchy(t, repository)
	reconciler := &perRunReconciler{clear: map[runs.ID]bool{"run": false, "child": false}}
	budget := &settledBudget{}
	recovery, err := NewCancellationRecovery(repository, reconciler, budget)
	if err != nil {
		t.Fatal(err)
	}

	// The cancellation is visible to the sweep even though the run is
	// committing, not cancelling.
	pending, err := repository.UnreconciledCancellations(ctx)
	if err != nil || len(pending) != 1 || pending[0].RunID != "run" {
		t.Fatalf("pending cancellations = %v (err %v), want the commit-phase cancellation", pending, err)
	}

	// Nothing is concluded while the child's effects are unresolved, and the
	// parent is reconciled on its own terms: inside the commit boundary.
	completed, err := recovery.Scan(ctx)
	if err != nil || completed != 0 {
		t.Fatalf("scan completed %d runs (err %v), want none while an effect is unresolved", completed, err)
	}
	if len(budget.settled) != 0 {
		t.Fatalf("settled %v, want nothing settled before finality is proven", budget.settled)
	}
	if len(budget.fenced) != 2 {
		t.Fatalf("fenced %v, want both the run and its descendant fenced", budget.fenced)
	}
	if !reconciler.commitPhase["run"] {
		t.Fatal("the committing run was reconciled outside the commit boundary")
	}
	if reconciler.commitPhase["child"] {
		t.Fatal("the descendant was reconciled on its parent's commit phase rather than its own")
	}

	// The child's effects resolve. This is the scan that used to be impossible:
	// the sweep concludes the descendant's hold even though its parent is not,
	// and will never be, in the cancelling state.
	reconciler.set("child", true)
	completed, err = recovery.Scan(ctx)
	if err != nil || completed != 0 {
		t.Fatalf("scan completed %d runs (err %v), want no transition for a commit-phase cancellation", completed, err)
	}
	if len(budget.settled) != 1 || budget.settled[0] != "child" {
		t.Fatalf("settled %v, want exactly the descendant's hold concluded", budget.settled)
	}
	current, err := repository.Current(ctx, scope(), "run")
	if err != nil || current.Status != runs.Committing {
		t.Fatalf("run state = %s (err %v), want the commit boundary still the domain owner's to decide", current.Status, err)
	}
}

// TestCancellationRecoveryPassesOverSettledFinishedRuns proves the sweep stops
// working a cancellation that has nothing left to do. A recovery path that
// keeps re-interrogating every effect store for a run whose lifecycle is over
// and whose holds are all released is a leak, not a recovery path.
func TestCancellationRecoveryPassesOverSettledFinishedRuns(t *testing.T) {
	ctx := context.Background()
	memory := NewMemoryRepository()
	seedCancelledHierarchy(t, memory)
	repository := &terminalRepository{MemoryRepository: memory, state: runs.Completed}
	reconciler := &perRunReconciler{clear: map[runs.ID]bool{"run": true, "child": true}}
	budget := &settledBudget{outstanding: false}
	recovery, err := NewCancellationRecovery(repository, reconciler, budget)
	if err != nil {
		t.Fatal(err)
	}
	completed, err := recovery.Scan(ctx)
	if err != nil || completed != 0 {
		t.Fatalf("scan completed %d runs (err %v), want nothing for a settled finished run", completed, err)
	}
	if len(budget.asked) != 1 || budget.asked[0] != "run" {
		t.Fatalf("ledger asked %v, want exactly one cheap outstanding-hold read", budget.asked)
	}
	if len(budget.fenced) != 0 || len(budget.settled) != 0 || len(reconciler.commitPhase) != 0 {
		t.Fatalf("finished run did work: fenced=%v settled=%v reconciled=%v", budget.fenced, budget.settled, reconciler.commitPhase)
	}

	// A finished run that still holds a fenced hold is not passed over: the
	// hold is exactly what this sweep exists to release.
	budget.outstanding = true
	if _, err := recovery.Scan(ctx); err != nil {
		t.Fatal(err)
	}
	if len(budget.settled) != 2 {
		t.Fatalf("settled %v, want the finished run and its descendant both concluded", budget.settled)
	}
}
