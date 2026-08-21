package interrupts

import (
	"context"
	"regexp"
	"testing"

	"github.com/ancyloce/anvilkit-agent-service/internal/runs"
)

// recordingRepository captures the write the recovery sweep makes so the
// durable preconditions of that write can be asserted here rather than
// discovered in production. The durable write-idempotency record is keyed by
// subject and refuses a write that has none, and the transition projects a run
// event whose trace context is schema-validated — neither of which the memory
// repository enforces, so the sweep would otherwise look correct in tests and
// fail on every real run.
type recordingRepository struct {
	Repository
	finished []Write
}

// Current keeps the optional current-authority reader visible through the
// wrapper: the sweep resolves the run's actor and version through it, and a
// wrapper that hid it would make the test pass against a repository the sweep
// cannot actually read.
func (r *recordingRepository) Current(ctx context.Context, scope runs.Scope, id runs.ID) (runs.Snapshot, error) {
	reader, ok := r.Repository.(interface {
		Current(context.Context, runs.Scope, runs.ID) (runs.Snapshot, error)
	})
	if !ok {
		return runs.Snapshot{}, context.Canceled
	}
	return reader.Current(ctx, scope, id)
}

func (r *recordingRepository) FinishCancellation(ctx context.Context, write Write, cancellation Cancellation) (OperationResult, error) {
	r.finished = append(r.finished, write)
	return r.Repository.FinishCancellation(ctx, write, cancellation)
}

// settledBudget accepts every budget act and records the runs it settled.
type settledBudget struct {
	fenced      []string
	settled     []string
	asked       []string
	outstanding bool
}

func (b *settledBudget) SettleRunBudget(context.Context, runs.Snapshot, bool) error { return nil }
func (b *settledBudget) FenceRunBudget(_ context.Context, snapshot runs.Snapshot) error {
	b.fenced = append(b.fenced, string(snapshot.RunID))
	return nil
}
func (b *settledBudget) SettleCancelledRunBudget(_ context.Context, snapshot runs.Snapshot) error {
	b.settled = append(b.settled, string(snapshot.RunID))
	return nil
}
func (b *settledBudget) OutstandingCancelledRunBudget(_ context.Context, snapshot runs.Snapshot) (bool, error) {
	b.asked = append(b.asked, string(snapshot.RunID))
	return b.outstanding, nil
}

// TestCancellationRecoveryFinishesWithADurablyValidWrite proves the sweep's
// transition carries what the durable stores require: a subject, a bounded
// operation key no control command can produce, the run's observed version,
// and a well-formed trace context.
func TestCancellationRecoveryFinishesWithADurablyValidWrite(t *testing.T) {
	ctx := context.Background()
	repository := NewMemoryRepository()
	_ = repository.Seed(scope(), snapshot("run", runs.Executing, 3))
	if _, _, err := repository.RequestCancellation(ctx, write("run", 3, "cancel"), "sha256:cancel", testNow); err != nil {
		t.Fatal(err)
	}
	recorder := &recordingRepository{Repository: repository}
	budget := &settledBudget{}
	recovery, err := NewCancellationRecovery(recorder, &testReconciler{clear: true}, budget)
	if err != nil {
		t.Fatal(err)
	}
	completed, err := recovery.Scan(ctx)
	if err != nil || completed != 1 {
		t.Fatalf("scan completed %d runs (err %v), want exactly the cancelling run", completed, err)
	}
	current, err := repository.Current(ctx, scope(), "run")
	if err != nil || current.Status != runs.Cancelled {
		t.Fatalf("run state after recovery = %s (err %v), want the cancellation finished", current.Status, err)
	}
	if len(budget.fenced) != 1 || len(budget.settled) != 1 {
		t.Fatalf("budget acts fenced=%v settled=%v, want the run fenced and settled once each", budget.fenced, budget.settled)
	}
	if len(recorder.finished) != 1 {
		t.Fatalf("finish writes = %d, want exactly one", len(recorder.finished))
	}
	finished := recorder.finished[0]
	// A write with no subject is refused by the durable idempotency record,
	// and the progress row the sweep scans does not carry one.
	if finished.Scope.ActorID == "" {
		t.Fatal("the recovery write carried no subject, which the durable idempotency record refuses")
	}
	// The cancellation request already advanced the aggregate, so the version
	// the sweep must present is the one it read, not the one the request saw.
	if finished.ExpectedVersion != current.Version-1 {
		t.Fatalf("recovery write version = %d, want the version the sweep observed before finishing", finished.ExpectedVersion)
	}
	// The operation key must be one no cancel request can produce: a cancel
	// derives its reconciliation key from the caller's own key plus a fixed
	// suffix, so a client cannot pre-empt or collide with this transition.
	if finished.IdempotencyKey != "cancellation-recovery:run" {
		t.Fatalf("recovery write key = %q, want the server-owned recovery key", finished.IdempotencyKey)
	}
	// The transition projects a run event whose trace context is
	// schema-validated, so the traceparent has to be well formed.
	if !regexp.MustCompile(`^[0-9a-f]{2}-[0-9a-f]{32}-[0-9a-f]{16}-[0-9a-f]{2}$`).MatchString(finished.Traceparent) {
		t.Fatalf("recovery traceparent = %q, want a well-formed trace context", finished.Traceparent)
	}
	// Repetition converges: the run is terminal, so the next scan finds
	// nothing and changes nothing.
	repeat, err := recovery.Scan(ctx)
	if err != nil || repeat != 0 {
		t.Fatalf("repeated scan completed %d runs (err %v), want nothing further", repeat, err)
	}
}

// TestCancellationRecoveryLeavesUnresolvedRunsAlone proves the sweep never
// terminalizes over work that may still be running, and never releases a hold
// it has no proof about — for the run itself or for a descendant it took down.
func TestCancellationRecoveryLeavesUnresolvedRunsAlone(t *testing.T) {
	ctx := context.Background()
	repository := NewMemoryRepository()
	_ = repository.Seed(scope(), snapshot("run", runs.Executing, 3))
	if _, _, err := repository.RequestCancellation(ctx, write("run", 3, "cancel"), "sha256:cancel", testNow); err != nil {
		t.Fatal(err)
	}
	budget := &settledBudget{}
	recovery, err := NewCancellationRecovery(repository, &testReconciler{clear: false}, budget)
	if err != nil {
		t.Fatal(err)
	}
	completed, err := recovery.Scan(ctx)
	if err != nil || completed != 0 {
		t.Fatalf("scan completed %d runs (err %v), want none while an effect is unresolved", completed, err)
	}
	if len(budget.settled) != 0 {
		t.Fatalf("settled %v, want nothing settled before finality is proven", budget.settled)
	}
	// Authority is still revoked immediately, which is the half of
	// cancellation that never waits for proof.
	if len(budget.fenced) != 1 {
		t.Fatalf("fenced %v, want the unresolved run's dispatch authority revoked anyway", budget.fenced)
	}
	current, err := repository.Current(ctx, scope(), "run")
	if err != nil || current.Status != runs.Cancelling {
		t.Fatalf("run state = %s (err %v), want it left visibly cancelling", current.Status, err)
	}
}
