package execution_test

import (
	"context"
	"encoding/json"
	"sync"
	"testing"
	"time"

	"github.com/ancyloce/anvilkit-agent-service/internal/budget"
	"github.com/ancyloce/anvilkit-agent-service/internal/execution"
	"github.com/ancyloce/anvilkit-agent-service/internal/interrupts"
	"github.com/ancyloce/anvilkit-agent-service/internal/workflow"
)

// TestReplacementReconcilesSupersededHoldsBeforeReserving proves the
// superseded-generation reconciliation is reachable from the production
// pipeline, not only from a controller call a test makes itself.
//
// A hold made by a generation the aggregate has since retried past can never
// be settled by the ordinary path again: that path requires the settling
// generation to be both the reservation's and the current one. Here a sibling
// run of the same root holds worst-case budget under generation 1 and reports
// its authoritative final usage, then the root retries. The replacement
// generation's own reservation is what has to reconcile it — otherwise the
// unspent worst case is held against the root for ever.
func TestReplacementReconcilesSupersededHoldsBeforeReserving(t *testing.T) {
	ctx := context.Background()
	// The replacement's reconciliation is held at its own doorstep, so what
	// the assertions below read is the state at an exact point rather than
	// whatever state a read happened to catch.
	//
	// Retrying resumes the replacement workflow asynchronously, and that
	// workflow's first act is the reconciliation this test is about. Reading
	// "nothing has reconciled it yet" straight after the retry was therefore a
	// race against the very thing under test: usually the read won, and
	// occasionally the replacement got there first and the test failed
	// claiming the retry had reconciled the hold. The claim is unchanged —
	// advancing the generation reconciles nothing, and the replacement's
	// reservation is what does — but it is now observed where it is true by
	// construction.
	gate := &heldReconciliation{reached: make(chan struct{}), release: make(chan struct{})}
	h := newHarness(t, [][]byte{inputPlan(), inputPlan(), finalPlan()}, func(options *harnessOptions) {
		options.inputTTL = 250 * time.Millisecond
		options.budget = func(inner execution.BudgetController) execution.BudgetController {
			gate.inner = inner
			return gate
		}
	})
	input := h.seedRun("artifact-validation")

	// A sibling run of the same root holds worst-case budget under the
	// aggregate's current generation and reports what it actually spent.
	const siblingWorstCase = int64(40_000_000)
	const siblingActual = int64(1_500)
	sibling, err := h.budgetController.ReserveInitial(ctx, budget.Estimate{
		ReservationID:     "budget:" + testRunID + ".child:g1",
		RootRunID:         testRunID,
		RunID:             testRunID + ".child",
		WorkspaceID:       testWorkspace,
		ProjectID:         testProject,
		PolicyVersion:     "policy-v1",
		BudgetVersion:     "budget-v1",
		MaximumCostMicros: siblingWorstCase,
		ExpiresAt:         time.Now().Add(time.Hour),
	}, 1)
	if err != nil {
		t.Fatal(err)
	}
	if err := h.budgetController.Observe(ctx, budget.Observation{
		ID:            "usage:" + string(sibling.ID),
		Scope:         testBudgetScope,
		ReservationID: sibling.ID,
		RootRunID:     testRunID,
		RunID:         testRunID + ".child",
		TaskID:        "sibling",
		AttemptID:     budget.AttemptID("attempt:" + string(sibling.ID)),
		CostMicros:    siblingActual,
		Final:         true,
	}); err != nil {
		t.Fatal(err)
	}

	// The root's first generation fails, so the aggregate can be retried.
	outcome, err := h.engine.ExecuteRun(ctx, input)
	if err != nil || outcome.Terminal != workflow.TerminalFailed {
		t.Fatalf("precondition failed run: %+v %v", outcome, err)
	}
	held, err := h.budgetLedger.Reservation(ctx, testBudgetScope, sibling.ID)
	if err != nil {
		t.Fatal(err)
	}
	if held.UpperBoundMicros != siblingWorstCase {
		t.Fatalf("sibling hold before the retry = %+v, want its worst case still held", held)
	}

	// The explicit retry advances the aggregate's generation, which is what
	// puts the sibling hold permanently out of the ordinary settlement path.
	snapshot := h.snapshot()
	if _, err := h.service.Retry(ctx, interrupts.Write{Scope: testScope(), RunID: testRunID, ExpectedVersion: snapshot.Version, IdempotencyKey: "retry-superseded", Traceparent: traceparent}); err != nil {
		t.Fatal(err)
	}
	// The replacement has reached its reconciliation and is held there. At
	// this point the retry has done everything it does — the aggregate's
	// generation has advanced — and the reconciliation has done nothing yet,
	// so the unspent worst case is still held against the root. What
	// reconciles it below is the replacement generation's own reservation,
	// which is the production path under test.
	gate.await(t)
	stranded, err := h.budgetLedger.Reservation(ctx, testBudgetScope, sibling.ID)
	if err != nil {
		t.Fatal(err)
	}
	if stranded.UpperBoundMicros != siblingWorstCase {
		t.Fatalf("sibling hold after the retry = %+v, want its worst case still held until the replacement reserves", stranded)
	}
	gate.resume()

	request := h.openInputRequest()
	current := h.snapshot()
	if _, err := h.service.RespondInput(ctx, interrupts.Write{Scope: testScope(), RunID: testRunID, ExpectedVersion: current.Version, IdempotencyKey: "respond-superseded-g2", Traceparent: traceparent}, interrupts.InputResponseCommand{RequestID: request.ID, RequestVersion: request.Version, Value: json.RawMessage(`{"answer":"retry answer"}`)}); err != nil {
		t.Fatal(err)
	}
	second, err := h.engine.ExecuteRun(ctx, workflow.RunInput{Key: workflow.RunKey{RunID: testRunID, Generation: 2}, Scope: input.Scope, Traceparent: traceparent})
	if err != nil || second.Terminal != workflow.TerminalCompleted {
		t.Fatalf("generation 2 outcome = %+v err = %v", second, err)
	}

	// Reserving the replacement generation reconciled the superseded hold down
	// to the usage its attempt authoritatively reported.
	reconciled, err := h.budgetLedger.Reservation(ctx, testBudgetScope, sibling.ID)
	if err != nil {
		t.Fatal(err)
	}
	if reconciled.UpperBoundMicros != siblingActual || reconciled.ObservedMicros != siblingActual {
		t.Fatalf("superseded hold = %+v, want reduction to its authoritative usage %d", reconciled, siblingActual)
	}
	// The reconciliation returned headroom and nothing else: the attempt's
	// actual cost is still counted against the root, and the hold has no
	// authority to dispatch under any generation.
	if reconciled.Released {
		t.Fatal("reconciliation released a prior attempt's actual cost out of the root total")
	}
	for name, generation := range map[string]budget.Generation{"own-generation": 1, "current-generation": 2} {
		if err := h.budgetController.Dispatch(ctx, testBudgetScope, sibling.ID, generation, func(context.Context, budget.Reservation) error {
			t.Fatalf("%s dispatched a reconciled superseded reservation", name)
			return nil
		}); err == nil {
			t.Fatalf("%s dispatch was permitted", name)
		}
	}
}

// heldReconciliation holds the replacement generation's superseded-hold
// reconciliation at its first call, so a test can read the ledger at the exact
// moment before it runs. Every other call passes straight through: what is
// being controlled is one point in time, not the budget authority's behaviour.
type heldReconciliation struct {
	execution.BudgetController
	inner   execution.BudgetController
	once    sync.Once
	reached chan struct{}
	release chan struct{}
}

func (h *heldReconciliation) ReconcileSuperseded(ctx context.Context, scope budget.Scope, rootRunID string, current budget.Generation, actor string) ([]budget.Reservation, error) {
	h.once.Do(func() {
		close(h.reached)
		<-h.release
	})
	return h.inner.ReconcileSuperseded(ctx, scope, rootRunID, current, actor)
}

func (h *heldReconciliation) ReserveInitial(ctx context.Context, estimate budget.Estimate, generation budget.Generation) (budget.Reservation, error) {
	return h.inner.ReserveInitial(ctx, estimate, generation)
}

func (h *heldReconciliation) ReserveReplacement(ctx context.Context, estimate budget.Estimate, generation budget.Generation, prior budget.ReservationID) (budget.Reservation, error) {
	return h.inner.ReserveReplacement(ctx, estimate, generation, prior)
}

func (h *heldReconciliation) Dispatch(ctx context.Context, scope budget.Scope, id budget.ReservationID, generation budget.Generation, dispatch budget.Dispatch) error {
	return h.inner.Dispatch(ctx, scope, id, generation, dispatch)
}

func (h *heldReconciliation) Observe(ctx context.Context, observation budget.Observation) error {
	return h.inner.Observe(ctx, observation)
}

func (h *heldReconciliation) Reservation(ctx context.Context, scope budget.Scope, id budget.ReservationID) (budget.Reservation, error) {
	return h.inner.Reservation(ctx, scope, id)
}

func (h *heldReconciliation) Reconcile(ctx context.Context, scope budget.Scope, id budget.ReservationID, generation budget.Generation, finalCost *int64, release bool, actor string) (budget.Reservation, error) {
	return h.inner.Reconcile(ctx, scope, id, generation, finalCost, release, actor)
}

func (h *heldReconciliation) RecoverSupersededFinality(ctx context.Context, scope budget.Scope, rootRunID string, actor string) ([]budget.Reservation, error) {
	return h.inner.RecoverSupersededFinality(ctx, scope, rootRunID, actor)
}

func (h *heldReconciliation) FenceCancelledRun(ctx context.Context, scope budget.Scope, rootRunID, runID string) ([]budget.Reservation, error) {
	return h.inner.FenceCancelledRun(ctx, scope, rootRunID, runID)
}

func (h *heldReconciliation) ConcludeCancelledRun(ctx context.Context, scope budget.Scope, rootRunID, runID, actor string) ([]budget.Reservation, error) {
	return h.inner.ConcludeCancelledRun(ctx, scope, rootRunID, runID, actor)
}

func (h *heldReconciliation) RecoverCancelledFinality(ctx context.Context, scope budget.Scope, rootRunID string, actor string) ([]budget.Reservation, error) {
	return h.inner.RecoverCancelledFinality(ctx, scope, rootRunID, actor)
}

func (h *heldReconciliation) OutstandingCancelledHolds(ctx context.Context, scope budget.Scope, rootRunID string) (bool, error) {
	return h.inner.OutstandingCancelledHolds(ctx, scope, rootRunID)
}

// await blocks until the replacement generation has reached its reconciliation.
func (h *heldReconciliation) await(t *testing.T) {
	t.Helper()
	select {
	case <-h.reached:
	case <-time.After(30 * time.Second):
		t.Fatal("the replacement generation never reached its superseded-hold reconciliation")
	}
}

// resume lets the held reconciliation proceed.
func (h *heldReconciliation) resume() { close(h.release) }
