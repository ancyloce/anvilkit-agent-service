package execution_test

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/ancyloce/anvilkit-agent-service/internal/budget"
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
	h := newHarness(t, [][]byte{inputPlan(), inputPlan(), finalPlan()}, func(options *harnessOptions) {
		options.inputTTL = 250 * time.Millisecond
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
	if _, err := h.budgetController.Reconcile(ctx, testBudgetScope, sibling.ID, 1, nil, false, budget.SettlementActor); err == nil {
		t.Fatal("the ordinary settlement path still reached a superseded hold; the fixture proves nothing")
	}

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
