package execution_test

import (
	"bytes"
	"context"
	"errors"
	"sync"
	"testing"

	"github.com/ancyloce/anvilkit-agent-service/internal/budget"
	"github.com/ancyloce/anvilkit-agent-service/internal/execution"
	"github.com/ancyloce/anvilkit-agent-service/internal/modelgateway"
	"github.com/ancyloce/anvilkit-agent-service/internal/problem"
	"github.com/ancyloce/anvilkit-agent-service/internal/workflow"
)

// Provider idempotency is a real provider-side property, not just a stable
// identity: repeating an operation key must not bill again, must not advance
// the controlled script, and must return the same bytes.
func TestProviderReplayUnderTheSameOperationKeyIsFree(t *testing.T) {
	h := newHarness(t, [][]byte{finalPlan(), toolPlan()})
	input := h.seedRun("artifact-validation")
	prepare(t, h, input)
	first, err := h.ops.ExecuteTurn(context.Background(), opID(input, "turn-0000"), workflow.TurnInput{Run: input, Turn: 0, Phase: workflow.PhasePlan})
	if err != nil {
		t.Fatal(err)
	}
	billed := billedOperations(t, h)
	if billed != 1 {
		t.Fatalf("billed provider operations = %d, want 1", billed)
	}
	// The identical durable operation is delivered again, as recovery does.
	second, err := h.ops.ExecuteTurn(context.Background(), opID(input, "turn-0000"), workflow.TurnInput{Run: input, Turn: 0, Phase: workflow.PhasePlan})
	if err != nil {
		t.Fatal(err)
	}
	if replayed := billedOperations(t, h); replayed != billed {
		t.Fatalf("a replayed operation key billed again: %d then %d", billed, replayed)
	}
	requests := h.adapter.Requests()
	if len(requests) != 2 {
		t.Fatalf("adapter calls = %d, want the original and its replay", len(requests))
	}
	if requests[0].IdempotencyKey != requests[1].IdempotencyKey || requests[0].InvocationID != requests[1].InvocationID {
		t.Fatalf("replay used a different provider identity: %s / %s", requests[0].IdempotencyKey, requests[1].IdempotencyKey)
	}
	if first.Decision.Kind != second.Decision.Kind {
		t.Fatalf("replay produced a different decision: %s then %s", first.Decision.Kind, second.Decision.Kind)
	}
	if first.Decision.Final == nil || second.Decision.Final == nil || !bytes.Equal(first.Decision.Final.Candidate, second.Decision.Final.Candidate) {
		t.Fatal("replay produced a different result")
	}
	if first.Carry.Usage != second.Carry.Usage {
		t.Fatalf("replay accounted different usage: %+v then %+v", first.Carry.Usage, second.Carry.Usage)
	}
}

// Every physical provider attempt is authorized and accounted, including the
// transport retries that precede a success. Counting one model call per
// planning attempt would under-report a retried turn and let it spend past
// the pinned budget.
func TestPhysicalRetriesAreAuthorizedAndAccountedExactly(t *testing.T) {
	h := newHarness(t, [][]byte{finalPlan()}, func(options *harnessOptions) {
		options.providerAttempts = 3
		options.retryableFailures = 2
	})
	input := h.seedRun("artifact-validation")
	prepare(t, h, input)
	result, err := h.ops.ExecuteTurn(context.Background(), opID(input, "turn-0000"), workflow.TurnInput{Run: input, Turn: 0, Phase: workflow.PhasePlan})
	if err != nil {
		t.Fatal(err)
	}
	if len(h.adapter.Requests()) != 3 {
		t.Fatalf("physical attempts = %d, want the two failures and the success", len(h.adapter.Requests()))
	}
	if billed := billedOperations(t, h); billed != 3 {
		t.Fatalf("billed operations = %d, want one per physical attempt", billed)
	}
	// The scripted adapter meters 100 input, 50 output, and 1000 cost micros
	// per physical attempt, failures included.
	usage := result.Carry.Usage
	if usage.ModelCalls != 3 || usage.InputTokens != 300 || usage.OutputTokens != 150 || usage.CostMicros != 3000 {
		t.Fatalf("usage = %+v, want every physical attempt accounted", usage)
	}
	identities := map[string]struct{}{}
	for _, request := range h.adapter.Requests() {
		identities[request.IdempotencyKey] = struct{}{}
	}
	if len(identities) != 3 {
		t.Fatalf("distinct attempt identities = %d, want one per physical attempt", len(identities))
	}
}

// Each budget dimension bounds a turn on its own.
func TestTokenAndModelCallExhaustionHaltTheRun(t *testing.T) {
	broken := []byte(`{"kind":"TypedPlan","steps":[`)
	cases := map[string]func(*harnessBudget){
		"input tokens":  func(budget *harnessBudget) { budget.inputTokens = 200 },
		"output tokens": func(budget *harnessBudget) { budget.outputTokens = 100 },
		"model calls":   func(budget *harnessBudget) { budget.modelCalls = 2 },
	}
	for name, shape := range cases {
		t.Run(name, func(t *testing.T) {
			h := newHarness(t, [][]byte{broken})
			// The scripted adapter meters 100 input and 50 output tokens per
			// attempt, so each pinned budget funds exactly two of the three
			// attempts bounded repair would otherwise make.
			input := h.seedRunWithBudget("artifact-validation", shape)
			outcome, err := h.engine.ExecuteRun(context.Background(), input)
			if err != nil {
				t.Fatal(err)
			}
			if outcome.Terminal != workflow.TerminalRefused || outcome.Problem == nil || outcome.Problem.Code != string(problem.CodeBudgetDenied) {
				t.Fatalf("outcome = %+v", outcome)
			}
			if calls := len(h.adapter.Requests()); calls != 2 {
				t.Fatalf("provider calls = %d, want the two the budget funds", calls)
			}
		})
	}
}

// prepare drives the run through its preparation boundary so a single turn
// can then be executed directly.
func prepare(t *testing.T, h *harness, input workflow.RunInput) {
	t.Helper()
	result, err := h.ops.Prepare(context.Background(), opID(input, "prepare"), input)
	if err != nil {
		t.Fatal(err)
	}
	if result.Refused != nil || result.Superseded {
		t.Fatalf("preparation did not complete: %+v", result)
	}
}

// billedOperations reads how many distinct provider operations the durable
// ledger has settled.
func billedOperations(t *testing.T, h *harness) int {
	t.Helper()
	billed, err := h.adapter.Billed(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	return billed
}

// lostCompletionRecorder is the durable invocation recorder failing at the one
// boundary that costs money: the provider call has been made and billed, and
// the write that records it does not land. The gateway returns that failure
// exactly as it is — the recorder's error is not a provider problem and is
// never reinterpreted as one — so the turn fails with an error nothing above
// it can classify.
type lostCompletionRecorder struct {
	inner    modelgateway.Recorder
	lock     sync.Mutex
	failures int
	fail     bool
}

func (r *lostCompletionRecorder) BeforeDisclosure(ctx context.Context, record modelgateway.InvocationRecord) error {
	return r.inner.BeforeDisclosure(ctx, record)
}

func (r *lostCompletionRecorder) BeforeAttempt(ctx context.Context, record modelgateway.InvocationRecord) error {
	return r.inner.BeforeAttempt(ctx, record)
}

func (r *lostCompletionRecorder) Complete(ctx context.Context, record modelgateway.InvocationRecord) error {
	r.lock.Lock()
	failing := r.fail
	if failing {
		r.failures++
	}
	r.lock.Unlock()
	if failing {
		return errors.New("the durable invocation record could not be written")
	}
	return r.inner.Complete(ctx, record)
}

func (r *lostCompletionRecorder) stopFailing() {
	r.lock.Lock()
	r.fail = false
	r.lock.Unlock()
}

// TestAFailedTurnStillAccountsTheAttemptsItWasBilledFor is the regression for
// an accounting hole in the failed-turn path. A provider call that is made and
// billed, and whose durable invocation record then fails to write, fails the
// turn with an error nothing above it can classify. That path used to return
// an empty outcome — the usage the call had already reported was discarded
// with it — and the executor returned before observing anything against the
// reservation at all. The run's spend was understated by exactly what the
// failure had cost, and the same allowance could be spent again.
//
// The completion standard for all-attempt accounting names failed attempts
// explicitly. This proves the failure path counts them, and counts them once.
func TestAFailedTurnStillAccountsTheAttemptsItWasBilledFor(t *testing.T) {
	ctx := context.Background()
	recorder := &lostCompletionRecorder{inner: &execution.MemoryModelRecorder{}, fail: true}
	h := newHarness(t, [][]byte{finalPlan(), finalPlan()}, func(options *harnessOptions) {
		options.modelRecorder = recorder
	})
	input := h.seedRun("artifact-validation")
	prepare(t, h, input)

	if _, err := h.ops.ExecuteTurn(ctx, opID(input, "turn-0000"), workflow.TurnInput{Run: input, Turn: 0, Phase: workflow.PhasePlan}); err == nil {
		t.Fatal("the turn reported success although its invocation record was lost")
	}
	// The provider really was called and really did bill.
	if billed := billedOperations(t, h); billed < 1 {
		t.Fatalf("billed provider operations = %d, want the failed attempt billed", billed)
	}
	if recorder.failures < 1 {
		t.Fatal("the invocation record never reached the boundary that failed")
	}

	reservationID := budget.ReservationID("budget:" + testRunID + ":g1")
	reservation, err := h.budgetLedger.Reservation(ctx, testBudgetScope, reservationID)
	if err != nil {
		t.Fatal(err)
	}
	if reservation.ObservedMicros <= 0 {
		t.Fatalf("observed usage after a failed turn = %d, want the billed attempt counted", reservation.ObservedMicros)
	}
	spent := reservation.ObservedMicros

	// Counted once. The engine re-executes the same durable step; the provider
	// replays the recorded operation for free, so the repeated observation
	// carries the same cost under the same identity and does not accumulate.
	recorder.stopFailing()
	if _, err := h.ops.ExecuteTurn(ctx, opID(input, "turn-0000"), workflow.TurnInput{Run: input, Turn: 0, Phase: workflow.PhasePlan}); err != nil {
		t.Fatalf("the re-executed durable step did not converge: %v", err)
	}
	repeated, err := h.budgetLedger.Reservation(ctx, testBudgetScope, reservationID)
	if err != nil {
		t.Fatal(err)
	}
	if repeated.ObservedMicros != spent {
		t.Fatalf("observed usage after the step was re-executed = %d, want the attempt counted exactly once (%d)", repeated.ObservedMicros, spent)
	}
}

// The complement: a turn that fails before it reaches a provider has no spend
// to account, and must not fix its turn identity at zero. Recording a
// zero-cost observation for such a turn would make the engine's retry of the
// same durable step contradict it, so the retry could not record what it
// actually spent.
func TestATurnThatFailedBeforeSpendingRecordsNothingAndLetsTheRetryAccount(t *testing.T) {
	ctx := context.Background()
	recorder := &refusedDisclosureRecorder{inner: &execution.MemoryModelRecorder{}, fail: true}
	h := newHarness(t, [][]byte{finalPlan()}, func(options *harnessOptions) {
		options.modelRecorder = recorder
	})
	input := h.seedRun("artifact-validation")
	prepare(t, h, input)

	if _, err := h.ops.ExecuteTurn(ctx, opID(input, "turn-0000"), workflow.TurnInput{Run: input, Turn: 0, Phase: workflow.PhasePlan}); err == nil {
		t.Fatal("the turn reported success although disclosure was refused")
	}
	if billed := billedOperations(t, h); billed != 0 {
		t.Fatalf("billed provider operations = %d, want none before disclosure was recorded", billed)
	}
	reservationID := budget.ReservationID("budget:" + testRunID + ":g1")
	reservation, err := h.budgetLedger.Reservation(ctx, testBudgetScope, reservationID)
	if err != nil {
		t.Fatal(err)
	}
	if reservation.ObservedMicros != 0 {
		t.Fatalf("observed usage = %d, want nothing accounted for a turn that never spent", reservation.ObservedMicros)
	}

	// The retry of the same durable step spends for real, and its cost is
	// recorded rather than refused as a contradiction of a zero already
	// written under the same identity.
	recorder.stopFailing()
	if _, err := h.ops.ExecuteTurn(ctx, opID(input, "turn-0000"), workflow.TurnInput{Run: input, Turn: 0, Phase: workflow.PhasePlan}); err != nil {
		t.Fatalf("the retried turn failed: %v", err)
	}
	settled, err := h.budgetLedger.Reservation(ctx, testBudgetScope, reservationID)
	if err != nil {
		t.Fatal(err)
	}
	if settled.ObservedMicros <= 0 {
		t.Fatalf("observed usage after the retry = %d, want the retry's real cost recorded", settled.ObservedMicros)
	}
}

// refusedDisclosureRecorder fails before any provider attempt is made, so the
// turn fails without spending anything.
type refusedDisclosureRecorder struct {
	inner modelgateway.Recorder
	lock  sync.Mutex
	fail  bool
}

func (r *refusedDisclosureRecorder) BeforeDisclosure(ctx context.Context, record modelgateway.InvocationRecord) error {
	r.lock.Lock()
	failing := r.fail
	r.lock.Unlock()
	if failing {
		return errors.New("the durable disclosure record could not be written")
	}
	return r.inner.BeforeDisclosure(ctx, record)
}

func (r *refusedDisclosureRecorder) BeforeAttempt(ctx context.Context, record modelgateway.InvocationRecord) error {
	return r.inner.BeforeAttempt(ctx, record)
}

func (r *refusedDisclosureRecorder) Complete(ctx context.Context, record modelgateway.InvocationRecord) error {
	return r.inner.Complete(ctx, record)
}

func (r *refusedDisclosureRecorder) stopFailing() {
	r.lock.Lock()
	r.fail = false
	r.lock.Unlock()
}
