package execution_test

import (
	"bytes"
	"context"
	"testing"

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
