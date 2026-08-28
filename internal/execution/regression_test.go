package execution_test

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/ancyloce/anvilkit-agent-service/internal/agent"
	"github.com/ancyloce/anvilkit-agent-service/internal/execution"
	"github.com/ancyloce/anvilkit-agent-service/internal/interrupts"
	"github.com/ancyloce/anvilkit-agent-service/internal/modelgateway"
	"github.com/ancyloce/anvilkit-agent-service/internal/problem"
	"github.com/ancyloce/anvilkit-agent-service/internal/runs"
	"github.com/ancyloce/anvilkit-agent-service/internal/workflow"
	"github.com/ancyloce/anvilkit-agent-service/internal/workflow/memory"
)

func opID(run workflow.RunInput, step string) workflow.OpID {
	return workflow.OpID{WorkflowID: run.Key.WorkflowID(), Step: step}
}

func expireRequest(run workflow.RunInput, requestID, kind string, version uint64) workflow.ExpireRequest {
	return workflow.ExpireRequest{Run: run, Turn: 0, RequestID: requestID, Kind: kind, Version: version}
}

// An accepted response that races the durable deadline must win outright: the
// expiry step reports the race, leaves the request unexpired, and leaves the
// run in a state the workflow keeps driving. A read-then-compare-and-set
// expiry could instead exit superseded and strand the answered run.
func TestAcceptedResponseRacingExpiryLeavesTheRunDriven(t *testing.T) {
	h := newHarness(t, [][]byte{inputPlan(), finalPlan()})
	input := h.seedRun("artifact-validation")
	if err := h.engine.StartRun(context.Background(), input); err != nil {
		t.Fatal(err)
	}
	request := h.openInputRequest()
	if _, err := h.respondInput(request, "respond-race"); err != nil {
		t.Fatal(err)
	}
	// The deadline fires after the response was accepted.
	ack, err := h.ops.ExpireInterrupt(context.Background(), opID(input, "expire-input-00-0000"), expireRequest(input, string(request.ID), "input", h.snapshot().Version))
	if err != nil {
		t.Fatal(err)
	}
	if !ack.Raced || ack.Superseded {
		t.Fatalf("accepted response lost the race: %+v", ack)
	}
	stored, err := h.repo.Input(context.Background(), testScope(), testRunID, request.ID)
	if err != nil {
		t.Fatal(err)
	}
	if stored.ExpiredAt != nil {
		t.Fatal("an answered request must never be marked expired")
	}
	outcome, err := h.engine.ExecuteRun(context.Background(), input)
	if err != nil || outcome.Terminal != workflow.TerminalCompleted {
		t.Fatalf("the answered run must still complete: %+v err = %v", outcome, err)
	}
}

// The reverse ordering must also be total: once expiry commits, the request
// is durably expired and a response can never revive it.
func TestExpiryThatWinsMakesTheResponseFailClosed(t *testing.T) {
	h := newHarness(t, [][]byte{inputPlan(), finalPlan()})
	input := h.seedRun("artifact-validation")
	if err := h.engine.StartRun(context.Background(), input); err != nil {
		t.Fatal(err)
	}
	request := h.openInputRequest()
	ack, err := h.ops.ExpireInterrupt(context.Background(), opID(input, "expire-input-00-0000"), expireRequest(input, string(request.ID), "input", h.snapshot().Version))
	if err != nil {
		t.Fatal(err)
	}
	if ack.Raced || ack.Superseded {
		t.Fatalf("expiry did not commit: %+v", ack)
	}
	if snapshot := h.snapshot(); snapshot.Status != runs.Failed || snapshot.Problem == nil || snapshot.Problem.Code != string(problem.CodeInputRequestExpired) {
		t.Fatalf("expiry left the run at %s", h.snapshot().Status)
	}
	_, err = h.respondInput(request, "respond-after-expiry")
	var details problem.Details
	if !errors.As(err, &details) || details.Code != string(problem.CodeInputRequestExpired) {
		t.Fatalf("late response error = %v", err)
	}
	stored, err := h.repo.Input(context.Background(), testScope(), testRunID, request.ID)
	if err != nil {
		t.Fatal(err)
	}
	if stored.ExpiredAt == nil || stored.Response != nil {
		t.Fatalf("expired request state = %+v", stored)
	}
}

// Recovery re-invokes an operation whose effect committed before its
// checkpoint. Every provider identity must be derived from the durable
// operation key, so a duplicate invocation is the same call, not a new one.
func TestDuplicateTurnDeliveryReusesTheSameProviderIdentity(t *testing.T) {
	h := newHarness(t, [][]byte{finalPlan()})
	input := h.seedRun("artifact-validation")
	prepared, err := h.ops.Prepare(context.Background(), opID(input, "prepare"), input)
	if err != nil || prepared.Superseded {
		t.Fatalf("prepare = %+v err = %v", prepared, err)
	}
	op := opID(input, "turn-0000")
	turn := workflow.TurnInput{Run: input, Turn: 0, Phase: workflow.PhasePlan, Carry: workflow.Carry{Version: prepared.Version}}
	first, err := h.ops.ExecuteTurn(context.Background(), op, turn)
	if err != nil {
		t.Fatal(err)
	}
	second, err := h.ops.ExecuteTurn(context.Background(), op, turn)
	if err != nil {
		t.Fatal(err)
	}
	if first.Decision.Kind != second.Decision.Kind {
		t.Fatalf("duplicate delivery produced a different decision: %s vs %s", first.Decision.Kind, second.Decision.Kind)
	}
	// The duplicate delivery reaches no provider at all: the logical task the
	// operation key names already committed an answer, and the re-executed
	// step reads it. The identity assertion below is what makes that safe to
	// rely on — every provider identity is derived from the durable operation,
	// so a delivery that did reach the provider would be the same call.
	requests := h.adapter.Requests()
	if len(requests) != 1 {
		t.Fatalf("adapter invocations = %d, want the original only", len(requests))
	}
	wanted := modelgateway.InvocationIdentity(op.Key() + ":plan-attempt-00")
	if requests[0].InvocationID != wanted {
		t.Fatalf("invocation identity %q is not derived from the durable operation key", requests[0].InvocationID)
	}
	// A different durable operation must produce a different identity.
	other := opID(input, "turn-0001")
	if _, err := h.ops.ExecuteTurn(context.Background(), other, workflow.TurnInput{Run: input, Turn: 1, Phase: workflow.PhasePlan, Carry: workflow.Carry{Version: prepared.Version}}); err != nil {
		t.Fatal(err)
	}
	nextOperation := h.adapter.Requests()[1]
	if nextOperation.InvocationID == requests[0].InvocationID {
		t.Fatal("distinct durable operations must not share a provider identity")
	}
}

// Every provider attempt of one turn, including bounded repair attempts, must
// carry its own deterministic identity derived from the same operation key.
func TestRepairAttemptsCarryDistinctDeterministicIdentities(t *testing.T) {
	broken := []byte(`{"kind":"TypedPlan","steps":[`)
	h := newHarness(t, [][]byte{broken})
	input := h.seedRun("artifact-validation")
	outcome, err := h.engine.ExecuteRun(context.Background(), input)
	if err != nil {
		t.Fatal(err)
	}
	if outcome.Terminal != workflow.TerminalRefused {
		t.Fatalf("outcome = %+v", outcome)
	}
	requests := h.adapter.Requests()
	if len(requests) != 3 {
		t.Fatalf("attempts = %d, want the raw attempt plus two pinned repairs", len(requests))
	}
	seen := map[string]bool{}
	for index, request := range requests {
		wanted := modelgateway.InvocationIdentity(fmt.Sprintf("%s:turn-0000:plan-attempt-%02d", input.Key.WorkflowID(), index))
		if request.InvocationID != wanted {
			t.Fatalf("attempt %d identity = %q, want %q", index, request.InvocationID, wanted)
		}
		if seen[request.IdempotencyKey] {
			t.Fatalf("attempt %d reused an idempotency identity", index)
		}
		seen[request.IdempotencyKey] = true
	}
}

// The pinned budget bounds every model call of a turn. Bounded repair used to
// run past an exhausted budget because only the first attempt was checked.
func TestBudgetExhaustionStopsBoundedRepairMidTurn(t *testing.T) {
	broken := []byte(`{"kind":"TypedPlan","steps":[`)
	h := newHarness(t, [][]byte{broken})
	input := h.seedRunWithCalls("artifact-validation", 2)
	outcome, err := h.engine.ExecuteRun(context.Background(), input)
	if err != nil {
		t.Fatal(err)
	}
	if outcome.Terminal != workflow.TerminalRefused || outcome.Problem == nil || outcome.Problem.Code != string(problem.CodeBudgetDenied) {
		t.Fatalf("outcome = %+v", outcome)
	}
	if calls := len(h.adapter.Requests()); calls != 2 {
		t.Fatalf("model calls = %d, want exactly the two the budget funds", calls)
	}
	if snapshot := h.snapshot(); snapshot.Status != runs.Refused {
		t.Fatalf("run state = %s", snapshot.Status)
	}
}

// The cost budget bounds repair the same way the model-call count does.
func TestCostBudgetBoundsEveryRepairAttempt(t *testing.T) {
	broken := []byte(`{"kind":"TypedPlan","steps":[`)
	h := newHarness(t, [][]byte{broken})
	// The scripted adapter meters 1000 cost micros per attempt, so a 2000
	// micro budget funds exactly two of the three pinned attempts.
	input := h.seedRunWithBudget("artifact-validation", func(budget *harnessBudget) {
		budget.costAmount = "0.002"
	})
	outcome, err := h.engine.ExecuteRun(context.Background(), input)
	if err != nil {
		t.Fatal(err)
	}
	if outcome.Terminal != workflow.TerminalRefused || outcome.Problem == nil || outcome.Problem.Code != string(problem.CodeBudgetDenied) {
		t.Fatalf("outcome = %+v", outcome)
	}
	if calls := len(h.adapter.Requests()); calls != 2 {
		t.Fatalf("model calls = %d, want the two the cost budget funds", calls)
	}
}

// Tool arguments are validated against the tool's digest-pinned input schema
// before any effect. Syntactically valid JSON that violates the schema must be
// denied durably and must never execute.
func TestToolArgumentsViolatingThePinnedSchemaAreDeniedDurably(t *testing.T) {
	invalidArguments := execution.PlanStep("anvilkit.tool.context-echo", map[string]json.RawMessage{"unexpected": json.RawMessage(`"value"`)})
	h := newHarness(t, [][]byte{invalidArguments, finalPlan()})
	input := h.seedRun("artifact-validation")
	outcome, err := h.engine.ExecuteRun(context.Background(), input)
	if err != nil {
		t.Fatal(err)
	}
	if outcome.Terminal != workflow.TerminalCompleted {
		t.Fatalf("outcome = %+v", outcome)
	}
	if h.tool.Executions() != 0 {
		t.Fatal("a schema-invalid tool call must never execute")
	}
	if len(h.recorder.Decisions) != 1 || h.recorder.Decisions[0].Decision.Allowed || h.recorder.Decisions[0].Decision.Code != "ARGUMENT_SCHEMA_INVALID" {
		t.Fatalf("guard decisions = %+v", h.recorder.Decisions)
	}
}

// Well-formed arguments that satisfy the pinned schema still dispatch.
func TestToolArgumentsSatisfyingThePinnedSchemaDispatch(t *testing.T) {
	h := newHarness(t, [][]byte{toolPlan(), finalPlan()})
	input := h.seedRun("artifact-validation")
	if _, err := h.engine.ExecuteRun(context.Background(), input); err != nil {
		t.Fatal(err)
	}
	if h.tool.Executions() != 1 {
		t.Fatalf("tool executions = %d, want 1", h.tool.Executions())
	}
}

// Authority revoked after the run started must stop the delegation before any
// Specialist turn runs.
func TestRevokedAuthorityRefusesDelegationBeforeAnySpecialistTurn(t *testing.T) {
	h := newHarness(t, [][]byte{delegatePlan(), finalPlan()})
	input := h.seedRun("artifact-validation")
	// Authority is revoked exactly as the delegation boundary opens, so the
	// manager turn that produced the delegate decision ran under live
	// authority and only the delegation itself faces the revocation.
	h.ops.before("delegate-open-0000", h.authoritySource.Revoke)
	outcome, err := h.engine.ExecuteRun(context.Background(), input)
	if err != nil {
		t.Fatal(err)
	}
	if outcome.Terminal != workflow.TerminalFailed || outcome.Problem == nil || outcome.Problem.Code != string(problem.CodeAuthorityStale) {
		t.Fatalf("outcome = %+v", outcome)
	}
	if h.ops.callsFor(":delegate-open-0000") != 1 {
		t.Fatal("the delegation boundary must be evaluated exactly once")
	}
	if h.ops.callsFor(":delegate-turn-0000-0000") != 0 {
		t.Fatal("a refused delegation must not open a specialist turn")
	}
}

// Each Specialist turn is its own durable boundary: a crash inside a
// delegation must resume at the last completed Specialist turn.
func TestCrashInsideDelegationDoesNotRepeatCompletedSpecialistTurns(t *testing.T) {
	h := newHarness(t, [][]byte{
		delegatePlan(), // manager turn 0 delegates
		execution.PlanStep("agent.continue", map[string]json.RawMessage{"note": json.RawMessage(`"still drafting"`)}), // specialist turn 0
		finalPlan(), // specialist turn 1 candidate
		finalPlan(), // manager turn 1 finalize
	})
	input := h.seedRun("artifact-validation")
	release, entered := h.ops.hold("delegate-turn-0000-0001")
	if err := h.engine.StartRun(context.Background(), input); err != nil {
		t.Fatal(err)
	}
	select {
	case <-entered:
	case <-time.After(10 * time.Second):
		t.Fatal("the delegation never reached its second specialist turn")
	}
	stopped := make(chan error, 1)
	go func() { stopped <- h.engine.Stop(context.Background()) }()
	close(release)
	if err := <-stopped; err != nil {
		t.Fatal(err)
	}

	// Restart over the same durable store.
	h.engine = memory.New(h.store, h.ops)
	outcome, err := h.engine.ExecuteRun(context.Background(), input)
	if err != nil || outcome.Terminal != workflow.TerminalCompleted {
		t.Fatalf("outcome = %+v err = %v", outcome, err)
	}
	if got := h.ops.callsFor(":delegate-open-0000"); got != 1 {
		t.Fatalf("delegation opened %d times across the crash, want 1", got)
	}
	if got := h.ops.callsFor(":delegate-turn-0000-0000"); got != 1 {
		t.Fatalf("completed specialist turn executed %d times across the crash, want 1", got)
	}
}

// A delegation that concludes with a candidate records exactly one specialist
// turn per durable boundary and folds the candidate into the parent carry.
func TestDelegationRunsOneSpecialistTurnPerDurableBoundary(t *testing.T) {
	h := newHarness(t, [][]byte{
		delegatePlan(),
		execution.PlanStep("agent.continue", map[string]json.RawMessage{"note": json.RawMessage(`"drafting"`)}),
		finalPlan(),
		finalPlan(),
	})
	input := h.seedRun("artifact-validation")
	outcome, err := h.engine.ExecuteRun(context.Background(), input)
	if err != nil || outcome.Terminal != workflow.TerminalCompleted {
		t.Fatalf("outcome = %+v err = %v", outcome, err)
	}
	for delegateTurn, want := range map[string]int{":delegate-turn-0000-0000": 1, ":delegate-turn-0000-0001": 1, ":delegate-turn-0000-0002": 0} {
		if got := h.ops.callsFor(delegateTurn); got != want {
			t.Fatalf("%s executed %d times, want %d", delegateTurn, got, want)
		}
	}
}

// The specialist definition is resolved by pinned identity and digest at every
// delegate turn; a tampered digest fails closed.
func TestDelegateTurnRejectsATamperedSpecialistDigest(t *testing.T) {
	h := newHarness(t, [][]byte{delegatePlan(), finalPlan()})
	input := h.seedRun("artifact-validation")
	prepared, err := h.ops.Prepare(context.Background(), opID(input, "prepare"), input)
	if err != nil {
		t.Fatal(err)
	}
	_, err = h.ops.ExecuteDelegateTurn(context.Background(), opID(input, "delegate-turn-0000-0000"), workflow.DelegateTurnInput{
		Run:              input,
		Turn:             0,
		Phase:            workflow.PhasePlan,
		SpecialistID:     agent.SpecialistDefinitionID,
		SpecialistDigest: "sha256:" + strings.Repeat("f", 64),
		Input:            execution.ControlledCandidate(),
		Carry:            workflow.Carry{Version: prepared.Version},
	})
	var details problem.Details
	if !errors.As(err, &details) || details.Code != string(problem.CodeContractInvalid) {
		t.Fatalf("tampered specialist digest error = %v", err)
	}
}

// The interrupts control surface and the executor must agree on expiry: an
// approval decided before the deadline wins the same way an input response
// does.
func TestDecidedApprovalRacingExpiryLeavesTheRunDriven(t *testing.T) {
	h := newHarness(t, [][]byte{finalPlan()})
	input := h.seedRun("page-change")
	if err := h.engine.StartRun(context.Background(), input); err != nil {
		t.Fatal(err)
	}
	request := h.openApprovalRequest()
	if _, err := h.decideApproval(request, interrupts.DecisionApprove, "approve-race"); err != nil {
		t.Fatal(err)
	}
	ack, err := h.ops.ExpireInterrupt(context.Background(), opID(input, "expire-approval-00-0000"), expireRequest(input, string(request.ID), "approval", h.snapshot().Version))
	if err != nil {
		t.Fatal(err)
	}
	if !ack.Raced {
		t.Fatalf("decided approval lost the race: %+v", ack)
	}
	outcome, err := h.engine.ExecuteRun(context.Background(), input)
	if err != nil || outcome.Terminal != workflow.TerminalCompleted {
		t.Fatalf("outcome = %+v err = %v", outcome, err)
	}
}
