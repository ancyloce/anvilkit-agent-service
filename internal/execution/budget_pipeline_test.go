package execution_test

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/ancyloce/anvilkit-agent-service/internal/budget"
	"github.com/ancyloce/anvilkit-agent-service/internal/domaincommit"
	"github.com/ancyloce/anvilkit-agent-service/internal/interrupts"
	"github.com/ancyloce/anvilkit-agent-service/internal/problem"
	"github.com/ancyloce/anvilkit-agent-service/internal/runs"
	"github.com/ancyloce/anvilkit-agent-service/internal/workflow"
)

// testBudgetScope is the tenant the harness run's budget belongs to.
var testBudgetScope = budget.Scope{WorkspaceID: testWorkspace, ProjectID: testProject}

// A completed run's standing reservation is settled and released: reserved at
// preparation before any dispatch, observed per turn, finalized and released
// at the terminal boundary.
func TestRunReservationIsMadeBeforeDispatchAndReleasedOnCompletion(t *testing.T) {
	h := newHarness(t, [][]byte{finalPlan()})
	input := h.seedRun("artifact-validation")
	outcome, err := h.engine.ExecuteRun(context.Background(), input)
	if err != nil || outcome.Terminal != workflow.TerminalCompleted {
		t.Fatalf("outcome = %+v err = %v", outcome, err)
	}
	reservation, err := h.budgetLedger.Reservation(context.Background(), testBudgetScope, budget.ReservationID("budget:"+testRunID+":g1"))
	if err != nil {
		t.Fatal(err)
	}
	if reservation.Generation != 1 || !reservation.AttemptFinal || !reservation.Released {
		t.Fatalf("reservation = %+v, want a finalized, released settlement", reservation)
	}
	if reservation.UpperBoundMicros != reservation.ObservedMicros {
		t.Fatalf("reservation = %+v, want the hold settled at observed cost", reservation)
	}
}

// A budget whose worst-case cost exceeds the controller's headroom refuses
// the run at preparation — before any model disclosure or dispatch exists.
func TestBudgetHeadroomDenialRefusesTheRunBeforeAnyDispatch(t *testing.T) {
	h := newHarness(t, [][]byte{finalPlan()}, func(options *harnessOptions) {
		options.budgetHeadroomMicros = 1
	})
	input := h.seedRun("artifact-validation")
	outcome, err := h.engine.ExecuteRun(context.Background(), input)
	if err != nil {
		t.Fatal(err)
	}
	if outcome.Terminal != workflow.TerminalRefused || outcome.Problem == nil || outcome.Problem.Code != string(problem.CodeBudgetDenied) {
		t.Fatalf("outcome = %+v", outcome)
	}
	if len(h.adapter.Requests()) != 0 {
		t.Fatal("a budget-refused run must not disclose context to a provider")
	}
	if snapshot := h.snapshot(); snapshot.Status != runs.Refused {
		t.Fatalf("run state = %s", snapshot.Status)
	}
}

// An explicit retry is replacement work: the failed generation's settled cost
// stays held un-released, and the new generation reserves incremental
// worst-case headroom on top of it before executing.
func TestExplicitRetryHoldsThePriorGenerationAndReservesReplacement(t *testing.T) {
	h := newHarness(t, [][]byte{inputPlan(), inputPlan(), finalPlan()}, func(options *harnessOptions) {
		options.inputTTL = 250 * time.Millisecond
	})
	input := h.seedRun("artifact-validation")
	outcome, err := h.engine.ExecuteRun(context.Background(), input)
	if err != nil || outcome.Terminal != workflow.TerminalFailed {
		t.Fatalf("precondition failed run: %+v %v", outcome, err)
	}
	failed, err := h.budgetLedger.Reservation(context.Background(), testBudgetScope, budget.ReservationID("budget:"+testRunID+":g1"))
	if err != nil {
		t.Fatal(err)
	}
	if !failed.AttemptFinal || failed.Released {
		t.Fatalf("failed generation reservation = %+v, want settled but held un-released", failed)
	}
	snapshot := h.snapshot()
	if _, err := h.service.Retry(context.Background(), interrupts.Write{Scope: testScope(), RunID: testRunID, ExpectedVersion: snapshot.Version, IdempotencyKey: "retry-budget", Traceparent: traceparent}); err != nil {
		t.Fatal(err)
	}
	request := h.openInputRequest()
	current := h.snapshot()
	if _, err := h.service.RespondInput(context.Background(), interrupts.Write{Scope: testScope(), RunID: testRunID, ExpectedVersion: current.Version, IdempotencyKey: "respond-budget-g2", Traceparent: traceparent}, interrupts.InputResponseCommand{RequestID: request.ID, RequestVersion: request.Version, Value: json.RawMessage(`{"answer":"retry answer"}`)}); err != nil {
		t.Fatal(err)
	}
	secondOutcome, err := h.engine.ExecuteRun(context.Background(), workflow.RunInput{Key: workflow.RunKey{RunID: testRunID, Generation: 2}, Scope: input.Scope, Traceparent: traceparent})
	if err != nil || secondOutcome.Terminal != workflow.TerminalCompleted {
		t.Fatalf("generation 2 outcome = %+v err = %v", secondOutcome, err)
	}
	replacement, err := h.budgetLedger.Reservation(context.Background(), testBudgetScope, budget.ReservationID("budget:"+testRunID+":g2"))
	if err != nil {
		t.Fatal(err)
	}
	if replacement.Generation != 2 || !replacement.Released {
		t.Fatalf("replacement reservation = %+v, want the completed generation released", replacement)
	}
	stillHeld, err := h.budgetLedger.Reservation(context.Background(), testBudgetScope, budget.ReservationID("budget:"+testRunID+":g1"))
	if err != nil || stillHeld.Released {
		t.Fatalf("prior generation = %+v err=%v, want its settled cost still held", stillHeld, err)
	}
}

// A replacement generation that no longer fits in headroom refuses instead of
// executing: the prior generation's held cost counts against the bound.
func TestReplacementWithoutHeadroomIsRefused(t *testing.T) {
	// The pinned budget costs exactly the headroom, so the first generation
	// reserves; the failed generation's observed cost stays held, and the
	// replacement no longer fits — it must be denied, not executed.
	h := newHarness(t, [][]byte{inputPlan(), inputPlan(), finalPlan()}, func(options *harnessOptions) {
		options.inputTTL = 250 * time.Millisecond
		options.budgetHeadroomMicros = 100_000_000
	})
	input := h.seedRun("artifact-validation")
	outcome, err := h.engine.ExecuteRun(context.Background(), input)
	if err != nil || outcome.Terminal != workflow.TerminalFailed {
		t.Fatalf("precondition failed run: %+v %v", outcome, err)
	}
	snapshot := h.snapshot()
	if _, err := h.service.Retry(context.Background(), interrupts.Write{Scope: testScope(), RunID: testRunID, ExpectedVersion: snapshot.Version, IdempotencyKey: "retry-tight", Traceparent: traceparent}); err != nil {
		t.Fatal(err)
	}
	secondOutcome, err := h.engine.ExecuteRun(context.Background(), workflow.RunInput{Key: workflow.RunKey{RunID: testRunID, Generation: 2}, Scope: input.Scope, Traceparent: traceparent})
	if err != nil {
		t.Fatal(err)
	}
	if secondOutcome.Terminal != workflow.TerminalRefused || secondOutcome.Problem == nil || secondOutcome.Problem.Code != string(problem.CodeBudgetDenied) {
		t.Fatalf("replacement outcome = %+v, want a budget refusal", secondOutcome)
	}
	if len(h.adapter.Requests()) != 1 {
		t.Fatalf("provider requests = %d, want no disclosure from the refused replacement", len(h.adapter.Requests()))
	}
}

// A governed effect that stays unsettled through the workflow's bounded wake
// budget releases the run at the submit boundary as unresolved: nothing is
// failed, nothing is resent, the journal is escalated for the operator, and
// the run aggregate keeps its submit-boundary state.
func TestUnsettledCommitExhaustionReleasesTheRunUnresolved(t *testing.T) {
	h := newHarness(t, [][]byte{finalPlan()})
	input := h.seedRun("page-change")
	h.domain.LoseSubmission(true)
	if err := h.engine.StartRun(context.Background(), input); err != nil {
		t.Fatal(err)
	}
	request := h.openApprovalRequest()
	if _, err := h.decideApproval(request, interrupts.DecisionApprove, "approve-unresolved"); err != nil {
		t.Fatal(err)
	}
	outcome, err := h.engine.ExecuteRun(context.Background(), input)
	if err != nil {
		t.Fatal(err)
	}
	if outcome.Terminal != workflow.TerminalUnresolved || outcome.Problem == nil || outcome.Problem.Code != string(problem.CodeDomainOutcomeUncertain) || outcome.Problem.Retryability != "operator-action" {
		t.Fatalf("outcome = %+v, want the unresolved release for operator action", outcome)
	}
	if snapshot := h.snapshot(); snapshot.Status != runs.AwaitingDomainConfirmation {
		t.Fatalf("run state = %s, want the submit boundary preserved", snapshot.Status)
	}
	if h.domain.Commits() != 0 {
		t.Fatalf("domain commits = %d, want zero resends across every wake", h.domain.Commits())
	}
	operation, active, err := h.submissions.ActiveForRun(context.Background(), domaincommit.Scope{WorkspaceID: testWorkspace, ProjectID: testProject}, testRunID)
	if err != nil || !active || operation.Status != domaincommit.Escalated {
		t.Fatalf("operation = %+v active=%v err=%v, want the escalated journal awaiting the operator", operation, active, err)
	}
}
