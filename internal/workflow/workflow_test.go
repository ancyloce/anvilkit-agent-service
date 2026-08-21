package workflow

import (
	"context"
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/ancyloce/anvilkit-agent-service/internal/agent"
	"github.com/ancyloce/anvilkit-agent-service/internal/problem"
)

// scriptHost executes steps inline without persistence: sufficient for
// single-execution orchestration units.
type scriptHost struct{ awaits []awaitScript }

type awaitScript struct {
	payload  []byte
	timedOut bool
}

func (h *scriptHost) WorkflowID() string { return "run.unit:g1" }
func (h *scriptHost) Step(_ string, fn func(context.Context) ([]byte, error)) ([]byte, error) {
	return fn(context.Background())
}
func (h *scriptHost) AwaitSignal(string, time.Duration) ([]byte, bool, error) {
	if len(h.awaits) == 0 {
		return nil, true, nil
	}
	next := h.awaits[0]
	h.awaits = h.awaits[1:]
	return next.payload, next.timedOut, nil
}

// scriptOps drives orchestration edges through configurable hooks.
type scriptOps struct {
	prepare        func() (PrepareResult, error)
	turn           func(TurnInput) (TurnResult, error)
	read           func() (InputRead, error)
	openDelegation func(DelegationInput) (DelegationOpened, error)
	delegateTurn   func(DelegateTurnInput) (DelegateTurnResult, error)
	commit         func(int) (CommitResult, error)
	review         func() (ReviewResult, error)
	calls          map[string]int
}

func newScriptOps() *scriptOps {
	return &scriptOps{
		calls:   map[string]int{},
		prepare: func() (PrepareResult, error) { return PrepareResult{TurnLimit: 4, Version: 2}, nil },
		read:    func() (InputRead, error) { return InputRead{RemainingMillis: 10, Version: 3}, nil },
	}
}

func (o *scriptOps) note(step string) { o.calls[step]++ }

func (o *scriptOps) Prepare(context.Context, OpID, RunInput) (PrepareResult, error) {
	o.note("prepare")
	return o.prepare()
}
func (o *scriptOps) ExecuteTurn(_ context.Context, _ OpID, input TurnInput) (TurnResult, error) {
	o.note("turn")
	return o.turn(input)
}
func (o *scriptOps) RecordDecision(context.Context, OpID, DecisionRecord) (Ack, error) {
	o.note("decision")
	return Ack{}, nil
}
func (o *scriptOps) ExecuteAction(context.Context, OpID, ActionInput) (ActionResult, error) {
	o.note("action")
	return ActionResult{}, nil
}
func (o *scriptOps) OpenDelegation(_ context.Context, _ OpID, input DelegationInput) (DelegationOpened, error) {
	o.note("delegate-open")
	if o.openDelegation != nil {
		return o.openDelegation(input)
	}
	return DelegationOpened{TurnLimit: 2, SpecialistID: "definition.unit.specialist", SpecialistDigest: "sha256:" + strings.Repeat("b", 64), Carry: input.Carry}, nil
}
func (o *scriptOps) ExecuteDelegateTurn(_ context.Context, _ OpID, input DelegateTurnInput) (DelegateTurnResult, error) {
	o.note("delegate-turn")
	if o.delegateTurn != nil {
		return o.delegateTurn(input)
	}
	return DelegateTurnResult{Done: true, Carry: input.Carry}, nil
}
func (o *scriptOps) OpenInput(context.Context, OpID, InterruptOpen) (InterruptOpened, error) {
	o.note("open-input")
	return InterruptOpened{RequestID: "request.unit", TimeoutMillis: 50, Version: 3}, nil
}
func (o *scriptOps) ReadInput(context.Context, OpID, InterruptRef) (InputRead, error) {
	o.note("read-input")
	return o.read()
}
func (o *scriptOps) ExpireInterrupt(context.Context, OpID, ExpireRequest) (Ack, error) {
	o.note("expire")
	return Ack{Version: 4}, nil
}
func (o *scriptOps) FinalizeCandidate(context.Context, OpID, FinalizeInput) (FinalizeResult, error) {
	o.note("finalize")
	return FinalizeResult{ArtifactDigest: "sha256:" + strings.Repeat("a", 64), Version: 5}, nil
}
func (o *scriptOps) ResolveReview(context.Context, OpID, ReviewInput) (ReviewResult, error) {
	o.note("review")
	if o.review != nil {
		return o.review()
	}
	return ReviewResult{Accepted: true, Version: 6}, nil
}
func (o *scriptOps) ReadApproval(context.Context, OpID, InterruptRef) (ApprovalRead, error) {
	o.note("read-approval")
	return ApprovalRead{Decided: true, Kind: "approve", Version: 7}, nil
}
func (o *scriptOps) Revise(context.Context, OpID, ReviseInput) (Ack, error) {
	o.note("revise")
	return Ack{Version: 8}, nil
}
func (o *scriptOps) Commit(context.Context, OpID, CommitInput) (CommitResult, error) {
	o.note("commit")
	if o.commit != nil {
		return o.commit(o.calls["commit"])
	}
	return CommitResult{Outcome: CommitCompleted, Version: 9}, nil
}
func (o *scriptOps) Terminalize(context.Context, OpID, TerminalInput) (Ack, error) {
	o.note("terminalize")
	return Ack{Version: 10}, nil
}

func unitInput() RunInput {
	return RunInput{Key: RunKey{RunID: "run.unit", Generation: 1}, Scope: Scope{WorkspaceID: "w", ProjectID: "p", ActorID: "a"}}
}

func finalDecision() agent.TurnDecision {
	return agent.TurnDecision{Kind: agent.DecisionFinal, Final: &agent.FinalDecision{Candidate: json.RawMessage(`{}`)}}
}

func TestWorkflowFailsClosedOnUnknownDecisionKind(t *testing.T) {
	ops := newScriptOps()
	ops.turn = func(TurnInput) (TurnResult, error) {
		return TurnResult{Decision: agent.TurnDecision{Kind: "bogus"}}, nil
	}
	outcome, err := AgentRunWorkflow(&scriptHost{}, ops, unitInput())
	if err != nil {
		t.Fatal(err)
	}
	if outcome.Terminal != TerminalFailed {
		t.Fatalf("outcome = %+v", outcome)
	}
	if ops.calls["terminalize"] != 1 {
		t.Fatal("unknown decisions must cross the terminal boundary")
	}
}

func TestWorkflowExitsSupersededWithoutFurtherOperations(t *testing.T) {
	ops := newScriptOps()
	ops.prepare = func() (PrepareResult, error) { return PrepareResult{Superseded: true}, nil }
	outcome, err := AgentRunWorkflow(&scriptHost{}, ops, unitInput())
	if err != nil {
		t.Fatal(err)
	}
	if outcome.Terminal != TerminalSuperseded {
		t.Fatalf("outcome = %+v", outcome)
	}
	if ops.calls["turn"] != 0 || ops.calls["terminalize"] != 0 {
		t.Fatalf("superseded workflow must write nothing: %+v", ops.calls)
	}
}

func TestWorkflowHaltBehaviorSelectsRefusalOrFailure(t *testing.T) {
	for _, testCase := range []struct {
		behavior TerminalState
		want     TerminalState
	}{{TerminalRefused, TerminalRefused}, {TerminalFailed, TerminalFailed}, {"unknown", TerminalFailed}} {
		ops := newScriptOps()
		halt := &Halt{Problem: problem.New(problem.CodeBudgetDenied, ""), Behavior: testCase.behavior}
		ops.turn = func(TurnInput) (TurnResult, error) { return TurnResult{Halt: halt}, nil }
		outcome, err := AgentRunWorkflow(&scriptHost{}, ops, unitInput())
		if err != nil {
			t.Fatal(err)
		}
		if outcome.Terminal != testCase.want {
			t.Fatalf("behavior %s: outcome = %+v", testCase.behavior, outcome)
		}
	}
}

func TestWorkflowTurnLimitExhaustionFailsWithTypedProblem(t *testing.T) {
	ops := newScriptOps()
	ops.turn = func(TurnInput) (TurnResult, error) {
		return TurnResult{Decision: agent.TurnDecision{Kind: agent.DecisionContinue, Continue: &agent.ContinueDecision{}}}, nil
	}
	outcome, err := AgentRunWorkflow(&scriptHost{}, ops, unitInput())
	if err != nil {
		t.Fatal(err)
	}
	if outcome.Terminal != TerminalFailed || outcome.Problem == nil || outcome.Problem.Code != string(problem.CodeLimitExceeded) {
		t.Fatalf("outcome = %+v", outcome)
	}
	if ops.calls["turn"] != 4 {
		t.Fatalf("turns executed = %d, want the pinned limit 4", ops.calls["turn"])
	}
}

func TestWorkflowBoundsSpuriousWakeBudget(t *testing.T) {
	ops := newScriptOps()
	turn := 0
	ops.turn = func(TurnInput) (TurnResult, error) {
		turn++
		if turn == 1 {
			return TurnResult{Decision: agent.TurnDecision{Kind: agent.DecisionNeedInput, NeedInput: &agent.NeedInputDecision{Question: "?"}}}, nil
		}
		return TurnResult{Decision: finalDecision()}, nil
	}
	// Every wake is spurious: not accepted, not expired, never timed out.
	host := &scriptHost{}
	for range 100 {
		host.awaits = append(host.awaits, awaitScript{})
	}
	outcome, err := AgentRunWorkflow(host, ops, unitInput())
	if err != nil {
		t.Fatal(err)
	}
	if outcome.Terminal != TerminalFailed {
		t.Fatalf("outcome = %+v", outcome)
	}
	if ops.calls["read-input"] > 64 {
		t.Fatalf("wake budget exceeded: %d reads", ops.calls["read-input"])
	}
}

func TestRunKeyIdentityRoundTripAndDerivedTrace(t *testing.T) {
	key := RunKey{RunID: "run.identity", Generation: 3}
	if key.WorkflowID() != "run.identity:g3" {
		t.Fatalf("workflow identity = %s", key.WorkflowID())
	}
	parsed, err := ParseWorkflowID(key.WorkflowID())
	if err != nil || parsed != key {
		t.Fatalf("parsed = %+v err = %v", parsed, err)
	}
	if _, err := ParseWorkflowID("run.identity"); err == nil {
		t.Fatal("identity without generation must fail")
	}
	if _, err := ParseWorkflowID("run.identity:g0"); err == nil {
		t.Fatal("zero generation must fail")
	}
	trace := key.DerivedTraceparent()
	valid := RunInput{Key: key, Scope: Scope{WorkspaceID: "w", ProjectID: "p", ActorID: "a"}, Traceparent: trace}
	if err := valid.Validate(); err != nil {
		t.Fatalf("derived traceparent must validate: %v", err)
	}
	if second := key.DerivedTraceparent(); second != trace {
		t.Fatal("derived traceparent must be deterministic")
	}
}

func TestRunInputValidateRejectsUnboundedIdentity(t *testing.T) {
	base := unitInput()
	broken := []RunInput{
		{Key: RunKey{RunID: "", Generation: 1}, Scope: base.Scope},
		{Key: RunKey{RunID: strings.Repeat("r", 130), Generation: 1}, Scope: base.Scope},
		{Key: RunKey{RunID: "run.x", Generation: 0}, Scope: base.Scope},
		{Key: base.Key, Scope: Scope{WorkspaceID: "", ProjectID: "p", ActorID: "a"}},
		{Key: base.Key, Scope: base.Scope, Traceparent: "not-a-traceparent"},
	}
	for index, input := range broken {
		if err := input.Validate(); err == nil {
			t.Fatalf("input %d must fail validation", index)
		}
	}
	if err := base.Validate(); err != nil {
		t.Fatalf("bounded input must validate: %v", err)
	}
}

// replayHost records step outputs on the first execution and replays the
// recorded bytes afterwards, exactly as a durable engine does after a crash.
type replayHost struct {
	steps    map[string][]byte
	failures map[string]error
	executed map[string]int
	awaits   []awaitScript
}

func newReplayHost() *replayHost {
	return &replayHost{steps: map[string][]byte{}, failures: map[string]error{}, executed: map[string]int{}}
}

func (h *replayHost) WorkflowID() string { return "run.replay:g1" }

func (h *replayHost) Step(name string, fn func(context.Context) ([]byte, error)) ([]byte, error) {
	if recorded, replay := h.steps[name]; replay {
		return recorded, nil
	}
	if failure, replay := h.failures[name]; replay {
		return nil, failure
	}
	h.executed[name]++
	output, err := fn(context.Background())
	if err != nil {
		// A durable engine records the failure as an opaque string; the
		// workflow must not depend on that string carrying structure.
		h.failures[name] = errors.New(err.Error())
		return nil, err
	}
	h.steps[name] = append([]byte(nil), output...)
	return output, nil
}

func (h *replayHost) AwaitSignal(string, time.Duration) ([]byte, bool, error) {
	if len(h.awaits) == 0 {
		return nil, true, nil
	}
	next := h.awaits[0]
	h.awaits = h.awaits[1:]
	return next.payload, next.timedOut, nil
}

// A typed operation problem must survive replay with its registry identity
// intact; before this was recorded structurally, replay degraded it into an
// opaque INTERNAL_ERROR.
func TestTypedOperationProblemSurvivesStepReplay(t *testing.T) {
	failure := problem.New(problem.CodeAuthorityStale, "")
	failure.Detail = "pinned run authority no longer matches current authority"

	first := newScriptOps()
	first.turn = func(TurnInput) (TurnResult, error) { return TurnResult{}, failure }
	host := newReplayHost()
	outcome, err := AgentRunWorkflow(host, first, unitInput())
	if err != nil {
		t.Fatal(err)
	}
	if outcome.Terminal != TerminalFailed || outcome.Problem == nil || outcome.Problem.Code != string(problem.CodeAuthorityStale) {
		t.Fatalf("first execution outcome = %+v", outcome)
	}
	if outcome.Problem.Detail != failure.Detail {
		t.Fatalf("first execution lost the typed detail: %q", outcome.Problem.Detail)
	}

	// Recovery replays the recorded step. The operation must not run again,
	// and the reconstructed problem must be identical.
	replayed := newScriptOps()
	replayed.turn = func(TurnInput) (TurnResult, error) {
		t.Fatal("replay must not re-execute a recorded operation")
		return TurnResult{}, nil
	}
	second, err := AgentRunWorkflow(host, replayed, unitInput())
	if err != nil {
		t.Fatal(err)
	}
	if second.Terminal != outcome.Terminal || second.Problem == nil {
		t.Fatalf("replayed outcome = %+v", second)
	}
	if !reflect.DeepEqual(*second.Problem, *outcome.Problem) {
		t.Fatalf("replayed problem drifted: %+v vs %+v", *second.Problem, *outcome.Problem)
	}
	if host.executed["turn-0000"] != 1 {
		t.Fatalf("turn executed %d times, want 1", host.executed["turn-0000"])
	}
}

// An untyped operation failure stays an engine failure: the workflow must not
// invent a typed problem for it, and it must not be recorded as a value.
func TestUntypedOperationFailureStaysAnEngineFailure(t *testing.T) {
	ops := newScriptOps()
	ops.turn = func(TurnInput) (TurnResult, error) { return TurnResult{}, errors.New("connection reset") }
	host := newReplayHost()
	outcome, err := AgentRunWorkflow(host, ops, unitInput())
	if err != nil {
		t.Fatal(err)
	}
	if outcome.Terminal != TerminalFailed || outcome.Problem == nil || outcome.Problem.Code != string(problem.CodeInternal) {
		t.Fatalf("outcome = %+v", outcome)
	}
	if _, recorded := host.steps["turn-0000"]; recorded {
		t.Fatal("an untyped failure must not be recorded as a step value")
	}
}

// Each Specialist turn must be its own durable step so a crash resumes at the
// last completed turn instead of repeating the delegation loop.
func TestDelegationDrivesOneDurableStepPerSpecialistTurn(t *testing.T) {
	ops := newScriptOps()
	turn := 0
	ops.turn = func(TurnInput) (TurnResult, error) {
		turn++
		if turn == 1 {
			return TurnResult{Decision: agent.TurnDecision{Kind: agent.DecisionDelegate, Delegate: &agent.DelegateDecision{DelegateID: "definition.unit.specialist", Input: json.RawMessage(`{"task":"draft"}`)}}}, nil
		}
		return TurnResult{Decision: finalDecision()}, nil
	}
	ops.openDelegation = func(input DelegationInput) (DelegationOpened, error) {
		return DelegationOpened{TurnLimit: 3, SpecialistID: "definition.unit.specialist", SpecialistDigest: "sha256:" + strings.Repeat("b", 64), Carry: input.Carry}, nil
	}
	delegateTurns := 0
	ops.delegateTurn = func(input DelegateTurnInput) (DelegateTurnResult, error) {
		delegateTurns++
		return DelegateTurnResult{Done: delegateTurns == 3, Carry: input.Carry}, nil
	}
	host := newReplayHost()
	outcome, err := AgentRunWorkflow(host, ops, unitInput())
	if err != nil {
		t.Fatal(err)
	}
	if outcome.Terminal != TerminalCompleted {
		t.Fatalf("outcome = %+v", outcome)
	}
	for delegateTurn := range 3 {
		stepName := delegateName(0, delegateTurn)
		if host.executed[stepName] != 1 {
			t.Fatalf("specialist turn %d executed %d times as step %s, want exactly one durable boundary", delegateTurn, host.executed[stepName], stepName)
		}
	}
	if ops.calls["delegate-turn"] != 3 {
		t.Fatalf("delegate turns = %d, want 3", ops.calls["delegate-turn"])
	}
}

// A delegation that never concludes inside its bounded turns fails closed
// rather than silently continuing the parent loop.
func TestDelegationWithoutConclusionFailsClosed(t *testing.T) {
	ops := newScriptOps()
	ops.turn = func(TurnInput) (TurnResult, error) {
		return TurnResult{Decision: agent.TurnDecision{Kind: agent.DecisionDelegate, Delegate: &agent.DelegateDecision{DelegateID: "definition.unit.specialist", Input: json.RawMessage(`{}`)}}}, nil
	}
	ops.openDelegation = func(input DelegationInput) (DelegationOpened, error) {
		return DelegationOpened{TurnLimit: 2, SpecialistID: "definition.unit.specialist", SpecialistDigest: "sha256:" + strings.Repeat("b", 64), Carry: input.Carry}, nil
	}
	ops.delegateTurn = func(input DelegateTurnInput) (DelegateTurnResult, error) {
		return DelegateTurnResult{Carry: input.Carry}, nil
	}
	outcome, err := AgentRunWorkflow(&scriptHost{}, ops, unitInput())
	if err != nil {
		t.Fatal(err)
	}
	if outcome.Terminal != TerminalFailed || outcome.Problem == nil || outcome.Problem.Code != string(problem.CodeInternal) {
		t.Fatalf("outcome = %+v", outcome)
	}
}

// An unbounded specialist turn limit from an operation must fail closed
// instead of opening an unbounded durable loop.
func TestDelegationRejectsUnboundedTurnLimit(t *testing.T) {
	for _, limit := range []int{0, maximumDelegateTurns + 1} {
		ops := newScriptOps()
		ops.turn = func(TurnInput) (TurnResult, error) {
			return TurnResult{Decision: agent.TurnDecision{Kind: agent.DecisionDelegate, Delegate: &agent.DelegateDecision{DelegateID: "definition.unit.specialist", Input: json.RawMessage(`{}`)}}}, nil
		}
		ops.openDelegation = func(input DelegationInput) (DelegationOpened, error) {
			return DelegationOpened{TurnLimit: limit, SpecialistID: "definition.unit.specialist", SpecialistDigest: "sha256:" + strings.Repeat("b", 64), Carry: input.Carry}, nil
		}
		outcome, err := AgentRunWorkflow(&scriptHost{}, ops, unitInput())
		if err != nil {
			t.Fatal(err)
		}
		if outcome.Terminal != TerminalFailed {
			t.Fatalf("turn limit %d: outcome = %+v", limit, outcome)
		}
		if ops.calls["delegate-turn"] != 0 {
			t.Fatalf("turn limit %d opened %d specialist turns", limit, ops.calls["delegate-turn"])
		}
	}
}

// approvalRequiredReview routes the run through the approval boundary so it
// reaches the governed commit.
func approvalRequiredReview() (ReviewResult, error) {
	return ReviewResult{Accepted: false, RequestID: "request.approval", TimeoutMillis: 1, Version: 6}, nil
}

// A run holding at the submit boundary is released as unresolved only after
// its governed effect is durably escalated. The wake count is not the release
// boundary: an operation that keeps answering "unsettled, not escalated" holds
// the run for ever rather than handing back an unresolved run nobody was paged
// for, and the workflow errors at its spin guard instead of releasing.
func TestUnresolvedReleaseRequiresDurableEscalation(t *testing.T) {
	ops := newScriptOps()
	ops.turn = func(TurnInput) (TurnResult, error) {
		return TurnResult{Decision: finalDecision()}, nil
	}
	ops.review = approvalRequiredReview
	ops.commit = func(int) (CommitResult, error) {
		return CommitResult{Unsettled: true, RetryAfterMillis: 1, Version: 9}, nil
	}
	outcome, err := AgentRunWorkflow(&scriptHost{}, ops, unitInput())
	if err == nil {
		t.Fatalf("an unescalated hold was released as %+v", outcome)
	}
	if ops.calls["commit"] != MaximumCommitWakes {
		t.Fatalf("commit calls=%d, want the spin guard to bound the hold", ops.calls["commit"])
	}
	if ops.calls["terminalize"] != 0 {
		t.Fatal("an unescalated hold terminalized the run")
	}
}

// A reconciliation window larger than the workflow's own hold window still
// reaches its escalation: the loop keeps reconciling until the operation
// reports the durable escalation, whatever wake that lands on.
func TestReconciliationWindowBeyondTheHoldWindowStillEscalatesBeforeRelease(t *testing.T) {
	for _, escalateAt := range []int{1, commitHoldWakes, commitHoldWakes + 1, commitHoldWakes * 3} {
		ops := newScriptOps()
		ops.turn = func(TurnInput) (TurnResult, error) {
			return TurnResult{Decision: finalDecision()}, nil
		}
		ops.review = approvalRequiredReview
		ops.commit = func(call int) (CommitResult, error) {
			return CommitResult{Unsettled: true, RetryAfterMillis: 1, Version: 9, Escalated: call >= escalateAt}, nil
		}
		outcome, err := AgentRunWorkflow(&scriptHost{}, ops, unitInput())
		if err != nil || outcome.Terminal != TerminalUnresolved {
			t.Fatalf("escalateAt=%d outcome=%+v err=%v", escalateAt, outcome, err)
		}
		// Release happens on the first wake that is both escalated and past
		// the hold window — never before the escalation.
		wantCalls := escalateAt
		if wantCalls < commitHoldWakes {
			wantCalls = commitHoldWakes
		}
		if ops.calls["commit"] != wantCalls {
			t.Fatalf("escalateAt=%d commit calls=%d, want %d", escalateAt, ops.calls["commit"], wantCalls)
		}
		if outcome.Problem == nil || outcome.Problem.Retryability != "operator-action" {
			t.Fatalf("escalateAt=%d unresolved problem=%+v, want an operator-action refusal", escalateAt, outcome.Problem)
		}
	}
}

// A settled answer at any point ends the hold immediately, escalated or not.
func TestSettledAnswerEndsTheHoldWithoutRelease(t *testing.T) {
	ops := newScriptOps()
	ops.turn = func(TurnInput) (TurnResult, error) {
		return TurnResult{Decision: finalDecision()}, nil
	}
	ops.review = approvalRequiredReview
	ops.commit = func(call int) (CommitResult, error) {
		if call < 3 {
			return CommitResult{Unsettled: true, RetryAfterMillis: 1, Version: 9, Escalated: call >= 2}, nil
		}
		return CommitResult{Outcome: CommitCompleted, Version: 9}, nil
	}
	outcome, err := AgentRunWorkflow(&scriptHost{}, ops, unitInput())
	if err != nil || outcome.Terminal != TerminalCompleted {
		t.Fatalf("outcome=%+v err=%v", outcome, err)
	}
	if ops.calls["commit"] != 3 {
		t.Fatalf("commit calls=%d, want the settled answer to end the hold", ops.calls["commit"])
	}
}

// The configurable reconciliation window can never be set past the point the
// commit loop can reach, which is what once let a run be released before its
// effect was escalated.
func TestConfigurableReconciliationWindowStaysWithinTheCommitLoop(t *testing.T) {
	if MaximumDomainReconciliations >= MaximumCommitWakes {
		t.Fatalf("configurable window %d is not bounded by the commit spin guard %d", MaximumDomainReconciliations, MaximumCommitWakes)
	}
	if commitHoldWakes > MaximumCommitWakes {
		t.Fatalf("hold window %d exceeds the spin guard %d", commitHoldWakes, MaximumCommitWakes)
	}
}
