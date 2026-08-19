package workflow

import (
	"context"
	"encoding/json"
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
	prepare func() (PrepareResult, error)
	turn    func(TurnInput) (TurnResult, error)
	read    func() (InputRead, error)
	calls   map[string]int
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
