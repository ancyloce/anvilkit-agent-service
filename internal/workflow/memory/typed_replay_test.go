package memory

import (
	"context"
	"testing"

	"github.com/ancyloce/anvilkit-agent-service/internal/problem"
	"github.com/ancyloce/anvilkit-agent-service/internal/workflow"
	"github.com/ancyloce/anvilkit-agent-service/internal/workflow/workflowtest"
)

// failingTurnOps fails one turn with a typed problem and counts executions,
// so replay behaviour can be observed on the controlled engine.
type failingTurnOps struct {
	*workflowtest.ProbeOps
	failure problem.Details
	turns   int
}

func (o *failingTurnOps) ExecuteTurn(_ context.Context, _ workflow.OpID, _ workflow.TurnInput) (workflow.TurnResult, error) {
	o.turns++
	return workflow.TurnResult{}, o.failure
}

// The memory engine records step outcomes as bytes. A typed ProblemDetails
// must be reconstructed on replay instead of degrading into an opaque
// internal error, otherwise recovery changes the recorded run outcome.
func TestMemoryEngineReplayReconstructsTypedProblem(t *testing.T) {
	failure := problem.New(problem.CodeBudgetDenied, "")
	failure.Detail = "the pinned agent budget is exhausted"
	ops := &failingTurnOps{ProbeOps: workflowtest.NewProbeOps(), failure: failure}
	store := NewStore()
	engine := New(store, ops)
	defer stopEngine(t, engine)
	input := memoryInput("run.memory-typed-replay", 1)

	first, err := engine.ExecuteRun(context.Background(), input)
	if err != nil {
		t.Fatal(err)
	}
	if first.Terminal != workflow.TerminalFailed || first.Problem == nil {
		t.Fatalf("outcome = %+v", first)
	}
	if first.Problem.Code != string(problem.CodeBudgetDenied) || first.Problem.Detail != failure.Detail {
		t.Fatalf("typed problem lost on the first execution: %+v", *first.Problem)
	}

	// A fresh engine over the same durable store models a restart.
	restarted := New(store, ops)
	defer stopEngine(t, restarted)
	second, err := restarted.ExecuteRun(context.Background(), input)
	if err != nil {
		t.Fatal(err)
	}
	if second.Problem == nil || second.Problem.Code != first.Problem.Code || second.Problem.Detail != first.Problem.Detail {
		t.Fatalf("replayed problem drifted: %+v", second.Problem)
	}
	if second.Problem.Retryability != first.Problem.Retryability || second.Problem.Title != first.Problem.Title || second.Problem.Status != first.Problem.Status {
		t.Fatalf("replayed problem lost its registry identity: %+v", *second.Problem)
	}
	if ops.turns != 1 {
		t.Fatalf("turn executed %d times across replay, want 1", ops.turns)
	}
}
