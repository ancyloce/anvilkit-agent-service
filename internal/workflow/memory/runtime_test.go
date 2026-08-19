package memory

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/ancyloce/anvilkit-agent-service/internal/problem"
	"github.com/ancyloce/anvilkit-agent-service/internal/workflow"
	"github.com/ancyloce/anvilkit-agent-service/internal/workflow/workflowtest"
)

func memoryInput(run string, generation uint64) workflow.RunInput {
	return workflow.RunInput{
		Key:         workflow.RunKey{RunID: run, Generation: generation},
		Scope:       workflow.Scope{WorkspaceID: "workspace.memory", ProjectID: "project.memory", ActorID: "actor.memory"},
		Traceparent: "00-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-bbbbbbbbbbbbbbbb-01",
	}
}

func TestMemoryEngineReplaysRecordedOutcome(t *testing.T) {
	ops := workflowtest.NewProbeOps()
	store := NewStore()
	engine := New(store, ops)
	defer engine.Stop(context.Background())
	input := memoryInput("run.memory-replay", 1)

	first, err := engine.ExecuteRun(context.Background(), input)
	if err != nil || first.Terminal != workflow.TerminalCompleted {
		t.Fatalf("outcome = %+v err = %v", first, err)
	}
	prepares := ops.CallCount("prepare")
	second, err := engine.ExecuteRun(context.Background(), input)
	if err != nil || second.Terminal != first.Terminal {
		t.Fatalf("replayed outcome = %+v err = %v", second, err)
	}
	if ops.CallCount("prepare") != prepares {
		t.Fatal("replay must not re-execute recorded operations")
	}
}

func TestMemoryEngineRestartHonorsRecordedAwaitDeadline(t *testing.T) {
	ops := workflowtest.NewProbeOps()
	ops.NeedInput = true
	ops.InputTimeout = 600 * time.Millisecond
	store := NewStore()
	engine := New(store, ops)
	input := memoryInput("run.memory-deadline", 1)
	started := time.Now()
	if err := engine.StartRun(context.Background(), input); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(5 * time.Second)
	for ops.CallCount("open-input-0000") == 0 && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	if err := engine.Stop(context.Background()); err != nil {
		t.Fatal(err)
	}
	// Restart mid-wait: the recorded deadline continues counting; the total
	// wait must stay near the original timeout instead of restarting it.
	engine = New(store, ops)
	defer engine.Stop(context.Background())
	outcome, err := engine.ExecuteRun(context.Background(), input)
	if err != nil {
		t.Fatal(err)
	}
	if outcome.Terminal != workflow.TerminalFailed || outcome.Problem == nil || outcome.Problem.Code != string(problem.CodeInputRequestExpired) {
		t.Fatalf("outcome = %+v", outcome)
	}
	if elapsed := time.Since(started); elapsed > 3*time.Second {
		t.Fatalf("recorded deadline was extended across restart: %s", elapsed)
	}
	if got := ops.CallCount("open-input-0000"); got != 1 {
		t.Fatalf("input opened %d times across restart, want 1", got)
	}
}

func TestMemoryEngineDeduplicatesSignalsByIdempotencyKey(t *testing.T) {
	ops := workflowtest.NewProbeOps()
	ops.NeedInput = true
	store := NewStore()
	engine := New(store, ops)
	defer engine.Stop(context.Background())
	input := memoryInput("run.memory-dedup", 1)
	if err := engine.StartRun(context.Background(), input); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(5 * time.Second)
	for ops.CallCount("open-input-0000") == 0 && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	ops.Accept(json.RawMessage(`{"answer":"once"}`))
	for range 3 {
		if err := engine.Signal(context.Background(), input.Key, workflow.InputTopic("request.probe"), json.RawMessage(`{}`), "same-key"); err != nil {
			t.Fatal(err)
		}
	}
	outcome, err := engine.ExecuteRun(context.Background(), input)
	if err != nil || outcome.Terminal != workflow.TerminalCompleted {
		t.Fatalf("outcome = %+v err = %v", outcome, err)
	}
}

func TestMemoryEngineCancellationDuringWait(t *testing.T) {
	ops := workflowtest.NewProbeOps()
	ops.NeedInput = true
	store := NewStore()
	engine := New(store, ops)
	defer engine.Stop(context.Background())
	input := memoryInput("run.memory-cancel", 1)
	if err := engine.StartRun(context.Background(), input); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(5 * time.Second)
	for ops.CallCount("open-input-0000") == 0 && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	if err := engine.CancelRun(context.Background(), input.Key); err != nil {
		t.Fatal(err)
	}
	outcome, err := engine.ExecuteRun(context.Background(), input)
	if err != nil || outcome.Terminal != workflow.TerminalCancelled {
		t.Fatalf("outcome = %+v err = %v", outcome, err)
	}
}
