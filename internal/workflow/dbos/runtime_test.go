package dbos

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/ancyloce/anvilkit-agent-service/internal/problem"
	"github.com/ancyloce/anvilkit-agent-service/internal/workflow"
	"github.com/ancyloce/anvilkit-agent-service/internal/workflow/workflowtest"
)

type sqliteHarness struct {
	t       *testing.T
	path    string
	ops     *workflowtest.ProbeOps
	runtime *Runtime
}

func newSqliteHarness(t *testing.T, ops *workflowtest.ProbeOps) *sqliteHarness {
	t.Helper()
	path := filepath.Join(t.TempDir(), "dbos.db")
	h := &sqliteHarness{t: t, path: path, ops: ops}
	h.runtime = h.start()
	t.Cleanup(func() { _ = h.runtime.Stop(context.Background()) })
	return h
}

func (h *sqliteHarness) start() *Runtime {
	h.t.Helper()
	runtime, err := New(context.Background(), Config{
		DatabaseURL:        "sqlite:" + h.path,
		ExecutorID:         "wp2-probe",
		ApplicationVersion: "wp2-probe",
		Logger:             slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError})),
	}, h.ops)
	if err != nil {
		h.t.Fatal(err)
	}
	if err := runtime.Start(context.Background()); err != nil {
		h.t.Fatal(err)
	}
	return runtime
}

// restart shuts the engine down mid-flight and starts a fresh engine over
// the same durable system database, proving process-crash recovery.
func (h *sqliteHarness) restart() {
	h.t.Helper()
	if err := h.runtime.Stop(context.Background()); err != nil {
		h.t.Fatal(err)
	}
	h.runtime = h.start()
}

func probeInput(run string, generation uint64) workflow.RunInput {
	return workflow.RunInput{
		Key:         workflow.RunKey{RunID: run, Generation: generation},
		Scope:       workflow.Scope{WorkspaceID: "workspace.probe", ProjectID: "project.probe", ActorID: "actor.probe"},
		Traceparent: "00-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-bbbbbbbbbbbbbbbb-01",
	}
}

func (h *sqliteHarness) waitForCall(step string, want int) {
	h.t.Helper()
	deadline := time.Now().Add(20 * time.Second)
	for time.Now().Before(deadline) {
		if h.ops.CallCount(step) >= want {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	h.t.Fatalf("step %s never reached %d executions", step, want)
}

func TestDBOSAgentRunWorkflowCompletesAndReplays(t *testing.T) {
	ops := workflowtest.NewProbeOps()
	h := newSqliteHarness(t, ops)
	input := probeInput("run.dbos-complete", 1)

	outcome, err := h.runtime.ExecuteRun(context.Background(), input)
	if err != nil {
		t.Fatal(err)
	}
	if outcome.Terminal != workflow.TerminalCompleted {
		t.Fatalf("outcome = %+v", outcome)
	}
	prepares := ops.CallCount("prepare")
	turns := ops.CallCount("turn-0000")
	replayed, err := h.runtime.ExecuteRun(context.Background(), input)
	if err != nil {
		t.Fatal(err)
	}
	if replayed.Terminal != workflow.TerminalCompleted {
		t.Fatalf("replayed outcome = %+v", replayed)
	}
	if ops.CallCount("prepare") != prepares || ops.CallCount("turn-0000") != turns {
		t.Fatal("replay must not re-execute recorded operations")
	}
}

func TestDBOSRestartRecoversDurableInputWaitWithoutRepeatingEffects(t *testing.T) {
	ops := workflowtest.NewProbeOps()
	ops.NeedInput = true
	h := newSqliteHarness(t, ops)
	input := probeInput("run.dbos-restart", 1)

	if err := h.runtime.StartRun(context.Background(), input); err != nil {
		t.Fatal(err)
	}
	h.waitForCall("open-input-0000", 1)

	h.restart()

	ops.Accept(json.RawMessage(`{"answer":"after restart"}`))
	if err := h.runtime.Signal(context.Background(), input.Key, workflow.InputTopic("request.probe"), json.RawMessage(`{"requestVersion":1}`), "signal-1"); err != nil {
		t.Fatal(err)
	}
	outcome, err := h.runtime.ExecuteRun(context.Background(), input)
	if err != nil {
		t.Fatal(err)
	}
	if outcome.Terminal != workflow.TerminalCompleted {
		t.Fatalf("outcome = %+v", outcome)
	}
	if got := ops.CallCount("prepare"); got != 1 {
		t.Fatalf("prepare executed %d times across restart, want 1", got)
	}
	if got := ops.CallCount("turn-0000"); got != 1 {
		t.Fatalf("turn 0 executed %d times across restart, want 1", got)
	}
	if got := ops.CallCount("open-input-0000"); got != 1 {
		t.Fatalf("input opened %d times across restart, want 1", got)
	}
}

func TestDBOSDuplicateStartAndDuplicateSignalStayExactlyOnce(t *testing.T) {
	ops := workflowtest.NewProbeOps()
	ops.NeedInput = true
	h := newSqliteHarness(t, ops)
	input := probeInput("run.dbos-duplicate", 1)

	if err := h.runtime.StartRun(context.Background(), input); err != nil {
		t.Fatal(err)
	}
	if err := h.runtime.StartRun(context.Background(), input); err != nil {
		t.Fatalf("duplicate start must be idempotent: %v", err)
	}
	h.waitForCall("open-input-0000", 1)
	ops.Accept(json.RawMessage(`{"answer":"once"}`))
	for range 2 {
		if err := h.runtime.Signal(context.Background(), input.Key, workflow.InputTopic("request.probe"), json.RawMessage(`{"requestVersion":1}`), "same-idempotency-key"); err != nil {
			t.Fatal(err)
		}
	}
	outcome, err := h.runtime.ExecuteRun(context.Background(), input)
	if err != nil || outcome.Terminal != workflow.TerminalCompleted {
		t.Fatalf("outcome = %+v err = %v", outcome, err)
	}
	if got := ops.CallCount("prepare"); got != 1 {
		t.Fatalf("duplicate start executed prepare %d times", got)
	}
}

func TestDBOSCancellationDuringDurableWait(t *testing.T) {
	ops := workflowtest.NewProbeOps()
	ops.NeedInput = true
	h := newSqliteHarness(t, ops)
	input := probeInput("run.dbos-cancel", 1)

	if err := h.runtime.StartRun(context.Background(), input); err != nil {
		t.Fatal(err)
	}
	h.waitForCall("open-input-0000", 1)
	if err := h.runtime.CancelRun(context.Background(), input.Key); err != nil {
		t.Fatal(err)
	}
	outcome, err := h.runtime.ExecuteRun(context.Background(), input)
	if err != nil {
		t.Fatal(err)
	}
	if outcome.Terminal != workflow.TerminalCancelled {
		t.Fatalf("outcome = %+v", outcome)
	}
}

func TestDBOSInputExpiryUsesDurableDeadline(t *testing.T) {
	ops := workflowtest.NewProbeOps()
	ops.NeedInput = true
	ops.InputTimeout = 500 * time.Millisecond
	h := newSqliteHarness(t, ops)
	input := probeInput("run.dbos-expiry", 1)

	outcome, err := h.runtime.ExecuteRun(context.Background(), input)
	if err != nil {
		t.Fatal(err)
	}
	if outcome.Terminal != workflow.TerminalFailed || outcome.Problem == nil || outcome.Problem.Code != string(problem.CodeInputRequestExpired) {
		t.Fatalf("outcome = %+v", outcome)
	}
	if got := ops.CallCount("expire-input-00-0000"); got == 0 {
		t.Fatal("expiry must cross the durable expire boundary")
	}

	// A late response after the terminal outcome is inert.
	if err := h.runtime.Signal(context.Background(), input.Key, workflow.InputTopic("request.probe"), json.RawMessage(`{"requestVersion":1}`), "late-signal"); err != nil {
		t.Fatal(err)
	}
	prepares := ops.CallCount("prepare")
	replayed, err := h.runtime.ExecuteRun(context.Background(), input)
	if err != nil || replayed.Terminal != workflow.TerminalFailed {
		t.Fatalf("late signal changed the terminal outcome: %+v %v", replayed, err)
	}
	if ops.CallCount("prepare") != prepares {
		t.Fatal("late signal must not re-execute the workflow")
	}
}

func TestDBOSApprovalWaitAndExplicitRetryGeneration(t *testing.T) {
	ops := workflowtest.NewProbeOps()
	ops.Governed = true
	h := newSqliteHarness(t, ops)
	input := probeInput("run.dbos-approval", 1)

	if err := h.runtime.StartRun(context.Background(), input); err != nil {
		t.Fatal(err)
	}
	h.waitForCall("review-0000", 1)
	ops.Approve()
	if err := h.runtime.Signal(context.Background(), input.Key, workflow.ApprovalTopic("approval.probe"), json.RawMessage(`{"decision":"approve"}`), "approve-1"); err != nil {
		t.Fatal(err)
	}
	outcome, err := h.runtime.ExecuteRun(context.Background(), input)
	if err != nil || outcome.Terminal != workflow.TerminalCompleted {
		t.Fatalf("outcome = %+v err = %v", outcome, err)
	}
	if got := ops.CallCount("commit-0000"); got != 1 {
		t.Fatalf("commit executed %d times, want 1", got)
	}

	// An explicit-retry generation is a distinct durable workflow identity.
	second := probeInput("run.dbos-approval", 2)
	secondOutcome, err := h.runtime.ExecuteRun(context.Background(), second)
	if err != nil || secondOutcome.Terminal != workflow.TerminalCompleted {
		t.Fatalf("generation 2 outcome = %+v err = %v", secondOutcome, err)
	}
	if secondOutcome.Key.WorkflowID() == outcome.Key.WorkflowID() {
		t.Fatal("generations must not share workflow identity")
	}
	if fmt.Sprintf("%s", second.Key.WorkflowID()) != "run.dbos-approval:g2" {
		t.Fatalf("workflow identity = %s", second.Key.WorkflowID())
	}
}
