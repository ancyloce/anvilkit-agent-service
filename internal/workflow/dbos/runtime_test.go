package dbos

// The SQLite system database is a test affordance only: production runs on
// Postgres, and the SDK registers a driver solely for the packages that import
// it. Registering it here keeps the pure-Go SQLite engine — and the megabytes
// of C-translated runtime behind it — out of the release binary, which the
// approved resource budget measures.
import (
	sdk "github.com/dbos-inc/dbos-transact-golang/dbos"
	_ "github.com/dbos-inc/dbos-transact-golang/dbos/driver/sqlite"

	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
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
	engine  workflow.Operations
	runtime *Runtime
}

func newSqliteHarness(t *testing.T, ops *workflowtest.ProbeOps) *sqliteHarness {
	t.Helper()
	return newSqliteHarnessWith(t, ops, ops)
}

// newSqliteHarnessWith drives the engine through a wrapper around the probe
// while call counts are still read from the probe underneath it. A test that
// needs to interrupt one operation mid-flight wraps only that operation and
// leaves every other answer, and every count, exactly as it was.
func newSqliteHarnessWith(t *testing.T, ops *workflowtest.ProbeOps, engine workflow.Operations) *sqliteHarness {
	t.Helper()
	path := filepath.Join(t.TempDir(), "dbos.db")
	h := &sqliteHarness{t: t, path: path, ops: ops, engine: engine}
	h.runtime = h.start()
	t.Cleanup(func() { _ = h.runtime.Stop(context.Background()) })
	return h
}

func (h *sqliteHarness) start() *Runtime {
	h.t.Helper()
	runtime, err := New(context.Background(), Config{
		DatabaseURL:        "sqlite:" + h.path,
		ExecutorID:         "runtime-probe",
		ApplicationVersion: "runtime-probe",
		Logger:             slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError})),
	}, h.engine)
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

// waitForCheckpoint waits until the engine has durably recorded one step's
// outcome, which is a different fact from the step having run.
//
// The distinction is the whole point. A call counter is incremented by the
// operation itself, inside the step body, before the engine has written
// anything: a restart taken on that observation lands in the window where the
// effect has happened and the checkpoint has not, and recovery correctly
// re-executes the step because nothing on the record says it finished. Waiting
// on the counter and then asserting the step ran exactly once is therefore
// asserting something the engine never promised, and the assertion fails at
// whatever rate the machine happens to schedule that window.
//
// So the durable record is asked directly, through the engine's own step
// listing. Once the outcome is recorded, the durable wait this test is about
// genuinely exists, and exactly-once across a restart is a property the engine
// does guarantee.
func (h *sqliteHarness) waitForCheckpoint(key workflow.RunKey, step string) {
	h.t.Helper()
	deadline := time.Now().Add(20 * time.Second)
	for time.Now().Before(deadline) {
		if h.recordedSteps(key)[step] {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	h.t.Fatalf("step %s was never durably recorded", step)
}

// recordedSteps reports which of a workflow's steps the engine holds a
// completed outcome for.
func (h *sqliteHarness) recordedSteps(key workflow.RunKey) map[string]bool {
	h.t.Helper()
	steps, err := sdk.GetWorkflowSteps(h.runtime.engine, key.WorkflowID())
	if err != nil {
		return nil
	}
	recorded := make(map[string]bool, len(steps))
	for _, step := range steps {
		if !step.CompletedAt.IsZero() {
			recorded[step.StepName] = true
		}
	}
	return recorded
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
	// The restart is taken once the input request is durably recorded, not
	// once the operation that opens it has been entered. Those are different
	// moments, and only the later one establishes the durable wait whose
	// recovery this test is about.
	h.waitForCheckpoint(input.Key, "open-input-0000")

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
	if second.Key.WorkflowID() != "run.dbos-approval:g2" {
		t.Fatalf("workflow identity = %s", second.Key.WorkflowID())
	}
}

// Each Specialist turn is a separate DBOS step, so recovery resumes at the
// last completed Specialist turn instead of replaying the whole delegation.
func TestDbosDelegationCheckpointsEverySpecialistTurn(t *testing.T) {
	ops := workflowtest.NewProbeOps()
	ops.Delegate = true
	ops.DelegateTurns = 3
	h := newSqliteHarness(t, ops)
	input := probeInput("run.probe-delegation", 1)

	outcome, err := h.runtime.ExecuteRun(context.Background(), input)
	if err != nil || outcome.Terminal != workflow.TerminalCompleted {
		t.Fatalf("outcome = %+v err = %v", outcome, err)
	}
	if got := ops.CallCount("delegate-open-0000"); got != 1 {
		t.Fatalf("delegation opened %d times, want 1", got)
	}
	for delegateTurn := range 3 {
		step := fmt.Sprintf("delegate-turn-0000-%04d", delegateTurn)
		if got := ops.CallCount(step); got != 1 {
			t.Fatalf("%s executed %d times, want exactly one durable boundary", step, got)
		}
	}

	// A restarted engine replays the recorded delegation steps instead of
	// re-executing any Specialist turn.
	h.restart()
	replayed, err := h.runtime.ExecuteRun(context.Background(), input)
	if err != nil || replayed.Terminal != outcome.Terminal {
		t.Fatalf("replayed outcome = %+v err = %v", replayed, err)
	}
	for delegateTurn := range 3 {
		step := fmt.Sprintf("delegate-turn-0000-%04d", delegateTurn)
		if got := ops.CallCount(step); got != 1 {
			t.Fatalf("%s re-executed after restart: %d", step, got)
		}
	}
}

// interruptedOpenInput holds one execution of the input-opening operation
// after its effect has happened and before the engine has recorded it, and
// releases it when the engine context is cancelled. That is the shape of a
// process crash taken in the un-checkpointed window, produced deliberately
// rather than waited for.
type interruptedOpenInput struct {
	*workflowtest.ProbeOps
	entered chan struct{}
	held    atomic.Bool
	lock    sync.Mutex
	keys    []string
}

func (o *interruptedOpenInput) OpenInput(ctx context.Context, op workflow.OpID, input workflow.InterruptOpen) (workflow.InterruptOpened, error) {
	opened, err := o.ProbeOps.OpenInput(ctx, op, input)
	o.lock.Lock()
	o.keys = append(o.keys, op.Key())
	o.lock.Unlock()
	if o.held.CompareAndSwap(false, true) {
		o.entered <- struct{}{}
		<-ctx.Done()
	}
	return opened, err
}

func (o *interruptedOpenInput) operationKeys() []string {
	o.lock.Lock()
	defer o.lock.Unlock()
	return append([]string(nil), o.keys...)
}

// TestDBOSRestartInsideAnUnrecordedStepRepeatsItUnderOneDurableIdentity pins
// what recovery actually promises when a process dies inside a step whose
// outcome was never recorded.
//
// The engine cannot skip such a step: nothing on the record says it finished,
// so the successor runs it again. What makes that safe is not the engine but
// the identity the step runs under — every operation the pipeline exposes is
// keyed on its durable operation identity, and a repeat that arrives under
// the same key converges on the work already done instead of doing it twice.
// This proves the identity is stable across the restart, which is the property
// the whole at-least-once boundary rests on, and that the steps that were
// recorded before the crash are not repeated at all.
func TestDBOSRestartInsideAnUnrecordedStepRepeatsItUnderOneDurableIdentity(t *testing.T) {
	probe := workflowtest.NewProbeOps()
	probe.NeedInput = true
	ops := &interruptedOpenInput{ProbeOps: probe, entered: make(chan struct{}, 1)}
	h := newSqliteHarnessWith(t, probe, ops)
	input := probeInput("run.dbos-unrecorded", 1)

	if err := h.runtime.StartRun(context.Background(), input); err != nil {
		t.Fatal(err)
	}
	<-ops.entered
	if recorded := h.recordedSteps(input.Key); recorded["open-input-0000"] {
		t.Fatal("the interrupted step must not be recorded when the crash is taken")
	}
	h.restart()

	probe.Accept(json.RawMessage(`{"answer":"after an unrecorded step"}`))
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
	// The steps that were already recorded are replayed from the record.
	if got := probe.CallCount("prepare"); got != 1 {
		t.Fatalf("prepare executed %d times across the crash, want 1", got)
	}
	if got := probe.CallCount("turn-0000"); got != 1 {
		t.Fatalf("turn 0 executed %d times across the crash, want 1", got)
	}
	// The unrecorded one is run again, exactly once more, and under the same
	// durable identity the first execution carried.
	if got := probe.CallCount("open-input-0000"); got != 2 {
		t.Fatalf("the unrecorded step executed %d times, want the interrupted one and one successor", got)
	}
	keys := ops.operationKeys()
	if len(keys) != 2 || keys[0] != keys[1] {
		t.Fatalf("the successor executed under %v, which is not one durable operation identity", keys)
	}
}
