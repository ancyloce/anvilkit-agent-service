package dbos

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"log/slog"
	"os"
	"testing"
	"time"

	"github.com/ancyloce/anvilkit-agent-service/internal/workflow"
	"github.com/ancyloce/anvilkit-agent-service/internal/workflow/workflowtest"
)

// Integration proofs against a disposable Postgres DBOS system database.
// They skip unless DBOS_TEST_URL points at a disposable instance.

func integrationConfig(t *testing.T, schemaSuffix, executorID string) Config {
	t.Helper()
	databaseURL := os.Getenv("DBOS_TEST_URL")
	if databaseURL == "" {
		t.Skip("DBOS_TEST_URL is not set")
	}
	return Config{
		DatabaseURL:        databaseURL,
		Schema:             "agent_dbos_" + schemaSuffix,
		ExecutorID:         executorID,
		ApplicationVersion: "runtime-integration",
		Logger:             slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError})),
	}
}

func randomSuffix(t *testing.T) string {
	t.Helper()
	raw := make([]byte, 6)
	if _, err := rand.Read(raw); err != nil {
		t.Fatal(err)
	}
	return hex.EncodeToString(raw)
}

func TestDBOSPostgresRestartAndReplay(t *testing.T) {
	suffix := randomSuffix(t)
	ops := workflowtest.NewProbeOps()
	ops.NeedInput = true
	first, err := New(context.Background(), integrationConfig(t, suffix, "runtime-executor"), ops)
	if err != nil {
		t.Fatal(err)
	}
	if err := first.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	input := workflow.RunInput{
		Key:         workflow.RunKey{RunID: "run.pg-" + suffix, Generation: 1},
		Scope:       workflow.Scope{WorkspaceID: "workspace.pg", ProjectID: "project.pg", ActorID: "actor.pg"},
		Traceparent: "00-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-bbbbbbbbbbbbbbbb-01",
	}
	if err := first.StartRun(context.Background(), input); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(20 * time.Second)
	for ops.CallCount("open-input-0000") == 0 && time.Now().Before(deadline) {
		time.Sleep(20 * time.Millisecond)
	}
	if ops.CallCount("open-input-0000") != 1 {
		t.Fatal("durable input wait never opened")
	}
	if err := first.Stop(context.Background()); err != nil {
		t.Fatal(err)
	}

	second, err := New(context.Background(), integrationConfig(t, suffix, "runtime-executor"), ops)
	if err != nil {
		t.Fatal(err)
	}
	if err := second.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	defer stopRuntime(t, second)
	ops.Accept(json.RawMessage(`{"answer":"pg"}`))
	if err := second.Signal(context.Background(), input.Key, workflow.InputTopic("request.probe"), json.RawMessage(`{}`), "pg-signal"); err != nil {
		t.Fatal(err)
	}
	outcome, err := second.ExecuteRun(context.Background(), input)
	if err != nil || outcome.Terminal != workflow.TerminalCompleted {
		t.Fatalf("outcome = %+v err = %v", outcome, err)
	}
	if got := ops.CallCount("prepare"); got != 1 {
		t.Fatalf("prepare executed %d times across processes, want 1", got)
	}
	replayed, err := second.ExecuteRun(context.Background(), input)
	if err != nil || replayed.Terminal != workflow.TerminalCompleted {
		t.Fatalf("replay outcome = %+v err = %v", replayed, err)
	}
	if got := ops.CallCount("prepare"); got != 1 {
		t.Fatalf("replay re-executed prepare: %d", got)
	}
}

func TestDBOSPostgresMultiReplicaContentionStaysExactlyOnce(t *testing.T) {
	suffix := randomSuffix(t)
	ops := workflowtest.NewProbeOps()
	left, err := New(context.Background(), integrationConfig(t, suffix, "replica-left"), ops)
	if err != nil {
		t.Fatal(err)
	}
	if err := left.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	defer stopRuntime(t, left)
	right, err := New(context.Background(), integrationConfig(t, suffix, "replica-right"), ops)
	if err != nil {
		t.Fatal(err)
	}
	if err := right.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	defer stopRuntime(t, right)

	input := workflow.RunInput{
		Key:         workflow.RunKey{RunID: "run.replica-" + suffix, Generation: 1},
		Scope:       workflow.Scope{WorkspaceID: "workspace.pg", ProjectID: "project.pg", ActorID: "actor.pg"},
		Traceparent: "00-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-bbbbbbbbbbbbbbbb-01",
	}
	if err := left.StartRun(context.Background(), input); err != nil {
		t.Fatal(err)
	}
	if err := right.StartRun(context.Background(), input); err != nil {
		t.Fatal(err)
	}
	outcome, err := left.ExecuteRun(context.Background(), input)
	if err != nil || outcome.Terminal != workflow.TerminalCompleted {
		t.Fatalf("outcome = %+v err = %v", outcome, err)
	}
	if got := ops.CallCount("prepare"); got != 1 {
		t.Fatalf("contending replicas executed prepare %d times, want 1", got)
	}
	if got := ops.CallCount("turn-0000"); got != 1 {
		t.Fatalf("contending replicas executed turn %d times, want 1", got)
	}
}

// stopRuntime shuts a durable runtime down and fails the test if the
// shutdown itself reports an error. A drain that cannot complete is a
// reliability defect, so it is never discarded.
func stopRuntime(t *testing.T, runtime *Runtime) {
	t.Helper()
	if err := runtime.Stop(context.Background()); err != nil {
		t.Errorf("stop runtime: %v", err)
	}
}
