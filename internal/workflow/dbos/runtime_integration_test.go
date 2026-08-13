package dbos

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"log/slog"
	"os"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ancyloce/anvilkit-agent-service/internal/workflow"
)

type proofExecutor struct{ counts sync.Map }

func (e *proofExecutor) Execute(_ context.Context, _ workflow.ID, step workflow.Step) (json.RawMessage, error) {
	value, _ := e.counts.LoadOrStore(step.Name, &atomic.Int64{})
	value.(*atomic.Int64).Add(1)
	return json.RawMessage(`{"accepted":true}`), nil
}

func TestDBOSAdapterDurableStepsWaitAndCancellation(t *testing.T) {
	databaseURL := os.Getenv("DBOS_TEST_URL")
	if databaseURL == "" {
		t.Skip("DBOS_TEST_URL is not set")
	}
	random := make([]byte, 6)
	if _, err := rand.Read(random); err != nil {
		t.Fatal(err)
	}
	suffix := hex.EncodeToString(random)
	executor := &proofExecutor{}
	runtime, err := New(context.Background(), Config{DatabaseURL: databaseURL, Schema: "agent_dbos_" + suffix, ExecutorID: "executor-" + suffix, ApplicationVersion: "m1-proof", Logger: slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))}, executor)
	if err != nil {
		t.Fatal(err)
	}
	if err := runtime.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	defer runtime.Stop(context.Background())
	request := workflow.Request{WorkflowID: workflow.ID("steps-" + suffix), Version: 1, Scope: workflow.Scope{WorkspaceID: "w", ProjectID: "p"}, Steps: []workflow.Step{{Name: "one", Kind: workflow.StepAction}, {Name: "two", Kind: workflow.StepAction}}}
	first, err := runtime.Execute(context.Background(), request)
	if err != nil || len(first.Steps) != 2 {
		t.Fatalf("first run %#v %v", first, err)
	}
	second, err := runtime.Execute(context.Background(), request)
	if err != nil || len(second.Steps) != 2 {
		t.Fatalf("replay %#v %v", second, err)
	}
	for _, step := range request.Steps {
		value, _ := executor.counts.Load(step.Name)
		if count := value.(*atomic.Int64).Load(); count != 1 {
			t.Fatalf("step %s executed %d times", step.Name, count)
		}
	}

	waitRequest := workflow.Request{WorkflowID: workflow.ID("wait-" + suffix), Version: 1, Scope: request.Scope, Steps: []workflow.Step{{Name: "wait", Kind: workflow.StepWait, Topic: "resume", Duration: 5 * time.Second}}}
	done := make(chan error, 1)
	go func() {
		result, executeErr := runtime.Execute(context.Background(), waitRequest)
		if executeErr == nil && (len(result.Steps) != 1 || string(result.Steps[0].Output) != `{"resume":true}`) {
			executeErr = context.Canceled
		}
		done <- executeErr
	}()
	time.Sleep(100 * time.Millisecond)
	if err := runtime.Signal(context.Background(), waitRequest.WorkflowID, "resume", json.RawMessage(`{"resume":true}`), "resume-1"); err != nil {
		t.Fatal(err)
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	detachedWait := workflow.Request{WorkflowID: workflow.ID("detached-wait-" + suffix), Version: 1, Scope: request.Scope, Steps: []workflow.Step{{Name: "wait", Kind: workflow.StepWait, Topic: "resume", Duration: 5 * time.Second}}}
	if err := runtime.StartWait(context.Background(), detachedWait); err != nil {
		t.Fatal(err)
	}
	time.Sleep(100 * time.Millisecond)
	if err := runtime.Signal(context.Background(), detachedWait.WorkflowID, "resume", json.RawMessage(`{"detached":true}`), "detached-1"); err != nil {
		t.Fatal(err)
	}
	detached, err := runtime.Execute(context.Background(), detachedWait)
	if err != nil || len(detached.Steps) != 1 || string(detached.Steps[0].Output) != `{"detached":true}` {
		t.Fatalf("detached wait=%#v err=%v", detached, err)
	}

	cancelRequest := workflow.Request{WorkflowID: workflow.ID("cancel-" + suffix), Version: 1, Scope: request.Scope, Steps: []workflow.Step{{Name: "sleep", Kind: workflow.StepSleep, Duration: 500 * time.Millisecond}}}
	cancelled := make(chan error, 1)
	go func() { _, executeErr := runtime.Execute(context.Background(), cancelRequest); cancelled <- executeErr }()
	time.Sleep(100 * time.Millisecond)
	if err := runtime.Cancel(context.Background(), cancelRequest.WorkflowID); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-cancelled:
		if err == nil {
			t.Fatal("cancelled workflow returned success")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("cancellation was not observed")
	}
}

func TestDBOSAdapterTwoExecutorsConvergeOnOneCheckpoint(t *testing.T) {
	databaseURL := os.Getenv("DBOS_TEST_URL")
	if databaseURL == "" {
		t.Skip("DBOS_TEST_URL is not set")
	}
	random := make([]byte, 6)
	if _, err := rand.Read(random); err != nil {
		t.Fatal(err)
	}
	suffix := hex.EncodeToString(random)
	executor := &proofExecutor{}
	newRuntime := func(executorID string) *Runtime {
		runtime, err := New(context.Background(), Config{DatabaseURL: databaseURL, Schema: "agent_dbos_replica_" + suffix, ExecutorID: executorID, ApplicationVersion: "m1-replica-proof", Logger: slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))}, executor)
		if err != nil {
			t.Fatal(err)
		}
		if err := runtime.Start(context.Background()); err != nil {
			t.Fatal(err)
		}
		return runtime
	}
	first := newRuntime("first-" + suffix)
	defer first.Stop(context.Background())
	second := newRuntime("second-" + suffix)
	defer second.Stop(context.Background())
	request := workflow.Request{WorkflowID: workflow.ID("replica-" + suffix), Version: 1, Scope: workflow.Scope{WorkspaceID: "w", ProjectID: "p"}, Steps: []workflow.Step{{Name: "effect", Kind: workflow.StepAction}}}
	var wait sync.WaitGroup
	failures := make(chan error, 2)
	for _, runtime := range []*Runtime{first, second} {
		wait.Add(1)
		go func() { defer wait.Done(); _, err := runtime.Execute(context.Background(), request); failures <- err }()
	}
	wait.Wait()
	close(failures)
	for err := range failures {
		if err != nil {
			t.Fatal(err)
		}
	}
	value, _ := executor.counts.Load("effect")
	if count := value.(*atomic.Int64).Load(); count != 1 {
		t.Fatalf("two executors ran effect %d times", count)
	}
}
