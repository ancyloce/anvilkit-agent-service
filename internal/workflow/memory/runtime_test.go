package memory

import (
	"context"
	"encoding/json"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ancyloce/anvilkit-agent-service/internal/workflow"
)

type countingExecutor struct{ counts *sync.Map }

func (e countingExecutor) Execute(_ context.Context, _ workflow.ID, step workflow.Step) (json.RawMessage, error) {
	value, _ := e.counts.LoadOrStore(step.Name, &atomic.Int64{})
	value.(*atomic.Int64).Add(1)
	return json.RawMessage(`{"ok":true}`), nil
}

func TestRestartAtEveryDurableStepDoesNotRepeatEffects(t *testing.T) {
	request := workflow.Request{WorkflowID: "restart", Version: 1, Scope: workflow.Scope{WorkspaceID: "w", ProjectID: "p"}, Steps: []workflow.Step{{Name: "one", Kind: workflow.StepAction}, {Name: "two", Kind: workflow.StepAction}, {Name: "three", Kind: workflow.StepAction}}}
	store := NewStore()
	counts := &sync.Map{}
	for range request.Steps {
		runtime := New(store, countingExecutor{counts: counts})
		if _, err := runtime.Execute(context.Background(), request); err != nil {
			t.Fatal(err)
		}
	}
	for _, step := range request.Steps {
		value, _ := counts.Load(step.Name)
		if got := value.(*atomic.Int64).Load(); got != 1 {
			t.Fatalf("step %s executed %d times", step.Name, got)
		}
	}
}

func TestTwoReplicasNeverExecuteSameStepConcurrently(t *testing.T) {
	store := NewStore()
	counts := &sync.Map{}
	request := workflow.Request{WorkflowID: "failover", Version: 1, Scope: workflow.Scope{WorkspaceID: "w", ProjectID: "p"}, Steps: []workflow.Step{{Name: "effect", Kind: workflow.StepAction}}}
	runtimes := []*Runtime{New(store, countingExecutor{counts: counts}), New(store, countingExecutor{counts: counts})}
	var wait sync.WaitGroup
	for _, runtime := range runtimes {
		wait.Add(1)
		go func() {
			defer wait.Done()
			if _, err := runtime.Execute(context.Background(), request); err != nil {
				t.Error(err)
			}
		}()
	}
	wait.Wait()
	value, _ := counts.Load("effect")
	if got := value.(*atomic.Int64).Load(); got != 1 {
		t.Fatalf("effect executed %d times", got)
	}
}

func TestDurableWaitSurvivesRuntimeReplacement(t *testing.T) {
	store := NewStore()
	runtime := New(store, countingExecutor{counts: &sync.Map{}})
	request := workflow.Request{WorkflowID: "wait", Version: 1, Scope: workflow.Scope{WorkspaceID: "w", ProjectID: "p"}, Steps: []workflow.Step{{Name: "input", Kind: workflow.StepWait, Topic: "resume", Duration: time.Second}}}
	done := make(chan workflow.Result, 1)
	go func() { result, _ := runtime.Execute(context.Background(), request); done <- result }()
	time.Sleep(10 * time.Millisecond)
	replacement := New(store, countingExecutor{counts: &sync.Map{}})
	if err := replacement.Signal(context.Background(), "wait", "resume", json.RawMessage(`{"accepted":true}`), "signal-1"); err != nil {
		t.Fatal(err)
	}
	select {
	case result := <-done:
		if len(result.Steps) != 1 || result.Steps[0].Problem != nil {
			t.Fatalf("unexpected result %#v", result)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("wait did not resume")
	}
}

func TestDetachedWaitSurvivesRuntimeReplacement(t *testing.T) {
	store := NewStore()
	request := workflow.Request{WorkflowID: "detached", Version: 1, Scope: workflow.Scope{WorkspaceID: "w", ProjectID: "p"}, Steps: []workflow.Step{{Name: "input", Kind: workflow.StepWait, Topic: "resume", Duration: time.Second}}}
	first := New(store, countingExecutor{counts: &sync.Map{}})
	if err := first.StartWait(context.Background(), request); err != nil {
		t.Fatal(err)
	}
	replacement := New(store, countingExecutor{counts: &sync.Map{}})
	if err := replacement.Signal(context.Background(), request.WorkflowID, "resume", json.RawMessage(`{"accepted":true}`), "signal"); err != nil {
		t.Fatal(err)
	}
	result, err := replacement.Execute(context.Background(), request)
	if err != nil || len(result.Steps) != 1 || string(result.Steps[0].Output) != `{"accepted":true}` {
		t.Fatalf("result=%#v err=%v", result, err)
	}
}

func TestCrossStepStateIsContractSerializable(t *testing.T) {
	request := workflow.Request{WorkflowID: "schema", Version: 1, Scope: workflow.Scope{WorkspaceID: "w", ProjectID: "p"}, Steps: []workflow.Step{{Name: "effect", Kind: workflow.StepAction}}}
	result, err := New(NewStore(), countingExecutor{counts: &sync.Map{}}).Execute(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	bytes, err := json.Marshal(result)
	if err != nil {
		t.Fatal(err)
	}
	var decoded workflow.Result
	if err := json.Unmarshal(bytes, &decoded); err != nil {
		t.Fatal(err)
	}
}
