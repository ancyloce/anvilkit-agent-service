package execution_test

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ancyloce/anvilkit-agent-service/internal/execution"
	"github.com/ancyloce/anvilkit-agent-service/internal/problem"
	"github.com/ancyloce/anvilkit-agent-service/internal/recovery"
	"github.com/ancyloce/anvilkit-agent-service/internal/scheduler"
	"github.com/ancyloce/anvilkit-agent-service/internal/tools"
	"github.com/ancyloce/anvilkit-agent-service/internal/usage"
)

// blockingWorker executes for a fixed duration, or until its context is
// cancelled when honorCancel is set. It records how it finished.
type blockingWorker struct {
	duration    time.Duration
	honorCancel bool
	executions  atomic.Int64
	cancelled   atomic.Int64
}

func (w *blockingWorker) Execute(ctx context.Context, _ execution.ToolInvocation) (execution.ToolResult, error) {
	w.executions.Add(1)
	timer := time.NewTimer(w.duration)
	defer timer.Stop()
	if w.honorCancel {
		select {
		case <-ctx.Done():
			w.cancelled.Add(1)
			return execution.ToolResult{}, ctx.Err()
		case <-timer.C:
		}
	} else {
		<-timer.C
	}
	return execution.ToolResult{Output: json.RawMessage(`{"echo":"slow"}`)}, nil
}

// heartbeatDenier fails every lease renewal, which is what a reclaimed or
// superseded lease looks like to the executing process.
type heartbeatDenier struct {
	execution.TaskScheduler
	denials atomic.Int64
}

func (d *heartbeatDenier) Heartbeat(context.Context, scheduler.Scope, scheduler.Lease, time.Time) (scheduler.Lease, error) {
	d.denials.Add(1)
	return scheduler.Lease{}, problem.New(problem.CodeWorkerFenceStale, "")
}

func renewalScheduler(t *testing.T, ttl time.Duration) *scheduler.Service {
	t.Helper()
	effects := &scheduler.MemoryEffects{}
	dispatch, err := scheduler.New(execution.DispatchIDs{}, systemClock{}, scheduler.PrerequisiteFunc(func(context.Context, scheduler.Create) error { return nil }), ttl, effects, effects, effects, nil)
	if err != nil {
		t.Fatal(err)
	}
	return dispatch
}

func renewalExecutor(t *testing.T, dispatch execution.TaskScheduler, worker execution.ToolExecutor) *execution.ScheduledToolExecutor {
	t.Helper()
	register, err := recovery.NewMemoryRegister(1)
	if err != nil {
		t.Fatal(err)
	}
	usagePipeline, err := usage.New(usage.NewMemoryStore(), execution.NewControlledUsageSink())
	if err != nil {
		t.Fatal(err)
	}
	material := staticToolMaterial{definition: tools.Definition{
		Kind:       "ToolDefinition",
		ToolID:     "anvilkit.tool.context-echo",
		Capability: "fake.execute",
		InputSchema: tools.SchemaReference{
			ComponentName: "anvilkit.tool.context-echo.arguments",
			Digest:        "sha256:" + strings.Repeat("a", 64),
		},
	}}
	executor, err := execution.NewScheduledToolExecutor(dispatch, register, dispatchAuthority(), material, worker, usagePipeline, execution.NewMemoryToolReservations(), systemClock{}, "executor-renewal", "sha256:"+strings.Repeat("b", 64))
	if err != nil {
		t.Fatal(err)
	}
	return executor
}

func renewalInvocation(key string) execution.ToolInvocation {
	return execution.ToolInvocation{
		IdempotencyKey:      key,
		ToolID:              "anvilkit.tool.context-echo",
		Arguments:           json.RawMessage(`{"query":"context"}`),
		WorkspaceID:         "workspace-01",
		ProjectID:           "project-01",
		RunID:               "run-01",
		RootRunID:           "run-01",
		ActorID:             "actor-01",
		ExecutionGeneration: 1,
		Traceparent:         traceparent,
	}
}

// A worker outliving its lease TTL survives because renewal extends the lease
// while it runs: the result is accepted through the full fence instead of
// being rejected as expired.
func TestLeaseRenewalKeepsALongExecutionAcceptable(t *testing.T) {
	ttl := 150 * time.Millisecond
	dispatch := renewalScheduler(t, ttl)
	worker := &blockingWorker{duration: 3 * ttl, honorCancel: true}
	executor := renewalExecutor(t, dispatch, worker)
	result, err := executor.Execute(context.Background(), renewalInvocation("workflow-renewal:action-0001"))
	if err != nil {
		t.Fatal(err)
	}
	if string(result.Output) != `{"echo":"slow"}` {
		t.Fatalf("output = %s", result.Output)
	}
	if worker.executions.Load() != 1 || worker.cancelled.Load() != 0 {
		t.Fatalf("executions=%d cancelled=%d, want one uncancelled execution", worker.executions.Load(), worker.cancelled.Load())
	}
}

// A renewal failure means the lease was reclaimed or superseded: the worker
// context is cancelled promptly, the attempt's usage still lands, and the
// stop is a typed retryable stale fence — never an accepted result.
func TestRenewalFailureCancelsTheWorkerAndFencesTheAttempt(t *testing.T) {
	ttl := 120 * time.Millisecond
	inner := renewalScheduler(t, ttl)
	denier := &heartbeatDenier{TaskScheduler: inner}
	worker := &blockingWorker{duration: time.Minute, honorCancel: true}
	executor := renewalExecutor(t, denier, worker)
	started := time.Now()
	_, err := executor.Execute(context.Background(), renewalInvocation("workflow-renewal:action-0002"))
	var details problem.Details
	if !errors.As(err, &details) || details.Code != string(problem.CodeWorkerFenceStale) || details.Retryability != "safe-after-backoff" {
		t.Fatalf("error = %v, want a typed retryable stale fence", err)
	}
	if elapsed := time.Since(started); elapsed > 30*time.Second {
		t.Fatalf("lease loss took %s to cancel the worker", elapsed)
	}
	if worker.cancelled.Load() != 1 {
		t.Fatalf("cancelled = %d, want the worker cancelled on lease loss", worker.cancelled.Load())
	}
	if denier.denials.Load() < 1 {
		t.Fatal("the renewal path never ran")
	}
	task, err := inner.Get(context.Background(), scheduler.Scope{WorkspaceID: "workspace-01", ProjectID: "project-01"}, taskIdentity("workflow-renewal:action-0002"))
	if err != nil {
		t.Fatal(err)
	}
	if task.State == scheduler.Completed {
		t.Fatal("a lease-lost attempt must never complete the task")
	}
}

// A worker that ignores cancellation and produces a late result after its
// lease was lost changes nothing: the result is fenced out, the task stays
// incomplete, and the stop is typed and retryable.
func TestLateResultAfterLeaseLossIsFencedOut(t *testing.T) {
	ttl := 120 * time.Millisecond
	inner := renewalScheduler(t, ttl)
	denier := &heartbeatDenier{TaskScheduler: inner}
	// The worker ignores its context and finishes with output anyway.
	worker := &blockingWorker{duration: 2 * ttl, honorCancel: false}
	executor := renewalExecutor(t, denier, worker)
	_, err := executor.Execute(context.Background(), renewalInvocation("workflow-renewal:action-0003"))
	var details problem.Details
	if !errors.As(err, &details) || details.Code != string(problem.CodeWorkerFenceStale) {
		t.Fatalf("error = %v, want the late result fenced out", err)
	}
	task, err := inner.Get(context.Background(), scheduler.Scope{WorkspaceID: "workspace-01", ProjectID: "project-01"}, taskIdentity("workflow-renewal:action-0003"))
	if err != nil {
		t.Fatal(err)
	}
	if task.State == scheduler.Completed || task.Result != nil {
		t.Fatalf("task = %+v, want no accepted result from a lease-lost attempt", task)
	}
}

// Two executors racing one live lease never execute concurrently under it: a
// live lease is exclusive, and the loser's dispatch fails with a typed
// conflict instead of a second execution.
func TestALiveLeaseExcludesAConcurrentDispatch(t *testing.T) {
	ttl := 2 * time.Second
	dispatch := renewalScheduler(t, ttl)
	first := &blockingWorker{duration: 500 * time.Millisecond, honorCancel: true}
	winner := renewalExecutor(t, dispatch, first)
	invocation := renewalInvocation("workflow-renewal:action-0004")
	done := make(chan error, 1)
	go func() {
		_, err := winner.Execute(context.Background(), invocation)
		done <- err
	}()
	// Wait until the winner holds the live lease.
	scope := scheduler.Scope{WorkspaceID: "workspace-01", ProjectID: "project-01"}
	deadline := time.Now().Add(5 * time.Second)
	for {
		task, err := dispatch.Get(context.Background(), scope, taskIdentity("workflow-renewal:action-0004"))
		if err == nil && task.State == scheduler.Leased {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("the winner never leased the task")
		}
		time.Sleep(5 * time.Millisecond)
	}
	second := &blockingWorker{duration: time.Millisecond, honorCancel: true}
	loser := renewalExecutor(t, dispatch, second)
	if _, err := loser.Execute(context.Background(), invocation); err == nil {
		t.Fatal("a second dispatch under a live lease must not run")
	}
	if second.executions.Load() != 0 {
		t.Fatalf("loser executions = %d, want the worker never executed under a live foreign lease", second.executions.Load())
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	// The loser converges afterwards on the winner's recorded output without
	// executing its own worker.
	replayed, err := loser.Execute(context.Background(), invocation)
	if err != nil {
		t.Fatal(err)
	}
	if string(replayed.Output) != `{"echo":"slow"}` || second.executions.Load() != 0 {
		t.Fatalf("replayed = %s executions=%d, want the winner's recorded output", replayed.Output, second.executions.Load())
	}
}

// taskIdentity mirrors the executor's deterministic task derivation.
func taskIdentity(idempotencyKey string) scheduler.TaskID {
	return execution.TaskIdentity(idempotencyKey)
}
