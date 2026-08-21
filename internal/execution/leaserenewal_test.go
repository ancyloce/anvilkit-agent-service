package execution_test

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"sync"
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
	return renewalSchedulerUnder(t, ttl, systemClock{})
}

// renewalSchedulerUnder builds the dispatch scheduler under a caller-supplied
// clock, so a test that has to reason about lease expiry decides when time
// moves instead of racing the wall clock for it.
func renewalSchedulerUnder(t *testing.T, ttl time.Duration, clock scheduler.Clock) *scheduler.Service {
	t.Helper()
	effects := &scheduler.MemoryEffects{}
	dispatch, err := scheduler.New(execution.DispatchIDs{}, clock, scheduler.PrerequisiteFunc(func(context.Context, scheduler.Create) error { return nil }), ttl, effects, effects, effects, nil)
	if err != nil {
		t.Fatal(err)
	}
	return dispatch
}

func renewalExecutor(t *testing.T, dispatch execution.TaskScheduler, worker execution.ToolExecutor) *execution.ScheduledToolExecutor {
	t.Helper()
	return renewalExecutorUnder(t, dispatch, worker, systemClock{})
}

// renewalExecutorUnder builds the executor under the same clock its scheduler
// runs on: lease issue, renewal, completion, and fence acceptance must all read
// one authoritative time, or the fence would be decided by two disagreeing ones.
func renewalExecutorUnder(t *testing.T, dispatch execution.TaskScheduler, worker execution.ToolExecutor, clock execution.Clock) *execution.ScheduledToolExecutor {
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
	executor, err := execution.NewScheduledToolExecutor(dispatch, register, dispatchAuthority(), material, worker, usagePipeline, execution.NewMemoryToolReservations(), clock, "executor-renewal", "sha256:"+strings.Repeat("b", 64))
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

// steadyClock is the authoritative time a lease-fenced execution is judged
// against, moved only by the test. Nothing here reads the wall clock, so
// "the worker outlived its lease" is a fact the test states rather than a
// window it hopes the scheduler lands inside.
type steadyClock struct {
	lock  sync.Mutex
	value time.Time
}

func (c *steadyClock) Now() time.Time {
	c.lock.Lock()
	defer c.lock.Unlock()
	return c.value
}

// Set moves authoritative time to an exact instant.
func (c *steadyClock) Set(value time.Time) {
	c.lock.Lock()
	defer c.lock.Unlock()
	c.value = value
}

// gatedWorker starts, reports that it started, and runs until the test
// releases it or its context is cancelled. It is the deterministic counterpart
// of a long execution: its length is decided by the test, not by a timer.
type gatedWorker struct {
	started    chan struct{}
	release    chan struct{}
	executions atomic.Int64
	cancelled  atomic.Int64
}

func newGatedWorker() *gatedWorker {
	return &gatedWorker{started: make(chan struct{}, 1), release: make(chan struct{})}
}

func (w *gatedWorker) Execute(ctx context.Context, _ execution.ToolInvocation) (execution.ToolResult, error) {
	w.executions.Add(1)
	select {
	case w.started <- struct{}{}:
	default:
	}
	select {
	case <-ctx.Done():
		w.cancelled.Add(1)
		return execution.ToolResult{}, ctx.Err()
	case <-w.release:
	}
	return execution.ToolResult{Output: json.RawMessage(`{"echo":"slow"}`)}, nil
}

// renewalWatcher reports the expiry every accepted renewal produced, so a test
// can wait for the renewal it needs instead of sleeping for one.
type renewalWatcher struct {
	execution.TaskScheduler
	renewals chan time.Time
}

func (w *renewalWatcher) Heartbeat(ctx context.Context, scope scheduler.Scope, lease scheduler.Lease, expectedExpiry time.Time) (scheduler.Lease, error) {
	renewed, err := w.TaskScheduler.Heartbeat(ctx, scope, lease, expectedExpiry)
	if err == nil {
		select {
		case w.renewals <- renewed.ExpiresAt:
		default:
		}
	}
	return renewed, err
}

// A worker outliving its lease TTL survives because renewal extends the lease
// while it runs: the result is accepted through the full fence instead of
// being rejected as expired.
//
// Every instant that decides the outcome is set by the test. The worker starts
// under a lease issued at the base instant; time then moves inside the original
// window, so the next renewal genuinely extends the lease; and only once an
// extended lease has been observed does time move past the original expiry and
// the worker finish there. The acceptance therefore proves what it claims —
// the execution outlived the lease it started under and was accepted under the
// renewed one — with no dependence on how the machine scheduled anything.
func TestLeaseRenewalKeepsALongExecutionAcceptable(t *testing.T) {
	ttl := 90 * time.Millisecond
	base := time.Unix(1750000000, 0).UTC()
	clock := &steadyClock{value: base}
	dispatch := renewalSchedulerUnder(t, ttl, clock)
	watcher := &renewalWatcher{TaskScheduler: dispatch, renewals: make(chan time.Time, 64)}
	worker := newGatedWorker()
	executor := renewalExecutorUnder(t, watcher, worker, clock)

	type outcome struct {
		result execution.ToolResult
		err    error
	}
	finished := make(chan outcome, 1)
	go func() {
		result, err := executor.Execute(context.Background(), renewalInvocation("workflow-renewal:action-0001"))
		finished <- outcome{result: result, err: err}
	}()

	// The worker is running, so the lease it runs under exists.
	select {
	case <-worker.started:
	case <-time.After(30 * time.Second):
		t.Fatal("the worker never started under a lease")
	}
	issuedExpiry := base.Add(ttl)
	// Time moves inside the original window: still current, so renewal is
	// accepted, and far enough that the renewal it produces extends the lease.
	clock.Set(base.Add(2 * ttl / 3))
	var extended time.Time
	for extended.IsZero() {
		select {
		case renewed := <-watcher.renewals:
			if renewed.After(issuedExpiry) {
				extended = renewed
			}
		case <-time.After(30 * time.Second):
			t.Fatal("the lease was never renewed past the expiry it was issued with")
		}
	}
	// Past the expiry the lease was issued with, inside the renewed one: this
	// is the instant the execution completes at.
	completion := issuedExpiry.Add(ttl / 3)
	if !completion.Before(extended) {
		t.Fatalf("completion %s is not inside the renewed lease expiring %s", completion, extended)
	}
	clock.Set(completion)
	close(worker.release)

	var done outcome
	select {
	case done = <-finished:
	case <-time.After(30 * time.Second):
		t.Fatal("the execution never returned")
	}
	if done.err != nil {
		t.Fatal(done.err)
	}
	if string(done.result.Output) != `{"echo":"slow"}` {
		t.Fatalf("output = %s", done.result.Output)
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
//
// Liveness is stated rather than timed. Authoritative time does not move, so
// the winner's lease cannot expire while the loser tries for it, and the
// winner starting is what tells the test the lease is held — no polling for a
// state the scheduler might not have reached yet.
func TestALiveLeaseExcludesAConcurrentDispatch(t *testing.T) {
	base := time.Unix(1750000000, 0).UTC()
	clock := &steadyClock{value: base}
	dispatch := renewalSchedulerUnder(t, 2*time.Second, clock)
	first := newGatedWorker()
	winner := renewalExecutorUnder(t, dispatch, first, clock)
	invocation := renewalInvocation("workflow-renewal:action-0004")
	done := make(chan error, 1)
	go func() {
		_, err := winner.Execute(context.Background(), invocation)
		done <- err
	}()
	// The winner's worker is running, so the winner holds the live lease.
	select {
	case <-first.started:
	case <-time.After(30 * time.Second):
		t.Fatal("the winner never leased the task")
	}

	second := newGatedWorker()
	// The loser's worker would return immediately if it ever ran, so the
	// assertion below is about whether it ran at all, not about how long for.
	close(second.release)
	loser := renewalExecutorUnder(t, dispatch, second, clock)
	if _, err := loser.Execute(context.Background(), invocation); err == nil {
		t.Fatal("a second dispatch under a live lease must not run")
	}
	if second.executions.Load() != 0 {
		t.Fatalf("loser executions = %d, want the worker never executed under a live foreign lease", second.executions.Load())
	}

	close(first.release)
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(30 * time.Second):
		t.Fatal("the winning execution never returned")
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
