// Package memory provides the deterministic in-memory implementation of the
// workflow port. It is a proof seam and test runtime, never production authority.
package memory

import (
	"context"
	"encoding/json"
	"fmt"
	"sync"
	"time"

	"github.com/ancyloce/anvilkit-agent-service/internal/problem"
	"github.com/ancyloce/anvilkit-agent-service/internal/workflow"
)

type stored struct {
	result    workflow.Result
	completed map[string]workflow.StepResult
	executing bool
	waiters   map[string]chan json.RawMessage
	cancelled bool
}

type Store struct {
	lock      sync.Mutex
	workflows map[workflow.ID]*stored
}

func NewStore() *Store { return &Store{workflows: make(map[workflow.ID]*stored)} }

type Runtime struct {
	store    *Store
	executor workflow.Executor
}

func New(store *Store, executor workflow.Executor) *Runtime {
	return &Runtime{store: store, executor: executor}
}
func (r *Runtime) Start(context.Context) error { return nil }
func (r *Runtime) Stop(context.Context) error  { return nil }

func (r *Runtime) StartWait(_ context.Context, request workflow.Request) error {
	if err := workflow.Validate(request); err != nil {
		return err
	}
	if len(request.Steps) != 1 || request.Steps[0].Kind != workflow.StepWait {
		return fmt.Errorf("start wait requires exactly one durable wait step")
	}
	go func() { _, _ = r.Execute(context.Background(), request) }()
	return nil
}

func (r *Runtime) Execute(ctx context.Context, request workflow.Request) (workflow.Result, error) {
	if err := workflow.Validate(request); err != nil {
		return workflow.Result{}, err
	}
	if err := r.claim(ctx, request.WorkflowID); err != nil {
		return workflow.Result{}, err
	}
	defer r.release(request.WorkflowID)
	result := workflow.Result{WorkflowID: request.WorkflowID}
	for _, step := range request.Steps {
		if existing, ok := r.completed(request.WorkflowID, step.Name); ok {
			result.Steps = append(result.Steps, existing)
			continue
		}
		if r.cancelled(request.WorkflowID) {
			return workflow.Result{}, context.Canceled
		}
		stepResult := workflow.StepResult{Name: step.Name}
		var output json.RawMessage
		var err error
		switch step.Kind {
		case workflow.StepAction:
			output, err = r.executor.Execute(ctx, request.WorkflowID, step)
		case workflow.StepSleep:
			timer := time.NewTimer(step.Duration)
			select {
			case <-ctx.Done():
				if !timer.Stop() {
					<-timer.C
				}
				err = ctx.Err()
			case <-timer.C:
			}
		case workflow.StepWait:
			output, err = r.wait(ctx, request.WorkflowID, step.Topic, step.Duration)
		}
		if err != nil {
			details := problem.Internal("")
			details.Detail = "durable step failed"
			if err == context.Canceled {
				details.Code = "WORKFLOW_CANCELLED"
				details.Title = "Workflow cancelled"
			}
			stepResult.Problem = &details
		} else {
			stepResult.Output = output
		}
		r.record(request.WorkflowID, stepResult)
		result.Steps = append(result.Steps, stepResult)
		if stepResult.Problem != nil {
			break
		}
	}
	r.finish(request.WorkflowID, result)
	return result, nil
}

func (r *Runtime) Signal(_ context.Context, id workflow.ID, topic string, payload json.RawMessage, _ string) error {
	r.store.lock.Lock()
	defer r.store.lock.Unlock()
	entry := r.ensure(id)
	channel, exists := entry.waiters[topic]
	if !exists {
		channel = make(chan json.RawMessage, 1)
		entry.waiters[topic] = channel
	}
	select {
	case channel <- append(json.RawMessage(nil), payload...):
		return nil
	default:
		return nil
	}
}

func (r *Runtime) Cancel(_ context.Context, id workflow.ID) error {
	r.store.lock.Lock()
	defer r.store.lock.Unlock()
	r.ensure(id).cancelled = true
	return nil
}

func (r *Runtime) claim(ctx context.Context, id workflow.ID) error {
	for {
		r.store.lock.Lock()
		entry := r.ensure(id)
		if !entry.executing {
			entry.executing = true
			r.store.lock.Unlock()
			return nil
		}
		r.store.lock.Unlock()
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(time.Millisecond):
		}
	}
}
func (r *Runtime) release(id workflow.ID) {
	r.store.lock.Lock()
	defer r.store.lock.Unlock()
	r.ensure(id).executing = false
}
func (r *Runtime) completed(id workflow.ID, step string) (workflow.StepResult, bool) {
	r.store.lock.Lock()
	defer r.store.lock.Unlock()
	value, ok := r.ensure(id).completed[step]
	return value, ok
}
func (r *Runtime) record(id workflow.ID, result workflow.StepResult) {
	r.store.lock.Lock()
	defer r.store.lock.Unlock()
	r.ensure(id).completed[result.Name] = result
}
func (r *Runtime) finish(id workflow.ID, result workflow.Result) {
	r.store.lock.Lock()
	defer r.store.lock.Unlock()
	r.ensure(id).result = result
}
func (r *Runtime) cancelled(id workflow.ID) bool {
	r.store.lock.Lock()
	defer r.store.lock.Unlock()
	return r.ensure(id).cancelled
}
func (r *Runtime) ensure(id workflow.ID) *stored {
	entry := r.store.workflows[id]
	if entry == nil {
		entry = &stored{completed: make(map[string]workflow.StepResult), waiters: make(map[string]chan json.RawMessage)}
		r.store.workflows[id] = entry
	}
	return entry
}
func (r *Runtime) wait(ctx context.Context, id workflow.ID, topic string, timeout time.Duration) (json.RawMessage, error) {
	r.store.lock.Lock()
	entry := r.ensure(id)
	channel := entry.waiters[topic]
	if channel == nil {
		channel = make(chan json.RawMessage, 1)
		entry.waiters[topic] = channel
	}
	r.store.lock.Unlock()
	timer := time.NewTimer(timeout)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-timer.C:
		return nil, fmt.Errorf("wait %s timed out", topic)
	case payload := <-channel:
		return payload, nil
	}
}

var _ workflow.Runtime = (*Runtime)(nil)
