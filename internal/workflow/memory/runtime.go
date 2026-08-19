// Package memory provides the controlled in-memory engine behind the same
// durable runtime port as the DBOS adapter. It mirrors durable semantics —
// recorded step outcomes, consumed-once signals, recorded await deadlines,
// cancellation, and replay — so workflow behavior can be proven
// deterministically without external infrastructure. It is a proof seam and
// test runtime, never production authority.
package memory

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/ancyloce/anvilkit-agent-service/internal/workflow"
)

// stoppedError reports that the engine aborted an execution without
// recording an outcome — the in-memory equivalent of a process crash.
type stoppedError struct{}

func (stoppedError) Error() string { return "memory engine stopped" }

type cancelledError struct{}

func (cancelledError) Error() string { return "memory workflow cancelled" }

type stepRecord struct {
	output []byte
	failed bool
	reason string
}

type awaitRecord struct {
	deadline time.Time
	done     bool
	timedOut bool
	payload  []byte
}

type instance struct {
	input     workflow.RunInput
	steps     map[string]stepRecord
	awaits    map[int]*awaitRecord
	signals   map[string][][]byte
	seenKeys  map[string]bool
	outcome   *workflow.RunOutcome
	failure   error
	cancelled bool
	running   bool
}

// Store is the durable state shared by every Runtime instance — the
// in-memory equivalent of the system database. Creating a new Runtime on
// the same Store models a process restart.
type Store struct {
	lock      sync.Mutex
	workflows map[string]*instance
	notify    chan struct{}
}

func NewStore() *Store {
	return &Store{workflows: make(map[string]*instance), notify: make(chan struct{})}
}

func (s *Store) broadcast() {
	close(s.notify)
	s.notify = make(chan struct{})
}

func (s *Store) instance(input workflow.RunInput) *instance {
	id := input.Key.WorkflowID()
	entry := s.workflows[id]
	if entry == nil {
		entry = &instance{input: input, steps: make(map[string]stepRecord), awaits: make(map[int]*awaitRecord), signals: make(map[string][][]byte), seenKeys: make(map[string]bool)}
		s.workflows[id] = entry
	}
	return entry
}

func (s *Store) lookup(id string) *instance { return s.workflows[id] }

// Runtime drives workflows against a Store. Stop aborts in-flight
// executions without recording outcomes, modeling a crash; a new Runtime on
// the same Store recovers them.
type Runtime struct {
	store   *Store
	ops     workflow.Operations
	clock   func() time.Time
	stopped chan struct{}
	stop    sync.Once
	wg      sync.WaitGroup
}

func New(store *Store, ops workflow.Operations) *Runtime {
	return &Runtime{store: store, ops: ops, clock: time.Now, stopped: make(chan struct{})}
}

func (r *Runtime) Start(context.Context) error { return nil }

func (r *Runtime) Stop(context.Context) error {
	r.stop.Do(func() { close(r.stopped) })
	r.wg.Wait()
	return nil
}

func (r *Runtime) StartRun(_ context.Context, input workflow.RunInput) error {
	if err := input.Validate(); err != nil {
		return err
	}
	r.store.lock.Lock()
	entry := r.store.instance(input)
	if entry.outcome != nil || entry.failure != nil || entry.running {
		r.store.lock.Unlock()
		return nil
	}
	entry.running = true
	r.store.lock.Unlock()
	r.wg.Add(1)
	go r.drive(entry)
	return nil
}

func (r *Runtime) drive(entry *instance) {
	defer r.wg.Done()
	host := &host{runtime: r, entry: entry}
	outcome, err := workflow.AgentRunWorkflow(host, r.ops, entry.input)
	r.store.lock.Lock()
	defer r.store.lock.Unlock()
	entry.running = false
	switch {
	case errors.Is(err, stoppedError{}):
		// Crash equivalent: no outcome recorded; a restart resumes.
	case errors.Is(err, cancelledError{}):
		entry.outcome = &workflow.RunOutcome{Key: entry.input.Key, Terminal: workflow.TerminalCancelled}
	case err != nil:
		entry.failure = err
	default:
		entry.outcome = &outcome
	}
	r.store.broadcast()
}

func (r *Runtime) ExecuteRun(ctx context.Context, input workflow.RunInput) (workflow.RunOutcome, error) {
	if err := r.StartRun(ctx, input); err != nil {
		return workflow.RunOutcome{}, err
	}
	id := input.Key.WorkflowID()
	for {
		r.store.lock.Lock()
		entry := r.store.lookup(id)
		notify := r.store.notify
		if entry != nil && entry.outcome != nil {
			outcome := *entry.outcome
			r.store.lock.Unlock()
			return outcome, nil
		}
		if entry != nil && entry.failure != nil {
			failure := entry.failure
			r.store.lock.Unlock()
			return workflow.RunOutcome{}, failure
		}
		if entry != nil && !entry.running {
			r.store.lock.Unlock()
			return workflow.RunOutcome{}, stoppedError{}
		}
		r.store.lock.Unlock()
		select {
		case <-ctx.Done():
			return workflow.RunOutcome{}, ctx.Err()
		case <-r.stopped:
			return workflow.RunOutcome{}, stoppedError{}
		case <-notify:
		}
	}
}

// Signal delivers one durable topic message, deduplicated by idempotency
// key, to the workflow instance.
func (r *Runtime) Signal(_ context.Context, key workflow.RunKey, topic string, payload json.RawMessage, idempotencyKey string) error {
	r.store.lock.Lock()
	defer r.store.lock.Unlock()
	entry := r.store.lookup(key.WorkflowID())
	if entry == nil {
		return fmt.Errorf("signal unknown workflow %s", key.WorkflowID())
	}
	if idempotencyKey != "" {
		dedup := topic + "\x00" + idempotencyKey
		if entry.seenKeys[dedup] {
			return nil
		}
		entry.seenKeys[dedup] = true
	}
	entry.signals[topic] = append(entry.signals[topic], append([]byte(nil), payload...))
	r.store.broadcast()
	return nil
}

func (r *Runtime) CancelRun(_ context.Context, key workflow.RunKey) error {
	r.store.lock.Lock()
	defer r.store.lock.Unlock()
	entry := r.store.lookup(key.WorkflowID())
	if entry == nil {
		return fmt.Errorf("cancel unknown workflow %s", key.WorkflowID())
	}
	entry.cancelled = true
	if !entry.running && entry.outcome == nil && entry.failure == nil {
		entry.outcome = &workflow.RunOutcome{Key: entry.input.Key, Terminal: workflow.TerminalCancelled}
	}
	r.store.broadcast()
	return nil
}

// Outcome exposes the recorded outcome for assertions and replay checks.
func (r *Runtime) Outcome(key workflow.RunKey) (workflow.RunOutcome, bool) {
	r.store.lock.Lock()
	defer r.store.lock.Unlock()
	entry := r.store.lookup(key.WorkflowID())
	if entry == nil || entry.outcome == nil {
		return workflow.RunOutcome{}, false
	}
	return *entry.outcome, true
}

type host struct {
	runtime  *Runtime
	entry    *instance
	awaitSeq int
}

func (h *host) WorkflowID() string { return h.entry.input.Key.WorkflowID() }

func (h *host) Step(name string, fn func(context.Context) ([]byte, error)) ([]byte, error) {
	store := h.runtime.store
	store.lock.Lock()
	if recorded, replay := h.entry.steps[name]; replay {
		store.lock.Unlock()
		if recorded.failed {
			return nil, errors.New(recorded.reason)
		}
		return recorded.output, nil
	}
	if h.entry.cancelled {
		store.lock.Unlock()
		return nil, cancelledError{}
	}
	store.lock.Unlock()
	select {
	case <-h.runtime.stopped:
		return nil, stoppedError{}
	default:
	}
	output, err := fn(context.Background())
	store.lock.Lock()
	defer store.lock.Unlock()
	select {
	case <-h.runtime.stopped:
		// Crash between effect and checkpoint: nothing recorded, recovery
		// re-executes the operation, which must be idempotent.
		return nil, stoppedError{}
	default:
	}
	if err != nil {
		h.entry.steps[name] = stepRecord{failed: true, reason: err.Error()}
		return nil, err
	}
	h.entry.steps[name] = stepRecord{output: append([]byte(nil), output...)}
	return output, nil
}

func (h *host) AwaitSignal(topic string, timeout time.Duration) ([]byte, bool, error) {
	sequence := h.awaitSeq
	h.awaitSeq++
	store := h.runtime.store
	store.lock.Lock()
	record := h.entry.awaits[sequence]
	if record == nil {
		record = &awaitRecord{deadline: h.runtime.clock().Add(timeout)}
		h.entry.awaits[sequence] = record
	}
	if record.done {
		store.lock.Unlock()
		return record.payload, record.timedOut, nil
	}
	for {
		if h.entry.cancelled {
			store.lock.Unlock()
			return nil, false, cancelledError{}
		}
		if queue := h.entry.signals[topic]; len(queue) > 0 {
			payload := queue[0]
			h.entry.signals[topic] = queue[1:]
			record.done = true
			record.payload = payload
			store.lock.Unlock()
			return payload, false, nil
		}
		now := h.runtime.clock()
		if !now.Before(record.deadline) {
			record.done = true
			record.timedOut = true
			store.lock.Unlock()
			return nil, true, nil
		}
		notify := store.notify
		remaining := record.deadline.Sub(now)
		store.lock.Unlock()
		timer := time.NewTimer(remaining)
		select {
		case <-h.runtime.stopped:
			timer.Stop()
			return nil, false, stoppedError{}
		case <-notify:
			timer.Stop()
		case <-timer.C:
		}
		store.lock.Lock()
	}
}

var _ workflow.Runtime = (*Runtime)(nil)
