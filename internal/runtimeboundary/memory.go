package runtimeboundary

import (
	"context"
	"fmt"
	"sync"

	"github.com/ancyloce/anvilkit-agent-service/contracts/generated/schema"
)

// MemoryRegister is the in-memory task register. It exists for tests; the
// production composition uses the durable store, so a callback that lands on a
// recovered process still finds the attempt it was dispatched for.
type MemoryRegister struct {
	lock  sync.Mutex
	tasks map[string]schema.AgentTask
}

// NewMemoryRegister builds an empty register.
func NewMemoryRegister() *MemoryRegister {
	return &MemoryRegister{tasks: map[string]schema.AgentTask{}}
}

// Offer records the dispatched task under its physical attempt identity.
func (r *MemoryRegister) Offer(_ context.Context, task schema.AgentTask, _ []byte) error {
	if task.PhysicalAttemptId == "" {
		return fmt.Errorf("task register: a task with no physical attempt identity cannot be offered")
	}
	r.lock.Lock()
	defer r.lock.Unlock()
	r.tasks[string(task.PhysicalAttemptId)] = Offered(task)
	return nil
}

// Task resolves one dispatched task by its physical attempt identity.
func (r *MemoryRegister) Task(_ context.Context, physicalAttemptID string) (schema.AgentTask, bool, error) {
	r.lock.Lock()
	defer r.lock.Unlock()
	task, known := r.tasks[physicalAttemptID]
	return task, known, nil
}

// MemoryAttempts is the in-memory attempt register. Every attempt is current
// until it is superseded; the production composition reads currency from the
// durable dispatch record instead.
type MemoryAttempts struct {
	lock       sync.Mutex
	superseded map[string]bool
}

// NewMemoryAttempts builds a register in which every attempt is current.
func NewMemoryAttempts() *MemoryAttempts {
	return &MemoryAttempts{superseded: map[string]bool{}}
}

// Supersede marks one attempt as no longer the current execution of its task.
func (a *MemoryAttempts) Supersede(physicalAttemptID string) {
	a.lock.Lock()
	defer a.lock.Unlock()
	a.superseded[physicalAttemptID] = true
}

// Current reports whether the attempt is still the current execution.
func (a *MemoryAttempts) Current(_ context.Context, _, _, _, physicalAttemptID string) (bool, error) {
	a.lock.Lock()
	defer a.lock.Unlock()
	return !a.superseded[physicalAttemptID], nil
}

// MemorySubmissions is the in-memory submission store twin of the durable one.
type MemorySubmissions struct {
	lock sync.Mutex
	// byAttempt is the replay register: one submission per attempt identity.
	byAttempt map[string]Submission
	// byDigest is the immutable record: one submission per (run, digest).
	byDigest map[string]Submission
}

// NewMemorySubmissions builds an empty store.
func NewMemorySubmissions() *MemorySubmissions {
	return &MemorySubmissions{byAttempt: map[string]Submission{}, byDigest: map[string]Submission{}}
}

// Record stores one submission with the boundary's idempotency semantics.
func (s *MemorySubmissions) Record(_ context.Context, submission Submission) (Submission, bool, error) {
	s.lock.Lock()
	defer s.lock.Unlock()
	if previous, present := s.byAttempt[submission.PhysicalAttemptID]; present {
		if previous.Digest != submission.Digest {
			return Submission{}, false, SubmissionConflictError{}
		}
		return previous, true, nil
	}
	key := submission.RunID + "\x00" + submission.Digest
	if existing, present := s.byDigest[key]; present {
		// Another attempt already recorded these bytes: the artifact is the
		// same immutable record, and this attempt's replay register now names
		// it too.
		s.byAttempt[submission.PhysicalAttemptID] = existing
		return existing, true, nil
	}
	s.byAttempt[submission.PhysicalAttemptID] = submission
	s.byDigest[key] = submission
	return submission, false, nil
}

// Content reads back one recorded submission by its reference.
func (s *MemorySubmissions) Content(_ context.Context, reference schema.SharedPrimitivesArtifactReference) ([]byte, error) {
	s.lock.Lock()
	defer s.lock.Unlock()
	for _, submission := range s.byDigest {
		if submission.ArtifactID == string(reference.ArtifactId) && submission.Digest == string(reference.Digest) {
			return append([]byte(nil), submission.Content...), nil
		}
	}
	return nil, fmt.Errorf("submission store: no recorded submission matches the reference")
}
