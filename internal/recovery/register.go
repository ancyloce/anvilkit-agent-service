// Package recovery defines the external non-rollback epoch and ordered restore workflow.
package recovery

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/ancyloce/anvilkit-agent-service/internal/problem"
)

type Epoch uint64

type IncrementEvidence struct {
	Actor, Workload, Reason, Ticket, Traceparent string
	At                                           time.Time
}

type Register interface {
	Current(context.Context) (Epoch, error)
	Increment(context.Context, Epoch, IncrementEvidence) (Epoch, error)
}

// MemoryRegister is a conformance stand-in only. The production register must
// be selected at Gate F and must live outside Platform Postgres and its backups.
type MemoryRegister struct {
	lock        sync.Mutex
	epoch       Epoch
	unavailable bool
	increments  []IncrementEvidence
}

func NewMemoryRegister(initial Epoch) (*MemoryRegister, error) {
	if initial == 0 {
		return nil, fmt.Errorf("initial recovery epoch must be positive")
	}
	return &MemoryRegister{epoch: initial}, nil
}

func (r *MemoryRegister) Current(context.Context) (Epoch, error) {
	r.lock.Lock()
	defer r.lock.Unlock()
	if r.unavailable {
		return 0, problem.New(problem.CodeInfrastructureUnavailable, "")
	}
	return r.epoch, nil
}

func (r *MemoryRegister) Increment(_ context.Context, expected Epoch, evidence IncrementEvidence) (Epoch, error) {
	if evidence.Actor == "" || evidence.Workload == "" || evidence.Reason == "" || evidence.Ticket == "" || evidence.Traceparent == "" || evidence.At.IsZero() {
		return 0, problem.New(problem.CodeRequestInvalid, "")
	}
	r.lock.Lock()
	defer r.lock.Unlock()
	if r.unavailable {
		return 0, problem.New(problem.CodeInfrastructureUnavailable, "")
	}
	if expected != r.epoch {
		return r.epoch, problem.New(problem.CodeVersionConflict, "")
	}
	r.epoch++
	r.increments = append(r.increments, evidence)
	return r.epoch, nil
}

func (r *MemoryRegister) SetUnavailable(value bool) {
	r.lock.Lock()
	defer r.lock.Unlock()
	r.unavailable = value
}

func (r *MemoryRegister) IncrementCount() int {
	r.lock.Lock()
	defer r.lock.Unlock()
	return len(r.increments)
}
