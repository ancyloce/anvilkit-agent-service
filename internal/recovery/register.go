// Package recovery defines the external non-rollback epoch and ordered restore workflow.
package recovery

import (
	"context"
	"fmt"
	"math"
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
// be selected through deployment configuration and must live outside Platform Postgres and its backups.
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

func (r *MemoryRegister) Current(ctx context.Context) (Epoch, error) {
	if err := ctx.Err(); err != nil {
		return 0, err
	}
	r.lock.Lock()
	defer r.lock.Unlock()
	if r.unavailable {
		return 0, problem.New(problem.CodeInfrastructureUnavailable, "")
	}
	return r.epoch, nil
}

func (r *MemoryRegister) Increment(ctx context.Context, expected Epoch, evidence IncrementEvidence) (Epoch, error) {
	if err := ctx.Err(); err != nil {
		return 0, err
	}
	if !validIncrementEvidence(evidence) {
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
	if r.epoch == Epoch(math.MaxUint64) {
		return r.epoch, problem.New(problem.CodeLimitExceeded, "")
	}
	r.epoch++
	evidence.At = evidence.At.UTC()
	r.increments = append(r.increments, evidence)
	return r.epoch, nil
}

func validIncrementEvidence(evidence IncrementEvidence) bool {
	for _, value := range []string{evidence.Actor, evidence.Workload, evidence.Ticket} {
		if len(value) < 1 || len(value) > 128 {
			return false
		}
	}
	if len(evidence.Reason) < 1 || len(evidence.Reason) > 1024 || evidence.At.IsZero() || !validTraceparent(evidence.Traceparent) {
		return false
	}
	for _, character := range evidence.Reason {
		if character < 0x20 || character > 0x7e {
			return false
		}
	}
	return true
}

func validTraceparent(value string) bool {
	if len(value) != 55 || value[:3] != "00-" || value[35] != '-' || value[52] != '-' || value[3:35] == "00000000000000000000000000000000" || value[36:52] == "0000000000000000" {
		return false
	}
	for index, character := range value {
		if index == 2 || index == 35 || index == 52 {
			continue
		}
		if !lowerHexDigit(character) {
			return false
		}
	}
	return true
}

// lowerHexDigit reports whether the character is a lower-case hexadecimal
// digit. Identity and digest formats are lower-case only, so an upper-case
// digit is rejected rather than normalized.
func lowerHexDigit(character rune) bool {
	return character >= '0' && character <= '9' || character >= 'a' && character <= 'f'
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
