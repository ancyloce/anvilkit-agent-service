// Package lifecycle owns base readiness and ordered graceful shutdown.
package lifecycle

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"sync"
)

type Check interface{ Check(context.Context) error }
type CheckFunc func(context.Context) error

func (f CheckFunc) Check(ctx context.Context) error { return f(ctx) }

type Dependency struct {
	Name  string
	Check Check
}
type Readiness struct{ dependencies []Dependency }
type Status struct {
	Ready        bool              `json:"ready"`
	Dependencies map[string]string `json:"dependencies"`
}

func NewReadiness(dependencies ...Dependency) *Readiness {
	return &Readiness{dependencies: append([]Dependency(nil), dependencies...)}
}
func (r *Readiness) Status(ctx context.Context) Status {
	status := Status{Ready: true, Dependencies: make(map[string]string, len(r.dependencies))}
	for _, dependency := range r.dependencies {
		if dependency.Check == nil {
			status.Ready = false
			status.Dependencies[dependency.Name] = "missing"
			continue
		}
		if err := dependency.Check.Check(ctx); err != nil {
			status.Ready = false
			status.Dependencies[dependency.Name] = "unavailable"
		} else {
			status.Dependencies[dependency.Name] = "available"
		}
	}
	return status
}
func (r *Readiness) ServeHTTP(response http.ResponseWriter, request *http.Request) {
	status := r.Status(request.Context())
	response.Header().Set("Content-Type", "application/json")
	if !status.Ready {
		response.WriteHeader(http.StatusServiceUnavailable)
	}
	_ = json.NewEncoder(response).Encode(status)
}

type Stage int

const (
	StopIngress Stage = iota + 1
	GuideStreamReconnect
	CheckpointExecutors
	CleanupLeases
)

type Hook struct {
	Name  string
	Stage Stage
	Run   func(context.Context) error
}

type LeaseCleaner interface {
	Cleanup(context.Context) error
}

type LeaseCleanerFunc func(context.Context) error

func (f LeaseCleanerFunc) Cleanup(ctx context.Context) error { return f(ctx) }

type Shutdown struct {
	lock     sync.Mutex
	running  bool
	complete bool
	hooks    []Hook
}

func NewShutdown(hooks ...Hook) *Shutdown { return &Shutdown{hooks: append([]Hook(nil), hooks...)} }
func (s *Shutdown) Run(ctx context.Context) error {
	s.lock.Lock()
	if s.complete {
		s.lock.Unlock()
		return nil
	}
	if s.running {
		s.lock.Unlock()
		return fmt.Errorf("shutdown already running")
	}
	s.running = true
	s.lock.Unlock()
	succeeded := false
	defer func() {
		s.lock.Lock()
		s.running = false
		s.complete = succeeded
		s.lock.Unlock()
	}()
	for stage := StopIngress; stage <= CleanupLeases; stage++ {
		for _, hook := range s.hooks {
			if hook.Stage != stage {
				continue
			}
			if err := hook.Run(ctx); err != nil {
				return fmt.Errorf("shutdown %s: %w", hook.Name, err)
			}
		}
	}
	succeeded = true
	return nil
}
