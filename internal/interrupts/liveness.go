package interrupts

import (
	"context"
	"fmt"
	"time"

	"github.com/ancyloce/anvilkit-agent-service/internal/problem"
	"github.com/ancyloce/anvilkit-agent-service/internal/runs"
)

type DwellPolicy struct {
	Deadline time.Duration
	Owner    string
}

type Monitor struct {
	repository Repository
	alerts     AlertSink
	clock      Clock
	policies   map[runs.State]DwellPolicy
}

func NewMonitor(repository Repository, alerts AlertSink, clock Clock, policies map[runs.State]DwellPolicy) (*Monitor, error) {
	if repository == nil || alerts == nil || clock == nil {
		return nil, fmt.Errorf("liveness monitor dependencies are required")
	}
	copyPolicies := make(map[runs.State]DwellPolicy, len(policies))
	for _, state := range nonterminalStates() {
		policy, ok := policies[state]
		if !ok || policy.Deadline <= 0 || policy.Owner == "" {
			return nil, fmt.Errorf("liveness policy for %s requires deadline and owner", state)
		}
		copyPolicies[state] = policy
	}
	return &Monitor{repository: repository, alerts: alerts, clock: clock, policies: copyPolicies}, nil
}

func (m *Monitor) Heartbeat(ctx context.Context, scope runs.Scope, id runs.ID, state runs.State) error {
	now := m.clock.Now().UTC()
	if now.IsZero() {
		return problem.New(problem.CodeAuthorityStale, "")
	}
	return m.repository.RecordProgress(ctx, scope, id, state, now)
}

func (m *Monitor) Scan(ctx context.Context) (int, error) {
	now := m.clock.Now().UTC()
	if now.IsZero() {
		return 0, problem.New(problem.CodeAuthorityStale, "")
	}
	progress, err := m.repository.Progress(ctx)
	if err != nil {
		return 0, fmt.Errorf("query run progress: %w", err)
	}
	emitted := 0
	for _, item := range progress {
		policy, nonterminal := m.policies[item.State]
		if !nonterminal || now.Sub(item.ProgressAt) < policy.Deadline {
			continue
		}
		marked, err := m.repository.MarkStuck(ctx, item, now, policy.Owner)
		if err != nil {
			return emitted, err
		}
		if !marked {
			continue
		}
		if err := m.alerts.Alert(ctx, "run-dwell-deadline", item.Scope, item.RunID, item.State); err != nil {
			return emitted, fmt.Errorf("emit stuck-run alert: %w", err)
		}
		emitted++
	}
	return emitted, nil
}

func (m *Monitor) Run(ctx context.Context, interval time.Duration) {
	if interval <= 0 || interval > 5*time.Minute {
		interval = time.Minute
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			_, _ = m.Scan(ctx)
		}
	}
}

func nonterminalStates() []runs.State {
	return []runs.State{runs.Created, runs.Preparing, runs.Planning, runs.AwaitingInput, runs.Executing, runs.Validating, runs.AwaitingReview, runs.AwaitingApproval, runs.Committing, runs.AwaitingDomainConfirmation, runs.Conflict, runs.Cancelling, runs.Failed}
}
