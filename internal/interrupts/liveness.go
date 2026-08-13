package interrupts

import (
	"context"
	"fmt"
	"time"

	"github.com/ancyloce/anvilkit-agent-service/internal/runs"
)

type DwellPolicy struct {
	Deadline time.Duration
	Owner    string
}

type Monitor struct {
	repository Repository
	events     EventSink
	alerts     AlertSink
	clock      Clock
	policies   map[runs.State]DwellPolicy
}

func NewMonitor(repository Repository, events EventSink, alerts AlertSink, clock Clock, policies map[runs.State]DwellPolicy) (*Monitor, error) {
	if repository == nil || events == nil || alerts == nil || clock == nil {
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
	return &Monitor{repository: repository, events: events, alerts: alerts, clock: clock, policies: copyPolicies}, nil
}

func (m *Monitor) Heartbeat(ctx context.Context, scope runs.Scope, id runs.ID, state runs.State) error {
	return m.repository.RecordProgress(ctx, scope, id, state, m.clock.Now().UTC())
}

func (m *Monitor) Scan(ctx context.Context) (int, error) {
	progress, err := m.repository.Progress(ctx)
	if err != nil {
		return 0, fmt.Errorf("query run progress: %w", err)
	}
	now := m.clock.Now().UTC()
	emitted := 0
	for _, item := range progress {
		policy, nonterminal := m.policies[item.State]
		if !nonterminal || now.Sub(item.ProgressAt) < policy.Deadline {
			continue
		}
		marked, err := m.repository.MarkStuck(ctx, item.Scope, item.RunID, item.State, now)
		if err != nil {
			return emitted, err
		}
		if !marked {
			continue
		}
		if err := m.events.Stuck(ctx, item, now); err != nil {
			return emitted, fmt.Errorf("persist stuck-run event: %w", err)
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
