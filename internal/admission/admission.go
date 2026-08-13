// Package admission owns bounded fairness, retry budgets, and dependency circuits.
package admission

import (
	"fmt"
	"math/rand"
	"sync"
	"time"

	"github.com/ancyloce/anvilkit-agent-service/internal/problem"
)

type Limits struct {
	GlobalActive, GlobalQueued, WorkspaceActive, WorkspaceQueued, ChildDepth, ChildFanout, Turns, Tools, Repairs, Retries, ContextTokens, InputTokens, OutputTokens, EventBytes int
	ArtifactBytes                                                                                                                                                               int64
	SSEConnections                                                                                                                                                              int
}

func (l Limits) Validate() error {
	values := []int{l.GlobalActive, l.GlobalQueued, l.WorkspaceActive, l.WorkspaceQueued, l.ChildDepth, l.ChildFanout, l.Turns, l.Tools, l.Repairs, l.Retries, l.ContextTokens, l.InputTokens, l.OutputTokens, l.EventBytes, l.SSEConnections}
	for _, v := range values {
		if v < 1 {
			return fmt.Errorf("admission limit must be positive")
		}
	}
	if l.ArtifactBytes < 1 {
		return fmt.Errorf("artifact bound must be positive")
	}
	return nil
}

type Request struct {
	WorkspaceID, RunID                                                                                            string
	ChildDepth, ChildFanout, Turns, Tools, Repairs, Retries, ContextTokens, InputTokens, OutputTokens, EventBytes int
	ArtifactBytes                                                                                                 int64
	SSEConnections                                                                                                int
}
type Decision struct {
	Admitted, Queued bool
	RetryAfter       time.Duration
	Code             string
}
type Manager struct {
	lock        sync.Mutex
	limits      Limits
	active      map[string]int
	queued      map[string][]Request
	order       []string
	cursor      int
	global      int
	queuedTotal int
	durable     int
}

func New(l Limits) (*Manager, error) {
	if err := l.Validate(); err != nil {
		return nil, err
	}
	return &Manager{limits: l, active: map[string]int{}, queued: map[string][]Request{}}, nil
}
func (m *Manager) Admit(v Request) Decision {
	m.lock.Lock()
	defer m.lock.Unlock()
	if v.WorkspaceID == "" || v.RunID == "" || m.exceeds(v) {
		return Decision{Code: string(problem.CodeLimitExceeded)}
	}
	if m.global < m.limits.GlobalActive && m.active[v.WorkspaceID] < m.limits.WorkspaceActive {
		m.global++
		m.active[v.WorkspaceID]++
		m.durable++
		return Decision{Admitted: true}
	}
	if m.queuedTotal >= m.limits.GlobalQueued || len(m.queued[v.WorkspaceID]) >= m.limits.WorkspaceQueued {
		return Decision{Code: string(problem.CodeAdmissionOverloaded), RetryAfter: time.Second}
	}
	if len(m.queued[v.WorkspaceID]) == 0 {
		m.order = append(m.order, v.WorkspaceID)
	}
	m.queued[v.WorkspaceID] = append(m.queued[v.WorkspaceID], v)
	m.queuedTotal++
	m.durable++
	return Decision{Queued: true, Code: string(problem.CodeAdmissionOverloaded), RetryAfter: time.Second}
}
func (m *Manager) Complete(workspace string) (Request, bool) {
	m.lock.Lock()
	defer m.lock.Unlock()
	if m.active[workspace] > 0 {
		m.active[workspace]--
		m.global--
	}
	return m.next()
}
func (m *Manager) next() (Request, bool) {
	if m.global >= m.limits.GlobalActive || len(m.order) == 0 {
		return Request{}, false
	}
	for scanned := 0; scanned < len(m.order); scanned++ {
		m.cursor %= len(m.order)
		workspace := m.order[m.cursor]
		if m.active[workspace] >= m.limits.WorkspaceActive || len(m.queued[workspace]) == 0 {
			m.cursor++
			continue
		}
		value := m.queued[workspace][0]
		m.queued[workspace] = m.queued[workspace][1:]
		m.queuedTotal--
		if len(m.queued[workspace]) == 0 {
			m.order = append(m.order[:m.cursor], m.order[m.cursor+1:]...)
			if len(m.order) == 0 {
				m.cursor = 0
			}
		} else {
			m.cursor++
		}
		m.active[workspace]++
		m.global++
		return value, true
	}
	return Request{}, false
}
func (m *Manager) exceeds(v Request) bool {
	return v.ChildDepth > m.limits.ChildDepth || v.ChildFanout > m.limits.ChildFanout || v.Turns > m.limits.Turns || v.Tools > m.limits.Tools || v.Repairs > m.limits.Repairs || v.Retries > m.limits.Retries || v.ContextTokens > m.limits.ContextTokens || v.InputTokens > m.limits.InputTokens || v.OutputTokens > m.limits.OutputTokens || v.EventBytes > m.limits.EventBytes || v.ArtifactBytes > m.limits.ArtifactBytes || v.SSEConnections > m.limits.SSEConnections
}
func (m *Manager) DurableRecords() int { m.lock.Lock(); defer m.lock.Unlock(); return m.durable }

type RetryPolicy struct {
	MaximumAttempts   int
	Base, Maximum     time.Duration
	Jitter            float64
	MaximumCostMicros int64
}
type RetryBudget struct {
	lock     sync.Mutex
	policy   RetryPolicy
	random   *rand.Rand
	attempts int
	cost     int64
}

func NewRetryBudget(p RetryPolicy, seed int64) (*RetryBudget, error) {
	if p.MaximumAttempts < 1 || p.Base <= 0 || p.Maximum < p.Base || p.Jitter < 0 || p.Jitter > 1 || p.MaximumCostMicros < 1 {
		return nil, fmt.Errorf("retry policy invalid")
	}
	return &RetryBudget{policy: p, random: rand.New(rand.NewSource(seed))}, nil
}
func (b *RetryBudget) Next(cost int64) (time.Duration, error) {
	b.lock.Lock()
	defer b.lock.Unlock()
	if cost < 0 || cost > b.policy.MaximumCostMicros || b.attempts >= b.policy.MaximumAttempts || b.cost > b.policy.MaximumCostMicros-cost {
		return 0, problem.New(problem.CodeLimitExceeded, "")
	}
	scale := time.Duration(1 << min(b.attempts, 20))
	delay := b.policy.Maximum
	if b.policy.Base <= b.policy.Maximum/scale {
		delay = b.policy.Base * scale
	}
	if delay > b.policy.Maximum {
		delay = b.policy.Maximum
	}
	factor := 1 - b.policy.Jitter + 2*b.policy.Jitter*b.random.Float64()
	b.attempts++
	b.cost += cost
	return time.Duration(float64(delay) * factor), nil
}
func (b *RetryBudget) Cost() int64 { b.lock.Lock(); defer b.lock.Unlock(); return b.cost }

type Circuit struct {
	lock      sync.Mutex
	threshold int
	cooldown  time.Duration
	failures  int
	openedAt  time.Time
}

func NewCircuit(threshold int, cooldown time.Duration) (*Circuit, error) {
	if threshold < 1 || cooldown <= 0 {
		return nil, fmt.Errorf("circuit config invalid")
	}
	return &Circuit{threshold: threshold, cooldown: cooldown}, nil
}
func (c *Circuit) Allow(now time.Time) error {
	c.lock.Lock()
	defer c.lock.Unlock()
	if !c.openedAt.IsZero() && now.Sub(c.openedAt) < c.cooldown {
		return problem.New(problem.CodeCircuitOpen, "")
	}
	if !c.openedAt.IsZero() {
		c.openedAt = time.Time{}
		c.failures = 0
	}
	return nil
}
func (c *Circuit) Failure(now time.Time) {
	c.lock.Lock()
	defer c.lock.Unlock()
	c.failures++
	if c.failures >= c.threshold && c.openedAt.IsZero() {
		c.openedAt = now
	}
}
func (c *Circuit) Success() {
	c.lock.Lock()
	defer c.lock.Unlock()
	c.failures = 0
	c.openedAt = time.Time{}
}
func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
