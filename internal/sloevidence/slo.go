// Package sloevidence pins binding objectives while observability review owns query approval.
package sloevidence

import (
	"context"
	"fmt"
	"sync"
)

type Definition struct {
	ID, Objective, Query, Denominator, Exclusions, Paging string
	GateHApproved                                         bool
}

func DraftDefinitions() []Definition {
	return []Definition{
		{"availability", ">=99.9% rolling 28d", `sum(rate(agent_requests_total{eligible="true",outcome="success"}[28d])) / sum(rate(agent_requests_total{eligible="true"}[28d]))`, "eligible Create/Get/Cancel requests", "invalid/auth-rejected before eligibility", "page below 99.9%", false},
		{"create-latency", "P95 <300ms", `histogram_quantile(0.95,sum by(le)(rate(agent_create_duration_seconds_bucket{outcome="accepted"}[15m])))`, "accepted durable create outcomes", "model execution", "page at >=0.300s", false},
		{"event-visibility", "P95 <2s", `histogram_quantile(0.95,sum by(le)(rate(agent_event_visibility_seconds_bucket{authorized="true"}[15m])))`, "durable events visible to authorized clients", "unauthorized subscribers", "page at >=2s", false},
		{"durable-recovery", ">=99.9% within 30m", `sum(increase(agent_recovery_total{eligible="true",within_rto="true"}[28d])) / sum(increase(agent_recovery_total{eligible="true"}[28d]))`, "eligible interrupted workflows", "terminal workflows", "page below 99.9% or any restore >30m", false},
		{"raw-plan-validity", ">=99.5%", `sum(increase(agent_plan_total{stage="raw",valid="true"}[7d])) / sum(increase(agent_plan_total{stage="raw"}[7d]))`, "pinned baseline raw outputs", "policy refusals and invalid client input", "block release below 99.5%", false},
		{"trace-continuity", ">=99%", `sum(increase(agent_boundary_total{trace_linked="true"}[24h])) / sum(increase(agent_boundary_total[24h]))`, "all governed cross-service boundaries", "none", "page below 99%", false},
		{"diagnosable-errors-dlq", "100%", `sum(increase(agent_failures_total{diagnosable="true"}[24h])) / sum(increase(agent_failures_total[24h]))`, "all errors and DLQ records", "none", "absolute alert below 100%", false},
		{"stuck-run-detection", "100% within 5m", `sum(increase(agent_stuck_total{alert_within_5m="true"}[24h])) / sum(increase(agent_stuck_total[24h]))`, "all runs past dwell deadline", "none", "absolute alert below 100%", false},
		{"accepted-output-validity", "100%", `sum(increase(agent_boundary_output_total{accepted="true",valid="true"}[24h])) / sum(increase(agent_boundary_output_total{accepted="true"}[24h]))`, "all accepted trust-boundary outputs", "none", "absolute alert below 100%", false},
		{"fake-tool-selection", ">=95% pinned corpus", `sum(agent_evaluation_total{dataset="baseline",tool_correct="true"}) / sum(agent_evaluation_total{dataset="baseline"})`, "versioned pinned baseline cases", "none", "block release below 95%", false},
		{"workspace-fairness", "no eligible workspace starvation", `max by(workspace_id)(agent_workspace_share_ratio) unless min by(workspace_id)(agent_workspace_eligible_waiting)==0`, "eligible queued workspaces during overload", "ineligible or policy-denied work", "page on any starvation", false},
	}
}

func ValidateDraft(definitions []Definition) error {
	if len(definitions) != 11 {
		return fmt.Errorf("expected eleven binding SLO definitions, got %d", len(definitions))
	}
	seen := map[string]bool{}
	for _, definition := range definitions {
		if definition.ID == "" || seen[definition.ID] || definition.Objective == "" || definition.Query == "" || definition.Denominator == "" || definition.Exclusions == "" || definition.Paging == "" {
			return fmt.Errorf("incomplete or duplicate SLO definition %q", definition.ID)
		}
		if definition.GateHApproved {
			return fmt.Errorf("draft query %q cannot claim observability approval", definition.ID)
		}
		seen[definition.ID] = true
	}
	return nil
}

type Violation struct {
	Kind, WorkspaceID, ProjectID, RunID, TraceID string
}
type Pager interface {
	Page(context.Context, Violation) error
}
type SafetyMonitor struct{ pager Pager }

func NewSafetyMonitor(pager Pager) (*SafetyMonitor, error) {
	if pager == nil {
		return nil, fmt.Errorf("safety pager required")
	}
	return &SafetyMonitor{pager: pager}, nil
}
func (m *SafetyMonitor) Observe(ctx context.Context, violation Violation) error {
	allowed := map[string]bool{"duplicate-effect": true, "approval-bypass": true, "forbidden-tool": true, "cross-tenant": true, "stale-result": true, "unauthorized-disclosure": true}
	if !allowed[violation.Kind] || violation.WorkspaceID == "" || violation.ProjectID == "" || violation.RunID == "" || violation.TraceID == "" {
		return fmt.Errorf("invalid safety violation")
	}
	return m.pager.Page(ctx, violation)
}

type MemoryPager struct {
	lock   sync.Mutex
	Values []Violation
}

func (p *MemoryPager) Page(_ context.Context, value Violation) error {
	p.lock.Lock()
	defer p.lock.Unlock()
	p.Values = append(p.Values, value)
	return nil
}
