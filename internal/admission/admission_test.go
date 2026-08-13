package admission

import (
	"fmt"
	"testing"
	"time"

	"github.com/ancyloce/anvilkit-agent-service/internal/problem"
)

func limits() Limits {
	return Limits{GlobalActive: 2, GlobalQueued: 4, WorkspaceActive: 1, WorkspaceQueued: 2, ChildDepth: 4, ChildFanout: 16, Turns: 20, Tools: 7, Repairs: 2, Retries: 3, ContextTokens: 32000, InputTokens: 16000, OutputTokens: 8000, EventBytes: 65536, ArtifactBytes: 1 << 20, SSEConnections: 10}
}
func request(workspace, run string) Request {
	return Request{WorkspaceID: workspace, RunID: run, ChildDepth: 1, ChildFanout: 1, Turns: 1, Tools: 3, Repairs: 1, Retries: 1, ContextTokens: 100, InputTokens: 100, OutputTokens: 100, EventBytes: 100, ArtifactBytes: 100, SSEConnections: 1}
}
func TestNoisyWorkspaceCannotStarveAnother(t *testing.T) {
	manager, _ := New(limits())
	if !manager.Admit(request("noisy", "n1")).Admitted {
		t.Fatal()
	}
	for _, id := range []string{"n2", "n3"} {
		if !manager.Admit(request("noisy", id)).Queued {
			t.Fatal("noisy not queued")
		}
	}
	if !manager.Admit(request("quiet", "q1")).Admitted {
		t.Fatal("quiet starved")
	}
	if decision := manager.Admit(request("quiet", "q2")); !decision.Queued {
		t.Fatal("quiet queue missing")
	}
	next, ok := manager.Complete("noisy")
	if !ok || next.WorkspaceID != "noisy" {
		t.Fatalf("next=%#v", next)
	}
	next, ok = manager.Complete("quiet")
	if !ok || next.WorkspaceID != "quiet" {
		t.Fatalf("fair next=%#v", next)
	}
}
func TestEveryBoundStableRejectsWithoutDurableRecord(t *testing.T) {
	mutations := []func(*Request){func(v *Request) { v.ChildDepth = 5 }, func(v *Request) { v.ChildFanout = 17 }, func(v *Request) { v.Turns = 21 }, func(v *Request) { v.Tools = 8 }, func(v *Request) { v.Repairs = 3 }, func(v *Request) { v.Retries = 4 }, func(v *Request) { v.ContextTokens = 32001 }, func(v *Request) { v.InputTokens = 16001 }, func(v *Request) { v.OutputTokens = 8001 }, func(v *Request) { v.EventBytes = 65537 }, func(v *Request) { v.ArtifactBytes = (1 << 20) + 1 }, func(v *Request) { v.SSEConnections = 11 }}
	for _, mutate := range mutations {
		manager, _ := New(limits())
		v := request("workspace", "run")
		mutate(&v)
		decision := manager.Admit(v)
		if decision.Code != "LIMIT_EXCEEDED" || manager.DurableRecords() != 0 {
			t.Fatalf("decision=%#v records=%d", decision, manager.DurableRecords())
		}
	}
}
func TestOverloadRetryStormBudgetAndCircuit(t *testing.T) {
	manager, _ := New(limits())
	_ = manager.Admit(request("w", "1"))
	_ = manager.Admit(request("w", "2"))
	_ = manager.Admit(request("w", "3"))
	decision := manager.Admit(request("w", "4"))
	if decision.Code != "ADMISSION_OVERLOADED" || decision.RetryAfter <= 0 || manager.DurableRecords() != 3 {
		t.Fatalf("decision=%#v records=%d", decision, manager.DurableRecords())
	}
	budget, _ := NewRetryBudget(RetryPolicy{MaximumAttempts: 3, Base: time.Millisecond, Maximum: 10 * time.Millisecond, Jitter: .2, MaximumCostMicros: 100}, 1)
	for range 3 {
		if _, err := budget.Next(30); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := budget.Next(1); err == nil || budget.Cost() != 90 {
		t.Fatalf("storm cost=%d err=%v", budget.Cost(), err)
	}
	circuit, _ := NewCircuit(2, time.Minute)
	now := time.Now()
	circuit.Failure(now)
	circuit.Failure(now)
	if err := circuit.Allow(now); err == nil {
		t.Fatal("open circuit allowed")
	}
	if err := circuit.Allow(now.Add(2 * time.Minute)); err != nil {
		t.Fatal("cooled circuit denied")
	}
}
func TestGrowthBoundedUnderDenialOfWallet(t *testing.T) {
	manager, _ := New(limits())
	for index := 0; index < 100000; index++ {
		v := request("noisy", "run")
		v.ArtifactBytes = 1 << 30
		_ = manager.Admit(v)
	}
	if manager.DurableRecords() != 0 {
		t.Fatalf("rejections grew durable state: %d", manager.DurableRecords())
	}
}

func TestGlobalQueueCapBoundsManyWorkspaces(t *testing.T) {
	configured := limits()
	configured.GlobalActive = 1
	configured.GlobalQueued = 3
	manager, _ := New(configured)
	if !manager.Admit(request("active", "active")).Admitted {
		t.Fatal("initial request not admitted")
	}
	for index := 0; index < configured.GlobalQueued; index++ {
		if !manager.Admit(request(fmt.Sprintf("workspace-%d", index), fmt.Sprintf("run-%d", index))).Queued {
			t.Fatal("request not queued within global cap")
		}
	}
	decision := manager.Admit(request("overflow", "overflow"))
	if decision.Code != string(problem.CodeAdmissionOverloaded) || decision.RetryAfter <= 0 || manager.DurableRecords() != configured.GlobalQueued+1 {
		t.Fatalf("decision=%#v durable=%d", decision, manager.DurableRecords())
	}
}
