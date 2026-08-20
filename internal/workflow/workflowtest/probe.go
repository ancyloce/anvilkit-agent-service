// Package workflowtest provides the controlled Operations probe used to
// prove engine semantics behind the production workflow port. It is a test
// seam only and is never selected by production composition.
package workflowtest

import (
	"context"
	"encoding/json"
	"sync"
	"time"

	"github.com/ancyloce/anvilkit-agent-service/internal/agent"
	"github.com/ancyloce/anvilkit-agent-service/internal/workflow"
)

const ProbeDigest = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"

// ProbeOps is a controlled Operations implementation behind the production
// pipeline port. It drives deterministic decision sequences so the DBOS
// engine semantics — checkpointing, recovery, durable waits, cancellation —
// can be proven without external infrastructure.
type ProbeOps struct {
	lock      sync.Mutex
	calls     map[string]int
	NeedInput bool
	Governed  bool
	// Delegate makes the first turn delegate, and DelegateTurns bounds how
	// many Specialist turns the delegation runs before concluding.
	Delegate      bool
	DelegateTurns int
	InputTimeout  time.Duration
	inputOpened   time.Time
	accepted      bool
	approved      bool
	value         json.RawMessage
}

func NewProbeOps() *ProbeOps {
	return &ProbeOps{calls: make(map[string]int), InputTimeout: 30 * time.Second, DelegateTurns: 2}
}

func (p *ProbeOps) count(op workflow.OpID) {
	p.lock.Lock()
	defer p.lock.Unlock()
	p.calls[op.Step]++
}

func (p *ProbeOps) CallCount(step string) int {
	p.lock.Lock()
	defer p.lock.Unlock()
	return p.calls[step]
}

func (p *ProbeOps) Accept(value json.RawMessage) {
	p.lock.Lock()
	defer p.lock.Unlock()
	p.accepted = true
	p.value = value
}

func (p *ProbeOps) Approve() {
	p.lock.Lock()
	defer p.lock.Unlock()
	p.approved = true
}

func (p *ProbeOps) Prepare(_ context.Context, op workflow.OpID, _ workflow.RunInput) (workflow.PrepareResult, error) {
	p.count(op)
	return workflow.PrepareResult{TurnLimit: 4, DefinitionID: "definition.probe", DefinitionDigest: ProbeDigest, Version: 2}, nil
}

func (p *ProbeOps) ExecuteTurn(_ context.Context, op workflow.OpID, input workflow.TurnInput) (workflow.TurnResult, error) {
	p.count(op)
	carry := input.Carry
	if p.NeedInput && input.Turn == 0 {
		return workflow.TurnResult{Decision: agent.TurnDecision{Kind: agent.DecisionNeedInput, NeedInput: &agent.NeedInputDecision{Question: "probe question"}}, Carry: carry}, nil
	}
	if p.Delegate && input.Turn == 0 {
		return workflow.TurnResult{Decision: agent.TurnDecision{Kind: agent.DecisionDelegate, Delegate: &agent.DelegateDecision{DelegateID: "definition.probe.specialist", Input: json.RawMessage(`{"task":"draft"}`)}}, Carry: carry}, nil
	}
	return workflow.TurnResult{Decision: agent.TurnDecision{Kind: agent.DecisionFinal, Final: &agent.FinalDecision{Candidate: json.RawMessage(`{"kind":"probe"}`)}}, Carry: carry}, nil
}

func (p *ProbeOps) RecordDecision(_ context.Context, op workflow.OpID, _ workflow.DecisionRecord) (workflow.Ack, error) {
	p.count(op)
	return workflow.Ack{}, nil
}

func (p *ProbeOps) ExecuteAction(_ context.Context, op workflow.OpID, _ workflow.ActionInput) (workflow.ActionResult, error) {
	p.count(op)
	return workflow.ActionResult{}, nil
}

func (p *ProbeOps) OpenDelegation(_ context.Context, op workflow.OpID, input workflow.DelegationInput) (workflow.DelegationOpened, error) {
	p.count(op)
	return workflow.DelegationOpened{TurnLimit: p.DelegateTurns, SpecialistID: "definition.probe.specialist", SpecialistDigest: ProbeDigest, Carry: input.Carry}, nil
}

func (p *ProbeOps) ExecuteDelegateTurn(_ context.Context, op workflow.OpID, input workflow.DelegateTurnInput) (workflow.DelegateTurnResult, error) {
	p.count(op)
	// The delegation concludes on its last bounded turn, so every earlier
	// Specialist turn is a separate durable boundary.
	return workflow.DelegateTurnResult{Done: input.Last, Carry: input.Carry}, nil
}

func (p *ProbeOps) OpenInput(_ context.Context, op workflow.OpID, input workflow.InterruptOpen) (workflow.InterruptOpened, error) {
	p.count(op)
	p.lock.Lock()
	defer p.lock.Unlock()
	if p.inputOpened.IsZero() {
		p.inputOpened = time.Now()
	}
	return workflow.InterruptOpened{RequestID: "request.probe", TimeoutMillis: p.InputTimeout.Milliseconds(), Version: input.Version + 1}, nil
}

func (p *ProbeOps) ReadInput(_ context.Context, op workflow.OpID, _ workflow.InterruptRef) (workflow.InputRead, error) {
	p.count(op)
	p.lock.Lock()
	defer p.lock.Unlock()
	if p.accepted {
		return workflow.InputRead{Accepted: true, Value: p.value, Version: 4}, nil
	}
	if !p.inputOpened.IsZero() && time.Now().After(p.inputOpened.Add(p.InputTimeout)) {
		return workflow.InputRead{Expired: true, Version: 4}, nil
	}
	return workflow.InputRead{RemainingMillis: 100, Version: 4}, nil
}

func (p *ProbeOps) ExpireInterrupt(_ context.Context, op workflow.OpID, _ workflow.ExpireRequest) (workflow.Ack, error) {
	p.count(op)
	return workflow.Ack{Version: 5}, nil
}

func (p *ProbeOps) FinalizeCandidate(_ context.Context, op workflow.OpID, input workflow.FinalizeInput) (workflow.FinalizeResult, error) {
	p.count(op)
	return workflow.FinalizeResult{ArtifactDigest: ProbeDigest, Version: input.Carry.Version + 3}, nil
}

func (p *ProbeOps) ResolveReview(_ context.Context, op workflow.OpID, input workflow.ReviewInput) (workflow.ReviewResult, error) {
	p.count(op)
	if p.Governed {
		return workflow.ReviewResult{RequestID: "approval.probe", TimeoutMillis: p.InputTimeout.Milliseconds(), Version: input.Version + 1}, nil
	}
	return workflow.ReviewResult{Accepted: true, Version: input.Version + 1}, nil
}

func (p *ProbeOps) ReadApproval(_ context.Context, op workflow.OpID, _ workflow.InterruptRef) (workflow.ApprovalRead, error) {
	p.count(op)
	p.lock.Lock()
	defer p.lock.Unlock()
	if p.approved {
		return workflow.ApprovalRead{Decided: true, Kind: "approve", Version: 8}, nil
	}
	return workflow.ApprovalRead{RemainingMillis: 100, Version: 8}, nil
}

func (p *ProbeOps) Revise(_ context.Context, op workflow.OpID, input workflow.ReviseInput) (workflow.Ack, error) {
	p.count(op)
	return workflow.Ack{Version: input.Version + 1}, nil
}

func (p *ProbeOps) Commit(_ context.Context, op workflow.OpID, input workflow.CommitInput) (workflow.CommitResult, error) {
	p.count(op)
	return workflow.CommitResult{Outcome: workflow.CommitCompleted, Version: input.Version + 3}, nil
}

func (p *ProbeOps) Terminalize(_ context.Context, op workflow.OpID, input workflow.TerminalInput) (workflow.Ack, error) {
	p.count(op)
	return workflow.Ack{Version: input.Version + 1}, nil
}

var _ workflow.Operations = (*ProbeOps)(nil)
