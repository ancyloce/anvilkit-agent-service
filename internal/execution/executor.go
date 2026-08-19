// Package execution implements the workflow.Operations pipeline behind the
// durable AgentRunWorkflow: preparation, turns, guarded actions, interrupts,
// validation, review, commit, and terminal recording. Every method is
// idempotent per operation identity and fences on the run's execution
// generation before writing state.
package execution

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/ancyloce/anvilkit-agent-service/internal/agent"
	"github.com/ancyloce/anvilkit-agent-service/internal/agent/runner"
	"github.com/ancyloce/anvilkit-agent-service/internal/canonical"
	"github.com/ancyloce/anvilkit-agent-service/internal/interrupts"
	"github.com/ancyloce/anvilkit-agent-service/internal/journal"
	"github.com/ancyloce/anvilkit-agent-service/internal/problem"
	"github.com/ancyloce/anvilkit-agent-service/internal/runs"
	"github.com/ancyloce/anvilkit-agent-service/internal/workflow"
)

// RunStore is the run-aggregate authority the executor needs: reads and
// compare-and-set transitions. The production Postgres store satisfies it.
type RunStore interface {
	Get(context.Context, runs.Scope, runs.ID) (runs.Snapshot, error)
	Transition(context.Context, runs.Scope, runs.ID, uint64, runs.Command) (runs.Snapshot, error)
}

// InterruptWriter opens durable input and approval requests. The interrupts
// service satisfies it.
type InterruptWriter interface {
	RequestInput(context.Context, interrupts.Write, interrupts.OpenInput) (interrupts.InputRequest, interrupts.OperationResult, error)
	RequestApproval(context.Context, interrupts.Write, interrupts.OpenApproval) (interrupts.ApprovalRequest, interrupts.OperationResult, error)
}

// InterruptReader reads recorded interrupt state. The interrupts repository
// satisfies it.
type InterruptReader interface {
	Input(context.Context, runs.Scope, runs.ID, interrupts.RequestID) (interrupts.InputRequest, error)
	Approval(context.Context, runs.Scope, runs.ID, interrupts.RequestID) (interrupts.ApprovalRequest, error)
}

// AuthorityProvider re-reads current run authority during preparation.
type AuthorityProvider interface {
	Current(context.Context, runs.Scope) (runs.Authority, error)
}

// ToolInvocation is one authorized tool execution. Implementations must be
// idempotent by IdempotencyKey.
type ToolInvocation struct {
	IdempotencyKey string
	ToolID         string
	Arguments      json.RawMessage
	WorkspaceID    string
	ProjectID      string
	RunID          string
}

type ToolResult struct {
	Output json.RawMessage
}

// ToolExecutor executes one guard-approved tool call.
type ToolExecutor interface {
	Execute(context.Context, ToolInvocation) (ToolResult, error)
}

// DomainCommand is one idempotent authoritative domain commit.
type DomainCommand struct {
	OperationID     string
	WorkspaceID     string
	ProjectID       string
	RunID           string
	ArtifactDigest  string
	AuthorizationID string
}

const (
	DomainConfirmed = "confirmed"
	DomainConflict  = "conflict"
	DomainRejected  = "rejected"
)

type DomainOutcome struct {
	Status string
}

// DomainPort submits governed effects to the authoritative domain owner.
type DomainPort interface {
	Commit(context.Context, DomainCommand) (DomainOutcome, error)
}

// AuthorizationRequest asks the commit authority for a durable, single-use
// apply authorization identity bound to the exact action.
type AuthorizationRequest struct {
	IdempotencyKey string
	WorkspaceID    string
	ProjectID      string
	RunID          string
	ArtifactDigest string
	ActionDigest   string
}

type IssuedAuthorization struct {
	AuthorizationID string
}

type CommitAuthority interface {
	Issue(context.Context, AuthorizationRequest) (IssuedAuthorization, error)
}

type Clock interface{ Now() time.Time }

// Config wires the executor. Every dependency is required; the executor
// never substitutes a fallback.
type Config struct {
	Registry          *agent.Registry
	Runner            *runner.Runner
	Runs              RunStore
	InterruptWriter   InterruptWriter
	InterruptReader   InterruptReader
	Authority         AuthorityProvider
	Tools             ToolExecutor
	Domain            DomainPort
	CommitAuthority   CommitAuthority
	Decisions         journal.Store
	Clock             Clock
	InputTTL          time.Duration
	ApprovalTTL       time.Duration
	TurnLimit         int
	ValidatorIdentity string
}

type Executor struct {
	cfg Config
}

// traceparentOf returns the caller trace context or a deterministic derived
// trace identity for internally originated operations.
func traceparentOf(input workflow.RunInput) string {
	if input.Traceparent != "" {
		return input.Traceparent
	}
	return input.Key.DerivedTraceparent()
}

func New(cfg Config) (*Executor, error) {
	if cfg.Registry == nil || cfg.Runner == nil || cfg.Runs == nil || cfg.InterruptWriter == nil || cfg.InterruptReader == nil || cfg.Authority == nil || cfg.Tools == nil || cfg.Domain == nil || cfg.CommitAuthority == nil || cfg.Decisions == nil || cfg.Clock == nil {
		return nil, fmt.Errorf("agent execution: every pipeline dependency is required")
	}
	if cfg.InputTTL <= 0 || cfg.ApprovalTTL <= 0 || cfg.TurnLimit < 1 {
		return nil, fmt.Errorf("agent execution: interrupt deadlines and turn limit must be positive")
	}
	if !validDigestString(cfg.ValidatorIdentity) {
		return nil, fmt.Errorf("agent execution: validator identity must be the pinned contract material digest")
	}
	return &Executor{cfg: cfg}, nil
}

var _ workflow.Operations = (*Executor)(nil)

// load reads the snapshot and fences on execution generation and external
// authority: a mismatched generation or a cancelling/terminal run means
// another authority owns the run and the workflow must exit silently.
func (e *Executor) load(ctx context.Context, input workflow.RunInput) (runs.Snapshot, runs.Scope, bool, error) {
	scope := runs.Scope{WorkspaceID: input.Scope.WorkspaceID, ProjectID: input.Scope.ProjectID, ActorID: input.Scope.ActorID}
	snapshot, err := e.cfg.Runs.Get(ctx, scope, runs.ID(input.Key.RunID))
	if err != nil {
		return runs.Snapshot{}, scope, false, fmt.Errorf("load run aggregate: %w", err)
	}
	if snapshot.ExecutionGeneration != input.Key.Generation {
		return snapshot, scope, true, nil
	}
	switch snapshot.Status {
	case runs.Cancelling, runs.Cancelled, runs.Discarded:
		return snapshot, scope, true, nil
	}
	return snapshot, scope, false, nil
}

// apply performs one compare-and-set transition and converges when recovery
// re-applies a transition that already committed.
func (e *Executor) apply(ctx context.Context, scope runs.Scope, id runs.ID, version uint64, command runs.Command, target runs.State) (runs.Snapshot, bool, error) {
	snapshot, err := e.cfg.Runs.Transition(ctx, scope, id, version, command)
	if err == nil {
		return snapshot, false, nil
	}
	var details problem.Details
	if !errors.As(err, &details) {
		return runs.Snapshot{}, false, err
	}
	if details.Code != string(problem.CodeVersionConflict) && details.Code != string(problem.CodeInvalidTransition) {
		return runs.Snapshot{}, false, err
	}
	current, getErr := e.cfg.Runs.Get(ctx, scope, id)
	if getErr != nil {
		return runs.Snapshot{}, false, fmt.Errorf("converge after transition conflict: %w", getErr)
	}
	if current.Status == target && current.Version == version+1 {
		return current, false, nil
	}
	return current, true, nil
}

func (e *Executor) Prepare(ctx context.Context, op workflow.OpID, input workflow.RunInput) (workflow.PrepareResult, error) {
	snapshot, scope, superseded, err := e.load(ctx, input)
	if err != nil {
		return workflow.PrepareResult{}, err
	}
	if superseded {
		return workflow.PrepareResult{Superseded: true}, nil
	}
	if snapshot.Status == runs.Created {
		next, lost, err := e.apply(ctx, scope, runs.ID(input.Key.RunID), snapshot.Version, runs.Command{Kind: runs.BeginPreparation, Traceparent: traceparentOf(input)}, runs.Preparing)
		if err != nil {
			return workflow.PrepareResult{}, err
		}
		if lost {
			return workflow.PrepareResult{Superseded: true}, nil
		}
		snapshot = next
	}
	authority, err := e.cfg.Authority.Current(ctx, scope)
	if err != nil {
		refusal := problem.New(problem.CodeAuthorityStale, "")
		refusal.Detail = "current authority is unavailable"
		return workflow.PrepareResult{Refused: &refusal, Version: snapshot.Version}, nil
	}
	if !canonicalEqual(authority.ContractBOM, snapshot.ContractBOM) || !canonicalEqual(authority.Policy, snapshot.Policy) {
		refusal := problem.New(problem.CodeAuthorityStale, "")
		refusal.Detail = "pinned run authority no longer matches current authority"
		return workflow.PrepareResult{Refused: &refusal, Version: snapshot.Version}, nil
	}
	definition, refusal := e.resolveDefinition(snapshot)
	if refusal != nil {
		return workflow.PrepareResult{Refused: refusal, Version: snapshot.Version}, nil
	}
	if _, err := parseBudget(snapshot.Budget); err != nil {
		budgetRefusal := problem.New(problem.CodeBudgetDenied, "")
		budgetRefusal.Detail = "pinned agent budget is not decodable"
		return workflow.PrepareResult{Refused: &budgetRefusal, Version: snapshot.Version}, nil
	}
	if snapshot.Status == runs.Preparing {
		next, lost, err := e.apply(ctx, scope, runs.ID(input.Key.RunID), snapshot.Version, runs.Command{Kind: runs.PreparationReady, Traceparent: traceparentOf(input)}, runs.Planning)
		if err != nil {
			return workflow.PrepareResult{}, err
		}
		if lost {
			return workflow.PrepareResult{Superseded: true}, nil
		}
		snapshot = next
	}
	turnLimit := definition.TurnLimit
	if e.cfg.TurnLimit < turnLimit {
		turnLimit = e.cfg.TurnLimit
	}
	return workflow.PrepareResult{TurnLimit: turnLimit, DefinitionID: definition.DefinitionID, DefinitionDigest: definition.DefinitionDigest, Version: snapshot.Version}, nil
}

func (e *Executor) ExecuteTurn(ctx context.Context, op workflow.OpID, input workflow.TurnInput) (workflow.TurnResult, error) {
	snapshot, _, superseded, err := e.load(ctx, input.Run)
	if err != nil {
		return workflow.TurnResult{}, err
	}
	if superseded || !turnStateAllowed(snapshot.Status, input.Phase) {
		return workflow.TurnResult{Superseded: true}, nil
	}
	definition, refusal := e.resolveDefinition(snapshot)
	if refusal != nil {
		return workflow.TurnResult{}, *refusal
	}
	budget, err := parseBudget(snapshot.Budget)
	if err != nil {
		return workflow.TurnResult{}, err
	}
	outcome, err := e.cfg.Runner.Turn(ctx, runner.TurnRequest{
		Definition:      definition,
		Run:             runView(snapshot),
		Phase:           phaseName(input.Phase),
		Turn:            input.Turn,
		Depth:           0,
		Notes:           input.Carry.Notes,
		InputValue:      input.Carry.InputValue,
		ReviewReason:    input.Carry.ReviewReason,
		DelegationsUsed: input.Carry.Delegations,
		Budget:          budget.remaining(input.Carry.Usage),
	})
	if err != nil {
		return workflow.TurnResult{}, err
	}
	carry := input.Carry
	carry.Usage = carry.Usage.Add(outcome.Usage)
	carry.Notes = boundNotes(append(carry.Notes, outcome.Notes...))
	carry.Version = snapshot.Version
	if outcome.Halted != nil {
		return workflow.TurnResult{Carry: carry, Halt: haltOf(*outcome.Halted)}, nil
	}
	return workflow.TurnResult{Decision: outcome.Decision, Carry: carry}, nil
}

func (e *Executor) RecordDecision(ctx context.Context, op workflow.OpID, record workflow.DecisionRecord) (workflow.Ack, error) {
	payload, err := json.Marshal(struct {
		Op       workflow.OpID      `json:"op"`
		RunID    string             `json:"runId"`
		Turn     int                `json:"turn"`
		Phase    workflow.Phase     `json:"phase"`
		Decision agent.TurnDecision `json:"decision"`
	}{op, record.Run.Key.RunID, record.Turn, record.Phase, record.Decision})
	if err != nil {
		return workflow.Ack{}, fmt.Errorf("marshal turn decision record: %w", err)
	}
	canonicalPayload, err := canonical.Bytes(payload)
	if err != nil {
		return workflow.Ack{}, fmt.Errorf("canonicalize turn decision record: %w", err)
	}
	fact, err := journal.NewFact(op.Key()+":decision", record.Run.Scope.WorkspaceID, record.Run.Scope.ProjectID, journal.FactDecision, canonicalPayload, nil)
	if err != nil {
		return workflow.Ack{}, err
	}
	if _, err := e.cfg.Decisions.Append(ctx, fact); err != nil {
		return workflow.Ack{}, fmt.Errorf("record turn decision durably: %w", err)
	}
	return workflow.Ack{}, nil
}

func (e *Executor) ExecuteAction(ctx context.Context, op workflow.OpID, input workflow.ActionInput) (workflow.ActionResult, error) {
	snapshot, _, superseded, err := e.load(ctx, input.Run)
	if err != nil {
		return workflow.ActionResult{}, err
	}
	if superseded || !turnStateAllowed(snapshot.Status, input.Phase) {
		return workflow.ActionResult{Superseded: true}, nil
	}
	definition, refusal := e.resolveDefinition(snapshot)
	if refusal != nil {
		return workflow.ActionResult{}, *refusal
	}
	budget, err := parseBudget(snapshot.Budget)
	if err != nil {
		return workflow.ActionResult{}, err
	}
	carry := input.Carry
	carry.Version = snapshot.Version
	switch input.Decision.Kind {
	case agent.DecisionToolCall:
		proposal := *input.Decision.ToolCall
		decision, err := e.cfg.Runner.GuardAction(ctx, definition, runView(snapshot), proposal)
		if err != nil {
			var details problem.Details
			if errors.As(err, &details) && details.Code == string(problem.CodeToolDispatchDenied) {
				// The denial is durable: the guard recorded it, this step
				// checkpoints it, and the next turn observes it.
				carry.Notes = boundNotes(append(carry.Notes, "tool denied ("+decision.Code+"): "+proposal.ToolID))
				return workflow.ActionResult{Carry: carry}, nil
			}
			return workflow.ActionResult{}, err
		}
		result, err := e.cfg.Tools.Execute(ctx, ToolInvocation{
			IdempotencyKey: op.Key(),
			ToolID:         proposal.ToolID,
			Arguments:      proposal.Arguments,
			WorkspaceID:    snapshot.WorkspaceID,
			ProjectID:      snapshot.Target.ProjectID,
			RunID:          string(snapshot.RunID),
		})
		if err != nil {
			return workflow.ActionResult{}, fmt.Errorf("execute authorized tool: %w", err)
		}
		carry.Notes = boundNotes(append(carry.Notes, "tool "+proposal.ToolID+" output: "+truncate(string(result.Output), 2048)))
		return workflow.ActionResult{Carry: carry}, nil
	case agent.DecisionDelegate:
		outcome, err := e.cfg.Runner.Delegate(ctx, runner.DelegateRequest{
			Parent:          definition,
			Decision:        *input.Decision.Delegate,
			Run:             runView(snapshot),
			Depth:           0,
			DelegationsUsed: carry.Delegations,
			Notes:           carry.Notes,
			Budget:          budget.remaining(carry.Usage),
		})
		if err != nil {
			return workflow.ActionResult{}, err
		}
		carry.Usage = carry.Usage.Add(outcome.Usage)
		carry.Delegations++
		carry.Notes = boundNotes(append(carry.Notes, outcome.Notes...))
		if outcome.Halted != nil {
			return workflow.ActionResult{Carry: carry, Halt: haltOf(*outcome.Halted)}, nil
		}
		if outcome.Refused != nil {
			carry.Notes = boundNotes(append(carry.Notes, "delegation refused: "+outcome.Refused.Code))
			return workflow.ActionResult{Carry: carry}, nil
		}
		carry.Notes = boundNotes(append(carry.Notes, "specialist candidate: "+truncate(string(outcome.Candidate), 4096)))
		return workflow.ActionResult{Carry: carry}, nil
	default:
		details := problem.Internal("")
		details.Detail = "action requires a tool call or delegation decision"
		return workflow.ActionResult{}, details
	}
}

func (e *Executor) OpenInput(ctx context.Context, op workflow.OpID, input workflow.InterruptOpen) (workflow.InterruptOpened, error) {
	snapshot, scope, superseded, err := e.load(ctx, input.Run)
	if err != nil {
		return workflow.InterruptOpened{}, err
	}
	if superseded {
		return workflow.InterruptOpened{Superseded: true}, nil
	}
	now := e.cfg.Clock.Now()
	digest, err := deterministicDigest(struct {
		Op       workflow.OpID `json:"op"`
		Question string        `json:"question"`
		Version  uint64        `json:"version"`
	}{op, input.Question, input.Version})
	if err != nil {
		return workflow.InterruptOpened{}, err
	}
	request, result, err := e.cfg.InterruptWriter.RequestInput(ctx, interrupts.Write{
		Scope:           scope,
		RunID:           runs.ID(input.Run.Key.RunID),
		ExpectedVersion: input.Version,
		IdempotencyKey:  op.Key(),
		CanonicalDigest: digest,
		Traceparent:     traceparentOf(input.Run),
	}, interrupts.OpenInput{
		Question:         input.Question,
		ResponseSchema:   json.RawMessage(`{"type":"object","required":["answer"],"properties":{"answer":{"type":"string","maxLength":4096}},"additionalProperties":false}`),
		ExpiresAt:        now.Add(e.cfg.InputTTL),
		ResumeCheckpoint: op.Step,
	})
	if err != nil {
		var details problem.Details
		if errors.As(err, &details) && details.Code == string(problem.CodeVersionConflict) {
			_ = snapshot
			return workflow.InterruptOpened{Superseded: true}, nil
		}
		return workflow.InterruptOpened{}, err
	}
	timeout := request.ExpiresAt.Sub(now)
	if timeout < time.Millisecond {
		timeout = time.Millisecond
	}
	return workflow.InterruptOpened{RequestID: string(request.ID), TimeoutMillis: timeout.Milliseconds(), Version: result.Snapshot.Version}, nil
}

func (e *Executor) ReadInput(ctx context.Context, op workflow.OpID, ref workflow.InterruptRef) (workflow.InputRead, error) {
	snapshot, scope, superseded, err := e.load(ctx, ref.Run)
	if err != nil {
		return workflow.InputRead{}, err
	}
	if superseded {
		return workflow.InputRead{Superseded: true}, nil
	}
	request, err := e.cfg.InterruptReader.Input(ctx, scope, runs.ID(ref.Run.Key.RunID), interrupts.RequestID(ref.RequestID))
	if err != nil {
		return workflow.InputRead{}, fmt.Errorf("read input request: %w", err)
	}
	now := e.cfg.Clock.Now()
	read := workflow.InputRead{Version: snapshot.Version}
	if request.Response != nil {
		read.Accepted = true
		read.Value = request.Response.Value
		return read, nil
	}
	if !now.Before(request.ExpiresAt) {
		read.Expired = true
		return read, nil
	}
	read.RemainingMillis = remainingMillis(request.ExpiresAt, now)
	return read, nil
}

func (e *Executor) ReadApproval(ctx context.Context, op workflow.OpID, ref workflow.InterruptRef) (workflow.ApprovalRead, error) {
	snapshot, scope, superseded, err := e.load(ctx, ref.Run)
	if err != nil {
		return workflow.ApprovalRead{}, err
	}
	if superseded {
		return workflow.ApprovalRead{Superseded: true}, nil
	}
	request, err := e.cfg.InterruptReader.Approval(ctx, scope, runs.ID(ref.Run.Key.RunID), interrupts.RequestID(ref.RequestID))
	if err != nil {
		return workflow.ApprovalRead{}, fmt.Errorf("read approval request: %w", err)
	}
	now := e.cfg.Clock.Now()
	read := workflow.ApprovalRead{Version: snapshot.Version}
	if request.Decision != nil {
		read.Decided = true
		read.Kind = string(request.Decision.Kind)
		read.Reason = request.Decision.Reason
		return read, nil
	}
	if !now.Before(request.ExpiresAt) {
		read.Expired = true
		return read, nil
	}
	read.RemainingMillis = remainingMillis(request.ExpiresAt, now)
	return read, nil
}

func (e *Executor) ExpireInterrupt(ctx context.Context, op workflow.OpID, expire workflow.ExpireRequest) (workflow.Ack, error) {
	snapshot, scope, superseded, err := e.load(ctx, expire.Run)
	if err != nil {
		return workflow.Ack{}, err
	}
	if superseded {
		return workflow.Ack{Superseded: true}, nil
	}
	// A response or decision accepted before the deadline wins over expiry.
	if expire.Kind == "input" {
		request, err := e.cfg.InterruptReader.Input(ctx, scope, runs.ID(expire.Run.Key.RunID), interrupts.RequestID(expire.RequestID))
		if err != nil {
			return workflow.Ack{}, err
		}
		if request.Response != nil {
			return workflow.Ack{Raced: true, Version: snapshot.Version}, nil
		}
	} else {
		request, err := e.cfg.InterruptReader.Approval(ctx, scope, runs.ID(expire.Run.Key.RunID), interrupts.RequestID(expire.RequestID))
		if err != nil {
			return workflow.Ack{}, err
		}
		if request.Decision != nil {
			return workflow.Ack{Raced: true, Version: snapshot.Version}, nil
		}
	}
	code := problem.CodeInputRequestExpired
	if expire.Kind == "approval" {
		code = problem.CodeApprovalRequestExpired
	}
	failure := problem.New(code, "")
	failure.Detail = "the durable " + expire.Kind + " deadline elapsed before a response was accepted"
	next, lost, err := e.apply(ctx, scope, runs.ID(expire.Run.Key.RunID), snapshot.Version, runs.Command{Kind: runs.RecordFailure, Failure: &failure, Traceparent: traceparentOf(expire.Run)}, runs.Failed)
	if err != nil {
		return workflow.Ack{}, err
	}
	if lost {
		return workflow.Ack{Superseded: true}, nil
	}
	return workflow.Ack{Version: next.Version}, nil
}

func (e *Executor) FinalizeCandidate(ctx context.Context, op workflow.OpID, input workflow.FinalizeInput) (workflow.FinalizeResult, error) {
	snapshot, scope, superseded, err := e.load(ctx, input.Run)
	if err != nil {
		return workflow.FinalizeResult{}, err
	}
	if superseded {
		return workflow.FinalizeResult{Superseded: true}, nil
	}
	definition, refusal := e.resolveDefinition(snapshot)
	if refusal != nil {
		return workflow.FinalizeResult{}, *refusal
	}
	id := runs.ID(input.Run.Key.RunID)
	if snapshot.Status == runs.Planning {
		next, lost, err := e.apply(ctx, scope, id, snapshot.Version, runs.Command{Kind: runs.BeginExecution, Traceparent: traceparentOf(input.Run)}, runs.Executing)
		if err != nil {
			return workflow.FinalizeResult{}, err
		}
		if lost {
			return workflow.FinalizeResult{Superseded: true}, nil
		}
		snapshot = next
	}
	if snapshot.Status == runs.Executing {
		next, lost, err := e.apply(ctx, scope, id, snapshot.Version, runs.Command{Kind: runs.BeginValidation, Traceparent: traceparentOf(input.Run)}, runs.Validating)
		if err != nil {
			return workflow.FinalizeResult{}, err
		}
		if lost {
			return workflow.FinalizeResult{Superseded: true}, nil
		}
		snapshot = next
	}
	candidate := input.Decision.Final.Candidate
	if err := e.cfg.Runner.ValidateCandidate(ctx, definition, candidate); err != nil {
		rejected := problem.New(problem.CodeContractInvalid, "")
		rejected.Detail = "final candidate violates the pinned output schema"
		return workflow.FinalizeResult{Rejected: &rejected, Version: snapshot.Version}, nil
	}
	artifactDigest, err := canonical.Digest(candidate)
	if err != nil {
		rejected := problem.New(problem.CodeContractInvalid, "")
		rejected.Detail = "final candidate is not canonicalizable"
		return workflow.FinalizeResult{Rejected: &rejected, Version: snapshot.Version}, nil
	}
	bom, err := bomDigest(snapshot.ContractBOM)
	if err != nil {
		return workflow.FinalizeResult{}, err
	}
	if snapshot.Status == runs.Validating {
		proof := runs.ValidationProof{Valid: true, BOMDigest: bom, SchemaDigest: definition.OutputSchema.Digest, ValidatorVersion: e.cfg.ValidatorIdentity, CatalogDigest: definition.DefinitionDigest}
		next, lost, err := e.apply(ctx, scope, id, snapshot.Version, runs.Command{Kind: runs.SubmitForReview, Validation: proof, Traceparent: traceparentOf(input.Run)}, runs.AwaitingReview)
		if err != nil {
			return workflow.FinalizeResult{}, err
		}
		if lost {
			return workflow.FinalizeResult{Superseded: true}, nil
		}
		snapshot = next
	}
	return workflow.FinalizeResult{ArtifactDigest: artifactDigest, Version: snapshot.Version}, nil
}

func (e *Executor) ResolveReview(ctx context.Context, op workflow.OpID, input workflow.ReviewInput) (workflow.ReviewResult, error) {
	snapshot, scope, superseded, err := e.load(ctx, input.Run)
	if err != nil {
		return workflow.ReviewResult{}, err
	}
	if superseded {
		return workflow.ReviewResult{Superseded: true}, nil
	}
	definition, refusal := e.resolveDefinition(snapshot)
	if refusal != nil {
		return workflow.ReviewResult{}, *refusal
	}
	id := runs.ID(input.Run.Key.RunID)
	if !governedEffect(snapshot) {
		next, lost, err := e.apply(ctx, scope, id, input.Version, runs.Command{Kind: runs.AcceptArtifact, Traceparent: traceparentOf(input.Run)}, runs.Completed)
		if err != nil {
			return workflow.ReviewResult{}, err
		}
		if lost {
			return workflow.ReviewResult{Superseded: true}, nil
		}
		return workflow.ReviewResult{Accepted: true, Version: next.Version}, nil
	}
	now := e.cfg.Clock.Now()
	digest, err := deterministicDigest(struct {
		Op             workflow.OpID `json:"op"`
		ArtifactDigest string        `json:"artifactDigest"`
		Version        uint64        `json:"version"`
	}{op, input.ArtifactDigest, input.Version})
	if err != nil {
		return workflow.ReviewResult{}, err
	}
	reviewerPolicy, err := json.Marshal(struct {
		PolicyID string `json:"policyId"`
		Version  string `json:"version"`
		Digest   string `json:"digest"`
	}{definition.GuardrailPolicy.PolicyID, definition.GuardrailPolicy.Version, definition.GuardrailPolicy.Digest})
	if err != nil {
		return workflow.ReviewResult{}, err
	}
	request, result, err := e.cfg.InterruptWriter.RequestApproval(ctx, interrupts.Write{
		Scope:           scope,
		RunID:           id,
		ExpectedVersion: input.Version,
		IdempotencyKey:  op.Key(),
		CanonicalDigest: digest,
		Traceparent:     traceparentOf(input.Run),
	}, interrupts.OpenApproval{
		ActionDigest:     input.ArtifactDigest,
		Effects:          json.RawMessage(`["domain-effect"]`),
		ExpectedCost:     json.RawMessage(`{"amount":"0","currency":"USD"}`),
		ReviewerPolicy:   reviewerPolicy,
		ExpiresAt:        now.Add(e.cfg.ApprovalTTL),
		ResumeCheckpoint: op.Step,
	})
	if err != nil {
		var details problem.Details
		if errors.As(err, &details) && details.Code == string(problem.CodeVersionConflict) {
			return workflow.ReviewResult{Superseded: true}, nil
		}
		return workflow.ReviewResult{}, err
	}
	timeout := request.ExpiresAt.Sub(now)
	if timeout < time.Millisecond {
		timeout = time.Millisecond
	}
	return workflow.ReviewResult{RequestID: string(request.ID), TimeoutMillis: timeout.Milliseconds(), Version: result.Snapshot.Version}, nil
}

func (e *Executor) Revise(ctx context.Context, op workflow.OpID, input workflow.ReviseInput) (workflow.Ack, error) {
	snapshot, scope, superseded, err := e.load(ctx, input.Run)
	if err != nil {
		return workflow.Ack{}, err
	}
	if superseded {
		return workflow.Ack{Superseded: true}, nil
	}
	kind := runs.Revise
	if input.FromConflict {
		kind = runs.Rebase
	}
	next, lost, err := e.apply(ctx, scope, runs.ID(input.Run.Key.RunID), input.Version, runs.Command{Kind: kind, Traceparent: traceparentOf(input.Run)}, runs.Executing)
	if err != nil {
		return workflow.Ack{}, err
	}
	if lost {
		_ = snapshot
		return workflow.Ack{Superseded: true}, nil
	}
	return workflow.Ack{Version: next.Version}, nil
}

func (e *Executor) Commit(ctx context.Context, op workflow.OpID, input workflow.CommitInput) (workflow.CommitResult, error) {
	snapshot, scope, superseded, err := e.load(ctx, input.Run)
	if err != nil {
		return workflow.CommitResult{}, err
	}
	if superseded {
		return workflow.CommitResult{Superseded: true}, nil
	}
	id := runs.ID(input.Run.Key.RunID)
	// Recovery convergence: a crash after the terminal domain transition
	// re-executes this operation against an already-settled aggregate.
	switch snapshot.Status {
	case runs.Completed:
		return workflow.CommitResult{Outcome: workflow.CommitCompleted, Version: snapshot.Version}, nil
	case runs.Conflict:
		return workflow.CommitResult{Outcome: workflow.CommitConflict, Version: snapshot.Version}, nil
	case runs.Failed:
		failure := problem.New(problem.CodeDomainRejected, "")
		if snapshot.Problem != nil {
			failure = *snapshot.Problem
		}
		return workflow.CommitResult{Outcome: workflow.CommitFailed, Problem: &failure, Version: snapshot.Version}, nil
	}
	approval, err := e.cfg.InterruptReader.Approval(ctx, scope, id, interrupts.RequestID(input.RequestID))
	if err != nil {
		return workflow.CommitResult{}, fmt.Errorf("recheck approval before commit: %w", err)
	}
	if approval.Decision == nil || approval.Decision.Kind != interrupts.DecisionApprove {
		denied := problem.New(problem.CodeApplyAuthorizationDenied, "")
		denied.Detail = "commit requires a current approve decision"
		return workflow.CommitResult{}, denied
	}
	issued, err := e.cfg.CommitAuthority.Issue(ctx, AuthorizationRequest{
		IdempotencyKey: op.Key(),
		WorkspaceID:    snapshot.WorkspaceID,
		ProjectID:      snapshot.Target.ProjectID,
		RunID:          string(id),
		ArtifactDigest: input.ArtifactDigest,
		ActionDigest:   approval.ActionDigest,
	})
	if err != nil {
		return workflow.CommitResult{}, fmt.Errorf("issue commit authorization: %w", err)
	}
	operationID := "domain." + strings.TrimPrefix(mustDeterministicDigest(op), "sha256:")[:32]
	version := snapshot.Version
	if snapshot.Status == runs.AwaitingApproval {
		proof := runs.CommitProof{
			ApprovalRechecked:    true,
			ArtifactEligible:     true,
			ActionBindingExact:   approval.ActionDigest == input.ArtifactDigest,
			AuthorizationDurable: true,
			AuthorizationID:      issued.AuthorizationID,
			DomainOperationID:    operationID,
			ActionDigest:         approval.ActionDigest,
			ArtifactDigest:       input.ArtifactDigest,
		}
		next, lost, err := e.apply(ctx, scope, id, version, runs.Command{Kind: runs.Approve, Commit: proof, Traceparent: traceparentOf(input.Run)}, runs.Committing)
		if err != nil {
			return workflow.CommitResult{}, err
		}
		if lost {
			return workflow.CommitResult{Superseded: true}, nil
		}
		snapshot = next
	}
	if snapshot.Status == runs.Committing {
		next, lost, err := e.apply(ctx, scope, id, snapshot.Version, runs.Command{Kind: runs.BeginDomainConfirmation, Traceparent: traceparentOf(input.Run)}, runs.AwaitingDomainConfirmation)
		if err != nil {
			return workflow.CommitResult{}, err
		}
		if lost {
			return workflow.CommitResult{Superseded: true}, nil
		}
		snapshot = next
	}
	outcome, err := e.cfg.Domain.Commit(ctx, DomainCommand{
		OperationID:     operationID,
		WorkspaceID:     snapshot.WorkspaceID,
		ProjectID:       snapshot.Target.ProjectID,
		RunID:           string(id),
		ArtifactDigest:  input.ArtifactDigest,
		AuthorizationID: issued.AuthorizationID,
	})
	if err != nil {
		return workflow.CommitResult{}, fmt.Errorf("submit governed domain effect: %w", err)
	}
	switch outcome.Status {
	case DomainConfirmed:
		next, lost, err := e.apply(ctx, scope, id, snapshot.Version, runs.Command{Kind: runs.ConfirmDomain, Traceparent: traceparentOf(input.Run)}, runs.Completed)
		if err != nil {
			return workflow.CommitResult{}, err
		}
		if lost {
			return workflow.CommitResult{Superseded: true}, nil
		}
		return workflow.CommitResult{Outcome: workflow.CommitCompleted, Version: next.Version}, nil
	case DomainConflict:
		next, lost, err := e.apply(ctx, scope, id, snapshot.Version, runs.Command{Kind: runs.RecordDomainConflict, Traceparent: traceparentOf(input.Run)}, runs.Conflict)
		if err != nil {
			return workflow.CommitResult{}, err
		}
		if lost {
			return workflow.CommitResult{Superseded: true}, nil
		}
		return workflow.CommitResult{Outcome: workflow.CommitConflict, Version: next.Version}, nil
	case DomainRejected:
		failure := problem.New(problem.CodeDomainRejected, "")
		failure.Retryability = "never"
		failure.Detail = "the authoritative domain owner rejected the governed effect"
		next, lost, err := e.apply(ctx, scope, id, snapshot.Version, runs.Command{Kind: runs.RecordDomainRejection, Failure: &failure, Traceparent: traceparentOf(input.Run)}, runs.Failed)
		if err != nil {
			return workflow.CommitResult{}, err
		}
		if lost {
			return workflow.CommitResult{Superseded: true}, nil
		}
		return workflow.CommitResult{Outcome: workflow.CommitFailed, Problem: &failure, Version: next.Version}, nil
	default:
		uncertain := problem.New(problem.CodeDomainOutcomeUncertain, "")
		uncertain.Detail = "domain outcome is uncertain; resolution requires the authoritative effect record"
		return workflow.CommitResult{}, uncertain
	}
}

func (e *Executor) Terminalize(ctx context.Context, op workflow.OpID, input workflow.TerminalInput) (workflow.Ack, error) {
	snapshot, scope, superseded, err := e.load(ctx, input.Run)
	if err != nil {
		return workflow.Ack{}, err
	}
	if superseded {
		return workflow.Ack{Superseded: true}, nil
	}
	target := runs.Failed
	kind := runs.RecordFailure
	if input.Kind == workflow.TerminalRefused && refusalLegal(snapshot.Status) {
		target = runs.Refused
		kind = runs.RecordRefusal
	}
	if snapshot.Status == target {
		return workflow.Ack{Version: snapshot.Version}, nil
	}
	command := runs.Command{Kind: kind, Traceparent: traceparentOf(input.Run)}
	if kind == runs.RecordFailure {
		failure := problem.Internal("")
		if input.Problem != nil {
			failure = *input.Problem
		}
		command.Failure = &failure
	}
	next, lost, err := e.apply(ctx, scope, runs.ID(input.Run.Key.RunID), snapshot.Version, command, target)
	if err != nil {
		return workflow.Ack{}, err
	}
	if lost {
		return workflow.Ack{Superseded: true}, nil
	}
	return workflow.Ack{Version: next.Version}, nil
}

func (e *Executor) resolveDefinition(snapshot runs.Snapshot) (agent.Definition, *problem.Details) {
	reference, err := agent.ParseDefinitionReference(snapshot.Definition)
	if err != nil {
		details := problem.New(problem.CodeContractInvalid, "")
		details.Detail = "run definition reference is not decodable"
		return agent.Definition{}, &details
	}
	definition, err := e.cfg.Registry.Resolve(reference)
	if err != nil {
		var details problem.Details
		if errors.As(err, &details) {
			return agent.Definition{}, &details
		}
		details = problem.New(problem.CodeContractInvalid, "")
		details.Detail = "run definition is not resolvable"
		return agent.Definition{}, &details
	}
	return definition, nil
}

// budgetLimits is the decoded pinned AgentBudget.
type budgetLimits struct {
	MaximumModelCalls   int64
	MaximumInputTokens  int64
	MaximumOutputTokens int64
	MaximumCostMicros   int64
	ExceedBehavior      string
}

func (b budgetLimits) remaining(used agent.Usage) runner.BudgetView {
	return runner.BudgetView{
		RemainingModelCalls:   b.MaximumModelCalls - used.ModelCalls,
		RemainingInputTokens:  b.MaximumInputTokens - used.InputTokens,
		RemainingOutputTokens: b.MaximumOutputTokens - used.OutputTokens,
		RemainingCostMicros:   b.MaximumCostMicros - used.CostMicros,
		ExceedBehavior:        b.ExceedBehavior,
	}
}

func parseBudget(raw json.RawMessage) (budgetLimits, error) {
	var document struct {
		Kind        string `json:"kind"`
		ModelLimits struct {
			MaximumCalls           int64 `json:"maximumCalls"`
			MaximumConcurrentCalls int64 `json:"maximumConcurrentCalls"`
		} `json:"modelLimits"`
		TokenLimits struct {
			InputTokens  int64 `json:"inputTokens"`
			OutputTokens int64 `json:"outputTokens"`
			TotalTokens  int64 `json:"totalTokens"`
		} `json:"tokenLimits"`
		WorkerLimits   json.RawMessage `json:"workerLimits"`
		GPULimits      json.RawMessage `json:"gpuLimits"`
		CurrencyLimits struct {
			MaximumCost struct {
				Amount   string `json:"amount"`
				Currency string `json:"currency"`
			} `json:"maximumCost"`
			ReservedCost json.RawMessage `json:"reservedCost"`
		} `json:"currencyLimits"`
		ReservationID  string          `json:"reservationId"`
		ExceedBehavior string          `json:"exceedBehavior"`
		Policy         json.RawMessage `json:"policy"`
	}
	if err := json.Unmarshal(raw, &document); err != nil {
		return budgetLimits{}, fmt.Errorf("decode pinned agent budget: %w", err)
	}
	if document.Kind != "AgentBudget" {
		return budgetLimits{}, fmt.Errorf("pinned budget kind must be AgentBudget")
	}
	costMicros, err := decimalMicros(document.CurrencyLimits.MaximumCost.Amount)
	if err != nil {
		return budgetLimits{}, fmt.Errorf("decode pinned budget cost: %w", err)
	}
	switch document.ExceedBehavior {
	case "refuse", "pause-for-approval", "cancel":
	default:
		return budgetLimits{}, fmt.Errorf("pinned budget exceed behavior is outside the frozen vocabulary")
	}
	return budgetLimits{
		MaximumModelCalls:   document.ModelLimits.MaximumCalls,
		MaximumInputTokens:  document.TokenLimits.InputTokens,
		MaximumOutputTokens: document.TokenLimits.OutputTokens,
		MaximumCostMicros:   costMicros,
		ExceedBehavior:      document.ExceedBehavior,
	}, nil
}

// decimalMicros converts a bounded decimal currency string into micros.
func decimalMicros(amount string) (int64, error) {
	if amount == "" || len(amount) > 20 {
		return 0, fmt.Errorf("amount is required and bounded")
	}
	whole, fraction, split := strings.Cut(amount, ".")
	units, err := strconv.ParseInt(whole, 10, 64)
	if err != nil || units < 0 {
		return 0, fmt.Errorf("amount must be a non-negative decimal")
	}
	micros := units * 1_000_000
	if split {
		if fraction == "" || len(fraction) > 6 {
			return 0, fmt.Errorf("amount fraction must contain 1-6 digits")
		}
		padded := fraction + strings.Repeat("0", 6-len(fraction))
		part, err := strconv.ParseInt(padded, 10, 64)
		if err != nil || part < 0 {
			return 0, fmt.Errorf("amount fraction must be numeric")
		}
		micros += part
	}
	return micros, nil
}

func turnStateAllowed(state runs.State, phase workflow.Phase) bool {
	if phase == workflow.PhaseRevise {
		return state == runs.Executing
	}
	return state == runs.Planning
}

func phaseName(phase workflow.Phase) string {
	if phase == workflow.PhaseRevise {
		return runner.PhaseRevise
	}
	return runner.PhasePlan
}

func governedEffect(snapshot runs.Snapshot) bool {
	return snapshot.Operation == "page-change"
}

func refusalLegal(state runs.State) bool {
	return state == runs.Preparing || state == runs.Planning || state == runs.Validating
}

func runView(snapshot runs.Snapshot) runner.RunView {
	return runner.RunView{
		RunID:       string(snapshot.RunID),
		WorkspaceID: snapshot.WorkspaceID,
		ProjectID:   snapshot.Target.ProjectID,
		ActorID:     snapshot.ActorID,
		Domain:      snapshot.Domain,
		Operation:   snapshot.Operation,
		TargetType:  snapshot.Target.Type,
		TargetID:    snapshot.Target.ID,
	}
}

func haltOf(halted runner.Halted) *workflow.Halt {
	behavior := workflow.TerminalFailed
	if halted.Refuse {
		behavior = workflow.TerminalRefused
	}
	return &workflow.Halt{Problem: halted.Problem, Behavior: behavior}
}

func bomDigest(raw json.RawMessage) (string, error) {
	var reference struct {
		Repository             string `json:"repository"`
		BOMDigest              string `json:"bomDigest"`
		OCIManifestDigest      string `json:"ociManifestDigest"`
		EvidenceManifestDigest string `json:"evidenceManifestDigest"`
	}
	if err := json.Unmarshal(raw, &reference); err != nil {
		return "", fmt.Errorf("decode pinned contract BOM reference: %w", err)
	}
	if !validDigestString(reference.BOMDigest) {
		return "", fmt.Errorf("pinned contract BOM digest is invalid")
	}
	return reference.BOMDigest, nil
}

func canonicalEqual(left, right json.RawMessage) bool {
	leftDigest, leftErr := canonical.Digest(left)
	rightDigest, rightErr := canonical.Digest(right)
	return leftErr == nil && rightErr == nil && leftDigest == rightDigest
}

func deterministicDigest(value any) (string, error) {
	raw, err := json.Marshal(value)
	if err != nil {
		return "", err
	}
	return canonical.Digest(raw)
}

func mustDeterministicDigest(value any) string {
	digest, err := deterministicDigest(value)
	if err != nil {
		return "sha256:0000000000000000000000000000000000000000000000000000000000000000"
	}
	return digest
}

func remainingMillis(deadline, now time.Time) int64 {
	remaining := deadline.Sub(now).Milliseconds()
	if remaining < 1 {
		return 1
	}
	return remaining
}

func boundNotes(notes []string) []string {
	const maximumNotes = 24
	bounded := notes
	if len(bounded) > maximumNotes {
		bounded = bounded[len(bounded)-maximumNotes:]
	}
	out := make([]string, 0, len(bounded))
	for _, note := range bounded {
		out = append(out, truncate(note, 4096))
	}
	return out
}

func truncate(value string, maximum int) string {
	if len(value) <= maximum {
		return value
	}
	return value[:maximum]
}

func validDigestString(value string) bool {
	if len(value) != 71 || value[:7] != "sha256:" {
		return false
	}
	for _, character := range value[7:] {
		if !(character >= '0' && character <= '9' || character >= 'a' && character <= 'f') {
			return false
		}
	}
	return true
}
