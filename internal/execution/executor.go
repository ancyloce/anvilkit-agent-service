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
	"github.com/ancyloce/anvilkit-agent-service/internal/authority"
	"github.com/ancyloce/anvilkit-agent-service/internal/canonical"
	"github.com/ancyloce/anvilkit-agent-service/internal/interrupts"
	"github.com/ancyloce/anvilkit-agent-service/internal/journal"
	"github.com/ancyloce/anvilkit-agent-service/internal/problem"
	"github.com/ancyloce/anvilkit-agent-service/internal/runs"
	"github.com/ancyloce/anvilkit-agent-service/internal/tools"
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

// InterruptExpirer settles a durable interrupt deadline atomically. The
// interrupts repository satisfies it. Expiry must never be a read followed
// by a separate compare-and-set: an accepted response arriving between the
// two would leave the run neither expired nor driven by any workflow.
type InterruptExpirer interface {
	ExpireInput(context.Context, interrupts.Write, interrupts.RequestID, problem.Details, time.Time) (interrupts.Expiry, error)
	ExpireApproval(context.Context, interrupts.Write, interrupts.RequestID, problem.Details, time.Time) (interrupts.Expiry, error)
}

// AuthorityProvider is the single current-authority port the whole runtime
// shares. The executor re-reads it inside every durable operation that
// discloses context to a model or causes an external effect, and passes the
// observation it just read into the runner instead of letting any component
// keep a private authority view.
type AuthorityProvider = authority.Source

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

// DomainUnsettled is the answer of an authoritative domain owner that has a
// record of the operation but has not yet decided it.
const DomainUnsettled = "unsettled"

type DomainOutcome struct {
	Status string
}

// DomainQuery reads the authoritative record of one already-submitted
// governed effect by the operation identity it was submitted under.
type DomainQuery struct {
	OperationID string
	WorkspaceID string
	ProjectID   string
	RunID       string
}

// DomainPort submits governed effects to the authoritative domain owner and
// reads back what became of them. Reconcile is what makes a crash or an
// uncertain answer after submission recoverable: the owner's record, not the
// workflow's belief, decides whether an effect happened. found is false only
// when the owner has no record of the operation at all, which is the one
// answer that proves nothing landed.
type DomainPort interface {
	Commit(context.Context, DomainCommand) (DomainOutcome, error)
	Reconcile(context.Context, DomainQuery) (DomainOutcome, bool, error)
}

// ArtifactQuery identifies the candidate artifact a commit would publish.
type ArtifactQuery struct {
	WorkspaceID    string
	ProjectID      string
	RunID          string
	ArtifactDigest string
}

// ArtifactEligibility is the authoritative answer to whether the candidate
// artifact may still be the subject of a governed effect. Quarantine,
// deletion, expiry, and legal hold all make it ineligible.
type ArtifactEligibility struct {
	Eligible bool
	Reason   string
}

// ToolMaterial exposes the Tool material the service is actually running for
// one Tool component: the digest of its argument schema and the complete
// ToolDefinition the process would dispatch. It is how a run proves the Tool
// material in the process is the material its definition froze — all of it,
// not just the argument schema.
type ToolMaterial interface {
	ComponentDigest(componentName string) (string, bool)
	ToolDefinition(componentName string) (tools.Definition, bool)
}

// ArtifactPort answers artifact eligibility. The executor never infers
// eligibility from run state: the artifact owner answers, and an ineligible
// answer stops the commit before any authorization is issued.
type ArtifactPort interface {
	Eligible(context.Context, ArtifactQuery) (ArtifactEligibility, error)
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
	InterruptExpirer  InterruptExpirer
	Authority         AuthorityProvider
	Tools             ToolExecutor
	ToolMaterial      ToolMaterial
	Artifacts         ArtifactPort
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
	if cfg.Registry == nil || cfg.Runner == nil || cfg.Runs == nil || cfg.InterruptWriter == nil || cfg.InterruptReader == nil || cfg.InterruptExpirer == nil || cfg.Authority == nil || cfg.Tools == nil || cfg.ToolMaterial == nil || cfg.Artifacts == nil || cfg.Domain == nil || cfg.CommitAuthority == nil || cfg.Decisions == nil || cfg.Clock == nil {
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

// currentAuthority re-reads the one current-authority source and proves it
// still governs this exact run: the source must answer, the observation must
// be complete and active, and the definition, Contract BOM, policy, and
// budget in force must still be byte-identical to the material pinned on the
// run. Every model disclosure and every external effect is preceded by this
// call inside the same durable operation.
func (e *Executor) currentAuthority(ctx context.Context, scope runs.Scope, snapshot runs.Snapshot) (authority.Current, *problem.Details) {
	current, err := e.cfg.Authority.Current(ctx, scope.AuthorityScope())
	if err != nil {
		return authority.Current{}, staleAuthority("current authority is unavailable")
	}
	if !current.MaterialComplete() {
		return authority.Current{}, staleAuthority("current authority material is unavailable")
	}
	if !current.Active() {
		return authority.Current{}, staleAuthority("current authority no longer permits this run")
	}
	if !canonicalEqual(current.Definition, snapshot.Definition) {
		return authority.Current{}, staleAuthority("the pinned agent definition is no longer the current definition")
	}
	if !canonicalEqual(current.ContractBOM, snapshot.ContractBOM) {
		return authority.Current{}, staleAuthority("the pinned Contract BOM is no longer current")
	}
	if !canonicalEqual(current.Policy, snapshot.Policy) {
		return authority.Current{}, staleAuthority("the pinned policy is no longer current")
	}
	if !canonicalEqual(current.Budget, snapshot.Budget) {
		return authority.Current{}, staleAuthority("the pinned agent budget is no longer current")
	}
	if _, err := parseBudget(current.Budget); err != nil {
		return authority.Current{}, staleAuthority("the current agent budget is not decodable")
	}
	return current, nil
}

// staleAuthority builds the typed AUTHORITY_STALE stop. It is never a
// recoverable error and never resolves to a normal decision: callers convert
// it into a halt or a refusal so the run stops at this durable boundary.
func staleAuthority(detail string) *problem.Details {
	details := problem.New(problem.CodeAuthorityStale, "")
	details.Detail = detail
	return &details
}

// haltOnStale converts a stale-authority stop into the workflow halt shape.
func haltOnStale(details *problem.Details) *workflow.Halt {
	return &workflow.Halt{Problem: *details, Behavior: workflow.TerminalFailed}
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
	if _, stale := e.currentAuthority(ctx, scope, snapshot); stale != nil {
		return workflow.PrepareResult{Refused: stale, Version: snapshot.Version}, nil
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
	scope := runs.Scope{WorkspaceID: input.Run.Scope.WorkspaceID, ProjectID: input.Run.Scope.ProjectID, ActorID: input.Run.Scope.ActorID}
	// The turn discloses compiled context to a provider, so authority is
	// re-read here, inside this durable step, and not inherited from prepare.
	current, stale := e.currentAuthority(ctx, scope, snapshot)
	if stale != nil {
		carry := input.Carry
		carry.Version = snapshot.Version
		return workflow.TurnResult{Carry: carry, Halt: haltOnStale(stale)}, nil
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
		OperationKey:    op.Key(),
		Authority:       current,
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
	carry := input.Carry
	carry.Version = snapshot.Version
	scope := runs.Scope{WorkspaceID: input.Run.Scope.WorkspaceID, ProjectID: input.Run.Scope.ProjectID, ActorID: input.Run.Scope.ActorID}
	// A tool call is an external effect: the Tool Guard evaluates against the
	// authority read here, in this step, not against the run's pinned grant.
	current, stale := e.currentAuthority(ctx, scope, snapshot)
	if stale != nil {
		return workflow.ActionResult{Carry: carry, Halt: haltOnStale(stale)}, nil
	}
	definition, refusal := e.resolveDefinition(snapshot)
	if refusal != nil {
		return workflow.ActionResult{}, *refusal
	}
	switch input.Decision.Kind {
	case agent.DecisionToolCall:
		proposal := *input.Decision.ToolCall
		decision, err := e.cfg.Runner.GuardAction(ctx, definition, runView(snapshot), current, proposal)
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
		// The guard returned the signed execution envelope of the tool it
		// allowed. The dispatch happens inside it: the signed timeout bounds
		// how long the tool may run, and the signed retry policy bounds how
		// many times it may be attempted at all.
		result, err := e.dispatch(ctx, decision.Dispatch, ToolInvocation{
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
	default:
		details := problem.Internal("")
		details.Detail = "action requires a tool call decision"
		return workflow.ActionResult{}, details
	}
}

// OpenDelegation authorizes one Specialist delegation. It fences, re-reads
// current authority through the runner, and returns the bounded turn budget
// the workflow drives one durable step at a time.
func (e *Executor) OpenDelegation(ctx context.Context, op workflow.OpID, input workflow.DelegationInput) (workflow.DelegationOpened, error) {
	snapshot, _, superseded, err := e.load(ctx, input.Run)
	if err != nil {
		return workflow.DelegationOpened{}, err
	}
	if superseded || !turnStateAllowed(snapshot.Status, input.Phase) {
		return workflow.DelegationOpened{Superseded: true}, nil
	}
	if input.Decision.Kind != agent.DecisionDelegate || input.Decision.Delegate == nil {
		details := problem.Internal("")
		details.Detail = "delegation requires a delegation decision"
		return workflow.DelegationOpened{}, details
	}
	definition, refusal := e.resolveDefinition(snapshot)
	if refusal != nil {
		return workflow.DelegationOpened{}, *refusal
	}
	carry := input.Carry
	carry.Version = snapshot.Version
	scope := runs.Scope{WorkspaceID: input.Run.Scope.WorkspaceID, ProjectID: input.Run.Scope.ProjectID, ActorID: input.Run.Scope.ActorID}
	current, stale := e.currentAuthority(ctx, scope, snapshot)
	if stale != nil {
		return workflow.DelegationOpened{Carry: carry, Halt: haltOnStale(stale)}, nil
	}
	// The fan-out counter advances at the authorized boundary so a crash
	// inside the delegation cannot spend a second delegation slot on replay.
	carry.Delegations++
	grant, denied := e.cfg.Runner.AuthorizeDelegation(ctx, runner.DelegationRequest{
		Parent:          definition,
		Decision:        *input.Decision.Delegate,
		Run:             runView(snapshot),
		Authority:       current,
		Depth:           0,
		DelegationsUsed: input.Carry.Delegations,
	})
	if denied != nil {
		carry.Notes = boundNotes(append(carry.Notes, "delegation refused ("+denied.Code+"): "+denied.Detail))
		return workflow.DelegationOpened{Refused: true, Carry: carry}, nil
	}
	turnLimit := grant.TurnLimit
	if e.cfg.TurnLimit < turnLimit {
		turnLimit = e.cfg.TurnLimit
	}
	carry.Notes = boundNotes(append(carry.Notes, "delegated task input accepted"))
	return workflow.DelegationOpened{
		TurnLimit:        turnLimit,
		SpecialistID:     grant.Specialist.DefinitionID,
		SpecialistDigest: grant.Specialist.DefinitionDigest,
		Carry:            carry,
	}, nil
}

// ExecuteDelegateTurn runs exactly one Specialist turn inside an authorized
// delegation. It is a full durable boundary: fencing, authority re-read, and
// budget accounting all apply per turn.
func (e *Executor) ExecuteDelegateTurn(ctx context.Context, op workflow.OpID, input workflow.DelegateTurnInput) (workflow.DelegateTurnResult, error) {
	snapshot, _, superseded, err := e.load(ctx, input.Run)
	if err != nil {
		return workflow.DelegateTurnResult{}, err
	}
	if superseded || !turnStateAllowed(snapshot.Status, input.Phase) {
		return workflow.DelegateTurnResult{Superseded: true}, nil
	}
	scope := runs.Scope{WorkspaceID: input.Run.Scope.WorkspaceID, ProjectID: input.Run.Scope.ProjectID, ActorID: input.Run.Scope.ActorID}
	current, stale := e.currentAuthority(ctx, scope, snapshot)
	if stale != nil {
		carry := input.Carry
		carry.Version = snapshot.Version
		return workflow.DelegateTurnResult{Done: true, Carry: carry, Halt: haltOnStale(stale)}, nil
	}
	specialist, err := e.cfg.Registry.Resolve(agent.DefinitionReference{DefinitionID: input.SpecialistID, DefinitionDigest: input.SpecialistDigest})
	if err != nil {
		var details problem.Details
		if errors.As(err, &details) {
			return workflow.DelegateTurnResult{}, details
		}
		return workflow.DelegateTurnResult{}, err
	}
	if mismatch := e.verifyMaterial(specialist); mismatch != nil {
		return workflow.DelegateTurnResult{}, *mismatch
	}
	budget, err := parseBudget(snapshot.Budget)
	if err != nil {
		return workflow.DelegateTurnResult{}, err
	}
	carry := input.Carry
	carry.Version = snapshot.Version
	outcome, err := e.cfg.Runner.DelegateTurn(ctx, runner.DelegateTurnRequest{
		Specialist:   specialist,
		Run:          runView(snapshot),
		Turn:         input.DelegateTurn,
		Depth:        1,
		Last:         input.Last,
		Notes:        carry.Notes,
		Input:        input.Input,
		Budget:       budget.remaining(carry.Usage),
		OperationKey: op.Key(),
		Authority:    current,
	})
	if err != nil {
		return workflow.DelegateTurnResult{}, err
	}
	carry.Usage = carry.Usage.Add(outcome.Usage)
	carry.Notes = boundNotes(append(carry.Notes, outcome.Notes...))
	if outcome.Halted != nil {
		return workflow.DelegateTurnResult{Done: true, Carry: carry, Halt: haltOf(*outcome.Halted)}, nil
	}
	if outcome.Refused != nil {
		carry.Notes = boundNotes(append(carry.Notes, "delegation refused: "+outcome.Refused.Code))
		return workflow.DelegateTurnResult{Done: true, Carry: carry}, nil
	}
	if len(outcome.Candidate) > 0 {
		carry.Notes = boundNotes(append(carry.Notes, "specialist candidate: "+truncate(string(outcome.Candidate), 4096)))
		return workflow.DelegateTurnResult{Done: true, Carry: carry}, nil
	}
	return workflow.DelegateTurnResult{Done: outcome.Done, Carry: carry}, nil
}

func (e *Executor) OpenInput(ctx context.Context, op workflow.OpID, input workflow.InterruptOpen) (workflow.InterruptOpened, error) {
	snapshot, scope, superseded, err := e.load(ctx, input.Run)
	if err != nil {
		return workflow.InterruptOpened{}, err
	}
	if superseded {
		return workflow.InterruptOpened{Superseded: true}, nil
	}
	// Opening an input request is an externally visible effect.
	if _, stale := e.currentAuthority(ctx, scope, snapshot); stale != nil {
		return workflow.InterruptOpened{Halt: haltOnStale(stale)}, nil
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

// ExpireInterrupt settles the durable deadline through the repository's
// atomic expiry seam. Observing the response and failing the run happen in
// one critical section, so an acceptance that races the deadline either wins
// outright (Raced) or loses outright; the run can never end up answered with
// no workflow left to drive it.
func (e *Executor) ExpireInterrupt(ctx context.Context, op workflow.OpID, expire workflow.ExpireRequest) (workflow.Ack, error) {
	snapshot, scope, superseded, err := e.load(ctx, expire.Run)
	if err != nil {
		return workflow.Ack{}, err
	}
	if superseded {
		return workflow.Ack{Superseded: true}, nil
	}
	code := problem.CodeInputRequestExpired
	if expire.Kind == "approval" {
		code = problem.CodeApprovalRequestExpired
	}
	failure := problem.New(code, "")
	failure.Detail = "the durable " + expire.Kind + " deadline elapsed before a response was accepted"
	write := interrupts.Write{
		Scope:           scope,
		RunID:           runs.ID(expire.Run.Key.RunID),
		ExpectedVersion: snapshot.Version,
		IdempotencyKey:  op.Key(),
		Traceparent:     traceparentOf(expire.Run),
	}
	settle := e.cfg.InterruptExpirer.ExpireInput
	if expire.Kind == "approval" {
		settle = e.cfg.InterruptExpirer.ExpireApproval
	}
	outcome, err := settle(ctx, write, interrupts.RequestID(expire.RequestID), failure, e.cfg.Clock.Now())
	if err != nil {
		return workflow.Ack{}, fmt.Errorf("settle durable %s deadline: %w", expire.Kind, err)
	}
	if outcome.Raced {
		return workflow.Ack{Raced: true, Version: outcome.Snapshot.Version}, nil
	}
	if outcome.Superseded {
		return workflow.Ack{Superseded: true}, nil
	}
	return workflow.Ack{Version: outcome.Snapshot.Version}, nil
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
	// Review either completes the run or opens an approval request, so it is
	// preceded by an authority re-read like every other external effect.
	if _, stale := e.currentAuthority(ctx, scope, snapshot); stale != nil {
		return workflow.ReviewResult{Halt: haltOnStale(stale)}, nil
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
	// Retry is a fresh authorization decision, not a continuation of the one
	// the run started with: the current definition, Contract BOM, policy, and
	// budget are all revalidated before the run is allowed to execute again.
	if _, stale := e.currentAuthority(ctx, scope, snapshot); stale != nil {
		return workflow.Ack{Version: snapshot.Version, Halt: haltOnStale(stale)}, nil
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
	// The domain operation identity is derived from the durable operation, so
	// a replay reconciles and resubmits under exactly the identity the first
	// execution used.
	operationID := domainOperationID(op)
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
	case runs.AwaitingDomainConfirmation:
		// A previous execution already crossed the submit boundary, so an
		// effect may exist. Nothing is re-issued and nothing is re-submitted:
		// the authoritative record decides what happened.
		return e.reconcileDomain(ctx, scope, snapshot, id, operationID, input)
	}
	// The commit gate runs in one fixed order, and each check must pass
	// before the next is attempted: current authority, then the approval and
	// its exact action binding, then artifact eligibility, then authorization
	// issuance, and only then the governed domain effect. No later step is
	// reached — and in particular neither the issuer nor the domain owner is
	// called — while an earlier one is unsatisfied.
	if _, stale := e.currentAuthority(ctx, scope, snapshot); stale != nil {
		return workflow.CommitResult{Version: snapshot.Version, Halt: haltOnStale(stale)}, nil
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
	if !validDigestString(input.ArtifactDigest) || approval.ActionDigest != input.ArtifactDigest {
		// The approved action and the artifact about to be committed must be
		// the same object. A mismatch is an unapproved effect, so the commit
		// stops before any authorization is issued.
		denied := problem.New(problem.CodeApplyAuthorizationDenied, "")
		denied.Detail = "the approved action digest does not bind the artifact being committed"
		return workflow.CommitResult{}, denied
	}
	eligibility, err := e.cfg.Artifacts.Eligible(ctx, ArtifactQuery{
		WorkspaceID:    snapshot.WorkspaceID,
		ProjectID:      snapshot.Target.ProjectID,
		RunID:          string(id),
		ArtifactDigest: input.ArtifactDigest,
	})
	if err != nil {
		return workflow.CommitResult{}, fmt.Errorf("resolve artifact eligibility before commit: %w", err)
	}
	if !eligibility.Eligible {
		denied := problem.New(problem.CodeApplyAuthorizationDenied, "")
		denied.Detail = "the candidate artifact is not eligible for a governed effect"
		if eligibility.Reason != "" {
			denied.Detail = "the candidate artifact is not eligible for a governed effect: " + truncate(eligibility.Reason, 256)
		}
		return workflow.CommitResult{}, denied
	}
	// Authority is re-read immediately before issuance. The reads above cost
	// real time, and an authorization is a durable capability: it must not be
	// minted against an authority that stopped permitting this run while the
	// gate was running.
	if _, stale := e.currentAuthority(ctx, scope, snapshot); stale != nil {
		return workflow.CommitResult{Version: snapshot.Version, Halt: haltOnStale(stale)}, nil
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
	version := snapshot.Version
	if snapshot.Status == runs.AwaitingApproval {
		proof := runs.CommitProof{
			ApprovalRechecked:    true,
			ArtifactEligible:     eligibility.Eligible,
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
	// Authority is re-read once more immediately before the domain effect,
	// while the run is still short of the submit boundary. A stale answer here
	// halts a run that has caused nothing yet, and committing has a legal
	// failure edge for exactly that stop.
	if _, stale := e.currentAuthority(ctx, scope, snapshot); stale != nil {
		return workflow.CommitResult{Version: snapshot.Version, Halt: haltOnStale(stale)}, nil
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
		// The submission outcome is unknown. The run stays at the submit
		// boundary, which is a state with defined exits, and the next
		// execution of this durable operation reconciles it against the
		// authoritative record instead of submitting again.
		return workflow.CommitResult{}, fmt.Errorf("submit governed domain effect: %w", err)
	}
	return e.settleDomain(ctx, scope, snapshot, id, input, outcome)
}

// reconcileDomain resolves a run that already crossed the submit boundary.
// It never re-issues an authorization and never re-submits an effect: the
// authoritative owner is asked what became of the operation, and the answer
// is what moves the run. An owner that has no record of the operation proves
// nothing landed, which is the only condition under which the run may fail
// out of awaiting_domain_confirmation.
func (e *Executor) reconcileDomain(ctx context.Context, scope runs.Scope, snapshot runs.Snapshot, id runs.ID, operationID string, input workflow.CommitInput) (workflow.CommitResult, error) {
	record, found, err := e.cfg.Domain.Reconcile(ctx, DomainQuery{
		OperationID: operationID,
		WorkspaceID: snapshot.WorkspaceID,
		ProjectID:   snapshot.Target.ProjectID,
		RunID:       string(id),
	})
	if err != nil {
		return workflow.CommitResult{}, fmt.Errorf("reconcile governed domain effect: %w", err)
	}
	if found {
		switch record.Status {
		case DomainConfirmed, DomainConflict, DomainRejected:
			return e.settleDomain(ctx, scope, snapshot, id, input, record)
		default:
			// The owner holds the operation but has not decided it. The run
			// stays where it is and this durable operation is retried; no
			// effect is repeated and no authorization is minted.
			uncertain := problem.New(problem.CodeDomainOutcomeUncertain, "")
			uncertain.Detail = "the authoritative domain owner has not settled the submitted effect"
			return workflow.CommitResult{}, uncertain
		}
	}
	failure := problem.New(problem.CodeDomainOutcomeUncertain, "")
	failure.Retryability = "safe-after-backoff"
	failure.Detail = "the authoritative domain owner has no record of the submitted effect, so no governed effect was applied"
	next, lost, err := e.apply(ctx, scope, id, snapshot.Version, runs.Command{
		Kind:           runs.RecordFailure,
		Failure:        &failure,
		Reconciliation: runs.DomainReconciliation{Reconciled: true, EffectApplied: false, DomainOperationID: operationID},
		Traceparent:    traceparentOf(input.Run),
	}, runs.Failed)
	if err != nil {
		return workflow.CommitResult{}, err
	}
	if lost {
		return workflow.CommitResult{Superseded: true}, nil
	}
	return workflow.CommitResult{Outcome: workflow.CommitFailed, Problem: &failure, Version: next.Version}, nil
}

// settleDomain records one authoritative domain outcome on the aggregate. It
// is the single place a governed effect becomes a terminal run state, whether
// the outcome came from the submission itself or from reconciling one.
func (e *Executor) settleDomain(ctx context.Context, scope runs.Scope, snapshot runs.Snapshot, id runs.ID, input workflow.CommitInput, outcome DomainOutcome) (workflow.CommitResult, error) {
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
		// An unrecognized answer settles nothing. The run holds at the submit
		// boundary and the next execution reconciles against the record.
		uncertain := problem.New(problem.CodeDomainOutcomeUncertain, "")
		uncertain.Detail = "domain outcome is uncertain; resolution requires the authoritative effect record"
		return workflow.CommitResult{}, uncertain
	}
}

// domainOperationID derives the governed effect identity from the durable
// operation, so every execution of the same commit step addresses the same
// operation at the authoritative owner.
func domainOperationID(op workflow.OpID) string {
	return "domain." + strings.TrimPrefix(mustDeterministicDigest(op), "sha256:")[:32]
}

func (e *Executor) Terminalize(ctx context.Context, op workflow.OpID, input workflow.TerminalInput) (workflow.Ack, error) {
	snapshot, scope, superseded, err := e.load(ctx, input.Run)
	if err != nil {
		return workflow.Ack{}, err
	}
	if superseded {
		return workflow.Ack{Superseded: true}, nil
	}
	if snapshot.Status == runs.AwaitingDomainConfirmation {
		// A run whose governed effect may exist cannot be terminalized on the
		// workflow's say-so. The typed stop keeps the run at the submit
		// boundary so the commit operation reconciles it against the
		// authoritative record instead.
		uncertain := problem.New(problem.CodeDomainOutcomeUncertain, "")
		uncertain.Retryability = "safe-after-backoff"
		uncertain.Detail = "a run with an unsettled governed effect must be reconciled, not terminalized"
		return workflow.Ack{}, uncertain
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

// dispatch executes one guard-approved tool call inside the signed execution
// envelope the approved catalog attests for it. The envelope is authority,
// not advice: a tool never runs longer than its signed timeout, and it is
// never attempted more times than its signed retry policy allows — an
// unbounded envelope is refused rather than treated as unlimited.
func (e *Executor) dispatch(ctx context.Context, envelope tools.DispatchEnvelope, invocation ToolInvocation) (ToolResult, error) {
	if envelope.TimeoutMilliseconds < 1 || envelope.MaximumAttempts < 1 {
		details := problem.New(problem.CodeContractInvalid, "")
		details.Detail = "the signed tool dispatch envelope does not bound execution"
		return ToolResult{}, details
	}
	var last error
	for attempt := 1; attempt <= envelope.MaximumAttempts; attempt++ {
		attemptCtx, cancel := context.WithTimeout(ctx, time.Duration(envelope.TimeoutMilliseconds)*time.Millisecond)
		result, err := e.cfg.Tools.Execute(attemptCtx, invocation)
		cancel()
		if err == nil {
			return result, nil
		}
		last = err
		// A further attempt happens only when the signed policy authorizes an
		// immediate retry and the caller's context is still live.
		if !envelope.RetryableImmediately() || attempt == envelope.MaximumAttempts || ctx.Err() != nil {
			break
		}
	}
	return ToolResult{}, last
}

// verifyMaterial proves that the Tool, model, Guardrail, memory, and policy
// material the process is running is exactly the material the definition
// frozen on this run references. Approved-at-startup is not enough: the
// definition carried by the run is checked against the running material
// before the definition is used for anything.
func (e *Executor) verifyMaterial(definition agent.Definition) *problem.Details {
	if err := e.cfg.Registry.VerifyDefinitionReferences(definition); err != nil {
		details := problem.New(problem.CodeContractInvalid, "")
		details.Detail = "referenced agent material does not match the approved catalog"
		return &details
	}
	for _, reference := range definition.ToolProfile.Tools {
		digest, known := e.cfg.ToolMaterial.ComponentDigest(reference.ComponentName)
		if !known || digest != reference.Digest {
			details := problem.New(problem.CodeContractInvalid, "")
			details.Detail = "the running tool material does not match the tool profile frozen on the run"
			return &details
		}
		// The argument schema digest proves only that the tool takes the same
		// arguments. Execution is bound to the whole signed ToolDefinition,
		// so the capability, side-effect class, risk, approval policy,
		// timeout, and retry policy the process would dispatch under are all
		// checked against the material the approved catalog attests.
		binding, approved := e.cfg.Registry.ToolBinding(reference.ComponentName)
		if !approved {
			details := problem.New(problem.CodeContractInvalid, "")
			details.Detail = "the approved catalog carries no signed definition for a tool the run's profile pins"
			return &details
		}
		running, present := e.cfg.ToolMaterial.ToolDefinition(reference.ComponentName)
		if !present || !matchesBinding(running, binding) {
			details := problem.New(problem.CodeContractInvalid, "")
			details.Detail = "the running tool definition is not the signed tool definition the approved catalog carries"
			return &details
		}
	}
	return nil
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
	if mismatch := e.verifyMaterial(definition); mismatch != nil {
		return agent.Definition{}, mismatch
	}
	return definition, nil
}

// budgetLimits is the decoded pinned AgentBudget.
type budgetLimits struct {
	MaximumModelCalls   int64
	MaximumInputTokens  int64
	MaximumOutputTokens int64
	MaximumTotalTokens  int64
	MaximumCostMicros   int64
	ExceedBehavior      string
}

func (b budgetLimits) remaining(used agent.Usage) runner.BudgetView {
	return runner.BudgetView{
		RemainingModelCalls:   b.MaximumModelCalls - used.ModelCalls,
		RemainingInputTokens:  b.MaximumInputTokens - used.InputTokens,
		RemainingOutputTokens: b.MaximumOutputTokens - used.OutputTokens,
		RemainingTotalTokens:  b.MaximumTotalTokens - (used.InputTokens + used.OutputTokens),
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
	// The aggregate allowance is a limit in its own right, not a derived
	// convenience: a budget that omits it, or that states a total the
	// component limits could never respect, authorizes nothing.
	if document.TokenLimits.InputTokens < 1 || document.TokenLimits.OutputTokens < 1 || document.TokenLimits.TotalTokens < 1 {
		return budgetLimits{}, fmt.Errorf("pinned budget token limits must be positive, aggregate limit included")
	}
	return budgetLimits{
		MaximumModelCalls:   document.ModelLimits.MaximumCalls,
		MaximumInputTokens:  document.TokenLimits.InputTokens,
		MaximumOutputTokens: document.TokenLimits.OutputTokens,
		MaximumTotalTokens:  document.TokenLimits.TotalTokens,
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
		if !lowerHexDigit(character) {
			return false
		}
	}
	return true
}

// lowerHexDigit reports whether the character is a lower-case hexadecimal
// digit. Digest and trace identities are lower-case only, so an upper-case
// digit is rejected rather than normalized.
func lowerHexDigit(character rune) bool {
	return character >= '0' && character <= '9' || character >= 'a' && character <= 'f'
}
