// Package runner implements the thin AgentRunner: one provider-neutral turn
// at a time against a digest-pinned definition and authorized compiled
// context. The runner resolves exactly one TurnDecision per turn and owns no
// retries, durable waits, cancellation, checkpoints, artifacts, approval,
// budget authority, or commits.
package runner

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/ancyloce/anvilkit-agent-service/internal/agent"
	"github.com/ancyloce/anvilkit-agent-service/internal/authority"
	"github.com/ancyloce/anvilkit-agent-service/internal/contextcompiler"
	"github.com/ancyloce/anvilkit-agent-service/internal/modelgateway"
	"github.com/ancyloce/anvilkit-agent-service/internal/planning"
	"github.com/ancyloce/anvilkit-agent-service/internal/problem"
	"github.com/ancyloce/anvilkit-agent-service/internal/tools"
)

// ContextCompiler compiles the authorized trust layers for one turn.
type ContextCompiler interface {
	Compile(context.Context, contextcompiler.Request) (contextcompiler.Result, error)
}

// Selector resolves the policy-eligible provider selection for one turn.
type Selector interface {
	Select(ctx context.Context, workspaceID string, policy agent.PolicyReference) (modelgateway.Selection, error)
}

// Invoker performs one policy-eligible provider invocation. The gateway
// satisfies this interface; the runner layers strict typed-plan validation
// and bounded repair on top of it.
type Invoker interface {
	Invoke(context.Context, modelgateway.InvokeRequest) (modelgateway.AdapterResponse, modelgateway.InvocationRecord, error)
}

// ActionGuard is the mandatory Tool Guard evaluation boundary.
type ActionGuard interface {
	Evaluate(context.Context, tools.Intent, tools.CurrentAuthority, tools.Proposal) (tools.Decision, error)
}

// CandidateValidator validates a candidate document against one pinned
// schema reference and fails closed on unknown references.
type CandidateValidator interface {
	Validate(ctx context.Context, reference agent.SchemaReference, candidate json.RawMessage) error
}

type Clock interface{ Now() time.Time }

// RunView is the bounded run identity the runner may disclose to planning.
type RunView struct {
	RunID       string `json:"runId"`
	WorkspaceID string `json:"workspaceId"`
	ProjectID   string `json:"projectId"`
	ActorID     string `json:"actorId"`
	Domain      string `json:"domain"`
	Operation   string `json:"operation"`
	TargetType  string `json:"targetType"`
	TargetID    string `json:"targetId"`
}

// BudgetView is the remaining budget the executor derived from the pinned
// AgentBudget and recorded usage. The runner enforces it before every model
// call, including every bounded repair attempt; it never mutates budget
// authority.
type BudgetView struct {
	RemainingModelCalls   int64 `json:"remainingModelCalls"`
	RemainingInputTokens  int64 `json:"remainingInputTokens"`
	RemainingOutputTokens int64 `json:"remainingOutputTokens"`
	// RemainingTotalTokens is the aggregate input+output allowance the pinned
	// AgentBudget still has. It is enforced in its own right: a run that has
	// input and output allowance left may still be out of aggregate tokens,
	// and repairs and transport retries spend it like any other attempt.
	RemainingTotalTokens int64  `json:"remainingTotalTokens"`
	RemainingCostMicros  int64  `json:"remainingCostMicros"`
	ExceedBehavior       string `json:"exceedBehavior"`
}

// Limits bound one provider invocation.
type Limits struct {
	MaximumOutputBytes  int
	MaximumInputTokens  int64
	MaximumOutputTokens int64
	Timeout             time.Duration
	MaximumAttempts     int
	RetryBudget         time.Duration
	ContextTokens       int
}

func (l Limits) validate() error {
	if l.MaximumOutputBytes < 1 || l.MaximumInputTokens < 1 || l.MaximumOutputTokens < 1 || l.Timeout <= 0 || l.MaximumAttempts < 1 || l.RetryBudget < 0 || l.ContextTokens < 1 {
		return fmt.Errorf("agent runner limits must be positive")
	}
	return nil
}

const (
	PhasePlan     = "plan"
	PhaseRevise   = "revise"
	PhaseDelegate = "delegate"
)

type TurnRequest struct {
	Definition agent.Definition
	Run        RunView
	Phase      string
	Turn       int
	Depth      int
	Notes      []string
	InputValue json.RawMessage
	// OperationKey is the durable operation identity of the turn. It is
	// required: every provider attempt derives its idempotency identity from
	// it, so replaying the durable step reproduces the same provider calls
	// instead of issuing new ones.
	OperationKey string
	// Authority is the current-authority observation the caller re-read
	// immediately before this turn, inside the same durable operation. The
	// runner discloses context to a provider only while it is active.
	Authority       authority.Current
	ReviewReason    string
	DelegationsUsed int
	Budget          BudgetView
}

// Halted is a typed budget or limit stop with the deterministic behavior the
// pinned budget demands.
type Halted struct {
	Problem problem.Details
	Refuse  bool
}

type TurnOutcome struct {
	Decision agent.TurnDecision
	Usage    agent.Usage
	Notes    []string
	Halted   *Halted
}

// Runner executes turns. It is stateless between calls.
type Runner struct {
	registry  *agent.Registry
	compiler  ContextCompiler
	selector  Selector
	invoker   Invoker
	guard     ActionGuard
	validator CandidateValidator
	clock     Clock
	limits    Limits
}

type Config struct {
	Registry  *agent.Registry
	Compiler  ContextCompiler
	Selector  Selector
	Invoker   Invoker
	Guard     ActionGuard
	Validator CandidateValidator
	Clock     Clock
	Limits    Limits
}

func New(cfg Config) (*Runner, error) {
	if cfg.Registry == nil || cfg.Compiler == nil || cfg.Selector == nil || cfg.Invoker == nil || cfg.Guard == nil || cfg.Validator == nil || cfg.Clock == nil {
		return nil, fmt.Errorf("agent runner: every pipeline dependency is required")
	}
	if err := cfg.Limits.validate(); err != nil {
		return nil, err
	}
	return &Runner{registry: cfg.Registry, compiler: cfg.Compiler, selector: cfg.Selector, invoker: cfg.Invoker, guard: cfg.Guard, validator: cfg.Validator, clock: cfg.Clock, limits: cfg.Limits}, nil
}

// reserved tool names map typed plans onto the explicit TurnDecision
// vocabulary. Any other agent.* name is invalid and resolves to a refusal;
// any non-reserved name is a tool call proposal.
const (
	planContinue  = "agent.continue"
	planNeedInput = "agent.need-input"
	planDelegate  = "agent.delegate"
	planFinal     = "agent.final"
	planRefuse    = "agent.refuse"
)

// Turn executes one bounded reasoning turn: budget precheck, authorized
// context compilation, and one policy-eligible provider invocation with
// bounded repair under the same budget, then deterministic TurnDecision
// resolution.
func (r *Runner) Turn(ctx context.Context, request TurnRequest) (TurnOutcome, error) {
	if request.OperationKey == "" {
		return TurnOutcome{}, fmt.Errorf("agent runner: a durable operation key is required for every turn")
	}
	// Nothing is compiled, selected, or disclosed until the re-read authority
	// the caller carried into this turn is proven active.
	if details := requireActive(request.Authority); details != nil {
		return TurnOutcome{Halted: &Halted{Problem: *details}}, nil
	}
	if halted := precheck(request.Budget); halted != nil {
		return TurnOutcome{Halted: halted}, nil
	}
	instruction, err := r.registry.Instruction(request.Definition.DefinitionID)
	if err != nil {
		return TurnOutcome{}, err
	}
	compiled, err := r.compileContext(ctx, instruction, request)
	if err != nil {
		return TurnOutcome{}, fmt.Errorf("compile turn context: %w", err)
	}
	selection, err := r.selector.Select(ctx, request.Run.WorkspaceID, request.Definition.ModelPolicy)
	if err != nil {
		return TurnOutcome{}, fmt.Errorf("select eligible provider: %w", err)
	}
	invoke := modelgateway.InvokeRequest{
		RunID:          request.Run.RunID,
		WorkspaceID:    request.Run.WorkspaceID,
		ProjectID:      request.Run.ProjectID,
		IdempotencyKey: request.OperationKey,
		Selection:      selection,
		Context:        compiled,
		DataClasses:    []modelgateway.DataClass{"public", "internal"},
		// The configured ceilings bound every attempt; the attempt budget
		// narrows them further from the remaining pinned agent budget.
		MaximumOutputBytes:  r.limits.MaximumOutputBytes,
		MaximumInputTokens:  r.limits.MaximumInputTokens,
		MaximumOutputTokens: r.limits.MaximumOutputTokens,
		MaximumTotalTokens:  r.limits.MaximumInputTokens + r.limits.MaximumOutputTokens,
		MaximumCostMicros:   selection.MaximumCostMicros,
		Timeout:             r.limits.Timeout,
		MaximumAttempts:     r.limits.MaximumAttempts,
		RetryBudget:         r.limits.RetryBudget,
		Scenario:            "agent-turn",
	}
	repairs := request.Definition.RepairPolicy.MaximumAttempts
	if request.Definition.RepairPolicy.Mode == "reject" {
		repairs = 0
	}
	guard := attemptBudget{view: request.Budget, limits: r.limits, providerCostMicros: selection.MaximumCostMicros}
	planResult, planErr := r.plan(ctx, invoke, repairs, guard)
	usage := usageOf(planResult)
	if planErr != nil {
		var details problem.Details
		if !errors.As(planErr, &details) {
			// The turn failed, but the physical provider attempts it already
			// made were still billed. Their usage travels with the error so
			// the caller can account a failed attempt: a turn that never
			// reaches a decision is exactly the case where dropping the
			// outcome would drop real spend with it.
			return TurnOutcome{Usage: usage}, fmt.Errorf("plan turn: %w", planErr)
		}
		if details.Code == string(problem.CodeBudgetDenied) {
			// The pinned budget ran out inside bounded repair. The stop is a
			// typed halt, not a refusal decision, and the attempts already
			// made are still accounted.
			return TurnOutcome{Usage: usage, Halted: &Halted{Problem: details, Refuse: request.Budget.ExceedBehavior == "refuse"}}, nil
		}
		// Typed-plan rejection after bounded repair resolves to an explicit
		// refusal decision; ambiguous fallthrough is impossible.
		return TurnOutcome{
			Decision: agent.TurnDecision{Kind: agent.DecisionRefuse, Refuse: &agent.RefuseDecision{Reason: "typed plan failed bounded validation and repair"}},
			Usage:    usage,
			Notes:    []string{"planning rejected: " + details.Code},
		}, nil
	}
	decision, invalidReason := r.resolveDecision(planResult.Plan, request)
	if invalidReason != "" {
		return TurnOutcome{
			Decision: agent.TurnDecision{Kind: agent.DecisionRefuse, Refuse: &agent.RefuseDecision{Reason: invalidReason}},
			Usage:    usage,
			Notes:    []string{"decision rejected: " + invalidReason},
		}, nil
	}
	if err := decision.Validate(); err != nil {
		return TurnOutcome{
			Decision: agent.TurnDecision{Kind: agent.DecisionRefuse, Refuse: &agent.RefuseDecision{Reason: "turn decision violates the bounded contract"}},
			Usage:    usage,
			Notes:    []string{"decision rejected: bounded contract violation"},
		}, nil
	}
	return TurnOutcome{Decision: decision, Usage: usage}, nil
}

// GuardAction evaluates the mandatory Tool Guard for one proposed tool call
// against the current-authority observation the caller re-read inside the
// same durable operation. The guard validates the arguments against the
// tool's digest-pinned input schema before any effect. Denials return the
// typed problem and the recorded decision.
func (r *Runner) GuardAction(ctx context.Context, definition agent.Definition, run RunView, current authority.Current, proposal agent.ToolCallDecision) (tools.Decision, error) {
	allowed := make([]string, 0, len(definition.ToolProfile.Tools))
	for _, tool := range definition.ToolProfile.Tools {
		allowed = append(allowed, tool.ComponentName)
	}
	intent := tools.Intent{
		RunID:          run.RunID,
		WorkspaceID:    run.WorkspaceID,
		ProjectID:      run.ProjectID,
		ActorID:        run.ActorID,
		AllowedTools:   allowed,
		AllowedEffects: []string{"read"},
		MaximumRisk:    "low",
		DataClasses:    []string{"public", "internal"},
	}
	return r.guard.Evaluate(ctx, intent, toolAuthority(current), tools.Proposal{ToolID: proposal.ToolID, Arguments: proposal.Arguments})
}

// ValidateCandidate validates a final candidate against the definition's
// pinned output schema reference.
func (r *Runner) ValidateCandidate(ctx context.Context, definition agent.Definition, candidate json.RawMessage) error {
	return r.validator.Validate(ctx, definition.OutputSchema, candidate)
}

// DelegationRequest asks for authorization to open one Specialist
// delegation inside the parent run boundary.
type DelegationRequest struct {
	Parent   agent.Definition
	Decision agent.DelegateDecision
	Run      RunView
	// Authority is the observation the caller re-read immediately before the
	// delegation opens.
	Authority       authority.Current
	Depth           int
	DelegationsUsed int
}

// DelegationGrant is the authorized delegation boundary. The workflow drives
// one durable turn at a time inside it.
type DelegationGrant struct {
	Specialist agent.Definition
	TurnLimit  int
}

// AuthorizeDelegation enforces every pinned delegation constraint and
// re-reads current authority immediately before the delegation opens.
// Authority revoked after the run started fails the delegation closed.
func (r *Runner) AuthorizeDelegation(ctx context.Context, request DelegationRequest) (DelegationGrant, *problem.Details) {
	if !request.Parent.AllowsDelegate(request.Decision.DelegateID) {
		return DelegationGrant{}, refusal(problem.CodePolicyDenied, "delegate is not in the pinned allowed-delegate set")
	}
	if request.Depth+1 > request.Parent.MaximumDelegationDepth {
		return DelegationGrant{}, refusal(problem.CodePolicyDenied, "delegation exceeds the pinned maximum depth")
	}
	if request.DelegationsUsed+1 > request.Parent.MaximumFanOut {
		return DelegationGrant{}, refusal(problem.CodePolicyDenied, "delegation exceeds the pinned maximum fan-out")
	}
	specialist, err := r.registry.ResolveDelegate(request.Decision.DelegateID)
	if err != nil {
		return DelegationGrant{}, refusal(problem.CodePolicyDenied, "delegate is not resolvable in the approved registry")
	}
	if details := requireActive(request.Authority); details != nil {
		return DelegationGrant{}, details
	}
	if err := r.validator.Validate(ctx, specialist.InputSchema, request.Decision.Input); err != nil {
		return DelegationGrant{}, refusal(problem.CodePolicyDenied, "delegate input violates the specialist input schema")
	}
	return DelegationGrant{Specialist: specialist, TurnLimit: specialist.TurnLimit}, nil
}

// DelegateTurnRequest is one durable Specialist turn inside an authorized
// delegation. Each turn is its own recoverable boundary: a crash resumes at
// the last completed Specialist turn instead of repeating the whole loop.
type DelegateTurnRequest struct {
	Specialist   agent.Definition
	Run          RunView
	Turn         int
	Depth        int
	Last         bool
	Notes        []string
	Input        json.RawMessage
	Budget       BudgetView
	OperationKey string
	// Authority is the observation the caller re-read immediately before this
	// Specialist turn.
	Authority authority.Current
}

// DelegateTurnOutcome is the classified result of one Specialist turn.
type DelegateTurnOutcome struct {
	// Done reports that the delegation concluded on this turn, with either a
	// candidate or a typed refusal.
	Done      bool
	Candidate json.RawMessage
	Refused   *problem.Details
	Usage     agent.Usage
	Notes     []string
	Halted    *Halted
}

// DelegateTurn executes exactly one Specialist turn. Current authority is
// re-read before the turn runs, so a revocation during a delegation stops it
// at the next durable boundary.
func (r *Runner) DelegateTurn(ctx context.Context, request DelegateTurnRequest) (DelegateTurnOutcome, error) {
	if details := requireActive(request.Authority); details != nil {
		return DelegateTurnOutcome{Done: true, Refused: details}, nil
	}
	notes := append([]string{}, request.Notes...)
	notes = append(notes, "delegated input: "+truncate(string(request.Input), 2048))
	turnOutcome, err := r.Turn(ctx, TurnRequest{
		Definition:      request.Specialist,
		Run:             request.Run,
		Phase:           PhaseDelegate,
		Turn:            request.Turn,
		Depth:           request.Depth,
		Notes:           notes,
		OperationKey:    request.OperationKey,
		Authority:       request.Authority,
		DelegationsUsed: 0,
		Budget:          request.Budget,
	})
	if err != nil {
		return DelegateTurnOutcome{}, err
	}
	outcome := DelegateTurnOutcome{Usage: turnOutcome.Usage, Notes: turnOutcome.Notes}
	if turnOutcome.Halted != nil {
		outcome.Done, outcome.Halted = true, turnOutcome.Halted
		return outcome, nil
	}
	switch turnOutcome.Decision.Kind {
	case agent.DecisionContinue:
		if turnOutcome.Decision.Continue.Note != "" {
			outcome.Notes = append(outcome.Notes, "specialist: "+turnOutcome.Decision.Continue.Note)
		}
		if request.Last {
			outcome.Done = true
			outcome.Refused = refusal(problem.CodeLimitExceeded, "specialist reached the pinned turn limit without a candidate")
		}
		return outcome, nil
	case agent.DecisionFinal:
		if err := r.validator.Validate(ctx, request.Specialist.OutputSchema, turnOutcome.Decision.Final.Candidate); err != nil {
			outcome.Done = true
			outcome.Refused = refusal(problem.CodeContractInvalid, "specialist candidate violates the pinned output schema")
			return outcome, nil
		}
		outcome.Done = true
		outcome.Candidate = turnOutcome.Decision.Final.Candidate
		outcome.Notes = append(outcome.Notes, "specialist candidate accepted")
		return outcome, nil
	case agent.DecisionRefuse:
		outcome.Done = true
		outcome.Refused = refusal(problem.CodePolicyDenied, turnOutcome.Decision.Refuse.Reason)
		return outcome, nil
	default:
		// Specialists may only continue, finalize, or refuse inside a
		// delegation boundary.
		outcome.Done = true
		outcome.Refused = refusal(problem.CodePolicyDenied, "specialist produced a decision outside the delegation contract")
		return outcome, nil
	}
}

// requireActive fails closed when the observation the caller carried in is
// not a complete, active authority. The runner never reads authority itself:
// one source is re-read by the caller inside the durable operation, and the
// same observation governs disclosure, dispatch, and delegation.
func requireActive(current authority.Current) *problem.Details {
	if !current.MaterialComplete() {
		return refusal(problem.CodeAuthorityStale, "current authority material is unavailable")
	}
	if !current.Active() {
		return refusal(problem.CodeAuthorityStale, "current authority no longer permits execution")
	}
	return nil
}

// toolAuthority projects the shared observation onto the Tool Guard's
// current-authority input.
func toolAuthority(current authority.Current) tools.CurrentAuthority {
	return tools.CurrentAuthority{
		WorkspaceActive:         current.WorkspaceActive,
		ActorActive:             current.ActorActive,
		PermissionActive:        current.PermissionActive,
		PolicyActive:            current.PolicyActive,
		AllowedTools:            append([]string(nil), current.Grants.AllowedTools...),
		AllowedCapabilities:     append([]string(nil), current.Grants.AllowedCapabilities...),
		AllowedEffects:          append([]string(nil), current.Grants.AllowedEffects...),
		MaximumRisk:             current.Grants.MaximumRisk,
		DataClasses:             append([]string(nil), current.Grants.DataClasses...),
		ApprovalDecisionVersion: current.Grants.ApprovalDecisionVersion,
	}
}

func (r *Runner) plan(ctx context.Context, invoke modelgateway.InvokeRequest, repairs int, budget planning.AttemptBudget) (planning.Result, error) {
	engine, err := planning.New(r.invoker, 8, boundRepairs(repairs))
	if err != nil {
		return planning.Result{}, err
	}
	return engine.Plan(ctx, invoke, budget)
}

// attemptBudget enforces the pinned remaining budget before every provider
// attempt of one turn, repair attempts included.
type attemptBudget struct {
	view               BudgetView
	limits             Limits
	providerCostMicros int64
}

func (b attemptBudget) Authorize(_ int, used planning.Usage) (planning.AttemptLimits, error) {
	remainingCalls := b.view.RemainingModelCalls - used.ModelCalls
	remainingInput := b.view.RemainingInputTokens - used.InputTokens
	remainingOutput := b.view.RemainingOutputTokens - used.OutputTokens
	// used covers every physical attempt already made inside this invocation
	// and, through the planning wrapper, every earlier repair attempt of the
	// turn, so the aggregate allowance shrinks across repairs and retries
	// exactly as it does across turns.
	remainingTotal := b.view.RemainingTotalTokens - (used.InputTokens + used.OutputTokens)
	remainingCost := b.view.RemainingCostMicros - used.CostMicros
	if remainingCalls < 1 || remainingInput < 1 || remainingOutput < 1 || remainingTotal < 1 || remainingCost < 1 {
		details := problem.New(problem.CodeBudgetDenied, "")
		details.Detail = "the pinned agent budget is exhausted"
		return planning.AttemptLimits{}, details
	}
	cost := remainingCost
	if b.providerCostMicros < cost {
		cost = b.providerCostMicros
	}
	// No component ceiling may exceed what is left of the aggregate: an
	// attempt authorized for more input than the aggregate allows would
	// spend past the pinned total in a single call.
	return planning.AttemptLimits{
		MaximumInputTokens:  minimum64(minimum64(b.limits.MaximumInputTokens, remainingInput), remainingTotal),
		MaximumOutputTokens: minimum64(minimum64(b.limits.MaximumOutputTokens, remainingOutput), remainingTotal),
		MaximumTotalTokens:  minimum64(b.limits.MaximumInputTokens+b.limits.MaximumOutputTokens, remainingTotal),
		MaximumCostMicros:   cost,
	}, nil
}

func (r *Runner) compileContext(ctx context.Context, instruction string, request TurnRequest) ([]byte, error) {
	sources := []contextcompiler.Source{
		{ID: "instruction", Trust: contextcompiler.System, Classification: contextcompiler.Internal, Content: instruction, WorkspaceID: request.Run.WorkspaceID, TokenBudget: r.limits.ContextTokens / 4},
		{ID: "task", Trust: contextcompiler.Agent, Classification: contextcompiler.Internal, Content: taskDescription(request), WorkspaceID: request.Run.WorkspaceID, TokenBudget: r.limits.ContextTokens / 4},
	}
	if len(request.InputValue) > 0 {
		sources = append(sources, contextcompiler.Source{ID: "input-response", Trust: contextcompiler.User, Classification: contextcompiler.Internal, Content: string(request.InputValue), WorkspaceID: request.Run.WorkspaceID, TokenBudget: r.limits.ContextTokens / 8})
	}
	if request.ReviewReason != "" {
		sources = append(sources, contextcompiler.Source{ID: "review-guidance", Trust: contextcompiler.User, Classification: contextcompiler.Internal, Content: request.ReviewReason, WorkspaceID: request.Run.WorkspaceID, TokenBudget: r.limits.ContextTokens / 8})
	}
	for index, note := range boundedNotes(request.Notes) {
		sources = append(sources, contextcompiler.Source{ID: fmt.Sprintf("note-%02d", index), Trust: contextcompiler.ToolOutput, Classification: contextcompiler.Internal, Content: note, WorkspaceID: request.Run.WorkspaceID, TokenBudget: r.limits.ContextTokens / 16})
	}
	compiled, err := r.compiler.Compile(ctx, contextcompiler.Request{
		WorkspaceID:     request.Run.WorkspaceID,
		ProjectID:       request.Run.ProjectID,
		RunID:           request.Run.RunID,
		Sources:         sources,
		Policy:          contextcompiler.PolicyReference{PolicyID: request.Definition.GuardrailPolicy.PolicyID, Version: request.Definition.GuardrailPolicy.Version, Digest: request.Definition.GuardrailPolicy.Digest},
		RedactionPolicy: contextcompiler.PolicyReference{PolicyID: request.Definition.GuardrailPolicy.PolicyID, Version: request.Definition.GuardrailPolicy.Version, Digest: request.Definition.GuardrailPolicy.Digest},
		TotalTokens:     r.limits.ContextTokens,
		CompiledAt:      r.clock.Now(),
	})
	if err != nil {
		return nil, err
	}
	var builder strings.Builder
	for _, layer := range compiled.Disclosure {
		builder.WriteString("[" + string(layer.Trust) + ":" + layer.LayerID + "]\n")
		builder.WriteString(layer.Content)
		builder.WriteString("\n")
	}
	return []byte(builder.String()), nil
}

// resolveDecision maps the first validated typed-plan step onto the explicit
// decision vocabulary and enforces every definition constraint the decision
// depends on. It returns a non-empty reason when the proposal is invalid.
func (r *Runner) resolveDecision(plan planning.Plan, request TurnRequest) (agent.TurnDecision, string) {
	first := plan.Steps[0]
	arguments := func() json.RawMessage {
		raw, err := json.Marshal(first.Arguments)
		if err != nil {
			return nil
		}
		return raw
	}
	switch first.Tool {
	case planContinue:
		note := stringArgument(first.Arguments, "note")
		return agent.TurnDecision{Kind: agent.DecisionContinue, Continue: &agent.ContinueDecision{Note: note}}, ""
	case planNeedInput:
		question := stringArgument(first.Arguments, "question")
		if question == "" {
			return agent.TurnDecision{}, "input request requires a bounded question"
		}
		if !hasStopCondition(request.Definition, "input-required") {
			return agent.TurnDecision{}, "definition does not allow input requests"
		}
		return agent.TurnDecision{Kind: agent.DecisionNeedInput, NeedInput: &agent.NeedInputDecision{Question: question}}, ""
	case planDelegate:
		delegate := stringArgument(first.Arguments, "delegate")
		input, hasInput := first.Arguments["input"]
		if delegate == "" || !hasInput {
			return agent.TurnDecision{}, "delegation requires a delegate identity and input"
		}
		if !request.Definition.AllowsDelegate(delegate) {
			return agent.TurnDecision{}, "delegate is not in the pinned allowed-delegate set"
		}
		return agent.TurnDecision{Kind: agent.DecisionDelegate, Delegate: &agent.DelegateDecision{DelegateID: delegate, Input: append(json.RawMessage(nil), input...)}}, ""
	case planFinal:
		candidate, hasCandidate := first.Arguments["candidate"]
		if !hasCandidate {
			return agent.TurnDecision{}, "final decision requires a candidate document"
		}
		summary := stringArgument(first.Arguments, "summary")
		return agent.TurnDecision{Kind: agent.DecisionFinal, Final: &agent.FinalDecision{Candidate: append(json.RawMessage(nil), candidate...), Summary: summary}}, ""
	case planRefuse:
		reason := stringArgument(first.Arguments, "reason")
		if reason == "" {
			return agent.TurnDecision{}, "refusal requires a bounded reason"
		}
		return agent.TurnDecision{Kind: agent.DecisionRefuse, Refuse: &agent.RefuseDecision{Reason: reason}}, ""
	default:
		if strings.HasPrefix(first.Tool, "agent.") {
			return agent.TurnDecision{}, "plan proposed an unknown reserved decision"
		}
		if !request.Definition.AllowsTool(first.Tool) {
			return agent.TurnDecision{}, "plan proposed a tool outside the pinned profile"
		}
		raw := arguments()
		if raw == nil {
			return agent.TurnDecision{}, "tool arguments are not serializable"
		}
		return agent.TurnDecision{Kind: agent.DecisionToolCall, ToolCall: &agent.ToolCallDecision{ToolID: first.Tool, Arguments: raw}}, ""
	}
}

func precheck(budget BudgetView) *Halted {
	if budget.RemainingModelCalls >= 1 && budget.RemainingInputTokens >= 1 && budget.RemainingOutputTokens >= 1 && budget.RemainingTotalTokens >= 1 && budget.RemainingCostMicros >= 1 {
		return nil
	}
	details := problem.New(problem.CodeBudgetDenied, "")
	details.Detail = "the pinned agent budget is exhausted"
	return &Halted{Problem: details, Refuse: budget.ExceedBehavior == "refuse"}
}

// Consume subtracts recorded usage from a budget view. The executor uses it
// to derive the remaining budget for the next durable boundary.
func Consume(budget BudgetView, usage agent.Usage) BudgetView {
	budget.RemainingModelCalls -= usage.ModelCalls
	budget.RemainingInputTokens -= usage.InputTokens
	budget.RemainingOutputTokens -= usage.OutputTokens
	budget.RemainingTotalTokens -= usage.InputTokens + usage.OutputTokens
	budget.RemainingCostMicros -= usage.CostMicros
	return budget
}

func refusal(code problem.Code, detail string) *problem.Details {
	details := problem.New(code, "")
	details.Detail = detail
	return &details
}

// usageOf accounts every physical provider attempt the turn caused, not one
// call per planning attempt: a planning attempt that took three transport
// retries billed three provider calls and is charged as three.
func usageOf(result planning.Result) agent.Usage {
	usage := agent.Usage{}
	for _, attempt := range result.Attempts {
		usage.ModelCalls += int64(len(attempt.Invocation.PhysicalAttempts))
		usage.InputTokens += attempt.Invocation.InputTokens
		usage.OutputTokens += attempt.Invocation.OutputTokens
		usage.CostMicros += attempt.Invocation.CostMicros
	}
	return usage
}

func taskDescription(request TurnRequest) string {
	return fmt.Sprintf("phase=%s turn=%d domain=%s operation=%s target=%s:%s", request.Phase, request.Turn, request.Run.Domain, request.Run.Operation, request.Run.TargetType, request.Run.TargetID)
}

func hasStopCondition(definition agent.Definition, condition string) bool {
	for _, stop := range definition.StopConditions {
		if stop == condition {
			return true
		}
	}
	return false
}

func stringArgument(arguments map[string]json.RawMessage, key string) string {
	raw, present := arguments[key]
	if !present {
		return ""
	}
	var value string
	if err := json.Unmarshal(raw, &value); err != nil {
		return ""
	}
	return value
}

func boundedNotes(notes []string) []string {
	const maximumNotes = 16
	if len(notes) <= maximumNotes {
		return notes
	}
	return notes[len(notes)-maximumNotes:]
}

func boundRepairs(value int) int {
	if value < 0 {
		return 0
	}
	if value > 3 {
		return 3
	}
	return value
}

func minimum64(left, right int64) int64 {
	if left < right {
		return left
	}
	return right
}

func truncate(value string, maximum int) string {
	if len(value) <= maximum {
		return value
	}
	return value[:maximum]
}
