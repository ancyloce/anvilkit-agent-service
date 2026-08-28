// Package runner implements the AgentRunner: the four stages one bounded turn
// passes through, in order — context compilation, task creation, result wait,
// and the next-step commit.
//
// The runner used to call a model. It no longer does, and cannot: a turn is
// executed by a runtime release in another process, and what reaches this
// package is a signed result proposing a decision. The stages are named after
// that shape because each is a different kind of failure — a context that
// cannot be compiled, work that cannot be admitted, an execution that never
// answered, and a result that may no longer change state — and collapsing them
// again would make a stale result indistinguishable from a failed one.
//
// The runner still owns no retries, durable waits, cancellation, checkpoints,
// approval, budget authority, or domain commits. It resolves exactly one
// TurnDecision per turn, under the fence the durable record issued it.
package runner

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/ancyloce/anvilkit-agent-service/contracts/generated/schema"
	"github.com/ancyloce/anvilkit-agent-service/internal/agent"
	"github.com/ancyloce/anvilkit-agent-service/internal/authority"
	"github.com/ancyloce/anvilkit-agent-service/internal/contextcompiler"
	"github.com/ancyloce/anvilkit-agent-service/internal/dispatch"
	"github.com/ancyloce/anvilkit-agent-service/internal/problem"
	"github.com/ancyloce/anvilkit-agent-service/internal/runtimes"
	"github.com/ancyloce/anvilkit-agent-service/internal/tools"
)

// ContextCompiler compiles the authorized trust layers for one turn.
type ContextCompiler interface {
	Compile(context.Context, contextcompiler.Request) (contextcompiler.Result, error)
}

// Tasks is the durable record of logical tasks and physical attempts. The
// runner depends on the coordinator's operations and nothing about how they
// are stored.
type Tasks interface {
	// Settled reads the answer a logical task already committed, if it has
	// one. It is consulted before anything is dispatched.
	Settled(ctx context.Context, scope dispatch.Scope, taskID string) (dispatch.Registration, bool, error)
	Open(ctx context.Context, request dispatch.Request) (dispatch.Execution, error)
	Dispatched(ctx context.Context, execution dispatch.Execution) error
	// Close ends an attempt this turn will not wait on any longer and will
	// not replace: a dispatch that answered with something that is not an
	// attributable result, or a turn that ended before its answer arrived.
	// An attempt left running after the turn gave up on it would stay the
	// task's current execution, with the runtime boundary still serving its
	// callbacks, until its lease ran out.
	Close(ctx context.Context, execution dispatch.Execution, reason string) error
	Settle(ctx context.Context, request dispatch.Settle) (dispatch.Result, error)
	// Unbound records a result this service will not attribute to the attempt
	// it is holding. A result refused before the fence never reaches Settle, so
	// without this the one class of failure most worth investigating — an
	// unverifiable signature, a result for other work — would be the only one
	// that left no trace.
	Unbound(ctx context.Context, scope dispatch.Scope, runID, taskID, attemptID, statementDigest, keyID, reason string) error
}

// Dispatcher executes one physical attempt on the release the run pinned. It
// is the transport-free port: the runner decides what to dispatch and what a
// result means, and how the bytes travel is the adapter's concern.
type Dispatcher interface {
	Dispatch(ctx context.Context, binding agent.RuntimeBinding, task schema.AgentTask, credential runtimes.Credential) (runtimes.DispatchReceipt, error)
}

// Credentials issues the short-lived, task-scoped authority one attempt is
// dispatched with. The tenant boundary is passed in because the canonical task
// carries none: what a runtime may act on comes from its credential.
type Credentials interface {
	Issue(ctx context.Context, task schema.AgentTask, subject runtimes.Subject) (runtimes.Credential, error)
}

// ResultVerification proves a result was produced by the release the run
// pinned, signed by a key the operator approved for it.
//
// It is separate from the fence and runs before it. The fence answers whether a
// result is still for the execution this process is holding; this answers
// whether the thing that produced it was the release that was dispatched to.
// Neither implies the other, and a commit needs both: a perfectly fenced result
// nobody can attribute is an anonymous proposal, and a perfectly signed result
// for a superseded attempt is a replay.
type ResultVerification interface {
	Verify(result schema.AgentRuntimeResult, binding agent.RuntimeBinding, now time.Time) error
}

// Disclosure hands one attempt's compiled context to a runtime that runs
// inside this process.
//
// It exists only for controlled compositions. A real runtime reads its
// task-scoped context across the process boundary, so production composes no
// disclosure at all and the compiled context leaves this process only as the
// digest the task pins. The port is optional for exactly that reason: a nil
// disclosure is the production case, not a missing dependency.
type Disclosure interface {
	Offer(ctx context.Context, task schema.AgentTask, compiled []byte) error
}

// Candidates resolves the content of an artifact a runtime produced.
//
// A final decision names its candidate as an immutable artifact reference,
// because the bounded decision payload cannot carry a document. Reading that
// artifact back is the runtime's artifact write path in reverse, and the
// service refuses a final decision whose artifact it cannot read rather than
// treating an unreadable reference as a candidate.
type Candidates interface {
	Content(ctx context.Context, reference schema.SharedPrimitivesArtifactReference) ([]byte, error)
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

// RunView is the bounded run identity the runner may disclose to a runtime.
type RunView struct {
	RunID       string `json:"runId"`
	RootRunID   string `json:"rootRunId"`
	WorkspaceID string `json:"workspaceId"`
	ProjectID   string `json:"projectId"`
	ActorID     string `json:"actorId"`
	Domain      string `json:"domain"`
	Operation   string `json:"operation"`
	TargetType  string `json:"targetType"`
	TargetID    string `json:"targetId"`
	// ExecutionGeneration is the run's generation fence. Every task, attempt,
	// and commit predicate carries it: a result produced under a superseded
	// generation is not a result for this run.
	ExecutionGeneration uint64 `json:"executionGeneration"`
	// Traceparent correlates the workflow, the task, the attempt, and the
	// runtime's own execution.
	Traceparent string `json:"traceparent"`
}

// BudgetView is the remaining budget the executor derived from the pinned
// AgentBudget and recorded usage. The runner enforces it before dispatching a
// turn; it never mutates budget authority.
type BudgetView struct {
	RemainingModelCalls   int64 `json:"remainingModelCalls"`
	RemainingInputTokens  int64 `json:"remainingInputTokens"`
	RemainingOutputTokens int64 `json:"remainingOutputTokens"`
	// RemainingTotalTokens is the aggregate input+output allowance the pinned
	// AgentBudget still has. It is enforced in its own right: a run that has
	// input and output allowance left may still be out of aggregate tokens.
	RemainingTotalTokens int64  `json:"remainingTotalTokens"`
	RemainingCostMicros  int64  `json:"remainingCostMicros"`
	ExceedBehavior       string `json:"exceedBehavior"`
}

// Limits bound one dispatched attempt.
type Limits struct {
	MaximumOutputBytes  int
	MaximumInputTokens  int64
	MaximumOutputTokens int64
	Timeout             time.Duration
	MaximumAttempts     int
	RetryBudget         time.Duration
	ContextTokens       int
	// MemoryBytes and CPUMillis are the resource envelope the task declares to
	// the runtime. They are contract fields, not process limits: the runtime's
	// deployment enforces them, and the task says what it was admitted for.
	MemoryBytes int64
	CPUMillis   int64
}

func (l Limits) validate() error {
	if l.MaximumOutputBytes < 1 || l.MaximumInputTokens < 1 || l.MaximumOutputTokens < 1 || l.Timeout <= 0 || l.MaximumAttempts < 1 || l.RetryBudget < 0 || l.ContextTokens < 1 {
		return fmt.Errorf("agent runner limits must be positive")
	}
	if l.MemoryBytes < minimumTaskMemoryBytes || l.CPUMillis < 1 {
		return fmt.Errorf("agent runner limits must declare the resource envelope a dispatched task runs under")
	}
	return nil
}

// minimumTaskMemoryBytes is the canonical ResourceLimits floor. Declaring less
// would produce a task no runtime may admit.
const minimumTaskMemoryBytes = 1 << 20

const (
	PhasePlan     = "plan"
	PhaseRevise   = "revise"
	PhaseDelegate = "delegate"
)

type TurnRequest struct {
	Definition agent.Definition
	Run        RunView
	// Runtime is the release the run pinned at creation. It is passed in
	// rather than resolved here: a turn must reach the release its run was
	// admitted against, whatever the registry would select now.
	Runtime agent.RuntimeBinding
	// ContractBOM is the run's pinned contract bill of materials. It travels
	// with the task so a runtime executes against the same contract material
	// this service verified.
	ContractBOM schema.SharedPrimitivesContractBomReference
	Phase       string
	Turn        int
	Depth       int
	Notes       []string
	InputValue  json.RawMessage
	// OperationKey is the durable operation identity of the turn. It is
	// required: the logical task identity is derived from it, so replaying the
	// durable step finds the task it already created instead of creating a
	// second one for the same work.
	OperationKey string
	// Authority is the current-authority observation the caller re-read
	// immediately before this turn, inside the same durable operation. The
	// runner discloses context to a runtime only while it is active.
	Authority       authority.Current
	ReviewReason    string
	DelegationsUsed int
	Budget          BudgetView
	// Delegation is the outcome of the run's most recent delegation, when this
	// turn is the one that concludes on it. It travels into the task's supplied
	// context so the runtime validates the outcome the control plane holds,
	// never one it remembers.
	Delegation *DelegationOutcome
}

// DelegationOutcome is the durable account of one concluded delegation.
type DelegationOutcome struct {
	// State is the governed vocabulary the concluding turn reads:
	// completed, failed, or refused.
	State      string
	DelegateID string
	ReasonCode string
	// Candidate is the immutable reference of the delegated candidate; zero
	// unless the delegation completed.
	Candidate schema.SharedPrimitivesArtifactReference
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
	// CandidateReference is the immutable reference a final decision named,
	// carried beside the resolved candidate document so a delegation's
	// conclusion can pin the reference into the next turn's task.
	CandidateReference schema.SharedPrimitivesArtifactReference
}

// Runner executes turns. It is stateless between calls.
type Runner struct {
	registry    *agent.Registry
	compiler    ContextCompiler
	tasks       Tasks
	dispatcher  Dispatcher
	credentials Credentials
	signatures  ResultVerification
	disclosure  Disclosure
	candidates  Candidates
	guard       ActionGuard
	validator   CandidateValidator
	clock       Clock
	limits      Limits
	observer    DispatchObserver
}

type Config struct {
	Registry    *agent.Registry
	Compiler    ContextCompiler
	Tasks       Tasks
	Dispatcher  Dispatcher
	Credentials Credentials
	// Signatures verifies the signature envelope of every result before the
	// fenced commit. It is required: a deployment that could not attribute a
	// result to a release would be committing state on the word of whatever
	// answered the dispatch.
	Signatures ResultVerification
	// Disclosure is optional and is composed only where the runtime runs
	// inside this process. See the port's own documentation.
	Disclosure Disclosure
	// Candidates is optional in the same sense: a composition that cannot read
	// runtime-produced artifacts refuses a final decision rather than
	// inventing one.
	Candidates Candidates
	Guard      ActionGuard
	Validator  CandidateValidator
	Clock      Clock
	Limits     Limits
	// Observer receives the bounded facts of the dispatch path. It is
	// optional: a composition without telemetry runs under a no-op.
	Observer DispatchObserver
}

func New(cfg Config) (*Runner, error) {
	if cfg.Registry == nil || cfg.Compiler == nil || cfg.Tasks == nil || cfg.Dispatcher == nil || cfg.Credentials == nil || cfg.Signatures == nil || cfg.Guard == nil || cfg.Validator == nil || cfg.Clock == nil {
		return nil, fmt.Errorf("agent runner: every pipeline dependency is required")
	}
	if err := cfg.Limits.validate(); err != nil {
		return nil, err
	}
	observer := cfg.Observer
	if observer == nil {
		observer = noopObserver{}
	}
	return &Runner{
		observer:    observer,
		registry:    cfg.Registry,
		compiler:    cfg.Compiler,
		tasks:       cfg.Tasks,
		dispatcher:  cfg.Dispatcher,
		credentials: cfg.Credentials,
		signatures:  cfg.Signatures,
		disclosure:  cfg.Disclosure,
		candidates:  cfg.Candidates,
		guard:       cfg.Guard,
		validator:   cfg.Validator,
		clock:       cfg.Clock,
		limits:      cfg.Limits,
	}, nil
}

// Turn executes one bounded turn: authority and budget prechecks, authorized
// context compilation, task and attempt creation, one dispatched execution on
// the pinned runtime release, and the fenced commit of whatever came back.
func (r *Runner) Turn(ctx context.Context, request TurnRequest) (TurnOutcome, error) {
	if request.OperationKey == "" {
		return TurnOutcome{}, fmt.Errorf("agent runner: a durable operation key is required for every turn")
	}
	// Nothing is compiled, dispatched, or disclosed until the re-read authority
	// the caller carried into this turn is proven active.
	if details := requireActive(request.Authority); details != nil {
		return TurnOutcome{Halted: &Halted{Problem: *details}}, nil
	}
	// The budget is checked before any task exists. An exhausted budget must
	// not produce a dispatched attempt that a later result could commit: the
	// cheapest place to stop is before the work is admitted at all.
	if halted := precheck(request.Budget); halted != nil {
		return TurnOutcome{Halted: halted}, nil
	}
	// A durable step that committed and then failed before recording its own
	// output is re-executed by the engine. The work is not done again: the
	// answer the logical task already committed is read back, which is what
	// makes redelivery free of a second provider call, a second charge, and a
	// second artifact.
	if outcome, replayed, err := r.replay(ctx, request); err != nil || replayed {
		return outcome, err
	}
	instruction, err := r.registry.Instruction(request.Definition.DefinitionID)
	if err != nil {
		return TurnOutcome{}, err
	}
	compiled, err := r.compileContext(ctx, instruction, request)
	if err != nil {
		return TurnOutcome{}, fmt.Errorf("compile turn context: %w", err)
	}
	// One turn may cost several executions. A dispatch that never answered is
	// replaced by a new physical attempt with its own number, lease epoch, and
	// fence, which is what makes the unanswered one permanently uncommittable;
	// the loop is bounded by the configured attempts and retry budget so a
	// release that is simply down cannot spin a turn for ever.
	deadline := r.clock.Now().Add(r.limits.RetryBudget)
	replacing := ""
	for attempt := 1; ; attempt++ {
		task, execution, credential, err := r.createTask(ctx, request, compiled, replacing)
		if err != nil {
			return TurnOutcome{}, err
		}
		receipt, err := r.awaitResult(ctx, request, task, execution, credential)
		if err == nil {
			return r.commitNextStep(ctx, request, execution, receipt)
		}
		if isUnanswered(err) && attempt < r.limits.MaximumAttempts && r.clock.Now().Before(deadline) {
			replacing = dispatch.ReasonDispatchFailed
			r.observer.ObserveReplacement(ctx, request.Runtime.RuntimeUnitID, replacing)
			continue
		}
		// No replacement will be opened for this attempt, so it is closed rather
		// than left running. An execution nobody waits on any longer must stop
		// being the task's current attempt: the runtime boundary refuses
		// callbacks from an attempt that is no longer current, and only a
		// closed attempt is one it can refuse.
		reason := dispatch.ReasonTurnAbandoned
		if isUnanswered(err) {
			reason = dispatch.ReasonDispatchFailed
		}
		return TurnOutcome{}, r.abandon(ctx, execution, reason, err)
	}
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
	Specialist agent.Definition
	Run        RunView
	// Runtime is the release serving the Specialist. A delegation crosses a
	// runtime boundary as well as a definition boundary: the Specialist runs
	// on its own release, with its own image and audience.
	Runtime      agent.RuntimeBinding
	ContractBOM  schema.SharedPrimitivesContractBomReference
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
	// CandidateReference is the immutable reference of the accepted candidate.
	CandidateReference schema.SharedPrimitivesArtifactReference
	Refused            *problem.Details
	Usage              agent.Usage
	Notes              []string
	Halted             *Halted
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
		Runtime:         request.Runtime,
		ContractBOM:     request.ContractBOM,
		Phase:           PhaseDelegate,
		Turn:            request.Turn,
		Depth:           request.Depth,
		Notes:           notes,
		InputValue:      request.Input,
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
		outcome.CandidateReference = turnOutcome.CandidateReference
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

func hasStopCondition(definition agent.Definition, condition string) bool {
	for _, stop := range definition.StopConditions {
		if stop == condition {
			return true
		}
	}
	return false
}

func truncate(value string, maximum int) string {
	if len(value) <= maximum {
		return value
	}
	return value[:maximum]
}
