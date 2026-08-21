// Package workflow owns the canonical AgentRunWorkflow. It is the only
// top-level durable business workflow, expressed against a repository-owned
// durable runtime port. Every type crossing this boundary is JSON serializable
// and contains no engine value; engine adapters supply the Host primitives and
// application code supplies the Operations pipeline.
package workflow

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/ancyloce/anvilkit-agent-service/internal/agent"
	"github.com/ancyloce/anvilkit-agent-service/internal/problem"
)

// Scope carries the authorization identities pinned at run creation.
type Scope struct {
	WorkspaceID string `json:"workspaceId"`
	ProjectID   string `json:"projectId"`
	ActorID     string `json:"actorId"`
}

// RunKey identifies one durable execution generation of one AgentRun. The
// generation is the explicit-retry execution generation from the run
// aggregate; it is runtime identity, not a release generation.
type RunKey struct {
	RunID      string `json:"runId"`
	Generation uint64 `json:"generation"`
}

// WorkflowID derives the engine workflow instance identity for the key.
func (k RunKey) WorkflowID() string { return fmt.Sprintf("%s:g%d", k.RunID, k.Generation) }

// ParseWorkflowID recovers the run key from an engine workflow identity.
func ParseWorkflowID(id string) (RunKey, error) {
	separator := strings.LastIndex(id, ":g")
	if separator < 1 || separator+2 >= len(id) {
		return RunKey{}, fmt.Errorf("workflow identity %q is not a run key", id)
	}
	generation, err := strconv.ParseUint(id[separator+2:], 10, 64)
	if err != nil || generation < 1 {
		return RunKey{}, fmt.Errorf("workflow identity %q carries no execution generation", id)
	}
	return RunKey{RunID: id[:separator], Generation: generation}, nil
}

// DerivedTraceparent produces a deterministic valid W3C traceparent for
// internally originated workflow operations that carry no caller trace.
func (k RunKey) DerivedTraceparent() string {
	digest := sha256.Sum256([]byte(k.WorkflowID()))
	hexDigest := hex.EncodeToString(digest[:])
	return "00-" + hexDigest[:32] + "-" + hexDigest[32:48] + "-01"
}

// RunInput is the complete workflow input. It carries intent identity only;
// all authority is re-read inside durable operations.
type RunInput struct {
	Key         RunKey `json:"key"`
	Scope       Scope  `json:"scope"`
	Traceparent string `json:"traceparent"`
}

func (i RunInput) Validate() error {
	if !validOpaqueID(i.Key.RunID) || len(i.Key.RunID) > 107 {
		return fmt.Errorf("agent run workflow: bounded run identity is required")
	}
	if i.Key.Generation < 1 {
		return fmt.Errorf("agent run workflow: execution generation must be positive")
	}
	if !validOpaqueID(i.Scope.WorkspaceID) || !validOpaqueID(i.Scope.ProjectID) || !validOpaqueID(i.Scope.ActorID) {
		return fmt.Errorf("agent run workflow: bounded workspace, project, and actor identities are required")
	}
	if i.Traceparent != "" && !validTraceparent(i.Traceparent) {
		return fmt.Errorf("agent run workflow: traceparent must be empty or use the W3C format")
	}
	return nil
}

// TerminalState is the workflow-level outcome. Superseded means another
// authority (cancel, explicit retry, newer generation) owns the run and this
// workflow exited without writing state.
type TerminalState string

const (
	TerminalCompleted  TerminalState = "completed"
	TerminalFailed     TerminalState = "failed"
	TerminalCancelled  TerminalState = "cancelled"
	TerminalRefused    TerminalState = "refused"
	TerminalSuperseded TerminalState = "superseded"
	// TerminalUnresolved reports that the workflow released a run whose
	// governed effect stayed unsettled through the bounded reconciliation
	// window. The run aggregate keeps its submit-boundary state — nothing was
	// failed, nothing was resent — and the audited operator-resolution path
	// settles it from the durable submission record.
	TerminalUnresolved TerminalState = "unresolved"
)

type RunOutcome struct {
	Key      RunKey           `json:"key"`
	Terminal TerminalState    `json:"terminal"`
	Problem  *problem.Details `json:"problem,omitempty"`
}

// OpID names one durable operation boundary. Operations must be idempotent
// for one OpID: engine recovery may re-invoke an operation whose effect
// committed before its checkpoint was recorded.
type OpID struct {
	WorkflowID string `json:"workflowId"`
	Step       string `json:"step"`
}

// Key is a bounded idempotency identity for external effects of the step.
func (o OpID) Key() string { return o.WorkflowID + ":" + o.Step }

// Phase distinguishes the planning loop from post-review revision. Input
// requests are legal only while planning; revision turns run in the executing
// aggregate state.
type Phase string

const (
	PhasePlan   Phase = "plan"
	PhaseRevise Phase = "revise"
)

// Carry is the deterministic state threaded between turns. It is derived
// exclusively from recorded operation outputs, so replay reconstructs it
// byte-identically.
type Carry struct {
	Notes        []string        `json:"notes,omitempty"`
	InputValue   json.RawMessage `json:"inputValue,omitempty"`
	ReviewReason string          `json:"reviewReason,omitempty"`
	Usage        agent.Usage     `json:"usage"`
	Delegations  int             `json:"delegations"`
	Version      uint64          `json:"version"`
}

// Halt is a typed non-error stop resolved by an operation: budget or limit
// exhaustion with the deterministic behavior the definition demands.
type Halt struct {
	Problem  problem.Details `json:"problem"`
	Behavior TerminalState   `json:"behavior"`
}

type PrepareResult struct {
	Superseded       bool             `json:"superseded,omitempty"`
	Refused          *problem.Details `json:"refused,omitempty"`
	TurnLimit        int              `json:"turnLimit"`
	DefinitionID     string           `json:"definitionId"`
	DefinitionDigest string           `json:"definitionDigest"`
	Version          uint64           `json:"version"`
}

type TurnInput struct {
	Run   RunInput `json:"run"`
	Turn  int      `json:"turn"`
	Phase Phase    `json:"phase"`
	Carry Carry    `json:"carry"`
}

type TurnResult struct {
	Superseded bool               `json:"superseded,omitempty"`
	Decision   agent.TurnDecision `json:"decision"`
	Carry      Carry              `json:"carry"`
	Halt       *Halt              `json:"halt,omitempty"`
}

type DecisionRecord struct {
	Run      RunInput           `json:"run"`
	Turn     int                `json:"turn"`
	Phase    Phase              `json:"phase"`
	Decision agent.TurnDecision `json:"decision"`
}

type Ack struct {
	Superseded bool `json:"superseded,omitempty"`
	// Raced reports that an accepted response or decision won the race
	// against expiry; the caller re-reads instead of failing the run.
	Raced   bool   `json:"raced,omitempty"`
	Version uint64 `json:"version"`
	// Halt carries a typed stop resolved inside the operation, such as
	// authority revoked before a retry. The workflow stops on it and never
	// continues normal execution.
	Halt *Halt `json:"halt,omitempty"`
}

type ActionInput struct {
	Run      RunInput           `json:"run"`
	Turn     int                `json:"turn"`
	Phase    Phase              `json:"phase"`
	Decision agent.TurnDecision `json:"decision"`
	Carry    Carry              `json:"carry"`
}

type ActionResult struct {
	Superseded bool  `json:"superseded,omitempty"`
	Carry      Carry `json:"carry"`
	Halt       *Halt `json:"halt,omitempty"`
}

// DelegationInput opens one Specialist delegation. Authorization, depth,
// fan-out, authority, and input-schema checks all run inside this boundary.
type DelegationInput struct {
	Run      RunInput           `json:"run"`
	Turn     int                `json:"turn"`
	Phase    Phase              `json:"phase"`
	Decision agent.TurnDecision `json:"decision"`
	Carry    Carry              `json:"carry"`
}

// DelegationOpened is the authorized delegation boundary. Refused reports a
// durable, typed refusal already folded into the carry notes.
type DelegationOpened struct {
	Superseded       bool   `json:"superseded,omitempty"`
	Refused          bool   `json:"refused,omitempty"`
	TurnLimit        int    `json:"turnLimit"`
	SpecialistID     string `json:"specialistId,omitempty"`
	SpecialistDigest string `json:"specialistDigest,omitempty"`
	Carry            Carry  `json:"carry"`
	Halt             *Halt  `json:"halt,omitempty"`
}

// DelegateTurnInput is one durable Specialist turn inside an opened
// delegation. Each turn is its own recoverable boundary.
type DelegateTurnInput struct {
	Run              RunInput        `json:"run"`
	Turn             int             `json:"turn"`
	DelegateTurn     int             `json:"delegateTurn"`
	Last             bool            `json:"last"`
	Phase            Phase           `json:"phase"`
	SpecialistID     string          `json:"specialistId"`
	SpecialistDigest string          `json:"specialistDigest"`
	Input            json.RawMessage `json:"input"`
	Carry            Carry           `json:"carry"`
}

// DelegateTurnResult reports whether the delegation concluded on this turn.
type DelegateTurnResult struct {
	Superseded bool  `json:"superseded,omitempty"`
	Done       bool  `json:"done"`
	Carry      Carry `json:"carry"`
	Halt       *Halt `json:"halt,omitempty"`
}

type InterruptOpen struct {
	Run      RunInput `json:"run"`
	Turn     int      `json:"turn"`
	Question string   `json:"question"`
	Version  uint64   `json:"version"`
}

type InterruptOpened struct {
	Superseded    bool   `json:"superseded,omitempty"`
	RequestID     string `json:"requestId"`
	TimeoutMillis int64  `json:"timeoutMillis"`
	Version       uint64 `json:"version"`
	Halt          *Halt  `json:"halt,omitempty"`
}

type InterruptRef struct {
	Run       RunInput `json:"run"`
	Turn      int      `json:"turn"`
	RequestID string   `json:"requestId"`
}

type InputRead struct {
	Superseded      bool            `json:"superseded,omitempty"`
	Accepted        bool            `json:"accepted"`
	Expired         bool            `json:"expired"`
	RemainingMillis int64           `json:"remainingMillis"`
	Value           json.RawMessage `json:"value,omitempty"`
	Version         uint64          `json:"version"`
}

type ApprovalRead struct {
	Superseded      bool   `json:"superseded,omitempty"`
	Decided         bool   `json:"decided"`
	Kind            string `json:"kind,omitempty"`
	Reason          string `json:"reason,omitempty"`
	Expired         bool   `json:"expired"`
	RemainingMillis int64  `json:"remainingMillis"`
	Version         uint64 `json:"version"`
}

type ExpireRequest struct {
	Run       RunInput `json:"run"`
	Turn      int      `json:"turn"`
	RequestID string   `json:"requestId"`
	Kind      string   `json:"kind"`
	Version   uint64   `json:"version"`
}

type FinalizeInput struct {
	Run      RunInput           `json:"run"`
	Turn     int                `json:"turn"`
	Phase    Phase              `json:"phase"`
	Decision agent.TurnDecision `json:"decision"`
	Carry    Carry              `json:"carry"`
}

type FinalizeResult struct {
	Superseded     bool             `json:"superseded,omitempty"`
	Rejected       *problem.Details `json:"rejected,omitempty"`
	ArtifactDigest string           `json:"artifactDigest,omitempty"`
	Version        uint64           `json:"version"`
}

type ReviewInput struct {
	Run            RunInput `json:"run"`
	Turn           int      `json:"turn"`
	ArtifactDigest string   `json:"artifactDigest"`
	Version        uint64   `json:"version"`
}

type ReviewResult struct {
	Superseded    bool   `json:"superseded,omitempty"`
	Accepted      bool   `json:"accepted"`
	RequestID     string `json:"requestId,omitempty"`
	TimeoutMillis int64  `json:"timeoutMillis,omitempty"`
	Version       uint64 `json:"version"`
	Halt          *Halt  `json:"halt,omitempty"`
}

type CommitInput struct {
	Run            RunInput `json:"run"`
	Turn           int      `json:"turn"`
	RequestID      string   `json:"requestId"`
	ArtifactDigest string   `json:"artifactDigest"`
	Version        uint64   `json:"version"`
}

const (
	CommitCompleted = "completed"
	CommitConflict  = "conflict"
	CommitFailed    = "failed"
)

type CommitResult struct {
	Superseded bool             `json:"superseded,omitempty"`
	Outcome    string           `json:"outcome"`
	Problem    *problem.Details `json:"problem,omitempty"`
	Version    uint64           `json:"version"`
	Halt       *Halt            `json:"halt,omitempty"`
	// Unsettled reports that the governed effect reached the submit boundary
	// but no authoritative record decides it yet. The workflow holds at the
	// boundary — waiting RetryAfterMillis or an explicit domain signal — and
	// reconciles again under a fresh durable step. It never fails the run and
	// never resends the command.
	Unsettled        bool  `json:"unsettled,omitempty"`
	RetryAfterMillis int64 `json:"retryAfterMillis,omitempty"`
	// Escalated reports that the unsettled governed effect is durably
	// escalated for operator resolution. It is the only thing that permits the
	// workflow to release a run at the submit boundary: the durable
	// escalation, not a wake count, is what makes releasing safe. An operation
	// sets it from the submission journal's recorded state, never from its own
	// bookkeeping.
	Escalated bool `json:"escalated,omitempty"`
}

type ReviseInput struct {
	Run          RunInput `json:"run"`
	Turn         int      `json:"turn"`
	Reason       string   `json:"reason"`
	FromConflict bool     `json:"fromConflict"`
	Version      uint64   `json:"version"`
}

type TerminalInput struct {
	Run     RunInput         `json:"run"`
	Turn    int              `json:"turn"`
	Kind    TerminalState    `json:"kind"`
	Problem *problem.Details `json:"problem,omitempty"`
	Version uint64           `json:"version"`
}

// Operations is the application pipeline behind every recoverable workflow
// boundary. Implementations perform all nondeterministic work, convert raw
// errors into serializable ProblemDetails, and stay idempotent per OpID.
type Operations interface {
	Prepare(context.Context, OpID, RunInput) (PrepareResult, error)
	ExecuteTurn(context.Context, OpID, TurnInput) (TurnResult, error)
	RecordDecision(context.Context, OpID, DecisionRecord) (Ack, error)
	ExecuteAction(context.Context, OpID, ActionInput) (ActionResult, error)
	OpenDelegation(context.Context, OpID, DelegationInput) (DelegationOpened, error)
	ExecuteDelegateTurn(context.Context, OpID, DelegateTurnInput) (DelegateTurnResult, error)
	OpenInput(context.Context, OpID, InterruptOpen) (InterruptOpened, error)
	ReadInput(context.Context, OpID, InterruptRef) (InputRead, error)
	ExpireInterrupt(context.Context, OpID, ExpireRequest) (Ack, error)
	FinalizeCandidate(context.Context, OpID, FinalizeInput) (FinalizeResult, error)
	ResolveReview(context.Context, OpID, ReviewInput) (ReviewResult, error)
	ReadApproval(context.Context, OpID, InterruptRef) (ApprovalRead, error)
	Revise(context.Context, OpID, ReviseInput) (Ack, error)
	Commit(context.Context, OpID, CommitInput) (CommitResult, error)
	Terminalize(context.Context, OpID, TerminalInput) (Ack, error)
}

// Host supplies the durable primitives one engine adapter implements. Step
// executes fn once per (workflow, name) and replays the recorded bytes on
// recovery. AwaitSignal blocks on a durable topic message with a durable
// deadline: recovery waits only the remaining time.
type Host interface {
	WorkflowID() string
	Step(name string, fn func(context.Context) ([]byte, error)) ([]byte, error)
	AwaitSignal(topic string, timeout time.Duration) (payload []byte, timedOut bool, err error)
}

// Runtime is the repository-owned durable runtime port.
type Runtime interface {
	Start(context.Context) error
	Stop(context.Context) error
	// StartRun ensures the durable AgentRunWorkflow for the key exists without
	// awaiting its outcome. Starting an existing key is idempotent.
	StartRun(context.Context, RunInput) error
	// ExecuteRun ensures the workflow exists and awaits its outcome.
	ExecuteRun(context.Context, RunInput) (RunOutcome, error)
	Signal(ctx context.Context, key RunKey, topic string, payload json.RawMessage, idempotencyKey string) error
	CancelRun(context.Context, RunKey) error
}

func InputTopic(requestID string) string    { return "input:" + requestID }
func ApprovalTopic(requestID string) string { return "approval:" + requestID }

// DomainTopic is the signal topic a run's commit wait listens on. Signaling
// it wakes an unsettled commit immediately — after an operator resolution or
// a late authoritative answer — instead of waiting out the bounded backoff.
func DomainTopic(runID string) string { return "domain:" + runID }

// maximumWakes bounds spurious wake handling per interrupt so a broken signal
// source cannot spin the workflow.
const maximumWakes = 64

// commitHoldWakes is how long the workflow keeps reconciling a governed effect
// that is already durably escalated. Escalation does not end the hold: the
// owner's late answer still settles the run without any operator action, and
// this window is how long the workflow stays available to observe it.
const commitHoldWakes = 64

// MaximumCommitWakes is the commit loop's spin guard. It is deliberately not a
// release boundary: a run holding at the submit boundary is released only once
// the commit operation reports a durable escalation, so this bound exists
// solely to stop a broken signal source or a submission journal that never
// counts from looping for ever. Reaching it is a defect, and the workflow
// errors rather than releasing an unescalated run.
const MaximumCommitWakes = 4096

// MaximumDomainReconciliations is the largest reconciliation window a
// deployment may configure. Bounding configuration by the same constant the
// commit loop spins on is what keeps the two from drifting into the state
// where the loop gives up before the operation has escalated anything.
const MaximumDomainReconciliations = MaximumCommitWakes / 2

// maximumDelegateTurns bounds the durable Specialist turn boundaries one
// delegation may open, independently of the definition's own turn limit.
const maximumDelegateTurns = 1024

// AgentRunWorkflow is the single canonical durable business workflow. The
// function is deterministic: every branch depends only on recorded operation
// outputs, and all side effects run behind Host.Step boundaries.
func AgentRunWorkflow(host Host, ops Operations, input RunInput) (RunOutcome, error) {
	if err := input.Validate(); err != nil {
		return RunOutcome{}, err
	}
	run := runContext{host: host, ops: ops, input: input}

	prep, err := step(host, "prepare", func(ctx context.Context) (PrepareResult, error) {
		return ops.Prepare(ctx, run.op("prepare"), input)
	})
	if err != nil {
		return run.fail(0, problemOf(err))
	}
	if prep.Superseded {
		return run.superseded()
	}
	if prep.Refused != nil {
		return run.terminal(0, TerminalRefused, prep.Refused)
	}

	carry := Carry{Version: prep.Version}
	phase := PhasePlan
	for turn := 0; ; turn++ {
		if turn >= prep.TurnLimit {
			exhausted := problem.New(problem.CodeLimitExceeded, "")
			exhausted.Detail = "agent run reached the pinned definition turn limit"
			return run.terminal(turn, TerminalFailed, &exhausted)
		}
		turnResult, err := step(host, name("turn", turn), func(ctx context.Context) (TurnResult, error) {
			return ops.ExecuteTurn(ctx, run.op(name("turn", turn)), TurnInput{Run: input, Turn: turn, Phase: phase, Carry: carry})
		})
		if err != nil {
			return run.fail(turn, problemOf(err))
		}
		if turnResult.Superseded {
			return run.superseded()
		}
		carry = turnResult.Carry
		if turnResult.Halt != nil {
			return run.halt(turn, *turnResult.Halt)
		}
		recorded, err := step(host, name("decision", turn), func(ctx context.Context) (Ack, error) {
			return ops.RecordDecision(ctx, run.op(name("decision", turn)), DecisionRecord{Run: input, Turn: turn, Phase: phase, Decision: turnResult.Decision})
		})
		if err != nil {
			return run.fail(turn, problemOf(err))
		}
		if recorded.Superseded {
			return run.superseded()
		}

		switch turnResult.Decision.Kind {
		case agent.DecisionContinue:
			continue

		case agent.DecisionRefuse:
			refusal := problem.New(problem.CodePolicyDenied, "")
			refusal.Detail = turnResult.Decision.Refuse.Reason
			return run.terminal(turn, TerminalRefused, &refusal)

		case agent.DecisionToolCall:
			action, err := step(host, name("action", turn), func(ctx context.Context) (ActionResult, error) {
				return ops.ExecuteAction(ctx, run.op(name("action", turn)), ActionInput{Run: input, Turn: turn, Phase: phase, Decision: turnResult.Decision, Carry: carry})
			})
			if err != nil {
				return run.fail(turn, problemOf(err))
			}
			if action.Superseded {
				return run.superseded()
			}
			carry = action.Carry
			if action.Halt != nil {
				return run.halt(turn, *action.Halt)
			}
			continue

		case agent.DecisionDelegate:
			// Every Specialist turn gets its own durable boundary, so a crash
			// inside a delegation resumes at the last completed Specialist
			// turn instead of replaying the whole delegation loop.
			opened, err := step(host, name("delegate-open", turn), func(ctx context.Context) (DelegationOpened, error) {
				return ops.OpenDelegation(ctx, run.op(name("delegate-open", turn)), DelegationInput{Run: input, Turn: turn, Phase: phase, Decision: turnResult.Decision, Carry: carry})
			})
			if err != nil {
				return run.fail(turn, problemOf(err))
			}
			if opened.Superseded {
				return run.superseded()
			}
			carry = opened.Carry
			if opened.Halt != nil {
				return run.halt(turn, *opened.Halt)
			}
			if opened.Refused {
				continue
			}
			if opened.TurnLimit < 1 || opened.TurnLimit > maximumDelegateTurns {
				invalid := problem.Internal("")
				invalid.Detail = "delegation opened outside the bounded specialist turn limit"
				return run.fail(turn, invalid)
			}
			concluded := false
			for delegateTurn := 0; delegateTurn < opened.TurnLimit; delegateTurn++ {
				stepName := delegateName(turn, delegateTurn)
				result, err := step(host, stepName, func(ctx context.Context) (DelegateTurnResult, error) {
					return ops.ExecuteDelegateTurn(ctx, run.op(stepName), DelegateTurnInput{
						Run:              input,
						Turn:             turn,
						DelegateTurn:     delegateTurn,
						Last:             delegateTurn == opened.TurnLimit-1,
						Phase:            phase,
						SpecialistID:     opened.SpecialistID,
						SpecialistDigest: opened.SpecialistDigest,
						Input:            turnResult.Decision.Delegate.Input,
						Carry:            carry,
					})
				})
				if err != nil {
					return run.fail(turn, problemOf(err))
				}
				if result.Superseded {
					return run.superseded()
				}
				carry = result.Carry
				if result.Halt != nil {
					return run.halt(turn, *result.Halt)
				}
				if result.Done {
					concluded = true
					break
				}
			}
			if !concluded {
				// The executor concludes on the last delegate turn, so an
				// unconcluded loop means the boundary contract was violated.
				invalid := problem.Internal("")
				invalid.Detail = "delegation exhausted its bounded turns without a durable conclusion"
				return run.fail(turn, invalid)
			}
			continue

		case agent.DecisionNeedInput:
			if phase != PhasePlan {
				invalid := problem.New(problem.CodeInvalidTransition, "")
				invalid.Detail = "input requests are legal only during planning"
				return run.terminal(turn, TerminalFailed, &invalid)
			}
			opened, err := step(host, name("open-input", turn), func(ctx context.Context) (InterruptOpened, error) {
				return ops.OpenInput(ctx, run.op(name("open-input", turn)), InterruptOpen{Run: input, Turn: turn, Question: turnResult.Decision.NeedInput.Question, Version: carry.Version})
			})
			if err != nil {
				return run.fail(turn, problemOf(err))
			}
			if opened.Superseded {
				return run.superseded()
			}
			if opened.Halt != nil {
				return run.halt(turn, *opened.Halt)
			}
			read, outcome, err := run.awaitInput(turn, opened)
			if err != nil {
				return RunOutcome{}, err
			}
			if outcome != nil {
				return *outcome, nil
			}
			carry.InputValue = read.Value
			carry.Version = read.Version
			continue

		case agent.DecisionFinal:
			finalized, err := step(host, name("finalize", turn), func(ctx context.Context) (FinalizeResult, error) {
				return ops.FinalizeCandidate(ctx, run.op(name("finalize", turn)), FinalizeInput{Run: input, Turn: turn, Phase: phase, Decision: turnResult.Decision, Carry: carry})
			})
			if err != nil {
				return run.fail(turn, problemOf(err))
			}
			if finalized.Superseded {
				return run.superseded()
			}
			carry.Version = finalized.Version
			if finalized.Rejected != nil {
				return run.terminal(turn, TerminalRefused, finalized.Rejected)
			}
			review, err := step(host, name("review", turn), func(ctx context.Context) (ReviewResult, error) {
				return ops.ResolveReview(ctx, run.op(name("review", turn)), ReviewInput{Run: input, Turn: turn, ArtifactDigest: finalized.ArtifactDigest, Version: carry.Version})
			})
			if err != nil {
				return run.fail(turn, problemOf(err))
			}
			if review.Superseded {
				return run.superseded()
			}
			if review.Halt != nil {
				return run.halt(turn, *review.Halt)
			}
			carry.Version = review.Version
			if review.Accepted {
				return RunOutcome{Key: input.Key, Terminal: TerminalCompleted}, nil
			}
			approval, outcome, err := run.awaitApproval(turn, review)
			if err != nil {
				return RunOutcome{}, err
			}
			if outcome != nil {
				return *outcome, nil
			}
			carry.Version = approval.Version
			if approval.Kind == "approve" {
				committed, outcome, err := run.commit(turn, review.RequestID, finalized.ArtifactDigest, carry.Version)
				if err != nil {
					return RunOutcome{}, err
				}
				if outcome != nil {
					return *outcome, nil
				}
				carry.Version = committed.Version
				switch committed.Outcome {
				case CommitCompleted:
					return RunOutcome{Key: input.Key, Terminal: TerminalCompleted}, nil
				case CommitFailed:
					return RunOutcome{Key: input.Key, Terminal: TerminalFailed, Problem: committed.Problem}, nil
				case CommitConflict:
					revised, err := run.revise(turn, "authoritative domain state moved; rebase required", true, carry.Version)
					if err != nil {
						return run.fail(turn, problemOf(err))
					}
					if revised.Superseded {
						return run.superseded()
					}
					if revised.Halt != nil {
						return run.halt(turn, *revised.Halt)
					}
					carry.Version = revised.Version
					carry.ReviewReason = "domain-conflict"
					phase = PhaseRevise
					continue
				default:
					invalid := problem.Internal("")
					invalid.Detail = "commit produced an unknown outcome"
					return run.fail(turn, invalid)
				}
			}
			revised, err := run.revise(turn, approval.Reason, false, carry.Version)
			if err != nil {
				return run.fail(turn, problemOf(err))
			}
			if revised.Superseded {
				return run.superseded()
			}
			if revised.Halt != nil {
				return run.halt(turn, *revised.Halt)
			}
			carry.Version = revised.Version
			carry.ReviewReason = approval.Reason
			phase = PhaseRevise
			continue

		default:
			// TurnDecision validation makes this unreachable; fail closed if an
			// operation ever returns an unknown kind.
			invalid := problem.Internal("")
			invalid.Detail = "turn produced an unknown decision kind"
			return run.fail(turn, invalid)
		}
	}
}

type runContext struct {
	host  Host
	ops   Operations
	input RunInput
}

func (r runContext) op(step string) OpID { return OpID{WorkflowID: r.host.WorkflowID(), Step: step} }

func (r runContext) superseded() (RunOutcome, error) {
	return RunOutcome{Key: r.input.Key, Terminal: TerminalSuperseded}, nil
}

// terminal records a refusal or failure through the terminal operation
// boundary and returns the workflow outcome.
func (r runContext) terminal(turn int, kind TerminalState, details *problem.Details) (RunOutcome, error) {
	stepName := name("terminal-"+string(kind), turn)
	ack, err := step(r.host, stepName, func(ctx context.Context) (Ack, error) {
		return r.ops.Terminalize(ctx, r.op(stepName), TerminalInput{Run: r.input, Turn: turn, Kind: kind, Problem: details})
	})
	if err != nil {
		return RunOutcome{}, err
	}
	if ack.Superseded {
		return r.superseded()
	}
	return RunOutcome{Key: r.input.Key, Terminal: kind, Problem: details}, nil
}

func (r runContext) fail(turn int, details problem.Details) (RunOutcome, error) {
	return r.terminal(turn, TerminalFailed, &details)
}

func (r runContext) halt(turn int, halt Halt) (RunOutcome, error) {
	behavior := halt.Behavior
	if behavior != TerminalRefused {
		behavior = TerminalFailed
	}
	return r.terminal(turn, behavior, &halt.Problem)
}

// commit drives the governed effect across the submit boundary. An unsettled
// answer holds the run at the boundary: the workflow waits durably — for the
// bounded backoff the operation chose, or for an explicit domain signal — and
// reconciles again under a fresh durable step. The loop never resends the
// command; only the operation's own durable write-ahead record decides
// whether submitting is safe.
//
// The run is released at the boundary as unresolved on exactly one condition:
// the operation reported that the governed effect is durably escalated. Until
// then the workflow keeps holding, however many wakes that takes. Releasing on
// a wake count instead would let a deployment whose reconciliation window
// exceeded the loop's bound hand back an unresolved run whose effect was never
// escalated — a run nobody is paged for and no audited operator-resolution
// path can find.
func (r runContext) commit(turn int, requestID, artifactDigest string, version uint64) (CommitResult, *RunOutcome, error) {
	for wake := 0; wake < MaximumCommitWakes; wake++ {
		// The first execution keeps the historical commit step identity; each
		// later reconciliation wake is its own durable step.
		stepName := name("commit", turn)
		if wake > 0 {
			stepName = name(fmt.Sprintf("commit-%02d", wake), turn)
		}
		committed, err := step(r.host, stepName, func(ctx context.Context) (CommitResult, error) {
			return r.ops.Commit(ctx, r.op(stepName), CommitInput{Run: r.input, Turn: turn, RequestID: requestID, ArtifactDigest: artifactDigest, Version: version})
		})
		if err != nil {
			outcome, failErr := r.fail(turn, problemOf(err))
			return CommitResult{}, &outcome, failErr
		}
		if committed.Superseded {
			outcome, err := r.superseded()
			return CommitResult{}, &outcome, err
		}
		if committed.Halt != nil {
			outcome, err := r.halt(turn, *committed.Halt)
			return CommitResult{}, &outcome, err
		}
		if !committed.Unsettled {
			return committed, nil, nil
		}
		if committed.Escalated && wake+1 >= commitHoldWakes {
			// The durable escalation exists and the hold window elapsed. The
			// run aggregate keeps its submit-boundary state, the submission
			// journal carries the escalation, and the audited
			// operator-resolution path settles it.
			unresolved := problem.New(problem.CodeDomainOutcomeUncertain, "")
			unresolved.Retryability = "operator-action"
			unresolved.Detail = "the governed effect is durably escalated; the run holds at the submit boundary for operator resolution"
			return CommitResult{}, &RunOutcome{Key: r.input.Key, Terminal: TerminalUnresolved, Problem: &unresolved}, nil
		}
		version = committed.Version
		timeout := time.Duration(committed.RetryAfterMillis) * time.Millisecond
		if timeout < time.Millisecond {
			timeout = time.Millisecond
		}
		if _, _, err := r.host.AwaitSignal(DomainTopic(r.input.Key.RunID), timeout); err != nil {
			return CommitResult{}, nil, err
		}
	}
	// The spin guard tripped without the operation ever reporting a durable
	// escalation. Releasing here is precisely the unsafe release this loop
	// exists to prevent, so the workflow errors instead: the run keeps its
	// submit-boundary state and a successor execution reconciles it again.
	return CommitResult{}, nil, fmt.Errorf("commit reconciliation exhausted its spin guard without a durable escalation")
}

func (r runContext) revise(turn int, reason string, fromConflict bool, version uint64) (Ack, error) {
	stepName := name("revise", turn)
	return step(r.host, stepName, func(ctx context.Context) (Ack, error) {
		return r.ops.Revise(ctx, r.op(stepName), ReviseInput{Run: r.input, Turn: turn, Reason: reason, FromConflict: fromConflict, Version: version})
	})
}

// awaitInput waits durably for the accepted input response, tolerating
// spurious wakes and enforcing the recorded expiry deadline. An acceptance
// that races expiry wins: the loop re-reads instead of failing the run.
func (r runContext) awaitInput(turn int, opened InterruptOpened) (InputRead, *RunOutcome, error) {
	timeout := time.Duration(opened.TimeoutMillis) * time.Millisecond
	for wake := 0; wake < maximumWakes; wake++ {
		_, timedOut, err := r.host.AwaitSignal(InputTopic(opened.RequestID), timeout)
		if err != nil {
			return InputRead{}, nil, err
		}
		stepName := name(fmt.Sprintf("read-input-%02d", wake), turn)
		read, err := step(r.host, stepName, func(ctx context.Context) (InputRead, error) {
			return r.ops.ReadInput(ctx, r.op(stepName), InterruptRef{Run: r.input, Turn: turn, RequestID: opened.RequestID})
		})
		if err != nil {
			outcome, err := r.fail(turn, problemOf(err))
			return InputRead{}, &outcome, err
		}
		if read.Superseded {
			outcome, err := r.superseded()
			return InputRead{}, &outcome, err
		}
		if read.Accepted {
			return read, nil, nil
		}
		if timedOut || read.Expired {
			raced, outcome, err := r.expire(turn, wake, opened.RequestID, "input", read.Version)
			if !raced {
				return InputRead{}, &outcome, err
			}
			timeout = time.Millisecond
			continue
		}
		timeout = time.Duration(read.RemainingMillis) * time.Millisecond
	}
	spun := problem.Internal("")
	spun.Detail = "input wait exceeded the bounded wake budget"
	outcome, err := r.fail(turn, spun)
	return InputRead{}, &outcome, err
}

// awaitApproval waits durably for the recorded approval decision.
func (r runContext) awaitApproval(turn int, review ReviewResult) (ApprovalRead, *RunOutcome, error) {
	timeout := time.Duration(review.TimeoutMillis) * time.Millisecond
	for wake := 0; wake < maximumWakes; wake++ {
		_, timedOut, err := r.host.AwaitSignal(ApprovalTopic(review.RequestID), timeout)
		if err != nil {
			return ApprovalRead{}, nil, err
		}
		stepName := name(fmt.Sprintf("read-approval-%02d", wake), turn)
		read, err := step(r.host, stepName, func(ctx context.Context) (ApprovalRead, error) {
			return r.ops.ReadApproval(ctx, r.op(stepName), InterruptRef{Run: r.input, Turn: turn, RequestID: review.RequestID})
		})
		if err != nil {
			outcome, err := r.fail(turn, problemOf(err))
			return ApprovalRead{}, &outcome, err
		}
		if read.Superseded {
			outcome, err := r.superseded()
			return ApprovalRead{}, &outcome, err
		}
		if read.Decided {
			return read, nil, nil
		}
		if timedOut || read.Expired {
			raced, outcome, err := r.expire(turn, wake, review.RequestID, "approval", read.Version)
			if !raced {
				return ApprovalRead{}, &outcome, err
			}
			timeout = time.Millisecond
			continue
		}
		timeout = time.Duration(read.RemainingMillis) * time.Millisecond
	}
	spun := problem.Internal("")
	spun.Detail = "approval wait exceeded the bounded wake budget"
	outcome, err := r.fail(turn, spun)
	return ApprovalRead{}, &outcome, err
}

// expire records interrupt expiry. It reports raced=true when an accepted
// response or decision won against the deadline.
func (r runContext) expire(turn, wake int, requestID, kind string, version uint64) (bool, RunOutcome, error) {
	stepName := name(fmt.Sprintf("expire-%s-%02d", kind, wake), turn)
	ack, err := step(r.host, stepName, func(ctx context.Context) (Ack, error) {
		return r.ops.ExpireInterrupt(ctx, r.op(stepName), ExpireRequest{Run: r.input, Turn: turn, RequestID: requestID, Kind: kind, Version: version})
	})
	if err != nil {
		return false, RunOutcome{}, err
	}
	if ack.Raced {
		return true, RunOutcome{}, nil
	}
	if ack.Superseded {
		outcome, err := r.superseded()
		return false, outcome, err
	}
	expired := problem.New(problem.CodeInputRequestExpired, "")
	if kind == "approval" {
		expired = problem.New(problem.CodeApprovalRequestExpired, "")
	}
	expired.Detail = "the durable " + kind + " deadline elapsed before a response was accepted"
	return false, RunOutcome{Key: r.input.Key, Terminal: TerminalFailed, Problem: &expired}, nil
}

func name(prefix string, turn int) string { return fmt.Sprintf("%s-%04d", prefix, turn) }

// delegateName is the durable step identity of one Specialist turn.
func delegateName(turn, delegateTurn int) string {
	return fmt.Sprintf("delegate-turn-%04d-%04d", turn, delegateTurn)
}

// stepRecord is the recorded output of one durable operation. A typed
// ProblemDetails outcome is recorded structurally so recovery reconstructs
// the same typed error instead of an opaque engine error string.
type stepRecord[T any] struct {
	Value   *T               `json:"value,omitempty"`
	Problem *problem.Details `json:"problem,omitempty"`
}

// step runs one typed durable operation behind the host boundary.
func step[T any](host Host, stepName string, fn func(context.Context) (T, error)) (T, error) {
	var zero T
	raw, err := host.Step(stepName, func(ctx context.Context) ([]byte, error) {
		value, err := fn(ctx)
		if err != nil {
			var details problem.Details
			if !errors.As(err, &details) {
				// Untyped failures stay engine failures: the engine owns
				// recovery and the workflow never reinterprets them.
				return nil, err
			}
			return json.Marshal(stepRecord[T]{Problem: &details})
		}
		return json.Marshal(stepRecord[T]{Value: &value})
	})
	if err != nil {
		return zero, err
	}
	var out stepRecord[T]
	if err := json.Unmarshal(raw, &out); err != nil {
		return zero, fmt.Errorf("decode durable step %s: %w", stepName, err)
	}
	if out.Problem != nil {
		return zero, *out.Problem
	}
	if out.Value == nil {
		return zero, fmt.Errorf("durable step %s recorded neither a value nor a problem", stepName)
	}
	return *out.Value, nil
}

// problemOf converts an operation error into serializable ProblemDetails,
// preserving typed problems and hiding raw diagnostics.
func problemOf(err error) problem.Details {
	var details problem.Details
	if errors.As(err, &details) {
		return details
	}
	internal := problem.Internal("")
	internal.Detail = "durable operation failed"
	return internal
}

func validOpaqueID(value string) bool {
	if len(value) < 1 || len(value) > 128 || !asciiAlphaNumeric(value[0]) {
		return false
	}
	for index := 1; index < len(value); index++ {
		if !asciiAlphaNumeric(value[index]) && !strings.ContainsRune("._:-", rune(value[index])) {
			return false
		}
	}
	return true
}

func asciiAlphaNumeric(character byte) bool {
	return character >= 'A' && character <= 'Z' || character >= 'a' && character <= 'z' || character >= '0' && character <= '9'
}

func validTraceparent(value string) bool {
	if len(value) != 55 || value[2] != '-' || value[35] != '-' || value[52] != '-' {
		return false
	}
	for index, character := range value {
		if index == 2 || index == 35 || index == 52 {
			continue
		}
		if !lowerHexDigit(character) {
			return false
		}
	}
	return value[:2] != "ff" && value[3:35] != strings.Repeat("0", 32) && value[36:52] != strings.Repeat("0", 16)
}

// lowerHexDigit reports whether the character is a lower-case hexadecimal
// digit. Digest and trace identities are lower-case only, so an upper-case
// digit is rejected rather than normalized.
func lowerHexDigit(character rune) bool {
	return character >= '0' && character <= '9' || character >= 'a' && character <= 'f'
}
