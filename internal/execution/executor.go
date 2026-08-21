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
	"github.com/ancyloce/anvilkit-agent-service/internal/applyauth"
	"github.com/ancyloce/anvilkit-agent-service/internal/authority"
	"github.com/ancyloce/anvilkit-agent-service/internal/budget"
	"github.com/ancyloce/anvilkit-agent-service/internal/canonical"
	"github.com/ancyloce/anvilkit-agent-service/internal/contractclient"
	"github.com/ancyloce/anvilkit-agent-service/internal/domaincommit"
	"github.com/ancyloce/anvilkit-agent-service/internal/events"
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
	// The fenced dispatch identity: the root run the usage rolls up to, the
	// actor whose authority the dispatch re-reads, the execution generation
	// the fence binds, and the trace the attempt is attributed to.
	RootRunID           string
	ActorID             string
	ExecutionGeneration uint64
	Traceparent         string
}

type ToolResult struct {
	Output json.RawMessage
}

// ToolExecutor executes one guard-approved tool call.
type ToolExecutor interface {
	Execute(context.Context, ToolInvocation) (ToolResult, error)
}

// DomainCommand is one idempotent authoritative domain commit. It carries the
// complete signed apply authorization together with every binding the caller
// re-derived from durable state; the domain boundary verifies the token —
// signature, audience, expiry, action, artifact, target, base revision,
// actor, and material digests — and atomically redeems it before any effect.
type DomainCommand struct {
	OperationID     string
	WorkspaceID     string
	ProjectID       string
	RunID           string
	ArtifactDigest  string
	AuthorizationID string
	// AuthorizationJWS is the complete signed capability, carried whole from
	// durable issuance through the write-ahead submission record.
	AuthorizationJWS string
	// The expected bindings the domain boundary verifies against the signed
	// payload, field for field.
	ActionDigest      string
	BaseRevision      string
	Target            applyauth.Target
	ActorID           string
	DefinitionDigest  string
	ContractBOMDigest string
	PolicyDigest      string
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

// ArtifactPort is the artifact owner's boundary. The workflow records every
// validated candidate as an immutable artifact, review acceptance finalizes
// it, and a confirmed governed effect commits it — each call convergent under
// replay. The executor never infers eligibility from run state: the artifact
// owner answers, and an ineligible answer stops the commit before any
// authorization is issued.
type ArtifactPort interface {
	RecordCandidate(context.Context, ArtifactCandidate) error
	EnsureFinalized(context.Context, ArtifactQuery) error
	EnsureCommitted(context.Context, ArtifactQuery) error
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
	// ApprovalRequestID names the accepted approval the authorization must
	// bind. The issuer re-reads and re-proves it; the request only names it.
	ApprovalRequestID string
}

// IssuedAuthorization is the durable issuance answer: the authorization
// identity together with the complete signed token. A replay of the same
// durable operation returns the original persisted capability.
type IssuedAuthorization struct {
	AuthorizationID string
	CompactJWS      string
	ExpiresAt       time.Time
}

type CommitAuthority interface {
	Issue(context.Context, AuthorizationRequest) (IssuedAuthorization, error)
}

// DeltaPublisher fans provisional stream deltas to live subscribers. Deltas
// are droppable by contract; publishing never blocks the workflow.
type DeltaPublisher interface {
	Publish(context.Context, events.Delta) error
}

// EvidenceRecorder appends internal AgentEvidence facts. The events evidence
// store satisfies it; recording is idempotent by evidence identity so every
// durable-operation replay converges on one record.
type EvidenceRecorder interface {
	AppendEvidence(context.Context, events.Evidence) (uint64, error)
	// RecordedEvidence answers what is already recorded under one identity,
	// so a repeated attempt at a durable operation converges on the fact that
	// was recorded instead of producing a second account of it.
	RecordedEvidence(context.Context, events.Scope, string) (events.RecordedEvidence, bool, error)
}

type Clock interface{ Now() time.Time }

// BudgetController is the Platform budget authority the pipeline reserves
// through before any expensive dispatch. The budget controller satisfies it:
// its ledger and generation source are durable, so reservation, observation,
// and settlement state survive restart and fence on the run aggregate's
// execution generation.
type BudgetController interface {
	ReserveInitial(context.Context, budget.Estimate, budget.Generation) (budget.Reservation, error)
	ReserveReplacement(context.Context, budget.Estimate, budget.Generation, budget.ReservationID) (budget.Reservation, error)
	Dispatch(context.Context, budget.Scope, budget.ReservationID, budget.Generation, budget.Dispatch) error
	Observe(context.Context, budget.Observation) error
	Reservation(context.Context, budget.Scope, budget.ReservationID) (budget.Reservation, error)
	Reconcile(ctx context.Context, scope budget.Scope, id budget.ReservationID, generation budget.Generation, finalCost *int64, release bool, actor string) (budget.Reservation, error)
	ReconcileSuperseded(ctx context.Context, scope budget.Scope, rootRunID string, current budget.Generation, actor string) ([]budget.Reservation, error)
	RecoverSupersededFinality(ctx context.Context, scope budget.Scope, rootRunID string, actor string) ([]budget.Reservation, error)
	FenceCancelledRun(ctx context.Context, scope budget.Scope, rootRunID, runID string) ([]budget.Reservation, error)
	ConcludeCancelledRun(ctx context.Context, scope budget.Scope, rootRunID, runID, actor string) ([]budget.Reservation, error)
	RecoverCancelledFinality(ctx context.Context, scope budget.Scope, rootRunID string, actor string) ([]budget.Reservation, error)
	OutstandingCancelledHolds(ctx context.Context, scope budget.Scope, rootRunID string) (bool, error)
}

// Config wires the executor. Every dependency is required; the executor
// never substitutes a fallback.
type Config struct {
	Registry         *agent.Registry
	Runner           *runner.Runner
	Runs             RunStore
	InterruptWriter  InterruptWriter
	InterruptReader  InterruptReader
	InterruptExpirer InterruptExpirer
	Authority        AuthorityProvider
	Tools            ToolExecutor
	ToolMaterial     ToolMaterial
	Artifacts        ArtifactPort
	Domain           DomainPort
	Submissions      domaincommit.Store
	CommitAuthority  CommitAuthority
	Contracts        ContractValidator
	Evidence         EvidenceRecorder
	Deltas           DeltaPublisher
	Decisions        journal.Store
	Budget           BudgetController
	Clock            Clock
	InputTTL         time.Duration
	// BudgetTTL bounds how long a run's standing reservation stays
	// dispatchable before requiring settlement or review.
	BudgetTTL         time.Duration
	ApprovalTTL       time.Duration
	TurnLimit         int
	ValidatorIdentity string
	// ReconcileLimit bounds how many durable uncertain reconciliations one
	// submitted governed effect may accumulate before the submission journal
	// escalates it to operator resolution. DomainRetryBase and DomainRetryCap
	// shape the bounded backoff the workflow holds for between
	// reconciliations of an unsettled effect.
	ReconcileLimit  int
	DomainRetryBase time.Duration
	DomainRetryCap  time.Duration
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
	if cfg.Registry == nil || cfg.Runner == nil || cfg.Runs == nil || cfg.InterruptWriter == nil || cfg.InterruptReader == nil || cfg.InterruptExpirer == nil || cfg.Authority == nil || cfg.Tools == nil || cfg.ToolMaterial == nil || cfg.Artifacts == nil || cfg.Domain == nil || cfg.Submissions == nil || cfg.CommitAuthority == nil || cfg.Contracts == nil || cfg.Evidence == nil || cfg.Deltas == nil || cfg.Decisions == nil || cfg.Budget == nil || cfg.Clock == nil {
		return nil, fmt.Errorf("agent execution: every pipeline dependency is required")
	}
	if cfg.BudgetTTL <= 0 {
		return nil, fmt.Errorf("agent execution: the budget reservation lifetime must be positive")
	}
	if cfg.InputTTL <= 0 || cfg.ApprovalTTL <= 0 || cfg.TurnLimit < 1 {
		return nil, fmt.Errorf("agent execution: interrupt deadlines and turn limit must be positive")
	}
	if cfg.ReconcileLimit < 1 || cfg.DomainRetryBase <= 0 || cfg.DomainRetryCap < cfg.DomainRetryBase {
		return nil, fmt.Errorf("agent execution: the domain reconciliation bound and backoff window must be positive and ordered")
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
	if current.TargetRevoked(snapshot.Target.ID) {
		return authority.Current{}, staleAuthority("authority over the run's target is revoked")
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

// recordEvidence appends one internal evidence fact for a durable operation.
// The identity derives from the operation key and type, so a replay records
// nothing new; a failed append fails the operation so evidence is never
// silently dropped.
// evidenceContractError marks a record the internal evidence contract itself
// refuses — a prohibited or unbounded payload fact. It is distinguishable from
// an infrastructure fault so a caller can refuse the command that produced it
// instead of reporting an internal error or, worse, writing something durable
// that can never be completed.
type evidenceContractError struct{ err error }

func (e evidenceContractError) Error() string { return e.err.Error() }
func (e evidenceContractError) Unwrap() error { return e.err }

// buildEvidence renders the immutable internal evidence record one durable
// operation leaves behind and proves the internal evidence contract accepts
// it. It is the single construction path: what a caller proves valid before
// writing anything durable is exactly what is recorded afterwards, so a
// pre-write proof can never diverge from the write it authorizes.
func (e *Executor) buildEvidence(op workflow.OpID, input workflow.RunInput, snapshot runs.Snapshot, evidenceType, retention string, occurredAt time.Time, payload map[string]string) (events.Evidence, error) {
	identity := evidenceIdentityOf(op, evidenceType)
	definitionDigest, bomDigest, policyDigest, err := materialDigests(snapshot.Definition, snapshot.ContractBOM, snapshot.Policy)
	if err != nil {
		return events.Evidence{}, fmt.Errorf("digest evidence producer material: %w", err)
	}
	value := events.Evidence{
		WorkspaceID: snapshot.WorkspaceID,
		ProjectID:   snapshot.Target.ProjectID,
		RunID:       string(snapshot.RunID),
		EvidenceID:  identity,
		Type:        evidenceType,
		OccurredAt:  occurredAt,
		Producer: events.EvidenceProducer{
			Component:         "agent-executor",
			DefinitionDigest:  definitionDigest,
			PolicyDigest:      policyDigest,
			ContractBOMDigest: bomDigest,
		},
		Classification: "internal",
		Retention:      retention,
		TurnID:         op.Step,
		WorkflowID:     input.Key.WorkflowID(),
		Traceparent:    traceparentOf(input),
		Payload:        payload,
	}
	if err := events.ValidateEvidence(value); err != nil {
		return events.Evidence{}, evidenceContractError{err: fmt.Errorf("validate %s evidence: %w", evidenceType, err)}
	}
	return value, nil
}

// evidenceIdentityOf is the durable-operation identity one internal fact is
// recorded under. It is derived from the operation key and the fact's type, so
// every attempt at the same operation names the same record.
func evidenceIdentityOf(op workflow.OpID, evidenceType string) string {
	return "evidence." + strings.TrimPrefix(mustDeterministicDigest(struct {
		Key  string `json:"key"`
		Type string `json:"type"`
	}{op.Key(), evidenceType}), "sha256:")[:32]
}

// recordEvidence records one internal fact about a durable operation.
//
// A repeated attempt at the same operation is the same fact, so it converges
// on the record that already exists rather than stamping a second account of
// it: the occurrence time of something that happened once was decided once,
// and the store is where that decision lives. Everything else about the fact
// still has to match — a genuinely different fact under the same identity is
// refused as a conflict, which is what makes the convergence safe rather than
// merely convenient.
func (e *Executor) recordEvidence(ctx context.Context, op workflow.OpID, input workflow.RunInput, snapshot runs.Snapshot, evidenceType, retention string, payload map[string]string) error {
	scope := events.Scope{WorkspaceID: snapshot.WorkspaceID, ProjectID: snapshot.Target.ProjectID}
	occurredAt := e.cfg.Clock.Now()
	recorded, present, err := e.cfg.Evidence.RecordedEvidence(ctx, scope, evidenceIdentityOf(op, evidenceType))
	if err != nil {
		return fmt.Errorf("read recorded %s evidence: %w", evidenceType, err)
	}
	if present {
		occurredAt = recorded.OccurredAt
	}
	value, err := e.buildEvidence(op, input, snapshot, evidenceType, retention, occurredAt, payload)
	if err != nil {
		return err
	}
	if _, err := e.cfg.Evidence.AppendEvidence(ctx, value); err != nil {
		return fmt.Errorf("record %s evidence: %w", evidenceType, err)
	}
	return nil
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
	limits, err := parseBudget(snapshot.Budget)
	if err != nil {
		budgetRefusal := problem.New(problem.CodeBudgetDenied, "")
		budgetRefusal.Detail = "pinned agent budget is not decodable"
		return workflow.PrepareResult{Refused: &budgetRefusal, Version: snapshot.Version}, nil
	}
	// Reservation before dispatch: the run's pinned worst-case cost is
	// durably reserved under the active budget generation before the run may
	// execute anything. A replayed preparation converges on the reservation
	// it already made; a denied reservation refuses the run here, before any
	// model or worker dispatch exists.
	if refused := e.ensureRunReservation(ctx, snapshot, limits); refused != nil {
		return workflow.PrepareResult{Refused: refused, Version: snapshot.Version}, nil
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
	limits, err := parseBudget(snapshot.Budget)
	if err != nil {
		return workflow.TurnResult{}, err
	}
	carry := input.Carry
	carry.Version = snapshot.Version
	// The model turn is an expensive dispatch: it runs only inside the budget
	// controller's dispatch gate, which proves the run's standing reservation
	// is current, unreleased, unexpired, and of the active generation at the
	// moment of dispatch.
	var outcome runner.TurnOutcome
	reservationID := budgetReservationID(string(snapshot.RunID), snapshot.ExecutionGeneration)
	dispatchErr := e.cfg.Budget.Dispatch(ctx, budgetScopeOf(snapshot), reservationID, budget.Generation(snapshot.ExecutionGeneration), func(ctx context.Context, _ budget.Reservation) error {
		var turnErr error
		outcome, turnErr = e.cfg.Runner.Turn(ctx, runner.TurnRequest{
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
			Budget:          limits.remaining(input.Carry.Usage),
		})
		return turnErr
	})
	if dispatchErr != nil {
		var details problem.Details
		if errors.As(dispatchErr, &details) && details.Code == string(problem.CodeBudgetDenied) {
			return workflow.TurnResult{Carry: carry, Halt: &workflow.Halt{Problem: details, Behavior: workflow.TerminalFailed}}, nil
		}
		return workflow.TurnResult{}, dispatchErr
	}
	// Every turn's observed cost lands on the durable reservation,
	// deduplicated by the durable operation identity so replay never counts
	// usage twice.
	if err := e.cfg.Budget.Observe(ctx, budget.Observation{
		ID:                  op.Key() + ":budget",
		Scope:               budgetScopeOf(snapshot),
		ReservationID:       reservationID,
		RootRunID:           string(snapshot.RootRunID),
		RunID:               string(snapshot.RunID),
		TaskID:              "model:" + op.Step,
		AttemptID:           budget.AttemptID(op.Key()),
		ExecutionGeneration: snapshot.ExecutionGeneration,
		MeterSequence:       uint64(input.Turn),
		CostMicros:          outcome.Usage.CostMicros,
	}); err != nil {
		return workflow.TurnResult{}, fmt.Errorf("observe turn usage against the budget reservation: %w", err)
	}
	carry.Usage = carry.Usage.Add(outcome.Usage)
	carry.Notes = boundNotes(append(carry.Notes, outcome.Notes...))
	if outcome.Halted != nil {
		return workflow.TurnResult{Carry: carry, Halt: haltOf(*outcome.Halted)}, nil
	}
	// A completed turn is live progress for connected consumers. The delta is
	// provisional by contract — dropping it changes nothing durable, so a
	// publish failure is never allowed to fail the turn.
	_ = e.cfg.Deltas.Publish(ctx, events.Delta{
		WorkspaceID: snapshot.WorkspaceID,
		RunID:       string(snapshot.RunID),
		Channel:     "progress",
		TurnID:      op.Key(),
		Traceparent: traceparentOf(input.Run),
		EmittedAt:   e.cfg.Clock.Now(),
		Payload:     map[string]string{"turn": fmt.Sprintf("%d", input.Turn), "decision": string(outcome.Decision.Kind)},
	})
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
			IdempotencyKey:      op.Key(),
			ToolID:              proposal.ToolID,
			Arguments:           proposal.Arguments,
			WorkspaceID:         snapshot.WorkspaceID,
			ProjectID:           snapshot.Target.ProjectID,
			RunID:               string(snapshot.RunID),
			RootRunID:           string(snapshot.RootRunID),
			ActorID:             snapshot.ActorID,
			ExecutionGeneration: snapshot.ExecutionGeneration,
			Traceparent:         traceparentOf(input.Run),
		})
		if err != nil {
			return workflow.ActionResult{}, fmt.Errorf("execute authorized tool: %w", err)
		}
		outputDigest, err := canonical.Digest(result.Output)
		if err != nil {
			return workflow.ActionResult{}, fmt.Errorf("digest tool output for evidence: %w", err)
		}
		if err := e.recordEvidence(ctx, op, input.Run, snapshot, "tool.execution-completed", "operational", map[string]string{"toolId": proposal.ToolID, "outputDigest": outputDigest}); err != nil {
			return workflow.ActionResult{}, err
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
	limits, err := parseBudget(snapshot.Budget)
	if err != nil {
		return workflow.DelegateTurnResult{}, err
	}
	carry := input.Carry
	carry.Version = snapshot.Version
	// A Specialist turn shares the parent run's budget boundary: the same
	// standing reservation gates its dispatch and accumulates its cost.
	var outcome runner.DelegateTurnOutcome
	reservationID := budgetReservationID(string(snapshot.RunID), snapshot.ExecutionGeneration)
	dispatchErr := e.cfg.Budget.Dispatch(ctx, budgetScopeOf(snapshot), reservationID, budget.Generation(snapshot.ExecutionGeneration), func(ctx context.Context, _ budget.Reservation) error {
		var turnErr error
		outcome, turnErr = e.cfg.Runner.DelegateTurn(ctx, runner.DelegateTurnRequest{
			Specialist:   specialist,
			Run:          runView(snapshot),
			Turn:         input.DelegateTurn,
			Depth:        1,
			Last:         input.Last,
			Notes:        carry.Notes,
			Input:        input.Input,
			Budget:       limits.remaining(carry.Usage),
			OperationKey: op.Key(),
			Authority:    current,
		})
		return turnErr
	})
	if dispatchErr != nil {
		var details problem.Details
		if errors.As(dispatchErr, &details) && details.Code == string(problem.CodeBudgetDenied) {
			return workflow.DelegateTurnResult{Done: true, Carry: carry, Halt: &workflow.Halt{Problem: details, Behavior: workflow.TerminalFailed}}, nil
		}
		return workflow.DelegateTurnResult{}, dispatchErr
	}
	if err := e.cfg.Budget.Observe(ctx, budget.Observation{
		ID:                  op.Key() + ":budget",
		Scope:               budgetScopeOf(snapshot),
		ReservationID:       reservationID,
		RootRunID:           string(snapshot.RootRunID),
		RunID:               string(snapshot.RunID),
		TaskID:              "model-delegate:" + op.Step,
		AttemptID:           budget.AttemptID(op.Key()),
		ExecutionGeneration: snapshot.ExecutionGeneration,
		MeterSequence:       uint64(input.DelegateTurn),
		CostMicros:          outcome.Usage.CostMicros,
	}); err != nil {
		return workflow.DelegateTurnResult{}, fmt.Errorf("observe delegate turn usage against the budget reservation: %w", err)
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
		Question: input.Question,
		// The recorded response schema is applied on top of the canonical
		// SubmitInputResponseRequest contract, so it may narrow that contract
		// but never widen it: the canonical payload is a bounded string map
		// whose values stop at 1024 characters.
		ResponseSchema:   json.RawMessage(`{"type":"object","required":["answer"],"properties":{"answer":{"type":"string","maxLength":1024}},"additionalProperties":false}`),
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
		read.Reason = request.Decision.Comment
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
	// Expiry fails the run inside the interrupt repository's critical
	// section, so this is its terminal boundary: the standing reservation is
	// settled here, held un-released like every failure.
	if err := e.settleRunBudget(ctx, snapshot, false); err != nil {
		return workflow.Ack{}, err
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
	// The Contract Runtime independently validates the candidate and records
	// durable validation evidence before anything reaches review. A
	// deterministic rejection fails the candidate; runtime unavailability is a
	// retryable error at this durable boundary — never a bypass. The catalog
	// identity is the real approved-catalog digest the registry was built
	// from, and the policy identity is the definition's pinned guardrail
	// policy; the runtime verifies all of them against approved material
	// before anything is recorded as validated.
	evidence, err := e.cfg.Contracts.Validate(ctx, contractclient.Request{
		WorkspaceID:   snapshot.WorkspaceID,
		ProjectID:     snapshot.Target.ProjectID,
		RunID:         string(id),
		Kind:          contractclient.Artifact,
		Payload:       candidate,
		BOMDigest:     bom,
		SchemaDigest:  definition.OutputSchema.Digest,
		CatalogDigest: e.cfg.Registry.CatalogDigest(),
		PolicyDigest:  definition.GuardrailPolicy.Digest,
	})
	if err != nil {
		var details problem.Details
		if errors.As(err, &details) && details.Code == string(problem.CodeContractInvalid) {
			return workflow.FinalizeResult{Rejected: &details, Version: snapshot.Version}, nil
		}
		return workflow.FinalizeResult{}, fmt.Errorf("validate candidate through the Contract Runtime: %w", err)
	}
	validationProof, err := e.cfg.Contracts.ReviewProof(evidence)
	if err != nil {
		return workflow.FinalizeResult{}, fmt.Errorf("derive validation proof for review: %w", err)
	}
	if err := e.recordEvidence(ctx, op, input.Run, snapshot, "validation.candidate-validated", "audit", map[string]string{"artifactDigest": artifactDigest, "schemaDigest": definition.OutputSchema.Digest, "validatorVersion": evidence.ValidatorVersion}); err != nil {
		return workflow.FinalizeResult{}, err
	}
	// The validated candidate becomes an immutable artifact before the run can
	// reach review: review, approval, and commit then govern a recorded
	// digest-attested object, never loose candidate bytes. Replays converge on
	// the same record.
	if err := e.cfg.Artifacts.RecordCandidate(ctx, ArtifactCandidate{
		WorkspaceID:         snapshot.WorkspaceID,
		ProjectID:           snapshot.Target.ProjectID,
		RunID:               string(id),
		Digest:              artifactDigest,
		Bytes:               candidate,
		SchemaComponent:     definition.OutputSchema.ComponentName,
		SchemaDigest:        definition.OutputSchema.Digest,
		BOMDigest:           bom,
		CatalogDigest:       e.cfg.Registry.CatalogDigest(),
		OperationKey:        op.Key(),
		ExecutionGeneration: input.Run.Key.Generation,
		BuildIdentity:       e.cfg.ValidatorIdentity,
		Producer:            "anvilkit-agent-runner",
	}); err != nil {
		return workflow.FinalizeResult{}, fmt.Errorf("record immutable candidate artifact: %w", err)
	}
	if snapshot.Status == runs.Validating {
		canonicalCandidate, err := canonical.Bytes(candidate)
		if err != nil {
			return workflow.FinalizeResult{}, fmt.Errorf("canonicalize candidate for artifact reference: %w", err)
		}
		artifactReference := &runs.EventArtifact{
			ArtifactID: string(ArtifactRecordID(string(id), artifactDigest)),
			Digest:     artifactDigest,
			MediaType:  "application/json",
			SizeBytes:  int64(len(canonicalCandidate)),
		}
		next, lost, err := e.apply(ctx, scope, id, snapshot.Version, runs.Command{Kind: runs.SubmitForReview, Validation: validationProof, Artifact: artifactReference, Traceparent: traceparentOf(input.Run)}, runs.AwaitingReview)
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
	// Review acceptance finalizes the immutable artifact in both exits: an
	// accepted artifact without a governed effect completes the run over a
	// finalized record, and a governed effect opens approval over one.
	finalizeArtifact := func() error {
		return e.cfg.Artifacts.EnsureFinalized(ctx, ArtifactQuery{
			WorkspaceID:    snapshot.WorkspaceID,
			ProjectID:      snapshot.Target.ProjectID,
			RunID:          string(id),
			ArtifactDigest: input.ArtifactDigest,
		})
	}
	if !governedEffect(snapshot) {
		if err := finalizeArtifact(); err != nil {
			return workflow.ReviewResult{}, fmt.Errorf("finalize accepted artifact: %w", err)
		}
		next, lost, err := e.apply(ctx, scope, id, input.Version, runs.Command{Kind: runs.AcceptArtifact, Traceparent: traceparentOf(input.Run)}, runs.Completed)
		if err != nil {
			return workflow.ReviewResult{}, err
		}
		if lost {
			return workflow.ReviewResult{Superseded: true}, nil
		}
		if err := e.settleRunBudget(ctx, snapshot, true); err != nil {
			return workflow.ReviewResult{}, err
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
	if err := finalizeArtifact(); err != nil {
		return workflow.ReviewResult{}, fmt.Errorf("finalize artifact for approval: %w", err)
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
	// The domain operation identity is derived from the workflow, the
	// accepted approval, and the artifact — facts stable across every durable
	// reconciliation wake — so every execution of this commit addresses the
	// same operation at the authoritative owner.
	operationID := domainOperationIDFor(input)
	// Recovery convergence: a crash after the terminal domain transition
	// re-executes this operation against an already-settled aggregate.
	switch snapshot.Status {
	case runs.Completed:
		if err := e.settleRunBudget(ctx, snapshot, true); err != nil {
			return workflow.CommitResult{}, err
		}
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
		// A previous execution reached the submit boundary. The durable
		// write-ahead submission record decides what is safe: a recorded but
		// never-issued submission may be sent under the same stable operation
		// identity, an issued one is only ever reconciled, and nothing is
		// re-issued.
		return e.reconcileDomain(ctx, scope, snapshot, id, operationID, input)
	}
	// The commit gate runs in one fixed order, and each check must pass
	// before the next is attempted: current authority, then the approval and
	// its exact action binding, then artifact eligibility, then authorization
	// issuance, and only then the governed domain effect. No later step is
	// reached — and in particular neither the issuer nor the domain owner is
	// called — while an earlier one is unsatisfied.
	gateAuthority, stale := e.currentAuthority(ctx, scope, snapshot)
	if stale != nil {
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
	if gateAuthority.ApprovalRevoked(input.RequestID) {
		denied := problem.New(problem.CodeApplyAuthorizationDenied, "")
		denied.Detail = "the accepted approval has been revoked by current authority"
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
	issuanceAuthority, stale := e.currentAuthority(ctx, scope, snapshot)
	if stale != nil {
		return workflow.CommitResult{Version: snapshot.Version, Halt: haltOnStale(stale)}, nil
	}
	if issuanceAuthority.ApprovalRevoked(input.RequestID) {
		denied := problem.New(problem.CodeApplyAuthorizationDenied, "")
		denied.Detail = "the accepted approval has been revoked by current authority"
		return workflow.CommitResult{}, denied
	}
	issued, err := e.cfg.CommitAuthority.Issue(ctx, AuthorizationRequest{
		IdempotencyKey:    op.Key(),
		WorkspaceID:       snapshot.WorkspaceID,
		ProjectID:         snapshot.Target.ProjectID,
		RunID:             string(id),
		ArtifactDigest:    input.ArtifactDigest,
		ActionDigest:      approval.ActionDigest,
		ApprovalRequestID: input.RequestID,
	})
	if err != nil {
		return workflow.CommitResult{}, fmt.Errorf("issue commit authorization: %w", err)
	}
	if err := e.recordEvidence(ctx, op, input.Run, snapshot, "commit.authorization-issued", "audit", map[string]string{"authorizationId": issued.AuthorizationID, "artifactDigest": input.ArtifactDigest}); err != nil {
		return workflow.CommitResult{}, err
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
	// The durable write-ahead submission record lands before the run crosses
	// the submit boundary. It carries the complete signed authorization under
	// the stable operation identity, so any successor process knows exactly
	// what was about to be sent and whether sending is still safe.
	operation, err := e.ensureSubmission(ctx, snapshot, id, operationID, op.Key(), approval.ActionDigest, input, issued)
	if err != nil {
		return workflow.CommitResult{}, err
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
	return e.submitRecorded(ctx, scope, snapshot, id, operation, input)
}

// ensureSubmission durably records the write-ahead domain operation in the
// not-submitted state, carrying the complete signed authorization. It is
// insert-once per run: a replay converges on the existing record, and a
// record that names a different operation or authorization is a conflict,
// never a second submission path.
func (e *Executor) ensureSubmission(ctx context.Context, snapshot runs.Snapshot, id runs.ID, operationID, operationKey, actionDigest string, input workflow.CommitInput, issued IssuedAuthorization) (domaincommit.Operation, error) {
	journalScope := domaincommit.Scope{WorkspaceID: snapshot.WorkspaceID, ProjectID: snapshot.Target.ProjectID}
	verify := func(operation domaincommit.Operation) (domaincommit.Operation, error) {
		if operation.ID != operationID || string(operation.AuthorizationID) != issued.AuthorizationID || operation.AuthorizationJWS == "" {
			return domaincommit.Operation{}, problem.New(problem.CodeIdempotencyConflict, "")
		}
		return operation, nil
	}
	if prior, active, err := e.cfg.Submissions.ActiveForRun(ctx, journalScope, id); err != nil {
		return domaincommit.Operation{}, fmt.Errorf("read domain submission journal: %w", err)
	} else if active {
		return verify(prior)
	}
	requestDigest, err := deterministicDigest(struct {
		OperationID     string `json:"operationId"`
		AuthorizationID string `json:"authorizationId"`
		ArtifactDigest  string `json:"artifactDigest"`
	}{operationID, issued.AuthorizationID, input.ArtifactDigest})
	if err != nil {
		return domaincommit.Operation{}, fmt.Errorf("digest domain submission identity: %w", err)
	}
	now := e.cfg.Clock.Now().UTC()
	operation := domaincommit.Operation{
		Scope:            journalScope,
		RunID:            id,
		ID:               operationID,
		AuthorizationID:  applyauth.AuthorizationID(issued.AuthorizationID),
		AuthorizationJWS: issued.CompactJWS,
		ActionDigest:     actionDigest,
		ArtifactDigest:   input.ArtifactDigest,
		ExpectedRevision: "rev:" + input.RequestID,
		IdempotencyKey:   operationKey,
		RequestDigest:    requestDigest,
		Status:           domaincommit.Recorded,
		CreatedAt:        now,
		UpdatedAt:        now,
	}
	if operation.AuthorizationJWS == "" {
		return domaincommit.Operation{}, fmt.Errorf("record domain submission: the issued authorization does not carry its signed token")
	}
	if err := e.cfg.Submissions.Create(ctx, operation); err != nil {
		// A racing execution recorded first; converge on its record.
		prior, active, readErr := e.cfg.Submissions.ActiveForRun(ctx, journalScope, id)
		if readErr == nil && active {
			return verify(prior)
		}
		return domaincommit.Operation{}, fmt.Errorf("durably record domain submission: %w", err)
	}
	return operation, nil
}

// submitRecorded drives one recorded operation across the submit boundary:
// the durable submitted-intent mark first, then the submission itself under
// the same stable operation identity, then settlement of a decided outcome.
// A submission whose answer is lost leaves the intent mark in place, so the
// next execution reconciles instead of sending again.
func (e *Executor) submitRecorded(ctx context.Context, scope runs.Scope, snapshot runs.Snapshot, id runs.ID, operation domaincommit.Operation, input workflow.CommitInput) (workflow.CommitResult, error) {
	if err := e.cfg.Submissions.MarkIssued(ctx, operation.Scope, operation.ID, e.cfg.Clock.Now().UTC()); err != nil {
		return workflow.CommitResult{}, fmt.Errorf("record domain submission intent: %w", err)
	}
	command, err := e.domainCommandOf(snapshot, id, operation)
	if err != nil {
		return workflow.CommitResult{}, err
	}
	outcome, err := e.cfg.Domain.Commit(ctx, command)
	if err != nil {
		// The submission outcome is unknown. The durable intent mark and the
		// run's submit-boundary state both survive; the run holds at the
		// boundary and the next reconciliation wake resolves against the
		// authoritative record instead of submitting again.
		return e.unsettledResult(1, snapshot.Version, false), nil
	}
	return e.settleDomain(ctx, scope, snapshot, id, operation.ID, input, outcome)
}

// domainCommandOf renders the authoritative domain command: the complete
// signed authorization from the durable submission record plus every binding
// re-derived from the run's durable state for the owner to verify against the
// signed payload.
func (e *Executor) domainCommandOf(snapshot runs.Snapshot, id runs.ID, operation domaincommit.Operation) (DomainCommand, error) {
	definitionDigest, bomDigest, policyDigest, err := materialDigests(snapshot.Definition, snapshot.ContractBOM, snapshot.Policy)
	if err != nil {
		return DomainCommand{}, fmt.Errorf("digest pinned material for the domain command: %w", err)
	}
	return DomainCommand{
		OperationID:       operation.ID,
		WorkspaceID:       snapshot.WorkspaceID,
		ProjectID:         snapshot.Target.ProjectID,
		RunID:             string(id),
		ArtifactDigest:    operation.ArtifactDigest,
		AuthorizationID:   string(operation.AuthorizationID),
		AuthorizationJWS:  operation.AuthorizationJWS,
		ActionDigest:      operation.ActionDigest,
		BaseRevision:      operation.ExpectedRevision,
		Target:            applyauth.Target{Type: snapshot.Target.Type, ID: snapshot.Target.ID, WorkspaceID: snapshot.Target.WorkspaceID, ProjectID: snapshot.Target.ProjectID},
		ActorID:           snapshot.ActorID,
		DefinitionDigest:  definitionDigest,
		ContractBOMDigest: bomDigest,
		PolicyDigest:      policyDigest,
	}, nil
}

// reconcileDomain resolves a run that already reached the submit boundary.
// The durable write-ahead submission record distinguishes the states: a
// not-submitted record proves nothing was sent and may be submitted under the
// same stable operation identity; a submitted-but-uncertain record is only
// ever reconciled against the authoritative owner — never repeated and never
// prematurely failed; a decided record settles the run. Nothing on any path
// re-issues an authorization.
func (e *Executor) reconcileDomain(ctx context.Context, scope runs.Scope, snapshot runs.Snapshot, id runs.ID, operationID string, input workflow.CommitInput) (workflow.CommitResult, error) {
	journalScope := domaincommit.Scope{WorkspaceID: snapshot.WorkspaceID, ProjectID: snapshot.Target.ProjectID}
	operation, active, err := e.cfg.Submissions.ActiveForRun(ctx, journalScope, id)
	if err != nil {
		return workflow.CommitResult{}, fmt.Errorf("read domain submission journal: %w", err)
	}
	if !active {
		// The journal may already be decided with only the run transition
		// outstanding (a crash between journal finalization and the run's
		// terminal transition).
		finalized, getErr := e.cfg.Submissions.Get(ctx, journalScope, operationID)
		if getErr == nil {
			if outcome, terminal := domainOutcomeOf(finalized.Status); terminal {
				return e.settleDomain(ctx, scope, snapshot, id, operationID, input, DomainOutcome{Status: outcome})
			}
		}
		// No durable submission record decides this run. Nothing proves a
		// submission happened, and nothing proves it did not: the run holds
		// at the submit boundary instead of failing an effect that may exist.
		return e.unsettledResult(1, snapshot.Version, false), nil
	}
	switch operation.Status {
	case domaincommit.Recorded:
		// The write-ahead record exists but the submitted-intent mark does
		// not: the crash happened before anything was sent, so submitting now
		// under the same stable operation identity is safe.
		return e.submitRecorded(ctx, scope, snapshot, id, operation, input)
	case domaincommit.Issued, domaincommit.Awaiting:
		record, found, err := e.cfg.Domain.Reconcile(ctx, DomainQuery{
			OperationID: operation.ID,
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
				return e.settleDomain(ctx, scope, snapshot, id, operation.ID, input, record)
			}
		}
		// The intent mark proves a submission may have been attempted and no
		// authoritative record decides it yet. The command could still be in
		// flight, so the effect is neither repeated nor prematurely failed:
		// the uncertain reconciliation is counted durably, the bounded window
		// escalates to operator resolution, and the run holds either way.
		return e.recordUncertainty(ctx, input, snapshot, journalScope, operation)
	case domaincommit.Escalated:
		// Escalation still self-heals: the owner's late answer settles the
		// run the moment it exists, and an audited operator resolution of the
		// journal settles it on the next wake.
		record, found, err := e.cfg.Domain.Reconcile(ctx, DomainQuery{
			OperationID: operation.ID,
			WorkspaceID: snapshot.WorkspaceID,
			ProjectID:   snapshot.Target.ProjectID,
			RunID:       string(id),
		})
		if err != nil {
			return workflow.CommitResult{}, fmt.Errorf("reconcile escalated domain effect: %w", err)
		}
		if found {
			switch record.Status {
			case DomainConfirmed, DomainConflict, DomainRejected:
				return e.settleDomain(ctx, scope, snapshot, id, operation.ID, input, record)
			}
		}
		return e.unsettledResult(operation.ReconcileAttempts, snapshot.Version, true), nil
	default:
		if outcome, terminal := domainOutcomeOf(operation.Status); terminal {
			return e.settleDomain(ctx, scope, snapshot, id, operation.ID, input, DomainOutcome{Status: outcome})
		}
		uncertain := problem.New(problem.CodeDomainOutcomeUncertain, "")
		uncertain.Detail = "the domain submission record is in an unrecognized state"
		return workflow.CommitResult{}, uncertain
	}
}

// recordUncertainty durably counts one uncertain reconciliation, records the
// evidence trail that makes the held run observable, and escalates the
// operation to operator resolution once the bounded window elapses. It
// always answers with an unsettled hold — never a failure, never a resend.
func (e *Executor) recordUncertainty(ctx context.Context, input workflow.CommitInput, snapshot runs.Snapshot, journalScope domaincommit.Scope, operation domaincommit.Operation) (workflow.CommitResult, error) {
	updated, err := e.cfg.Submissions.RecordReconcile(ctx, journalScope, operation.ID, e.cfg.Clock.Now().UTC())
	if err != nil {
		// The journal may have been decided or escalated concurrently. The
		// hold is never lost to that race, but the escalation state reported
		// to the workflow must still come from the record rather than from
		// this failed write, so the journal is re-read.
		concurrent, getErr := e.cfg.Submissions.Get(ctx, journalScope, operation.ID)
		return e.unsettledResult(operation.ReconcileAttempts+1, snapshot.Version, getErr == nil && concurrent.Status == domaincommit.Escalated), nil
	}
	if updated.ReconcileAttempts == 1 {
		if err := e.recordEvidence(ctx, workflow.OpID{WorkflowID: input.Run.Key.WorkflowID(), Step: "domain-uncertain:" + operation.ID}, input.Run, snapshot, "domain.submission-uncertain", "audit", map[string]string{"operationId": operation.ID}); err != nil {
			return workflow.CommitResult{}, err
		}
	}
	escalated := updated.Status == domaincommit.Escalated
	if e.cfg.ReconcileLimit > 0 && updated.ReconcileAttempts >= uint64(e.cfg.ReconcileLimit) && !escalated {
		if err := e.cfg.Submissions.Escalate(ctx, journalScope, operation.ID, e.cfg.Clock.Now().UTC()); err != nil {
			return workflow.CommitResult{}, fmt.Errorf("escalate uncertain domain submission: %w", err)
		}
		if err := e.recordEvidence(ctx, workflow.OpID{WorkflowID: input.Run.Key.WorkflowID(), Step: "domain-escalated:" + operation.ID}, input.Run, snapshot, "domain.submission-escalated", "audit", map[string]string{"operationId": operation.ID, "reconcileAttempts": fmt.Sprintf("%d", updated.ReconcileAttempts)}); err != nil {
			return workflow.CommitResult{}, err
		}
		escalated = true
	}
	return e.unsettledResult(updated.ReconcileAttempts, snapshot.Version, escalated), nil
}

// OperatorResolution is one audited operator decision on a governed effect
// that is durably escalated. OperationID names the exact submission the
// operator reviewed, so a decision can never land on a different operation
// than the one the evidence was read from. OperatorID is derived from the
// verified request authority by the caller, never from the request body.
// Basis is a bounded reference to the authoritative evidence the decision
// rests on — never operator-authored prose, which would carry unbounded
// content of unknown sensitivity into an immutable audit record.
type OperatorResolution struct {
	OperationID string
	Outcome     string
	OperatorID  string
	Basis       string
}

// Validate bounds the command. The outcome vocabulary is the domain outcome
// vocabulary: an operator decides which authoritative outcome the effect
// actually had, never an outcome the domain has no word for.
func (r OperatorResolution) Validate() error {
	if r.OperationID == "" || len(r.OperationID) > 128 {
		return stableProblem(problem.CodeRequestInvalid, "the escalated operation identity is required")
	}
	switch r.Outcome {
	case DomainConfirmed, DomainConflict, DomainRejected:
	default:
		return stableProblem(problem.CodeRequestInvalid, "the resolution outcome is not an authoritative domain outcome")
	}
	if r.OperatorID == "" || len(r.OperatorID) > 128 {
		return stableProblem(problem.CodeRequestInvalid, "the resolving operator identity is required")
	}
	if !validEvidenceReference(r.Basis) {
		return stableProblem(problem.CodeRequestInvalid, "the resolution basis must be a bounded anvilkit://evidence/<authority>/<record> reference")
	}
	return nil
}

// validEvidenceReference reports whether the basis is the bounded evidence
// reference the canonical ResolveDomainOperationRequest contract defines:
// anvilkit://evidence/<authority>/<record>. The executor proves it again
// rather than trusting that transport validated the wire shape, because this
// value becomes an immutable audit fact and the bound is what keeps
// operator-supplied bytes from carrying anything but a retrievable identity.
func validEvidenceReference(value string) bool {
	const prefix = "anvilkit://evidence/"
	if len(value) < 24 || len(value) > 256 || !strings.HasPrefix(value, prefix) {
		return false
	}
	rest := value[len(prefix):]
	separator := strings.IndexByte(rest, '/')
	if separator < 2 || separator > 32 {
		return false
	}
	authority, record := rest[:separator], rest[separator+1:]
	if record == "" || len(record) > 128 {
		return false
	}
	for index := 0; index < len(authority); index++ {
		character := authority[index]
		if character >= 'a' && character <= 'z' || character >= '0' && character <= '9' {
			continue
		}
		if index == 0 || character != '-' {
			return false
		}
	}
	for index := 0; index < len(record); index++ {
		character := record[index]
		if character >= 'a' && character <= 'z' || character >= 'A' && character <= 'Z' || character >= '0' && character <= '9' {
			continue
		}
		if index == 0 || character != '.' && character != '_' && character != '-' {
			return false
		}
	}
	return true
}

func stableProblem(code problem.Code, detail string) problem.Details {
	value := problem.New(code, "")
	value.Detail = detail
	return value
}

// ResolveEscalation is the production operator recovery path for a run whose
// governed effect is durably escalated. It records the audited resolution on
// the durable submission journal and then settles the held run from that
// record.
//
// Everything the decision needs is proved here rather than assumed by the
// caller: the run is read inside the operator's own workspace and project, so
// a run in another tenant is indistinguishable from one that does not exist;
// current authority is re-read and must be active, complete, hold the operator
// role in this scope's subject register, and not have had authority over the
// run's target withdrawn; the operator's identity comes from the verified
// request authority the caller resolved; the journal write is a
// compare-and-set on the escalated state, so two operators racing produce one
// winner and one conflict; and a replay of the same decision converges on the
// recorded one instead of deciding twice. It never contacts the domain owner
// and never resends anything.
func (e *Executor) ResolveEscalation(ctx context.Context, scope runs.Scope, id runs.ID, expectedVersion uint64, command OperatorResolution) (runs.Snapshot, error) {
	if err := command.Validate(); err != nil {
		return runs.Snapshot{}, err
	}
	snapshot, err := e.cfg.Runs.Get(ctx, scope, id)
	if err != nil {
		return runs.Snapshot{}, err
	}
	if _, denial := e.operatorAuthority(ctx, scope, snapshot); denial != nil {
		return runs.Snapshot{}, *denial
	}
	journalScope := domaincommit.Scope{WorkspaceID: snapshot.WorkspaceID, ProjectID: snapshot.Target.ProjectID}
	operation, found, err := e.cfg.Submissions.LatestForRun(ctx, journalScope, id)
	if err != nil {
		return runs.Snapshot{}, fmt.Errorf("load domain submission for operator resolution: %w", err)
	}
	if !found || operation.ID != command.OperationID {
		// The operator decided an operation this run does not hold. Naming the
		// exact operation is what binds the decision to the evidence it was
		// made from, so a mismatch is refused rather than redirected.
		mismatched := problem.New(problem.CodeIdempotencyConflict, "")
		mismatched.Detail = "the named operation is not the run's current domain submission"
		return runs.Snapshot{}, mismatched
	}
	if recorded, terminal := domainOutcomeOf(operation.Status); terminal {
		// Already decided. A replay of this exact audited decision converges;
		// anything else — a different outcome, a different operator, a
		// different basis, or an outcome the owner decided itself — is a
		// conflict, never an override.
		if recorded == command.Outcome && operation.ResolvedBy == command.OperatorID && operation.ResolutionBasis == command.Basis {
			return e.settleResolvedRun(ctx, scope, snapshot, id, operation)
		}
		decided := problem.New(problem.CodeIdempotencyConflict, "")
		decided.Detail = "the governed effect is already decided"
		return runs.Snapshot{}, decided
	}
	if operation.Status != domaincommit.Escalated {
		notEscalated := problem.New(problem.CodeInvalidTransition, "")
		notEscalated.Detail = "only a durably escalated governed effect may be operator-resolved"
		return runs.Snapshot{}, notEscalated
	}
	if snapshot.Status != runs.AwaitingDomainConfirmation {
		invalid := problem.New(problem.CodeInvalidTransition, "")
		invalid.Detail = "only a run holding at the submit boundary can be operator-resolved"
		return runs.Snapshot{}, invalid
	}
	if expectedVersion != 0 && snapshot.Version != expectedVersion {
		return runs.Snapshot{}, problem.New(problem.CodeVersionConflict, "")
	}
	status, ok := submissionStatusOf(command.Outcome)
	if !ok {
		return runs.Snapshot{}, stableProblem(problem.CodeRequestInvalid, "the resolution outcome is not an authoritative domain outcome")
	}
	// The immutable audit record this decision will leave behind is proved
	// acceptable before anything durable is written. The order is the whole
	// point: the journal resolution is immutable, so recording it first and
	// only then discovering that its evidence cannot be stored would leave a
	// decided submission on a run that can never settle — every retry would
	// re-read the same recorded decision and fail on the same evidence.
	// Proving first means a basis that cannot be audited is refused as an
	// invalid command, with nothing persisted and the run still recoverable.
	if err := e.proveOperatorResolutionEvidence(scope, snapshot, id, operation.ID, command.Outcome, command.OperatorID, command.Basis); err != nil {
		return runs.Snapshot{}, err
	}
	// The audited resolution is durable before anything settles: the journal
	// row records who decided, on what basis, and to what outcome, under a
	// compare-and-set on the escalated state that only one racer can win.
	resolved, err := e.cfg.Submissions.Resolve(ctx, journalScope, operation.ID, status, command.OperatorID, command.Basis, e.cfg.Clock.Now().UTC())
	if err != nil {
		return runs.Snapshot{}, err
	}
	return e.settleResolvedRun(ctx, scope, snapshot, id, resolved)
}

// AuthorizeOperatorRecovery proves current authority admits this actor as an
// operator for this run right now, without deciding anything. It exists for
// the boundary that answers a recorded operator-recovery receipt: that path
// returns a privileged response without running the command, so it needs the
// same current-authority proof the command path gets — activation, complete
// governance material, the operator role, and revocation of authority over the
// run's target — resolved against the run this request addresses. The run read
// is scoped, so a caller reaching outside its workspace or project is refused
// here exactly as it would be by the command.
func (e *Executor) AuthorizeOperatorRecovery(ctx context.Context, scope runs.Scope, id runs.ID) error {
	snapshot, err := e.cfg.Runs.Get(ctx, scope, id)
	if err != nil {
		return err
	}
	if _, denial := e.operatorAuthority(ctx, scope, snapshot); denial != nil {
		return *denial
	}
	return nil
}

// operatorResolutionEvidenceType names the immutable audit record an operator
// recovery leaves behind.
const operatorResolutionEvidenceType = "domain.submission-operator-resolved"

// operatorResolutionEvidence renders the durable operation identity, run
// input, and bounded payload of one operator recovery. The pre-write proof and
// the post-write record are both built here, so the record that is authorized
// and the record that is stored can never diverge.
func operatorResolutionEvidence(scope runs.Scope, snapshot runs.Snapshot, id runs.ID, operationID, outcome, operatorID, basis string) (workflow.OpID, workflow.RunInput, map[string]string) {
	input := workflow.RunInput{
		Key:   workflow.RunKey{RunID: string(id), Generation: snapshot.ExecutionGeneration},
		Scope: workflow.Scope{WorkspaceID: scope.WorkspaceID, ProjectID: scope.ProjectID, ActorID: scope.ActorID},
	}
	return workflow.OpID{WorkflowID: input.Key.WorkflowID(), Step: "domain-operator-resolved:" + operationID}, input, map[string]string{
		"operationId": operationID,
		"outcome":     outcome,
		"resolvedBy":  operatorID,
		"basis":       basis,
	}
}

// proveOperatorResolutionEvidence proves the internal evidence contract
// accepts the operator-recovery record this decision will produce. A basis the
// contract refuses is an invalid command, not an internal fault: it is
// reported as such and nothing durable is written.
func (e *Executor) proveOperatorResolutionEvidence(scope runs.Scope, snapshot runs.Snapshot, id runs.ID, operationID, outcome, operatorID, basis string) error {
	op, input, payload := operatorResolutionEvidence(scope, snapshot, id, operationID, outcome, operatorID, basis)
	_, err := e.buildEvidence(op, input, snapshot, operatorResolutionEvidenceType, "audit", e.cfg.Clock.Now(), payload)
	if err == nil {
		return nil
	}
	var contract evidenceContractError
	if errors.As(err, &contract) {
		refused := problem.New(problem.CodeRequestInvalid, "")
		refused.Detail = "the resolution basis cannot be recorded as immutable operator-recovery evidence"
		return refused
	}
	return fmt.Errorf("prove operator recovery evidence: %w", err)
}

// operatorAuthority re-reads the one current-authority source and proves it
// permits this actor to recover this run right now. Nothing here trusts a
// past decision: an authority withdrawn since the escalation was raised
// denies the recovery on this read.
func (e *Executor) operatorAuthority(ctx context.Context, scope runs.Scope, snapshot runs.Snapshot) (authority.Current, *problem.Details) {
	current, err := e.cfg.Authority.Current(ctx, scope.AuthorityScope())
	if err != nil {
		denied := problem.New(problem.CodeAuthorityStale, "")
		denied.Detail = "current authority could not be resolved for operator recovery"
		return authority.Current{}, &denied
	}
	if !current.Active() || !current.MaterialComplete() {
		denied := problem.New(problem.CodeAuthorityStale, "")
		denied.Detail = "current authority does not permit operator recovery"
		return authority.Current{}, &denied
	}
	if !current.HasRole(authority.RoleOperator) {
		denied := problem.New(problem.CodeAuthorizationDenied, "")
		denied.Detail = "operator recovery requires the operator role in this scope"
		return authority.Current{}, &denied
	}
	if current.TargetRevoked(snapshot.Target.ID) {
		denied := problem.New(problem.CodeAuthorityStale, "")
		denied.Detail = "authority over the run's target is revoked"
		return authority.Current{}, &denied
	}
	return current, nil
}

// settleResolvedRun drives the run to the outcome its decided submission
// record carries and records the immutable operator-recovery evidence. Every
// audited fact comes from the durable journal record rather than from the
// command that produced it: the journal write is the compare-and-set that
// picks the single winner among racing operators, so reading the decision back
// is what keeps the audit record and the decision in agreement. It converges:
// evidence is idempotent by its derived identity, settlement is idempotent by
// the operation, and a run already settled to the recorded outcome is returned
// as it stands — so a crash anywhere in this sequence is repaired by repeating
// it.
func (e *Executor) settleResolvedRun(ctx context.Context, scope runs.Scope, snapshot runs.Snapshot, id runs.ID, operation domaincommit.Operation) (runs.Snapshot, error) {
	outcome, terminal := domainOutcomeOf(operation.Status)
	if !terminal {
		return runs.Snapshot{}, stableProblem(problem.CodeDomainOutcomeUncertain, "the submission record is not decided")
	}
	op, runInput, payload := operatorResolutionEvidence(scope, snapshot, id, operation.ID, outcome, operation.ResolvedBy, operation.ResolutionBasis)
	if err := e.recordEvidence(ctx, op, runInput, snapshot, operatorResolutionEvidenceType, "audit", payload); err != nil {
		return runs.Snapshot{}, err
	}
	input := workflow.CommitInput{Run: runInput, ArtifactDigest: operation.ArtifactDigest}
	if _, err := e.settleDomain(ctx, scope, snapshot, id, operation.ID, input, DomainOutcome{Status: outcome}); err != nil {
		return runs.Snapshot{}, err
	}
	return e.cfg.Runs.Get(ctx, scope, id)
}

// submissionStatusOf maps a domain outcome onto the submission journal's
// terminal vocabulary.
func submissionStatusOf(outcome string) (domaincommit.Status, bool) {
	switch outcome {
	case DomainConfirmed:
		return domaincommit.Applied, true
	case DomainConflict:
		return domaincommit.Conflicted, true
	case DomainRejected:
		return domaincommit.Rejected, true
	default:
		return "", false
	}
}

// ResolveEscalatedSubmission settles a run held at the submit boundary from
// its decided durable submission record. It is the settlement half of
// operator recovery, reachable on its own for the case where the owner's late
// answer finalized the journal and only the run transition is outstanding. It
// never contacts the domain owner and never resends anything; the decided
// journal is its only input, and settling converges under replay.
func (e *Executor) ResolveEscalatedSubmission(ctx context.Context, scope runs.Scope, id runs.ID) (runs.Snapshot, error) {
	snapshot, err := e.cfg.Runs.Get(ctx, scope, id)
	if err != nil {
		return runs.Snapshot{}, fmt.Errorf("load run for operator settlement: %w", err)
	}
	switch snapshot.Status {
	case runs.Completed, runs.Conflict, runs.Failed:
		// Already settled; converge.
		return snapshot, nil
	case runs.AwaitingDomainConfirmation:
	default:
		invalid := problem.New(problem.CodeInvalidTransition, "")
		invalid.Detail = "only a run holding at the submit boundary can be operator-settled"
		return runs.Snapshot{}, invalid
	}
	journalScope := domaincommit.Scope{WorkspaceID: snapshot.WorkspaceID, ProjectID: snapshot.Target.ProjectID}
	operation, found, err := e.cfg.Submissions.LatestForRun(ctx, journalScope, id)
	if err != nil {
		return runs.Snapshot{}, fmt.Errorf("load domain submission for operator settlement: %w", err)
	}
	if !found {
		missing := problem.New(problem.CodeDomainOutcomeUncertain, "")
		missing.Retryability = "operator-action"
		missing.Detail = "no durable submission record exists for the held run"
		return runs.Snapshot{}, missing
	}
	outcome, terminal := domainOutcomeOf(operation.Status)
	if !terminal {
		undecided := problem.New(problem.CodeDomainOutcomeUncertain, "")
		undecided.Retryability = "operator-action"
		undecided.Detail = "the submission record is not decided; record the audited resolution on the journal first"
		return runs.Snapshot{}, undecided
	}
	input := workflow.CommitInput{
		Run: workflow.RunInput{
			Key:   workflow.RunKey{RunID: string(id), Generation: snapshot.ExecutionGeneration},
			Scope: workflow.Scope{WorkspaceID: scope.WorkspaceID, ProjectID: scope.ProjectID, ActorID: scope.ActorID},
		},
		ArtifactDigest: operation.ArtifactDigest,
	}
	result, err := e.settleDomain(ctx, scope, snapshot, id, operation.ID, input, DomainOutcome{Status: outcome})
	if err != nil {
		return runs.Snapshot{}, err
	}
	_ = result
	return e.cfg.Runs.Get(ctx, scope, id)
}

// runStateOf maps a domain outcome onto the terminal run state it settles to.
func runStateOf(outcome string) (runs.State, bool) {
	switch outcome {
	case DomainConfirmed:
		return runs.Completed, true
	case DomainConflict:
		return runs.Conflict, true
	case DomainRejected:
		return runs.Failed, true
	default:
		return "", false
	}
}

// commitOutcomeOf maps a domain outcome onto the workflow commit vocabulary.
func commitOutcomeOf(outcome string) string {
	switch outcome {
	case DomainConfirmed:
		return workflow.CommitCompleted
	case DomainConflict:
		return workflow.CommitConflict
	default:
		return workflow.CommitFailed
	}
}

// submissionStatusMust maps a domain outcome already proved terminal onto the
// submission journal's terminal vocabulary.
func submissionStatusMust(outcome string) domaincommit.Status {
	status, _ := submissionStatusOf(outcome)
	return status
}

// domainOutcomeOf maps a decided submission-journal status onto the domain
// outcome vocabulary.
func domainOutcomeOf(status domaincommit.Status) (string, bool) {
	switch status {
	case domaincommit.Applied:
		return DomainConfirmed, true
	case domaincommit.Conflicted:
		return DomainConflict, true
	case domaincommit.Rejected:
		return DomainRejected, true
	default:
		return "", false
	}
}

// finalizeSubmission records the decided outcome on the durable submission
// journal, converging when another execution already finalized it identically.
func (e *Executor) finalizeSubmission(ctx context.Context, journalScope domaincommit.Scope, operationID string, status domaincommit.Status) error {
	if err := e.cfg.Submissions.Finalize(ctx, journalScope, operationID, status, e.cfg.Clock.Now().UTC()); err != nil {
		current, getErr := e.cfg.Submissions.Get(ctx, journalScope, operationID)
		if getErr == nil && current.Status == status {
			return nil
		}
		return fmt.Errorf("finalize domain submission record: %w", err)
	}
	return nil
}

// settleDomain records one authoritative domain outcome on the aggregate. It
// is the single place a governed effect becomes a terminal run state, whether
// the outcome came from the submission itself or from reconciling one. The
// durable submission journal is finalized before the run transitions, so a
// crash between the two leaves a decided journal a successor replays from.
func (e *Executor) settleDomain(ctx context.Context, scope runs.Scope, snapshot runs.Snapshot, id runs.ID, operationID string, input workflow.CommitInput, outcome DomainOutcome) (workflow.CommitResult, error) {
	journalScope := domaincommit.Scope{WorkspaceID: snapshot.WorkspaceID, ProjectID: snapshot.Target.ProjectID}
	if state, terminal := runStateOf(outcome.Status); terminal && snapshot.Status == state {
		// Another execution already settled this run to the same outcome — the
		// workflow's own wake and the audited operator resolution can both
		// reach here for one decided effect. Converge on the settled run
		// instead of re-applying a transition it already made.
		if err := e.finalizeSubmission(ctx, journalScope, operationID, submissionStatusMust(outcome.Status)); err != nil {
			return workflow.CommitResult{}, err
		}
		return workflow.CommitResult{Outcome: commitOutcomeOf(outcome.Status), Version: snapshot.Version}, nil
	}
	switch outcome.Status {
	case DomainConfirmed:
		if err := e.finalizeSubmission(ctx, journalScope, operationID, domaincommit.Applied); err != nil {
			return workflow.CommitResult{}, err
		}
		if err := e.recordEvidence(ctx, workflow.OpID{WorkflowID: input.Run.Key.WorkflowID(), Step: "domain:" + operationID}, input.Run, snapshot, "domain.effect-confirmed", "audit", map[string]string{"operationId": operationID, "status": outcome.Status}); err != nil {
			return workflow.CommitResult{}, err
		}
		// The confirmed governed effect commits the immutable artifact before
		// the run settles; a replay converges on the committed record.
		if err := e.cfg.Artifacts.EnsureCommitted(ctx, ArtifactQuery{
			WorkspaceID:    snapshot.WorkspaceID,
			ProjectID:      snapshot.Target.ProjectID,
			RunID:          string(id),
			ArtifactDigest: input.ArtifactDigest,
		}); err != nil {
			return workflow.CommitResult{}, fmt.Errorf("commit confirmed artifact: %w", err)
		}
		next, lost, err := e.apply(ctx, scope, id, snapshot.Version, runs.Command{Kind: runs.ConfirmDomain, Traceparent: traceparentOf(input.Run)}, runs.Completed)
		if err != nil {
			return workflow.CommitResult{}, err
		}
		if lost {
			return workflow.CommitResult{Superseded: true}, nil
		}
		if err := e.settleRunBudget(ctx, snapshot, true); err != nil {
			return workflow.CommitResult{}, err
		}
		return workflow.CommitResult{Outcome: workflow.CommitCompleted, Version: next.Version}, nil
	case DomainConflict:
		if err := e.finalizeSubmission(ctx, journalScope, operationID, domaincommit.Conflicted); err != nil {
			return workflow.CommitResult{}, err
		}
		next, lost, err := e.apply(ctx, scope, id, snapshot.Version, runs.Command{Kind: runs.RecordDomainConflict, Traceparent: traceparentOf(input.Run)}, runs.Conflict)
		if err != nil {
			return workflow.CommitResult{}, err
		}
		if lost {
			return workflow.CommitResult{Superseded: true}, nil
		}
		return workflow.CommitResult{Outcome: workflow.CommitConflict, Version: next.Version}, nil
	case DomainRejected:
		if err := e.finalizeSubmission(ctx, journalScope, operationID, domaincommit.Rejected); err != nil {
			return workflow.CommitResult{}, err
		}
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
		if err := e.settleRunBudget(ctx, snapshot, false); err != nil {
			return workflow.CommitResult{}, err
		}
		return workflow.CommitResult{Outcome: workflow.CommitFailed, Problem: &failure, Version: next.Version}, nil
	default:
		// An unrecognized answer settles nothing. The run holds at the submit
		// boundary and the next reconciliation wake resolves it against the
		// authoritative record.
		return e.unsettledResult(1, snapshot.Version, false), nil
	}
}

// domainOperationIDFor derives the governed effect identity from the
// workflow, the accepted approval, and the artifact. The identity is stable
// across reconciliation wakes and process restarts, so recovery always
// addresses the operation the first execution recorded.
func domainOperationIDFor(input workflow.CommitInput) string {
	return "domain." + strings.TrimPrefix(mustDeterministicDigest(struct {
		WorkflowID     string `json:"workflowId"`
		RequestID      string `json:"requestId"`
		ArtifactDigest string `json:"artifactDigest"`
	}{input.Run.Key.WorkflowID(), input.RequestID, input.ArtifactDigest}), "sha256:")[:32]
}

// unsettledResult holds the run at the submit boundary without failing it:
// the workflow waits out a bounded backoff shaped by how long the effect has
// been uncertain, then reconciles again. escalated reports the submission
// journal's durable escalation state — the workflow releases the run at the
// boundary on that and nothing else, so it is only ever set from a record
// that was actually read or written, never inferred from a local count.
func (e *Executor) unsettledResult(attempts, version uint64, escalated bool) workflow.CommitResult {
	backoff := e.cfg.DomainRetryBase
	for i := uint64(1); i < attempts && backoff < e.cfg.DomainRetryCap; i++ {
		backoff *= 2
	}
	if backoff > e.cfg.DomainRetryCap {
		backoff = e.cfg.DomainRetryCap
	}
	return workflow.CommitResult{Unsettled: true, RetryAfterMillis: backoff.Milliseconds(), Version: version, Escalated: escalated}
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
		if err := e.settleRunBudget(ctx, snapshot, target == runs.Refused); err != nil {
			return workflow.Ack{}, err
		}
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
	// Terminal settlement: a refused run releases its budget hold; a failed
	// run keeps its settled cost held so replacement work reserves on top.
	if err := e.settleRunBudget(ctx, snapshot, target == runs.Refused); err != nil {
		return workflow.Ack{}, err
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

// budgetReservationID derives the deterministic identity of the standing
// reservation one execution generation of one run holds.
func budgetReservationID(runID string, generation uint64) budget.ReservationID {
	return budget.ReservationID("budget:" + runID + ":g" + strconv.FormatUint(generation, 10))
}

// ensureRunReservation reserves the run's pinned worst-case cost under the
// active budget generation before the run may execute. The first generation
// reserves initially; a later generation is replacement work — the prior
// generation's settled cost stays held, so the replacement must fit in
// incremental worst-case headroom on top of it. Replay converges on the
// reservation already made. A typed denial refuses the run.
func (e *Executor) ensureRunReservation(ctx context.Context, snapshot runs.Snapshot, limits budgetLimits) *problem.Details {
	policyVersion, policyErr := canonical.Digest(snapshot.Policy)
	budgetVersion, budgetErr := canonical.Digest(snapshot.Budget)
	if policyErr != nil || budgetErr != nil {
		refusal := problem.New(problem.CodeBudgetDenied, "")
		refusal.Detail = "pinned budget material is not digestible"
		return &refusal
	}
	estimate := budget.Estimate{
		ReservationID:     budgetReservationID(string(snapshot.RunID), snapshot.ExecutionGeneration),
		RootRunID:         string(snapshot.RootRunID),
		RunID:             string(snapshot.RunID),
		WorkspaceID:       snapshot.WorkspaceID,
		ProjectID:         snapshot.Target.ProjectID,
		PolicyVersion:     policyVersion,
		BudgetVersion:     budgetVersion,
		MaximumCostMicros: limits.MaximumCostMicros,
		ExpiresAt:         e.cfg.Clock.Now().Add(e.cfg.BudgetTTL),
	}
	generation := budget.Generation(snapshot.ExecutionGeneration)
	var reserveErr error
	if snapshot.ExecutionGeneration > 1 {
		// Replacement work reconciles the root aggregate's superseded holds
		// before it asks for headroom of its own. Without this, every
		// generation whose attempt was fenced or abandoned would keep its full
		// worst-case bound for ever — the ordinary settlement path can no
		// longer reach a generation that is no longer current — and enough
		// retries would exhaust the root's headroom permanently on budget
		// nothing ever spent. Only holds whose usage is authoritatively final
		// are reduced, and none of them regains authority to dispatch.
		if _, err := e.cfg.Budget.ReconcileSuperseded(ctx, budgetScopeOf(snapshot), string(snapshot.RootRunID), generation, budget.SettlementActor); err != nil {
			var details problem.Details
			if errors.As(err, &details) {
				return &details
			}
			refusal := problem.New(problem.CodeBudgetDenied, "")
			refusal.Detail = "superseded budget reservations could not be reconciled"
			return &refusal
		}
		prior := budgetReservationID(string(snapshot.RunID), snapshot.ExecutionGeneration-1)
		if _, err := e.cfg.Budget.Reservation(ctx, budgetScopeOf(snapshot), prior); err == nil {
			// The prior generation holds budget: this generation is
			// replacement work and reserves against it.
			_, reserveErr = e.cfg.Budget.ReserveReplacement(ctx, estimate, generation, prior)
		} else {
			// The prior generation failed before it ever reserved; nothing is
			// held, so this generation reserves initially.
			_, reserveErr = e.cfg.Budget.ReserveInitial(ctx, estimate, generation)
		}
	} else {
		_, reserveErr = e.cfg.Budget.ReserveInitial(ctx, estimate, generation)
	}
	if reserveErr != nil {
		var details problem.Details
		if errors.As(reserveErr, &details) {
			return &details
		}
		refusal := problem.New(problem.CodeBudgetDenied, "")
		refusal.Detail = "the durable budget reservation could not be made"
		return &refusal
	}
	return nil
}

// settleRunBudget finalizes and settles the run's standing reservation at its
// observed cost. Completion, refusal, and discard release the hold; a failed
// run keeps its settled cost held un-released so an explicit-retry
// replacement must reserve incremental worst-case headroom on top of it.
// Settlement converges under replay and is a no-op for a run that never
// reserved.
func (e *Executor) settleRunBudget(ctx context.Context, snapshot runs.Snapshot, release bool) error {
	scope := budgetScopeOf(snapshot)
	generation := budget.Generation(snapshot.ExecutionGeneration)
	id := budgetReservationID(string(snapshot.RunID), snapshot.ExecutionGeneration)
	reservation, err := e.cfg.Budget.Reservation(ctx, scope, id)
	if err != nil {
		var details problem.Details
		if errors.As(err, &details) && details.Code == string(problem.CodeResourceNotFound) {
			return nil
		}
		return fmt.Errorf("read run budget reservation for settlement: %w", err)
	}
	if reservation.Released {
		return e.recoverSupersededBudget(ctx, snapshot)
	}
	if err := e.cfg.Budget.Observe(ctx, budget.Observation{
		ID:                  "budget:final:" + string(snapshot.RunID) + ":g" + strconv.FormatUint(snapshot.ExecutionGeneration, 10),
		Scope:               scope,
		ReservationID:       id,
		RootRunID:           string(snapshot.RootRunID),
		RunID:               string(snapshot.RunID),
		TaskID:              "settlement",
		AttemptID:           budget.AttemptID("settlement:" + string(id)),
		ExecutionGeneration: snapshot.ExecutionGeneration,
		Final:               true,
	}); err != nil {
		return fmt.Errorf("finalize run budget reservation: %w", err)
	}
	reservation, err = e.cfg.Budget.Reservation(ctx, scope, id)
	if err != nil {
		return fmt.Errorf("re-read run budget reservation for settlement: %w", err)
	}
	// The reservation may have been superseded between its finality being
	// recorded and this settlement — an explicit retry can advance the root
	// aggregate's generation while this attempt is still finishing. The
	// controller completes that settlement on superseded terms rather than
	// refusing it, so a late final no longer waits for another retry to run
	// the superseded sweep.
	//
	// The settlement is a compare-and-set against the usage this read saw, so
	// usage that commits while it is being computed makes it lose rather than
	// overwrite that usage. Losing is answered by re-reading and settling
	// against the larger, now-durable total; each round costs one committed
	// observation, so the bound converges.
	for attempt := 0; ; attempt++ {
		observed := reservation.ObservedMicros
		_, settleErr := e.cfg.Budget.Reconcile(ctx, scope, id, generation, &observed, release, budget.SettlementActor)
		if settleErr == nil {
			break
		}
		var conflict budget.Conflict
		if !errors.As(settleErr, &conflict) || attempt >= budgetSettlementRounds {
			return fmt.Errorf("settle run budget reservation: %w", settleErr)
		}
		reservation, err = e.cfg.Budget.Reservation(ctx, scope, id)
		if err != nil {
			return fmt.Errorf("re-read run budget reservation after settlement conflict: %w", err)
		}
		if reservation.Released {
			break
		}
	}
	if err := e.recoverCancelledBudget(ctx, snapshot); err != nil {
		return err
	}
	return e.recoverSupersededBudget(ctx, snapshot)
}

// budgetSettlementRounds bounds the re-read-and-settle loop a losing
// compare-and-set drives. Each round requires another observation to have
// committed, so a small bound still converges for every attempt shape this
// service dispatches while an unbounded loop would turn a stuck writer into a
// spin.
const budgetSettlementRounds = 8

// FenceRunBudget withdraws a run's budget dispatch authority the instant its
// cancellation is requested. It is deliberately not settlement: cancellation
// may revoke dispatch, leases, and descendant work immediately, but a billed
// model, tool, or worker operation can still be running at that instant, and
// nothing at that moment knows what it will report. So the hold keeps its
// worst-case bound and stays unreleased, and only stops being able to
// authorize new work.
func (e *Executor) FenceRunBudget(ctx context.Context, snapshot runs.Snapshot) error {
	if _, err := e.cfg.Budget.FenceCancelledRun(ctx, budgetScopeOf(snapshot), string(snapshot.RootRunID), string(snapshot.RunID)); err != nil {
		var details problem.Details
		if errors.As(err, &details) && details.Code == string(problem.CodeResourceNotFound) {
			return nil
		}
		return fmt.Errorf("fence cancelled run budget: %w", err)
	}
	return nil
}

// SettleCancelledRunBudget concludes a cancelled run's accounting once an
// authoritative reconciliation has proven that no physical attempt of the run
// remains outstanding. Only the caller holds that proof, which is why this is
// a separate act from fencing rather than something cancellation does on its
// own: settling here without the proof would release budget a running
// operation is still spending.
func (e *Executor) SettleCancelledRunBudget(ctx context.Context, snapshot runs.Snapshot) error {
	if _, err := e.cfg.Budget.ConcludeCancelledRun(ctx, budgetScopeOf(snapshot), string(snapshot.RootRunID), string(snapshot.RunID), budget.SettlementActor); err != nil {
		return fmt.Errorf("settle cancelled run budget: %w", err)
	}
	return nil
}

// OutstandingCancelledRunBudget reports whether a run's root aggregate still
// holds budget a cancellation fenced and nothing has concluded. The recovery
// sweep leads with it for runs whose lifecycle is already over, so a
// cancellation that has nothing left to settle costs one indexed ledger read
// rather than a fresh interrogation of every authoritative effect store.
func (e *Executor) OutstandingCancelledRunBudget(ctx context.Context, snapshot runs.Snapshot) (bool, error) {
	outstanding, err := e.cfg.Budget.OutstandingCancelledHolds(ctx, budgetScopeOf(snapshot), string(snapshot.RootRunID))
	if err != nil {
		return false, fmt.Errorf("read outstanding cancelled budget holds: %w", err)
	}
	return outstanding, nil
}

// recoverCancelledBudget converges the root aggregate's cancelled holds whose
// physical attempt has since reported finality. It closes the same kind of
// window recoverSupersededBudget closes: a crash between an attempt's finality
// becoming durable and the settlement that acts on it leaves a hold nothing
// re-drives, because the cancelled run is terminal and its workflow will not
// replay. The predicate it works from — cancelled, final, unreleased — is
// falsified by the settlement itself, so repeating it converges.
func (e *Executor) recoverCancelledBudget(ctx context.Context, snapshot runs.Snapshot) error {
	if _, err := e.cfg.Budget.RecoverCancelledFinality(ctx, budgetScopeOf(snapshot), string(snapshot.RootRunID), budget.SettlementActor); err != nil {
		return fmt.Errorf("recover cancelled budget reservations: %w", err)
	}
	return nil
}

// recoverSupersededBudget converges the root aggregate's superseded holds that
// a crash left authoritatively final but unreconciled. The window it closes is
// the one between recording an attempt's finality and settling against it:
// nothing re-drives a hold whose generation is already gone, because that
// generation's workflow will not replay and the ordinary settlement path is
// fenced on a generation that can never be current again.
//
// It runs from every terminal budget settlement, so recovery no longer waits
// for the next explicit retry to happen to reserve. It is derived entirely
// from durable ledger state and settles only downward to reported usage, so
// running it on every settlement — and again after a crash — converges instead
// of accumulating. A failure is returned rather than swallowed: the settlement
// above is already durable, so replay re-drives this and converges.
func (e *Executor) recoverSupersededBudget(ctx context.Context, snapshot runs.Snapshot) error {
	if _, err := e.cfg.Budget.RecoverSupersededFinality(ctx, budgetScopeOf(snapshot), string(snapshot.RootRunID), budget.SettlementActor); err != nil {
		return fmt.Errorf("recover superseded budget reservations: %w", err)
	}
	return nil
}

// budgetScopeOf is the one place a run snapshot becomes a budget scope. The
// project axis is the run's target project, which is the project the run's
// spend belongs to — never the caller's ambient project.
func budgetScopeOf(snapshot runs.Snapshot) budget.Scope {
	return budget.Scope{WorkspaceID: snapshot.WorkspaceID, ProjectID: snapshot.Target.ProjectID}
}

// SettleRunBudget is the terminal budget settlement of one run, reachable from
// the lifecycle paths that terminalize a run outside the durable workflow —
// cancellation and discard. It performs the same idempotent,
// generation-fenced final usage reconciliation the workflow's own terminal
// transitions perform, so a run that ends through the control API accounts
// for its usage and frees its headroom exactly like one that ends in the
// workflow.
func (e *Executor) SettleRunBudget(ctx context.Context, snapshot runs.Snapshot, release bool) error {
	return e.settleRunBudget(ctx, snapshot, release)
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
