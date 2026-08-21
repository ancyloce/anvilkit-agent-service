package interrupts

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/ancyloce/anvilkit-agent-service/internal/canonical"
	"github.com/ancyloce/anvilkit-agent-service/internal/journal"
	"github.com/ancyloce/anvilkit-agent-service/internal/problem"
	"github.com/ancyloce/anvilkit-agent-service/internal/runs"
)

type Clock interface{ Now() time.Time }
type IDs interface {
	NewRequestID() (RequestID, error)
	NewRunID() (runs.ID, error)
}

type Limits struct {
	ChildDepth  int
	ChildFanout int
}

type Service struct {
	repository  Repository
	schema      SchemaValidator
	authority   Authority
	runtime     Runtime
	leases      LeaseRevoker
	reconciler  CancellationReconciler
	reservation Reservation
	budget      TerminalBudget
	receipts    journal.Store
	clock       Clock
	ids         IDs
	limits      Limits
}

func NewService(repository Repository, schema SchemaValidator, authority Authority, runtime Runtime, leases LeaseRevoker, reconciler CancellationReconciler, reservation Reservation, terminalBudget TerminalBudget, receipts journal.Store, clock Clock, ids IDs, limits Limits) (*Service, error) {
	if repository == nil || schema == nil || authority == nil || runtime == nil || leases == nil || reconciler == nil || reservation == nil || terminalBudget == nil || receipts == nil || clock == nil || ids == nil || limits.ChildDepth < 1 || limits.ChildFanout < 1 {
		return nil, fmt.Errorf("interrupt service dependencies and positive child bounds are required")
	}
	return &Service{repository: repository, schema: schema, authority: authority, runtime: runtime, leases: leases, reconciler: reconciler, reservation: reservation, budget: terminalBudget, receipts: receipts, clock: clock, ids: ids, limits: limits}, nil
}

// settleTerminalBudget performs the final usage reconciliation and budget
// settlement of a run this service just made terminal. It runs after the
// aggregate transition and before the receipt, so a crash in between is
// recovered by the idempotent replay of the same control command; a
// settlement failure is reported rather than swallowed, because a terminal run
// whose usage was never reconciled is a budget-correctness defect, not a
// cosmetic one.
//
// Discard is the one path that settles this way. It acts on a run waiting for
// a reviewer, so the executor's terminal step is an authority on the attempt
// being over. Cancellation is not: it can land while a billed operation is
// still running, so it fences first and concludes only behind an
// authoritative reconciliation.
func (s *Service) settleTerminalBudget(ctx context.Context, snapshot runs.Snapshot) error {
	if err := s.budget.SettleRunBudget(ctx, snapshot, true); err != nil {
		return fmt.Errorf("settle terminal run budget: %w", err)
	}
	return nil
}

func (s *Service) now() (time.Time, error) {
	now := s.clock.Now().UTC()
	if now.IsZero() {
		return time.Time{}, problem.New(problem.CodeAuthorityStale, "")
	}
	return now, nil
}

type OpenInput struct {
	Question, ResumeCheckpoint string
	ResponseSchema             json.RawMessage
	ExpiresAt                  time.Time
}

func (s *Service) RequestInput(ctx context.Context, write Write, command OpenInput) (InputRequest, OperationResult, error) {
	if strings.TrimSpace(command.Question) == "" || len(command.Question) > 4096 || len(command.ResponseSchema) == 0 || command.ExpiresAt.IsZero() || command.ResumeCheckpoint == "" || len(command.ResumeCheckpoint) > 256 {
		return InputRequest{}, OperationResult{}, stable(problem.CodeRequestInvalid, "input request is incomplete or unbounded")
	}
	id, err := s.ids.NewRequestID()
	if err != nil {
		return InputRequest{}, OperationResult{}, fmt.Errorf("allocate input request identity: %w", err)
	}
	now, err := s.now()
	if err != nil {
		return InputRequest{}, OperationResult{}, err
	}
	if !now.Before(command.ExpiresAt) {
		return InputRequest{}, OperationResult{}, stable(problem.CodeRequestInvalid, "input request expiry must be in the future")
	}
	request := InputRequest{ID: id, RunID: write.RunID, Question: command.Question, ResponseSchema: clone(command.ResponseSchema), ExpiresAt: command.ExpiresAt.UTC(), ResumeCheckpoint: command.ResumeCheckpoint, CreatedAt: now}
	digest, err := digestFor(write, command)
	if err != nil {
		return InputRequest{}, OperationResult{}, err
	}
	stored, result, err := s.repository.OpenInput(ctx, write, request, digest)
	if err != nil {
		return InputRequest{}, OperationResult{}, err
	}
	return stored, result, nil
}

func (s *Service) RespondInput(ctx context.Context, write Write, command InputResponseCommand) (OperationResult, error) {
	if command.RequestID == "" || command.RequestVersion == 0 || len(command.Value) == 0 {
		return OperationResult{}, stable(problem.CodeRequestInvalid, "input response is incomplete")
	}
	digest, err := digestFor(write, command)
	if err != nil {
		return OperationResult{}, stable(problem.CodeInputSchemaInvalid, "input response is not canonicalizable")
	}
	request, err := s.repository.Input(ctx, write.Scope, write.RunID, command.RequestID)
	if err != nil {
		return OperationResult{}, err
	}
	if err := s.authority.AuthorizeInput(ctx, write.Scope, request); err != nil {
		return OperationResult{}, err
	}
	if err := s.schema.Validate(ctx, request.ResponseSchema, command.Value); err != nil {
		return OperationResult{}, stable(problem.CodeInputSchemaInvalid, "input response violates the recorded response schema")
	}
	now, err := s.now()
	if err != nil {
		return OperationResult{}, err
	}
	result, err := s.repository.AcceptInput(ctx, write, command, digest, now)
	if err != nil {
		return OperationResult{}, err
	}
	if err := s.acknowledge(ctx, write, journal.FactInput, digest, command, result); err != nil {
		return OperationResult{}, err
	}
	payload, _ := json.Marshal(command)
	if err := s.runtime.Signal(ctx, executionWorkflowID(write.RunID, result.Snapshot.ExecutionGeneration), inputTopic(command.RequestID), payload, write.IdempotencyKey); err != nil {
		return OperationResult{}, fmt.Errorf("signal durable input wait after accepted fact: %w", err)
	}
	if err := s.runtime.ResumeRun(ctx, write.Scope, result.Snapshot, request.ResumeCheckpoint, "input:"+string(request.ID)); err != nil {
		return OperationResult{}, fmt.Errorf("resume input wait at recorded checkpoint: %w", err)
	}
	return result, nil
}

type OpenApproval struct {
	ActionDigest, ResumeCheckpoint        string
	Effects, ExpectedCost, ReviewerPolicy json.RawMessage
	ExpiresAt                             time.Time
}

func (s *Service) RequestApproval(ctx context.Context, write Write, command OpenApproval) (ApprovalRequest, OperationResult, error) {
	if !validDigest(command.ActionDigest) || len(command.Effects) == 0 || len(command.ExpectedCost) == 0 || len(command.ReviewerPolicy) == 0 || command.ExpiresAt.IsZero() || command.ResumeCheckpoint == "" {
		return ApprovalRequest{}, OperationResult{}, stable(problem.CodeRequestInvalid, "approval request evidence is incomplete")
	}
	if _, err := decodePolicyReference(command.ReviewerPolicy); err != nil {
		return ApprovalRequest{}, OperationResult{}, stable(problem.CodeRequestInvalid, "approval reviewer policy is invalid")
	}
	id, err := s.ids.NewRequestID()
	if err != nil {
		return ApprovalRequest{}, OperationResult{}, fmt.Errorf("allocate approval request identity: %w", err)
	}
	now, err := s.now()
	if err != nil {
		return ApprovalRequest{}, OperationResult{}, err
	}
	if !now.Before(command.ExpiresAt) {
		return ApprovalRequest{}, OperationResult{}, stable(problem.CodeRequestInvalid, "approval request expiry must be in the future")
	}
	request := ApprovalRequest{ID: id, RunID: write.RunID, ActionDigest: command.ActionDigest, Effects: clone(command.Effects), ExpectedCost: clone(command.ExpectedCost), ReviewerPolicy: clone(command.ReviewerPolicy), ExpiresAt: command.ExpiresAt.UTC(), ResumeCheckpoint: command.ResumeCheckpoint, CreatedAt: now}
	// The idempotency digest is the caller's deterministic operation digest —
	// like the input path — never a digest over the command itself: the
	// command carries the wall-clock expiry, and a durable replay in a
	// successor process must converge on the recorded request instead of
	// conflicting on a drifted timestamp.
	digest, err := digestFor(write, command)
	if err != nil {
		return ApprovalRequest{}, OperationResult{}, err
	}
	stored, result, err := s.repository.OpenApproval(ctx, write, request, digest)
	if err != nil {
		return ApprovalRequest{}, OperationResult{}, err
	}
	return stored, result, nil
}

func (s *Service) DecideApproval(ctx context.Context, write Write, command ApprovalDecisionCommand) (OperationResult, error) {
	if command.RequestID == "" || command.RequestVersion == 0 || (command.Decision != DecisionApprove && command.Decision != DecisionReject && command.Decision != DecisionChange) || !validDigest(command.ActionDigest) || len(command.Comment) > 2048 {
		return OperationResult{}, stable(problem.CodeRequestInvalid, "approval decision is invalid")
	}
	request, err := s.repository.Approval(ctx, write.Scope, write.RunID, command.RequestID)
	if err != nil {
		return OperationResult{}, err
	}
	// The reviewer states which action they decided. A decision whose action
	// digest is not the one the open request carries is refused rather than
	// recorded against a different action — the request may have been reopened
	// against new material since the reviewer read it.
	if command.ActionDigest != request.ActionDigest {
		return OperationResult{}, stable(problem.CodeApprovalRequestStale, "the decision names a different action than the open approval request")
	}
	if err := s.authority.AuthorizeReviewer(ctx, write.Scope, request, command.Decision); err != nil {
		return OperationResult{}, err
	}
	digest, err := digestFor(write, command)
	if err != nil {
		return OperationResult{}, err
	}
	now, err := s.now()
	if err != nil {
		return OperationResult{}, err
	}
	result, err := s.repository.DecideApproval(ctx, write, command, digest, now)
	if err != nil {
		return OperationResult{}, err
	}
	if err := s.acknowledge(ctx, write, journal.FactApproval, digest, command, result); err != nil {
		return OperationResult{}, err
	}
	payload, _ := json.Marshal(command)
	if err := s.runtime.Signal(ctx, executionWorkflowID(write.RunID, result.Snapshot.ExecutionGeneration), approvalTopic(command.RequestID), payload, write.IdempotencyKey); err != nil {
		return OperationResult{}, fmt.Errorf("signal durable approval wait after accepted fact: %w", err)
	}
	if command.Decision == DecisionReject || command.Decision == DecisionChange {
		if err := s.runtime.ResumeRun(ctx, write.Scope, result.Snapshot, request.ResumeCheckpoint, "approval:"+string(request.ID)); err != nil {
			return OperationResult{}, fmt.Errorf("resume approval wait at recorded checkpoint: %w", err)
		}
	}
	return result, nil
}

func (s *Service) Cancel(ctx context.Context, write Write) (OperationResult, error) {
	digest, _ := digestFor(write, struct{}{})
	now, err := s.now()
	if err != nil {
		return OperationResult{}, err
	}
	cancellation, result, err := s.repository.RequestCancellation(ctx, write, digest, now)
	if err != nil {
		return OperationResult{}, err
	}
	if err := s.runtime.StopRun(ctx, write.Scope, write.RunID, result.Snapshot.ExecutionGeneration); err != nil {
		return result, fmt.Errorf("stop run dispatch: %w", err)
	}
	if err := s.leases.RevokeRun(ctx, write.Scope, write.RunID); err != nil {
		return result, fmt.Errorf("revoke cancellation leases: %w", err)
	}
	// Budget dispatch authority is revoked in the same immediate breath as the
	// workflow and the leases. It has to be: a reservation the control plane
	// left current would still authorize an expensive dispatch after the run
	// was cancelled, and a replayed durable step or a restarted workflow is
	// exactly the thing that would use it. Fencing withdraws that authority
	// and nothing else — the hold keeps its worst-case bound and stays
	// unreleased, because the attempt this cancellation interrupted may still
	// be running and its cost is not yet known to anybody.
	if err := s.budget.FenceRunBudget(ctx, result.Snapshot); err != nil {
		return result, fmt.Errorf("revoke cancellation budget authority: %w", err)
	}
	descendants, err := s.repository.Descendants(ctx, write.Scope, write.RunID)
	if err != nil {
		return result, fmt.Errorf("load cancellation descendants: %w", err)
	}
	// Descendants already contains only children below the requested run; the
	// parent lookup proves the requested run is resolvable inside this
	// hierarchy before any descendant is stopped.
	if _, _, err := s.repository.Parent(ctx, write.Scope, write.RunID); err != nil {
		return result, err
	}
	for _, child := range descendants {
		childSnapshot, err := currentSnapshot(ctx, s.repository, Write{Scope: write.Scope, RunID: child.RunID})
		if err != nil {
			return result, fmt.Errorf("load descendant generation: %w", err)
		}
		if err := s.runtime.StopRun(ctx, write.Scope, child.RunID, childSnapshot.ExecutionGeneration); err != nil {
			return result, fmt.Errorf("stop descendant workflow: %w", err)
		}
		if err := s.leases.RevokeRun(ctx, write.Scope, child.RunID); err != nil {
			return result, fmt.Errorf("revoke descendant leases: %w", err)
		}
		if err := s.budget.FenceRunBudget(ctx, childSnapshot); err != nil {
			return result, fmt.Errorf("revoke descendant budget authority: %w", err)
		}
	}
	// Reconciliation and accounting cover the whole hierarchy, not just the
	// requested run. Cancelling a parent stops its children's workflows, so no
	// terminal step of theirs will ever settle what they spent — and a parent
	// projected as cancelled over a child that is still running would be a
	// terminal state asserted about work in flight.
	//
	// The accounting is concluded before the aggregate transition, not after,
	// so a failure leaves the run visibly cancelling, which is the state the
	// recovery sweep looks for. Settling after the transition would hide a
	// stranded hold behind a terminal run nothing comes back to.
	settled, err := concludeCancelledHierarchy(ctx, s.repository, s.reconciler, s.budget, write.Scope, write.RunID, result.Snapshot, descendants)
	if err != nil {
		return result, err
	}
	cancellation.DispatchStopped, cancellation.LeasesRevoked, cancellation.ChildrenPropagated = true, true, true
	cancellation.Reconciled, cancellation.ExternalUncertain = settled, !settled
	if err := s.repository.RecordCancellation(ctx, write, cancellation); err != nil {
		return result, fmt.Errorf("record cancellation progress: %w", err)
	}
	if !settled {
		// Commit-phase cancellation, an authoritative outcome the domain owner
		// already settled, and an unresolved effect anywhere in the hierarchy
		// all stay visible; none may be projected as cancelled by this service.
		// The recovery sweep comes back to them.
		if err := s.acknowledge(ctx, write, journal.FactCancel, digest, struct{}{}, result); err != nil {
			return OperationResult{}, err
		}
		return result, nil
	}
	final, err := s.repository.FinishCancellation(ctx, Write{Scope: write.Scope, RunID: write.RunID, ExpectedVersion: result.Snapshot.Version, IdempotencyKey: write.IdempotencyKey + ":reconciled", Traceparent: write.Traceparent}, cancellation)
	if err != nil {
		return OperationResult{}, err
	}
	if err := s.acknowledge(ctx, write, journal.FactCancel, digest, struct{}{}, final); err != nil {
		return OperationResult{}, err
	}
	return final, nil
}

func (s *Service) Retry(ctx context.Context, write Write) (RetryOutcome, error) {
	digest, _ := digestFor(write, struct{}{})
	if outcome, ok, err := s.repository.RecordedRetry(ctx, write, digest); err != nil || ok {
		if err != nil {
			return RetryOutcome{}, err
		}
		// Replaying a recorded retry still starts a workflow. Authority
		// revoked between the recording and this replay must stop the resume,
		// so the complete material set is revalidated before the runtime is
		// asked to run anything.
		if err := s.authority.AuthorizeResume(ctx, write.Scope, outcome.Snapshot); err != nil {
			return RetryOutcome{}, err
		}
		if err := s.runtime.ResumeRun(ctx, write.Scope, outcome.Snapshot, outcome.ResumeCheckpoint, ""); err != nil {
			return RetryOutcome{}, fmt.Errorf("resume durable retry workflow: %w", err)
		}
		if err := s.acknowledge(ctx, write, journal.FactRetry, digest, struct{}{}, outcome); err != nil {
			return RetryOutcome{}, err
		}
		return outcome, nil
	}
	snapshot, err := currentSnapshot(ctx, s.repository, write)
	if err != nil {
		return RetryOutcome{}, err
	}
	eligible, checkpoint, err := s.authority.RetryEligibility(ctx, write.Scope, snapshot)
	if err != nil {
		return RetryOutcome{}, err
	}
	if !eligible {
		if snapshot.Problem != nil {
			return RetryOutcome{}, *snapshot.Problem
		}
		return RetryOutcome{}, stable(problem.CodeRetryIneligible, "current failure is not eligible for retry")
	}
	outcome, err := s.repository.Retry(ctx, write, digest, checkpoint)
	if err != nil {
		return RetryOutcome{}, err
	}
	if err := s.runtime.ResumeRun(ctx, write.Scope, outcome.Snapshot, outcome.ResumeCheckpoint, ""); err != nil {
		return RetryOutcome{}, fmt.Errorf("resume durable retry workflow: %w", err)
	}
	if err := s.acknowledge(ctx, write, journal.FactRetry, digest, struct{}{}, outcome); err != nil {
		return RetryOutcome{}, err
	}
	return outcome, nil
}

func (s *Service) Discard(ctx context.Context, write Write) (OperationResult, error) {
	digest, _ := digestFor(write, struct{}{})
	result, err := s.repository.Discard(ctx, write, digest)
	if err != nil {
		return OperationResult{}, err
	}
	// Discard is terminal in the same sense cancellation is, and settles the
	// same way: the attempt's observed usage is reconciled and the remaining
	// worst-case hold is released back to root headroom.
	if err := s.settleTerminalBudget(ctx, result.Snapshot); err != nil {
		return OperationResult{}, err
	}
	if err := s.acknowledge(ctx, write, journal.FactDiscard, digest, struct{}{}, result); err != nil {
		return OperationResult{}, err
	}
	return result, nil
}

type CreateChild struct {
	Mode             ChildMode
	PredecessorRunID *runs.ID
}

func (s *Service) CreateChild(ctx context.Context, write Write, command CreateChild) (Child, error) {
	if command.Mode != ChildRequired && command.Mode != ChildOptional && command.Mode != ChildFallback {
		return Child{}, stable(problem.CodeRequestInvalid, "child mode is invalid")
	}
	parentSnapshot, err := currentSnapshot(ctx, s.repository, write)
	if err != nil {
		return Child{}, err
	}
	descendants, err := s.repository.Descendants(ctx, write.Scope, parentSnapshot.RootRunID)
	if err != nil {
		return Child{}, err
	}
	parentDepth, direct := 0, 0
	if parentLink, isChild, err := s.repository.Parent(ctx, write.Scope, write.RunID); err != nil {
		return Child{}, err
	} else if isChild {
		parentDepth = parentLink.Depth
	}
	for _, child := range descendants {
		if child.ParentRunID == write.RunID {
			direct++
		}
	}
	if parentDepth+1 > s.limits.ChildDepth || direct >= s.limits.ChildFanout {
		return Child{}, stable(problem.CodeChildLimitExceeded, "child depth or fan-out bound is exceeded")
	}
	childID, err := s.ids.NewRunID()
	if err != nil {
		return Child{}, err
	}
	if command.Mode == ChildFallback {
		if command.PredecessorRunID == nil {
			return Child{}, stable(problem.CodeChildPredecessorIneligible, "fallback child requires a predecessor")
		}
		outcome, err := s.repository.ChildOutcome(ctx, write.Scope, *command.PredecessorRunID)
		if err != nil || (outcome.State != runs.Failed && outcome.State != runs.Refused) {
			return Child{}, stable(problem.CodeChildPredecessorIneligible, "fallback predecessor has not reached an eligible failure")
		}
	}
	digest, err := digestFor(write, command)
	if err != nil {
		return Child{}, err
	}
	now, err := s.now()
	if err != nil {
		return Child{}, err
	}
	if err := s.reservation.ReserveChild(ctx, ChildBudgetRequest{Write: write, ChildRunID: childID, Mode: command.Mode, Digest: digest, RequestedAt: now}); err != nil {
		return Child{}, fmt.Errorf("reserve root budget before child dispatch: %w", err)
	}
	child := Child{RunID: childID, ParentRunID: write.RunID, WorkspaceID: write.Scope.WorkspaceID, ProjectID: write.Scope.ProjectID, ActorID: write.Scope.ActorID, Mode: command.Mode, PredecessorRunID: command.PredecessorRunID, Depth: parentDepth + 1, CreatedAt: now}
	created, err := s.repository.CreateChild(ctx, write, child, digest)
	if err != nil {
		return Child{}, err
	}
	if err := s.runtime.StartChild(ctx, created); err != nil {
		return Child{}, fmt.Errorf("start durable child workflow: %w", err)
	}
	return created, nil
}

func digestValue(value any) (string, error) {
	raw, err := json.Marshal(value)
	if err != nil {
		return "", fmt.Errorf("marshal control command: %w", err)
	}
	return canonical.Digest(raw)
}
func digestFor(write Write, value any) (string, error) {
	if write.CanonicalDigest != "" {
		return write.CanonicalDigest, nil
	}
	return digestValue(value)
}

func clone(value json.RawMessage) json.RawMessage { return append(json.RawMessage(nil), value...) }
func executionWorkflowID(id runs.ID, generation uint64) string {
	return fmt.Sprintf("%s:g%d", id, generation)
}
func inputTopic(id RequestID) string    { return "input:" + string(id) }
func approvalTopic(id RequestID) string { return "approval:" + string(id) }
func validDigest(value string) bool {
	if !strings.HasPrefix(value, "sha256:") || len(value) != 71 {
		return false
	}
	for _, character := range value[7:] {
		if !strings.ContainsRune("0123456789abcdef", character) {
			return false
		}
	}
	return true
}

func (s *Service) acknowledge(ctx context.Context, write Write, class journal.FactClass, digest string, command, projection any) error {
	raw, err := json.Marshal(struct {
		Scope           runs.Scope `json:"scope"`
		RunID           runs.ID    `json:"runId"`
		ExpectedVersion uint64     `json:"expectedVersion"`
		CanonicalDigest string     `json:"canonicalDigest"`
		Command         any        `json:"command"`
	}{write.Scope, write.RunID, write.ExpectedVersion, digest, command})
	if err != nil {
		return fmt.Errorf("marshal acknowledged control fact: %w", err)
	}
	canonicalBytes, err := canonical.Bytes(raw)
	if err != nil {
		return fmt.Errorf("canonicalize acknowledged control fact: %w", err)
	}
	projectionBytes, err := json.Marshal(projection)
	if err != nil {
		return fmt.Errorf("marshal acknowledged control projection: %w", err)
	}
	fact, err := journal.NewFact(write.Scope.WorkspaceID+":"+string(write.RunID)+":"+string(class)+":"+write.IdempotencyKey, write.Scope.WorkspaceID, write.Scope.ProjectID, class, canonicalBytes, projectionBytes)
	if err != nil {
		return err
	}
	// Bind the canonical digest selected by the command path as additional
	// evidence without trusting a caller-supplied value.
	if digest == "" {
		return fmt.Errorf("acknowledged control digest is required")
	}
	if _, err := s.receipts.Append(ctx, fact); err != nil {
		return fmt.Errorf("authority fact remains unacknowledged: %w", err)
	}
	return nil
}

// currentReader is optional so repositories can expose current state without
// expanding the mutation-only authority interface.
type currentReader interface {
	Current(context.Context, runs.Scope, runs.ID) (runs.Snapshot, error)
}

func currentSnapshot(ctx context.Context, repository Repository, write Write) (runs.Snapshot, error) {
	reader, ok := repository.(currentReader)
	if !ok {
		return runs.Snapshot{}, fmt.Errorf("retry repository cannot read current authority")
	}
	return reader.Current(ctx, write.Scope, write.RunID)
}
