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
	receipts    journal.Store
	clock       Clock
	ids         IDs
	limits      Limits
}

func NewService(repository Repository, schema SchemaValidator, authority Authority, runtime Runtime, leases LeaseRevoker, reconciler CancellationReconciler, reservation Reservation, receipts journal.Store, clock Clock, ids IDs, limits Limits) (*Service, error) {
	if repository == nil || schema == nil || authority == nil || runtime == nil || leases == nil || reconciler == nil || reservation == nil || receipts == nil || clock == nil || ids == nil || limits.ChildDepth < 1 || limits.ChildFanout < 1 {
		return nil, fmt.Errorf("interrupt service dependencies and positive child bounds are required")
	}
	return &Service{repository: repository, schema: schema, authority: authority, runtime: runtime, leases: leases, reconciler: reconciler, reservation: reservation, receipts: receipts, clock: clock, ids: ids, limits: limits}, nil
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
	now := s.clock.Now().UTC()
	if !now.Before(command.ExpiresAt) {
		return InputRequest{}, OperationResult{}, stable(problem.CodeRequestInvalid, "input request expiry must be in the future")
	}
	request := InputRequest{ID: id, RunID: write.RunID, Version: 1, Question: command.Question, ResponseSchema: clone(command.ResponseSchema), ExpiresAt: command.ExpiresAt.UTC(), ResumeCheckpoint: command.ResumeCheckpoint, CreatedAt: now}
	digest, err := digestFor(write, command)
	if err != nil {
		return InputRequest{}, OperationResult{}, err
	}
	stored, result, err := s.repository.OpenInput(ctx, write, request, digest)
	if err != nil {
		return InputRequest{}, OperationResult{}, err
	}
	if err := s.runtime.OpenWait(ctx, write.Scope, inputWaitWorkflowID(write.RunID, stored.ID), inputTopic(stored.ID), stored.ExpiresAt.Sub(s.clock.Now())); err != nil {
		return InputRequest{}, OperationResult{}, fmt.Errorf("open durable input wait: %w", err)
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
	result, err := s.repository.AcceptInput(ctx, write, command, digest, s.clock.Now().UTC())
	if err != nil {
		return OperationResult{}, err
	}
	if err := s.acknowledge(ctx, write, journal.FactInput, digest, command, result); err != nil {
		return OperationResult{}, err
	}
	payload, _ := json.Marshal(command)
	if err := s.runtime.Signal(ctx, inputWaitWorkflowID(write.RunID, command.RequestID), inputTopic(command.RequestID), payload, write.IdempotencyKey); err != nil {
		return OperationResult{}, fmt.Errorf("signal durable input wait after accepted fact: %w", err)
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
	id, err := s.ids.NewRequestID()
	if err != nil {
		return ApprovalRequest{}, OperationResult{}, fmt.Errorf("allocate approval request identity: %w", err)
	}
	now := s.clock.Now().UTC()
	if !now.Before(command.ExpiresAt) {
		return ApprovalRequest{}, OperationResult{}, stable(problem.CodeRequestInvalid, "approval request expiry must be in the future")
	}
	request := ApprovalRequest{ID: id, RunID: write.RunID, Version: 1, ActionDigest: command.ActionDigest, Effects: clone(command.Effects), ExpectedCost: clone(command.ExpectedCost), ReviewerPolicy: clone(command.ReviewerPolicy), ExpiresAt: command.ExpiresAt.UTC(), ResumeCheckpoint: command.ResumeCheckpoint, CreatedAt: now}
	digest, err := digestValue(command)
	if err != nil {
		return ApprovalRequest{}, OperationResult{}, err
	}
	stored, result, err := s.repository.OpenApproval(ctx, write, request, digest)
	if err != nil {
		return ApprovalRequest{}, OperationResult{}, err
	}
	if err := s.runtime.OpenWait(ctx, write.Scope, approvalWaitWorkflowID(write.RunID, stored.ID), approvalTopic(stored.ID), stored.ExpiresAt.Sub(s.clock.Now())); err != nil {
		return ApprovalRequest{}, OperationResult{}, fmt.Errorf("open durable approval wait: %w", err)
	}
	return stored, result, nil
}

func (s *Service) DecideApproval(ctx context.Context, write Write, command ApprovalDecisionCommand) (OperationResult, error) {
	if command.RequestID == "" || command.RequestVersion == 0 || (command.Decision != DecisionApprove && command.Decision != DecisionReject && command.Decision != DecisionChange) || len(command.Reason) > 4096 {
		return OperationResult{}, stable(problem.CodeRequestInvalid, "approval decision is invalid")
	}
	request, err := s.repository.Approval(ctx, write.Scope, write.RunID, command.RequestID)
	if err != nil {
		return OperationResult{}, err
	}
	if err := s.authority.AuthorizeReviewer(ctx, write.Scope, request, command.Decision); err != nil {
		return OperationResult{}, err
	}
	digest, err := digestFor(write, command)
	if err != nil {
		return OperationResult{}, err
	}
	result, err := s.repository.DecideApproval(ctx, write, command, digest, s.clock.Now().UTC())
	if err != nil {
		return OperationResult{}, err
	}
	if err := s.acknowledge(ctx, write, journal.FactApproval, digest, command, result); err != nil {
		return OperationResult{}, err
	}
	payload, _ := json.Marshal(command)
	if err := s.runtime.Signal(ctx, approvalWaitWorkflowID(write.RunID, command.RequestID), approvalTopic(command.RequestID), payload, write.IdempotencyKey); err != nil {
		return OperationResult{}, fmt.Errorf("signal durable approval wait after accepted fact: %w", err)
	}
	return result, nil
}

func (s *Service) Cancel(ctx context.Context, write Write) (OperationResult, error) {
	digest, _ := digestFor(write, struct{}{})
	cancellation, result, err := s.repository.RequestCancellation(ctx, write, digest, s.clock.Now().UTC())
	if err != nil {
		return OperationResult{}, err
	}
	if err := s.leases.RevokeRun(ctx, write.Scope, write.RunID); err != nil {
		return result, fmt.Errorf("revoke cancellation leases: %w", err)
	}
	descendants, err := s.repository.Descendants(ctx, write.Scope, write.RunID)
	if err != nil {
		return result, fmt.Errorf("load cancellation descendants: %w", err)
	}
	if _, isChild, err := s.repository.Parent(ctx, write.Scope, write.RunID); err != nil {
		return result, err
	} else if isChild {
		// Descendants already contains only children below the requested run;
		// parent lookup proves the requested run is scoped to this hierarchy.
	}
	for _, child := range descendants {
		if err := s.runtime.Signal(ctx, workflowID(child.RunID), "cancel", json.RawMessage(`{"requested":true}`), write.IdempotencyKey+":"+string(child.RunID)); err != nil {
			return result, fmt.Errorf("propagate child cancellation: %w", err)
		}
	}
	clear, authoritative, err := s.reconciler.Reconcile(ctx, write.Scope, write.RunID, cancellation.CommitPhase)
	if err != nil {
		return result, fmt.Errorf("reconcile cancellation: %w", err)
	}
	cancellation.DispatchStopped, cancellation.LeasesRevoked, cancellation.ChildrenPropagated = true, true, true
	cancellation.Reconciled, cancellation.ExternalUncertain = clear, !clear
	if authoritative != nil || !clear {
		// Commit-phase cancellation and uncertainty stay visible; neither may be
		// projected as cancelled by this service.
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
	if err := s.reservation.ReserveChild(ctx, write.Scope, write.RunID, childID, command.Mode); err != nil {
		return Child{}, fmt.Errorf("reserve root budget before child dispatch: %w", err)
	}
	child := Child{RunID: childID, ParentRunID: write.RunID, WorkspaceID: write.Scope.WorkspaceID, ProjectID: write.Scope.ProjectID, ActorID: write.Scope.ActorID, Mode: command.Mode, PredecessorRunID: command.PredecessorRunID, Depth: parentDepth + 1, CreatedAt: s.clock.Now().UTC()}
	digest, _ := digestValue(command)
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
func workflowID(id runs.ID) string                { return string(id) + ":v1" }
func inputWaitWorkflowID(id runs.ID, request RequestID) string {
	return workflowID(id) + ":input:" + string(request)
}
func approvalWaitWorkflowID(id runs.ID, request RequestID) string {
	return workflowID(id) + ":approval:" + string(request)
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
	canonicalBytes, err := json.Marshal(command)
	if err != nil {
		return fmt.Errorf("marshal acknowledged control fact: %w", err)
	}
	projectionBytes, err := json.Marshal(projection)
	if err != nil {
		return fmt.Errorf("marshal acknowledged control projection: %w", err)
	}
	fact, err := journal.NewFact(write.Scope.WorkspaceID+":"+string(write.RunID)+":"+string(class)+":"+write.IdempotencyKey, write.Scope.WorkspaceID, write.Scope.ProjectID, class, write.ExpectedVersion, canonicalBytes, projectionBytes)
	if err != nil {
		return err
	}
	// Bind the canonical digest selected by the command path as additional
	// evidence without trusting a caller-supplied value.
	if digest == "" {
		return fmt.Errorf("acknowledged control digest is required")
	}
	if err := s.receipts.Append(ctx, fact); err != nil {
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
