package interrupts

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/ancyloce/anvilkit-agent-service/internal/problem"
	"github.com/ancyloce/anvilkit-agent-service/internal/runs"
)

type memoryRun struct {
	scope        runs.Scope
	snapshot     runs.Snapshot
	inputs       map[RequestID]InputRequest
	approvals    map[RequestID]ApprovalRequest
	cancellation *Cancellation
	progress     Progress
	retained     []string
}

type memoryReplay struct {
	digest  string
	version uint64
	value   any
}

// MemoryRepository is a deterministic authority implementation for aggregate,
// restart, concurrency, and failure-injection proofs. Production uses the
// Postgres adapter behind the same Repository port.
type MemoryRepository struct {
	lock     sync.Mutex
	runs     map[runs.ID]*memoryRun
	replays  map[string]memoryReplay
	children map[runs.ID]Child
	outcomes map[runs.ID]ChildOutcome
}

func NewMemoryRepository() *MemoryRepository {
	return &MemoryRepository{runs: make(map[runs.ID]*memoryRun), replays: make(map[string]memoryReplay), children: make(map[runs.ID]Child), outcomes: make(map[runs.ID]ChildOutcome)}
}

func (r *MemoryRepository) Seed(scope runs.Scope, snapshot runs.Snapshot) error {
	if err := scope.Validate(); err != nil || snapshot.RunID == "" || snapshot.Version == 0 {
		return fmt.Errorf("seed run requires scope and versioned snapshot")
	}
	r.lock.Lock()
	defer r.lock.Unlock()
	now := snapshot.UpdatedAt
	r.runs[snapshot.RunID] = &memoryRun{scope: scope, snapshot: cloneSnapshot(snapshot), inputs: make(map[RequestID]InputRequest), approvals: make(map[RequestID]ApprovalRequest), progress: Progress{Scope: scope, RunID: snapshot.RunID, State: snapshot.Status, EnteredAt: now, ProgressAt: now}, retained: []string{"events", "artifacts", "usage"}}
	return nil
}

// Get satisfies the execution pipeline's run-store read port with the same
// scope enforcement the production store applies.
func (r *MemoryRepository) Get(ctx context.Context, scope runs.Scope, id runs.ID) (runs.Snapshot, error) {
	return r.Current(ctx, scope, id)
}

// Transition satisfies the execution pipeline's compare-and-set port with
// exactly the aggregate legality the production store enforces. The fake is
// never looser than the contract it imitates.
func (r *MemoryRepository) Transition(_ context.Context, scope runs.Scope, id runs.ID, expectedVersion uint64, command runs.Command) (runs.Snapshot, error) {
	r.lock.Lock()
	defer r.lock.Unlock()
	entry, err := r.scoped(scope, id)
	if err != nil {
		return runs.Snapshot{}, err
	}
	if entry.snapshot.Version != expectedVersion {
		return runs.Snapshot{}, problem.New(problem.CodeVersionConflict, "")
	}
	snapshot, err := transition(entry.snapshot, command)
	if err != nil {
		return runs.Snapshot{}, err
	}
	r.advance(entry, snapshot, snapshot.UpdatedAt)
	return cloneSnapshot(entry.snapshot), nil
}

func (r *MemoryRepository) Current(_ context.Context, scope runs.Scope, id runs.ID) (runs.Snapshot, error) {
	r.lock.Lock()
	defer r.lock.Unlock()
	entry, err := r.scoped(scope, id)
	if err != nil {
		return runs.Snapshot{}, err
	}
	return cloneSnapshot(entry.snapshot), nil
}

func (r *MemoryRepository) Input(_ context.Context, scope runs.Scope, runID runs.ID, id RequestID) (InputRequest, error) {
	r.lock.Lock()
	defer r.lock.Unlock()
	entry, err := r.scoped(scope, runID)
	if err != nil {
		return InputRequest{}, err
	}
	request, ok := entry.inputs[id]
	if !ok {
		return InputRequest{}, problem.New(problem.CodeResourceNotFound, "")
	}
	return cloneInput(request), nil
}

func (r *MemoryRepository) OpenInput(_ context.Context, write Write, request InputRequest, digest string) (InputRequest, OperationResult, error) {
	r.lock.Lock()
	defer r.lock.Unlock()
	entry, replay, err := r.prepare(write, "request-input", digest)
	if err != nil {
		return InputRequest{}, OperationResult{}, err
	}
	if replay != nil {
		value := replay.value.(struct {
			Request InputRequest
			Result  OperationResult
		})
		value.Result.Replayed = true
		return cloneInput(value.Request), value.Result, nil
	}
	snapshot, err := transition(entry.snapshot, runs.Command{Kind: runs.RequestInput, Traceparent: write.Traceparent})
	if err != nil {
		return InputRequest{}, OperationResult{}, err
	}
	request.Version = 0
	for _, prior := range entry.inputs {
		if prior.Version >= request.Version {
			request.Version = prior.Version + 1
		}
	}
	if request.Version == 0 {
		request.Version = 1
	}
	entry.inputs[request.ID] = cloneInput(request)
	r.advance(entry, snapshot, request.CreatedAt)
	result := OperationResult{Snapshot: cloneSnapshot(snapshot)}
	r.record(write, "request-input", digest, struct {
		Request InputRequest
		Result  OperationResult
	}{cloneInput(request), result})
	return cloneInput(request), result, nil
}

func (r *MemoryRepository) AcceptInput(_ context.Context, write Write, command InputResponseCommand, digest string, now time.Time) (OperationResult, error) {
	r.lock.Lock()
	defer r.lock.Unlock()
	entry, err := r.scoped(write.Scope, write.RunID)
	if err != nil {
		return OperationResult{}, err
	}
	if replay, ok := r.replays[replayKey(write, "respond-input")]; ok {
		if conflict := ReplayConflict(replay.digest, digest, replay.version, write.ExpectedVersion); conflict != nil {
			return OperationResult{}, conflict
		}
		result := replay.value.(OperationResult)
		result.Replayed = true
		return result, nil
	}
	request, ok := entry.inputs[command.RequestID]
	if !ok || request.Version != command.RequestVersion {
		return OperationResult{}, stable(problem.CodeInputRequestStale, "input request version is not current")
	}
	if request.Response != nil {
		return OperationResult{}, stable(problem.CodeInputAlreadyResponded, "input request already has an immutable response")
	}
	if request.ExpiredAt != nil {
		return OperationResult{}, stable(problem.CodeInputRequestExpired, "the input request is durably expired and cannot be revived")
	}
	if entry.snapshot.Version != write.ExpectedVersion {
		return OperationResult{}, problem.New(problem.CodeVersionConflict, "")
	}
	if !now.Before(request.ExpiresAt) {
		return OperationResult{}, stable(problem.CodeInputRequestExpired, "the input deadline elapsed before the response was accepted")
	}
	snapshot, err := transition(entry.snapshot, runs.Command{Kind: runs.AcceptInput, Traceparent: write.Traceparent})
	if err != nil {
		return OperationResult{}, err
	}
	request.Response = &InputResponse{RequestVersion: command.RequestVersion, Value: clone(command.Value), ActorID: write.Scope.ActorID, AcceptedAt: now}
	entry.inputs[command.RequestID] = request
	r.advance(entry, snapshot, now)
	result := OperationResult{Snapshot: cloneSnapshot(snapshot)}
	r.record(write, "respond-input", digest, result)
	return result, nil
}

// ExpireInput settles the input deadline atomically. Acceptance and expiry
// contend for the same lock, so exactly one of them wins and the run can
// never be left expired-and-answered or answered-and-abandoned.
func (r *MemoryRepository) ExpireInput(_ context.Context, write Write, id RequestID, failure problem.Details, now time.Time) (Expiry, error) {
	r.lock.Lock()
	defer r.lock.Unlock()
	entry, err := r.scoped(write.Scope, write.RunID)
	if err != nil {
		return Expiry{}, err
	}
	request, ok := entry.inputs[id]
	if !ok {
		return Expiry{}, problem.New(problem.CodeResourceNotFound, "")
	}
	if request.Response != nil {
		return Expiry{Raced: true, Snapshot: cloneSnapshot(entry.snapshot)}, nil
	}
	if request.ExpiredAt != nil {
		// Recovery re-executed the already-committed expiry.
		return Expiry{Snapshot: cloneSnapshot(entry.snapshot)}, nil
	}
	if entry.snapshot.Version != write.ExpectedVersion {
		return Expiry{Superseded: true, Snapshot: cloneSnapshot(entry.snapshot)}, nil
	}
	snapshot, err := transition(entry.snapshot, runs.Command{Kind: runs.RecordFailure, Failure: &failure, Traceparent: write.Traceparent})
	if err != nil {
		return Expiry{Superseded: true, Snapshot: cloneSnapshot(entry.snapshot)}, nil
	}
	expired := now
	request.ExpiredAt = &expired
	entry.inputs[id] = request
	r.advance(entry, snapshot, now)
	return Expiry{Snapshot: cloneSnapshot(entry.snapshot)}, nil
}

func (r *MemoryRepository) Approval(_ context.Context, scope runs.Scope, runID runs.ID, id RequestID) (ApprovalRequest, error) {
	r.lock.Lock()
	defer r.lock.Unlock()
	entry, err := r.scoped(scope, runID)
	if err != nil {
		return ApprovalRequest{}, err
	}
	request, ok := entry.approvals[id]
	if !ok {
		return ApprovalRequest{}, problem.New(problem.CodeResourceNotFound, "")
	}
	return cloneApproval(request), nil
}

func (r *MemoryRepository) OpenApproval(_ context.Context, write Write, request ApprovalRequest, digest string) (ApprovalRequest, OperationResult, error) {
	r.lock.Lock()
	defer r.lock.Unlock()
	entry, replay, err := r.prepare(write, "request-approval", digest)
	if err != nil {
		return ApprovalRequest{}, OperationResult{}, err
	}
	if replay != nil {
		value := replay.value.(struct {
			Request ApprovalRequest
			Result  OperationResult
		})
		value.Result.Replayed = true
		return cloneApproval(value.Request), value.Result, nil
	}
	snapshot, err := transition(entry.snapshot, runs.Command{Kind: runs.RequestApproval, Traceparent: write.Traceparent})
	if err != nil {
		return ApprovalRequest{}, OperationResult{}, err
	}
	request.Version = 0
	for _, prior := range entry.approvals {
		if prior.Version >= request.Version {
			request.Version = prior.Version + 1
		}
	}
	if request.Version == 0 {
		request.Version = 1
	}
	entry.approvals[request.ID] = cloneApproval(request)
	r.advance(entry, snapshot, request.CreatedAt)
	result := OperationResult{Snapshot: cloneSnapshot(snapshot)}
	r.record(write, "request-approval", digest, struct {
		Request ApprovalRequest
		Result  OperationResult
	}{cloneApproval(request), result})
	return cloneApproval(request), result, nil
}

func (r *MemoryRepository) DecideApproval(_ context.Context, write Write, command ApprovalDecisionCommand, digest string, now time.Time) (OperationResult, error) {
	r.lock.Lock()
	defer r.lock.Unlock()
	entry, err := r.scoped(write.Scope, write.RunID)
	if err != nil {
		return OperationResult{}, err
	}
	if replay, ok := r.replays[replayKey(write, "decide-approval")]; ok {
		if conflict := ReplayConflict(replay.digest, digest, replay.version, write.ExpectedVersion); conflict != nil {
			return OperationResult{}, conflict
		}
		result := replay.value.(OperationResult)
		result.Replayed = true
		return result, nil
	}
	request, ok := entry.approvals[command.RequestID]
	if !ok || request.Version != command.RequestVersion {
		return OperationResult{}, stable(problem.CodeApprovalRequestStale, "approval decision version is not current")
	}
	if request.Decision != nil {
		return OperationResult{}, stable(problem.CodeApprovalAlreadyDecided, "approval decision is immutable")
	}
	if request.ExpiredAt != nil {
		return OperationResult{}, stable(problem.CodeApprovalRequestExpired, "the approval request is durably expired and cannot be revived")
	}
	if entry.snapshot.Version != write.ExpectedVersion {
		return OperationResult{}, problem.New(problem.CodeVersionConflict, "")
	}
	if !now.Before(request.ExpiresAt) {
		return OperationResult{}, stable(problem.CodeApprovalRequestExpired, "the approval deadline elapsed before the decision was accepted")
	}
	request.Decision = &Decision{RequestVersion: command.RequestVersion, Kind: command.Decision, ReviewerID: write.Scope.ActorID, Comment: command.Comment, AcceptedAt: now}
	entry.approvals[command.RequestID] = request
	snapshot := entry.snapshot
	if command.Decision == DecisionReject || command.Decision == DecisionChange {
		snapshot, err = transition(entry.snapshot, runs.Command{Kind: runs.RejectApproval, Traceparent: write.Traceparent})
		if err != nil {
			return OperationResult{}, err
		}
		r.advance(entry, snapshot, now)
	} else {
		// Approval is immutable evidence only. Commit's authorization gateway must
		// supply CommitProof before the aggregate can enter committing.
		entry.progress.ProgressAt = now
	}
	result := OperationResult{Snapshot: cloneSnapshot(snapshot)}
	r.record(write, "decide-approval", digest, result)
	return result, nil
}

// ExpireApproval is the approval counterpart of ExpireInput.
func (r *MemoryRepository) ExpireApproval(_ context.Context, write Write, id RequestID, failure problem.Details, now time.Time) (Expiry, error) {
	r.lock.Lock()
	defer r.lock.Unlock()
	entry, err := r.scoped(write.Scope, write.RunID)
	if err != nil {
		return Expiry{}, err
	}
	request, ok := entry.approvals[id]
	if !ok {
		return Expiry{}, problem.New(problem.CodeResourceNotFound, "")
	}
	if request.Decision != nil {
		return Expiry{Raced: true, Snapshot: cloneSnapshot(entry.snapshot)}, nil
	}
	if request.ExpiredAt != nil {
		return Expiry{Snapshot: cloneSnapshot(entry.snapshot)}, nil
	}
	if entry.snapshot.Version != write.ExpectedVersion {
		return Expiry{Superseded: true, Snapshot: cloneSnapshot(entry.snapshot)}, nil
	}
	snapshot, err := transition(entry.snapshot, runs.Command{Kind: runs.RecordFailure, Failure: &failure, Traceparent: write.Traceparent})
	if err != nil {
		return Expiry{Superseded: true, Snapshot: cloneSnapshot(entry.snapshot)}, nil
	}
	expired := now
	request.ExpiredAt = &expired
	entry.approvals[id] = request
	r.advance(entry, snapshot, now)
	return Expiry{Snapshot: cloneSnapshot(entry.snapshot)}, nil
}

func (r *MemoryRepository) RequestCancellation(_ context.Context, write Write, digest string, now time.Time) (Cancellation, OperationResult, error) {
	r.lock.Lock()
	defer r.lock.Unlock()
	entry, replay, err := r.prepare(write, "cancel", digest)
	if err != nil {
		return Cancellation{}, OperationResult{}, err
	}
	if replay != nil {
		value := replay.value.(struct {
			Cancellation Cancellation
			Result       OperationResult
		})
		value.Result.Replayed = true
		return value.Cancellation, value.Result, nil
	}
	commitPhase := entry.snapshot.Status == runs.Committing || entry.snapshot.Status == runs.AwaitingDomainConfirmation
	snapshot := entry.snapshot
	if !commitPhase {
		snapshot, err = transition(entry.snapshot, runs.Command{Kind: runs.RequestCancellation, Traceparent: write.Traceparent})
		if err != nil {
			return Cancellation{}, OperationResult{}, err
		}
		r.advance(entry, snapshot, now)
	}
	cancellation := Cancellation{RequestedAt: now, RequestedBy: write.Scope.ActorID, CommitPhase: commitPhase}
	entry.cancellation = &cancellation
	result := OperationResult{Snapshot: cloneSnapshot(snapshot)}
	r.record(write, "cancel", digest, struct {
		Cancellation Cancellation
		Result       OperationResult
	}{cancellation, result})
	return cancellation, result, nil
}

func (r *MemoryRepository) RecordCancellation(_ context.Context, write Write, cancellation Cancellation) error {
	r.lock.Lock()
	defer r.lock.Unlock()
	entry, err := r.scoped(write.Scope, write.RunID)
	if err != nil {
		return err
	}
	if entry.cancellation == nil || !entry.cancellation.RequestedAt.Equal(cancellation.RequestedAt) {
		return problem.New(problem.CodeVersionConflict, "")
	}
	copyValue := cancellation
	entry.cancellation = &copyValue
	return nil
}

func (r *MemoryRepository) FinishCancellation(_ context.Context, write Write, cancellation Cancellation) (OperationResult, error) {
	r.lock.Lock()
	defer r.lock.Unlock()
	entry, replay, err := r.prepare(write, "cancel-reconciled", "sha256:reconciled")
	if err != nil {
		return OperationResult{}, err
	}
	if replay != nil {
		result := replay.value.(OperationResult)
		result.Replayed = true
		return result, nil
	}
	if cancellation.CommitPhase || cancellation.ExternalUncertain || !cancellation.Reconciled {
		return OperationResult{}, stable(problem.CodeCancellationUnreconciled, "cancellation cannot terminate before reconciliation")
	}
	snapshot, err := transition(entry.snapshot, runs.Command{Kind: runs.ReconcileCancellation, Traceparent: write.Traceparent})
	if err != nil {
		return OperationResult{}, err
	}
	r.advance(entry, snapshot, cancellation.RequestedAt)
	copyValue := cancellation
	entry.cancellation = &copyValue
	result := OperationResult{Snapshot: cloneSnapshot(snapshot)}
	r.record(write, "cancel-reconciled", "sha256:reconciled", result)
	return result, nil
}

func (r *MemoryRepository) RecordedRetry(_ context.Context, write Write, digest string) (RetryOutcome, bool, error) {
	r.lock.Lock()
	defer r.lock.Unlock()
	key := replayKey(write, "retry")
	replay, ok := r.replays[key]
	if !ok {
		return RetryOutcome{}, false, nil
	}
	if conflict := ReplayConflict(replay.digest, digest, replay.version, write.ExpectedVersion); conflict != nil {
		return RetryOutcome{}, false, conflict
	}
	result := replay.value.(RetryOutcome)
	result.Replayed = true
	return result, true, nil
}

func (r *MemoryRepository) Retry(_ context.Context, write Write, digest, checkpoint string) (RetryOutcome, error) {
	r.lock.Lock()
	defer r.lock.Unlock()
	entry, replay, err := r.prepare(write, "retry", digest)
	if err != nil {
		return RetryOutcome{}, err
	}
	if replay != nil {
		result := replay.value.(RetryOutcome)
		result.Replayed = true
		return result, nil
	}
	snapshot, err := transition(entry.snapshot, runs.Command{Kind: runs.Retry, RetryEligible: true, Traceparent: write.Traceparent})
	if err != nil {
		return RetryOutcome{}, err
	}
	r.advance(entry, snapshot, time.Now().UTC())
	result := RetryOutcome{Snapshot: cloneSnapshot(snapshot), ResumeCheckpoint: checkpoint}
	r.record(write, "retry", digest, result)
	return result, nil
}

func (r *MemoryRepository) Discard(_ context.Context, write Write, digest string) (OperationResult, error) {
	r.lock.Lock()
	defer r.lock.Unlock()
	entry, replay, err := r.prepare(write, "discard", digest)
	if err != nil {
		return OperationResult{}, err
	}
	if replay != nil {
		result := replay.value.(OperationResult)
		result.Replayed = true
		return result, nil
	}
	snapshot, err := transition(entry.snapshot, runs.Command{Kind: runs.Discard, Traceparent: write.Traceparent})
	if err != nil {
		return OperationResult{}, err
	}
	r.advance(entry, snapshot, time.Now().UTC())
	result := OperationResult{Snapshot: cloneSnapshot(snapshot)}
	r.record(write, "discard", digest, result)
	return result, nil
}

func (r *MemoryRepository) CreateChild(_ context.Context, write Write, child Child, digest string) (Child, error) {
	r.lock.Lock()
	defer r.lock.Unlock()
	parent, replay, err := r.prepare(write, "create-child", digest)
	if err != nil {
		return Child{}, err
	}
	if replay != nil {
		return replay.value.(Child), nil
	}
	if parent.snapshot.Status != runs.Executing {
		return Child{}, problem.New(problem.CodeInvalidTransition, "")
	}
	child.RootRunID = parent.snapshot.RootRunID
	if child.RootRunID == "" {
		child.RootRunID = parent.snapshot.RunID
	}
	child.ContractBOM = clone(parent.snapshot.ContractBOM)
	child.DataPolicy = clone(parent.snapshot.Policy)
	r.children[child.RunID] = cloneChild(child)
	childSnapshot := cloneSnapshot(parent.snapshot)
	childSnapshot.RunID = child.RunID
	childSnapshot.RootRunID = child.RootRunID
	parentID := child.ParentRunID
	childSnapshot.ParentRunID = &parentID
	childSnapshot.Status = runs.Created
	childSnapshot.Version = 1
	childSnapshot.ExecutionGeneration = 1
	childSnapshot.Problem = nil
	childSnapshot.CreatedAt = child.CreatedAt
	childSnapshot.UpdatedAt = child.CreatedAt
	r.runs[child.RunID] = &memoryRun{scope: parent.scope, snapshot: childSnapshot, inputs: make(map[RequestID]InputRequest), approvals: make(map[RequestID]ApprovalRequest), progress: Progress{Scope: parent.scope, RunID: child.RunID, State: runs.Created, EnteredAt: child.CreatedAt, ProgressAt: child.CreatedAt}, retained: []string{"events", "artifacts", "usage"}}
	r.record(write, "create-child", digest, cloneChild(child))
	return cloneChild(child), nil
}

func (r *MemoryRepository) Parent(_ context.Context, scope runs.Scope, id runs.ID) (Child, bool, error) {
	r.lock.Lock()
	defer r.lock.Unlock()
	child, ok := r.children[id]
	if !ok {
		if _, err := r.scoped(scope, id); err != nil {
			return Child{}, false, err
		}
		return Child{}, false, nil
	}
	if child.WorkspaceID != scope.WorkspaceID || child.ProjectID != scope.ProjectID {
		return Child{}, false, problem.New(problem.CodeResourceNotFound, "")
	}
	return cloneChild(child), true, nil
}

func (r *MemoryRepository) RecordChildOutcome(_ context.Context, scope runs.Scope, id runs.ID, outcome ChildOutcome) error {
	r.lock.Lock()
	defer r.lock.Unlock()
	child, ok := r.children[id]
	if !ok || child.WorkspaceID != scope.WorkspaceID || child.ProjectID != scope.ProjectID {
		return problem.New(problem.CodeResourceNotFound, "")
	}
	if outcome.Artifact != "" && (len(outcome.Artifact) > 512 || !strings.HasPrefix(outcome.Artifact, "artifact-lineage:")) {
		return stable(problem.CodeRequestInvalid, "artifact return must be an immutable lineage reference")
	}
	if child.Mode == ChildOptional && outcome.State != runs.Completed {
		outcome.Warning = "optional child did not complete"
	}
	r.outcomes[id] = outcome
	if child.Mode == ChildRequired && outcome.State != runs.Completed {
		parent := r.runs[child.ParentRunID]
		if parent != nil && (parent.snapshot.Status == runs.Executing || parent.snapshot.Status == runs.Validating) {
			failure := problem.New(problem.CodeWorkerFailed, "")
			failure.Detail = "required child did not complete"
			snapshot, transitionErr := transition(parent.snapshot, runs.Command{Kind: runs.RecordFailure, Failure: &failure, Traceparent: "00-0123456789abcdef0123456789abcdef-0123456789abcdef-01"})
			if transitionErr == nil {
				r.advance(parent, snapshot, time.Now().UTC())
			}
		}
	}
	return nil
}

func (r *MemoryRepository) ChildOutcome(_ context.Context, scope runs.Scope, id runs.ID) (ChildOutcome, error) {
	r.lock.Lock()
	defer r.lock.Unlock()
	child, ok := r.children[id]
	if !ok || child.WorkspaceID != scope.WorkspaceID || child.ProjectID != scope.ProjectID {
		return ChildOutcome{}, problem.New(problem.CodeResourceNotFound, "")
	}
	outcome, ok := r.outcomes[id]
	if !ok {
		return ChildOutcome{}, stable(problem.CodeChildPredecessorIneligible, "child has no terminal outcome")
	}
	return outcome, nil
}

func (r *MemoryRepository) Descendants(_ context.Context, scope runs.Scope, ancestor runs.ID) ([]Child, error) {
	r.lock.Lock()
	defer r.lock.Unlock()
	if _, err := r.scoped(scope, ancestor); err != nil {
		if child, ok := r.children[ancestor]; !ok || child.WorkspaceID != scope.WorkspaceID || child.ProjectID != scope.ProjectID {
			return nil, err
		}
	}
	seen := map[runs.ID]bool{ancestor: true}
	var result []Child
	for changed := true; changed; {
		changed = false
		for _, child := range r.children {
			if seen[child.ParentRunID] && !seen[child.RunID] {
				seen[child.RunID] = true
				result = append(result, cloneChild(child))
				changed = true
			}
		}
	}
	return result, nil
}

func (r *MemoryRepository) Progress(context.Context) ([]Progress, error) {
	r.lock.Lock()
	defer r.lock.Unlock()
	result := make([]Progress, 0, len(r.runs))
	for _, entry := range r.runs {
		result = append(result, entry.progress)
	}
	return result, nil
}

func (r *MemoryRepository) RecordProgress(_ context.Context, scope runs.Scope, id runs.ID, state runs.State, at time.Time) error {
	r.lock.Lock()
	defer r.lock.Unlock()
	entry, err := r.scoped(scope, id)
	if err != nil {
		return err
	}
	if entry.snapshot.Status != state {
		return problem.New(problem.CodeVersionConflict, "")
	}
	if at.After(entry.progress.ProgressAt) {
		entry.progress.ProgressAt = at
	}
	return nil
}

func (r *MemoryRepository) MarkStuck(_ context.Context, progress Progress, at time.Time, owner string) (bool, error) {
	r.lock.Lock()
	defer r.lock.Unlock()
	entry, err := r.scoped(progress.Scope, progress.RunID)
	if err != nil {
		return false, err
	}
	if owner == "" || entry.snapshot.Status != progress.State || entry.progress.StuckAt != nil {
		return false, nil
	}
	copyAt := at
	entry.progress.StuckAt = &copyAt
	return true, nil
}

func (r *MemoryRepository) prepare(write Write, operation, digest string) (*memoryRun, *memoryReplay, error) {
	if err := write.Scope.Validate(); err != nil || write.RunID == "" || write.ExpectedVersion == 0 || write.IdempotencyKey == "" || digest == "" {
		return nil, nil, stable(problem.CodeRequestInvalid, "control write requires scope, run, version, idempotency, and digest")
	}
	entry, err := r.scoped(write.Scope, write.RunID)
	if err != nil {
		return nil, nil, err
	}
	key := replayKey(write, operation)
	if replay, ok := r.replays[key]; ok {
		if conflict := ReplayConflict(replay.digest, digest, replay.version, write.ExpectedVersion); conflict != nil {
			return nil, nil, conflict
		}
		return entry, &replay, nil
	}
	if entry.snapshot.Version != write.ExpectedVersion {
		return nil, nil, problem.New(problem.CodeVersionConflict, "")
	}
	return entry, nil, nil
}

func (r *MemoryRepository) record(write Write, operation, digest string, value any) {
	r.replays[replayKey(write, operation)] = memoryReplay{digest: digest, version: write.ExpectedVersion, value: value}
}
func replayKey(write Write, operation string) string {
	return write.Scope.WorkspaceID + "\x00" + write.Scope.ProjectID + "\x00" + operation + "\x00" + write.IdempotencyKey
}
func (r *MemoryRepository) scoped(scope runs.Scope, id runs.ID) (*memoryRun, error) {
	entry := r.runs[id]
	if entry == nil || entry.scope.WorkspaceID != scope.WorkspaceID || entry.scope.ProjectID != scope.ProjectID {
		return nil, problem.New(problem.CodeResourceNotFound, "")
	}
	return entry, nil
}
func (r *MemoryRepository) advance(entry *memoryRun, snapshot runs.Snapshot, now time.Time) {
	entry.snapshot = cloneSnapshot(snapshot)
	entry.progress = Progress{Scope: entry.scope, RunID: snapshot.RunID, State: snapshot.Status, EnteredAt: now, ProgressAt: now}
}

func transition(snapshot runs.Snapshot, command runs.Command) (runs.Snapshot, error) {
	aggregate := runs.Run{ID: snapshot.RunID, State: snapshot.Status, Version: snapshot.Version, ExecutionGeneration: snapshot.ExecutionGeneration, Problem: snapshot.Problem}
	updated, _, err := aggregate.Apply(command)
	if err != nil {
		return runs.Snapshot{}, err
	}
	result := cloneSnapshot(snapshot)
	result.Status, result.Version, result.ExecutionGeneration, result.Problem = updated.State, updated.Version, updated.ExecutionGeneration, updated.Problem
	return result, nil
}
func cloneSnapshot(value runs.Snapshot) runs.Snapshot {
	raw, _ := json.Marshal(value)
	var result runs.Snapshot
	_ = json.Unmarshal(raw, &result)
	result.Version = value.Version
	result.LatestEventID = value.LatestEventID
	return result
}
func cloneInput(value InputRequest) InputRequest {
	raw, _ := json.Marshal(value)
	var result InputRequest
	_ = json.Unmarshal(raw, &result)
	// ExpiredAt is deliberately absent from the closed wire contract, so the
	// JSON clone cannot carry it.
	if value.ExpiredAt != nil {
		expired := *value.ExpiredAt
		result.ExpiredAt = &expired
	}
	return result
}
func cloneApproval(value ApprovalRequest) ApprovalRequest {
	raw, _ := json.Marshal(value)
	var result ApprovalRequest
	_ = json.Unmarshal(raw, &result)
	if value.ExpiredAt != nil {
		expired := *value.ExpiredAt
		result.ExpiredAt = &expired
	}
	return result
}
func cloneChild(value Child) Child {
	raw, _ := json.Marshal(value)
	var result Child
	_ = json.Unmarshal(raw, &result)
	return result
}
