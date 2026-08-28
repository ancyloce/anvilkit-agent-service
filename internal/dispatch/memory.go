package dispatch

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/ancyloce/anvilkit-agent-service/internal/problem"
)

// MemoryRepository is the in-memory reference implementation of the durable
// record. It exists so the state machine, the fence, and the evidence rules can
// be proven without a database, and it enforces every invariant the schema
// does — one current attempt per task, monotonic lease epochs, one registered
// result per task — because a relaxed double would make the tests that use it
// prove less than they claim.
//
// It is deliberately not selectable from the composition root: the service
// composes the PostgreSQL repository, and process memory is not a durable
// record of work handed to another process.
type MemoryRepository struct {
	lock     sync.Mutex
	tasks    map[string]Task
	attempts map[string][]Attempt
	results  map[string]Registration
	evidence []Evidence
}

func NewMemoryRepository() *MemoryRepository {
	return &MemoryRepository{tasks: map[string]Task{}, attempts: map[string][]Attempt{}, results: map[string]Registration{}}
}

func key(scope Scope, id string) string {
	return scope.WorkspaceID + "\x00" + scope.ProjectID + "\x00" + id
}

func (m *MemoryRepository) EnsureTask(_ context.Context, task Task) (Task, error) {
	if err := task.Validate(); err != nil {
		return Task{}, err
	}
	m.lock.Lock()
	defer m.lock.Unlock()
	existing, present := m.tasks[key(task.Scope, task.TaskID)]
	if !present {
		m.tasks[key(task.Scope, task.TaskID)] = task
		return task, nil
	}
	if err := sameWork(existing, task); err != nil {
		return Task{}, err
	}
	return existing, nil
}

// sameWork proves a repeated creation is the same work. A durable step that
// replays must find its own task; a step that reaches an existing identity with
// different content has reused an identity, which is a different failure and
// gets a different answer.
func sameWork(existing, offered Task) error {
	for _, comparison := range []struct {
		field            string
		wanted, observed string
	}{
		{"run", existing.RunID, offered.RunID},
		{"definition digest", existing.DefinitionDigest, offered.DefinitionDigest},
		{"request digest", existing.RequestDigest, offered.RequestDigest},
		{"runtime unit", existing.Runtime.RuntimeUnitID, offered.Runtime.RuntimeUnitID},
		{"runtime manifest digest", existing.Runtime.RuntimeManifestDigest, offered.Runtime.RuntimeManifestDigest},
		{"runtime image digest", existing.Runtime.RuntimeImageDigest, offered.Runtime.RuntimeImageDigest},
		{"capability", existing.Capability, offered.Capability},
	} {
		if comparison.wanted != comparison.observed {
			details := problem.New(problem.CodeIdempotencyKeyReused, "")
			details.Detail = "the task identity was reused with a different " + comparison.field
			return details
		}
	}
	if existing.ExecutionGeneration != offered.ExecutionGeneration {
		details := problem.New(problem.CodeIdempotencyKeyReused, "")
		details.Detail = "the task identity was reused under a different execution generation"
		return details
	}
	return nil
}

func (m *MemoryRepository) OpenAttempt(_ context.Context, open Open) (Task, Attempt, error) {
	if !ValidReasonCode(open.SupersededReason) {
		return Task{}, Attempt{}, fmt.Errorf("dispatch attempt: a stable supersession reason code is required")
	}
	m.lock.Lock()
	defer m.lock.Unlock()
	identity := key(open.Scope, open.TaskID)
	task, present := m.tasks[identity]
	if !present {
		return Task{}, Attempt{}, notFound("the task does not exist")
	}
	if task.Status.Terminal() {
		return Task{}, Attempt{}, refused("the task already reached a terminal state and admits no further execution")
	}
	attempts := m.attempts[identity]
	for index, attempt := range attempts {
		if attempt.Status != Accepted && attempt.Status != Running {
			continue
		}
		// An attempt found past its own deadline expired; it was not replaced
		// by a decision anyone made. Recording the reason it actually stopped
		// is what makes the record answer "why" rather than only "when".
		attempts[index].Status, attempts[index].FailureReason = Superseded, open.SupersededReason
		if open.At.After(attempt.ExpiresAt) {
			attempts[index].Status, attempts[index].FailureReason = Expired, ReasonDeadlineExceeded
		}
		attempts[index].FinishedAt = open.At
		attempts[index].UpdatedAt = open.At
	}
	task.Attempts++
	task.LeaseEpoch++
	task.UpdatedAt = open.At
	// The logical task lives as long as the execution it currently has. A task
	// whose deadline stayed at its first attempt's would make every
	// replacement uncommittable the moment the first lease ran out, which is
	// exactly when replacements are needed.
	task.ExpiresAt = open.ExpiresAt
	opened := Attempt{
		Scope:             open.Scope,
		PhysicalAttemptID: AttemptID(task.TaskID, task.Attempts),
		TaskID:            task.TaskID,
		AttemptNumber:     task.Attempts,
		LeaseEpoch:        task.LeaseEpoch,
		FenceTokenDigest:  open.FenceTokenDigest,
		RuntimeUnitID:     open.RuntimeUnitID,
		Status:            Accepted,
		ExpiresAt:         open.ExpiresAt,
		CreatedAt:         open.At,
		UpdatedAt:         open.At,
	}
	m.tasks[identity] = task
	m.attempts[identity] = append(attempts, opened)
	return task, opened, nil
}

func (m *MemoryRepository) MarkDispatched(_ context.Context, scope Scope, attemptID string, at time.Time) error {
	m.lock.Lock()
	defer m.lock.Unlock()
	for identity, attempts := range m.attempts {
		for index, attempt := range attempts {
			if attempt.PhysicalAttemptID != attemptID || attempt.Scope != scope {
				continue
			}
			if attempt.Status != Accepted {
				// A dispatch record on a superseded or settled attempt would
				// claim work left this process that no longer may return.
				return refused("the attempt is no longer accepting a dispatch")
			}
			attempts[index].Status = Running
			attempts[index].DispatchedAt = at
			attempts[index].StartedAt = at
			attempts[index].UpdatedAt = at
			task := m.tasks[identity]
			if task.Status == Accepted {
				task.Status = Running
				task.UpdatedAt = at
				m.tasks[identity] = task
			}
			return nil
		}
	}
	return notFound("the attempt does not exist")
}

func (m *MemoryRepository) CloseAttempt(_ context.Context, scope Scope, attemptID, reason string, at time.Time) error {
	if !ValidReasonCode(reason) {
		return fmt.Errorf("dispatch attempt: a stable close reason code is required")
	}
	m.lock.Lock()
	defer m.lock.Unlock()
	for _, attempts := range m.attempts {
		for index, attempt := range attempts {
			if attempt.PhysicalAttemptID != attemptID || attempt.Scope != scope {
				continue
			}
			if attempt.Status.Terminal() {
				// Whatever ended the attempt first stands; closing settled
				// work is idempotent rather than a second ending.
				return nil
			}
			attempts[index].Status = Failed
			attempts[index].FailureReason = reason
			attempts[index].FinishedAt = at
			attempts[index].UpdatedAt = at
			return nil
		}
	}
	return notFound("the attempt does not exist")
}

func (m *MemoryRepository) Commit(_ context.Context, request Settle) (Result, error) {
	m.lock.Lock()
	defer m.lock.Unlock()
	identity := key(request.Scope, request.Predicate.TaskID)
	task, present := m.tasks[identity]
	if !present {
		return Result{}, notFound("the task does not exist")
	}
	attempts := m.attempts[identity]
	index := -1
	for position, attempt := range attempts {
		if attempt.PhysicalAttemptID == request.Predicate.PhysicalAttemptID {
			index = position
			break
		}
	}
	if index < 0 {
		m.evidence = append(m.evidence, evidenceOf(request, DispositionUnbound, "the attempt does not exist", request.Outcome.ObservedAt))
		return Result{Disposition: DispositionUnbound, Reason: "the attempt does not exist", Task: task}, nil
	}
	var committed *Registration
	if registration, settled := m.results[identity]; settled {
		committed = &registration
	}
	disposition, reason := Evaluate(task, attempts[index], committed, request, request.Outcome.ObservedAt)
	if !disposition.Committed() {
		m.evidence = append(m.evidence, evidenceOf(request, disposition, reason, request.Outcome.ObservedAt))
		// An expiry discovered here is also recorded as one: the attempt, and
		// the task if its own deadline has passed, stop being open work rather
		// than staying accepted for ever.
		if disposition == DispositionExpired {
			if !attempts[index].Status.Terminal() {
				attempts[index].Status = Expired
				attempts[index].FailureReason = ReasonDeadlineExceeded
				attempts[index].FinishedAt = request.Outcome.ObservedAt
				attempts[index].UpdatedAt = request.Outcome.ObservedAt
			}
			if request.Outcome.ObservedAt.After(task.ExpiresAt) && !task.Status.Terminal() {
				task.Status = Expired
				task.UpdatedAt = request.Outcome.ObservedAt
				m.tasks[identity] = task
			}
		}
		return Result{Disposition: disposition, Reason: reason, Task: task, Attempt: attempts[index]}, nil
	}
	outcome := Succeeded
	if request.Outcome.Failed {
		outcome = Failed
	}
	attempts[index].Status = outcome
	attempts[index].ResultStatementDigest = request.Outcome.ResultStatementDigest
	attempts[index].SignatureKeyID = request.Outcome.SignatureKeyID
	if request.Outcome.Failed {
		attempts[index].FailureReason = request.Outcome.ReasonCode
	}
	attempts[index].FinishedAt = request.Outcome.ObservedAt
	attempts[index].UpdatedAt = request.Outcome.ObservedAt
	task.UpdatedAt = request.Outcome.ObservedAt
	if request.Outcome.Failed {
		// A failed execution closes the attempt and nothing else. Whether the
		// work is tried again is the workflow's decision, not this record's,
		// so the task stays open for a replacement — and a task nobody tries
		// again stops being committable at its own deadline rather than by a
		// status this layer would have had to guess.
		m.tasks[identity] = task
		return Result{Task: task, Attempt: attempts[index]}, nil
	}
	task.Status = outcome
	m.tasks[identity] = task
	m.results[identity] = Registration{
		TaskID:                task.TaskID,
		PhysicalAttemptID:     attempts[index].PhysicalAttemptID,
		AttemptNumber:         attempts[index].AttemptNumber,
		LeaseEpoch:            attempts[index].LeaseEpoch,
		ExecutionGeneration:   task.ExecutionGeneration,
		ResultStatementDigest: request.Outcome.ResultStatementDigest,
		SignatureKeyID:        request.Outcome.SignatureKeyID,
		Status:                request.Outcome.Status,
		ReasonCode:            request.Outcome.ReasonCode,
		Statement:             append([]byte(nil), request.Outcome.Statement...),
		CommittedAt:           request.Outcome.ObservedAt,
	}
	return Result{Task: task, Attempt: attempts[index]}, nil
}

func (m *MemoryRepository) RecordEvidence(_ context.Context, evidence Evidence) error {
	m.lock.Lock()
	defer m.lock.Unlock()
	m.evidence = append(m.evidence, evidence)
	return nil
}

func (m *MemoryRepository) CancelRun(_ context.Context, scope Scope, runID, reason string, at time.Time) (int, error) {
	if !ValidReasonCode(reason) {
		return 0, fmt.Errorf("dispatch cancellation: a stable reason code is required")
	}
	m.lock.Lock()
	defer m.lock.Unlock()
	open := 0
	for identity, task := range m.tasks {
		if task.Scope != scope || task.RunID != runID || task.Status.Terminal() {
			continue
		}
		attempts := m.attempts[identity]
		for index, attempt := range attempts {
			if attempt.Status == Accepted || attempt.Status == Running {
				open++
				attempts[index].Status = Canceled
				attempts[index].FailureReason = reason
				attempts[index].FinishedAt = at
				attempts[index].UpdatedAt = at
			}
		}
		task.Status = Canceled
		task.UpdatedAt = at
		m.tasks[identity] = task
	}
	return open, nil
}

func (m *MemoryRepository) Load(_ context.Context, scope Scope, taskID string) (Task, []Attempt, bool, error) {
	m.lock.Lock()
	defer m.lock.Unlock()
	task, present := m.tasks[key(scope, taskID)]
	if !present {
		return Task{}, nil, false, nil
	}
	return task, append([]Attempt(nil), m.attempts[key(scope, taskID)]...), true, nil
}

func (m *MemoryRepository) Registration(_ context.Context, scope Scope, taskID string) (Registration, bool, error) {
	m.lock.Lock()
	defer m.lock.Unlock()
	registration, settled := m.results[key(scope, taskID)]
	if !settled {
		return Registration{}, false, nil
	}
	registration.Statement = append([]byte(nil), registration.Statement...)
	return registration, true, nil
}

// Evidence returns the recorded non-committing outcomes. Tests read it to
// prove that a result that changed nothing was still accounted for.
func (m *MemoryRepository) Evidence() []Evidence {
	m.lock.Lock()
	defer m.lock.Unlock()
	return append([]Evidence(nil), m.evidence...)
}

func evidenceOf(request Settle, disposition Disposition, reason string, at time.Time) Evidence {
	return Evidence{
		Scope:                 request.Scope,
		TaskID:                request.Predicate.TaskID,
		RunID:                 request.RunID,
		PhysicalAttemptID:     request.Predicate.PhysicalAttemptID,
		AttemptNumber:         request.Predicate.AttemptNumber,
		LeaseEpoch:            request.Predicate.LeaseEpoch,
		ResultStatementDigest: request.Outcome.ResultStatementDigest,
		SignatureKeyID:        request.Outcome.SignatureKeyID,
		Disposition:           disposition,
		Reason:                reason,
		RecordedAt:            at,
	}
}

func notFound(detail string) error {
	details := problem.New(problem.CodeResourceNotFound, "")
	details.Detail = detail
	return details
}

func refused(detail string) error {
	details := problem.New(problem.CodeTaskDispatchDenied, "")
	details.Detail = detail
	return details
}
