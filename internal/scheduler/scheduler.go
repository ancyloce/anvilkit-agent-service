// Package scheduler owns immutable tasks, monotonic leases, result fencing,
// pending-output promotion, diagnostics, and DLQ records.
package scheduler

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/ancyloce/anvilkit-agent-service/internal/problem"
)

type TaskID string
type AttemptID string
type State string

const (
	Queued       State = "queued"
	Leased       State = "leased"
	Completed    State = "completed"
	Failed       State = "failed"
	DeadLettered State = "dead-lettered"
	Cancelled    State = "cancelled"
)

type Scope struct{ WorkspaceID, ProjectID string }
type Create struct {
	Scope                                        Scope
	TaskID                                       TaskID
	RunID, RootRunID                             string
	RecoveryEpoch, ExecutionGeneration           uint64
	Capability, CapabilityVersion, ReservationID string
	ReservationCurrent, PolicyAllowed            bool
	InputDigest, InputObjectKey                  string
	CreatedAt                                    time.Time
}
type Task struct {
	Create
	State                                                   State
	BusinessAttempts, PhysicalAttempts, LeaseEpoch, Version uint64
	Lease                                                   *Lease
	Result                                                  *Result
}
type Lease struct {
	TaskID                             TaskID
	RecoveryEpoch, ExecutionGeneration uint64
	PhysicalAttemptID                  AttemptID
	AttemptNumber, LeaseEpoch          uint64
	Owner                              string
	IssuedAt, ExpiresAt                time.Time
	FenceToken                         string
}
type Result struct {
	TaskID                                                                              TaskID
	RecoveryEpoch, ExecutionGeneration                                                  uint64
	PhysicalAttemptID                                                                   AttemptID
	LeaseEpoch                                                                          uint64
	FenceToken, Capability, BuildIdentity, ArtifactID, ArtifactDigest, PendingObjectKey string
	CompletedAt                                                                         time.Time
}
type Diagnostic struct {
	TaskID            TaskID
	RunID             string
	PhysicalAttemptID AttemptID
	Code, Reason      string
	RecordedAt        time.Time
}
type DLQEntry struct {
	ID                         string
	TaskID                     TaskID
	RunID, Code, Stage, Detail string
	CreatedAt                  time.Time
	Replayed                   bool
}
type Acceptance struct {
	Accepted, Duplicate bool
	Task                Task
}
type IDs interface {
	PhysicalAttemptID() (AttemptID, error)
	FenceToken() (string, error)
	DLQID() (string, error)
}
type Clock interface{ Now() time.Time }
type Promotion interface {
	Promote(context.Context, Result) error
}
type Advancement interface {
	Advance(context.Context, Task, Result) error
}
type Release interface {
	ReleaseAttempt(context.Context, Task, Result) error
}
type FailurePoint string

const (
	AfterFenceCheck  FailurePoint = "after-fence-check"
	AfterPromotion   FailurePoint = "after-promotion"
	AfterAdvancement FailurePoint = "after-advancement"
	AfterRelease     FailurePoint = "after-release"
)

type FailureInjector func(FailurePoint) error
type Service struct {
	lock        sync.Mutex
	ids         IDs
	clock       Clock
	ttl         time.Duration
	promotion   Promotion
	advancement Advancement
	release     Release
	inject      FailureInjector
	tasks       map[string]Task
	attempts    map[AttemptID]struct{}
	diagnostics []Diagnostic
	dlq         []DLQEntry
}

func New(ids IDs, clock Clock, ttl time.Duration, promotion Promotion, advancement Advancement, release Release, inject FailureInjector) (*Service, error) {
	if ids == nil || clock == nil || ttl <= 0 || promotion == nil || advancement == nil || release == nil {
		return nil, fmt.Errorf("scheduler dependencies and lease TTL are required")
	}
	return &Service{ids: ids, clock: clock, ttl: ttl, promotion: promotion, advancement: advancement, release: release, inject: inject, tasks: map[string]Task{}, attempts: map[AttemptID]struct{}{}}, nil
}
func key(scope Scope, id TaskID) string {
	return scope.WorkspaceID + "\x00" + scope.ProjectID + "\x00" + string(id)
}
func (s *Service) Create(_ context.Context, input Create) (Task, error) {
	if input.Scope.WorkspaceID == "" || input.Scope.ProjectID == "" || input.TaskID == "" || input.RunID == "" || input.RootRunID == "" || input.ExecutionGeneration == 0 || input.Capability == "" || input.CapabilityVersion != input.Capability+"/v1" || input.ReservationID == "" || !input.ReservationCurrent || !input.PolicyAllowed || !digest(input.InputDigest) || input.InputObjectKey == "" || input.CreatedAt.IsZero() {
		return Task{}, problem.New(problem.CodeTaskDispatchDenied, "")
	}
	s.lock.Lock()
	defer s.lock.Unlock()
	identity := key(input.Scope, input.TaskID)
	if prior, ok := s.tasks[identity]; ok {
		if prior.Create != input {
			return Task{}, problem.New(problem.CodeIdempotencyConflict, "")
		}
		return cloneTask(prior), nil
	}
	value := Task{Create: input, State: Queued, Version: 1}
	s.tasks[identity] = value
	return cloneTask(value), nil
}
func (s *Service) Lease(_ context.Context, scope Scope, id TaskID, owner string) (Lease, error) {
	s.lock.Lock()
	defer s.lock.Unlock()
	identity := key(scope, id)
	task, ok := s.tasks[identity]
	if !ok {
		return Lease{}, problem.New(problem.CodeResourceNotFound, "")
	}
	now := s.clock.Now().UTC()
	if now.IsZero() {
		return Lease{}, problem.New(problem.CodeInfrastructureUnavailable, "")
	}
	if task.State == Leased && task.Lease != nil && now.Before(task.Lease.ExpiresAt) {
		return Lease{}, problem.New(problem.CodeVersionConflict, "")
	}
	if task.State != Queued && task.State != Leased {
		return Lease{}, problem.New(problem.CodeInvalidTransition, "")
	}
	if owner == "" {
		return Lease{}, problem.New(problem.CodeRequestInvalid, "")
	}
	attempt, err := s.ids.PhysicalAttemptID()
	if err != nil {
		return Lease{}, fmt.Errorf("allocate physical attempt: %w", err)
	}
	if attempt == "" {
		return Lease{}, fmt.Errorf("allocate physical attempt: empty identifier")
	}
	if _, exists := s.attempts[attempt]; exists {
		return Lease{}, problem.New(problem.CodeIdempotencyConflict, "")
	}
	token, err := s.ids.FenceToken()
	if err != nil {
		return Lease{}, fmt.Errorf("allocate fence token: %w", err)
	}
	if len(token) < 16 {
		return Lease{}, fmt.Errorf("allocate fence token: token is too short")
	}
	task.LeaseEpoch++
	task.PhysicalAttempts++
	lease := Lease{TaskID: id, RecoveryEpoch: task.RecoveryEpoch, ExecutionGeneration: task.ExecutionGeneration, PhysicalAttemptID: attempt, AttemptNumber: task.PhysicalAttempts, LeaseEpoch: task.LeaseEpoch, Owner: owner, IssuedAt: now, ExpiresAt: now.Add(s.ttl), FenceToken: token}
	task.State = Leased
	task.Version++
	task.Lease = &lease
	s.tasks[identity] = task
	s.attempts[attempt] = struct{}{}
	return lease, nil
}
func (s *Service) Heartbeat(_ context.Context, scope Scope, lease Lease, expectedExpiry time.Time) (Lease, error) {
	s.lock.Lock()
	defer s.lock.Unlock()
	task, ok := s.tasks[key(scope, lease.TaskID)]
	now := s.clock.Now().UTC()
	if now.IsZero() || !ok || task.State != Leased || task.Lease == nil || !sameLease(*task.Lease, lease) || !task.Lease.ExpiresAt.Equal(expectedExpiry) || !now.Before(task.Lease.ExpiresAt) {
		return Lease{}, problem.New(problem.CodeWorkerFenceStale, "")
	}
	task.Lease.ExpiresAt = now.Add(s.ttl)
	task.Version++
	s.tasks[key(scope, lease.TaskID)] = task
	return *task.Lease, nil
}
func (s *Service) ReclaimExpired(_ context.Context, scope Scope, id TaskID) (bool, error) {
	s.lock.Lock()
	defer s.lock.Unlock()
	identity := key(scope, id)
	task, ok := s.tasks[identity]
	if !ok {
		return false, problem.New(problem.CodeResourceNotFound, "")
	}
	if task.State != Leased || task.Lease == nil || s.clock.Now().Before(task.Lease.ExpiresAt) {
		return false, nil
	}
	task.State = Queued
	task.Lease = nil
	task.Version++
	s.tasks[identity] = task
	return true, nil
}
func (s *Service) AcceptResult(ctx context.Context, scope Scope, result Result) (Acceptance, error) {
	s.lock.Lock()
	defer s.lock.Unlock()
	identity := key(scope, result.TaskID)
	task, ok := s.tasks[identity]
	if !ok {
		for _, candidate := range s.tasks {
			if candidate.Scope == scope && candidate.Lease != nil && candidate.Lease.PhysicalAttemptID == result.PhysicalAttemptID {
				s.diagnostics = append(s.diagnostics, Diagnostic{result.TaskID, candidate.RunID, result.PhysicalAttemptID, string(problem.CodeWorkerFenceStale), "task", s.clock.Now()})
				return Acceptance{Task: cloneTask(candidate)}, problem.New(problem.CodeWorkerFenceStale, "")
			}
		}
		return Acceptance{}, problem.New(problem.CodeResourceNotFound, "")
	}
	if task.Result != nil && sameResult(*task.Result, result) {
		return Acceptance{Duplicate: true, Task: cloneTask(task)}, nil
	}
	reason := fenceReason(task, result, s.clock.Now())
	if reason != "" {
		s.diagnostics = append(s.diagnostics, Diagnostic{result.TaskID, task.RunID, result.PhysicalAttemptID, string(problem.CodeWorkerFenceStale), reason, s.clock.Now()})
		return Acceptance{Task: cloneTask(task)}, problem.New(problem.CodeWorkerFenceStale, "")
	}
	if err := validateOutput(task, result); err != nil {
		s.diagnostics = append(s.diagnostics, Diagnostic{result.TaskID, task.RunID, result.PhysicalAttemptID, string(problem.CodeArtifactInvalid), err.Error(), s.clock.Now()})
		return Acceptance{Task: cloneTask(task)}, err
	}
	if err := s.fail(AfterFenceCheck); err != nil {
		return Acceptance{}, err
	}
	// The three ports must provide transaction participants in production. The
	// memory implementation snapshots their state so injection proves rollback.
	promoteSnapshot := snapshot(s.promotion)
	advanceSnapshot := snapshot(s.advancement)
	releaseSnapshot := snapshot(s.release)
	rollback := func() {
		restore(s.promotion, promoteSnapshot)
		restore(s.advancement, advanceSnapshot)
		restore(s.release, releaseSnapshot)
	}
	if err := s.promotion.Promote(ctx, result); err != nil {
		rollback()
		return Acceptance{}, err
	}
	if err := s.fail(AfterPromotion); err != nil {
		rollback()
		return Acceptance{}, err
	}
	if err := s.advancement.Advance(ctx, task, result); err != nil {
		rollback()
		return Acceptance{}, err
	}
	if err := s.fail(AfterAdvancement); err != nil {
		rollback()
		return Acceptance{}, err
	}
	if err := s.release.ReleaseAttempt(ctx, task, result); err != nil {
		rollback()
		return Acceptance{}, err
	}
	if err := s.fail(AfterRelease); err != nil {
		rollback()
		return Acceptance{}, err
	}
	task.State = Completed
	task.Version++
	copyResult := result
	task.Result = &copyResult
	s.tasks[identity] = task
	return Acceptance{Accepted: true, Task: cloneTask(task)}, nil
}
func (s *Service) DeadLetter(_ context.Context, scope Scope, id TaskID, code, stage, detail string) (DLQEntry, error) {
	if code == "" || stage == "" {
		return DLQEntry{}, problem.New(problem.CodeRequestInvalid, "")
	}
	s.lock.Lock()
	defer s.lock.Unlock()
	identity := key(scope, id)
	task, ok := s.tasks[identity]
	if !ok {
		return DLQEntry{}, problem.New(problem.CodeResourceNotFound, "")
	}
	dlqID, err := s.ids.DLQID()
	if err != nil {
		return DLQEntry{}, fmt.Errorf("allocate DLQ identifier: %w", err)
	}
	if dlqID == "" {
		return DLQEntry{}, fmt.Errorf("allocate DLQ identifier: empty identifier")
	}
	entry := DLQEntry{ID: dlqID, TaskID: id, RunID: task.RunID, Code: code, Stage: stage, Detail: detail, CreatedAt: s.clock.Now()}
	task.State = DeadLettered
	task.Version++
	s.tasks[identity] = task
	s.dlq = append(s.dlq, entry)
	return entry, nil
}
func (s *Service) ReplayDLQ(_ context.Context, scope Scope, entryID string) (Task, error) {
	s.lock.Lock()
	defer s.lock.Unlock()
	for index := range s.dlq {
		entry := &s.dlq[index]
		if entry.ID != entryID {
			continue
		}
		task := s.tasks[key(scope, entry.TaskID)]
		if entry.Replayed {
			return cloneTask(task), nil
		}
		entry.Replayed = true
		task.State = Queued
		task.Lease = nil
		task.Version++
		s.tasks[key(scope, entry.TaskID)] = task
		return cloneTask(task), nil
	}
	return Task{}, problem.New(problem.CodeResourceNotFound, "")
}
func (s *Service) Get(_ context.Context, scope Scope, id TaskID) (Task, error) {
	s.lock.Lock()
	defer s.lock.Unlock()
	value, ok := s.tasks[key(scope, id)]
	if !ok {
		return Task{}, problem.New(problem.CodeResourceNotFound, "")
	}
	return cloneTask(value), nil
}
func (s *Service) Diagnostics() []Diagnostic {
	s.lock.Lock()
	defer s.lock.Unlock()
	return append([]Diagnostic(nil), s.diagnostics...)
}
func (s *Service) DLQ() []DLQEntry {
	s.lock.Lock()
	defer s.lock.Unlock()
	return append([]DLQEntry(nil), s.dlq...)
}
func (s *Service) fail(point FailurePoint) error {
	if s.inject == nil {
		return nil
	}
	return s.inject(point)
}
func sameLease(a, b Lease) bool {
	return a.TaskID == b.TaskID && a.RecoveryEpoch == b.RecoveryEpoch && a.ExecutionGeneration == b.ExecutionGeneration && a.PhysicalAttemptID == b.PhysicalAttemptID && a.LeaseEpoch == b.LeaseEpoch && a.Owner == b.Owner && a.FenceToken == b.FenceToken
}
func sameResult(a, b Result) bool { return a == b }
func fenceReason(task Task, result Result, now time.Time) string {
	if now.IsZero() {
		return "authoritative-time-unavailable"
	}
	if task.State != Leased || task.Lease == nil {
		return "task-not-leased"
	}
	lease := task.Lease
	if result.TaskID != task.TaskID {
		return "task"
	}
	if result.RecoveryEpoch != task.RecoveryEpoch {
		return "recovery-epoch"
	}
	if result.ExecutionGeneration != task.ExecutionGeneration {
		return "execution-generation"
	}
	if result.PhysicalAttemptID != lease.PhysicalAttemptID {
		return "physical-attempt"
	}
	if result.LeaseEpoch != lease.LeaseEpoch {
		return "lease-epoch"
	}
	if result.FenceToken != lease.FenceToken {
		return "fence-token"
	}
	if result.Capability != task.Capability {
		return "capability"
	}
	if !now.Before(lease.ExpiresAt) || !result.CompletedAt.Before(lease.ExpiresAt) {
		return "expired"
	}
	return ""
}
func validateOutput(task Task, result Result) error {
	if result.ArtifactID == "" || !digest(result.ArtifactDigest) || result.BuildIdentity == "" || result.PendingObjectKey == "" {
		return problem.New(problem.CodeArtifactInvalid, "")
	}
	prefix := fmt.Sprintf("pending/%s/r%d/g%d/%s/", task.TaskID, task.RecoveryEpoch, task.ExecutionGeneration, result.PhysicalAttemptID)
	if !strings.HasPrefix(result.PendingObjectKey, prefix) {
		return problem.New(problem.CodeArtifactInvalid, "")
	}
	return nil
}
func digest(value string) bool {
	if len(value) != 71 || !strings.HasPrefix(value, "sha256:") {
		return false
	}
	for _, c := range value[7:] {
		if !strings.ContainsRune("0123456789abcdef", c) {
			return false
		}
	}
	return true
}
func cloneTask(value Task) Task {
	if value.Lease != nil {
		copyLease := *value.Lease
		value.Lease = &copyLease
	}
	if value.Result != nil {
		copyResult := *value.Result
		value.Result = &copyResult
	}
	return value
}

type stateful interface {
	Snapshot() any
	Restore(any)
}

func snapshot(value any) any {
	if s, ok := value.(stateful); ok {
		return s.Snapshot()
	}
	return nil
}
func restore(value, snap any) {
	if s, ok := value.(stateful); ok && snap != nil {
		s.Restore(snap)
	}
}

type MemoryEffects struct {
	lock                         sync.Mutex
	Promoted, Advanced, Released []string
}

func (m *MemoryEffects) Promote(_ context.Context, r Result) error {
	m.lock.Lock()
	defer m.lock.Unlock()
	m.Promoted = append(m.Promoted, r.PendingObjectKey)
	return nil
}
func (m *MemoryEffects) Advance(_ context.Context, t Task, _ Result) error {
	m.lock.Lock()
	defer m.lock.Unlock()
	m.Advanced = append(m.Advanced, t.RunID)
	return nil
}
func (m *MemoryEffects) ReleaseAttempt(_ context.Context, _ Task, r Result) error {
	m.lock.Lock()
	defer m.lock.Unlock()
	m.Released = append(m.Released, string(r.PhysicalAttemptID))
	return nil
}
func (m *MemoryEffects) Snapshot() any {
	m.lock.Lock()
	defer m.lock.Unlock()
	return [3][]string{append([]string(nil), m.Promoted...), append([]string(nil), m.Advanced...), append([]string(nil), m.Released...)}
}
func (m *MemoryEffects) Restore(raw any) {
	m.lock.Lock()
	defer m.lock.Unlock()
	v := raw.([3][]string)
	m.Promoted, m.Advanced, m.Released = v[0], v[1], v[2]
}
func OutputDigest(value []byte) string {
	sum := sha256.Sum256(value)
	return "sha256:" + hex.EncodeToString(sum[:])
}
