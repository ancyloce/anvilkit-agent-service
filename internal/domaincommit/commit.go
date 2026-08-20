// Package domaincommit owns the last local authority boundary before Pagix.
// Domain outcomes become terminal only from authoritative Pagix events.
package domaincommit

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/ancyloce/anvilkit-agent-service/internal/applyauth"
	"github.com/ancyloce/anvilkit-agent-service/internal/pagixclient"
	"github.com/ancyloce/anvilkit-agent-service/internal/problem"
	"github.com/ancyloce/anvilkit-agent-service/internal/runs"
)

type Scope struct{ WorkspaceID, ProjectID string }
type Status string

const (
	Recorded Status = "recorded"
	Issued   Status = "issued"
	Awaiting Status = "awaiting-domain-confirmation"
	// Escalated marks a submitted-but-uncertain operation whose bounded
	// reconciliation window elapsed without the authoritative owner deciding
	// it. It is still the run's one active operation; leaving it requires an
	// audited operator resolution or the owner's late answer.
	Escalated  Status = "escalated"
	Applied    Status = "applied"
	Conflicted Status = "conflict"
	Rejected   Status = "rejected"
)

type Operation struct {
	Scope                                          Scope
	RunID                                          runs.ID
	ID                                             string
	AuthorizationID                                applyauth.AuthorizationID
	AuthorizationJWS                               string
	ActionDigest, ArtifactDigest, ExpectedRevision string
	IdempotencyKey, RequestDigest                  string
	Status                                         Status
	AuthorizationConsumed                          bool
	// ReconcileAttempts counts the durable uncertain reconciliations of a
	// submitted operation; FirstUncertainAt stamps when uncertainty began and
	// EscalatedAt when the bounded window elapsed. ResolvedBy and
	// ResolutionBasis audit the operator resolution of an escalated
	// operation; both are empty for owner-decided outcomes.
	ReconcileAttempts             uint64
	FirstUncertainAt, EscalatedAt time.Time
	ResolvedBy, ResolutionBasis   string
	CreatedAt, UpdatedAt          time.Time
}
type Store interface {
	ActiveForRun(context.Context, Scope, runs.ID) (Operation, bool, error)
	Create(context.Context, Operation) error
	MarkIssued(context.Context, Scope, string, time.Time) error
	MarkAwaiting(context.Context, Scope, string, time.Time) error
	Finalize(context.Context, Scope, string, Status, time.Time) error
	// RecordReconcile durably counts one uncertain reconciliation of a
	// submitted operation and stamps when uncertainty began, so recovery is
	// bounded by a durable count rather than process memory.
	RecordReconcile(context.Context, Scope, string, time.Time) (Operation, error)
	// Escalate marks a bounded-out submitted operation as requiring operator
	// resolution. Escalating an already-escalated operation converges.
	Escalate(context.Context, Scope, string, time.Time) error
	// Resolve records an audited operator resolution of an escalated
	// operation: the decided terminal outcome, the resolving operator, and
	// the reference to the authoritative evidence the decision is based on.
	// It never applies to an operation the owner already decided.
	Resolve(ctx context.Context, scope Scope, id string, outcome Status, resolvedBy, basis string, at time.Time) (Operation, error)
	// LatestForRun answers the most recently created operation for the run,
	// decided or not — the record an operator settlement resolves from.
	LatestForRun(context.Context, Scope, runs.ID) (Operation, bool, error)
	Get(context.Context, Scope, string) (Operation, error)
}
type RunStore interface {
	Current(context.Context, Scope, runs.ID) (runs.Run, error)
	Transition(context.Context, Scope, runs.ID, uint64, runs.Command) (runs.Run, error)
}
type Issuer interface {
	Issue(context.Context, applyauth.Command) (applyauth.Authorization, error)
}
type Pagix interface {
	Persist(context.Context, pagixclient.DomainCommand) (pagixclient.DomainOutcome, error)
	Reconcile(context.Context, string, string) (pagixclient.DomainOutcome, bool, error)
	Consume(context.Context, pagixclient.DomainEvent) (pagixclient.DomainOutcome, bool, error)
}
type IDs interface{ OperationID() (string, error) }
type Clock interface{ Now() time.Time }
type Coordinator struct {
	store  Store
	runs   RunStore
	issuer Issuer
	pagix  Pagix
	ids    IDs
	clock  Clock
}

func New(store Store, runsStore RunStore, issuer Issuer, pagix Pagix, ids IDs, clock Clock) (*Coordinator, error) {
	if store == nil || runsStore == nil || issuer == nil || pagix == nil || ids == nil || clock == nil {
		return nil, fmt.Errorf("domain commit dependencies are required")
	}
	return &Coordinator{store: store, runs: runsStore, issuer: issuer, pagix: pagix, ids: ids, clock: clock}, nil
}

type Start struct {
	Scope              Scope
	RunID              runs.ID
	ExpectedRunVersion uint64
	Authorization      applyauth.Command
	Metadata           pagixclient.Metadata
	ExpectedRevision   string
}

func (c *Coordinator) Start(ctx context.Context, input Start) (Operation, error) {
	if input.Scope.WorkspaceID == "" || input.Scope.ProjectID == "" || input.RunID == "" || input.ExpectedRunVersion == 0 || input.Authorization.WorkspaceID != input.Scope.WorkspaceID || input.Authorization.ProjectID != input.Scope.ProjectID || input.Authorization.RunID != string(input.RunID) || input.ExpectedRevision == "" {
		return Operation{}, problem.New(problem.CodeCommitProofMissing, "")
	}
	if err := input.Metadata.Validate(); err != nil {
		return Operation{}, problem.New(problem.CodeCommitProofMissing, "")
	}
	if prior, ok, err := c.store.ActiveForRun(ctx, input.Scope, input.RunID); err != nil {
		return Operation{}, err
	} else if ok {
		if prior.ExpectedRevision != input.ExpectedRevision || prior.IdempotencyKey != input.Metadata.IdempotencyKey || prior.RequestDigest != input.Metadata.RequestDigest {
			return Operation{}, problem.New(problem.CodeIdempotencyConflict, "")
		}
		return c.resume(ctx, input, prior)
	}
	currentRun, err := c.runs.Current(ctx, input.Scope, input.RunID)
	if err != nil {
		return Operation{}, err
	}
	if currentRun.State != runs.AwaitingApproval || currentRun.Version != input.ExpectedRunVersion {
		return Operation{}, problem.New(problem.CodeVersionConflict, "")
	}
	issued, err := c.issuer.Issue(ctx, input.Authorization)
	if err != nil {
		return Operation{}, err
	}
	operationID, err := c.ids.OperationID()
	if err != nil {
		return Operation{}, fmt.Errorf("allocate domain operation identity: %w", err)
	}
	if operationID == "" {
		return Operation{}, fmt.Errorf("allocate domain operation identity: empty identity")
	}
	now := c.clock.Now().UTC()
	operation := Operation{Scope: input.Scope, RunID: input.RunID, ID: operationID, AuthorizationID: issued.ID, AuthorizationJWS: issued.Compact, ActionDigest: issued.Payload.ActionDigest, ArtifactDigest: issued.Payload.ArtifactDigest, ExpectedRevision: issued.Payload.BaseRevision, IdempotencyKey: input.Metadata.IdempotencyKey, RequestDigest: input.Metadata.RequestDigest, Status: Recorded, CreatedAt: now, UpdatedAt: now}
	if operation.ExpectedRevision != input.ExpectedRevision {
		return Operation{}, problem.New(problem.CodeCommitProofMissing, "")
	}
	if err := c.store.Create(ctx, operation); err != nil {
		return Operation{}, fmt.Errorf("durably record domain operation: %w", err)
	}
	return c.resume(ctx, input, operation)
}

func (c *Coordinator) resume(ctx context.Context, input Start, operation Operation) (Operation, error) {
	if operation.Status == Awaiting {
		return operation, nil
	}
	current, err := c.runs.Current(ctx, input.Scope, input.RunID)
	if err != nil {
		return operation, err
	}
	if operation.Status == Recorded {
		if current.State == runs.AwaitingApproval {
			if current.Version != input.ExpectedRunVersion {
				return operation, problem.New(problem.CodeVersionConflict, "")
			}
			current, err = c.runs.Transition(ctx, input.Scope, input.RunID, current.Version, runs.Command{Kind: runs.Approve, Traceparent: input.Metadata.Traceparent, Commit: runs.CommitProof{ApprovalRechecked: true, ArtifactEligible: true, ActionBindingExact: true, AuthorizationDurable: true, AuthorizationID: string(operation.AuthorizationID), DomainOperationID: operation.ID, ActionDigest: operation.ActionDigest, ArtifactDigest: operation.ArtifactDigest}})
			if err != nil {
				return operation, err
			}
		}
		if current.State != runs.Committing {
			return operation, problem.New(problem.CodeInvalidTransition, "")
		}
		// This write-ahead marker prevents a restored workflow checkpoint from
		// treating absence as permission to send a second command.
		if err := c.store.MarkIssued(ctx, input.Scope, operation.ID, c.clock.Now().UTC()); err != nil {
			return operation, fmt.Errorf("record command issuance intent: %w", err)
		}
		operation.Status = Issued
		operation.UpdatedAt = c.clock.Now().UTC()
		command := pagixclient.DomainCommand{Metadata: input.Metadata, OperationID: operation.ID, AuthorizationJWS: operation.AuthorizationJWS, AuthorizationID: string(operation.AuthorizationID), ActionDigest: operation.ActionDigest, ArtifactDigest: operation.ArtifactDigest, ExpectedRevision: operation.ExpectedRevision}
		_, persistErr := c.pagix.Persist(ctx, command)
		return c.awaitConfirmation(ctx, input, operation, persistErr)
	}
	if operation.Status == Issued {
		// Issued is deliberately reconcile-first: the command may have crossed
		// the boundary before a process failure, so this path never sends again.
		outcome, found, reconcileErr := c.pagix.Reconcile(ctx, input.Scope.WorkspaceID, operation.ID)
		if reconcileErr != nil {
			return operation, reconcileErr
		}
		if found && (outcome.OperationID != operation.ID || outcome.AuthorizationID != string(operation.AuthorizationID)) {
			return operation, problem.New(problem.CodeIdempotencyConflict, "")
		}
		uncertain := problem.New(problem.CodeDomainOutcomeUncertain, "")
		return c.awaitConfirmation(ctx, input, operation, uncertain)
	}
	return operation, problem.New(problem.CodeInvalidTransition, "")
}

func (c *Coordinator) awaitConfirmation(ctx context.Context, input Start, operation Operation, persistErr error) (Operation, error) {
	current, err := c.runs.Current(ctx, input.Scope, input.RunID)
	if err != nil {
		return operation, err
	}
	if current.State == runs.Committing {
		current, err = c.runs.Transition(ctx, input.Scope, input.RunID, current.Version, runs.Command{Kind: runs.BeginDomainConfirmation, Traceparent: input.Metadata.Traceparent})
		if err != nil {
			return operation, err
		}
	}
	if current.State != runs.AwaitingDomainConfirmation {
		return operation, problem.New(problem.CodeInvalidTransition, "")
	}
	if err := c.store.MarkAwaiting(ctx, input.Scope, operation.ID, c.clock.Now().UTC()); err != nil {
		return operation, err
	}
	operation.Status = Awaiting
	operation.UpdatedAt = c.clock.Now().UTC()
	return operation, persistErr
}

// Reconcile reads by the original operation identity. It never manufactures a
// terminal run outcome; terminal projection remains event-only.
func (c *Coordinator) Reconcile(ctx context.Context, scope Scope, runID runs.ID) (Operation, error) {
	operation, ok, err := c.store.ActiveForRun(ctx, scope, runID)
	if err != nil {
		return Operation{}, err
	}
	if !ok {
		return Operation{}, problem.New(problem.CodeResourceNotFound, "")
	}
	outcome, found, err := c.pagix.Reconcile(ctx, scope.WorkspaceID, operation.ID)
	if err == nil && found && (outcome.OperationID != operation.ID || outcome.AuthorizationID != string(operation.AuthorizationID)) {
		return operation, problem.New(problem.CodeIdempotencyConflict, "")
	}
	return operation, err
}

func (c *Coordinator) HandleEvent(ctx context.Context, scope Scope, event pagixclient.DomainEvent) (runs.Run, bool, error) {
	outcome, accepted, err := c.pagix.Consume(ctx, event)
	if err != nil {
		return runs.Run{}, accepted, err
	}
	operation, err := c.store.Get(ctx, scope, outcome.OperationID)
	if err != nil {
		return runs.Run{}, false, err
	}
	if string(operation.AuthorizationID) != outcome.AuthorizationID {
		return runs.Run{}, false, problem.New(problem.CodeIdempotencyConflict, "")
	}
	current, err := c.runs.Current(ctx, scope, operation.RunID)
	if err != nil {
		return runs.Run{}, false, err
	}
	if current.State == runs.Committing {
		current, err = c.runs.Transition(ctx, scope, operation.RunID, current.Version, runs.Command{Kind: runs.BeginDomainConfirmation, Traceparent: event.Traceparent})
		if err != nil {
			return runs.Run{}, false, err
		}
	}
	var command runs.Command
	var status Status
	switch outcome.Kind {
	case pagixclient.OutcomeApplied:
		command = runs.Command{Kind: runs.ConfirmDomain, Traceparent: event.Traceparent}
		status = Applied
	case pagixclient.OutcomeConflict:
		command = runs.Command{Kind: runs.RecordDomainConflict, Traceparent: event.Traceparent}
		status = Conflicted
	case pagixclient.OutcomeRejected:
		failure := problem.New(problem.CodeDomainRejected, event.Traceparent)
		command = runs.Command{Kind: runs.RecordDomainRejection, Traceparent: event.Traceparent, Failure: &failure}
		status = Rejected
	default:
		return runs.Run{}, false, problem.New(problem.CodeDomainOutcomeUncertain, "")
	}
	updated := current
	if current.State == runs.AwaitingDomainConfirmation {
		updated, err = c.runs.Transition(ctx, scope, operation.RunID, current.Version, command)
		if err != nil {
			return runs.Run{}, accepted, err
		}
	} else if !terminalMatches(current.State, status) {
		return runs.Run{}, accepted, problem.New(problem.CodeInvalidTransition, "")
	}
	if err := c.store.Finalize(ctx, scope, operation.ID, status, c.clock.Now().UTC()); err != nil {
		return runs.Run{}, accepted, err
	}
	return updated, accepted, nil
}

func terminalMatches(state runs.State, status Status) bool {
	return status == Applied && state == runs.Completed || status == Conflicted && state == runs.Conflict || status == Rejected && state == runs.Failed
}

func (c *Coordinator) Cancel(context.Context, Scope, runs.ID) error {
	return problem.New(problem.CodeCancellationUnreconciled, "")
}

type MemoryStore struct {
	lock   sync.Mutex
	values map[string]Operation
}

func NewMemoryStore() *MemoryStore { return &MemoryStore{values: map[string]Operation{}} }
func operationKey(scope Scope, id string) string {
	return scope.WorkspaceID + "\x00" + scope.ProjectID + "\x00" + id
}
func (s *MemoryStore) ActiveForRun(_ context.Context, scope Scope, runID runs.ID) (Operation, bool, error) {
	s.lock.Lock()
	defer s.lock.Unlock()
	for _, value := range s.values {
		if value.Scope == scope && value.RunID == runID && (value.Status == Recorded || value.Status == Issued || value.Status == Awaiting || value.Status == Escalated) {
			return value, true, nil
		}
	}
	return Operation{}, false, nil
}
func (s *MemoryStore) Create(_ context.Context, value Operation) error {
	s.lock.Lock()
	defer s.lock.Unlock()
	for _, prior := range s.values {
		if prior.Scope == value.Scope && prior.RunID == value.RunID && (prior.Status == Recorded || prior.Status == Issued || prior.Status == Awaiting || prior.Status == Escalated) {
			if prior == value {
				return nil
			}
			return problem.New(problem.CodeIdempotencyConflict, "")
		}
	}
	key := operationKey(value.Scope, value.ID)
	if prior, ok := s.values[key]; ok {
		if prior != value {
			return problem.New(problem.CodeIdempotencyConflict, "")
		}
		return nil
	}
	s.values[key] = value
	return nil
}
func (s *MemoryStore) update(scope Scope, id string, status Status, now time.Time, consumed bool) error {
	key := operationKey(scope, id)
	value, ok := s.values[key]
	if !ok {
		return problem.New(problem.CodeResourceNotFound, "")
	}
	if now.Before(value.UpdatedAt) || !statusTransition(value.Status, status) || consumed != (status == Applied || status == Conflicted || status == Rejected) {
		return problem.New(problem.CodeInvalidTransition, "")
	}
	value.Status = status
	value.UpdatedAt = now
	value.AuthorizationConsumed = value.AuthorizationConsumed || consumed
	s.values[key] = value
	return nil
}
func (s *MemoryStore) MarkIssued(_ context.Context, scope Scope, id string, now time.Time) error {
	s.lock.Lock()
	defer s.lock.Unlock()
	return s.update(scope, id, Issued, now, false)
}
func (s *MemoryStore) MarkAwaiting(_ context.Context, scope Scope, id string, now time.Time) error {
	s.lock.Lock()
	defer s.lock.Unlock()
	return s.update(scope, id, Awaiting, now, false)
}
func (s *MemoryStore) Finalize(_ context.Context, scope Scope, id string, status Status, now time.Time) error {
	s.lock.Lock()
	defer s.lock.Unlock()
	return s.update(scope, id, status, now, true)
}
func (s *MemoryStore) RecordReconcile(_ context.Context, scope Scope, id string, now time.Time) (Operation, error) {
	s.lock.Lock()
	defer s.lock.Unlock()
	key := operationKey(scope, id)
	value, ok := s.values[key]
	if !ok {
		return Operation{}, problem.New(problem.CodeResourceNotFound, "")
	}
	if value.Status != Issued && value.Status != Awaiting {
		return Operation{}, problem.New(problem.CodeInvalidTransition, "")
	}
	if now.Before(value.UpdatedAt) {
		return Operation{}, problem.New(problem.CodeInvalidTransition, "")
	}
	value.ReconcileAttempts++
	if value.FirstUncertainAt.IsZero() {
		value.FirstUncertainAt = now
	}
	value.UpdatedAt = now
	s.values[key] = value
	return value, nil
}
func (s *MemoryStore) Escalate(_ context.Context, scope Scope, id string, now time.Time) error {
	s.lock.Lock()
	defer s.lock.Unlock()
	key := operationKey(scope, id)
	value, ok := s.values[key]
	if !ok {
		return problem.New(problem.CodeResourceNotFound, "")
	}
	if value.Status == Escalated {
		return nil
	}
	if err := s.update(scope, id, Escalated, now, false); err != nil {
		return err
	}
	value = s.values[key]
	value.EscalatedAt = now
	s.values[key] = value
	return nil
}
func (s *MemoryStore) Resolve(_ context.Context, scope Scope, id string, outcome Status, resolvedBy, basis string, now time.Time) (Operation, error) {
	s.lock.Lock()
	defer s.lock.Unlock()
	if outcome != Applied && outcome != Conflicted && outcome != Rejected {
		return Operation{}, problem.New(problem.CodeInvalidTransition, "")
	}
	if resolvedBy == "" || basis == "" {
		return Operation{}, problem.New(problem.CodeRequestInvalid, "")
	}
	key := operationKey(scope, id)
	value, ok := s.values[key]
	if !ok {
		return Operation{}, problem.New(problem.CodeResourceNotFound, "")
	}
	if value.Status != Escalated {
		// Two operators submitting the identical audited decision converge on
		// the one that landed; anything else is refused rather than
		// overwriting a decision already made.
		if value.Status == outcome && value.ResolvedBy == resolvedBy && value.ResolutionBasis == basis {
			return value, nil
		}
		return Operation{}, problem.New(problem.CodeInvalidTransition, "")
	}
	if err := s.update(scope, id, outcome, now, true); err != nil {
		return Operation{}, err
	}
	value = s.values[key]
	value.ResolvedBy = resolvedBy
	value.ResolutionBasis = basis
	s.values[key] = value
	return value, nil
}

func statusTransition(current, next Status) bool {
	if current == next {
		return true
	}
	switch current {
	case Recorded:
		return next == Issued
	case Issued:
		return next == Awaiting || next == Escalated || next == Applied || next == Conflicted || next == Rejected
	case Awaiting:
		return next == Escalated || next == Applied || next == Conflicted || next == Rejected
	case Escalated:
		return next == Applied || next == Conflicted || next == Rejected
	default:
		return false
	}
}
func (s *MemoryStore) LatestForRun(_ context.Context, scope Scope, runID runs.ID) (Operation, bool, error) {
	s.lock.Lock()
	defer s.lock.Unlock()
	var latest Operation
	found := false
	for _, value := range s.values {
		if value.Scope != scope || value.RunID != runID {
			continue
		}
		if !found || value.CreatedAt.After(latest.CreatedAt) {
			latest = value
			found = true
		}
	}
	return latest, found, nil
}
func (s *MemoryStore) Get(_ context.Context, scope Scope, id string) (Operation, error) {
	s.lock.Lock()
	defer s.lock.Unlock()
	value, ok := s.values[operationKey(scope, id)]
	if !ok {
		return Operation{}, problem.New(problem.CodeResourceNotFound, "")
	}
	return value, nil
}
