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
	Recorded   Status = "recorded"
	Issued     Status = "issued"
	Awaiting   Status = "awaiting-domain-confirmation"
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
	Status                                         Status
	AuthorizationConsumed                          bool
	CreatedAt, UpdatedAt                           time.Time
}
type Store interface {
	ActiveForRun(context.Context, Scope, runs.ID) (Operation, bool, error)
	Create(context.Context, Operation) error
	MarkIssued(context.Context, Scope, string, time.Time) error
	MarkAwaiting(context.Context, Scope, string, time.Time) error
	Finalize(context.Context, Scope, string, Status, time.Time) error
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
		return prior, nil
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
	operation := Operation{Scope: input.Scope, RunID: input.RunID, ID: operationID, AuthorizationID: issued.ID, AuthorizationJWS: issued.Compact, ActionDigest: issued.Payload.ActionDigest, ArtifactDigest: issued.Payload.ArtifactDigest, ExpectedRevision: issued.Payload.BaseRevision, Status: Recorded, CreatedAt: now, UpdatedAt: now}
	if operation.ExpectedRevision != input.ExpectedRevision {
		return Operation{}, problem.New(problem.CodeCommitProofMissing, "")
	}
	if err := c.store.Create(ctx, operation); err != nil {
		return Operation{}, fmt.Errorf("durably record domain operation: %w", err)
	}
	_, err = c.runs.Transition(ctx, input.Scope, input.RunID, input.ExpectedRunVersion, runs.Command{Kind: runs.Approve, Traceparent: input.Metadata.Traceparent, Commit: runs.CommitProof{ApprovalRechecked: true, ArtifactEligible: true, ActionBindingExact: true, AuthorizationDurable: true, AuthorizationID: string(issued.ID), DomainOperationID: operationID, ActionDigest: operation.ActionDigest, ArtifactDigest: operation.ArtifactDigest}})
	if err != nil {
		return operation, err
	}
	// This write-ahead marker prevents a restored workflow checkpoint from ever
	// treating absence as permission to send a second command.
	if err := c.store.MarkIssued(ctx, input.Scope, operationID, c.clock.Now().UTC()); err != nil {
		return operation, fmt.Errorf("record command issuance intent: %w", err)
	}
	command := pagixclient.DomainCommand{Metadata: input.Metadata, OperationID: operationID, AuthorizationJWS: issued.Compact, AuthorizationID: string(issued.ID), ActionDigest: operation.ActionDigest, ArtifactDigest: operation.ArtifactDigest, ExpectedRevision: operation.ExpectedRevision}
	_, persistErr := c.pagix.Persist(ctx, command)
	current, err := c.runs.Current(ctx, input.Scope, input.RunID)
	if err != nil {
		return operation, err
	}
	if current.State == runs.Committing {
		if _, err := c.runs.Transition(ctx, input.Scope, input.RunID, current.Version, runs.Command{Kind: runs.BeginDomainConfirmation, Traceparent: input.Metadata.Traceparent}); err != nil {
			return operation, err
		}
	}
	if err := c.store.MarkAwaiting(ctx, input.Scope, operationID, c.clock.Now().UTC()); err != nil {
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
	_, _, err = c.pagix.Reconcile(ctx, scope.WorkspaceID, operation.ID)
	return operation, err
}

func (c *Coordinator) HandleEvent(ctx context.Context, scope Scope, event pagixclient.DomainEvent) (runs.Run, bool, error) {
	outcome, accepted, err := c.pagix.Consume(ctx, event)
	if err != nil || !accepted {
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
	updated, err := c.runs.Transition(ctx, scope, operation.RunID, current.Version, command)
	if err != nil {
		return runs.Run{}, false, err
	}
	if err := c.store.Finalize(ctx, scope, operation.ID, status, c.clock.Now().UTC()); err != nil {
		return runs.Run{}, false, err
	}
	return updated, true, nil
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
		if value.Scope == scope && value.RunID == runID && (value.Status == Recorded || value.Status == Issued || value.Status == Awaiting) {
			return value, true, nil
		}
	}
	return Operation{}, false, nil
}
func (s *MemoryStore) Create(_ context.Context, value Operation) error {
	s.lock.Lock()
	defer s.lock.Unlock()
	for _, prior := range s.values {
		if prior.Scope == value.Scope && prior.RunID == value.RunID && (prior.Status == Recorded || prior.Status == Issued || prior.Status == Awaiting) {
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
func (s *MemoryStore) Get(_ context.Context, scope Scope, id string) (Operation, error) {
	s.lock.Lock()
	defer s.lock.Unlock()
	value, ok := s.values[operationKey(scope, id)]
	if !ok {
		return Operation{}, problem.New(problem.CodeResourceNotFound, "")
	}
	return value, nil
}
