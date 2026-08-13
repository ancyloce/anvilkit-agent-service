// Package pagixclient owns the scoped Pagix boundary. It carries workload
// identity, trace context, idempotency, and canonical digest on every write.
package pagixclient

import (
	"context"
	"fmt"
	"reflect"
	"sync"
	"time"

	"github.com/ancyloce/anvilkit-agent-service/internal/budget"
	"github.com/ancyloce/anvilkit-agent-service/internal/problem"
)

type Health interface{ Check(context.Context) error }
type Metadata struct{ WorkloadIdentity, Traceparent, WorkspaceID, ProjectID, ActorID, Operation, IdempotencyKey, RequestDigest string }

func (m Metadata) Validate() error {
	if m.WorkloadIdentity == "" || !traceparent(m.Traceparent) || m.WorkspaceID == "" || m.ProjectID == "" || m.ActorID == "" || m.Operation == "" || m.IdempotencyKey == "" || !digest(m.RequestDigest) {
		return fmt.Errorf("Pagix write metadata is incomplete")
	}
	return nil
}

func traceparent(value string) bool {
	if len(value) != 55 || value[2] != '-' || value[35] != '-' || value[52] != '-' {
		return false
	}
	for index, character := range value {
		if index == 2 || index == 35 || index == 52 {
			continue
		}
		if (character < '0' || character > '9') && (character < 'a' || character > 'f') {
			return false
		}
	}
	return true
}

type Target struct{ TargetType, TargetID, WorkspaceID string }
type Snapshot struct {
	Target                                                             Target
	BaseRevision, ArtifactID, Digest, ContractBOMDigest, CatalogDigest string
	CapturedAt                                                         time.Time
}
type EntitlementRequest struct {
	Metadata   Metadata
	Capability string
}
type SnapshotRequest struct {
	Metadata Metadata
	Target   Target
}
type DomainCommand struct {
	Metadata                                                                                       Metadata
	OperationID, AuthorizationJWS, AuthorizationID, ActionDigest, ArtifactDigest, ExpectedRevision string
}
type OutcomeKind string

const (
	OutcomeApplied   OutcomeKind = "applied"
	OutcomeConflict  OutcomeKind = "conflict"
	OutcomeRejected  OutcomeKind = "rejected"
	OutcomeUncertain OutcomeKind = "uncertain"
)

type DomainOutcome struct {
	OperationID, AuthorizationID string
	Kind                         OutcomeKind
	Revision                     string
	Problem                      *problem.Details
	EventID                      string
	Recorded                     bool
}
type DomainEvent struct {
	MessageID, OperationID, AuthorizationID string
	Outcome                                 DomainOutcome
	Traceparent                             string
}
type Port interface {
	AuthorizedSnapshot(context.Context, SnapshotRequest) (Snapshot, error)
	CheckEntitlement(context.Context, EntitlementRequest) error
	Reserve(context.Context, Metadata, budget.Estimate, budget.Generation) (budget.Reservation, error)
	Observe(context.Context, Metadata, budget.Observation) error
	Settle(context.Context, Metadata, budget.Settlement) (budget.Reservation, error)
	Persist(context.Context, DomainCommand) (DomainOutcome, error)
	Effect(context.Context, string, string) (DomainOutcome, bool, error)
}
type Inbox interface {
	Accept(context.Context, DomainEvent) (bool, error)
}
type Client struct {
	port  Port
	inbox Inbox
}

func New(port Port, inbox Inbox) (*Client, error) {
	if port == nil || inbox == nil {
		return nil, fmt.Errorf("Pagix port and inbox are required")
	}
	return &Client{port: port, inbox: inbox}, nil
}
func (c *Client) Snapshot(ctx context.Context, request SnapshotRequest) (Snapshot, error) {
	if request.Metadata.Validate() != nil || request.Target.WorkspaceID != request.Metadata.WorkspaceID {
		return Snapshot{}, problem.New(problem.CodeAuthorizationDenied, "")
	}
	return c.port.AuthorizedSnapshot(ctx, request)
}
func (c *Client) Entitlement(ctx context.Context, request EntitlementRequest) error {
	if request.Metadata.Validate() != nil || request.Capability == "" {
		return problem.New(problem.CodeAuthorizationDenied, "")
	}
	return c.port.CheckEntitlement(ctx, request)
}
func (c *Client) Reserve(ctx context.Context, metadata Metadata, estimate budget.Estimate, generation budget.Generation) (budget.Reservation, error) {
	if metadata.Validate() != nil {
		return budget.Reservation{}, problem.New(problem.CodeRequestInvalid, "")
	}
	return c.port.Reserve(ctx, metadata, estimate, generation)
}
func (c *Client) Observe(ctx context.Context, metadata Metadata, observation budget.Observation) error {
	if metadata.Validate() != nil {
		return problem.New(problem.CodeRequestInvalid, "")
	}
	return c.port.Observe(ctx, metadata, observation)
}
func (c *Client) Settle(ctx context.Context, metadata Metadata, settlement budget.Settlement) (budget.Reservation, error) {
	if metadata.Validate() != nil {
		return budget.Reservation{}, problem.New(problem.CodeRequestInvalid, "")
	}
	return c.port.Settle(ctx, metadata, settlement)
}
func (c *Client) Persist(ctx context.Context, command DomainCommand) (DomainOutcome, error) {
	if command.Metadata.Validate() != nil || command.OperationID == "" || command.AuthorizationJWS == "" || command.AuthorizationID == "" || !digest(command.ActionDigest) || !digest(command.ArtifactDigest) || command.ExpectedRevision == "" {
		return DomainOutcome{}, problem.New(problem.CodeRequestInvalid, "")
	}
	outcome, err := c.port.Persist(ctx, command)
	if err == nil && outcome.Recorded {
		return outcome, nil
	}
	recorded, ok, lookupErr := c.port.Effect(ctx, command.Metadata.WorkspaceID, command.OperationID)
	if lookupErr == nil && ok {
		return recorded, nil
	}
	return DomainOutcome{OperationID: command.OperationID, AuthorizationID: command.AuthorizationID, Kind: OutcomeUncertain}, problem.New(problem.CodeDomainOutcomeUncertain, "")
}
func (c *Client) Reconcile(ctx context.Context, workspaceID, operationID string) (DomainOutcome, bool, error) {
	if workspaceID == "" || operationID == "" {
		return DomainOutcome{}, false, problem.New(problem.CodeRequestInvalid, "")
	}
	return c.port.Effect(ctx, workspaceID, operationID)
}
func (c *Client) Consume(ctx context.Context, event DomainEvent) (DomainOutcome, bool, error) {
	if event.MessageID == "" || event.OperationID == "" || event.Outcome.OperationID != event.OperationID {
		return DomainOutcome{}, false, problem.New(problem.CodeEventInvalid, "")
	}
	accepted, err := c.inbox.Accept(ctx, event)
	if err != nil || !accepted {
		return event.Outcome, false, err
	}
	return event.Outcome, true, nil
}
func digest(value string) bool {
	if len(value) != 71 || value[:7] != "sha256:" {
		return false
	}
	for _, character := range value[7:] {
		if (character < '0' || character > '9') && (character < 'a' || character > 'f') {
			return false
		}
	}
	return true
}

type MemoryInbox struct {
	lock sync.Mutex
	seen map[string]DomainEvent
}

func NewMemoryInbox() *MemoryInbox { return &MemoryInbox{seen: map[string]DomainEvent{}} }
func (i *MemoryInbox) Accept(_ context.Context, event DomainEvent) (bool, error) {
	i.lock.Lock()
	defer i.lock.Unlock()
	previous, ok := i.seen[event.MessageID]
	if ok {
		if !reflect.DeepEqual(previous, event) {
			return false, problem.New(problem.CodeIdempotencyConflict, "")
		}
		return false, nil
	}
	i.seen[event.MessageID] = event
	return true, nil
}
