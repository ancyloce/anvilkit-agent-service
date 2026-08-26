// Package pagixclient owns the scoped Pagix boundary. It carries workload
// identity, trace context, idempotency, and canonical digest on every write.
package pagixclient

import (
	"context"
	"fmt"
	"reflect"
	"strings"
	"sync"
	"time"

	"github.com/ancyloce/anvilkit-agent-service/internal/budget"
	"github.com/ancyloce/anvilkit-agent-service/internal/problem"
)

type Health interface{ Check(context.Context) error }
type Metadata struct{ WorkloadIdentity, Traceparent, WorkspaceID, ProjectID, ActorID, Operation, IdempotencyKey, RequestDigest string }

func (m Metadata) Validate() error {
	if !bounded(m.WorkloadIdentity, 512) || !traceparent(m.Traceparent) || !bounded(m.WorkspaceID, 128) || !bounded(m.ProjectID, 128) || !bounded(m.ActorID, 128) || !bounded(m.Operation, 64) || !bounded(m.IdempotencyKey, 256) || !digest(m.RequestDigest) {
		return fmt.Errorf("write metadata for Pagix is incomplete")
	}
	return nil
}

func traceparent(value string) bool {
	if len(value) != 55 || value[:2] != "00" || value[2] != '-' || value[35] != '-' || value[52] != '-' {
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
	return value[3:35] != strings.Repeat("0", 32) && value[36:52] != strings.Repeat("0", 16)
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
		return nil, fmt.Errorf("port and inbox for Pagix are required")
	}
	return &Client{port: port, inbox: inbox}, nil
}
func (c *Client) Snapshot(ctx context.Context, request SnapshotRequest) (Snapshot, error) {
	if request.Metadata.Validate() != nil || !validTarget(request.Target) || request.Target.WorkspaceID != request.Metadata.WorkspaceID {
		return Snapshot{}, problem.New(problem.CodeAuthorizationDenied, "")
	}
	value, err := c.port.AuthorizedSnapshot(ctx, request)
	if err != nil {
		return Snapshot{}, err
	}
	if value.Target != request.Target || !bounded(value.BaseRevision, 128) || !bounded(value.ArtifactID, 128) || !digest(value.Digest) || !digest(value.ContractBOMDigest) || !digest(value.CatalogDigest) || value.CapturedAt.IsZero() {
		return Snapshot{}, problem.New(problem.CodeContractInvalid, "")
	}
	return value, nil
}
func (c *Client) Entitlement(ctx context.Context, request EntitlementRequest) error {
	if request.Metadata.Validate() != nil || request.Capability == "" {
		return problem.New(problem.CodeAuthorizationDenied, "")
	}
	return c.port.CheckEntitlement(ctx, request)
}
func (c *Client) Reserve(ctx context.Context, metadata Metadata, estimate budget.Estimate, generation budget.Generation) (budget.Reservation, error) {
	if metadata.Validate() != nil || estimate.WorkspaceID != metadata.WorkspaceID {
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
func (c *Client) Reconcile(ctx context.Context, workspaceID, operationID string) (DomainOutcome, bool, error) {
	if workspaceID == "" || operationID == "" {
		return DomainOutcome{}, false, problem.New(problem.CodeRequestInvalid, "")
	}
	value, ok, err := c.port.Effect(ctx, workspaceID, operationID)
	if err != nil || !ok {
		return value, ok, err
	}
	if !validOutcome(value, operationID, value.AuthorizationID, true) {
		return DomainOutcome{}, false, problem.New(problem.CodeContractInvalid, "")
	}
	return value, true, nil
}
func (c *Client) Consume(ctx context.Context, event DomainEvent) (DomainOutcome, bool, error) {
	if !bounded(event.MessageID, 128) || !bounded(event.OperationID, 128) || !bounded(event.AuthorizationID, 128) || !traceparent(event.Traceparent) || !validOutcome(event.Outcome, event.OperationID, event.AuthorizationID, true) || event.Outcome.EventID != "" && event.Outcome.EventID != event.MessageID {
		return DomainOutcome{}, false, problem.New(problem.CodeEventInvalid, "")
	}
	accepted, err := c.inbox.Accept(ctx, event)
	if err != nil || !accepted {
		return event.Outcome, false, err
	}
	return event.Outcome, true, nil
}

func validTarget(value Target) bool {
	return bounded(value.TargetType, 64) && bounded(value.TargetID, 128) && bounded(value.WorkspaceID, 128)
}

func validOutcome(value DomainOutcome, operationID, authorizationID string, recorded bool) bool {
	if value.OperationID != operationID || value.AuthorizationID != authorizationID || value.Recorded != recorded || !bounded(value.EventID, 128) {
		return false
	}
	switch value.Kind {
	case OutcomeApplied, OutcomeConflict:
		return bounded(value.Revision, 128) && value.Problem == nil
	case OutcomeRejected:
		return value.Problem != nil && value.Problem.Code != ""
	default:
		return false
	}
}

func bounded(value string, maximum int) bool {
	if len(value) < 1 || len(value) > maximum {
		return false
	}
	for _, character := range value {
		if character < 0x20 || character == 0x7f {
			return false
		}
	}
	return true
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
