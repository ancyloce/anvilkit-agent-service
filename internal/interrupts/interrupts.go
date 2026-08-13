// Package interrupts owns durable human/lifecycle controls and parent/child
// orchestration. Caller-authored commands never contain server authority.
package interrupts

import (
	"context"
	"encoding/json"
	"time"

	"github.com/ancyloce/anvilkit-agent-service/internal/problem"
	"github.com/ancyloce/anvilkit-agent-service/internal/runs"
)

type RequestID string

type Write struct {
	Scope           runs.Scope
	RunID           runs.ID
	ExpectedVersion uint64
	IdempotencyKey  string
	CanonicalDigest string
	Traceparent     string
}

type InputRequest struct {
	ID               RequestID       `json:"requestId"`
	RunID            runs.ID         `json:"runId"`
	Version          uint64          `json:"version"`
	Question         string          `json:"question"`
	ResponseSchema   json.RawMessage `json:"responseSchema"`
	ExpiresAt        time.Time       `json:"expiresAt"`
	ResumeCheckpoint string          `json:"resumeState"`
	CreatedAt        time.Time       `json:"createdAt"`
	Response         *InputResponse  `json:"response,omitempty"`
}

type InputResponse struct {
	RequestVersion uint64          `json:"requestVersion"`
	Value          json.RawMessage `json:"value"`
	ActorID        string          `json:"-"`
	AcceptedAt     time.Time       `json:"acceptedAt"`
}

type InputResponseCommand struct {
	RequestID      RequestID       `json:"requestId"`
	RequestVersion uint64          `json:"requestVersion"`
	Value          json.RawMessage `json:"value"`
}

type ApprovalRequest struct {
	ID               RequestID       `json:"requestId"`
	RunID            runs.ID         `json:"runId"`
	Version          uint64          `json:"decisionVersion"`
	ActionDigest     string          `json:"actionDigest"`
	Effects          json.RawMessage `json:"effects"`
	ExpectedCost     json.RawMessage `json:"expectedCost"`
	ReviewerPolicy   json.RawMessage `json:"reviewerPolicy"`
	ExpiresAt        time.Time       `json:"expiresAt"`
	ResumeCheckpoint string          `json:"resumeState"`
	CreatedAt        time.Time       `json:"createdAt"`
	Decision         *Decision       `json:"decision,omitempty"`
}

type DecisionKind string

const (
	DecisionApprove DecisionKind = "approve"
	DecisionReject  DecisionKind = "reject"
	DecisionChange  DecisionKind = "change"
)

type Decision struct {
	RequestVersion uint64       `json:"decisionVersion"`
	Kind           DecisionKind `json:"decision"`
	ReviewerID     string       `json:"-"`
	Reason         string       `json:"reason,omitempty"`
	AcceptedAt     time.Time    `json:"acceptedAt"`
}

type ApprovalDecisionCommand struct {
	RequestID      RequestID    `json:"requestId"`
	RequestVersion uint64       `json:"decisionVersion"`
	Decision       DecisionKind `json:"decision"`
	Reason         string       `json:"reason,omitempty"`
}

type Cancellation struct {
	RequestedAt        time.Time `json:"requestedAt"`
	RequestedBy        string    `json:"-"`
	CommitPhase        bool      `json:"commitPhase"`
	DispatchStopped    bool      `json:"dispatchStopped"`
	ChildrenPropagated bool      `json:"childrenPropagated"`
	LeasesRevoked      bool      `json:"leasesRevoked"`
	Reconciled         bool      `json:"reconciled"`
	ExternalUncertain  bool      `json:"externalUncertain"`
}

type RetryOutcome struct {
	Snapshot         runs.Snapshot `json:"run"`
	ResumeCheckpoint string        `json:"resumeCheckpoint"`
	Replayed         bool          `json:"-"`
}

type ChildMode string

const (
	ChildRequired ChildMode = "required"
	ChildOptional ChildMode = "optional"
	ChildFallback ChildMode = "fallback"
)

type Child struct {
	RunID            runs.ID         `json:"runId"`
	RootRunID        runs.ID         `json:"rootRunId"`
	ParentRunID      runs.ID         `json:"parentRunId"`
	WorkspaceID      string          `json:"workspaceId"`
	ProjectID        string          `json:"projectId"`
	ActorID          string          `json:"actorId"`
	ContractBOM      json.RawMessage `json:"contractBomReference"`
	DataPolicy       json.RawMessage `json:"dataPolicy"`
	Mode             ChildMode       `json:"mode"`
	PredecessorRunID *runs.ID        `json:"predecessorRunId,omitempty"`
	Depth            int             `json:"depth"`
	CreatedAt        time.Time       `json:"createdAt"`
}

type ChildOutcome struct {
	State    runs.State `json:"state"`
	Warning  string     `json:"warning,omitempty"`
	Artifact string     `json:"artifactLineageReference,omitempty"`
}

type Progress struct {
	Scope      runs.Scope
	RunID      runs.ID
	State      runs.State
	EnteredAt  time.Time
	ProgressAt time.Time
	StuckAt    *time.Time
}

type OperationResult struct {
	Snapshot runs.Snapshot
	Replayed bool `json:"-"`
}

func (r OperationResult) MarshalJSON() ([]byte, error) {
	return json.Marshal(struct {
		Snapshot runs.Snapshot `json:"snapshot"`
		Version  uint64        `json:"version"`
	}{r.Snapshot, r.Snapshot.Version})
}
func (r *OperationResult) UnmarshalJSON(raw []byte) error {
	var wire struct {
		Snapshot runs.Snapshot `json:"snapshot"`
		Version  uint64        `json:"version"`
	}
	if err := json.Unmarshal(raw, &wire); err != nil {
		return err
	}
	wire.Snapshot.Version = wire.Version
	r.Snapshot = wire.Snapshot
	return nil
}

func (r RetryOutcome) MarshalJSON() ([]byte, error) {
	return json.Marshal(struct {
		Snapshot         runs.Snapshot `json:"run"`
		Version          uint64        `json:"version"`
		ResumeCheckpoint string        `json:"resumeCheckpoint"`
	}{r.Snapshot, r.Snapshot.Version, r.ResumeCheckpoint})
}
func (r *RetryOutcome) UnmarshalJSON(raw []byte) error {
	var wire struct {
		Snapshot         runs.Snapshot `json:"run"`
		Version          uint64        `json:"version"`
		ResumeCheckpoint string        `json:"resumeCheckpoint"`
	}
	if err := json.Unmarshal(raw, &wire); err != nil {
		return err
	}
	wire.Snapshot.Version = wire.Version
	r.Snapshot, r.ResumeCheckpoint = wire.Snapshot, wire.ResumeCheckpoint
	return nil
}

// Repository is the durable atomic authority seam. Each accepted method must
// persist its control fact, run transition, event, and checkpoint together.
type Repository interface {
	Input(context.Context, runs.Scope, runs.ID, RequestID) (InputRequest, error)
	OpenInput(context.Context, Write, InputRequest, string) (InputRequest, OperationResult, error)
	AcceptInput(context.Context, Write, InputResponseCommand, string, time.Time) (OperationResult, error)
	Approval(context.Context, runs.Scope, runs.ID, RequestID) (ApprovalRequest, error)
	OpenApproval(context.Context, Write, ApprovalRequest, string) (ApprovalRequest, OperationResult, error)
	DecideApproval(context.Context, Write, ApprovalDecisionCommand, string, time.Time) (OperationResult, error)
	RequestCancellation(context.Context, Write, string, time.Time) (Cancellation, OperationResult, error)
	FinishCancellation(context.Context, Write, Cancellation) (OperationResult, error)
	RecordedRetry(context.Context, Write, string) (RetryOutcome, bool, error)
	Retry(context.Context, Write, string, string) (RetryOutcome, error)
	Discard(context.Context, Write, string) (OperationResult, error)
	Parent(context.Context, runs.Scope, runs.ID) (Child, bool, error)
	CreateChild(context.Context, Write, Child, string) (Child, error)
	RecordChildOutcome(context.Context, runs.Scope, runs.ID, ChildOutcome) error
	ChildOutcome(context.Context, runs.Scope, runs.ID) (ChildOutcome, error)
	Descendants(context.Context, runs.Scope, runs.ID) ([]Child, error)
	RecordProgress(context.Context, runs.Scope, runs.ID, runs.State, time.Time) error
	Progress(context.Context) ([]Progress, error)
	MarkStuck(context.Context, runs.Scope, runs.ID, runs.State, time.Time) (bool, error)
}

type SchemaValidator interface {
	Validate(context.Context, json.RawMessage, json.RawMessage) error
}

type Authority interface {
	AuthorizeInput(context.Context, runs.Scope, InputRequest) error
	AuthorizeReviewer(context.Context, runs.Scope, ApprovalRequest, DecisionKind) error
	RetryEligibility(context.Context, runs.Scope, runs.Snapshot) (bool, string, error)
}

type Runtime interface {
	Signal(context.Context, string, string, json.RawMessage, string) error
	StartChild(context.Context, Child) error
	OpenWait(context.Context, runs.Scope, string, string, time.Duration) error
}

type LeaseRevoker interface {
	RevokeRun(context.Context, runs.Scope, runs.ID) error
}

type CancellationReconciler interface {
	Reconcile(context.Context, runs.Scope, runs.ID, bool) (clear bool, authoritative *runs.State, err error)
}

type Reservation interface {
	ReserveChild(context.Context, runs.Scope, runs.ID, runs.ID, ChildMode) error
}

type EventSink interface {
	Stuck(context.Context, Progress, time.Time) error
}

type AlertSink interface {
	Alert(context.Context, string, runs.Scope, runs.ID, runs.State) error
}

func stable(code problem.Code, detail string) problem.Details {
	value := problem.New(code, "")
	value.Detail = detail
	return value
}
