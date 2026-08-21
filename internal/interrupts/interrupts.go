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
	// ExpiredAt is the durable expiry marker. It is server-internal state,
	// never part of the closed request contract, and once set no response
	// can revive the request.
	ExpiredAt *time.Time `json:"-"`
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
	// ExpiredAt is the durable expiry marker; see InputRequest.ExpiredAt.
	ExpiredAt *time.Time `json:"-"`
}

type DecisionKind string

// The decision vocabulary is the canonical one: both canonical contracts that
// name a review decision — SubmitApprovalDecisionRequest.decision and
// ApprovalRequest.allowedDecisions — spell the third decision
// "request-changes". There is no second spelling anywhere in the system.
const (
	DecisionApprove DecisionKind = "approve"
	DecisionReject  DecisionKind = "reject"
	DecisionChange  DecisionKind = "request-changes"
)

type Decision struct {
	RequestVersion uint64       `json:"decisionVersion"`
	Kind           DecisionKind `json:"decision"`
	ReviewerID     string       `json:"-"`
	Comment        string       `json:"comment,omitempty"`
	AcceptedAt     time.Time    `json:"acceptedAt"`
}

// ApprovalDecisionCommand is the reviewer's decision. ActionDigest is the
// action the reviewer states they are deciding: the canonical command requires
// it, and the service proves it is the digest the open request actually
// carries, so a decision can never be recorded against an action the reviewer
// did not see.
type ApprovalDecisionCommand struct {
	RequestID      RequestID    `json:"requestId"`
	RequestVersion uint64       `json:"decisionVersion"`
	Decision       DecisionKind `json:"decision"`
	ActionDigest   string       `json:"actionDigest"`
	Comment        string       `json:"comment,omitempty"`
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

// Expiry is the atomic outcome of one durable interrupt deadline. Exactly
// one of the three states holds: the response or decision won the race, the
// expiry committed and the run is failed, or another authority owns the run.
type Expiry struct {
	// Raced reports that an accepted response or decision won against the
	// deadline. Nothing was expired and the caller must re-read.
	Raced bool
	// Superseded reports that another authority moved the run first.
	Superseded bool
	Snapshot   runs.Snapshot
}

// Repository is the durable atomic authority seam. Each accepted method must
// persist its control fact, run transition, event, and checkpoint together.
type Repository interface {
	Input(context.Context, runs.Scope, runs.ID, RequestID) (InputRequest, error)
	OpenInput(context.Context, Write, InputRequest, string) (InputRequest, OperationResult, error)
	AcceptInput(context.Context, Write, InputResponseCommand, string, time.Time) (OperationResult, error)
	// ExpireInput atomically settles the input deadline: in one critical
	// section it observes any accepted response, marks the request expired,
	// and fails the run. It exists so acceptance and expiry can never both
	// win and leave the run without a driving workflow.
	ExpireInput(context.Context, Write, RequestID, problem.Details, time.Time) (Expiry, error)
	Approval(context.Context, runs.Scope, runs.ID, RequestID) (ApprovalRequest, error)
	OpenApproval(context.Context, Write, ApprovalRequest, string) (ApprovalRequest, OperationResult, error)
	DecideApproval(context.Context, Write, ApprovalDecisionCommand, string, time.Time) (OperationResult, error)
	// ExpireApproval is the approval counterpart of ExpireInput.
	ExpireApproval(context.Context, Write, RequestID, problem.Details, time.Time) (Expiry, error)
	RequestCancellation(context.Context, Write, string, time.Time) (Cancellation, OperationResult, error)
	RecordCancellation(context.Context, Write, Cancellation) error
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
	// MarkStuck atomically records the stuck marker, durable run event, and
	// durable operator alert. A false result means another scanner already won.
	MarkStuck(context.Context, Progress, time.Time, string) (bool, error)
}

type SchemaValidator interface {
	Validate(context.Context, json.RawMessage, json.RawMessage) error
}

type Authority interface {
	AuthorizeInput(context.Context, runs.Scope, InputRequest) error
	AuthorizeReviewer(context.Context, runs.Scope, ApprovalRequest, DecisionKind) error
	RetryEligibility(context.Context, runs.Scope, runs.Snapshot) (bool, string, error)
	// AuthorizeResume revalidates the complete current authority and material
	// set before a recorded retry restarts a workflow. Recording the retry and
	// resuming it are separate durable acts, and authority revoked between
	// them must stop the resume rather than be inherited from the recording.
	AuthorizeResume(context.Context, runs.Scope, runs.Snapshot) error
}

// Runtime drives the canonical AgentRunWorkflow. Input and approval waits
// live inside the run workflow itself, so opening an interrupt requires no
// separate durable wait; acceptance signals target the run workflow by
// execution generation.
type Runtime interface {
	Signal(context.Context, string, string, json.RawMessage, string) error
	StartChild(context.Context, Child) error
	StopRun(context.Context, runs.Scope, runs.ID, uint64) error
	// ResumeRun must be idempotent for a run, execution generation, and resume
	// key. An empty key identifies the generation-level explicit retry.
	ResumeRun(context.Context, runs.Scope, runs.Snapshot, string, string) error
}

type LeaseRevoker interface {
	RevokeRun(context.Context, runs.Scope, runs.ID) error
}

type CancellationReconciler interface {
	Reconcile(context.Context, runs.Scope, runs.ID, bool) (clear bool, authoritative *runs.State, err error)
}

type Reservation interface {
	ReserveChild(context.Context, ChildBudgetRequest) error
}

// TerminalBudget settles a run's standing budget reservation when a control
// operation — not the durable workflow — is what makes the run terminal.
// Cancellation and discard end a run outside the workflow's own terminal
// transitions, so without this port their usage would never be reconciled and
// their worst-case hold would keep consuming root headroom until it expired.
// The settlement is idempotent and fenced on the run's execution generation,
// so a replayed control command settles nothing twice and a superseded
// generation settles nothing at all. The executor's terminal settlement
// satisfies it.
type TerminalBudget interface {
	SettleRunBudget(ctx context.Context, snapshot runs.Snapshot, release bool) error
}

type ChildBudgetRequest struct {
	Write       Write
	ChildRunID  runs.ID
	Mode        ChildMode
	Digest      string
	RequestedAt time.Time
}

type AlertSink interface {
	Alert(context.Context, string, runs.Scope, runs.ID, runs.State) error
}

func stable(code problem.Code, detail string) problem.Details {
	value := problem.New(code, "")
	value.Detail = detail
	return value
}

// ReplayConflict reports why a recorded control write cannot answer this
// repeat, or nil when it can.
//
// The two faults are deliberately distinct codes. Changed canonical bytes
// under a key already committed to is the governed IDEMPOTENCY_KEY_REUSED case
// (ADR-021 §4): the caller asked for a different command, so no recorded
// outcome can honestly answer it, and a client must fix the request rather
// than retry it. A repeat whose bytes match but whose observed resource
// revision differs is an unrelated fault — the same command aimed at a
// precondition the first request was not made under — and keeps the general
// idempotency conflict, so the two never have to be told apart by their
// message.
func ReplayConflict(recordedDigest, digest string, recordedVersion, version uint64) error {
	switch {
	case recordedDigest != digest:
		return stable(problem.CodeIdempotencyKeyReused, "the idempotency key was already used with different canonical request bytes")
	case recordedVersion != version:
		return stable(problem.CodeIdempotencyConflict, "the idempotency key was already used against a different resource revision")
	}
	return nil
}
