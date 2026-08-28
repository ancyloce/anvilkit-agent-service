// Package dispatch owns the logical agent task and its physical attempts.
//
// A turn used to be a model call this service made itself, so the work and the
// execution of the work could not come apart. Dispatching a turn to a separate
// runtime process separates them permanently: the logical task is what the run
// asked for, and a physical attempt is one execution of it. Everything in this
// package follows from that split — a replacement is a new attempt of the same
// task, only the current attempt may change state, and a result that arrives
// for any other attempt is evidence rather than an outcome.
package dispatch

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"time"

	"github.com/ancyloce/anvilkit-agent-service/internal/agent"
)

// Scope is the mandatory workspace and project boundary every record carries.
type Scope struct{ WorkspaceID, ProjectID string }

// Validate fails closed on an unscoped record: a task without a scope is a
// task no tenant owns.
func (s Scope) Validate() error {
	if s.WorkspaceID == "" || s.ProjectID == "" {
		return fmt.Errorf("dispatch scope: workspace and project are both required")
	}
	return nil
}

// State is the lifecycle vocabulary shared by logical tasks and physical
// attempts.
type State string

const (
	// Accepted is work admitted and not yet observed running.
	Accepted State = "accepted"
	// Running is work a runtime has admitted and is executing.
	Running State = "running"
	// Succeeded and Failed are terminal outcomes of an execution.
	Succeeded State = "succeeded"
	Failed    State = "failed"
	// Expired is work whose own deadline passed before it produced an outcome.
	Expired State = "expired"
	// Canceled is work stopped by an authority outside it.
	Canceled State = "canceled"
	// Superseded is an execution a replacement took over from. It is an
	// attempt state only: what a replacement supersedes is an execution, not
	// the work, and a task whose attempt was replaced is still the same task.
	Superseded State = "superseded"
)

// Terminal reports whether a state admits no further transition. A late result
// for a terminal attempt never mutates it.
func (s State) Terminal() bool {
	switch s {
	case Succeeded, Failed, Expired, Canceled, Superseded:
		return true
	}
	return false
}

// ValidTaskStatus reports whether a state is one a logical task may hold.
func ValidTaskStatus(s State) bool {
	switch s {
	case Accepted, Running, Succeeded, Failed, Expired, Canceled:
		return true
	}
	return false
}

// ValidAttemptStatus reports whether a state is one a physical attempt may
// hold.
func ValidAttemptStatus(s State) bool {
	return s == Superseded || ValidTaskStatus(s)
}

// Task is the logical unit of work: what the run asked a runtime release to
// do, independent of how many times it has been executed.
type Task struct {
	Scope               Scope
	TaskID              string
	RunID, RootRunID    string
	ExecutionGeneration uint64
	DefinitionDigest    string
	// Runtime is pinned when the task is created and never re-resolved. A
	// replacement attempt must reach the release the work was admitted
	// against, whatever the registry would select now.
	Runtime    agent.RuntimeBinding
	Capability string
	// RequestDigest is the canonical digest of what was asked, taken over the
	// content that is the same for every attempt. It is what makes a repeated
	// creation provably the same task rather than a reused identity.
	RequestDigest        string
	Status               State
	Attempts, LeaseEpoch uint64
	ExpiresAt            time.Time
	CreatedAt, UpdatedAt time.Time
}

// Validate holds a task to everything the durable record requires before it
// reaches the database, so a rejection names the field rather than a
// constraint.
func (t Task) Validate() error {
	if err := t.Scope.Validate(); err != nil {
		return err
	}
	switch {
	case t.TaskID == "" || t.RunID == "" || t.RootRunID == "":
		return fmt.Errorf("dispatch task: task, run, and root run identity are all required")
	case t.ExecutionGeneration == 0:
		return fmt.Errorf("dispatch task: an execution generation is required")
	case !validDigest(t.DefinitionDigest) || !validDigest(t.RequestDigest):
		return fmt.Errorf("dispatch task: definition and request digests must be sha256 digests")
	case t.Capability == "":
		return fmt.Errorf("dispatch task: a capability is required")
	case t.ExpiresAt.IsZero():
		return fmt.Errorf("dispatch task: an expiry is required; a task that cannot expire cannot be recovered")
	case !ValidTaskStatus(t.Status):
		return fmt.Errorf("dispatch task: %q is not a task status", t.Status)
	}
	return validRuntime(t.Runtime)
}

// Attempt is one physical execution of one logical task.
type Attempt struct {
	Scope                     Scope
	PhysicalAttemptID, TaskID string
	AttemptNumber, LeaseEpoch uint64
	// FenceTokenDigest is what is persisted of the fence. The raw token is a
	// commit capability: it travels with the task and returns in the result,
	// and storing it would hand every reader of this record the ability to
	// commit an attempt they never ran.
	FenceTokenDigest string
	RuntimeUnitID    string
	Status           State
	// ResultStatementDigest correlates the result that settled this attempt.
	// It is empty until an outcome is registered.
	ResultStatementDigest string
	SignatureKeyID        string
	// FailureReason is a stable governed reason code, never a diagnostic.
	FailureReason                       string
	DispatchedAt, StartedAt, FinishedAt time.Time
	ExpiresAt, CreatedAt, UpdatedAt     time.Time
}

// Execution is the current attempt of a task together with the fence
// capability only the process that opened it holds.
type Execution struct {
	Task    Task
	Attempt Attempt
	// FenceToken is the raw capability. It is dispatched with the task and
	// compared against the stored digest at commit; it is never persisted,
	// logged, or published.
	FenceToken string
}

// Predicate is the complete set of facts a result must still agree with
// before it may change state, as the canonical commit predicate defines it.
// Every field is compared against the authoritative database record inside the
// commit transaction: a result that agrees with ten of them and disagrees with
// the eleventh is a result for work that no longer exists.
type Predicate struct {
	RunID                    string
	TaskID                   string
	ExecutionGeneration      uint64
	PhysicalAttemptID        string
	AttemptNumber            uint64
	LeaseEpoch               uint64
	FenceToken               string
	RuntimeUnitID            string
	RuntimeManifestDigest    string
	RuntimeImageDigest       string
	InvocationProtocolDigest string
}

// Validate refuses an incomplete predicate. A missing field would otherwise
// compare equal to a missing column and turn the fence into a formality.
func (p Predicate) Validate() error {
	switch {
	case p.RunID == "" || p.TaskID == "" || p.PhysicalAttemptID == "":
		return fmt.Errorf("commit predicate: run, task, and physical attempt identity are all required")
	case p.ExecutionGeneration == 0 || p.AttemptNumber == 0 || p.LeaseEpoch == 0:
		return fmt.Errorf("commit predicate: generation, attempt number, and lease epoch are all required")
	case len(p.FenceToken) < minimumFenceTokenLength:
		return fmt.Errorf("commit predicate: a fence token of at least %d characters is required", minimumFenceTokenLength)
	case p.RuntimeUnitID == "":
		return fmt.Errorf("commit predicate: the runtime unit is required")
	case !validDigest(p.RuntimeManifestDigest) || !validDigest(p.RuntimeImageDigest) || !validDigest(p.InvocationProtocolDigest):
		return fmt.Errorf("commit predicate: manifest, image, and protocol digests must be sha256 digests")
	}
	return nil
}

// maximumStatementBytes bounds what one committed statement may occupy. The
// canonical result contract is bounded; a record that admitted more would let
// a runtime decide how much of this service's storage it uses.
const maximumStatementBytes = 1 << 20

// minimumFenceTokenLength is the canonical AgentTask bound. A shorter token
// would be admitted by no runtime, so refusing it here fails at the boundary
// that can explain it.
const minimumFenceTokenLength = 16

// Outcome is what a runtime proposed for one attempt.
type Outcome struct {
	// Statement is the canonical byte sequence the runtime signed. It is
	// registered with a committed outcome and is what a replay reads back.
	Statement []byte
	// Status and ReasonCode are the governed result vocabulary the canonical
	// AgentRuntimeResult carries.
	Status                string
	ReasonCode            string
	ResultStatementDigest string
	SignatureKeyID        string
	// Failed reports whether the outcome terminates the attempt as failed
	// rather than succeeded. It is derived from Status by the caller that
	// understands the result contract, not guessed here.
	Failed     bool
	ObservedAt time.Time
}

// Validate refuses an outcome that could not be correlated or audited.
func (o Outcome) Validate() error {
	switch {
	case o.Status == "":
		return fmt.Errorf("runtime outcome: a governed status is required")
	case o.ReasonCode == "":
		return fmt.Errorf("runtime outcome: a governed reason code is required")
	case !validDigest(o.ResultStatementDigest):
		return fmt.Errorf("runtime outcome: the result statement digest must be a sha256 digest")
	case o.SignatureKeyID == "":
		return fmt.Errorf("runtime outcome: the signing key identity is required for audit")
	case o.ObservedAt.IsZero():
		return fmt.Errorf("runtime outcome: an observation time is required")
	case !o.Failed && len(o.Statement) == 0:
		return fmt.Errorf("runtime outcome: a committed outcome must carry the statement it committed")
	case len(o.Statement) > maximumStatementBytes:
		return fmt.Errorf("runtime outcome: the statement exceeds the bounded contract")
	}
	return nil
}

// Disposition names what happened to a result that did not commit. Every value
// is a durable evidence category, not a diagnostic string.
type Disposition string

const (
	// DispositionDuplicate is the same result statement arriving again for a
	// task that already committed it. It is the idempotent case: the recorded
	// outcome stands and nothing changes.
	DispositionDuplicate Disposition = "duplicate"
	// DispositionStaleFence is a result whose fence, lease, attempt, or
	// runtime binding no longer matches the authoritative record.
	DispositionStaleFence Disposition = "stale-fence"
	// DispositionSuperseded is a result from an attempt a replacement took
	// over from.
	DispositionSuperseded Disposition = "superseded"
	// DispositionTerminal is a result for an attempt or task that already
	// reached a terminal state.
	DispositionTerminal Disposition = "terminal"
	// DispositionExpired is a result that arrived after the task's own
	// deadline.
	DispositionExpired Disposition = "expired"
	// DispositionCanceled is a result for work whose lease was revoked.
	DispositionCanceled Disposition = "canceled"
	// DispositionUnbound is a result naming a task or attempt this service has
	// no record of.
	DispositionUnbound Disposition = "unbound"
)

// Committed reports whether a disposition means state changed. Only an empty
// disposition does: every named one is a reason the result was recorded and
// nothing else.
func (d Disposition) Committed() bool { return d == "" }

// Evidence is the durable account of a result that did not commit.
type Evidence struct {
	Scope                     Scope
	TaskID, RunID             string
	PhysicalAttemptID         string
	AttemptNumber, LeaseEpoch uint64
	ResultStatementDigest     string
	SignatureKeyID            string
	Disposition               Disposition
	Reason                    string
	RecordedAt                time.Time
}

// Result is what a commit attempt reports back.
type Result struct {
	// Disposition is empty when the result committed. Otherwise it names why
	// the result became evidence.
	Disposition Disposition
	// Reason is the bounded internal explanation recorded with the evidence.
	Reason string
	// Task and Attempt are the authoritative records after the operation.
	Task    Task
	Attempt Attempt
}

// Digest is the persistent comparison value for a fence token. It is a plain
// digest by design: a reader may prove which token produced it, and may not
// reconstruct the token.
func Digest(value string) string {
	sum := sha256.Sum256([]byte(value))
	return "sha256:" + hex.EncodeToString(sum[:])
}

func validDigest(value string) bool {
	if len(value) != 71 || value[:7] != "sha256:" {
		return false
	}
	_, err := hex.DecodeString(value[7:])
	return err == nil
}

func validRuntime(binding agent.RuntimeBinding) error {
	switch {
	case binding.RuntimeUnitID == "":
		return fmt.Errorf("dispatch task: the pinned runtime unit is required")
	case !validDigest(binding.RuntimeManifestDigest) || !validDigest(binding.RuntimeImageDigest) || !validDigest(binding.InvocationProtocolDigest):
		return fmt.Errorf("dispatch task: the pinned runtime manifest, image, and protocol digests must be sha256 digests")
	case binding.RuntimeAudience == "":
		return fmt.Errorf("dispatch task: the pinned runtime audience is required")
	}
	return nil
}

// The stable reason codes this service records against an attempt it ended
// itself. A runtime's own failure carries the governed runtime-result reason
// instead; these name the cases where no runtime answered at all.
const (
	// ReasonReplaced is recorded when a replacement execution took the task
	// over. It is the ordinary recovery case, not a failure of the attempt.
	ReasonReplaced = "ATTEMPT_REPLACED"
	// ReasonLeaseRevoked is recorded when cancellation revoked the lease.
	ReasonLeaseRevoked = "LEASE_REVOKED"
	// ReasonDeadlineExceeded is recorded when the attempt's own deadline
	// passed before an outcome arrived.
	ReasonDeadlineExceeded = "ATTEMPT_DEADLINE_EXCEEDED"
	// ReasonDispatchFailed is recorded when the dispatch itself did not reach
	// a runtime.
	ReasonDispatchFailed = "DISPATCH_FAILED"
	// ReasonResultUnattributable is recorded when what came back from a
	// dispatch could not be attributed to the attempt it was dispatched for —
	// a statement whose digest does not describe it, a signature no approved
	// key produced, or a result addressed to other work — so the attempt ends
	// without an outcome rather than staying the task's current execution.
	ReasonResultUnattributable = "RESULT_UNATTRIBUTABLE"
	// ReasonResultContractInvalid is recorded when a dispatch answered with a
	// document that is not a canonical result this service can account for.
	ReasonResultContractInvalid = "RESULT_CONTRACT_INVALID"
	// ReasonTurnAbandoned is recorded when the turn holding an attempt ended
	// before an outcome arrived — its own deadline passed or its process is
	// stopping — so nothing will wait for the answer any more.
	ReasonTurnAbandoned = "TURN_ABANDONED"
	// ReasonRunTerminal is recorded against work still open when its run
	// reached a terminal state: the run has an answer, and an execution that
	// outlived it can no longer change anything.
	ReasonRunTerminal = "RUN_TERMINAL"
)

// ValidReasonCode reports whether a value is shaped like the stable reason
// codes the durable record admits. The shape is checked rather than the
// vocabulary: a runtime's governed reason and this service's own reasons share
// one column, and inventing a closed union of both here would make every new
// governed runtime reason a schema change.
func ValidReasonCode(value string) bool {
	if len(value) < 3 || len(value) > 64 {
		return false
	}
	if value[0] < 'A' || value[0] > 'Z' {
		return false
	}
	for _, character := range value[1:] {
		switch {
		case character >= 'A' && character <= 'Z':
		case character >= '0' && character <= '9':
		case character == '_':
		default:
			return false
		}
	}
	return true
}

// Registration is the committed outcome of a logical task. There is at most
// one, ever: it is what makes redelivery of the same result idempotent and a
// different result for settled work a contradiction rather than an update.
type Registration struct {
	TaskID, PhysicalAttemptID                      string
	AttemptNumber, LeaseEpoch, ExecutionGeneration uint64
	ResultStatementDigest, SignatureKeyID          string
	Status, ReasonCode                             string
	// Statement is the canonical result the task committed. It is kept so a
	// durable step that committed and then failed before recording its own
	// output can be re-executed: the replay reads the answer the task already
	// has instead of executing the work a second time.
	Statement   []byte
	CommittedAt time.Time
}

// Evaluate decides what a result may do, given the authoritative records the
// caller read inside its own transaction.
//
// It is a pure function on purpose. Two repositories implement the same
// predicate — one over memory for tests, one over PostgreSQL for production —
// and a predicate written twice is a predicate that will eventually disagree
// with itself. The reason strings name the field that disagreed and never the
// value: a fence token in a diagnostic is a fence token in a log.
func Evaluate(task Task, attempt Attempt, committed *Registration, request Settle, now time.Time) (Disposition, string) {
	if committed != nil && committed.ResultStatementDigest == request.Outcome.ResultStatementDigest {
		return DispositionDuplicate, "the task already committed this result statement"
	}
	if committed != nil {
		return DispositionTerminal, "the task already committed a different result statement"
	}
	switch task.Status {
	case Canceled:
		return DispositionCanceled, "the task's lease was revoked before the result arrived"
	case Expired:
		return DispositionExpired, "the task expired before the result arrived"
	case Succeeded, Failed:
		return DispositionTerminal, "the task already reached a terminal state"
	}
	switch attempt.Status {
	case Superseded:
		return DispositionSuperseded, "a replacement execution took the task over"
	case Canceled:
		return DispositionCanceled, "the attempt's lease was revoked before the result arrived"
	case Expired:
		return DispositionExpired, "the attempt expired before the result arrived"
	case Succeeded, Failed:
		return DispositionTerminal, "the attempt already reached a terminal state"
	}
	for _, comparison := range []struct {
		field            string
		wanted, observed string
	}{
		{"run", task.RunID, request.Predicate.RunID},
		{"task", task.TaskID, request.Predicate.TaskID},
		{"physical attempt", attempt.PhysicalAttemptID, request.Predicate.PhysicalAttemptID},
		{"fence token", attempt.FenceTokenDigest, Digest(request.Predicate.FenceToken)},
		{"runtime unit", task.Runtime.RuntimeUnitID, request.Predicate.RuntimeUnitID},
		{"runtime manifest digest", task.Runtime.RuntimeManifestDigest, request.Predicate.RuntimeManifestDigest},
		{"runtime image digest", task.Runtime.RuntimeImageDigest, request.Predicate.RuntimeImageDigest},
		{"invocation protocol digest", task.Runtime.InvocationProtocolDigest, request.Predicate.InvocationProtocolDigest},
	} {
		if comparison.wanted != comparison.observed {
			return DispositionStaleFence, "the result's " + comparison.field + " does not match the authoritative record"
		}
	}
	for _, comparison := range []struct {
		field            string
		wanted, observed uint64
	}{
		{"execution generation", task.ExecutionGeneration, request.Predicate.ExecutionGeneration},
		{"attempt number", attempt.AttemptNumber, request.Predicate.AttemptNumber},
		{"lease epoch", attempt.LeaseEpoch, request.Predicate.LeaseEpoch},
	} {
		if comparison.wanted != comparison.observed {
			return DispositionStaleFence, "the result's " + comparison.field + " does not match the authoritative record"
		}
	}
	// Expiry is checked last so a result that is stale for a stronger reason
	// is recorded under that reason: an expired result from a superseded
	// attempt is evidence of a replacement, not of a slow runtime.
	if now.After(task.ExpiresAt) {
		return DispositionExpired, "the task's deadline passed before the result arrived"
	}
	if now.After(attempt.ExpiresAt) {
		return DispositionExpired, "the attempt's deadline passed before the result arrived"
	}
	return "", ""
}
