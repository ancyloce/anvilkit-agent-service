package dispatch

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"time"

	"github.com/ancyloce/anvilkit-agent-service/internal/agent"
)

// Repository is the durable record of logical tasks and physical attempts.
//
// Every operation on it is a state transition the database decides, not one
// the caller computes and then writes: opening an attempt supersedes the
// current one and issues the next lease epoch in the same transaction, and
// committing a result compares the whole predicate and registers the outcome
// in the same transaction. Splitting either would leave a window in which two
// executions of one task are both current, or in which a result has changed
// state without being recorded.
type Repository interface {
	// EnsureTask creates the logical task or returns the existing one. It is
	// the idempotent half of dispatch: a replayed durable step must find the
	// task it already created. A repeat that carries different content is a
	// reused identity and is refused.
	EnsureTask(ctx context.Context, task Task) (Task, error)
	// OpenAttempt supersedes any current attempt of the task and opens a new
	// one with the next attempt number, the next lease epoch, and the supplied
	// fence digest.
	OpenAttempt(ctx context.Context, open Open) (Task, Attempt, error)
	// MarkDispatched records that the task left this process for the runtime.
	MarkDispatched(ctx context.Context, scope Scope, attemptID string, at time.Time) error
	// CloseAttempt ends an open attempt this service will not wait on any
	// longer, as failed with a stable reason. The task stays open: whether
	// the work is tried again is the workflow's decision, exactly as it is
	// for an execution the runtime itself reported failed. Closing an attempt
	// that already reached a terminal state changes nothing.
	CloseAttempt(ctx context.Context, scope Scope, attemptID, reason string, at time.Time) error
	// Commit applies the fenced conditional commit and records evidence for a
	// result that does not satisfy it.
	Commit(ctx context.Context, request Settle) (Result, error)
	// RecordEvidence stores an outcome that never reached the commit
	// predicate — an undecodable or unbound result.
	RecordEvidence(ctx context.Context, evidence Evidence) error
	// CancelRun revokes every open task and attempt of one run and reports how
	// many were open. Cancellation is what makes a later result uncommittable
	// rather than merely unwelcome.
	CancelRun(ctx context.Context, scope Scope, runID, reason string, at time.Time) (int, error)
	// Load reads a task and its attempts, newest attempt last.
	Load(ctx context.Context, scope Scope, taskID string) (Task, []Attempt, bool, error)
	// Registration reads the committed outcome of a logical task, if it has
	// one. It is what makes a re-executed durable step read the answer instead
	// of executing the work again.
	Registration(ctx context.Context, scope Scope, taskID string) (Registration, bool, error)
}

// Open is a request for the next physical attempt of one logical task.
type Open struct {
	Scope            Scope
	TaskID           string
	FenceTokenDigest string
	RuntimeUnitID    string
	// SupersededReason is the stable reason code recorded against the attempt
	// this open replaces, so a replacement is never silent.
	SupersededReason string
	ExpiresAt        time.Time
	At               time.Time
}

// Settle is one result offered for one attempt.
type Settle struct {
	Scope     Scope
	RunID     string
	Predicate Predicate
	Outcome   Outcome
}

// Tokens mints fence capabilities. It is a port because the fence is a
// capability: a deployment that wants it minted by a key service replaces this
// and nothing else.
type Tokens interface {
	FenceToken() (string, error)
}

// RandomTokens mints fence tokens from the system source. The alphabet is the
// canonical AgentTask fence-token alphabet, so a minted token is one the
// contract admits.
type RandomTokens struct{}

func (RandomTokens) FenceToken() (string, error) {
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return "", fmt.Errorf("mint fence token: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(raw), nil
}

// Clock is the coordinator's only source of time.
type Clock interface{ Now() time.Time }

// Coordinator turns the four durable operations a dispatched turn needs —
// create the work, open an execution, record that it left, settle what came
// back — into transitions the repository can hold atomically.
type Coordinator struct {
	repository Repository
	tokens     Tokens
	clock      Clock
	lease      time.Duration
}

// Config is the coordinator's dependency set. Every field is required: a
// coordinator missing any one of them could open an execution it cannot fence,
// time, or record.
type Config struct {
	Repository Repository
	Tokens     Tokens
	Clock      Clock
	// Lease is how long one attempt may run before its own deadline passes.
	// It bounds recovery: an attempt nobody can hear from stops being current
	// after it, rather than holding the task for ever.
	Lease time.Duration
}

func New(cfg Config) (*Coordinator, error) {
	if cfg.Repository == nil || cfg.Tokens == nil || cfg.Clock == nil {
		return nil, fmt.Errorf("dispatch coordinator: a repository, a fence token source, and a clock are all required")
	}
	if cfg.Lease <= 0 {
		return nil, fmt.Errorf("dispatch coordinator: a positive attempt lease is required")
	}
	return &Coordinator{repository: cfg.Repository, tokens: cfg.Tokens, clock: cfg.Clock, lease: cfg.Lease}, nil
}

// Request is what one turn asks the coordinator to make executable.
type Request struct {
	Scope               Scope
	TaskID              string
	RunID, RootRunID    string
	ExecutionGeneration uint64
	DefinitionDigest    string
	Runtime             agent.RuntimeBinding
	Capability          string
	RequestDigest       string
	// Replacing is the stable reason code recorded against the attempt this
	// open replaces. The first attempt of a task leaves it empty.
	Replacing string
}

// Open creates the logical task if it does not exist and opens the next
// physical attempt of it, with a new attempt number, lease epoch, and fence.
//
// It is safe to call repeatedly. A replay after a crash finds the task it
// already created and opens a replacement rather than reusing an attempt whose
// fence this process can no longer produce: the raw token was never persisted,
// so an attempt opened by a previous process cannot be continued by this one —
// only replaced, which is what makes the earlier one permanently uncommittable.
func (c *Coordinator) Open(ctx context.Context, request Request) (Execution, error) {
	now := c.clock.Now().UTC()
	expiry := now.Add(c.lease)
	task := Task{
		Scope:               request.Scope,
		TaskID:              request.TaskID,
		RunID:               request.RunID,
		RootRunID:           request.RootRunID,
		ExecutionGeneration: request.ExecutionGeneration,
		DefinitionDigest:    request.DefinitionDigest,
		Runtime:             request.Runtime,
		Capability:          request.Capability,
		RequestDigest:       request.RequestDigest,
		Status:              Accepted,
		ExpiresAt:           expiry,
		CreatedAt:           now,
		UpdatedAt:           now,
	}
	if err := task.Validate(); err != nil {
		return Execution{}, err
	}
	stored, err := c.repository.EnsureTask(ctx, task)
	if err != nil {
		return Execution{}, err
	}
	token, err := c.tokens.FenceToken()
	if err != nil {
		return Execution{}, err
	}
	reason := request.Replacing
	if reason == "" {
		reason = ReasonReplaced
	}
	openedTask, attempt, err := c.repository.OpenAttempt(ctx, Open{
		Scope:            request.Scope,
		TaskID:           request.TaskID,
		FenceTokenDigest: Digest(token),
		RuntimeUnitID:    stored.Runtime.RuntimeUnitID,
		SupersededReason: reason,
		ExpiresAt:        expiry,
		At:               now,
	})
	if err != nil {
		return Execution{}, err
	}
	return Execution{Task: openedTask, Attempt: attempt, FenceToken: token}, nil
}

// Dispatched records that the attempt was handed to its runtime. It is written
// before the dispatch is observed to succeed: an attempt that left this process
// and was never recorded as having left is exactly the state recovery cannot
// tell apart from one that never went.
func (c *Coordinator) Dispatched(ctx context.Context, execution Execution) error {
	return c.repository.MarkDispatched(ctx, execution.Task.Scope, execution.Attempt.PhysicalAttemptID, c.clock.Now().UTC())
}

// Close ends an open attempt this process will not wait on any longer, as
// failed with a stable reason.
//
// It exists for the answers a dispatch can give that are neither an outcome
// nor a reason to replace the execution: a result that cannot be attributed to
// the attempt, a document that is not a canonical result, a turn whose own
// deadline passed. Left alone, such an attempt would stay the task's current
// execution until its lease ran out — the runtime boundary would keep serving
// its callbacks, and the record would report an active execution of work the
// control plane had already given up on. A replacement supersedes it; when
// there will be no replacement, this is what ends it.
func (c *Coordinator) Close(ctx context.Context, execution Execution, reason string) error {
	if !ValidReasonCode(reason) {
		return fmt.Errorf("dispatch coordinator: a stable close reason code is required")
	}
	return c.repository.CloseAttempt(ctx, execution.Task.Scope, execution.Attempt.PhysicalAttemptID, reason, c.clock.Now().UTC())
}

// Settle applies the full fenced conditional commit. A result that satisfies
// the predicate transitions its attempt and its task and registers its result
// statement, atomically. A result that does not is recorded as evidence and
// changes nothing.
func (c *Coordinator) Settle(ctx context.Context, request Settle) (Result, error) {
	if err := request.Scope.Validate(); err != nil {
		return Result{}, err
	}
	if err := request.Predicate.Validate(); err != nil {
		return Result{}, err
	}
	if err := request.Outcome.Validate(); err != nil {
		return Result{}, err
	}
	return c.repository.Commit(ctx, request)
}

// Unbound records a result this service cannot attribute to any attempt it
// opened. It is evidence by construction: there is no state such a result
// could mutate even if every other check passed.
func (c *Coordinator) Unbound(ctx context.Context, scope Scope, runID, taskID, attemptID, statementDigest, keyID, reason string) error {
	return c.repository.RecordEvidence(ctx, Evidence{
		Scope:                 scope,
		TaskID:                taskID,
		RunID:                 runID,
		PhysicalAttemptID:     attemptID,
		ResultStatementDigest: statementDigest,
		SignatureKeyID:        keyID,
		Disposition:           DispositionUnbound,
		Reason:                reason,
		RecordedAt:            c.clock.Now().UTC(),
	})
}

// CancelRun revokes every open task of a run and reports how many were open.
func (c *Coordinator) CancelRun(ctx context.Context, scope Scope, runID, reason string) (int, error) {
	return c.repository.CancelRun(ctx, scope, runID, reason, c.clock.Now().UTC())
}

// Load reads a task and its attempts.
func (c *Coordinator) Load(ctx context.Context, scope Scope, taskID string) (Task, []Attempt, bool, error) {
	return c.repository.Load(ctx, scope, taskID)
}

// Settled reads the answer a logical task already committed.
//
// A durable step that committed and then failed before recording its own
// output is re-executed by the engine. Reading the committed answer is what
// makes that safe: the work is not done again, the provider is not called
// again, and the run sees the same decision it already reached.
func (c *Coordinator) Settled(ctx context.Context, scope Scope, taskID string) (Registration, bool, error) {
	return c.repository.Registration(ctx, scope, taskID)
}

// TaskID derives the logical task identity from the durable operation that
// owns the work. It is a pure function of that operation, so every replay of
// the step converges on the same logical task instead of creating a second one
// for the same work.
func TaskID(operationKey string) string {
	sum := sha256.Sum256([]byte("agent-task\x00" + operationKey))
	return "task." + hex.EncodeToString(sum[:16])
}

// AttemptID derives the physical attempt identity from the task and the
// attempt number the repository assigned. Deriving rather than minting keeps
// the identity reproducible from the durable record: the same numbered attempt
// of the same task is the same attempt, whichever process reads it.
func AttemptID(taskID string, number uint64) string {
	sum := sha256.Sum256([]byte(fmt.Sprintf("physical-attempt\x00%s\x00%d", taskID, number)))
	return "attempt." + hex.EncodeToString(sum[:16])
}
