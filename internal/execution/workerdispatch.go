package execution

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"strconv"
	"sync"
	"time"

	"github.com/ancyloce/anvilkit-agent-service/internal/authority"
	"github.com/ancyloce/anvilkit-agent-service/internal/problem"
	"github.com/ancyloce/anvilkit-agent-service/internal/recovery"
	"github.com/ancyloce/anvilkit-agent-service/internal/scheduler"
	"github.com/ancyloce/anvilkit-agent-service/internal/usage"
)

// TaskScheduler is the fenced dispatch boundary tool executions run through.
// The scheduler module satisfies it. Every part of the record — task, lease,
// fence, accepted result, and the replayable output — is durable, and
// AcceptedOutput is how a replay in this or any successor process reads what
// was already accepted instead of executing again.
type TaskScheduler interface {
	Create(context.Context, scheduler.Create) (scheduler.Task, error)
	Lease(ctx context.Context, scope scheduler.Scope, id scheduler.TaskID, owner string) (scheduler.Lease, error)
	// Heartbeat renews the active lease before its TTL elapses. Renewal is
	// fenced on the complete lease identity and the exact expected expiry, so
	// a reclaimed or superseded lease can never be revived by a late renewal.
	Heartbeat(ctx context.Context, scope scheduler.Scope, lease scheduler.Lease, expectedExpiry time.Time) (scheduler.Lease, error)
	ReclaimExpired(ctx context.Context, scope scheduler.Scope, id scheduler.TaskID) (bool, error)
	AcceptResult(ctx context.Context, scope scheduler.Scope, result scheduler.Result, output []byte) (scheduler.Acceptance, error)
	AcceptedOutput(ctx context.Context, scope scheduler.Scope, id scheduler.TaskID) ([]byte, scheduler.Result, error)
	Get(ctx context.Context, scope scheduler.Scope, id scheduler.TaskID) (scheduler.Task, error)
}

// RecoveryEpochs reads the external non-rollback recovery epoch every task is
// fenced under.
type RecoveryEpochs interface {
	Current(context.Context) (recovery.Epoch, error)
}

// UsageAcceptor records one deduplicated usage observation per physical
// attempt, independent of result acceptance. The usage pipeline satisfies it.
type UsageAcceptor interface {
	Accept(context.Context, usage.Observation) (bool, error)
}

// ToolReservations proves the standing zero-cost reservation a run's tool
// dispatch runs under: Ensure records the reservation once per run and
// answers whether it is still current. Kernel tool capabilities are read-only
// and bill nothing, so the reservation's upper bound is zero — its purpose is
// the accountable identity every task and usage observation is fenced to.
type ToolReservations interface {
	Ensure(ctx context.Context, workspaceID, projectID, rootRunID, runID, reservationID string, now time.Time) (bool, error)
}

// MemoryToolReservations is the in-memory reservation record for tests.
type MemoryToolReservations struct {
	lock sync.Mutex
	rows map[string]bool
}

func NewMemoryToolReservations() *MemoryToolReservations {
	return &MemoryToolReservations{rows: make(map[string]bool)}
}

func (r *MemoryToolReservations) Ensure(_ context.Context, workspaceID, projectID, _, _, reservationID string, _ time.Time) (bool, error) {
	r.lock.Lock()
	defer r.lock.Unlock()
	r.rows[workspaceID+"\x00"+projectID+"\x00"+reservationID] = true
	return true, nil
}

// ScheduledToolExecutor dispatches every authorized tool execution as a
// fenced worker task: the current authority and capability grants gate task
// creation, a monotonic lease fences the attempt, the controlled worker
// executes only its declared capability against immutable inputs, the result
// is accepted through the full fence, and every physical attempt — winning or
// failing — contributes a usage observation. It sits behind the executor's
// existing tool boundary, so the Tool Guard's decision still precedes it.
type ScheduledToolExecutor struct {
	scheduler    TaskScheduler
	epochs       RecoveryEpochs
	authority    AuthorityProvider
	material     ToolMaterial
	worker       ToolExecutor
	usage        UsageAcceptor
	reservations ToolReservations
	clock        Clock
	owner        string
	build        string
}

func NewScheduledToolExecutor(taskScheduler TaskScheduler, epochs RecoveryEpochs, source AuthorityProvider, material ToolMaterial, worker ToolExecutor, usageAcceptor UsageAcceptor, reservations ToolReservations, clock Clock, owner, buildIdentity string) (*ScheduledToolExecutor, error) {
	if taskScheduler == nil || epochs == nil || source == nil || material == nil || worker == nil || usageAcceptor == nil || reservations == nil || clock == nil {
		return nil, fmt.Errorf("scheduled tool executor: scheduler, recovery epochs, authority, tool material, worker, usage, reservations, and clock are required")
	}
	if owner == "" || len(owner) > 128 || !validDigestString(buildIdentity) {
		return nil, fmt.Errorf("scheduled tool executor: a bounded owner identity and the pinned build identity are required")
	}
	return &ScheduledToolExecutor{scheduler: taskScheduler, epochs: epochs, authority: source, material: material, worker: worker, usage: usageAcceptor, reservations: reservations, clock: clock, owner: owner, build: buildIdentity}, nil
}

var _ ToolExecutor = (*ScheduledToolExecutor)(nil)

// RetrievalTools forwards the declaration of the worker this fenced dispatch
// path wraps. The fencing changes when and how often a tool runs, never what
// it needs, so a networkless worker stays networkless behind it and a worker
// that needs the mediated exchange does not lose the declaration by being
// dispatched through a lease.
func (e *ScheduledToolExecutor) RetrievalTools() []string {
	declaring, capable := e.worker.(RetrievalCapable)
	if !capable {
		return nil
	}
	return declaring.RetrievalTools()
}

var _ RetrievalCapable = (*ScheduledToolExecutor)(nil)

func (e *ScheduledToolExecutor) Execute(ctx context.Context, invocation ToolInvocation) (ToolResult, error) {
	if invocation.IdempotencyKey == "" || invocation.ToolID == "" || invocation.WorkspaceID == "" || invocation.ProjectID == "" || invocation.RunID == "" || invocation.RootRunID == "" || invocation.ActorID == "" || invocation.ExecutionGeneration == 0 || invocation.Traceparent == "" {
		return ToolResult{}, fmt.Errorf("scheduled tool executor: a complete fenced invocation identity is required")
	}
	definition, known := e.material.ToolDefinition(invocation.ToolID)
	if !known {
		return ToolResult{}, fmt.Errorf("scheduled tool executor: %q is not a tool the approved catalog attests", invocation.ToolID)
	}
	epoch, err := e.epochs.Current(ctx)
	if err != nil {
		return ToolResult{}, fmt.Errorf("read non-rollback recovery epoch: %w", err)
	}
	current, err := e.authority.Current(ctx, authority.Scope{WorkspaceID: invocation.WorkspaceID, ProjectID: invocation.ProjectID, ActorID: invocation.ActorID})
	if err != nil {
		return ToolResult{}, fmt.Errorf("read current authority before dispatch: %w", err)
	}
	policyAllowed := false
	for _, capability := range current.Grants.AllowedCapabilities {
		if capability == definition.Capability {
			policyAllowed = true
			break
		}
	}
	now := e.clock.Now()
	if now.IsZero() {
		return ToolResult{}, fmt.Errorf("scheduled tool executor: authoritative time is unavailable")
	}
	reservationID := "run-budget:" + invocation.RunID
	reservationCurrent, err := e.reservations.Ensure(ctx, invocation.WorkspaceID, invocation.ProjectID, invocation.RootRunID, invocation.RunID, reservationID, now)
	if err != nil {
		return ToolResult{}, fmt.Errorf("ensure standing tool reservation: %w", err)
	}
	taskID := TaskIdentity(invocation.IdempotencyKey)
	argumentsSum := sha256.Sum256(invocation.Arguments)
	scope := scheduler.Scope{WorkspaceID: invocation.WorkspaceID, ProjectID: invocation.ProjectID}
	task, err := e.scheduler.Create(ctx, scheduler.Create{
		Scope:               scope,
		TaskID:              taskID,
		RunID:               invocation.RunID,
		RootRunID:           invocation.RootRunID,
		RecoveryEpoch:       uint64(epoch),
		ExecutionGeneration: invocation.ExecutionGeneration,
		Capability:          definition.Capability,
		// Kernel tool capabilities are read-only and carry no incremental
		// billable cost: the run's standing zero-cost reservation is the
		// accountable identity they dispatch under, re-proved current here
		// together with the run's authority.
		ReservationID:      reservationID,
		ReservationCurrent: reservationCurrent && current.MaterialComplete() && current.Active(),
		PolicyAllowed:      policyAllowed,
		InputDigest:        "sha256:" + hex.EncodeToString(argumentsSum[:]),
		InputObjectKey:     "inputs/" + string(taskID),
		CreatedAt:          now,
	})
	if err != nil {
		return ToolResult{}, fmt.Errorf("dispatch fenced tool task: %w", err)
	}
	if task.State == scheduler.Completed {
		// The task already settled in a prior execution — possibly in a prior
		// process. The durably recorded accepted result and its replayable
		// output answer; the worker never executes again.
		return e.replayAccepted(ctx, scope, taskID)
	}
	if task.State == scheduler.Leased {
		if _, err := e.scheduler.ReclaimExpired(ctx, scope, taskID); err != nil {
			return ToolResult{}, fmt.Errorf("reclaim expired tool lease: %w", err)
		}
	}
	lease, err := e.scheduler.Lease(ctx, scope, taskID, e.owner)
	if err != nil {
		return ToolResult{}, fmt.Errorf("lease fenced tool task: %w", err)
	}
	started := e.clock.Now()
	// The worker runs under a lease that is renewed while it executes. If
	// renewal fails, the lease has been reclaimed or superseded: the worker
	// context is cancelled so the stale attempt stops promptly, and its late
	// result is fenced out of acceptance below.
	executed := e.executeUnderLease(ctx, scope, lease, invocation, epoch)
	lease = executed.lease
	output, workerErr := executed.output, executed.workerErr
	finished := e.clock.Now()
	elapsed := finished.Sub(started).Milliseconds()
	if elapsed < 0 {
		elapsed = 0
	}
	observation := usage.Observation{
		WorkspaceID:         invocation.WorkspaceID,
		ProjectID:           invocation.ProjectID,
		ObservationID:       string(lease.PhysicalAttemptID) + ":tool-final",
		RootRunID:           invocation.RootRunID,
		RunID:               invocation.RunID,
		TaskID:              string(taskID),
		RecoveryEpoch:       uint64(epoch),
		ExecutionGeneration: invocation.ExecutionGeneration,
		PhysicalAttemptID:   string(lease.PhysicalAttemptID),
		ReservationID:       reservationID,
		Meter:               "worker-duration",
		Quantity:            strconv.FormatInt(elapsed, 10),
		Unit:                "millisecond",
		Currency:            "USD",
		CostMicros:          0,
		MeterSequence:       1,
		Final:               true,
		ObservedAt:          finished,
		Provider:            e.owner,
		BuildIdentity:       e.build,
		Traceparent:         invocation.Traceparent,
	}
	// Every physical attempt contributes usage, independent of whether its
	// result is accepted or even produced.
	if _, usageErr := e.usage.Accept(ctx, observation); usageErr != nil {
		return ToolResult{}, fmt.Errorf("record tool attempt usage: %w", usageErr)
	}
	if executed.leaseLost {
		// The attempt's usage is recorded above; its outcome is decided by the
		// durable record, never by this superseded execution.
		return e.convergeAfterLeaseLoss(ctx, scope, taskID)
	}
	if workerErr != nil {
		return ToolResult{}, workerErr
	}
	outputSum := sha256.Sum256(output.Output)
	acceptance, err := e.scheduler.AcceptResult(ctx, scope, scheduler.Result{
		TaskID:              taskID,
		RecoveryEpoch:       task.RecoveryEpoch,
		ExecutionGeneration: task.ExecutionGeneration,
		PhysicalAttemptID:   lease.PhysicalAttemptID,
		LeaseEpoch:          lease.LeaseEpoch,
		FenceToken:          lease.FenceToken,
		Capability:          definition.Capability,
		BuildIdentity:       e.build,
		ArtifactID:          "tool-output." + hex.EncodeToString(outputSum[:16]),
		ArtifactDigest:      "sha256:" + hex.EncodeToString(outputSum[:]),
		PendingObjectKey:    fmt.Sprintf("pending/%s/r%d/g%d/%s/output.json", taskID, task.RecoveryEpoch, task.ExecutionGeneration, lease.PhysicalAttemptID),
		CompletedAt:         finished,
	}, output.Output)
	if err != nil {
		var details problem.Details
		if errors.As(err, &details) && details.Code == string(problem.CodeWorkerFenceStale) {
			// A late result: the lease expired or was reclaimed between the
			// last renewal and acceptance. The fence recorded the diagnostic
			// and changed no state; the durable record decides what happened.
			return e.convergeAfterLeaseLoss(ctx, scope, taskID)
		}
		return ToolResult{}, fmt.Errorf("accept fenced tool result: %w", err)
	}
	if !acceptance.Accepted && !acceptance.Duplicate {
		return ToolResult{}, fmt.Errorf("scheduled tool executor: the fenced result was neither accepted nor a recorded duplicate")
	}
	return output, nil
}

// TaskIdentity derives the deterministic fenced task identity one
// invocation's idempotency key maps to; a replay in any process addresses
// the same durable task.
func TaskIdentity(idempotencyKey string) scheduler.TaskID {
	sum := sha256.Sum256([]byte(idempotencyKey))
	return scheduler.TaskID("task." + hex.EncodeToString(sum[:16]))
}

// leasedExecution is the outcome of one worker execution driven under lease
// renewal.
type leasedExecution struct {
	lease     scheduler.Lease
	output    ToolResult
	workerErr error
	leaseLost bool
}

// executeUnderLease runs the worker while renewing the lease at a fraction of
// its TTL. A failed renewal cancels the worker context and marks the lease
// lost; the worker's return is always awaited so no execution is abandoned
// mid-flight.
//
// The non-rollback recovery epoch is re-read on the same beat as the renewal.
// The epoch is read once before dispatch, so an attempt that started before a
// restore would otherwise keep renewing its lease and keep running against a
// fabric that has since been restored underneath it — its result refused only
// at the very end, after the whole execution had been spent. An advanced epoch
// is therefore treated exactly as a lost lease: the worker is cancelled at the
// next beat and the attempt converges against the durable record.
func (e *ScheduledToolExecutor) executeUnderLease(ctx context.Context, scope scheduler.Scope, lease scheduler.Lease, invocation ToolInvocation, dispatched recovery.Epoch) leasedExecution {
	workerCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	type outcome struct {
		output ToolResult
		err    error
	}
	done := make(chan outcome, 1)
	go func() {
		output, err := e.worker.Execute(workerCtx, invocation)
		done <- outcome{output: output, err: err}
	}()
	interval := lease.ExpiresAt.Sub(lease.IssuedAt) / 3
	if interval < time.Millisecond {
		interval = time.Millisecond
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	current := lease
	lost := false
	for {
		select {
		case result := <-done:
			return leasedExecution{lease: current, output: result.output, workerErr: result.err, leaseLost: lost}
		case <-ticker.C:
			if lost {
				continue
			}
			// A register that cannot be read decides nothing: an unreachable
			// register is not evidence that the epoch moved, and abandoning a
			// live attempt on that basis would turn a register outage into
			// lost work. The renewal below still fences the attempt on the
			// lease itself.
			if epoch, err := e.epochs.Current(ctx); err == nil && epoch != dispatched {
				lost = true
				cancel()
				continue
			}
			renewed, err := e.scheduler.Heartbeat(ctx, scope, current, current.ExpiresAt)
			if err != nil {
				lost = true
				cancel()
				continue
			}
			current = renewed
		}
	}
}

// convergeAfterLeaseLoss resolves a superseded or late attempt against the
// durable task record. A task another attempt completed converges on the
// recorded, digest-attested output; anything else is a typed retryable stop —
// the superseded attempt changed no state and may be safely retried.
func (e *ScheduledToolExecutor) convergeAfterLeaseLoss(ctx context.Context, scope scheduler.Scope, id scheduler.TaskID) (ToolResult, error) {
	task, err := e.scheduler.Get(ctx, scope, id)
	if err == nil && task.State == scheduler.Completed {
		return e.replayAccepted(ctx, scope, id)
	}
	stale := problem.New(problem.CodeWorkerFenceStale, "")
	stale.Retryability = "safe-after-backoff"
	stale.Detail = "the worker lease could not be renewed; this attempt is superseded and its result was not accepted"
	return ToolResult{}, stale
}

// replayAccepted reads the durably accepted result and its recorded output.
// The recorded bytes must still attest the accepted digest; drifted storage
// fails closed rather than replaying unattested output.
func (e *ScheduledToolExecutor) replayAccepted(ctx context.Context, scope scheduler.Scope, taskID scheduler.TaskID) (ToolResult, error) {
	output, result, err := e.scheduler.AcceptedOutput(ctx, scope, taskID)
	if err != nil {
		return ToolResult{}, fmt.Errorf("replay accepted worker output: %w", err)
	}
	sum := sha256.Sum256(output)
	if "sha256:"+hex.EncodeToString(sum[:]) != result.ArtifactDigest {
		return ToolResult{}, fmt.Errorf("scheduled tool executor: the recorded output does not attest the accepted result digest")
	}
	return ToolResult{Output: append([]byte(nil), output...)}, nil
}

// DispatchIDs allocates unguessable scheduler identities.
type DispatchIDs struct{}

func (DispatchIDs) PhysicalAttemptID() (scheduler.AttemptID, error) {
	value, err := randomToken("attempt.")
	return scheduler.AttemptID(value), err
}

func (DispatchIDs) FenceToken() (string, error) { return randomToken("fence.") }

func (DispatchIDs) DLQID() (string, error) { return randomToken("dlq.") }

func randomToken(prefix string) (string, error) {
	raw := make([]byte, 16)
	if _, err := rand.Read(raw); err != nil {
		return "", fmt.Errorf("allocate dispatch identity: %w", err)
	}
	return prefix + hex.EncodeToString(raw), nil
}

// ControlledUsageSink is the controlled stand-in for the authoritative
// domain-owned usage meter. It is idempotent by observation identity and
// selected only with the controlled domain topology; production rejects it.
type ControlledUsageSink struct {
	lock sync.Mutex
	seen map[string]usage.Observation
}

func NewControlledUsageSink() *ControlledUsageSink {
	return &ControlledUsageSink{seen: make(map[string]usage.Observation)}
}

func (s *ControlledUsageSink) Observe(_ context.Context, value usage.Observation) error {
	s.lock.Lock()
	defer s.lock.Unlock()
	key := value.WorkspaceID + "\x00" + value.ProjectID + "\x00" + value.ObservationID
	if _, recorded := s.seen[key]; recorded {
		return nil
	}
	s.seen[key] = value
	return nil
}

// Observations reports how many distinct observations the sink accepted.
func (s *ControlledUsageSink) Observations() int {
	s.lock.Lock()
	defer s.lock.Unlock()
	return len(s.seen)
}
