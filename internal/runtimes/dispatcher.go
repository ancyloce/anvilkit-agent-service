package runtimes

import (
	"context"
	"errors"
	"time"

	"github.com/ancyloce/anvilkit-agent-service/contracts/generated/schema"
	"github.com/ancyloce/anvilkit-agent-service/internal/agent"
)

// Credential is the task-scoped authority a runtime is handed with one task.
// It is issued for exactly one physical attempt, names the audience of the
// release the attempt was dispatched to, and expires with the attempt. Nothing
// here is a provider, storage, or domain credential: a runtime that held one of
// those could act outside the attempt it was given.
type Credential struct {
	Value     string
	Audience  string
	ExpiresAt time.Time
	// Claims are what the credential binds. Only Value crosses a transport: a
	// released unit recovers these by verifying the token it was presented,
	// and an in-process one reads them directly. Carrying them on the port
	// keeps one description of what a credential means on both sides.
	Claims Claims
}

// DispatchReceipt is what the control plane learns from one dispatch: the
// release that answered, the signed result it proposed, and when the exchange
// happened. A receipt is not a commit — the result is a proposal Agent Service
// verifies against the fence before any state changes.
type DispatchReceipt struct {
	Release      agent.RuntimeBinding
	Result       schema.AgentRuntimeResult
	DispatchedAt time.Time
	ObservedAt   time.Time
}

// CancelReceipt records what a runtime did with a cancellation.
type CancelReceipt struct {
	Acknowledged bool
	ObservedAt   time.Time
}

// CompatibilityResult reports whether a release still answers as the release a
// Run pinned. It is a pre-dispatch check, not a guarantee: the commit-time
// fence is what makes a late or replaced execution safe.
type CompatibilityResult struct {
	Compatible bool
	// Reason names the first disagreement found. It is empty when compatible.
	Reason     string
	Observed   agent.RuntimeBinding
	ObservedAt time.Time
}

// CancellationNotOfferedError is returned by an adapter whose protocol carries
// no cancellation operation. It is not a failure of the cancellation: a
// cancelled run revokes the lease, and the commit-time fence is what stops a
// late result. Telling the runtime is an optimisation that saves it wasted
// work, and an adapter that cannot do it says so rather than reporting a
// cancellation it did not perform.
type CancellationNotOfferedError struct{ RuntimeUnitID string }

func (e CancellationNotOfferedError) Error() string {
	return "runtime dispatch: the invocation protocol " + e.RuntimeUnitID + " speaks offers no cancellation operation"
}

// IsCancellationNotOffered reports whether a cancellation failed because the
// protocol carries no such operation, as distinct from one that was attempted
// and failed.
func IsCancellationNotOffered(err error) bool {
	var target CancellationNotOfferedError
	return errors.As(err, &target)
}

// Dispatcher is the boundary between the control plane and a runtime release.
//
// It is deliberately transport-free: no request, response, header, or status
// type crosses it. The business layer decides what to dispatch and what a
// result means; how those bytes travel is the adapter's concern alone, and a
// second transport must not require the business layer to change.
type Dispatcher interface {
	// Dispatch executes one physical attempt of one task on the pinned release.
	Dispatch(ctx context.Context, binding agent.RuntimeBinding, task schema.AgentTask, credential Credential) (DispatchReceipt, error)
	// Cancel tells a release to stop an attempt it may still be running.
	Cancel(ctx context.Context, binding agent.RuntimeBinding, physicalAttemptID string) (CancelReceipt, error)
	// CheckCompatibility asks a release to identify itself and compares it to
	// the binding a Run pinned.
	CheckCompatibility(ctx context.Context, binding agent.RuntimeBinding) (CompatibilityResult, error)
}

// Endpoints resolves the address a runtime unit answers on. Addresses are
// deployment material, so they are configuration rather than contract: the
// release says which unit must serve the work, and the deployment says where
// that unit is.
type Endpoints interface {
	Endpoint(runtimeUnitID string) (string, error)
}
