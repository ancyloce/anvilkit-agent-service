package interrupts

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"time"

	"github.com/ancyloce/anvilkit-agent-service/internal/runs"
)

// CancellationRecovery completes a cancellation that could not be completed
// when it was requested.
//
// Cancellation revokes dispatch authority, leases, and descendant work
// immediately, and fences the budget of the run and every descendant in the
// same breath. What it deliberately does not do is conclude the accounting: at
// the instant a cancellation arrives a billed model, tool, or worker operation
// can still be running, and nothing yet knows what it will report. So the holds
// stay fenced and held at their worst-case bound until an authoritative
// reconciliation proves every physical attempt has durably reported.
//
// When that proof is already available the control command finishes the
// cancellation itself. When it is not — the common case for a cancellation that
// interrupts an in-flight provider call — nothing else would ever come back to
// it: the run's workflow will not replay, the command that cancelled it has
// been acknowledged, and a fresh cancel request cannot help, because the
// aggregate leaves the cancelling state only through reconciliation. This is
// the path that comes back to it.
//
// Its subject is the set of cancellations that have not reconciled, not the set
// of runs in the cancelling state. The distinction is the whole reason this
// type exists in its present shape: a cancellation requested inside the commit
// boundary deliberately leaves the run in its committing state under the domain
// owner's authority, so a sweep that looked for cancelling runs would never
// come back to the descendant holds that cancellation fenced, and they would
// consume root headroom for ever.
//
// It is replay-safe and restart-safe because it derives its work from durable
// state alone and settles only what that state proves: a scan finds the same
// cancellations a crashed scan found, the conclusion it drives is deduplicated
// by a deterministic observation identity, and the aggregate transition it
// makes is idempotent on a deterministic operation identity.
type CancellationRecovery struct {
	repository Repository
	reconciler CancellationReconciler
	budget     TerminalBudget
}

func NewCancellationRecovery(repository Repository, reconciler CancellationReconciler, terminalBudget TerminalBudget) (*CancellationRecovery, error) {
	if repository == nil || reconciler == nil || terminalBudget == nil {
		return nil, fmt.Errorf("cancellation recovery dependencies are required")
	}
	return &CancellationRecovery{repository: repository, reconciler: reconciler, budget: terminalBudget}, nil
}

// Scan advances every unreconciled cancellation as far as its durable state
// allows, and returns how many runs it terminalized. A cancellation still
// holding an outstanding effect — its own or a descendant's — is left exactly
// as it is: held, fenced, unreleased, and visibly unreconciled. That is the
// entire point. Releasing it would discard a cost the running attempt has not
// reported yet, and terminalizing it would hide the fact that something is
// still running.
//
// One cancellation that cannot be advanced never stops the rest: a sweep that
// returned at the first failure would let a single stuck run strand every other
// cancelled run's budget indefinitely, and this sweep is the only thing that
// releases fenced money. The first failure is reported; the scan finishes.
func (r *CancellationRecovery) Scan(ctx context.Context) (int, error) {
	pending, err := r.repository.UnreconciledCancellations(ctx)
	if err != nil {
		return 0, fmt.Errorf("query unreconciled cancellations: %w", err)
	}
	completed := 0
	var failure error
	record := func(err error) {
		if failure == nil {
			failure = err
		}
	}
	for _, item := range pending {
		done, err := r.advance(ctx, item)
		if err != nil {
			record(err)
			continue
		}
		if done {
			completed++
		}
	}
	return completed, failure
}

// advance carries one unreconciled cancellation as far as its durable state
// allows, and reports whether the run reached its terminal state.
func (r *CancellationRecovery) advance(ctx context.Context, item PendingCancellation) (bool, error) {
	snapshot, err := currentSnapshot(ctx, r.repository, Write{Scope: item.Scope, RunID: item.RunID})
	if err != nil {
		return false, fmt.Errorf("read cancelled run %s: %w", item.RunID, err)
	}
	// A run whose lifecycle is already over has no transition left to make, so
	// the only thing that can still need doing is settling a fenced hold it or
	// a descendant left behind. Asking the ledger that question is one indexed
	// read; asking the effect stores would be several per member of the
	// hierarchy, every tick, for ever.
	if terminal(snapshot.Status) {
		outstanding, err := r.budget.OutstandingCancelledRunBudget(ctx, snapshot)
		if err != nil {
			return false, fmt.Errorf("read cancelled run %s budget: %w", item.RunID, err)
		}
		if !outstanding {
			return false, nil
		}
	}
	// Fencing is repeated rather than assumed. A cancellation that failed
	// between recording the request and revoking budget authority would
	// otherwise leave a hold that still authorizes an expensive dispatch, and
	// this sweep is the only thing that comes back to it.
	if err := r.budget.FenceRunBudget(ctx, snapshot); err != nil {
		return false, fmt.Errorf("fence cancelled run %s budget: %w", item.RunID, err)
	}
	descendants, err := r.repository.Descendants(ctx, item.Scope, item.RunID)
	if err != nil {
		return false, fmt.Errorf("load descendants of cancelled run %s: %w", item.RunID, err)
	}
	settled, err := concludeCancelledHierarchy(ctx, r.repository, r.reconciler, r.budget, item.Scope, item.RunID, snapshot, descendants)
	if err != nil {
		return false, err
	}
	// Only a run the aggregate left in the cancelling state has a cancellation
	// transition to make. One cancelled inside the commit boundary is the
	// domain owner's to terminalize, and this sweep must never project it as
	// cancelled — its accounting is concluded above, and its state is not this
	// path's to decide.
	if !settled || snapshot.Status != runs.Cancelling {
		return false, nil
	}
	// The sweep finishes the cancellation but deliberately does not rewrite the
	// evidence the original control command recorded. That record is keyed on
	// the command's own idempotency key, which this sweep does not have and
	// must not guess, and it is an accurate account of what that command
	// observed at the time. The authoritative state is the aggregate, and this
	// is the transition that moves it.
	//
	// The write is scoped to the run's own actor: the durable
	// write-idempotency record is keyed by subject, and a write with no subject
	// is refused outright. The operation key is one no control command can
	// produce — a cancel request derives its reconciliation key from the
	// caller's own key with a fixed suffix — so this transition can never
	// collide with, or be pre-empted by, a client-supplied key.
	traceparent, err := recoveryTraceparent()
	if err != nil {
		return false, fmt.Errorf("allocate cancellation recovery trace: %w", err)
	}
	scope := item.Scope
	if scope.ActorID == "" {
		scope.ActorID = snapshot.ActorID
	}
	write := Write{Scope: scope, RunID: item.RunID, ExpectedVersion: snapshot.Version, IdempotencyKey: "cancellation-recovery:" + string(item.RunID), Traceparent: traceparent}
	cancellation := Cancellation{RequestedAt: item.RequestedAt, RequestedBy: scope.ActorID, DispatchStopped: true, LeasesRevoked: true, ChildrenPropagated: true, Reconciled: true}
	if _, err := r.repository.FinishCancellation(ctx, write, cancellation); err != nil {
		return false, fmt.Errorf("finish cancelled run %s: %w", item.RunID, err)
	}
	return true, nil
}

// Run scans on an interval until the context is cancelled. A failed scan is
// not fatal: the next one repeats the same derivation, and the state it works
// from is durable.
func (r *CancellationRecovery) Run(ctx context.Context, interval time.Duration) {
	if interval <= 0 || interval > 5*time.Minute {
		interval = time.Minute
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			_, _ = r.Scan(ctx)
		}
	}
}

// concludeCancelledHierarchy concludes the accounting of one cancelled run and
// every descendant it took down with it, and reports whether the whole
// hierarchy is settled.
//
// Descendants need concluding for the same reason the run does and by the same
// standard: cancelling a parent stops its children's workflows, so no terminal
// step of theirs will ever run to settle what they spent, and their fenced
// holds would otherwise consume root headroom for ever. Each one is proven
// separately — an authoritative reconciliation of that child, under that
// child's own commit phase, not its parent's — because the parent's proof says
// nothing about a provider call the child still has open.
//
// A hierarchy with any unresolved member is reported unsettled, which keeps the
// parent from terminalizing over work that is still running.
func concludeCancelledHierarchy(ctx context.Context, repository Repository, reconciler CancellationReconciler, budget TerminalBudget, scope runs.Scope, id runs.ID, snapshot runs.Snapshot, descendants []Child) (bool, error) {
	settled := true
	for _, child := range descendants {
		childSnapshot, err := currentSnapshot(ctx, repository, Write{Scope: scope, RunID: child.RunID})
		if err != nil {
			return false, fmt.Errorf("read cancelled descendant %s: %w", child.RunID, err)
		}
		// A descendant's fence is repeated for the same reason the parent's is,
		// and it matters more: a cancellation that failed partway through its
		// descendant loop leaves the children it never reached still holding
		// reservations that authorize expensive dispatch, and this is the only
		// path that comes back to them.
		if err := budget.FenceRunBudget(ctx, childSnapshot); err != nil {
			return false, fmt.Errorf("fence cancelled descendant %s budget: %w", child.RunID, err)
		}
		clear, authoritative, err := reconciler.Reconcile(ctx, scope, child.RunID, commitPhase(childSnapshot.Status))
		if err != nil {
			return false, fmt.Errorf("reconcile cancelled descendant %s: %w", child.RunID, err)
		}
		if !clear || authoritative != nil {
			settled = false
			continue
		}
		if err := budget.SettleCancelledRunBudget(ctx, childSnapshot); err != nil {
			return false, fmt.Errorf("settle cancelled descendant %s budget: %w", child.RunID, err)
		}
	}
	clear, authoritative, err := reconciler.Reconcile(ctx, scope, id, commitPhase(snapshot.Status))
	if err != nil {
		return false, fmt.Errorf("reconcile cancelled run %s: %w", id, err)
	}
	if !clear || authoritative != nil {
		return false, nil
	}
	if err := budget.SettleCancelledRunBudget(ctx, snapshot); err != nil {
		return false, fmt.Errorf("settle cancelled run %s budget: %w", id, err)
	}
	return settled, nil
}

// commitPhase reports whether a run is inside the commit boundary, which is
// where a governed effect may be in flight at the domain owner with nothing
// recorded here yet. It is derived from the run's live state rather than
// carried from the moment the cancellation was requested: a run that has since
// entered or left the boundary must be reconciled as it is now, not as it was.
func commitPhase(state runs.State) bool {
	return state == runs.Committing || state == runs.AwaitingDomainConfirmation
}

// terminal reports whether a run's lifecycle is over, so nothing will move its
// state again.
func terminal(state runs.State) bool {
	for _, open := range nonterminalStates() {
		if state == open {
			return false
		}
	}
	return true
}

// recoveryTraceparent starts a new trace for one recovery act. The sweep is not
// continuing the trace of the control command that cancelled the run — that
// command completed, possibly in another process, long before — so it opens its
// own rather than fabricating a continuation of one it never saw.
func recoveryTraceparent() (string, error) {
	raw := make([]byte, 24)
	if _, err := rand.Read(raw); err != nil {
		return "", err
	}
	// The identifiers must both be non-zero, which random bytes are with
	// overwhelming probability; a leading one is set so the format is
	// satisfied even in the degenerate draw.
	raw[0] |= 1
	raw[16] |= 1
	return "00-" + hex.EncodeToString(raw[:16]) + "-" + hex.EncodeToString(raw[16:]) + "-01", nil
}
