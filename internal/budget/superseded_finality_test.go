package budget

import (
	"context"
	"testing"
	"time"
)

// TestLateFinalityAfterReplacementReconcilesWithoutAnotherRetry is the gap this
// path exists to close.
//
// A replacement generation can start while the attempt it replaces is still
// running: the retry advances the aggregate's generation, and only afterwards
// does the earlier attempt report what it actually spent. The ordinary
// settlement path used to refuse that settlement outright, because it required
// the settling generation to be the current one — so the hold kept its full
// worst-case bound until some later retry happened to run the superseded
// sweep. The settlement has to complete when finality arrives, not when the
// next retry does.
func TestLateFinalityAfterReplacementReconcilesWithoutAnotherRetry(t *testing.T) {
	ctx := context.Background()
	controller, ledger, generations, _, generation := controller(t)

	const worstCase = int64(400_000)
	const actual = int64(3_000)
	first, err := controller.ReserveInitial(ctx, estimate("reservation-1", "run", worstCase), generation)
	if err != nil {
		t.Fatal(err)
	}
	// The aggregate retries while the first attempt is still running, and the
	// replacement reserves against the still-open prior hold.
	generations.Set("workspace", "project", "root", 2)
	if _, err := controller.ReserveReplacement(ctx, estimate("reservation-2", "run", worstCase), 2, first.ID); err != nil {
		t.Fatal(err)
	}
	// Reserving the replacement reconciled nothing, because the prior
	// attempt's cost was not yet known.
	stranded, err := ledger.Reservation(ctx, testScope, first.ID)
	if err != nil {
		t.Fatal(err)
	}
	if stranded.UpperBoundMicros != worstCase {
		t.Fatalf("prior hold = %+v, want its worst case held while its attempt is unfinished", stranded)
	}

	// The superseded attempt now finishes and reports its authoritative usage,
	// and its own terminal settlement runs for the generation that made it.
	if err := controller.Observe(ctx, observation("late-final", first.ID, actual, true)); err != nil {
		t.Fatal(err)
	}
	settled, err := controller.Reconcile(ctx, testScope, first.ID, 1, ptr(actual), true, SettlementActor)
	if err != nil {
		t.Fatalf("late finality on a superseded generation was refused: %v", err)
	}
	if settled.UpperBoundMicros != actual || settled.ObservedMicros != actual {
		t.Fatalf("settled = %+v, want reduction to the usage the attempt reported", settled)
	}
	// It settled on superseded terms: the attempt's real cost stays counted
	// against the root, and the hold gains no authority to dispatch.
	if settled.Released {
		t.Fatal("a superseded generation released a prior attempt's cost out of the root total")
	}
	if settled.Generation != 1 {
		t.Fatalf("settled generation = %d, want the generation that made the hold", settled.Generation)
	}
	for name, attempt := range map[string]Generation{"own-generation": 1, "current-generation": 2} {
		if err := controller.Dispatch(ctx, testScope, first.ID, attempt, func(context.Context, Reservation) error {
			t.Fatalf("%s dispatched a reconciled superseded reservation", name)
			return nil
		}); err == nil {
			t.Fatalf("%s dispatch was permitted", name)
		}
	}

	// No third generation was needed to get here.
	current, err := generations.Current(ctx, "workspace", "project", "root")
	if err != nil || current != 2 {
		t.Fatalf("current generation = %d err=%v, want the reconciliation to need no further retry", current, err)
	}
	// The headroom is genuinely back: a further replacement fits where the
	// stranded worst case would have blocked it.
	generations.Set("workspace", "project", "root", 3)
	if _, err := controller.ReserveInitial(ctx, estimate("reservation-3", "run", worstCase), 3); err != nil {
		t.Fatalf("headroom the superseded hold never spent was still withheld: %v", err)
	}
}

// TestSupersededFinalityConvergesUnderReplayAndCrashRecovery covers the two
// ways this settlement is re-driven after it is interrupted.
//
// Replay: the final observation is idempotent, so re-executing the durable
// settlement step re-observes nothing — which means the reconciliation, not the
// observation, is what has to be retried, and it has to converge.
//
// Crash: a process that dies between recording finality and settling against it
// leaves a hold that is final, unreleased, and still at its worst case, with
// nothing to re-drive it — the generation that owned it is gone. The recovery
// sweep is derived from that durable state alone, so a successor process
// converges it without any journal of its own.
func TestSupersededFinalityConvergesUnderReplayAndCrashRecovery(t *testing.T) {
	ctx := context.Background()
	now := time.Now()
	controller, ledger, generations, _, generation := controllerForTime(t, now)

	const worstCase = int64(400_000)
	const actual = int64(2_500)
	first, err := controller.ReserveInitial(ctx, estimate("reservation-1", "run", worstCase), generation)
	if err != nil {
		t.Fatal(err)
	}
	generations.Set("workspace", "project", "root", 2)
	// Finality is recorded durably, and the process dies before settling.
	if err := controller.Observe(ctx, observation("late-final", first.ID, actual, true)); err != nil {
		t.Fatal(err)
	}
	crashed, err := ledger.Reservation(ctx, testScope, first.ID)
	if err != nil {
		t.Fatal(err)
	}
	if !crashed.AttemptFinal || crashed.UpperBoundMicros != worstCase {
		t.Fatalf("crash window state = %+v, want a final hold still carrying its worst case", crashed)
	}

	// A successor process builds a fresh controller over the same durable
	// ledger and generation authority — it holds no memory of the settlement
	// that never happened — and recovers from durable state alone.
	successor, err := New(ledger, generations, &exposure{}, clock{now: now}, HeadroomPolicy{MaximumReservedMicros: 1_000_000, ReviewAtBasisPoints: 8000})
	if err != nil {
		t.Fatal(err)
	}
	recovered, err := successor.RecoverSupersededFinality(ctx, testScope, "root", SettlementActor)
	if err != nil {
		t.Fatal(err)
	}
	if len(recovered) != 1 || recovered[0].ID != first.ID || recovered[0].UpperBoundMicros != actual || recovered[0].Released {
		t.Fatalf("recovered = %+v, want a single non-releasing reduction to reported usage", recovered)
	}
	// Recovery is idempotent: the predicate it acts on is false once it has
	// acted, so a second crash and a second sweep report nothing further.
	again, err := successor.RecoverSupersededFinality(ctx, testScope, "root", SettlementActor)
	if err != nil || len(again) != 0 {
		t.Fatalf("repeat recovery = %+v err=%v, want a no-op", again, err)
	}

	// Replay of the durable settlement step: the identical final observation
	// deduplicates, and the reconciliation it guards still converges on the
	// same answer rather than failing on the already-settled hold.
	if err := successor.Observe(ctx, observation("late-final", first.ID, actual, true)); err != nil {
		t.Fatalf("replayed final observation was refused: %v", err)
	}
	replayed, err := successor.Reconcile(ctx, testScope, first.ID, 1, ptr(actual), true, SettlementActor)
	if err != nil {
		t.Fatalf("replayed settlement was refused: %v", err)
	}
	if replayed.UpperBoundMicros != actual || replayed.ObservedMicros != actual || replayed.Released {
		t.Fatalf("replayed = %+v, want convergence on the recovered settlement", replayed)
	}
}

// TestSupersededRecoveryFailsClosedOnForeignTenantAndStaleAuthority proves the
// recovery path buys its convergence without giving anything else away. It
// reaches no other tenant's ledger, it is not an actor-agnostic settlement
// door, and it refuses any caller whose view of the generation authority is
// not the authority's own.
func TestSupersededRecoveryFailsClosedOnForeignTenantAndStaleAuthority(t *testing.T) {
	ctx := context.Background()
	controller, ledger, generations, _, generation := controller(t)

	const worstCase = int64(400_000)
	const actual = int64(1_200)
	held, err := controller.ReserveInitial(ctx, estimate("reservation-1", "run", worstCase), generation)
	if err != nil {
		t.Fatal(err)
	}
	generations.Set("workspace", "project", "root", 2)
	if err := controller.Observe(ctx, observation("late-final", held.ID, actual, true)); err != nil {
		t.Fatal(err)
	}

	// A foreign tenant that owns a root run of the very same identity, and is
	// itself a legitimate settlement authority, reaches nothing here.
	for name, foreign := range map[string]Scope{
		"foreign-workspace": {WorkspaceID: "other-workspace", ProjectID: "project"},
		"foreign-project":   {WorkspaceID: "workspace", ProjectID: "other-project"},
	} {
		generations.Set(foreign.WorkspaceID, foreign.ProjectID, "root", 2)
		swept, err := controller.RecoverSupersededFinality(ctx, foreign, "root", SettlementActor)
		if err != nil || len(swept) != 0 {
			t.Fatalf("%s swept = %+v err=%v, want no reach into another tenant's ledger", name, swept, err)
		}
	}
	untouched, err := ledger.Reservation(ctx, testScope, held.ID)
	if err != nil {
		t.Fatal(err)
	}
	if untouched.UpperBoundMicros != worstCase {
		t.Fatalf("hold after foreign sweeps = %+v, want it untouched", untouched)
	}

	// Neither an unscoped sweep, an unknown root, nor any actor but the one
	// settlement authority may run it.
	if _, err := controller.RecoverSupersededFinality(ctx, Scope{}, "root", SettlementActor); err == nil {
		t.Fatal("an unscoped recovery sweep was accepted")
	}
	if _, err := controller.RecoverSupersededFinality(ctx, testScope, "", SettlementActor); err == nil {
		t.Fatal("a rootless recovery sweep was accepted")
	}
	if _, err := controller.RecoverSupersededFinality(ctx, testScope, "root", "operator"); err == nil {
		t.Fatal("an unauthorized actor ran the recovery sweep")
	}
	if _, err := controller.RecoverSupersededFinality(ctx, testScope, "absent-root", SettlementActor); err == nil {
		t.Fatal("a sweep of a root with no generation authority was accepted")
	}

	// A settlement claiming a generation the durable authority has not reached
	// is a stale or forged view, never a late one.
	if _, err := controller.Reconcile(ctx, testScope, held.ID, 2, ptr(actual), false, SettlementActor); err == nil {
		t.Fatal("a settlement for a generation that never made the hold was accepted")
	}
	generations.Set("workspace", "project", "root", 1)
	ahead, err := controller.ReserveInitial(ctx, estimate("reservation-2", "run", 1_000), 1)
	if err != nil {
		t.Fatal(err)
	}
	if err := controller.Observe(ctx, observation("ahead-final", ahead.ID, 400, true)); err != nil {
		t.Fatal(err)
	}
	generations.Set("workspace", "project", "root", 0)
	if _, err := controller.Reconcile(ctx, testScope, ahead.ID, 1, ptr(int64(400)), false, SettlementActor); err == nil {
		t.Fatal("a settlement ahead of the durable generation authority was accepted")
	}

	// And a superseded settlement may not restate the cost: only the usage the
	// attempt authoritatively reported settles it.
	generations.Set("workspace", "project", "root", 2)
	if _, err := controller.Reconcile(ctx, testScope, held.ID, 1, ptr(actual+1), false, SettlementActor); err == nil {
		t.Fatal("a superseded settlement invented a cost the attempt never reported")
	}
	final, err := controller.Reconcile(ctx, testScope, held.ID, 1, nil, false, SettlementActor)
	if err != nil || final.UpperBoundMicros != actual || final.Released {
		t.Fatalf("settled = %+v err=%v, want the reported usage and no release", final, err)
	}
}
