package budget

import (
	"context"
	"fmt"
	"testing"
	"time"
)

// TestSupersededGenerationsSettleToAuthoritativeUsage proves the reconciliation
// path a superseded generation's hold depends on.
//
// A reservation is fenced on the generation that made it. Once an explicit
// retry advances the root aggregate's generation, the ordinary settlement path
// can never reach the prior hold again — it requires the settling generation to
// be both the reservation's and the current one. Without this path the prior
// hold keeps its full worst-case bound for ever. The reconciliation must give
// that headroom back once the attempt's usage is authoritatively final, and
// must give back nothing while it is not.
func TestSupersededGenerationsSettleToAuthoritativeUsage(t *testing.T) {
	ctx := context.Background()
	controller, ledger, generations, _, generation := controller(t)

	// Generation 1 reserves its worst case and reports a small final usage.
	first, err := controller.ReserveInitial(ctx, estimate("reservation-1", "run", 400_000), generation)
	if err != nil {
		t.Fatal(err)
	}
	if err := controller.Observe(ctx, observation("usage-1", first.ID, 1_000, true)); err != nil {
		t.Fatal(err)
	}
	// Generation 2 reserves too, and its attempt is still running.
	generations.Set("workspace", "project", "root", 2)
	second, err := controller.ReserveReplacement(ctx, estimate("reservation-2", "run", 400_000), 2, first.ID)
	if err != nil {
		t.Fatal(err)
	}
	if err := controller.Observe(ctx, observation("usage-2", second.ID, 2_000, false)); err != nil {
		t.Fatal(err)
	}
	generations.Set("workspace", "project", "root", 3)

	// A caller acting for a generation that is not the current one settles
	// nothing, and neither does anything but the settlement authority.
	if _, err := controller.ReconcileSuperseded(ctx, testScope, "root", 2, SettlementActor); err == nil {
		t.Fatal("a stale view of the current generation settled superseded holds")
	}
	if _, err := controller.ReconcileSuperseded(ctx, testScope, "root", 3, "operator"); err == nil {
		t.Fatal("an unauthorized actor settled superseded holds")
	}
	if _, err := controller.ReconcileSuperseded(ctx, Scope{}, "root", 3, SettlementActor); err == nil {
		t.Fatal("an unscoped reconciliation was accepted")
	}

	settled, err := controller.ReconcileSuperseded(ctx, testScope, "root", 3, SettlementActor)
	if err != nil {
		t.Fatal(err)
	}
	if len(settled) != 1 || settled[0].ID != first.ID {
		t.Fatalf("settled = %+v, want only the finalized prior generation", settled)
	}
	if settled[0].UpperBoundMicros != 1_000 || settled[0].ObservedMicros != 1_000 {
		t.Fatalf("finalized hold = %+v, want reduction to its authoritative usage", settled[0])
	}
	// The unknown-final generation keeps its full worst-case headroom: a
	// superseded generation is not evidence of what an attempt spent.
	held, err := ledger.Reservation(ctx, testScope, second.ID)
	if err != nil {
		t.Fatal(err)
	}
	if held.UpperBoundMicros != 400_000 || held.Released {
		t.Fatalf("unknown-final hold = %+v, want its worst-case bound retained", held)
	}

	// Repeating the reconciliation changes nothing and reports nothing: the
	// finalized hold is already at its authoritative usage.
	again, err := controller.ReconcileSuperseded(ctx, testScope, "root", 3, SettlementActor)
	if err != nil || len(again) != 0 {
		t.Fatalf("repeat reconciliation = %+v err=%v, want a no-op", again, err)
	}
}

// TestSupersededSettlementNeverRestoresDispatchAuthority proves the
// reconciliation gives back headroom and nothing else. A settled
// prior-generation hold must stay un-dispatchable: its generation can never be
// current again, and the expiry fence it may carry is not lifted.
func TestSupersededSettlementNeverRestoresDispatchAuthority(t *testing.T) {
	ctx := context.Background()
	now := time.Now()
	controller, ledger, generations, _, generation := controllerForTime(t, now)

	reservation, err := controller.ReserveInitial(ctx, estimate("reservation-1", "run", 300_000), generation)
	if err != nil {
		t.Fatal(err)
	}
	if err := controller.Observe(ctx, observation("usage-1", reservation.ID, 5_000, true)); err != nil {
		t.Fatal(err)
	}
	// The hold's lifetime elapses and it is fenced, then the aggregate retries.
	fenced, err := ledger.FenceExpired(ctx, testScope, "root", now.Add(2*time.Hour))
	if err != nil || len(fenced) != 1 || !fenced[0].Expired {
		t.Fatalf("fence = %+v err=%v, want the elapsed hold fenced", fenced, err)
	}
	generations.Set("workspace", "project", "root", 2)

	settled, err := controller.ReconcileSuperseded(ctx, testScope, "root", 2, SettlementActor)
	if err != nil || len(settled) != 1 {
		t.Fatalf("settled = %+v err=%v, want the fenced finalized hold", settled, err)
	}
	if !settled[0].Expired {
		t.Fatal("reconciliation lifted the expiry fence")
	}
	if settled[0].Released {
		t.Fatal("reconciliation released a prior attempt's actual cost out of the root total")
	}
	// Neither its own generation nor the current one may dispatch it.
	for name, attempt := range map[string]Generation{"own-generation": 1, "current-generation": 2} {
		if err := controller.Dispatch(ctx, testScope, settled[0].ID, attempt, func(context.Context, Reservation) error {
			t.Fatalf("%s dispatched a settled superseded reservation", name)
			return nil
		}); err == nil {
			t.Fatalf("%s dispatch was permitted", name)
		}
	}
}

// TestLateUsageOnSupersededHoldsStaysAdditiveAndDuplicateSafe proves the
// reconciliation does not close a hold to the usage it is waiting for. A
// fenced attempt can still be running; its observations must keep accumulating
// additively, redelivery of the same observation must remain a no-op, and only
// the arrival of authoritative finality makes the hold settleable.
func TestLateUsageOnSupersededHoldsStaysAdditiveAndDuplicateSafe(t *testing.T) {
	ctx := context.Background()
	now := time.Now()
	controller, ledger, generations, _, generation := controllerForTime(t, now)

	reservation, err := controller.ReserveInitial(ctx, estimate("reservation-1", "run", 300_000), generation)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ledger.FenceExpired(ctx, testScope, "root", now.Add(2*time.Hour)); err != nil {
		t.Fatal(err)
	}
	generations.Set("workspace", "project", "root", 2)

	// Nothing is final yet, so nothing settles and the worst case is retained.
	settled, err := controller.ReconcileSuperseded(ctx, testScope, "root", 2, SettlementActor)
	if err != nil || len(settled) != 0 {
		t.Fatalf("reconciliation before finality = %+v err=%v, want nothing settled", settled, err)
	}

	// Late usage from the still-running attempt accumulates.
	for _, value := range []struct {
		id   string
		cost int64
	}{{"late-1", 700}, {"late-2", 300}} {
		if err := controller.Observe(ctx, observation(value.id, reservation.ID, value.cost, false)); err != nil {
			t.Fatalf("%s: %v", value.id, err)
		}
	}
	// Redelivery of an identical observation is a no-op, not a second charge.
	if err := controller.Observe(ctx, observation("late-1", reservation.ID, 700, false)); err != nil {
		t.Fatal(err)
	}
	held, err := ledger.Reservation(ctx, testScope, reservation.ID)
	if err != nil {
		t.Fatal(err)
	}
	if held.ObservedMicros != 1_000 {
		t.Fatalf("observed = %d, want the additive, deduplicated total", held.ObservedMicros)
	}
	if held.UpperBoundMicros != 300_000 {
		t.Fatalf("upper bound = %d, want the worst case retained until finality", held.UpperBoundMicros)
	}

	// Finality arrives and the hold reconciles to exactly what was reported.
	if err := controller.Observe(ctx, observation("late-final", reservation.ID, 0, true)); err != nil {
		t.Fatal(err)
	}
	settled, err = controller.ReconcileSuperseded(ctx, testScope, "root", 2, SettlementActor)
	if err != nil || len(settled) != 1 || settled[0].UpperBoundMicros != 1_000 || settled[0].ObservedMicros != 1_000 {
		t.Fatalf("settled = %+v err=%v, want reduction to the reported usage", settled, err)
	}
}

// TestRepeatedRetriesCannotPermanentlyExhaustRootHeadroom is the outcome the
// whole path exists for. Each retry fences the previous generation's hold
// without ever settling it, so without reconciliation the worst-case bounds
// accumulate and the root runs out of headroom on budget no attempt spent.
// With reconciliation, each superseded hold falls back to its actual usage and
// the aggregate keeps retrying.
func TestRepeatedRetriesCannotPermanentlyExhaustRootHeadroom(t *testing.T) {
	ctx := context.Background()
	now := time.Now()
	// The bound admits two worst cases at a time; ten attempts cannot fit
	// unless superseded holds give their unspent headroom back.
	const worstCase = int64(400_000)
	const actual = int64(1_000)
	const attempts = 10

	unreconciled, _, generations, _, _ := controllerForTime(t, now)
	exhausted := false
	for attempt := 1; attempt <= attempts; attempt++ {
		generations.Set("workspace", "project", "root", Generation(attempt))
		id := fmt.Sprintf("reservation-%d", attempt)
		reservation, err := unreconciled.ReserveInitial(ctx, estimate(id, "run", worstCase), Generation(attempt))
		if err != nil {
			exhausted = true
			break
		}
		// The attempt reports its real, small usage and is then fenced by the
		// retry that supersedes it.
		if err := unreconciled.Observe(ctx, observation("usage-"+id, reservation.ID, actual, true)); err != nil {
			t.Fatal(err)
		}
	}
	if !exhausted {
		t.Fatal("the fixture never exhausts headroom, so it cannot prove the fix")
	}

	reconciled, ledger, generations, _, _ := controllerForTime(t, now)
	for attempt := 1; attempt <= attempts; attempt++ {
		generations.Set("workspace", "project", "root", Generation(attempt))
		if attempt > 1 {
			if _, err := reconciled.ReconcileSuperseded(ctx, testScope, "root", Generation(attempt), SettlementActor); err != nil {
				t.Fatalf("attempt %d reconciliation: %v", attempt, err)
			}
		}
		id := fmt.Sprintf("reservation-%d", attempt)
		reservation, err := reconciled.ReserveInitial(ctx, estimate(id, "run", worstCase), Generation(attempt))
		if err != nil {
			t.Fatalf("attempt %d was refused headroom it never spent: %v", attempt, err)
		}
		if err := reconciled.Observe(ctx, observation("usage-"+id, reservation.ID, actual, true)); err != nil {
			t.Fatal(err)
		}
	}
	// All-attempt accounting survives: every attempt's actual cost is still
	// counted against the root, only the unspent worst case was returned.
	total, err := reconciled.RootTotal(ctx, testScope, "root")
	if err != nil {
		t.Fatal(err)
	}
	if total != actual*attempts {
		t.Fatalf("root total = %d, want every attempt's actual usage (%d)", total, actual*attempts)
	}
	values, err := ledger.RootReservations(ctx, testScope, "root")
	if err != nil {
		t.Fatal(err)
	}
	if len(values) != attempts {
		t.Fatalf("root holds = %d, want one per attempt", len(values))
	}
}
