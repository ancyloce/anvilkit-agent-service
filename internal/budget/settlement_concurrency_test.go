package budget

import (
	"context"
	"errors"
	"testing"
	"time"
)

// interposingLedger lands a concurrent observation in the exact window a
// settlement is computed in: after the caller has read the reservation and
// before the ledger writes. That window is the whole defect — a settlement
// that writes a cost derived from a stale read discards whatever committed
// inside it — so the test creates it deliberately rather than hoping to hit it.
type interposingLedger struct {
	Ledger
	inject func()
	once   bool
}

func (l *interposingLedger) Settle(ctx context.Context, value Settlement) (Reservation, error) {
	if !l.once {
		l.once = true
		l.inject()
	}
	return l.Ledger.Settle(ctx, value)
}

// TestSettlementNeverOverwritesUsageThatArrivesConcurrently is the regression
// for a lost-cost defect: settlement read a reservation, computed a final cost
// from the usage that read saw, and then wrote that cost over the row. Usage
// that committed in between was overwritten and never billed.
//
// The corrected settlement is a compare-and-set against exactly the usage and
// finality the caller read. The losing write is refused with a typed retryable
// conflict rather than allowed to overwrite the cost that arrived.
func TestSettlementNeverOverwritesUsageThatArrivesConcurrently(t *testing.T) {
	ctx := context.Background()
	memory := NewMemoryLedger(time.Now)
	generations := NewMemoryGenerations()
	generations.Set("workspace", "project", "root", 1)
	ledger := &interposingLedger{Ledger: memory}
	controller, err := New(ledger, generations, &exposure{}, clock{now: time.Now()}, HeadroomPolicy{MaximumReservedMicros: 1_000_000, ReviewAtBasisPoints: 8000})
	if err != nil {
		t.Fatal(err)
	}
	reserved, err := controller.ReserveInitial(ctx, estimate("reservation-cas", "run", 10_000), 1)
	if err != nil {
		t.Fatal(err)
	}
	if err := controller.Observe(ctx, observation("usage-first", reserved.ID, 400, true)); err != nil {
		t.Fatal(err)
	}
	// The physical attempt reports more usage inside the settlement window.
	ledger.inject = func() {
		if err := memory.Observe(ctx, observation("usage-late", reserved.ID, 250, false)); err != nil {
			t.Errorf("concurrent usage was rejected: %v", err)
		}
	}
	final := int64(400)
	_, err = controller.Reconcile(ctx, testScope, reserved.ID, 1, &final, true, SettlementActor)
	var conflict Conflict
	if !errors.As(err, &conflict) {
		t.Fatalf("settlement racing concurrent usage returned %v, want a typed conflict", err)
	}
	if !conflict.Retryable() || conflict.ObservedMicros != 650 {
		t.Fatalf("conflict = %+v, want a retryable conflict carrying the usage the ledger now holds", conflict)
	}
	untouched, err := controller.Reservation(ctx, testScope, reserved.ID)
	if err != nil {
		t.Fatal(err)
	}
	if untouched.ObservedMicros != 650 || untouched.UpperBoundMicros != 10_000 || untouched.Released {
		t.Fatalf("reservation after the losing settlement = %+v, want the concurrent usage intact and unreleased", untouched)
	}
	// Re-reading and settling again converges on the full amount, and
	// replaying that settlement converges rather than conflicting.
	fresh := untouched.ObservedMicros
	settled, err := controller.Reconcile(ctx, testScope, reserved.ID, 1, &fresh, true, SettlementActor)
	if err != nil {
		t.Fatalf("settlement after re-reading: %v", err)
	}
	if settled.ObservedMicros != 650 || settled.UpperBoundMicros != 650 || !settled.Released {
		t.Fatalf("settled reservation = %+v, want the full 650 micros settled and released", settled)
	}
	replayed, err := controller.Reconcile(ctx, testScope, reserved.ID, 1, &fresh, true, SettlementActor)
	if err != nil || replayed.ObservedMicros != 650 || replayed.UpperBoundMicros != 650 {
		t.Fatalf("replayed settlement = %+v err = %v, want convergence", replayed, err)
	}
}

// TestStaleFinalCostReportsAConflictRatherThanARefusal covers the wider half of
// the settlement race: usage that lands before the controller's own read, not
// after it. The caller's final cost is then already below the usage the ledger
// holds, and reporting that as a rejected settlement would strand the hold at
// its worst-case bound for ever — the caller has no way to tell a stale view
// from a real inconsistency, so it stops retrying. It is a conflict, and it
// says so.
func TestStaleFinalCostReportsAConflictRatherThanARefusal(t *testing.T) {
	ctx := context.Background()
	controller, _, _, _, generation := controller(t)
	reserved, err := controller.ReserveInitial(ctx, estimate("reservation-stale", "run", 10_000), generation)
	if err != nil {
		t.Fatal(err)
	}
	if err := controller.Observe(ctx, observation("usage-early", reserved.ID, 400, true)); err != nil {
		t.Fatal(err)
	}
	read, err := controller.Reservation(ctx, testScope, reserved.ID)
	if err != nil {
		t.Fatal(err)
	}
	// Usage lands before the settlement's own read of the reservation, which
	// is the wider of the two windows and the one a re-read loop must survive.
	if err := controller.Observe(ctx, observation("usage-overtaking", reserved.ID, 250, false)); err != nil {
		t.Fatal(err)
	}
	stale := read.ObservedMicros
	_, err = controller.Reconcile(ctx, testScope, reserved.ID, generation, &stale, true, SettlementActor)
	var conflict Conflict
	if !errors.As(err, &conflict) {
		t.Fatalf("settlement from a stale read returned %v, want a typed conflict", err)
	}
	if !conflict.Retryable() || conflict.ObservedMicros != 650 {
		t.Fatalf("conflict = %+v, want a retryable conflict carrying the usage the ledger now holds", conflict)
	}
	// A final cost outside the reservation's own bounds is a real
	// inconsistency, not a stale view, and stays a refusal.
	over := int64(20_000)
	if _, err := controller.Reconcile(ctx, testScope, reserved.ID, generation, &over, true, SettlementActor); errors.As(err, &conflict) || err == nil {
		t.Fatalf("a final cost above the reservation bound returned %v, want a refusal", err)
	}
	// Re-reading converges.
	fresh, err := controller.Reservation(ctx, testScope, reserved.ID)
	if err != nil {
		t.Fatal(err)
	}
	settled, err := controller.Reconcile(ctx, testScope, reserved.ID, generation, &fresh.ObservedMicros, true, SettlementActor)
	if err != nil || settled.ObservedMicros != 650 || !settled.Released {
		t.Fatalf("settled = %+v err = %v, want convergence on the full usage", settled, err)
	}
}

// TestCancelledSettlementConvergesOnUsageThatRacesIt proves the other half of
// the compare-and-set contract: the sweeps that settle at reported usage do
// not merely refuse a losing write, they re-read and settle again, so a cost
// that lands inside the settlement window ends up billed rather than dropped
// or stranded.
func TestCancelledSettlementConvergesOnUsageThatRacesIt(t *testing.T) {
	ctx := context.Background()
	memory := NewMemoryLedger(time.Now)
	generations := NewMemoryGenerations()
	generations.Set("workspace", "project", "root", 1)
	ledger := &interposingLedger{Ledger: memory}
	controller, err := New(ledger, generations, &exposure{}, clock{now: time.Now()}, HeadroomPolicy{MaximumReservedMicros: 1_000_000, ReviewAtBasisPoints: 8000})
	if err != nil {
		t.Fatal(err)
	}
	reserved, err := controller.ReserveInitial(ctx, estimate("reservation-converge", "run", 10_000), 1)
	if err != nil {
		t.Fatal(err)
	}
	if err := controller.Observe(ctx, observation("usage-reported", reserved.ID, 300, false)); err != nil {
		t.Fatal(err)
	}
	if _, err := controller.FenceCancelledRun(ctx, testScope, "root", "run"); err != nil {
		t.Fatal(err)
	}
	ledger.inject = func() {
		if err := memory.Observe(ctx, observation("usage-racing", reserved.ID, 175, false)); err != nil {
			t.Errorf("concurrent usage was rejected: %v", err)
		}
	}
	concluded, err := controller.ConcludeCancelledRun(ctx, testScope, "root", "run", SettlementActor)
	if err != nil || len(concluded) != 1 {
		t.Fatalf("conclusion settled %v err = %v, want the fenced hold settled", concluded, err)
	}
	if concluded[0].ObservedMicros != 475 || concluded[0].UpperBoundMicros != 475 || !concluded[0].Released {
		t.Fatalf("concluded hold = %+v, want it settled at the full 475 micros including the usage that raced it", concluded[0])
	}
}

// TestCancellationFencesWithoutManufacturingFinalityOrRelease is the budget
// half of the cancellation contract: revoking authority is immediate, and
// concluding the accounting is not. A hold whose run was cancelled stops
// authorizing dispatch, keeps its full worst-case bound, keeps accepting the
// usage its in-flight attempt reports, and is released only once an
// authoritative reconciliation concludes it — after which nothing hands its
// dispatch authority back.
func TestCancellationFencesWithoutManufacturingFinalityOrRelease(t *testing.T) {
	ctx := context.Background()
	controller, ledger, _, _, generation := controller(t)
	reserved, err := controller.ReserveInitial(ctx, estimate("reservation-cancel", "run", 10_000), generation)
	if err != nil {
		t.Fatal(err)
	}
	fenced, err := controller.FenceCancelledRun(ctx, testScope, "root", "run")
	if err != nil || len(fenced) != 1 {
		t.Fatalf("fenced %v err = %v, want the run's single hold fenced", fenced, err)
	}
	if !fenced[0].Cancelled || fenced[0].Released || fenced[0].AttemptFinal || fenced[0].UpperBoundMicros != 10_000 {
		t.Fatalf("fenced hold = %+v, want the full worst case held and no manufactured finality", fenced[0])
	}
	// The fence left its own immutable record, asserting neither cost nor
	// finality.
	record, recorded := ledger.observations[observationKey(testScope, CancellationObservationID(reserved.ID))]
	if !recorded || record.Final || record.CostMicros != 0 {
		t.Fatalf("cancellation record = %+v recorded = %t, want a fence that asserts neither cost nor finality", record, recorded)
	}
	if err := controller.Dispatch(ctx, testScope, reserved.ID, generation, func(context.Context, Reservation) error {
		t.Fatal("a cancelled reservation authorized a dispatch")
		return nil
	}); err == nil {
		t.Fatal("a cancelled reservation authorized a dispatch")
	}
	// Replaying the cancelled identity is refused rather than answered with a
	// reservation that can no longer authorize anything.
	replay := estimate("reservation-cancel", "run", 10_000)
	replay.ExpiresAt = time.Now().Add(time.Hour)
	if _, err := controller.ReserveInitial(ctx, replay, generation); err == nil {
		t.Fatal("a cancelled reservation replayed as a successful reservation")
	}
	// Recovery settles nothing while the interrupted attempt may still be
	// running: nothing has reported its finality.
	settled, err := controller.RecoverCancelledFinality(ctx, testScope, "root", SettlementActor)
	if err != nil || len(settled) != 0 {
		t.Fatalf("recovery settled %v err = %v, want nothing before finality", settled, err)
	}
	// The interrupted attempt reports what it spent.
	if err := controller.Observe(ctx, observation("usage-cancelled", reserved.ID, 725, false)); err != nil {
		t.Fatalf("a cancelled hold refused the usage its attempt reported: %v", err)
	}
	// Fencing again changes nothing, which is what makes a repeated
	// cancellation safe.
	if _, err := controller.FenceCancelledRun(ctx, testScope, "root", "run"); err != nil {
		t.Fatal(err)
	}
	// Concluding is the act that requires proof, and it settles the full
	// reported usage.
	concluded, err := controller.ConcludeCancelledRun(ctx, testScope, "root", "run", SettlementActor)
	if err != nil || len(concluded) != 1 {
		t.Fatalf("concluded %v err = %v, want the fenced hold settled", concluded, err)
	}
	if concluded[0].ObservedMicros != 725 || concluded[0].UpperBoundMicros != 725 || !concluded[0].Released || !concluded[0].AttemptFinal || !concluded[0].Cancelled {
		t.Fatalf("concluded hold = %+v, want it settled at reported usage, released, and still fenced", concluded[0])
	}
	if err := controller.Dispatch(ctx, testScope, reserved.ID, generation, func(context.Context, Reservation) error {
		t.Fatal("a settled cancelled reservation authorized a dispatch")
		return nil
	}); err == nil {
		t.Fatal("settlement handed cancelled work its dispatch authority back")
	}
	// Repetition converges: no further settlement, no further cost.
	again, err := controller.ConcludeCancelledRun(ctx, testScope, "root", "run", SettlementActor)
	if err != nil || len(again) != 0 {
		t.Fatalf("repeated conclusion settled %v err = %v, want nothing further", again, err)
	}
	total, err := controller.RootTotal(ctx, testScope, "root")
	if err != nil || total != 725 {
		t.Fatalf("root total = %d err = %v, want exactly the usage the attempt reported once", total, err)
	}
}

// TestUnauthorizedCancellationSettlementIsRefused keeps the settlement
// authority narrow: only the one settlement actor may conclude a cancelled
// run's accounting, and only inside a valid tenant scope.
func TestUnauthorizedCancellationSettlementIsRefused(t *testing.T) {
	ctx := context.Background()
	controller, _, _, _, generation := controller(t)
	if _, err := controller.ReserveInitial(ctx, estimate("reservation-auth", "run", 10_000), generation); err != nil {
		t.Fatal(err)
	}
	if _, err := controller.ConcludeCancelledRun(ctx, testScope, "root", "run", "someone-else"); err == nil {
		t.Fatal("an unauthorized actor concluded a cancelled run's accounting")
	}
	if _, err := controller.RecoverCancelledFinality(ctx, testScope, "root", "someone-else"); err == nil {
		t.Fatal("an unauthorized actor recovered cancelled finality")
	}
	if _, err := controller.FenceCancelledRun(ctx, Scope{}, "root", "run"); err == nil {
		t.Fatal("cancellation fencing crossed an unscoped boundary")
	}
	if _, err := controller.FenceCancelledRun(ctx, testScope, "", "run"); err == nil {
		t.Fatal("cancellation fencing accepted an unscoped root run")
	}
}
