package budget

import (
	"context"
	"errors"
	"fmt"
	"math/rand"
	"sync"
	"testing"
	"time"

	"github.com/ancyloce/anvilkit-agent-service/internal/problem"
)

type exposure struct {
	lock         sync.Mutex
	held, actual int64
	calls        int
	review       bool
}

func (e *exposure) ObserveExposure(_ context.Context, _ string, held, actual int64, review bool) error {
	e.lock.Lock()
	defer e.lock.Unlock()
	e.held, e.actual, e.calls = held, actual, e.calls+1
	e.review = review
	return nil
}

type clock struct{ now time.Time }

func (c clock) Now() time.Time { return c.now }

// movableClock is one authoritative time both the controller and its ledger
// read, so a test that advances time advances it for the expiry settlement
// inside the ledger too.
type movableClock struct {
	lock sync.Mutex
	now  time.Time
}

func (c *movableClock) Now() time.Time {
	c.lock.Lock()
	defer c.lock.Unlock()
	return c.now
}
func (c *movableClock) set(value time.Time) {
	c.lock.Lock()
	defer c.lock.Unlock()
	c.now = value
}

// testScope is the tenant every fixture reservation belongs to.
var testScope = Scope{WorkspaceID: "workspace", ProjectID: "project"}

func controller(t *testing.T) (*Controller, *MemoryLedger, *MemoryGenerations, *exposure, Generation) {
	t.Helper()
	return controllerForTime(t, time.Now())
}

func controllerForTime(t *testing.T, now time.Time) (*Controller, *MemoryLedger, *MemoryGenerations, *exposure, Generation) {
	t.Helper()
	moving := &movableClock{now: now}
	ledger := NewMemoryLedger(moving.Now)
	generations := NewMemoryGenerations()
	generations.Set("workspace", "project", "root", 1)
	metric := &exposure{}
	built, err := New(ledger, generations, metric, moving, HeadroomPolicy{MaximumReservedMicros: 1_000_000, ReviewAtBasisPoints: 8000})
	if err != nil {
		t.Fatal(err)
	}
	return built, ledger, generations, metric, 1
}

func estimate(id, run string, cost int64) Estimate {
	return Estimate{ReservationID: ReservationID(id), RootRunID: "root", RunID: run, WorkspaceID: "workspace", ProjectID: "project", PolicyVersion: "policy-v1", BudgetVersion: "budget-v1", MaximumCostMicros: cost, ExpiresAt: time.Now().Add(time.Hour)}
}

func observation(id string, reservation ReservationID, cost int64, final bool) Observation {
	return Observation{ID: id, Scope: testScope, ReservationID: reservation, RootRunID: "root", RunID: "run", TaskID: "task", AttemptID: "attempt", CostMicros: cost, Final: final}
}

func TestReservationBeforeDispatchAndReplacementKeepsPriorOpen(t *testing.T) {
	controller, ledger, _, metric, generation := controller(t)
	calls := 0
	if err := controller.Dispatch(context.Background(), testScope, "missing", generation, func(context.Context, Reservation) error { calls++; return nil }); err == nil || calls != 0 {
		t.Fatal("unreserved dispatch occurred")
	}
	first, err := controller.ReserveInitial(context.Background(), estimate("reservation-1", "run", 100), generation)
	if err != nil {
		t.Fatal(err)
	}
	if err := controller.Dispatch(context.Background(), testScope, first.ID, generation, func(context.Context, Reservation) error { calls++; return nil }); err != nil || calls != 1 {
		t.Fatalf("dispatch=%d err=%v", calls, err)
	}
	replacement, err := controller.ReserveReplacement(context.Background(), estimate("reservation-2", "run", 200), generation, first.ID)
	if err != nil {
		t.Fatal(err)
	}
	prior, _ := ledger.Reservation(context.Background(), testScope, first.ID)
	if prior.Released || replacement.ID == first.ID || metric.held != 300 {
		t.Fatalf("prior=%#v replacement=%#v metric=%#v", prior, replacement, metric)
	}
}

func TestReplayedReservationConvergesWithoutDoubleHold(t *testing.T) {
	controller, _, _, metric, generation := controller(t)
	first, err := controller.ReserveInitial(context.Background(), estimate("reservation-1", "run", 100), generation)
	if err != nil {
		t.Fatal(err)
	}
	// A crash after the durable reservation re-executes the same operation:
	// the identical estimate converges on the recorded reservation, and no
	// second hold appears.
	replayed, err := controller.ReserveInitial(context.Background(), estimate("reservation-1", "run", 100), generation)
	if err != nil {
		t.Fatal(err)
	}
	if replayed.ID != first.ID || metric.held != 100 {
		t.Fatalf("replayed=%#v held=%d", replayed, metric.held)
	}
	// The same identity with drifted content is a conflict, never a merge.
	drifted := estimate("reservation-1", "run", 150)
	if _, err := controller.ReserveInitial(context.Background(), drifted, generation); err == nil {
		t.Fatal("drifted replay accepted")
	}
}

func TestGenerationFencingDeniesSupersededReserveAndDispatch(t *testing.T) {
	controller, _, generations, _, generation := controller(t)
	reservation, err := controller.ReserveInitial(context.Background(), estimate("reservation-1", "run", 100), generation)
	if err != nil {
		t.Fatal(err)
	}
	// The run aggregate advances its execution generation (explicit retry);
	// the superseded generation can no longer reserve, dispatch, or settle.
	generations.Set("workspace", "project", "root", 2)
	if _, err := controller.ReserveInitial(context.Background(), estimate("reservation-x", "other", 10), generation); err == nil {
		t.Fatal("superseded generation reserved")
	}
	if err := controller.Dispatch(context.Background(), testScope, reservation.ID, generation, func(context.Context, Reservation) error { return nil }); err == nil {
		t.Fatal("superseded generation dispatched")
	}
	if err := controller.Observe(context.Background(), observation("observation", reservation.ID, 10, true)); err != nil {
		t.Fatal(err)
	}
	// Late finality on a superseded generation reconciles rather than
	// stranding the hold at a worst case nothing spent — but it settles on
	// superseded terms: reduced to the usage actually reported, never
	// released however the caller asked, and never dispatchable again.
	settled, err := controller.Reconcile(context.Background(), testScope, reservation.ID, generation, ptr(int64(10)), true, SettlementActor)
	if err != nil {
		t.Fatal(err)
	}
	if settled.Released || settled.UpperBoundMicros != 10 || settled.ObservedMicros != 10 || settled.Generation != generation {
		t.Fatalf("settled = %+v, want a non-releasing reduction to reported usage on its own generation", settled)
	}
	if err := controller.Dispatch(context.Background(), testScope, reservation.ID, generation, func(context.Context, Reservation) error { return nil }); err == nil {
		t.Fatal("a settled superseded reservation regained dispatch authority")
	}
	// The replacement generation reserves against the still-open prior hold.
	replacement := estimate("reservation-2", "run", 200)
	if _, err := controller.ReserveReplacement(context.Background(), replacement, 2, reservation.ID); err != nil {
		t.Fatal(err)
	}
}

func TestRestartRecoveryFencesOnDurableStateOnly(t *testing.T) {
	first, ledger, generations, _, generation := controller(t)
	reservation, err := first.ReserveInitial(context.Background(), estimate("reservation-1", "run", 100), generation)
	if err != nil {
		t.Fatal(err)
	}
	// A successor process builds a fresh controller over the same durable
	// ledger and generation authority: nothing about the reservation, its
	// observations, or the active generation lives in process memory.
	successor, err := New(ledger, generations, &exposure{}, clock{time.Now()}, HeadroomPolicy{MaximumReservedMicros: 1_000_000, ReviewAtBasisPoints: 8000})
	if err != nil {
		t.Fatal(err)
	}
	if err := successor.Dispatch(context.Background(), testScope, reservation.ID, generation, func(context.Context, Reservation) error { return nil }); err != nil {
		t.Fatal(err)
	}
	if err := successor.Observe(context.Background(), observation("observation", reservation.ID, 40, true)); err != nil {
		t.Fatal(err)
	}
	settled, err := successor.Reconcile(context.Background(), testScope, reservation.ID, generation, ptr(int64(40)), true, SettlementActor)
	if err != nil || !settled.Released || settled.ObservedMicros != 40 {
		t.Fatalf("settled=%#v err=%v", settled, err)
	}
}

func TestReplacementMatrixReservesIncrementBeforeProviderRetryFallbackOrSupersede(t *testing.T) {
	for _, mode := range []string{"provider-retry", "fallback-child", "superseded-attempt"} {
		t.Run(mode, func(t *testing.T) {
			controller, ledger, _, _, generation := controller(t)
			prior, err := controller.ReserveInitial(context.Background(), estimate("reservation-1", "run", 100), generation)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := controller.ReserveReplacement(context.Background(), estimate("reservation-2", mode, 150), generation, prior.ID); err != nil {
				t.Fatal(err)
			}
			stillHeld, _ := ledger.Reservation(context.Background(), testScope, prior.ID)
			if stillHeld.Released {
				t.Fatalf("%s released prior reservation before replacement finality", mode)
			}
		})
	}
}

func TestExposureMetricRaisesConfiguredReviewSignal(t *testing.T) {
	ledger := NewMemoryLedger(time.Now)
	generations := NewMemoryGenerations()
	generations.Set("workspace", "project", "root", 1)
	metric := &exposure{}
	controller, err := New(ledger, generations, metric, clock{time.Now()}, HeadroomPolicy{MaximumReservedMicros: 250, ReviewAtBasisPoints: 8000})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := controller.ReserveInitial(context.Background(), estimate("reservation-1", "run", 200), 1); err != nil {
		t.Fatal(err)
	}
	if !metric.review || metric.held != 200 {
		t.Fatalf("review signal=%v held=%d", metric.review, metric.held)
	}
}

func TestUnknownFinalAndGenerationFencedSettlement(t *testing.T) {
	controller, ledger, _, _, generation := controller(t)
	reservation, _ := controller.ReserveInitial(context.Background(), estimate("reservation-1", "run", 100), generation)
	if err := controller.Observe(context.Background(), observation("observation", reservation.ID, 25, true)); err != nil {
		t.Fatal(err)
	}
	total, _ := controller.RootTotal(context.Background(), testScope, "root")
	if total != 25 {
		t.Fatalf("known final=%d", total)
	}
	next, _ := controller.ReserveReplacement(context.Background(), estimate("reservation-2", "run", 200), generation, reservation.ID)
	total, _ = controller.RootTotal(context.Background(), testScope, "root")
	if total != 225 {
		t.Fatalf("unknown final not held at upper bound: %d", total)
	}
	for _, item := range []struct {
		generation Generation
		actor      string
	}{{generation + 1, SettlementActor}, {generation, "worker"}} {
		if _, err := controller.Reconcile(context.Background(), testScope, reservation.ID, item.generation, ptr(25), true, item.actor); err == nil {
			t.Fatal("unauthorized release succeeded")
		}
	}
	if _, err := controller.Reconcile(context.Background(), testScope, next.ID, generation, nil, true, SettlementActor); err == nil {
		t.Fatal("nonfinal reservation released")
	}
	settled, err := controller.Reconcile(context.Background(), testScope, reservation.ID, generation, ptr(25), true, SettlementActor)
	if err != nil || !settled.Released {
		t.Fatalf("settled=%#v err=%v", settled, err)
	}
	_ = ledger
}

func TestRootAggregationNeverUndercountsRandomAttemptHistories(t *testing.T) {
	for seed := int64(0); seed < 100; seed++ {
		controller, _, _, _, generation := controller(t)
		random := rand.New(rand.NewSource(seed))
		var expected int64
		var prior ReservationID
		for index := 0; index < 25; index++ {
			upper := int64(random.Intn(1000) + 1)
			identity := "reservation-" + string(rune('a'+index))
			var reservation Reservation
			var err error
			if index == 0 {
				reservation, err = controller.ReserveInitial(context.Background(), estimate(identity, "root", upper), generation)
			} else {
				reservation, err = controller.ReserveReplacement(context.Background(), estimate(identity, "child", upper), generation, prior)
			}
			if err != nil {
				t.Fatal(err)
			}
			prior = reservation.ID
			if random.Intn(2) == 0 {
				actual := int64(random.Intn(int(upper) + 1))
				if err := controller.Observe(context.Background(), Observation{ID: string(reservation.ID), Scope: testScope, ReservationID: reservation.ID, RootRunID: "root", RunID: "child", TaskID: "task", AttemptID: AttemptID(reservation.ID), CostMicros: actual, Final: true}); err != nil {
					t.Fatal(err)
				}
				expected += actual
			} else {
				expected += upper
			}
		}
		total, err := controller.RootTotal(context.Background(), testScope, "root")
		if err != nil || total != expected {
			t.Fatalf("seed=%d total=%d expected=%d err=%v", seed, total, expected, err)
		}
	}
}

func TestReservationFailureNeverDispatches(t *testing.T) {
	ledger := NewMemoryLedger(time.Now)
	generations := NewMemoryGenerations()
	generations.Set("workspace", "project", "root", 1)
	controller, _ := New(ledger, generations, &exposure{}, clock{time.Now()}, HeadroomPolicy{MaximumReservedMicros: 50, ReviewAtBasisPoints: 8000})
	_, err := controller.ReserveInitial(context.Background(), estimate("reservation-1", "run", 100), 1)
	var details problem.Details
	if !errors.As(err, &details) || details.Code != string(problem.CodeBudgetDenied) {
		t.Fatalf("err=%v", err)
	}
}

type alteredLedger struct {
	Ledger
	alter func(Reservation) Reservation
}

func (l alteredLedger) Reserve(ctx context.Context, estimate Estimate, generation Generation, maximumReservedMicros int64) (Reservation, error) {
	value, err := l.Ledger.Reserve(ctx, estimate, generation, maximumReservedMicros)
	if err != nil {
		return value, err
	}
	return l.alter(value), nil
}

func TestReservationBindingExpiryAndArithmeticFailClosed(t *testing.T) {
	now := time.Unix(100, 0)
	base := NewMemoryLedger(func() time.Time { return now })
	generations := NewMemoryGenerations()
	generations.Set("workspace", "project", "root", 1)
	ledger := alteredLedger{Ledger: base, alter: func(value Reservation) Reservation {
		value.WorkspaceID = "substituted-workspace"
		return value
	}}
	controller, err := New(ledger, generations, &exposure{}, clock{now}, HeadroomPolicy{MaximumReservedMicros: maxMicros, ReviewAtBasisPoints: 8000})
	if err != nil {
		t.Fatal(err)
	}
	value := estimate("reservation-1", "run", 10)
	value.ExpiresAt = now.Add(time.Minute)
	if _, err := controller.ReserveInitial(context.Background(), value, 1); err == nil {
		t.Fatal("ledger-substituted reservation binding accepted")
	}

	expiredController, expiredLedger, _, _, expiredGeneration := controllerForTime(t, now)
	expired := estimate("reservation-2", "run", 10)
	expired.ExpiresAt = now.Add(time.Minute)
	reserved, err := expiredController.ReserveInitial(context.Background(), expired, expiredGeneration)
	if err != nil {
		t.Fatal(err)
	}
	expiredController.clock.(*movableClock).set(reserved.ExpiresAt)
	called := false
	if err := expiredController.Dispatch(context.Background(), testScope, reserved.ID, expiredGeneration, func(context.Context, Reservation) error { called = true; return nil }); err == nil || called {
		t.Fatal("dispatch occurred at the exact reservation expiry")
	}

	expiredLedger.values[scopedKey(testScope, "overflow-a")] = Reservation{ID: "overflow-a", RootRunID: "overflow", WorkspaceID: testScope.WorkspaceID, ProjectID: testScope.ProjectID, UpperBoundMicros: maxMicros}
	expiredLedger.values[scopedKey(testScope, "overflow-b")] = Reservation{ID: "overflow-b", RootRunID: "overflow", WorkspaceID: testScope.WorkspaceID, ProjectID: testScope.ProjectID, UpperBoundMicros: 1}
	if _, err := expiredController.RootTotal(context.Background(), testScope, "overflow"); err == nil {
		t.Fatal("root accounting overflow was not rejected")
	}
}

func ptr(value int64) *int64 { return &value }

// Concurrent reservations against one root can never together exceed the
// configured maximum. The check and the insertion are one critical section in
// the ledger, so there is no window where two callers both observe the
// pre-insertion total and both find room.
func TestConcurrentReservationsCannotExceedTheConfiguredMaximum(t *testing.T) {
	const (
		racers  = 32
		cost    = int64(100)
		maximum = int64(1000)
	)
	moving := &movableClock{now: time.Unix(1_000_000, 0)}
	ledger := NewMemoryLedger(moving.Now)
	generations := NewMemoryGenerations()
	generations.Set("workspace", "project", "root", 1)
	controller, err := New(ledger, generations, &exposure{}, moving, HeadroomPolicy{MaximumReservedMicros: maximum, ReviewAtBasisPoints: 8000})
	if err != nil {
		t.Fatal(err)
	}
	var start sync.WaitGroup
	var done sync.WaitGroup
	start.Add(1)
	granted := make([]bool, racers)
	for index := 0; index < racers; index++ {
		done.Add(1)
		go func(index int) {
			defer done.Done()
			start.Wait()
			value := estimate(fmt.Sprintf("reservation-%02d", index), "run", cost)
			value.ExpiresAt = moving.Now().Add(time.Hour)
			_, err := controller.ReserveInitial(context.Background(), value, 1)
			granted[index] = err == nil
		}(index)
	}
	start.Done()
	done.Wait()
	accepted := 0
	for _, ok := range granted {
		if ok {
			accepted++
		}
	}
	if int64(accepted)*cost > maximum {
		t.Fatalf("accepted %d reservations of %d against a %d maximum", accepted, cost, maximum)
	}
	if accepted != int(maximum/cost) {
		t.Fatalf("accepted %d reservations, want the maximum to be fully but exactly used", accepted)
	}
	reservations, err := ledger.RootReservations(context.Background(), testScope, "root")
	if err != nil {
		t.Fatal(err)
	}
	if held := rootHeld(reservations); held != maximum {
		t.Fatalf("held=%d, want exactly the configured maximum", held)
	}
}

// One reservation identity in two tenants is two reservations, and a read made
// under the wrong tenant resolves nothing. Root aggregation, settlement, and
// observation all carry the same boundary.
func TestReservationIdentityNeverCrossesATenantBoundary(t *testing.T) {
	moving := &movableClock{now: time.Unix(1_000_000, 0)}
	ledger := NewMemoryLedger(moving.Now)
	generations := NewMemoryGenerations()
	generations.Set("workspace", "project", "root", 1)
	generations.Set("other-workspace", "project", "root", 1)
	generations.Set("workspace", "other-project", "root", 1)
	controller, err := New(ledger, generations, &exposure{}, moving, HeadroomPolicy{MaximumReservedMicros: 1_000, ReviewAtBasisPoints: 8000})
	if err != nil {
		t.Fatal(err)
	}
	mine := estimate("reservation-shared", "run", 600)
	mine.ExpiresAt = moving.Now().Add(time.Hour)
	if _, err := controller.ReserveInitial(context.Background(), mine, 1); err != nil {
		t.Fatal(err)
	}
	for _, neighbour := range []Scope{{WorkspaceID: "other-workspace", ProjectID: "project"}, {WorkspaceID: "workspace", ProjectID: "other-project"}} {
		// The same identity in a neighbouring tenant is a different
		// reservation: it neither converges on nor is blocked by mine.
		theirs := mine
		theirs.WorkspaceID, theirs.ProjectID = neighbour.WorkspaceID, neighbour.ProjectID
		if _, err := controller.ReserveInitial(context.Background(), theirs, 1); err != nil {
			t.Fatalf("scope %+v could not reserve its own identity: %v", neighbour, err)
		}
		// And my reservation is invisible from there.
		if _, err := controller.Reservation(context.Background(), neighbour, mine.ReservationID); err != nil {
			t.Fatalf("scope %+v could not read its own reservation: %v", neighbour, err)
		}
		reservations, err := ledger.RootReservations(context.Background(), neighbour, "root")
		if err != nil || len(reservations) != 1 || reservations[0].WorkspaceID != neighbour.WorkspaceID || reservations[0].ProjectID != neighbour.ProjectID {
			t.Fatalf("scope %+v aggregated %d foreign reservations: %v", neighbour, len(reservations), err)
		}
		// An observation made in the neighbouring tenant accumulates on that
		// tenant's own reservation and leaves mine untouched, even though both
		// rows answer to the same identity.
		crossing := observation("cross-tenant", mine.ReservationID, 7, false)
		crossing.Scope = neighbour
		crossing.RootRunID = "root"
		if err := controller.Observe(context.Background(), crossing); err != nil {
			t.Fatalf("scope %+v could not observe its own reservation: %v", neighbour, err)
		}
		theirRow, err := controller.Reservation(context.Background(), neighbour, mine.ReservationID)
		if err != nil || theirRow.ObservedMicros != 7 {
			t.Fatalf("neighbour reservation=%+v err=%v", theirRow, err)
		}
		myRow, err := controller.Reservation(context.Background(), testScope, mine.ReservationID)
		if err != nil || myRow.ObservedMicros != 0 {
			t.Fatalf("a neighbouring tenant's observation reached my reservation: %+v err=%v", myRow, err)
		}
	}
	if _, err := controller.Reservation(context.Background(), Scope{WorkspaceID: "workspace", ProjectID: "missing-project"}, mine.ReservationID); err == nil {
		t.Fatal("an unrelated scope resolved a reservation identity")
	}
}

// Clock expiry fences a reservation. It records the fence immutably, refuses
// further dispatch, and keeps the worst-case hold — because the clock knows
// only that a lifetime elapsed, never what the physical attempt spent. It does
// not manufacture attempt finality, does not release, and does not answer a
// replay of the elapsed identity as though the hold were still good. Late
// usage from the attempt that outlived its lifetime stays additive and
// duplicate-safe, and only authoritative finality releases the headroom.
func TestExpiredReservationsFenceWithoutManufacturingFinalityOrRelease(t *testing.T) {
	moving := &movableClock{now: time.Unix(1_000_000, 0)}
	ledger := NewMemoryLedger(moving.Now)
	generations := NewMemoryGenerations()
	generations.Set("workspace", "project", "root", 1)
	controller, err := New(ledger, generations, &exposure{}, moving, HeadroomPolicy{MaximumReservedMicros: 1_000, ReviewAtBasisPoints: 8000})
	if err != nil {
		t.Fatal(err)
	}
	first := estimate("reservation-1", "run", 900)
	first.ExpiresAt = moving.Now().Add(time.Minute)
	if _, err := controller.ReserveInitial(context.Background(), first, 1); err != nil {
		t.Fatal(err)
	}
	if err := controller.Observe(context.Background(), observation("observation-1", first.ReservationID, 250, false)); err != nil {
		t.Fatal(err)
	}
	// While the hold is live it consumes headroom, so the second reservation
	// is denied.
	second := estimate("reservation-2", "run", 900)
	second.ExpiresAt = moving.Now().Add(time.Minute)
	if _, err := controller.ReserveInitial(context.Background(), second, 1); err == nil {
		t.Fatal("a live hold did not consume headroom")
	}
	// The hold elapses. The next reservation attempt fences it inside the same
	// critical section that measures headroom — and is still denied, because a
	// fence is not a settlement: the elapsed attempt keeps its worst-case
	// headroom until somebody reports what it actually spent.
	moving.set(first.ExpiresAt.Add(time.Second))
	second.ExpiresAt = moving.Now().Add(time.Minute)
	if _, err := controller.ReserveInitial(context.Background(), second, 1); err == nil {
		t.Fatal("an elapsed hold released headroom before its cost was known")
	}
	fenced, err := controller.Reservation(context.Background(), testScope, first.ReservationID)
	if err != nil {
		t.Fatal(err)
	}
	if !fenced.Expired || fenced.Released || fenced.AttemptFinal || fenced.UpperBoundMicros != 900 || fenced.ObservedMicros != 250 {
		t.Fatalf("expired reservation = %+v, want a fence that keeps the worst-case hold and claims no finality", fenced)
	}
	// The fence left its own immutable record: it is auditable, and it states
	// only that the lifetime elapsed — no cost, no finality.
	record, recorded := ledger.observations[observationKey(testScope, ExpiryObservationID(first.ReservationID))]
	if !recorded {
		t.Fatal("the expiry fence left no durable record")
	}
	if record.Final || record.CostMicros != 0 {
		t.Fatalf("expiry record = %+v, want a fence that asserts neither cost nor finality", record)
	}
	// A fenced hold can no longer authorize expensive work.
	if err := controller.Dispatch(context.Background(), testScope, first.ReservationID, 1, func(context.Context, Reservation) error {
		t.Fatal("a fenced reservation authorized a dispatch")
		return nil
	}); err == nil {
		t.Fatal("a fenced reservation authorized a dispatch")
	}
	// Replaying the elapsed reservation identity is refused rather than
	// answered with a reservation that can no longer authorize anything.
	replay := estimate("reservation-1", "run", 900)
	replay.ExpiresAt = first.ExpiresAt
	if _, err := controller.ReserveInitial(context.Background(), replay, 1); err == nil {
		t.Fatal("an expired reservation replayed as a successful reservation")
	}
	// The physical attempt that outlived its lifetime is still spending. Its
	// late usage is additive, and replaying the same observation identity
	// counts it exactly once.
	late := observation("observation-late", first.ReservationID, 100, false)
	if err := controller.Observe(context.Background(), late); err != nil {
		t.Fatalf("late usage from an expired attempt was rejected: %v", err)
	}
	if err := controller.Observe(context.Background(), late); err != nil {
		t.Fatalf("replaying a late observation was rejected: %v", err)
	}
	accrued, err := controller.Reservation(context.Background(), testScope, first.ReservationID)
	if err != nil || accrued.ObservedMicros != 350 || accrued.UpperBoundMicros != 900 || accrued.Released {
		t.Fatalf("reservation after late usage = %+v err=%v, want 350 observed against the retained bound", accrued, err)
	}
	// All-attempt accounting still charges the elapsed attempt its worst case,
	// because its cost is not yet authoritative.
	total, err := controller.RootTotal(context.Background(), testScope, "root")
	if err != nil || total != 900 {
		t.Fatalf("root total=%d err=%v, want the fenced attempt still charged at worst case", total, err)
	}
	// Sweeping again converges: a hold is fenced once.
	swept, err := controller.FenceExpired(context.Background(), testScope, "root")
	if err != nil || len(swept) != 0 {
		t.Fatalf("swept=%d err=%v, want nothing left to fence", len(swept), err)
	}
	// Authoritative finality arrives from the attempt itself. Only now may the
	// reservation reconcile and release, and only now does the headroom return.
	if err := controller.Observe(context.Background(), observation("observation-final", first.ReservationID, 0, true)); err != nil {
		t.Fatal(err)
	}
	settledCost := int64(350)
	settled, err := controller.Reconcile(context.Background(), testScope, first.ReservationID, 1, &settledCost, true, SettlementActor)
	if err != nil || !settled.Released || settled.UpperBoundMicros != 350 {
		t.Fatalf("settled=%+v err=%v, want release at the authoritative final cost", settled, err)
	}
	third := estimate("reservation-3", "run", 600)
	third.ExpiresAt = moving.Now().Add(time.Minute)
	if _, err := controller.ReserveInitial(context.Background(), third, 1); err != nil {
		t.Fatalf("headroom did not return after authoritative settlement: %v", err)
	}
}
