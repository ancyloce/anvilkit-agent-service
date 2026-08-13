package budget

import (
	"context"
	"errors"
	"math/rand"
	"testing"
	"time"

	"github.com/ancyloce/anvilkit-agent-service/internal/problem"
)

type ids struct{ next int }

func (i *ids) ReservationID() ReservationID {
	i.next++
	return ReservationID("reservation-" + string(rune('0'+i.next)))
}

type exposure struct {
	held, actual int64
	calls        int
	review       bool
}

func (e *exposure) ObserveExposure(_ context.Context, _ string, held, actual int64, review bool) error {
	e.held, e.actual, e.calls = held, actual, e.calls+1
	e.review = review
	return nil
}

type clock struct{ now time.Time }

func (c clock) Now() time.Time { return c.now }
func controller(t *testing.T) (*Controller, *MemoryLedger, *exposure, Generation) {
	t.Helper()
	ids := &ids{}
	ledger := NewMemoryLedger(ids)
	metric := &exposure{}
	controller, err := New(ledger, ids, metric, clock{time.Now()}, HeadroomPolicy{MaximumReservedMicros: 1_000_000, ReviewAtBasisPoints: 8000})
	if err != nil {
		t.Fatal(err)
	}
	generation, _ := controller.Activate("root")
	return controller, ledger, metric, generation
}
func estimate(run string, cost int64) Estimate {
	return Estimate{RootRunID: "root", RunID: run, WorkspaceID: "workspace", PolicyVersion: "policy-v1", BudgetVersion: "budget-v1", MaximumCostMicros: cost, ExpiresAt: time.Now().Add(time.Hour)}
}

func TestReservationBeforeDispatchAndReplacementKeepsPriorOpen(t *testing.T) {
	controller, ledger, metric, generation := controller(t)
	calls := 0
	if err := controller.Dispatch(context.Background(), "missing", generation, func(context.Context, Reservation) error { calls++; return nil }); err == nil || calls != 0 {
		t.Fatal("unreserved dispatch occurred")
	}
	first, err := controller.ReserveInitial(context.Background(), estimate("run", 100), generation)
	if err != nil {
		t.Fatal(err)
	}
	if err := controller.Dispatch(context.Background(), first.ID, generation, func(context.Context, Reservation) error { calls++; return nil }); err != nil || calls != 1 {
		t.Fatalf("dispatch=%d err=%v", calls, err)
	}
	replacement, err := controller.ReserveReplacement(context.Background(), estimate("run", 200), generation, first.ID)
	if err != nil {
		t.Fatal(err)
	}
	prior, _ := ledger.Reservation(context.Background(), first.ID)
	if prior.Released || replacement.ID == first.ID || metric.held != 300 {
		t.Fatalf("prior=%#v replacement=%#v metric=%#v", prior, replacement, metric)
	}
}

func TestReplacementMatrixReservesIncrementBeforeProviderRetryFallbackOrSupersede(t *testing.T) {
	for _, mode := range []string{"provider-retry", "fallback-child", "superseded-attempt"} {
		t.Run(mode, func(t *testing.T) {
			controller, ledger, _, generation := controller(t)
			prior, err := controller.ReserveInitial(context.Background(), estimate("run", 100), generation)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := controller.ReserveReplacement(context.Background(), estimate(mode, 150), generation, prior.ID); err != nil {
				t.Fatal(err)
			}
			stillHeld, _ := ledger.Reservation(context.Background(), prior.ID)
			if stillHeld.Released {
				t.Fatalf("%s released prior reservation before replacement finality", mode)
			}
		})
	}
}

func TestExposureMetricRaisesConfiguredReviewSignal(t *testing.T) {
	identifier := &ids{}
	ledger := NewMemoryLedger(identifier)
	metric := &exposure{}
	controller, err := New(ledger, identifier, metric, clock{time.Now()}, HeadroomPolicy{MaximumReservedMicros: 250, ReviewAtBasisPoints: 8000})
	if err != nil {
		t.Fatal(err)
	}
	generation, _ := controller.Activate("root")
	if _, err := controller.ReserveInitial(context.Background(), estimate("run", 200), generation); err != nil {
		t.Fatal(err)
	}
	if !metric.review || metric.held != 200 {
		t.Fatalf("review signal=%v held=%d", metric.review, metric.held)
	}
}

func TestUnknownFinalAndGenerationFencedSettlement(t *testing.T) {
	controller, ledger, _, generation := controller(t)
	reservation, _ := controller.ReserveInitial(context.Background(), estimate("run", 100), generation)
	if err := controller.Observe(context.Background(), Observation{ID: "observation", ReservationID: reservation.ID, RootRunID: "root", RunID: "run", TaskID: "task", AttemptID: "attempt", CostMicros: 25, Final: true}); err != nil {
		t.Fatal(err)
	}
	total, _ := controller.RootTotal(context.Background(), "root")
	if total != 25 {
		t.Fatalf("known final=%d", total)
	}
	next, _ := controller.ReserveReplacement(context.Background(), estimate("run", 200), generation, reservation.ID)
	total, _ = controller.RootTotal(context.Background(), "root")
	if total != 225 {
		t.Fatalf("unknown final not held at upper bound: %d", total)
	}
	for _, item := range []struct {
		generation Generation
		actor      string
	}{{generation + 1, "budget-controller"}, {generation, "worker"}} {
		if _, err := controller.Reconcile(context.Background(), reservation.ID, item.generation, ptr(25), true, item.actor); err == nil {
			t.Fatal("unauthorized release succeeded")
		}
	}
	if _, err := controller.Reconcile(context.Background(), next.ID, generation, nil, true, "budget-controller"); err == nil {
		t.Fatal("nonfinal reservation released")
	}
	settled, err := controller.Reconcile(context.Background(), reservation.ID, generation, ptr(25), true, "budget-controller")
	if err != nil || !settled.Released {
		t.Fatalf("settled=%#v err=%v", settled, err)
	}
	_ = ledger
}

func TestRootAggregationNeverUndercountsRandomAttemptHistories(t *testing.T) {
	for seed := int64(0); seed < 100; seed++ {
		controller, _, _, generation := controller(t)
		random := rand.New(rand.NewSource(seed))
		var expected int64
		var prior ReservationID
		for index := 0; index < 25; index++ {
			upper := int64(random.Intn(1000) + 1)
			var reservation Reservation
			var err error
			if index == 0 {
				reservation, err = controller.ReserveInitial(context.Background(), estimate("root", upper), generation)
			} else {
				reservation, err = controller.ReserveReplacement(context.Background(), estimate("child", upper), generation, prior)
			}
			if err != nil {
				t.Fatal(err)
			}
			prior = reservation.ID
			if random.Intn(2) == 0 {
				actual := int64(random.Intn(int(upper) + 1))
				if err := controller.Observe(context.Background(), Observation{ID: string(reservation.ID), ReservationID: reservation.ID, RootRunID: "root", RunID: "child", TaskID: "task", AttemptID: AttemptID(reservation.ID), CostMicros: actual, Final: true}); err != nil {
					t.Fatal(err)
				}
				expected += actual
			} else {
				expected += upper
			}
		}
		total, err := controller.RootTotal(context.Background(), "root")
		if err != nil || total != expected {
			t.Fatalf("seed=%d total=%d expected=%d err=%v", seed, total, expected, err)
		}
	}
}

func TestReservationFailureNeverDispatches(t *testing.T) {
	ids := &ids{}
	ledger := NewMemoryLedger(ids)
	controller, _ := New(ledger, ids, &exposure{}, clock{time.Now()}, HeadroomPolicy{MaximumReservedMicros: 50, ReviewAtBasisPoints: 8000})
	generation, _ := controller.Activate("root")
	_, err := controller.ReserveInitial(context.Background(), estimate("run", 100), generation)
	var details problem.Details
	if !errors.As(err, &details) || details.Code != string(problem.CodeBudgetDenied) {
		t.Fatalf("err=%v", err)
	}
}
func ptr(value int64) *int64 { return &value }
