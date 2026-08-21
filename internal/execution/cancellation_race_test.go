package execution_test

import (
	"context"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/ancyloce/anvilkit-agent-service/internal/budget"
	"github.com/ancyloce/anvilkit-agent-service/internal/interrupts"
	"github.com/ancyloce/anvilkit-agent-service/internal/modelgateway"
	"github.com/ancyloce/anvilkit-agent-service/internal/runs"
	"github.com/ancyloce/anvilkit-agent-service/internal/workflow"
)

// heldProviderCall holds one real billable provider call open. The first
// invocation announces that it has entered the provider and then blocks until
// the test releases it; everything after it passes straight through. It is the
// only faithful way to exercise the race this file is about — a cancellation
// that lands while a call the tenant is being billed for is still running.
type heldProviderCall struct {
	inner    modelgateway.Adapter
	entered  chan struct{}
	release  chan struct{}
	announce sync.Once
	lock     sync.Mutex
	returned bool
}

func newHeldProviderCall(inner modelgateway.Adapter) *heldProviderCall {
	return &heldProviderCall{inner: inner, entered: make(chan struct{}), release: make(chan struct{})}
}

func (h *heldProviderCall) Invoke(ctx context.Context, request modelgateway.AdapterRequest) (modelgateway.AdapterResponse, error) {
	first := false
	h.announce.Do(func() {
		first = true
		close(h.entered)
	})
	if first {
		<-h.release
	}
	response, err := h.inner.Invoke(ctx, request)
	if first {
		h.lock.Lock()
		h.returned = true
		h.lock.Unlock()
	}
	return response, err
}

// inFlight reports whether the held call is still running. The production
// reconciler answers the same question from the durable provider-invocation
// record, which carries a start with no completion for exactly this window.
func (h *heldProviderCall) inFlight() bool {
	select {
	case <-h.entered:
	default:
		return false
	}
	h.lock.Lock()
	defer h.lock.Unlock()
	return !h.returned
}

// providerReconciler answers cancellation reconciliation from the same
// in-flight provider state the production reader answers from: a run with an
// open provider invocation is never clear.
type providerReconciler struct{ call *heldProviderCall }

func (r providerReconciler) Reconcile(context.Context, runs.Scope, runs.ID, bool) (bool, *runs.State, error) {
	return !r.call.inFlight(), nil, nil
}

// recordingLeases records the runs whose leases cancellation revoked.
type recordingLeases struct {
	lock    sync.Mutex
	revoked []string
}

func (l *recordingLeases) RevokeRun(_ context.Context, _ runs.Scope, id runs.ID) error {
	l.lock.Lock()
	defer l.lock.Unlock()
	l.revoked = append(l.revoked, string(id))
	return nil
}

func (l *recordingLeases) records() []string {
	l.lock.Lock()
	defer l.lock.Unlock()
	return append([]string(nil), l.revoked...)
}

// TestCancellationDuringBilledCallHoldsBudgetUntilFinality is the regression
// for the accounting defect cancellation used to have: it concluded the
// physical attempt on the spot — recording a finality nobody had observed and
// releasing the hold — while a call the tenant was being billed for was still
// running. The usage that call reported afterwards then landed on a released
// reservation, where it was refused, so the run's real cost was lost and the
// root's exposure understated by exactly the amount actually spent.
//
// The run below is cancelled while a real provider call is held open. What the
// test asserts is the whole corrected sequence: authority is revoked at once,
// the hold stays fenced and whole until the call returns, the returning usage
// is accepted once and only once, the settlement is for the full amount, the
// release happens only after finality, and replaying or restarting the
// recovery converges instead of charging again.
func TestCancellationDuringBilledCallHoldsBudgetUntilFinality(t *testing.T) {
	ctx := context.Background()
	held := newHeldProviderCall(nil)
	reconciler := providerReconciler{call: held}
	leases := &recordingLeases{}
	h := newHarness(t, [][]byte{inputPlan(), finalPlan()}, func(options *harnessOptions) {
		options.modelAdapter = func(inner modelgateway.Adapter) modelgateway.Adapter {
			held.inner = inner
			return held
		}
		options.reconciler = reconciler
		options.leases = leases
	})

	input := h.seedRun("artifact-validation")
	reservationID := budget.ReservationID("budget:" + testRunID + ":g1")
	const worstCaseMicros = int64(100_000_000)
	const billedMicros = int64(1_000)

	done := make(chan workflow.RunOutcome, 1)
	go func() {
		outcome, _ := h.engine.ExecuteRun(ctx, input)
		done <- outcome
	}()

	// The run is now inside a billable provider call that has not returned.
	select {
	case <-held.entered:
	case <-time.After(10 * time.Second):
		t.Fatal("the provider call was never entered")
	}
	reserved, err := h.budgetLedger.Reservation(ctx, testBudgetScope, reservationID)
	if err != nil {
		t.Fatalf("the run did not reserve before dispatching a billed call: %v", err)
	}
	if reserved.UpperBoundMicros != worstCaseMicros || reserved.Cancelled || reserved.Released {
		t.Fatalf("reservation before cancellation = %+v, want the full worst case held and unfenced", reserved)
	}

	// Cancel while the billed call is still running.
	snapshot := h.snapshot()
	if _, err := h.service.Cancel(ctx, interrupts.Write{Scope: testScope(), RunID: testRunID, ExpectedVersion: snapshot.Version, IdempotencyKey: "cancel-during-billed-call", Traceparent: traceparent}); err != nil {
		t.Fatalf("cancel during a billed call: %v", err)
	}

	// Dispatch authority and leases are gone immediately.
	if records := leases.records(); len(records) == 0 || records[0] != testRunID {
		t.Fatalf("revoked leases = %v, want the cancelled run revoked immediately", records)
	}
	fenced, err := h.budgetLedger.Reservation(ctx, testBudgetScope, reservationID)
	if err != nil {
		t.Fatal(err)
	}
	if !fenced.Cancelled {
		t.Fatalf("reservation after cancellation = %+v, want its dispatch authority revoked", fenced)
	}
	dispatchErr := h.budgetController.Dispatch(ctx, testBudgetScope, reservationID, 1, func(context.Context, budget.Reservation) error {
		return fmt.Errorf("a cancelled reservation authorized an expensive dispatch")
	})
	if dispatchErr == nil {
		t.Fatal("a cancelled reservation still authorized an expensive dispatch")
	}

	// The budget is still held, whole, and unfinalized: the call this
	// cancellation interrupted is still running and nobody knows its cost.
	if fenced.Released || fenced.AttemptFinal || fenced.UpperBoundMicros != worstCaseMicros {
		t.Fatalf("reservation while the billed call runs = %+v, want the full worst case still held and no manufactured finality", fenced)
	}
	if h.snapshot().Status != runs.Cancelling {
		t.Fatalf("run state = %s, want the cancellation to stay visibly unreconciled", h.snapshot().Status)
	}

	// Let the billed call return.
	close(held.release)
	select {
	case <-done:
	case <-time.After(20 * time.Second):
		t.Fatal("the cancelled run never unwound")
	}

	// The usage the call reported was accepted, exactly once, onto the fenced
	// hold — and it changed nothing else.
	reported, err := h.budgetLedger.Reservation(ctx, testBudgetScope, reservationID)
	if err != nil {
		t.Fatal(err)
	}
	if reported.ObservedMicros != billedMicros {
		t.Fatalf("observed usage after the call returned = %d, want exactly the %d micros it billed", reported.ObservedMicros, billedMicros)
	}
	if reported.Released || reported.AttemptFinal || reported.UpperBoundMicros != worstCaseMicros {
		t.Fatalf("reservation after the call returned = %+v, want it still held until finality is reconciled", reported)
	}

	// Recovery is what concludes it, and only now that the reconciler can
	// prove no physical attempt of the run is outstanding.
	recovery, err := interrupts.NewCancellationRecovery(h.repo, reconciler, h.settlement)
	if err != nil {
		t.Fatal(err)
	}
	concluded, err := recovery.Scan(ctx)
	if err != nil || concluded != 1 {
		t.Fatalf("recovery scan settled %d runs (err %v), want exactly the cancelled run", concluded, err)
	}
	// The recovery finishes the cancellation, not just its accounting. A run
	// left cancelling for ever would be a terminal state nothing can reach:
	// the aggregate leaves that state only through reconciliation, and no
	// fresh cancel request can supply it.
	if state := h.snapshot().Status; state != runs.Cancelled {
		t.Fatalf("run state after recovery = %s, want the cancellation finished", state)
	}
	settled, err := h.budgetLedger.Reservation(ctx, testBudgetScope, reservationID)
	if err != nil {
		t.Fatal(err)
	}
	if !settled.AttemptFinal || !settled.Released {
		t.Fatalf("settled reservation = %+v, want it final and released once finality was reconciled", settled)
	}
	if settled.ObservedMicros != billedMicros || settled.UpperBoundMicros != billedMicros {
		t.Fatalf("settled reservation = %+v, want it settled at the full %d micros the attempt billed", settled, billedMicros)
	}
	if !settled.Cancelled {
		t.Fatalf("settled reservation = %+v, want the cancellation fence to survive settlement", settled)
	}
	if dispatchErr := h.budgetController.Dispatch(ctx, testBudgetScope, reservationID, 1, func(context.Context, budget.Reservation) error {
		return fmt.Errorf("a settled cancelled reservation authorized an expensive dispatch")
	}); dispatchErr == nil {
		t.Fatal("settlement handed cancelled work its dispatch authority back")
	}

	// Replay and restart converge: the same scan, and a fresh controller over
	// the same durable ledger, report nothing further and charge nothing more.
	total, err := h.budgetController.RootTotal(ctx, testBudgetScope, testRunID)
	if err != nil {
		t.Fatal(err)
	}
	repeat, err := recovery.Scan(ctx)
	if err != nil || repeat != 0 {
		t.Fatalf("repeated recovery scan settled %d runs (err %v), want nothing further", repeat, err)
	}
	if state := h.snapshot().Status; state != runs.Cancelled {
		t.Fatalf("run state after a repeated recovery = %s, want it unchanged", state)
	}
	restarted, err := budget.New(h.budgetLedger, repoGenerations{h.repo}, nullExposure{}, systemClock{}, budget.HeadroomPolicy{MaximumReservedMicros: 10_000_000_000, ReviewAtBasisPoints: 8000})
	if err != nil {
		t.Fatal(err)
	}
	recovered, err := restarted.RecoverCancelledFinality(ctx, testBudgetScope, testRunID, budget.SettlementActor)
	if err != nil || len(recovered) != 0 {
		t.Fatalf("recovery after restart settled %v (err %v), want nothing further", recovered, err)
	}
	after, err := h.budgetController.RootTotal(ctx, testBudgetScope, testRunID)
	if err != nil {
		t.Fatal(err)
	}
	if after != total || after != billedMicros {
		t.Fatalf("root total after replay and restart = %d (was %d), want the single %d micros the attempt actually billed", after, total, billedMicros)
	}
}
