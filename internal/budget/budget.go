// Package budget enforces reservation-before-dispatch and all-attempt accounting.
// Pagix remains financially authoritative behind Ledger.
package budget

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"sync"
	"time"

	"github.com/ancyloce/anvilkit-agent-service/internal/problem"
)

type ReservationID string
type AttemptID string
type Generation uint64

// Scope is the tenant boundary every budget read, lock, observation,
// settlement, and root aggregation is made under. No ledger operation
// addresses a reservation by identity alone: a reservation identity is only
// ever resolved inside the workspace and project that owns it, so one
// tenant's identity can never reach another tenant's ledger row.
type Scope struct{ WorkspaceID, ProjectID string }

func (s Scope) Valid() bool { return s.WorkspaceID != "" && s.ProjectID != "" }

// Estimate is the worst-case cost declaration a reservation is made from.
// ReservationID is the caller-derived deterministic identity of the
// reservation, so a durable operation replayed after a crash converges on
// the reservation it already made instead of holding budget twice.
type Estimate struct {
	ReservationID                                                          ReservationID
	RootRunID, RunID, WorkspaceID, ProjectID, PolicyVersion, BudgetVersion string
	MaximumCostMicros                                                      int64
	ExpiresAt                                                              time.Time
}

// Scope is the tenant boundary the estimate reserves inside.
func (e Estimate) Scope() Scope { return Scope{WorkspaceID: e.WorkspaceID, ProjectID: e.ProjectID} }

// Reservation is one durable hold. AttemptFinal and Released are authoritative
// facts about the physical attempt, never about the clock: only an observed
// final attempt makes a reservation final, and only settlement after finality
// releases it. Expired is the clock's own fact — the reservation's lifetime
// elapsed, so it may no longer authorize a dispatch and is awaiting
// reconciliation — and it deliberately does not release the hold: work whose
// true cost is still unknown keeps its worst-case headroom until finality is
// known.
type Reservation struct {
	ID                                                                     ReservationID
	RootRunID, RunID, WorkspaceID, ProjectID, PolicyVersion, BudgetVersion string
	UpperBoundMicros, ObservedMicros                                       int64
	Generation                                                             Generation
	AttemptFinal                                                           bool
	Released                                                               bool
	Expired                                                                bool
	ExpiresAt                                                              time.Time
}

// Scope is the tenant boundary the reservation belongs to.
func (r Reservation) Scope() Scope {
	return Scope{WorkspaceID: r.WorkspaceID, ProjectID: r.ProjectID}
}

type Observation struct {
	ID                                                string
	Scope                                             Scope
	ReservationID                                     ReservationID
	RootRunID, RunID, TaskID                          string
	AttemptID                                         AttemptID
	RecoveryEpoch, ExecutionGeneration, MeterSequence uint64
	CostMicros                                        int64
	Final                                             bool
}
type Settlement struct {
	Scope         Scope
	ReservationID ReservationID
	Generation    Generation
	FinalCost     int64
	Release       bool
	Actor         string
}

// Ledger is the durable reservation record. Every operation is scoped by
// workspace and project. Reserve converges when an identical reservation
// identity already exists (a replayed durable operation) and conflicts on any
// identity mismatch; the recorded expiry wins on convergence. Observe is
// additive and deduplicated by observation identity; Settle is
// generation-fenced and monotonic.
type Ledger interface {
	// Reserve enforces the root headroom bound and records the reservation in
	// one serialized critical section per root-run scope: the check and the
	// insertion are atomic, so concurrent reservations can never together
	// exceed maximumReservedMicros. Reservations whose lifetime already
	// elapsed are fenced inside that same critical section, so the headroom
	// the bound is measured against is always live — and, because a fenced
	// hold keeps its worst-case bound, never understated. Replaying the
	// identity of a reservation that has since expired is refused rather than
	// answered with a reservation that can no longer authorize anything.
	Reserve(ctx context.Context, estimate Estimate, generation Generation, maximumReservedMicros int64) (Reservation, error)
	Observe(context.Context, Observation) error
	Settle(context.Context, Settlement) (Reservation, error)
	Reservation(context.Context, Scope, ReservationID) (Reservation, error)
	RootReservations(context.Context, Scope, string) ([]Reservation, error)
	// FenceExpired fences every unreleased reservation of the scope's root
	// aggregate whose lifetime elapsed and reports what it fenced. Fencing is
	// an explicit durable act with its own immutable record: the hold may no
	// longer authorize a dispatch, its late usage stays additive, and it keeps
	// its worst-case headroom until the physical attempt's authoritative
	// finality arrives. The clock never settles, releases, or finalizes work
	// whose true cost nobody has reported.
	FenceExpired(ctx context.Context, scope Scope, rootRunID string, now time.Time) ([]Reservation, error)
}

// Generations answers the one active budget generation for a root run. The
// run aggregate's execution generation is that authority: an explicit retry
// advances it durably, and the controller fences every reservation and
// settlement on it — there is no second, process-local generation state, so
// a restarted process recovers the current generation by reading it.
type Generations interface {
	Current(ctx context.Context, workspaceID, projectID, rootRunID string) (Generation, error)
}
type ExposureSink interface {
	ObserveExposure(context.Context, string, int64, int64, bool) error
}
type Clock interface{ Now() time.Time }

type HeadroomPolicy struct {
	MaximumReservedMicros int64
	ReviewAtBasisPoints   int
}

func (p HeadroomPolicy) Validate() error {
	if p.MaximumReservedMicros < 1 || p.ReviewAtBasisPoints < 1 || p.ReviewAtBasisPoints > 10_000 {
		return fmt.Errorf("budget headroom policy is invalid")
	}
	return nil
}

type Controller struct {
	ledger      Ledger
	generations Generations
	exposure    ExposureSink
	clock       Clock
	policy      HeadroomPolicy
}

func New(ledger Ledger, generations Generations, exposure ExposureSink, clock Clock, policy HeadroomPolicy) (*Controller, error) {
	if ledger == nil || generations == nil || exposure == nil || clock == nil || policy.Validate() != nil {
		return nil, fmt.Errorf("budget controller dependencies are invalid")
	}
	return &Controller{ledger: ledger, generations: generations, exposure: exposure, clock: clock, policy: policy}, nil
}

// current resolves the active generation for the root run through the one
// durable generation authority.
func (c *Controller) current(ctx context.Context, scope Scope, rootRunID string) (Generation, error) {
	generation, err := c.generations.Current(ctx, scope.WorkspaceID, scope.ProjectID, rootRunID)
	if err != nil {
		return 0, fmt.Errorf("resolve budget generation: %w", err)
	}
	return generation, nil
}

// ReserveInitial and ReserveReplacement both reserve before dispatch.
// Replacement deliberately does not settle any prior reservation: the prior
// generation's cost stays held, so replacement work needs incremental
// worst-case headroom on top of what was already spent.
func (c *Controller) ReserveInitial(ctx context.Context, estimate Estimate, generation Generation) (Reservation, error) {
	return c.reserve(ctx, estimate, generation)
}
func (c *Controller) ReserveReplacement(ctx context.Context, estimate Estimate, generation Generation, prior ReservationID) (Reservation, error) {
	if !estimate.Scope().Valid() {
		return Reservation{}, budgetProblem("reservation estimate is invalid")
	}
	previous, err := c.ledger.Reservation(ctx, estimate.Scope(), prior)
	if err != nil || previous.Released || previous.RootRunID != estimate.RootRunID || previous.WorkspaceID != estimate.WorkspaceID || previous.ProjectID != estimate.ProjectID {
		return Reservation{}, budgetProblem("prior reservation must remain open for replacement or fallback")
	}
	return c.reserve(ctx, estimate, generation)
}
func (c *Controller) reserve(ctx context.Context, estimate Estimate, generation Generation) (Reservation, error) {
	now := c.clock.Now()
	if estimate.ReservationID == "" || estimate.RootRunID == "" || estimate.RunID == "" || !estimate.Scope().Valid() || estimate.PolicyVersion == "" || estimate.BudgetVersion == "" || estimate.MaximumCostMicros < 1 || now.IsZero() || estimate.ExpiresAt.IsZero() || generation == 0 {
		return Reservation{}, budgetProblem("reservation estimate is invalid")
	}
	current, err := c.current(ctx, estimate.Scope(), estimate.RootRunID)
	if err != nil {
		return Reservation{}, err
	}
	if generation != current {
		return Reservation{}, budgetProblem("reservation generation is not the active budget generation")
	}
	// Headroom is enforced by the ledger inside the same critical section that
	// inserts the reservation. There is no check-then-insert window here: a
	// controller-side sum could only ever observe a pre-insertion total, which
	// is exactly what lets two concurrent reservations both pass.
	reserved, err := c.ledger.Reserve(ctx, estimate, generation, c.policy.MaximumReservedMicros)
	if err != nil {
		var details problem.Details
		if errors.As(err, &details) {
			return Reservation{}, err
		}
		return Reservation{}, budgetProblem("authoritative reservation failed")
	}
	if reserved.ID == "" {
		return Reservation{}, fmt.Errorf("ledger returned empty reservation identity")
	}
	// The binding of the durable reservation is verified field for field. The
	// expiry is exempt from equality: a replayed reservation keeps the expiry
	// the first execution recorded.
	if reserved.ID != estimate.ReservationID || reserved.RootRunID != estimate.RootRunID || reserved.RunID != estimate.RunID || reserved.WorkspaceID != estimate.WorkspaceID || reserved.ProjectID != estimate.ProjectID || reserved.PolicyVersion != estimate.PolicyVersion || reserved.BudgetVersion != estimate.BudgetVersion || reserved.Generation != generation || reserved.UpperBoundMicros != estimate.MaximumCostMicros || reserved.ExpiresAt.IsZero() || reserved.Released {
		return Reservation{}, budgetProblem("authoritative reservation binding is invalid")
	}
	c.reportExposure(ctx, estimate.Scope(), estimate.RootRunID)
	return reserved, nil
}

// reportExposure publishes the root aggregate's current exposure. It is
// observational: the authoritative bound is enforced inside the ledger, so a
// failed read here never changes what was allowed.
func (c *Controller) reportExposure(ctx context.Context, scope Scope, rootRunID string) {
	reservations, err := c.ledger.RootReservations(ctx, scope, rootRunID)
	if err != nil {
		return
	}
	held := rootHeld(reservations)
	_ = c.exposure.ObserveExposure(ctx, rootRunID, held, rootObserved(reservations), c.review(held))
}

type Dispatch func(context.Context, Reservation) error

// Dispatch proves reservation-before-dispatch at the moment of dispatch: the
// reservation must exist in this scope, be unreleased and unexpired, and
// belong to the active budget generation of its root run.
func (c *Controller) Dispatch(ctx context.Context, scope Scope, id ReservationID, generation Generation, dispatch Dispatch) error {
	if dispatch == nil {
		return fmt.Errorf("dispatch function is required")
	}
	if !scope.Valid() {
		return budgetProblem("expensive dispatch lacks a scoped reservation")
	}
	reservation, err := c.ledger.Reservation(ctx, scope, id)
	now := c.clock.Now()
	if err != nil || reservation.Released || reservation.Expired || reservation.Generation != generation || now.IsZero() || !now.Before(reservation.ExpiresAt) {
		return budgetProblem("expensive dispatch lacks a current reservation")
	}
	current, err := c.current(ctx, reservation.Scope(), reservation.RootRunID)
	if err != nil {
		return err
	}
	if generation != current {
		return budgetProblem("expensive dispatch lacks a current reservation")
	}
	return dispatch(ctx, reservation)
}
func (c *Controller) Observe(ctx context.Context, observation Observation) error {
	if observation.ID == "" || !observation.Scope.Valid() || observation.ReservationID == "" || observation.RootRunID == "" || observation.RunID == "" || observation.TaskID == "" || observation.AttemptID == "" || observation.CostMicros < 0 {
		return budgetProblem("usage observation is invalid")
	}
	return c.ledger.Observe(ctx, observation)
}

// Reservation reads one durable reservation inside its owning scope.
func (c *Controller) Reservation(ctx context.Context, scope Scope, id ReservationID) (Reservation, error) {
	if !scope.Valid() {
		return Reservation{}, budgetProblem("reservation read requires workspace and project identity")
	}
	return c.ledger.Reservation(ctx, scope, id)
}

// FenceExpired fences every elapsed reservation of one root aggregate and
// republishes the resulting exposure. It is the explicit operator- and
// lifecycle-reachable form of the same fencing Reserve performs inside its
// critical section. Fencing is not settlement: the clock can prove that a
// reservation may no longer authorize new work, but it can prove nothing about
// what the physical attempt actually spent. So the hold stays, at its
// worst-case bound, until an observed final attempt or an authorized
// reconciliation supplies that fact.
func (c *Controller) FenceExpired(ctx context.Context, scope Scope, rootRunID string) ([]Reservation, error) {
	now := c.clock.Now()
	if !scope.Valid() || rootRunID == "" || now.IsZero() {
		return nil, budgetProblem("expiry fencing requires a scoped root run and authoritative time")
	}
	fenced, err := c.ledger.FenceExpired(ctx, scope, rootRunID, now)
	if err != nil {
		return nil, err
	}
	c.reportExposure(ctx, scope, rootRunID)
	return fenced, nil
}

// Reconcile holds unknown-final work at the upper bound. Only the active
// budget generation may reduce or release after finality. An expired
// reservation reconciles by exactly this path and no other: the fence removed
// its authority to dispatch, not the requirement that its release be backed by
// an authoritative final cost.
func (c *Controller) Reconcile(ctx context.Context, scope Scope, id ReservationID, generation Generation, finalCost *int64, release bool, actor string) (Reservation, error) {
	if !scope.Valid() {
		return Reservation{}, budgetProblem("settlement requires workspace and project identity")
	}
	reservation, err := c.ledger.Reservation(ctx, scope, id)
	if err != nil {
		return Reservation{}, err
	}
	current, err := c.current(ctx, reservation.Scope(), reservation.RootRunID)
	if err != nil {
		return Reservation{}, err
	}
	if actor != SettlementActor || generation == 0 || generation != reservation.Generation || generation != current {
		return Reservation{}, budgetProblem("stale or unauthorized reservation settlement")
	}
	if !reservation.AttemptFinal {
		return Reservation{}, budgetProblem("reservation cannot reconcile before attempt finality")
	}
	cost := reservation.UpperBoundMicros
	if finalCost != nil {
		if *finalCost < 0 || *finalCost > reservation.UpperBoundMicros || *finalCost < reservation.ObservedMicros {
			return Reservation{}, budgetProblem("final usage is inconsistent")
		}
		cost = *finalCost
	}
	settled, err := c.ledger.Settle(ctx, Settlement{Scope: scope, ReservationID: id, Generation: generation, FinalCost: cost, Release: release, Actor: actor})
	if err != nil {
		return Reservation{}, err
	}
	c.reportExposure(ctx, scope, reservation.RootRunID)
	return settled, nil
}

// ReconcileSuperseded settles the root aggregate's finalized reservations from
// generations the active one has superseded, and reports what it settled.
//
// A reservation is fenced on the generation that made it: once an explicit
// retry advances the root aggregate's generation, the prior generation's hold
// can never again be the active one, so the ordinary settlement path — which
// requires the settling generation to be both the reservation's and the
// current one — can no longer reach it. Its worst-case bound would then stay
// held for ever, and enough retries would exhaust the root's headroom
// permanently even though no attempt ever spent it. This is the path that
// closes that: the current authority proves itself, and each prior-generation
// hold whose physical attempt is authoritatively final is reduced to the usage
// that attempt actually reported.
//
// What it deliberately does not do is as important. It settles nothing whose
// finality is unknown — a hold whose attempt may still be running keeps its
// full worst-case bound, because a superseded generation is not evidence of
// what an attempt spent. It does not release: the actual cost of every attempt
// stays counted against the root, which is what all-attempt accounting means.
// And it never clears the fence or the expiry, so a settled prior-generation
// reservation gains no authority to dispatch — Dispatch still requires the
// active generation, which a superseded hold can never be again.
//
// It converges: a hold already reduced to its observed usage is skipped, so
// repeating the reconciliation reports nothing further and changes nothing.
func (c *Controller) ReconcileSuperseded(ctx context.Context, scope Scope, rootRunID string, current Generation, actor string) ([]Reservation, error) {
	if !scope.Valid() || rootRunID == "" {
		return nil, budgetProblem("superseded settlement requires a scoped root run")
	}
	if actor != SettlementActor || current == 0 {
		return nil, budgetProblem("stale or unauthorized reservation settlement")
	}
	active, err := c.current(ctx, scope, rootRunID)
	if err != nil {
		return nil, err
	}
	if current != active {
		// The caller is not acting for the generation that is actually current.
		// Settling prior generations on a stale view of which one is current is
		// exactly the mistake this path exists to avoid.
		return nil, budgetProblem("stale or unauthorized reservation settlement")
	}
	held, err := c.ledger.RootReservations(ctx, scope, rootRunID)
	if err != nil {
		return nil, err
	}
	var settled []Reservation
	for _, reservation := range held {
		if reservation.Generation >= active || reservation.Released || !reservation.AttemptFinal {
			continue
		}
		if reservation.UpperBoundMicros == reservation.ObservedMicros {
			// Already reconciled to its authoritative usage; there is no
			// worst-case headroom left to give back.
			continue
		}
		// The settlement is fenced on the reservation's own generation, which
		// is what the ledger's monotonic guard checks. Authorization to make
		// it at all came from the current-authority proof above.
		value, err := c.ledger.Settle(ctx, Settlement{Scope: scope, ReservationID: reservation.ID, Generation: reservation.Generation, FinalCost: reservation.ObservedMicros, Release: false, Actor: actor})
		if err != nil {
			return nil, fmt.Errorf("settle superseded reservation %s: %w", reservation.ID, err)
		}
		settled = append(settled, value)
	}
	if len(settled) > 0 {
		c.reportExposure(ctx, scope, rootRunID)
	}
	return settled, nil
}

// SettlementActor names the one authority permitted to reduce or release a
// reservation after attempt finality.
const SettlementActor = "budget-controller"

func (c *Controller) review(held int64) bool {
	whole := c.policy.MaximumReservedMicros / 10_000
	remainder := c.policy.MaximumReservedMicros % 10_000
	threshold := whole*int64(c.policy.ReviewAtBasisPoints) + (remainder*int64(c.policy.ReviewAtBasisPoints)+9_999)/10_000
	return held >= threshold
}
func (c *Controller) RootTotal(ctx context.Context, scope Scope, rootRunID string) (int64, error) {
	if !scope.Valid() {
		return 0, budgetProblem("root total requires workspace and project identity")
	}
	values, err := c.ledger.RootReservations(ctx, scope, rootRunID)
	if err != nil {
		return 0, err
	}
	var total int64
	for _, value := range values {
		charge := value.UpperBoundMicros
		if value.AttemptFinal {
			charge = value.ObservedMicros
		}
		var ok bool
		total, ok = addMicros(total, charge)
		if !ok {
			return 0, budgetProblem("root usage total overflowed")
		}
	}
	return total, nil
}
func rootHeld(values []Reservation) int64 {
	var total int64
	for _, value := range values {
		if !value.Released {
			var ok bool
			total, ok = addMicros(total, value.UpperBoundMicros)
			if !ok {
				return maxMicros
			}
		}
	}
	return total
}
func rootObserved(values []Reservation) int64 {
	var total int64
	for _, value := range values {
		var ok bool
		total, ok = addMicros(total, value.ObservedMicros)
		if !ok {
			return maxMicros
		}
	}
	return total
}

const maxMicros = int64(^uint64(0) >> 1)

func addMicros(left, right int64) (int64, bool) {
	if left < 0 || right < 0 || right > maxMicros-left {
		return 0, false
	}
	return left + right, true
}
func budgetProblem(detail string) problem.Details {
	value := problem.New(problem.CodeBudgetDenied, "")
	value.Detail = detail
	return value
}

// ExpiryObservationID is the deterministic identity of the immutable record an
// expiry fence leaves behind. Both ledgers write it, so an expired hold is
// auditable as an explicit fence in either topology. The record carries no
// cost and is not final: it states that the lifetime elapsed, never what the
// attempt spent.
func ExpiryObservationID(id ReservationID) string { return "budget:expired:" + string(id) }

// MemoryGenerations is the deterministic test generation authority. The
// production authority reads the root run aggregate's execution generation.
type MemoryGenerations struct {
	lock   sync.Mutex
	values map[string]Generation
}

func NewMemoryGenerations() *MemoryGenerations {
	return &MemoryGenerations{values: map[string]Generation{}}
}
func generationKey(workspaceID, projectID, rootRunID string) string {
	return workspaceID + "\x00" + projectID + "\x00" + rootRunID
}
func (g *MemoryGenerations) Set(workspaceID, projectID, rootRunID string, generation Generation) {
	g.lock.Lock()
	defer g.lock.Unlock()
	g.values[generationKey(workspaceID, projectID, rootRunID)] = generation
}
func (g *MemoryGenerations) Current(_ context.Context, workspaceID, projectID, rootRunID string) (Generation, error) {
	g.lock.Lock()
	defer g.lock.Unlock()
	generation, ok := g.values[generationKey(workspaceID, projectID, rootRunID)]
	if !ok {
		return 0, problem.New(problem.CodeResourceNotFound, "")
	}
	return generation, nil
}

// MemoryLedger is deterministic test/local infrastructure implementing
// scoped, convergent reservation, atomic headroom enforcement, additive
// deduplicated observations, explicit expiry settlement, and
// generation-fenced settlement — the same contract the durable ledger keeps.
type MemoryLedger struct {
	lock         sync.Mutex
	now          func() time.Time
	values       map[string]Reservation
	observations map[string]Observation
}

// NewMemoryLedger builds the in-memory ledger over an explicit clock. The
// ledger owns its own time for the same reason the durable one does: expiry
// settlement is a ledger decision made inside the same critical section as
// the headroom check, not something a caller can shift.
func NewMemoryLedger(now func() time.Time) *MemoryLedger {
	if now == nil {
		now = time.Now
	}
	return &MemoryLedger{now: now, values: map[string]Reservation{}, observations: map[string]Observation{}}
}

// scopedKey binds a reservation identity to the tenant that owns it, so the
// memory ledger cannot resolve an identity across a workspace or project
// boundary any more than the durable one can.
func scopedKey(scope Scope, id ReservationID) string {
	return scope.WorkspaceID + "\x00" + scope.ProjectID + "\x00" + string(id)
}
func observationKey(scope Scope, id string) string {
	return scope.WorkspaceID + "\x00" + scope.ProjectID + "\x00" + id
}

func (l *MemoryLedger) Reserve(_ context.Context, estimate Estimate, generation Generation, maximumReservedMicros int64) (Reservation, error) {
	l.lock.Lock()
	defer l.lock.Unlock()
	if estimate.ReservationID == "" || !estimate.Scope().Valid() {
		return Reservation{}, fmt.Errorf("scoped reservation identity is required")
	}
	if maximumReservedMicros < 1 {
		return Reservation{}, fmt.Errorf("a positive reserved-exposure bound is required")
	}
	scope := estimate.Scope()
	key := scopedKey(scope, estimate.ReservationID)
	// Elapsed holds are fenced before anything else is decided — before the
	// replay is answered and before headroom is measured — so a replay can
	// never be answered from a hold the clock has already invalidated. The
	// whole sequence runs under one lock, exactly as the durable ledger runs
	// it under one transaction.
	l.fenceExpiredLocked(scope, estimate.RootRunID, l.now().UTC())
	if prior, exists := l.values[key]; exists {
		// A replayed durable operation converges on the reservation it
		// already made; any identity drift is a conflict. The recorded expiry
		// wins.
		if prior.RootRunID != estimate.RootRunID || prior.RunID != estimate.RunID || prior.WorkspaceID != estimate.WorkspaceID || prior.ProjectID != estimate.ProjectID || prior.PolicyVersion != estimate.PolicyVersion || prior.BudgetVersion != estimate.BudgetVersion || prior.Generation != generation || prior.UpperBoundMicros != estimate.MaximumCostMicros {
			return Reservation{}, problem.New(problem.CodeIdempotencyConflict, "")
		}
		if prior.Expired || prior.Released {
			// Answering this replay with the recorded reservation would tell
			// the caller it holds budget it does not: the fence already
			// withdrew its authority to dispatch. The replay is refused so the
			// expiry is handled rather than skipped.
			return Reservation{}, budgetProblem("the reservation lifetime elapsed and must reconcile to authoritative finality")
		}
		return prior, nil
	}
	var held int64
	for _, value := range l.values {
		if value.WorkspaceID != scope.WorkspaceID || value.ProjectID != scope.ProjectID || value.RootRunID != estimate.RootRunID || value.Released {
			continue
		}
		total, ok := addMicros(held, value.UpperBoundMicros)
		if !ok {
			return Reservation{}, budgetProblem("held reservation total is invalid")
		}
		held = total
	}
	if held > maximumReservedMicros-estimate.MaximumCostMicros {
		return Reservation{}, budgetProblem("budget headroom requires review")
	}
	value := Reservation{ID: estimate.ReservationID, RootRunID: estimate.RootRunID, RunID: estimate.RunID, WorkspaceID: estimate.WorkspaceID, ProjectID: estimate.ProjectID, PolicyVersion: estimate.PolicyVersion, BudgetVersion: estimate.BudgetVersion, UpperBoundMicros: estimate.MaximumCostMicros, Generation: generation, ExpiresAt: estimate.ExpiresAt}
	l.values[key] = value
	return value, nil
}

// fenceExpiredLocked fences every elapsed unreleased hold of one root
// aggregate and records the immutable expiry observation. It changes exactly
// one thing: the hold may no longer authorize a dispatch. It deliberately does
// not set the observed cost, does not mark the attempt final, and does not
// release — a clock cannot witness what a physical attempt spent, and treating
// its silence as a final cost of zero both understates real exposure and
// destroys the headroom the still-running attempt is entitled to. The caller
// holds the lock.
func (l *MemoryLedger) fenceExpiredLocked(scope Scope, rootRunID string, now time.Time) []Reservation {
	if now.IsZero() {
		return nil
	}
	var fenced []Reservation
	for key, value := range l.values {
		if value.WorkspaceID != scope.WorkspaceID || value.ProjectID != scope.ProjectID || value.RootRunID != rootRunID || value.Released || value.Expired || now.Before(value.ExpiresAt) {
			continue
		}
		value.Expired = true
		l.values[key] = value
		identity := ExpiryObservationID(value.ID)
		if _, recorded := l.observations[observationKey(scope, identity)]; !recorded {
			l.observations[observationKey(scope, identity)] = Observation{ID: identity, Scope: scope, ReservationID: value.ID, RootRunID: value.RootRunID, RunID: value.RunID, TaskID: expiryTaskID, AttemptID: AttemptID(identity), ExecutionGeneration: uint64(value.Generation)}
		}
		fenced = append(fenced, value)
	}
	sort.Slice(fenced, func(i, j int) bool { return fenced[i].ID < fenced[j].ID })
	return fenced
}

// expiryTaskID names the fence an elapsed reservation records.
const expiryTaskID = "budget-expiry"

func (l *MemoryLedger) FenceExpired(_ context.Context, scope Scope, rootRunID string, now time.Time) ([]Reservation, error) {
	if !scope.Valid() || rootRunID == "" || now.IsZero() {
		return nil, budgetProblem("expiry fencing requires a scoped root run and authoritative time")
	}
	l.lock.Lock()
	defer l.lock.Unlock()
	return l.fenceExpiredLocked(scope, rootRunID, now), nil
}

func (l *MemoryLedger) Observe(_ context.Context, value Observation) error {
	if !value.Scope.Valid() {
		return budgetProblem("observation scope is required")
	}
	l.lock.Lock()
	defer l.lock.Unlock()
	previous, exists := l.observations[observationKey(value.Scope, value.ID)]
	if exists {
		if previous != value {
			return problem.New(problem.CodeIdempotencyConflict, "")
		}
		return nil
	}
	key := scopedKey(value.Scope, value.ReservationID)
	reservation, ok := l.values[key]
	if !ok || reservation.RootRunID != value.RootRunID {
		return budgetProblem("observation reservation mismatch")
	}
	// A fenced reservation still accepts usage: the physical attempt whose
	// lifetime elapsed can still be running, and its cost is exactly the fact
	// the fence is waiting for. Only a released reservation — one already
	// settled against an authoritative final cost — is closed to new usage.
	if reservation.Released || value.CostMicros > reservation.UpperBoundMicros-reservation.ObservedMicros {
		return budgetProblem("observed usage exceeds reservation")
	}
	reservation.ObservedMicros += value.CostMicros
	reservation.AttemptFinal = reservation.AttemptFinal || value.Final
	l.values[key] = reservation
	l.observations[observationKey(value.Scope, value.ID)] = value
	return nil
}
func (l *MemoryLedger) Settle(_ context.Context, value Settlement) (Reservation, error) {
	if !value.Scope.Valid() {
		return Reservation{}, budgetProblem("settlement scope is required")
	}
	l.lock.Lock()
	defer l.lock.Unlock()
	key := scopedKey(value.Scope, value.ReservationID)
	reservation, ok := l.values[key]
	if !ok {
		return Reservation{}, problem.New(problem.CodeResourceNotFound, "")
	}
	if reservation.Generation != value.Generation || !reservation.AttemptFinal {
		return Reservation{}, budgetProblem("settlement fence failed")
	}
	if reservation.Released && (reservation.ObservedMicros != value.FinalCost || reservation.UpperBoundMicros != value.FinalCost || !value.Release) {
		return Reservation{}, budgetProblem("released budget reservation is immutable")
	}
	reservation.ObservedMicros = value.FinalCost
	reservation.UpperBoundMicros = value.FinalCost
	reservation.Released = value.Release
	l.values[key] = reservation
	return reservation, nil
}
func (l *MemoryLedger) Reservation(_ context.Context, scope Scope, id ReservationID) (Reservation, error) {
	if !scope.Valid() {
		return Reservation{}, budgetProblem("reservation read requires workspace and project identity")
	}
	l.lock.Lock()
	defer l.lock.Unlock()
	value, ok := l.values[scopedKey(scope, id)]
	if !ok {
		return Reservation{}, problem.New(problem.CodeResourceNotFound, "")
	}
	return value, nil
}
func (l *MemoryLedger) RootReservations(_ context.Context, scope Scope, root string) ([]Reservation, error) {
	if !scope.Valid() {
		return nil, budgetProblem("root aggregation requires workspace and project identity")
	}
	l.lock.Lock()
	defer l.lock.Unlock()
	var values []Reservation
	for _, value := range l.values {
		if value.WorkspaceID == scope.WorkspaceID && value.ProjectID == scope.ProjectID && value.RootRunID == root {
			values = append(values, value)
		}
	}
	sort.Slice(values, func(i, j int) bool { return values[i].ID < values[j].ID })
	return values, nil
}

var _ Ledger = (*MemoryLedger)(nil)
