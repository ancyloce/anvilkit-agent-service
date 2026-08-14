// Package budget enforces reservation-before-dispatch and all-attempt accounting.
// Pagix remains financially authoritative behind Ledger.
package budget

import (
	"context"
	"fmt"
	"sort"
	"sync"
	"time"

	"github.com/ancyloce/anvilkit-agent-service/internal/problem"
)

type ReservationID string
type AttemptID string
type Generation uint64

type Estimate struct {
	RootRunID, RunID, WorkspaceID, PolicyVersion, BudgetVersion string
	MaximumCostMicros                                           int64
	ExpiresAt                                                   time.Time
}
type Reservation struct {
	ID                                                          ReservationID
	RootRunID, RunID, WorkspaceID, PolicyVersion, BudgetVersion string
	UpperBoundMicros, ObservedMicros                            int64
	Generation                                                  Generation
	AttemptFinal                                                bool
	Released                                                    bool
	ExpiresAt                                                   time.Time
}
type Observation struct {
	ID                                                string
	ReservationID                                     ReservationID
	RootRunID, RunID, TaskID                          string
	AttemptID                                         AttemptID
	RecoveryEpoch, ExecutionGeneration, MeterSequence uint64
	CostMicros                                        int64
	Final                                             bool
}
type Settlement struct {
	ReservationID ReservationID
	Generation    Generation
	FinalCost     int64
	Release       bool
	Actor         string
}
type Ledger interface {
	Reserve(context.Context, Estimate, Generation) (Reservation, error)
	Observe(context.Context, Observation) error
	Settle(context.Context, Settlement) (Reservation, error)
	Reservation(context.Context, ReservationID) (Reservation, error)
	RootReservations(context.Context, string) ([]Reservation, error)
}
type IDs interface{ ReservationID() ReservationID }
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
	ids         IDs
	exposure    ExposureSink
	clock       Clock
	policy      HeadroomPolicy
	lock        sync.Mutex
	generations map[string]Generation
}

func New(ledger Ledger, ids IDs, exposure ExposureSink, clock Clock, policy HeadroomPolicy) (*Controller, error) {
	if ledger == nil || ids == nil || exposure == nil || clock == nil || policy.Validate() != nil {
		return nil, fmt.Errorf("budget controller dependencies are invalid")
	}
	return &Controller{ledger: ledger, ids: ids, exposure: exposure, clock: clock, policy: policy, generations: map[string]Generation{}}, nil
}

func (c *Controller) Activate(rootRunID string) (Generation, error) {
	if rootRunID == "" {
		return 0, fmt.Errorf("root run ID is required")
	}
	c.lock.Lock()
	defer c.lock.Unlock()
	c.generations[rootRunID]++
	return c.generations[rootRunID], nil
}
func (c *Controller) Current(rootRunID string) Generation {
	c.lock.Lock()
	defer c.lock.Unlock()
	return c.generations[rootRunID]
}

// ReserveInitial and ReserveReplacement both reserve before dispatch. Replacement
// deliberately does not settle any prior reservation.
func (c *Controller) ReserveInitial(ctx context.Context, estimate Estimate, generation Generation) (Reservation, error) {
	return c.reserve(ctx, estimate, generation)
}
func (c *Controller) ReserveReplacement(ctx context.Context, estimate Estimate, generation Generation, prior ReservationID) (Reservation, error) {
	previous, err := c.ledger.Reservation(ctx, prior)
	if err != nil || previous.Released || previous.RootRunID != estimate.RootRunID || previous.WorkspaceID != estimate.WorkspaceID {
		return Reservation{}, budgetProblem("prior reservation must remain open for replacement or fallback")
	}
	return c.reserve(ctx, estimate, generation)
}
func (c *Controller) reserve(ctx context.Context, estimate Estimate, generation Generation) (Reservation, error) {
	now := c.clock.Now()
	if estimate.RootRunID == "" || estimate.RunID == "" || estimate.WorkspaceID == "" || estimate.PolicyVersion == "" || estimate.BudgetVersion == "" || estimate.MaximumCostMicros < 1 || now.IsZero() || !now.Before(estimate.ExpiresAt) || generation == 0 || generation != c.Current(estimate.RootRunID) {
		return Reservation{}, budgetProblem("reservation estimate or controller generation is invalid")
	}
	reservations, err := c.ledger.RootReservations(ctx, estimate.RootRunID)
	if err != nil {
		return Reservation{}, fmt.Errorf("load root reservations: %w", err)
	}
	var held int64
	for _, reservation := range reservations {
		if !reservation.Released {
			var ok bool
			held, ok = addMicros(held, reservation.UpperBoundMicros)
			if !ok {
				return Reservation{}, budgetProblem("held reservation total is invalid")
			}
		}
	}
	if held > c.policy.MaximumReservedMicros-estimate.MaximumCostMicros {
		return Reservation{}, budgetProblem("budget headroom requires review")
	}
	reserved, err := c.ledger.Reserve(ctx, estimate, generation)
	if err != nil {
		return Reservation{}, budgetProblem("authoritative reservation failed")
	}
	if reserved.ID == "" {
		return Reservation{}, fmt.Errorf("ledger returned empty reservation identity")
	}
	if reserved.RootRunID != estimate.RootRunID || reserved.RunID != estimate.RunID || reserved.WorkspaceID != estimate.WorkspaceID || reserved.PolicyVersion != estimate.PolicyVersion || reserved.BudgetVersion != estimate.BudgetVersion || reserved.Generation != generation || reserved.UpperBoundMicros != estimate.MaximumCostMicros || reserved.ObservedMicros != 0 || reserved.AttemptFinal || !reserved.ExpiresAt.Equal(estimate.ExpiresAt) || reserved.Released {
		return Reservation{}, budgetProblem("authoritative reservation binding is invalid")
	}
	currentHeld, ok := addMicros(held, reserved.UpperBoundMicros)
	if !ok {
		return Reservation{}, budgetProblem("held reservation total overflowed")
	}
	_ = c.exposure.ObserveExposure(ctx, estimate.RootRunID, currentHeld, rootObserved(reservations), c.review(currentHeld))
	return reserved, nil
}

type Dispatch func(context.Context, Reservation) error

func (c *Controller) Dispatch(ctx context.Context, id ReservationID, generation Generation, dispatch Dispatch) error {
	if dispatch == nil {
		return fmt.Errorf("dispatch function is required")
	}
	reservation, err := c.ledger.Reservation(ctx, id)
	now := c.clock.Now()
	if err != nil || reservation.Released || reservation.Generation != generation || generation != c.Current(reservation.RootRunID) || now.IsZero() || !now.Before(reservation.ExpiresAt) {
		return budgetProblem("expensive dispatch lacks a current reservation")
	}
	return dispatch(ctx, reservation)
}
func (c *Controller) Observe(ctx context.Context, observation Observation) error {
	if observation.ID == "" || observation.ReservationID == "" || observation.RootRunID == "" || observation.RunID == "" || observation.TaskID == "" || observation.AttemptID == "" || observation.CostMicros < 0 {
		return budgetProblem("usage observation is invalid")
	}
	return c.ledger.Observe(ctx, observation)
}

// Reconcile holds unknown-final work at the upper bound. Only the active
// controller generation may reduce or release after finality.
func (c *Controller) Reconcile(ctx context.Context, id ReservationID, generation Generation, finalCost *int64, release bool, actor string) (Reservation, error) {
	reservation, err := c.ledger.Reservation(ctx, id)
	if err != nil {
		return Reservation{}, err
	}
	if actor != "budget-controller" || generation == 0 || generation != reservation.Generation || generation != c.Current(reservation.RootRunID) {
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
	settled, err := c.ledger.Settle(ctx, Settlement{ReservationID: id, Generation: generation, FinalCost: cost, Release: release, Actor: actor})
	if err != nil {
		return Reservation{}, err
	}
	reservations, _ := c.ledger.RootReservations(ctx, reservation.RootRunID)
	held := rootHeld(reservations)
	_ = c.exposure.ObserveExposure(ctx, reservation.RootRunID, held, rootObserved(reservations), c.review(held))
	return settled, nil
}
func (c *Controller) review(held int64) bool {
	whole := c.policy.MaximumReservedMicros / 10_000
	remainder := c.policy.MaximumReservedMicros % 10_000
	threshold := whole*int64(c.policy.ReviewAtBasisPoints) + (remainder*int64(c.policy.ReviewAtBasisPoints)+9_999)/10_000
	return held >= threshold
}
func (c *Controller) RootTotal(ctx context.Context, rootRunID string) (int64, error) {
	values, err := c.ledger.RootReservations(ctx, rootRunID)
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

// MemoryLedger is deterministic test/local infrastructure implementing additive,
// deduplicated observations and generation-fenced settlement.
type MemoryLedger struct {
	lock         sync.Mutex
	ids          IDs
	values       map[ReservationID]Reservation
	observations map[string]Observation
}

func NewMemoryLedger(ids IDs) *MemoryLedger {
	return &MemoryLedger{ids: ids, values: map[ReservationID]Reservation{}, observations: map[string]Observation{}}
}
func (l *MemoryLedger) Reserve(_ context.Context, estimate Estimate, generation Generation) (Reservation, error) {
	l.lock.Lock()
	defer l.lock.Unlock()
	id := l.ids.ReservationID()
	if id == "" {
		return Reservation{}, fmt.Errorf("empty reservation ID")
	}
	if _, exists := l.values[id]; exists {
		return Reservation{}, problem.New(problem.CodeIdempotencyConflict, "")
	}
	value := Reservation{ID: id, RootRunID: estimate.RootRunID, RunID: estimate.RunID, WorkspaceID: estimate.WorkspaceID, PolicyVersion: estimate.PolicyVersion, BudgetVersion: estimate.BudgetVersion, UpperBoundMicros: estimate.MaximumCostMicros, Generation: generation, ExpiresAt: estimate.ExpiresAt}
	l.values[id] = value
	return value, nil
}
func (l *MemoryLedger) Observe(_ context.Context, value Observation) error {
	l.lock.Lock()
	defer l.lock.Unlock()
	previous, exists := l.observations[value.ID]
	if exists {
		if previous != value {
			return problem.New(problem.CodeIdempotencyConflict, "")
		}
		return nil
	}
	reservation, ok := l.values[value.ReservationID]
	if !ok || reservation.RootRunID != value.RootRunID {
		return budgetProblem("observation reservation mismatch")
	}
	if reservation.Released || value.CostMicros > reservation.UpperBoundMicros-reservation.ObservedMicros {
		return budgetProblem("observed usage exceeds reservation")
	}
	reservation.ObservedMicros += value.CostMicros
	reservation.AttemptFinal = reservation.AttemptFinal || value.Final
	l.values[value.ReservationID] = reservation
	l.observations[value.ID] = value
	return nil
}
func (l *MemoryLedger) Settle(_ context.Context, value Settlement) (Reservation, error) {
	l.lock.Lock()
	defer l.lock.Unlock()
	reservation, ok := l.values[value.ReservationID]
	if !ok {
		return Reservation{}, problem.New(problem.CodeResourceNotFound, "")
	}
	if reservation.Generation != value.Generation || !reservation.AttemptFinal {
		return Reservation{}, budgetProblem("settlement fence failed")
	}
	reservation.ObservedMicros = value.FinalCost
	reservation.UpperBoundMicros = value.FinalCost
	reservation.Released = value.Release
	l.values[value.ReservationID] = reservation
	return reservation, nil
}
func (l *MemoryLedger) Reservation(_ context.Context, id ReservationID) (Reservation, error) {
	l.lock.Lock()
	defer l.lock.Unlock()
	value, ok := l.values[id]
	if !ok {
		return Reservation{}, problem.New(problem.CodeResourceNotFound, "")
	}
	return value, nil
}
func (l *MemoryLedger) RootReservations(_ context.Context, root string) ([]Reservation, error) {
	l.lock.Lock()
	defer l.lock.Unlock()
	var values []Reservation
	for _, value := range l.values {
		if value.RootRunID == root {
			values = append(values, value)
		}
	}
	sort.Slice(values, func(i, j int) bool { return values[i].ID < values[j].ID })
	return values, nil
}
