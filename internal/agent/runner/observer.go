package runner

import (
	"context"
	"time"
)

// DispatchObserver receives the bounded facts of the dispatch path: what a
// dispatch did, what a result did once it reached the fence, and what an
// attempt cost.
//
// Every value it is handed is from a closed vocabulary — a runtime unit
// identity from the approved release catalog, an outcome or disposition from
// this package's own sets, a status and reason code from the governed result
// registry — and never a task, run, attempt, fence, token, or signature value.
// That is what lets an implementation put any of them on a metric label: the
// port is where the bound is decided, so no metric has to decide it again.
type DispatchObserver interface {
	// ObserveDispatchStarted reports that one physical attempt left this
	// process for its runtime unit.
	ObserveDispatchStarted(ctx context.Context, runtimeUnitID string)
	// ObserveDispatch reports how the wait for that attempt ended and how
	// long it lasted.
	ObserveDispatch(ctx context.Context, runtimeUnitID string, outcome DispatchOutcome, wait time.Duration)
	// ObserveReplacement reports that a new physical attempt superseded the
	// previous one, with the stable reason recorded against the replaced
	// attempt.
	ObserveReplacement(ctx context.Context, runtimeUnitID, reason string)
	// ObserveRejection reports a result refused before or at the fence, by
	// the stage that refused it and the stable reason.
	ObserveRejection(ctx context.Context, stage RejectionStage, reason string)
	// ObserveResult reports what a result did once it reached the fence —
	// committed, or the disposition it became evidence under — and the
	// latency from dispatch to observation.
	ObserveResult(ctx context.Context, runtimeUnitID, outcome string, latency time.Duration)
	// ObserveAttemptUsage reports the per-attempt usage a committed result
	// carried, under the governed status and reason it settled with.
	ObserveAttemptUsage(ctx context.Context, runtimeUnitID, status, reasonCode string, usage AttemptUsage)
}

// DispatchOutcome is how one wait for a dispatched attempt ended.
type DispatchOutcome string

const (
	// DispatchAnswered is a dispatch that produced a result to verify.
	DispatchAnswered DispatchOutcome = "answered"
	// DispatchUnanswered is a dispatch that produced no result and may be
	// replaced.
	DispatchUnanswered DispatchOutcome = "unanswered"
	// DispatchAbandoned is a dispatch the turn stopped waiting on because the
	// turn itself ended.
	DispatchAbandoned DispatchOutcome = "abandoned"
)

// RejectionStage is where a result was refused.
type RejectionStage string

const (
	// RejectionContract is a result that is not a canonical, accountable
	// statement at all.
	RejectionContract RejectionStage = "contract"
	// RejectionStatementDigest is a result whose declared digest does not
	// describe it.
	RejectionStatementDigest RejectionStage = "statement-digest"
	// RejectionSignature is a result no approved key signed for the pinned
	// release.
	RejectionSignature RejectionStage = "signature"
	// RejectionBinding is a result addressed to other work than the attempt
	// this process dispatched.
	RejectionBinding RejectionStage = "binding"
	// RejectionFence is a result the fenced commit refused: stale, superseded,
	// expired, canceled, terminal, or unbound.
	RejectionFence RejectionStage = "fence"
)

// ResultCommitted is the result outcome of a fenced commit that changed
// state; every other outcome is the disposition the result became evidence
// under.
const ResultCommitted = "committed"

// AttemptUsage is what one attempt reported spending, as the signed result
// carried it.
type AttemptUsage struct {
	ModelCalls, ToolCalls            int64
	InputTokens, OutputTokens        int64
	DurationMilliseconds, CostMicros int64
}

// noopObserver is the observer a composition without telemetry runs under.
type noopObserver struct{}

func (noopObserver) ObserveDispatchStarted(context.Context, string)                          {}
func (noopObserver) ObserveDispatch(context.Context, string, DispatchOutcome, time.Duration) {}
func (noopObserver) ObserveReplacement(context.Context, string, string)                      {}
func (noopObserver) ObserveRejection(context.Context, RejectionStage, string)                {}
func (noopObserver) ObserveResult(context.Context, string, string, time.Duration)            {}
func (noopObserver) ObserveAttemptUsage(context.Context, string, string, string, AttemptUsage) {
}
