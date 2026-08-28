package runner

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/ancyloce/anvilkit-agent-service/contracts/generated/schema"
	"github.com/ancyloce/anvilkit-agent-service/internal/agent"
	"github.com/ancyloce/anvilkit-agent-service/internal/dispatch"
	"github.com/ancyloce/anvilkit-agent-service/internal/problem"
	"github.com/ancyloce/anvilkit-agent-service/internal/runtimes"
)

// unanswered is a dispatch that produced no result. It is its own type because
// it is the one failure a replacement can repair: the release may still be
// executing the attempt, or may never have received it, and this process
// cannot tell which. Every other failure is a decision the durable record
// already made, and repeating it would change nothing.
type unanswered struct{ err error }

func (u unanswered) Error() string { return u.err.Error() }
func (u unanswered) Unwrap() error { return u.err }

// awaitResult is the third stage of a turn: one dispatched execution of one
// physical attempt, bounded by the attempt's own deadline.
//
// The dispatch is recorded before it is made. An execution that left this
// process and was not recorded as having left is indistinguishable from one
// that never went, and those two states need opposite recoveries.
func (r *Runner) awaitResult(ctx context.Context, request TurnRequest, task schema.AgentTask, execution dispatch.Execution, credential runtimes.Credential) (runtimes.DispatchReceipt, error) {
	if err := r.tasks.Dispatched(ctx, execution); err != nil {
		return runtimes.DispatchReceipt{}, fmt.Errorf("record the dispatch of the physical attempt: %w", err)
	}
	// The attempt carries its own deadline. A runtime that never answers must
	// release this turn rather than hold the durable step open for as long as
	// a transport is willing to wait.
	dispatched, cancel := context.WithTimeout(ctx, r.limits.Timeout)
	defer cancel()
	unit := request.Runtime.RuntimeUnitID
	started := r.clock.Now()
	r.observer.ObserveDispatchStarted(ctx, unit)
	receipt, err := r.dispatcher.Dispatch(dispatched, request.Runtime, task, credential)
	wait := r.clock.Now().Sub(started)
	if err != nil {
		if ctx.Err() != nil {
			// The turn itself was cancelled or its own deadline passed. That
			// is not an unanswered dispatch to replace: nothing is waiting for
			// the answer any more.
			r.observer.ObserveDispatch(ctx, unit, DispatchAbandoned, wait)
			return runtimes.DispatchReceipt{}, fmt.Errorf("dispatch the physical attempt: %w", err)
		}
		r.observer.ObserveDispatch(ctx, unit, DispatchUnanswered, wait)
		return runtimes.DispatchReceipt{}, unanswered{err: fmt.Errorf("dispatch the physical attempt to %s: %w", unit, err)}
	}
	r.observer.ObserveDispatch(ctx, unit, DispatchAnswered, wait)
	return receipt, nil
}

// replay returns the outcome a logical task already committed. It is the
// idempotent half of the result wait: the same durable operation delivered
// twice must produce the same decision without executing anything.
func (r *Runner) replay(ctx context.Context, request TurnRequest) (TurnOutcome, bool, error) {
	registration, settled, err := r.tasks.Settled(ctx,
		dispatch.Scope{WorkspaceID: request.Run.WorkspaceID, ProjectID: request.Run.ProjectID},
		dispatch.TaskID(request.OperationKey))
	if err != nil {
		return TurnOutcome{}, false, fmt.Errorf("read the committed outcome of the turn: %w", err)
	}
	if !settled {
		return TurnOutcome{}, false, nil
	}
	var result schema.AgentRuntimeResult
	if err := json.Unmarshal(registration.Statement, &result); err != nil {
		return TurnOutcome{}, true, contractRefusal("the committed result statement is not decodable")
	}
	usage, err := usageOf(result)
	if err != nil {
		return TurnOutcome{}, true, contractRefusal("the committed result did not report accountable usage")
	}
	outcome, err := r.nextStep(ctx, request, result, usage)
	return outcome, true, err
}

// commitNextStep is the fourth stage of a turn: the fenced conditional commit
// of what came back, and the decision the workflow acts on next.
//
// Nothing here trusts the result's own account of which attempt it belongs to.
// The predicate is built from the execution this process opened and compared
// against the authoritative record inside the commit transaction; the result's
// identity fields are compared first, so a result addressed to another attempt
// is refused before the database is asked about it.
func (r *Runner) commitNextStep(ctx context.Context, request TurnRequest, execution dispatch.Execution, receipt runtimes.DispatchReceipt) (TurnOutcome, error) {
	result := receipt.Result
	// The receipt carries the decoded result rather than the bytes it arrived
	// in, so the statement a replay of this durable step reads back is this
	// encoding of it. That is safe because the digest below is the canonical
	// (JCS) digest of the same value: the replay decodes these bytes into the
	// same result and reaches the same digest, whatever member order this
	// encoder chose.
	unit := request.Runtime.RuntimeUnitID
	statement, err := json.Marshal(result)
	if err != nil {
		r.observer.ObserveRejection(ctx, RejectionContract, dispatch.ReasonResultContractInvalid)
		return TurnOutcome{}, r.abandon(ctx, execution, dispatch.ReasonResultContractInvalid,
			contractRefusal("the release did not answer with a canonical result statement"))
	}
	statementDigest, err := runtimes.StatementDigest(result)
	if err != nil {
		r.observer.ObserveRejection(ctx, RejectionContract, dispatch.ReasonResultContractInvalid)
		return TurnOutcome{}, r.abandon(ctx, execution, dispatch.ReasonResultContractInvalid,
			contractRefusal("the release did not answer with a canonical result statement"))
	}
	// A result that misreports its own statement digest cannot be correlated:
	// the digest is what makes redelivery idempotent, and one that does not
	// describe the bytes it arrived in would make two different results
	// interchangeable.
	if string(result.Signature.StatementDigest) != statementDigest {
		r.observer.ObserveRejection(ctx, RejectionStatementDigest, reasonStatementDigestMismatch)
		return TurnOutcome{}, r.abandon(ctx, execution, dispatch.ReasonResultUnattributable,
			r.unattributable(ctx, request, execution, result, statementDigest,
				reasonStatementDigestMismatch, "the result's statement digest does not describe the result"))
	}
	// Trust before binding, and binding before the fence. An unattributable
	// result is refused here rather than compared against an execution: there
	// is no point asking which attempt a document belongs to before knowing
	// whether the thing that produced it was a release at all.
	if err := r.signatures.Verify(result, request.Runtime, r.clock.Now()); err != nil {
		r.observer.ObserveRejection(ctx, RejectionSignature, reasonSignatureUnverified)
		return TurnOutcome{}, r.abandon(ctx, execution, dispatch.ReasonResultUnattributable,
			r.unattributable(ctx, request, execution, result, statementDigest,
				reasonSignatureUnverified, ""))
	}
	if mismatch := resultIdentity(result, execution); mismatch != "" {
		r.observer.ObserveRejection(ctx, RejectionBinding, reasonResultNotForAttempt)
		return TurnOutcome{}, r.abandon(ctx, execution, dispatch.ReasonResultUnattributable,
			r.unattributable(ctx, request, execution, result, statementDigest,
				reasonResultNotForAttempt, mismatch))
	}
	usage, err := usageOf(result)
	if err != nil {
		r.observer.ObserveRejection(ctx, RejectionContract, dispatch.ReasonResultContractInvalid)
		return TurnOutcome{}, r.abandon(ctx, execution, dispatch.ReasonResultContractInvalid,
			contractRefusal("the result did not report accountable usage"))
	}
	status := string(result.Status.Status)
	settled, err := r.tasks.Settle(ctx, dispatch.Settle{
		Scope:     dispatch.Scope{WorkspaceID: request.Run.WorkspaceID, ProjectID: request.Run.ProjectID},
		RunID:     request.Run.RunID,
		Predicate: predicateOf(execution),
		Outcome: dispatch.Outcome{
			Status:                status,
			ReasonCode:            string(result.Status.ReasonCode),
			ResultStatementDigest: statementDigest,
			SignatureKeyID:        string(result.Signature.KeyId),
			Statement:             statement,
			Failed:                status != completedStatus && status != refusedStatus,
			ObservedAt:            observedAt(receipt, r.clock.Now()),
		},
	})
	if err != nil {
		return TurnOutcome{}, err
	}
	// The result latency is this service's own measure: from the moment the
	// dispatch left to the moment the answer was observed, on one clock.
	latency := observedAt(receipt, r.clock.Now()).Sub(receipt.DispatchedAt)
	if receipt.DispatchedAt.IsZero() || latency < 0 {
		latency = 0
	}
	// A result that did not commit changed nothing, and its usage is not this
	// turn's to account: the coordinator recorded it as evidence, and charging
	// this turn for work a replacement already redid would bill it twice.
	if !settled.Disposition.Committed() && settled.Disposition != dispatch.DispositionDuplicate {
		r.observer.ObserveResult(ctx, unit, string(settled.Disposition), latency)
		r.observer.ObserveRejection(ctx, RejectionFence, string(settled.Disposition))
		// The code names the failure, not the component that holds the fence.
		// A second code for the same meaning would split one condition across
		// two vocabularies.
		details := problem.New(problem.CodeWorkerFenceStale, "")
		details.Detail = settled.Reason
		return TurnOutcome{}, details
	}
	outcome := ResultCommitted
	if settled.Disposition == dispatch.DispositionDuplicate {
		outcome = string(dispatch.DispositionDuplicate)
	}
	r.observer.ObserveResult(ctx, unit, outcome, latency)
	if outcome == ResultCommitted {
		// Per-attempt usage is reported once, for the attempt that settled;
		// a duplicate is the same attempt's usage arriving again.
		r.observer.ObserveAttemptUsage(ctx, unit, status, string(result.Status.ReasonCode), AttemptUsage{
			ModelCalls:           usage.ModelCalls,
			ToolCalls:            int64(result.Usage.ToolCalls),
			InputTokens:          usage.InputTokens,
			OutputTokens:         usage.OutputTokens,
			DurationMilliseconds: int64(result.Usage.DurationMilliseconds),
			CostMicros:           usage.CostMicros,
		})
	}
	return r.nextStep(ctx, request, result, usage)
}

const (
	completedStatus = "completed"
	refusedStatus   = "refused"
	cancelledStatus = "cancelled"
)

// budgetExhaustedReason is the governed runtime reason for an attempt that
// stopped because continuing would exceed the run's remaining budget. It is a
// halt rather than a failure: the run has an answer about why it stopped.
const budgetExhaustedReason = "RUNTIME_BUDGET_EXHAUSTED"

// nextStep turns a committed result into the decision the workflow acts on.
// Every constraint the definition pins is enforced here rather than trusted
// from the runtime: a runtime proposes, and the control plane decides what the
// proposal is allowed to be.
func (r *Runner) nextStep(ctx context.Context, request TurnRequest, result schema.AgentRuntimeResult, usage agent.Usage) (TurnOutcome, error) {
	switch string(result.Status.Status) {
	case cancelledStatus:
		details := problem.New(problem.CodeTaskDispatchDenied, "")
		details.Detail = "the runtime reported the attempt cancelled"
		return TurnOutcome{Usage: usage, Halted: &Halted{Problem: details}}, nil
	case refusedStatus:
		reason := result.TurnDecision.Payload["reason"]
		if reason == "" {
			reason = string(result.Status.ReasonCode)
		}
		return TurnOutcome{
			Decision: agent.TurnDecision{Kind: agent.DecisionRefuse, Refuse: &agent.RefuseDecision{Reason: truncate(reason, maximumParameterBytes)}},
			Usage:    usage,
			Notes:    []string{"runtime refused: " + string(result.Status.ReasonCode)},
		}, nil
	case completedStatus:
	default:
		if string(result.Status.ReasonCode) == budgetExhaustedReason {
			details := problem.New(problem.CodeBudgetDenied, "")
			details.Detail = "the runtime stopped because the pinned budget is exhausted"
			return TurnOutcome{Usage: usage, Halted: &Halted{Problem: details, Refuse: request.Budget.ExceedBehavior == "refuse"}}, nil
		}
		// A failed attempt is a failed turn, and its usage travels with the
		// error: an attempt whose cost is dropped because it did not reach a
		// decision is an attempt the run gets to make again for nothing.
		return TurnOutcome{Usage: usage}, fmt.Errorf("the runtime failed the attempt: %s", result.Status.ReasonCode)
	}
	decision, reason := r.resolveDecision(ctx, request, result.TurnDecision)
	if reason != "" {
		return TurnOutcome{
			Decision: agent.TurnDecision{Kind: agent.DecisionRefuse, Refuse: &agent.RefuseDecision{Reason: reason}},
			Usage:    usage,
			Notes:    []string{"decision rejected: " + reason},
		}, nil
	}
	if err := decision.Validate(); err != nil {
		return TurnOutcome{
			Decision: agent.TurnDecision{Kind: agent.DecisionRefuse, Refuse: &agent.RefuseDecision{Reason: "turn decision violates the bounded contract"}},
			Usage:    usage,
			Notes:    []string{"decision rejected: bounded contract violation"},
		}, nil
	}
	outcome := TurnOutcome{Decision: decision, Usage: usage}
	if decision.Kind == agent.DecisionFinal && len(result.TurnDecision.ArtifactOutputs) == 1 {
		outcome.CandidateReference = result.TurnDecision.ArtifactOutputs[0]
	}
	return outcome, nil
}

// resolveDecision maps the canonical decision vocabulary onto the explicit
// TurnDecision the workflow understands, enforcing every definition constraint
// the decision depends on. A non-empty reason means the proposal is refused.
func (r *Runner) resolveDecision(ctx context.Context, request TurnRequest, proposed schema.AgentRuntimeResultTurnDecision) (agent.TurnDecision, string) {
	payload := proposed.Payload
	switch proposed.Decision {
	case schema.AgentRuntimeResultTurnDecisionDecisionContinue:
		return agent.TurnDecision{Kind: agent.DecisionContinue, Continue: &agent.ContinueDecision{Note: payload["note"]}}, ""
	case schema.AgentRuntimeResultTurnDecisionDecisionNeedInput:
		question := payload["question"]
		if question == "" {
			return agent.TurnDecision{}, "input request requires a bounded question"
		}
		if !hasStopCondition(request.Definition, "input-required") {
			return agent.TurnDecision{}, "definition does not allow input requests"
		}
		return agent.TurnDecision{Kind: agent.DecisionNeedInput, NeedInput: &agent.NeedInputDecision{Question: question}}, ""
	case schema.AgentRuntimeResultTurnDecisionDecisionDelegateAgent:
		delegate := payload["delegate"]
		// The delegation input is carried in the bounded decision payload, so a
		// specialist brief longer than one value arrives as an indexed
		// continuation (`input`, or `input.0`, `input.1`, …) exactly the way
		// the supplied context and model output do. Reassembling it here is
		// what lets a Manager delegate a page brief the single-value bound
		// cannot hold.
		input := joinedPayload(payload, "input")
		if delegate == "" || input == "" {
			return agent.TurnDecision{}, "delegation requires a delegate identity and input"
		}
		if !json.Valid([]byte(input)) {
			return agent.TurnDecision{}, "delegation input is not a document"
		}
		if !request.Definition.AllowsDelegate(delegate) {
			return agent.TurnDecision{}, "delegate is not in the pinned allowed-delegate set"
		}
		return agent.TurnDecision{Kind: agent.DecisionDelegate, Delegate: &agent.DelegateDecision{DelegateID: delegate, Input: json.RawMessage(input)}}, ""
	case schema.AgentRuntimeResultTurnDecisionDecisionFinal:
		candidate, reason := r.candidate(ctx, proposed)
		if reason != "" {
			return agent.TurnDecision{}, reason
		}
		return agent.TurnDecision{Kind: agent.DecisionFinal, Final: &agent.FinalDecision{Candidate: candidate, Summary: payload["summary"]}}, ""
	case schema.AgentRuntimeResultTurnDecisionDecisionRefuse:
		reason := payload["reason"]
		if reason == "" {
			return agent.TurnDecision{}, "refusal requires a bounded reason"
		}
		return agent.TurnDecision{Kind: agent.DecisionRefuse, Refuse: &agent.RefuseDecision{Reason: reason}}, ""
	case schema.AgentRuntimeResultTurnDecisionDecisionToolCall:
		tool, arguments := payload["tool"], payload["arguments"]
		if tool == "" || arguments == "" {
			return agent.TurnDecision{}, "tool call requires a tool identity and arguments"
		}
		if !json.Valid([]byte(arguments)) {
			return agent.TurnDecision{}, "tool arguments are not a document"
		}
		if !request.Definition.AllowsTool(tool) {
			return agent.TurnDecision{}, "runtime proposed a tool outside the pinned profile"
		}
		return agent.TurnDecision{Kind: agent.DecisionToolCall, ToolCall: &agent.ToolCallDecision{ToolID: tool, Arguments: json.RawMessage(arguments)}}, ""
	default:
		return agent.TurnDecision{}, "runtime proposed a decision outside the governed vocabulary"
	}
}

// candidate resolves the document a final decision names.
//
// A candidate is an artifact reference rather than a payload value because the
// bounded decision payload cannot carry a document, and because a runtime that
// produced a candidate wrote it somewhere before saying so. The content is
// verified against the digest the reference pins: an artifact store that
// returned different bytes than the reference names is not one this service
// will finalize from.
func (r *Runner) candidate(ctx context.Context, proposed schema.AgentRuntimeResultTurnDecision) (json.RawMessage, string) {
	if len(proposed.ArtifactOutputs) != 1 {
		return nil, "a final decision must name exactly one candidate artifact"
	}
	reference := proposed.ArtifactOutputs[0]
	if r.candidates == nil {
		// A deployment reaches this when a runtime returns a candidate through
		// an artifact path this service cannot read back. Refusing is the only
		// honest answer: the alternative is finalizing a document it never saw.
		return nil, "the candidate artifact cannot be read by this deployment"
	}
	content, err := r.candidates.Content(ctx, reference)
	if err != nil {
		return nil, "the candidate artifact could not be read"
	}
	if contentDigest(content) != string(reference.Digest) {
		return nil, "the candidate artifact does not match the digest the result pinned"
	}
	if !json.Valid(content) {
		return nil, "the candidate artifact is not a document"
	}
	return json.RawMessage(content), ""
}

// resultIdentity compares what the result says about itself with the execution
// this process opened. It is the cheap half of the fence: a mismatch here is a
// result for other work, and the database never needs to be asked.
func resultIdentity(result schema.AgentRuntimeResult, execution dispatch.Execution) string {
	for _, comparison := range []struct {
		field            string
		wanted, observed string
		// secret marks a value whose comparison must not leak how much of it
		// matched: the fence is a capability, and a comparison that stops at
		// the first differing byte tells a caller that can time it how many
		// bytes it guessed right.
		secret bool
	}{
		{"task", execution.Task.TaskID, string(result.TaskId), false},
		{"run", execution.Task.RunID, string(result.RunId), false},
		{"physical attempt", execution.Attempt.PhysicalAttemptID, string(result.PhysicalAttemptId), false},
		{"fence token", execution.FenceToken, result.FenceToken, true},
		{"runtime unit", execution.Task.Runtime.RuntimeUnitID, string(result.Selected.RuntimeUnitId), false},
		{"runtime manifest digest", execution.Task.Runtime.RuntimeManifestDigest, string(result.Selected.RuntimeManifestDigest), false},
		{"runtime image digest", execution.Task.Runtime.RuntimeImageDigest, string(result.Selected.ImageDigest), false},
		{"invocation protocol digest", execution.Task.Runtime.InvocationProtocolDigest, string(result.Selected.InvocationProtocolDigest), false},
	} {
		equal := comparison.wanted == comparison.observed
		if comparison.secret {
			equal = subtle.ConstantTimeCompare([]byte(comparison.wanted), []byte(comparison.observed)) == 1
		}
		if !equal {
			return "the result's " + comparison.field + " does not belong to the dispatched attempt"
		}
	}
	for _, comparison := range []struct {
		field            string
		wanted, observed int
	}{
		{"attempt number", int(execution.Attempt.AttemptNumber), result.AttemptNumber},
		{"lease epoch", int(execution.Attempt.LeaseEpoch), result.LeaseEpoch},
		{"execution generation", int(execution.Task.ExecutionGeneration), result.ExecutionGeneration},
	} {
		if comparison.wanted != comparison.observed {
			return "the result's " + comparison.field + " does not belong to the dispatched attempt"
		}
	}
	return ""
}

func predicateOf(execution dispatch.Execution) dispatch.Predicate {
	return dispatch.Predicate{
		RunID:                    execution.Task.RunID,
		TaskID:                   execution.Task.TaskID,
		ExecutionGeneration:      execution.Task.ExecutionGeneration,
		PhysicalAttemptID:        execution.Attempt.PhysicalAttemptID,
		AttemptNumber:            execution.Attempt.AttemptNumber,
		LeaseEpoch:               execution.Attempt.LeaseEpoch,
		FenceToken:               execution.FenceToken,
		RuntimeUnitID:            execution.Task.Runtime.RuntimeUnitID,
		RuntimeManifestDigest:    execution.Task.Runtime.RuntimeManifestDigest,
		RuntimeImageDigest:       execution.Task.Runtime.RuntimeImageDigest,
		InvocationProtocolDigest: execution.Task.Runtime.InvocationProtocolDigest,
	}
}

// usageOf accounts what the attempt reported. The cost is a governed decimal
// on the wire and micros in this service; a cost that does not parse is a
// result this service cannot bill, which is a refusal rather than a free turn.
func usageOf(result schema.AgentRuntimeResult) (agent.Usage, error) {
	micros, err := agent.CostMicros(string(result.Usage.Cost.Amount))
	if err != nil {
		return agent.Usage{}, err
	}
	return agent.Usage{
		ModelCalls:   int64(result.Usage.ModelCalls),
		InputTokens:  int64(result.Usage.InputTokens),
		OutputTokens: int64(result.Usage.OutputTokens),
		CostMicros:   micros,
	}, nil
}

// observedAt is when this service saw the result. A runtime's own clock never
// decides when an attempt settled: the commit is this service's event.
func observedAt(receipt runtimes.DispatchReceipt, now time.Time) time.Time {
	if !receipt.ObservedAt.IsZero() {
		return receipt.ObservedAt.UTC()
	}
	return now.UTC()
}

func contractRefusal(detail string) error {
	details := problem.New(problem.CodeContractInvalid, "")
	details.Detail = detail
	return details
}

// The stable internal reasons a result is refused before the fence. They are
// recorded as Internal Evidence, never returned to whoever produced the result.
const (
	reasonStatementDigestMismatch = "RESULT_STATEMENT_DIGEST_MISMATCH"
	reasonSignatureUnverified     = "RESULT_SIGNATURE_UNVERIFIED"
	reasonResultNotForAttempt     = "RESULT_NOT_FOR_ATTEMPT"
)

// unattributable refuses a result the fence will never see, and records why.
//
// A result rejected here changed nothing, and the coordinator's own evidence
// path only covers results that reached the commit predicate. Without this,
// the failures most worth investigating — a signature that does not verify, a
// result addressed to other work — would be the only ones that left no trace,
// while an ordinary stale fence left one.
//
// Recording is best-effort in exactly one direction: a failure to record does
// not turn a refusal into a commit. The refusal is what protects state; the
// evidence is what explains it.
func (r *Runner) unattributable(ctx context.Context, request TurnRequest, execution dispatch.Execution,
	result schema.AgentRuntimeResult, statementDigest, reason, detail string) error {
	keyID := string(result.Signature.KeyId)
	if keyID == "" {
		// A result that names no signing key at all is the plainest form of an
		// unsigned result, and the durable record requires a key identity on
		// every evidence row. It is recorded under a governed sentinel rather
		// than not at all: the refusal most worth investigating must not be
		// the one refusal that leaves no trace.
		keyID = unsignedResultKeyID
	}
	if err := r.tasks.Unbound(ctx,
		dispatch.Scope{WorkspaceID: request.Run.WorkspaceID, ProjectID: request.Run.ProjectID},
		execution.Task.RunID, execution.Task.TaskID, execution.Attempt.PhysicalAttemptID,
		statementDigest, keyID, reason); err != nil {
		return fmt.Errorf("record the unattributable result of the physical attempt: %w", err)
	}
	details := problem.New(problem.CodeContractInvalid, "")
	// A signature failure is the one refusal that says nothing about why. The
	// detail would tell whoever produced the result which of the trust, scope,
	// key state, or signature checks it fell at — a description of the control
	// plane's verification, written for the benefit of something that failed
	// it. The evidence just recorded carries what an operator needs.
	if detail == "" {
		detail = "the result could not be attributed to the runtime release this run pinned"
	}
	details.Detail = detail
	return details
}

// unsignedResultKeyID is the key identity evidence records for a result whose
// signature envelope names no key. It is a sentinel in the governed key
// identity shape, never a key anything resolves.
const unsignedResultKeyID = "urn:anvilkit:key:unsigned-result"

// abandon closes the attempt this turn will not wait on any longer and returns
// the error that ended the wait.
//
// The close runs on a context detached from the turn's cancellation, because
// the turn ending is exactly when it runs, and it is bounded by the dispatch
// deadline rather than open-ended. A close that fails does not turn the
// refusal into anything else: the attempt is then ended by its lease instead,
// and the error says both what ended the turn and that the record could not
// be told.
func (r *Runner) abandon(ctx context.Context, execution dispatch.Execution, reason string, cause error) error {
	detached, cancel := context.WithTimeout(context.WithoutCancel(ctx), r.limits.Timeout)
	defer cancel()
	if err := r.tasks.Close(detached, execution, reason); err != nil {
		return errors.Join(cause, fmt.Errorf("close the abandoned physical attempt: %w", err))
	}
	return cause
}

// isUnanswered reports whether a dispatch produced no result and may therefore
// be replaced by a new attempt.
func isUnanswered(err error) bool {
	var target unanswered
	return errors.As(err, &target)
}

// joinedPayload reassembles one bounded-payload value that may have been split
// into an indexed continuation. `key` alone wins; otherwise `key.0`, `key.1`, …
// are concatenated in order and stop at the first gap. It mirrors the runtime
// SDK's own reassembly so a value chunked on one side rejoins on the other.
func joinedPayload(payload map[string]string, key string) string {
	if value, present := payload[key]; present {
		return value
	}
	prefix := key + "."
	indexes := make([]int, 0, len(payload))
	for candidate := range payload {
		if !strings.HasPrefix(candidate, prefix) {
			continue
		}
		index, err := strconv.Atoi(candidate[len(prefix):])
		if err != nil || index < 0 {
			continue
		}
		indexes = append(indexes, index)
	}
	if len(indexes) == 0 {
		return ""
	}
	sort.Ints(indexes)
	var builder strings.Builder
	for position, index := range indexes {
		if index != position {
			break
		}
		builder.WriteString(payload[prefix+strconv.Itoa(index)])
	}
	return builder.String()
}
