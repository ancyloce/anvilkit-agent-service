package dispatch_test

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/ancyloce/anvilkit-agent-service/internal/agent"
	"github.com/ancyloce/anvilkit-agent-service/internal/dispatch"
	"github.com/ancyloce/anvilkit-agent-service/internal/problem"
)

type movableClock struct{ now time.Time }

func (c *movableClock) Now() time.Time { return c.now }

const (
	statementOne = "sha256:" + "11111111111111111111111111111111111111111111111111111111111111ab"
	statementTwo = "sha256:" + "22222222222222222222222222222222222222222222222222222222222222ab"
	keyID        = "urn:anvilkit:key:test-runtime-result"
)

func testScope() dispatch.Scope {
	return dispatch.Scope{WorkspaceID: "workspace", ProjectID: "project"}
}

func testBinding() agent.RuntimeBinding {
	digest := func(fill string) string { return "sha256:" + strings.Repeat(fill, 64) }
	return agent.RuntimeBinding{
		RuntimeUnitID:            "runtime.platform.manager",
		RuntimeManifestDigest:    digest("a"),
		RuntimeImageDigest:       digest("b"),
		InvocationProtocolDigest: digest("c"),
		RuntimeAudience:          "urn:anvilkit:audience:runtime-manager",
	}
}

func testRequest() dispatch.Request {
	return dispatch.Request{
		Scope:               testScope(),
		TaskID:              dispatch.TaskID("run.test:g1:turn-0000"),
		RunID:               "run.test",
		RootRunID:           "run.test",
		ExecutionGeneration: 1,
		DefinitionDigest:    "sha256:" + strings.Repeat("d", 64),
		Runtime:             testBinding(),
		Capability:          "provider.invoke",
		RequestDigest:       "sha256:" + strings.Repeat("e", 64),
	}
}

func newCoordinator(t *testing.T) (*dispatch.Coordinator, *dispatch.MemoryRepository, *movableClock) {
	t.Helper()
	repository := dispatch.NewMemoryRepository()
	clock := &movableClock{now: time.Unix(1000, 0).UTC()}
	coordinator, err := dispatch.New(dispatch.Config{Repository: repository, Tokens: dispatch.RandomTokens{}, Clock: clock, Lease: time.Minute})
	if err != nil {
		t.Fatal(err)
	}
	return coordinator, repository, clock
}

func settle(execution dispatch.Execution, statement string) dispatch.Settle {
	return dispatch.Settle{
		Scope: execution.Task.Scope,
		RunID: execution.Task.RunID,
		Predicate: dispatch.Predicate{
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
		},
		Outcome: dispatch.Outcome{
			Status:                "completed",
			ReasonCode:            "RUNTIME_COMPLETED",
			ResultStatementDigest: statement,
			Statement:             []byte(`{"kind":"AgentRuntimeResult"}`),
			SignatureKeyID:        keyID,
			ObservedAt:            time.Unix(1010, 0).UTC(),
		},
	}
}

// One turn is one logical task however many times it is executed, and each
// execution is a numbered attempt with its own lease and fence.
func TestOneLogicalTaskCarriesManyNumberedAttempts(t *testing.T) {
	coordinator, repository, _ := newCoordinator(t)
	ctx := context.Background()
	first, err := coordinator.Open(ctx, testRequest())
	if err != nil {
		t.Fatal(err)
	}
	replacement := testRequest()
	replacement.Replacing = dispatch.ReasonDispatchFailed
	second, err := coordinator.Open(ctx, replacement)
	if err != nil {
		t.Fatal(err)
	}
	if first.Task.TaskID != second.Task.TaskID {
		t.Fatal("a replacement must be another attempt of the same task")
	}
	if second.Attempt.AttemptNumber != 2 || second.Attempt.LeaseEpoch != 2 {
		t.Fatalf("second attempt = %+v", second.Attempt)
	}
	if second.FenceToken == first.FenceToken {
		t.Fatal("each attempt must carry its own fence")
	}
	if second.Attempt.PhysicalAttemptID == first.Attempt.PhysicalAttemptID {
		t.Fatal("each attempt must have its own identity")
	}
	_, attempts, _, err := repository.Load(ctx, testScope(), first.Task.TaskID)
	if err != nil {
		t.Fatal(err)
	}
	if attempts[0].Status != dispatch.Superseded || attempts[0].FailureReason != dispatch.ReasonDispatchFailed {
		t.Fatalf("the replaced attempt must be superseded with its reason: %+v", attempts[0])
	}
	// The raw fence is never persisted; only a value that proves which token
	// produced it.
	if attempts[0].FenceTokenDigest != dispatch.Digest(first.FenceToken) || strings.Contains(attempts[0].FenceTokenDigest, first.FenceToken) {
		t.Fatal("the record must hold the fence digest and not the fence")
	}
}

// A replacement permanently fences every earlier attempt: what the superseded
// one returns is evidence, and it changes nothing.
func TestAReplacementPermanentlyFencesEarlierAttempts(t *testing.T) {
	coordinator, repository, _ := newCoordinator(t)
	ctx := context.Background()
	first, err := coordinator.Open(ctx, testRequest())
	if err != nil {
		t.Fatal(err)
	}
	replacement := testRequest()
	replacement.Replacing = dispatch.ReasonReplaced
	second, err := coordinator.Open(ctx, replacement)
	if err != nil {
		t.Fatal(err)
	}
	late, err := coordinator.Settle(ctx, settle(first, statementOne))
	if err != nil {
		t.Fatal(err)
	}
	if late.Disposition != dispatch.DispositionSuperseded {
		t.Fatalf("a superseded attempt must not commit: %+v", late)
	}
	current, err := coordinator.Settle(ctx, settle(second, statementTwo))
	if err != nil {
		t.Fatal(err)
	}
	if !current.Disposition.Committed() || current.Task.Status != dispatch.Succeeded {
		t.Fatalf("the current attempt must commit: %+v", current)
	}
	evidence := repository.Evidence()
	if len(evidence) != 1 || evidence[0].Disposition != dispatch.DispositionSuperseded || evidence[0].ResultStatementDigest != statementOne {
		t.Fatalf("the superseded result must be recorded as evidence: %+v", evidence)
	}
}

// An attempt the turn gives up on without replacing it is closed, not left
// running: a result for it becomes evidence, the task stays open for a later
// replacement, and closing settled work is idempotent.
func TestAnAbandonedAttemptIsClosedAndCannotCommit(t *testing.T) {
	coordinator, repository, _ := newCoordinator(t)
	ctx := context.Background()
	execution, err := coordinator.Open(ctx, testRequest())
	if err != nil {
		t.Fatal(err)
	}
	if err := coordinator.Dispatched(ctx, execution); err != nil {
		t.Fatal(err)
	}
	if err := coordinator.Close(ctx, execution, "not a reason code"); err == nil {
		t.Fatal("a close without a stable reason code must be refused")
	}
	if err := coordinator.Close(ctx, execution, dispatch.ReasonResultUnattributable); err != nil {
		t.Fatal(err)
	}
	task, attempts, known, err := coordinator.Load(ctx, testScope(), execution.Task.TaskID)
	if err != nil || !known {
		t.Fatalf("load: known=%v err=%v", known, err)
	}
	if len(attempts) != 1 || attempts[0].Status != dispatch.Failed || attempts[0].FailureReason != dispatch.ReasonResultUnattributable || attempts[0].FinishedAt.IsZero() {
		t.Fatalf("the abandoned attempt must be closed as failed with its reason: %+v", attempts)
	}
	if task.Status.Terminal() {
		t.Fatalf("closing an attempt must not close the logical task: %+v", task)
	}
	late, err := coordinator.Settle(ctx, settle(execution, statementOne))
	if err != nil {
		t.Fatal(err)
	}
	if late.Disposition != dispatch.DispositionTerminal {
		t.Fatalf("a result for a closed attempt must be evidence, not an outcome: %+v", late)
	}
	if evidence := repository.Evidence(); len(evidence) != 1 || evidence[0].Disposition != dispatch.DispositionTerminal {
		t.Fatalf("the late result must be recorded: %+v", evidence)
	}
	// Closing again changes nothing: whatever ended the attempt first stands.
	if err := coordinator.Close(ctx, execution, dispatch.ReasonTurnAbandoned); err != nil {
		t.Fatal(err)
	}
	_, attempts, _, _ = coordinator.Load(ctx, testScope(), execution.Task.TaskID)
	if attempts[0].FailureReason != dispatch.ReasonResultUnattributable {
		t.Fatalf("a second close must not rewrite the first reason: %+v", attempts[0])
	}
	// The task is still open work: a replacement opens on it and commits.
	replacement := testRequest()
	replacement.Replacing = dispatch.ReasonReplaced
	second, err := coordinator.Open(ctx, replacement)
	if err != nil {
		t.Fatal(err)
	}
	if second.Attempt.AttemptNumber != 2 || second.Attempt.LeaseEpoch != 2 {
		t.Fatalf("the replacement must carry the next attempt number and lease epoch: %+v", second.Attempt)
	}
	committed, err := coordinator.Settle(ctx, settle(second, statementTwo))
	if err != nil {
		t.Fatal(err)
	}
	if !committed.Disposition.Committed() {
		t.Fatalf("the replacement must commit: %+v", committed)
	}
	unknown := execution
	unknown.Attempt.PhysicalAttemptID = "attempt.unknown"
	if err := coordinator.Close(ctx, unknown, dispatch.ReasonTurnAbandoned); err == nil {
		t.Fatal("closing an attempt the record does not know must be refused")
	}
}

// Redelivery of the same result is idempotent: one statement settles one task
// once, and arriving again changes nothing and is still accounted for.
func TestRedeliveredResultCommitsOnlyOnce(t *testing.T) {
	coordinator, repository, _ := newCoordinator(t)
	ctx := context.Background()
	execution, err := coordinator.Open(ctx, testRequest())
	if err != nil {
		t.Fatal(err)
	}
	first, err := coordinator.Settle(ctx, settle(execution, statementOne))
	if err != nil || !first.Disposition.Committed() {
		t.Fatalf("first result must commit: %+v %v", first, err)
	}
	again, err := coordinator.Settle(ctx, settle(execution, statementOne))
	if err != nil {
		t.Fatal(err)
	}
	if again.Disposition != dispatch.DispositionDuplicate {
		t.Fatalf("redelivery = %+v, want duplicate", again)
	}
	different, err := coordinator.Settle(ctx, settle(execution, statementTwo))
	if err != nil {
		t.Fatal(err)
	}
	if different.Disposition != dispatch.DispositionTerminal {
		t.Fatalf("a second, different result must not overwrite a settled task: %+v", different)
	}
	if len(repository.Evidence()) != 2 {
		t.Fatalf("both non-committing results must be recorded: %+v", repository.Evidence())
	}
}

// The commit predicate is all of its fields. Each one alone is enough to stop
// a result from changing state.
func TestEveryPredicateFieldFencesTheCommit(t *testing.T) {
	for _, testCase := range []struct {
		name   string
		break_ func(*dispatch.Settle)
	}{
		{"fence token", func(s *dispatch.Settle) { s.Predicate.FenceToken = strings.Repeat("x", 32) }},
		{"attempt number", func(s *dispatch.Settle) { s.Predicate.AttemptNumber = 7 }},
		{"lease epoch", func(s *dispatch.Settle) { s.Predicate.LeaseEpoch = 7 }},
		{"execution generation", func(s *dispatch.Settle) { s.Predicate.ExecutionGeneration = 9 }},
		{"runtime unit", func(s *dispatch.Settle) { s.Predicate.RuntimeUnitID = "runtime.platform.other" }},
		{"runtime manifest digest", func(s *dispatch.Settle) {
			s.Predicate.RuntimeManifestDigest = "sha256:" + strings.Repeat("f", 64)
		}},
		{"runtime image digest", func(s *dispatch.Settle) {
			s.Predicate.RuntimeImageDigest = "sha256:" + strings.Repeat("f", 64)
		}},
		{"invocation protocol digest", func(s *dispatch.Settle) {
			s.Predicate.InvocationProtocolDigest = "sha256:" + strings.Repeat("f", 64)
		}},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			coordinator, repository, _ := newCoordinator(t)
			ctx := context.Background()
			execution, err := coordinator.Open(ctx, testRequest())
			if err != nil {
				t.Fatal(err)
			}
			request := settle(execution, statementOne)
			testCase.break_(&request)
			result, err := coordinator.Settle(ctx, request)
			if err != nil {
				t.Fatal(err)
			}
			if result.Disposition != dispatch.DispositionStaleFence {
				t.Fatalf("a mismatched %s must fence the commit, got %+v", testCase.name, result)
			}
			if !strings.Contains(result.Reason, testCase.name) {
				t.Fatalf("the evidence must name the field that disagreed: %q", result.Reason)
			}
			if len(repository.Evidence()) != 1 {
				t.Fatal("a fenced result must still be recorded")
			}
			task, _, _, err := repository.Load(ctx, testScope(), execution.Task.TaskID)
			if err != nil {
				t.Fatal(err)
			}
			if task.Status == dispatch.Succeeded {
				t.Fatal("a fenced result must not settle the task")
			}
		})
	}
}

// Cancellation revokes the lease, and a result that arrives afterwards cannot
// commit however valid it is on its own terms.
func TestCancellationPreventsALaterCommit(t *testing.T) {
	coordinator, repository, _ := newCoordinator(t)
	ctx := context.Background()
	execution, err := coordinator.Open(ctx, testRequest())
	if err != nil {
		t.Fatal(err)
	}
	if err := coordinator.Dispatched(ctx, execution); err != nil {
		t.Fatal(err)
	}
	open, err := coordinator.CancelRun(ctx, testScope(), "run.test", dispatch.ReasonLeaseRevoked)
	if err != nil {
		t.Fatal(err)
	}
	if open != 1 {
		t.Fatalf("cancellation must report the executions it revoked, got %d", open)
	}
	result, err := coordinator.Settle(ctx, settle(execution, statementOne))
	if err != nil {
		t.Fatal(err)
	}
	if result.Disposition != dispatch.DispositionCanceled {
		t.Fatalf("a result after cancellation must not commit: %+v", result)
	}
	if len(repository.Evidence()) != 1 {
		t.Fatal("the cancelled result must still be recorded")
	}
}

// A task that outlived its own deadline is expired, and an answer that arrives
// after it is evidence.
func TestExpiryPreventsALaterCommit(t *testing.T) {
	coordinator, repository, clock := newCoordinator(t)
	ctx := context.Background()
	execution, err := coordinator.Open(ctx, testRequest())
	if err != nil {
		t.Fatal(err)
	}
	clock.now = clock.now.Add(2 * time.Minute)
	request := settle(execution, statementOne)
	request.Outcome.ObservedAt = clock.now
	result, err := coordinator.Settle(ctx, request)
	if err != nil {
		t.Fatal(err)
	}
	if result.Disposition != dispatch.DispositionExpired {
		t.Fatalf("an expired attempt must not commit: %+v", result)
	}
	// The record says so too: work whose deadline passed stops being open
	// rather than staying accepted for ever.
	task, attempts, _, err := repository.Load(ctx, testScope(), execution.Task.TaskID)
	if err != nil {
		t.Fatal(err)
	}
	if attempts[0].Status != dispatch.Expired || attempts[0].FailureReason != dispatch.ReasonDeadlineExceeded {
		t.Fatalf("the attempt must be recorded as expired: %+v", attempts[0])
	}
	if task.Status != dispatch.Expired {
		t.Fatalf("the task must be recorded as expired: %+v", task)
	}
}

// The logical task lives as long as the execution it currently has: a
// replacement opened after the first lease ran out must still be able to
// commit, or recovery would produce work nothing can accept.
func TestAReplacementOpenedAfterTheFirstLeaseCanStillCommit(t *testing.T) {
	coordinator, _, clock := newCoordinator(t)
	ctx := context.Background()
	if _, err := coordinator.Open(ctx, testRequest()); err != nil {
		t.Fatal(err)
	}
	clock.now = clock.now.Add(2 * time.Minute)
	replacement := testRequest()
	replacement.Replacing = dispatch.ReasonDispatchFailed
	second, err := coordinator.Open(ctx, replacement)
	if err != nil {
		t.Fatal(err)
	}
	request := settle(second, statementOne)
	request.Outcome.ObservedAt = clock.now
	result, err := coordinator.Settle(ctx, request)
	if err != nil {
		t.Fatal(err)
	}
	if !result.Disposition.Committed() {
		t.Fatalf("the replacement must be committable: %+v", result)
	}
}

// A result naming an attempt this service never opened has nothing to change.
func TestUnknownAttemptIsRecordedAsUnbound(t *testing.T) {
	coordinator, repository, _ := newCoordinator(t)
	ctx := context.Background()
	execution, err := coordinator.Open(ctx, testRequest())
	if err != nil {
		t.Fatal(err)
	}
	request := settle(execution, statementOne)
	request.Predicate.PhysicalAttemptID = "attempt.never-opened"
	result, err := coordinator.Settle(ctx, request)
	if err != nil {
		t.Fatal(err)
	}
	if result.Disposition != dispatch.DispositionUnbound {
		t.Fatalf("an unknown attempt must be unbound: %+v", result)
	}
	if len(repository.Evidence()) != 1 {
		t.Fatal("an unbound result must still be recorded")
	}
}

// The logical task identity is the work, so reaching it with different work is
// a reused identity rather than a retry.
func TestTaskIdentityReuseWithDifferentWorkIsRefused(t *testing.T) {
	coordinator, _, _ := newCoordinator(t)
	ctx := context.Background()
	if _, err := coordinator.Open(ctx, testRequest()); err != nil {
		t.Fatal(err)
	}
	different := testRequest()
	different.RequestDigest = "sha256:" + strings.Repeat("9", 64)
	_, err := coordinator.Open(ctx, different)
	var details problem.Details
	if err == nil || !errorsAs(err, &details) || details.Code != string(problem.CodeIdempotencyKeyReused) {
		t.Fatalf("reused identity = %v", err)
	}
}

// The logical task identity is a pure function of the durable operation, so a
// replayed step converges on the task it already created.
func TestTaskIdentityIsDerivedFromTheDurableOperation(t *testing.T) {
	operation := "run.test:g1:turn-0000"
	derived := dispatch.TaskID(operation)
	if again := dispatch.TaskID(operation); derived != again {
		t.Fatalf("the same operation must derive the same task: %s then %s", derived, again)
	}
	if dispatch.TaskID("run.test:g1:turn-0000") == dispatch.TaskID("run.test:g1:turn-0001") {
		t.Fatal("different operations must derive different tasks")
	}
	if dispatch.AttemptID("task.a", 1) == dispatch.AttemptID("task.a", 2) {
		t.Fatal("each numbered attempt of a task is its own identity")
	}
}

// A task may not be dispatched twice under one attempt: the record of the
// dispatch is what tells recovery an execution left this process.
func TestDispatchIsRecordedOncePerAttempt(t *testing.T) {
	coordinator, _, _ := newCoordinator(t)
	ctx := context.Background()
	execution, err := coordinator.Open(ctx, testRequest())
	if err != nil {
		t.Fatal(err)
	}
	if err := coordinator.Dispatched(ctx, execution); err != nil {
		t.Fatal(err)
	}
	if err := coordinator.Dispatched(ctx, execution); err == nil {
		t.Fatal("a second dispatch of the same attempt must be refused")
	}
}

func errorsAs(err error, target *problem.Details) bool {
	details, ok := err.(problem.Details)
	if ok {
		*target = details
		return true
	}
	return false
}
