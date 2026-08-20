package execution_test

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/ancyloce/anvilkit-agent-service/internal/interrupts"
	"github.com/ancyloce/anvilkit-agent-service/internal/problem"
	"github.com/ancyloce/anvilkit-agent-service/internal/runs"
	"github.com/ancyloce/anvilkit-agent-service/internal/workflow"
)

// approvedCommit drives a governed-effect run up to the approved commit
// boundary and returns the durable commit operation and its input. The
// workflow is held at the boundary so the test owns every commit that runs.
func approvedCommit(t *testing.T, h *harness, key string) (workflow.RunInput, workflow.OpID, workflow.CommitInput, chan struct{}) {
	t.Helper()
	input := h.seedRun("page-change")
	release, entered := h.ops.hold("commit-0000")
	if err := h.engine.StartRun(context.Background(), input); err != nil {
		t.Fatal(err)
	}
	request := h.openApprovalRequest()
	if _, err := h.decideApproval(request, interrupts.DecisionApprove, key); err != nil {
		t.Fatal(err)
	}
	<-entered
	return input, opID(input, "commit-0000"), workflow.CommitInput{
		Run: input, Turn: 0, RequestID: string(request.ID), ArtifactDigest: request.ActionDigest, Version: h.snapshot().Version,
	}, release
}

// A crash after a successful domain effect must never repeat that effect. The
// replayed commit reconciles against the authoritative record and settles the
// run from what already happened.
func TestCrashAfterASuccessfulDomainEffectReconcilesInsteadOfRepeatingIt(t *testing.T) {
	h := newHarness(t, [][]byte{finalPlan()})
	_, op, commit, release := approvedCommit(t, h, "approve-crash")
	defer close(release)

	// The effect lands, then the answer is lost — the process crashes before
	// it can record the outcome.
	h.domain.LoseAnswer(true)
	if _, err := h.ops.Commit(context.Background(), op, commit); err == nil {
		t.Fatal("a lost domain answer must not report a settled commit")
	}
	if h.domain.Commits() != 1 {
		t.Fatalf("domain commits = %d, want exactly the one that landed", h.domain.Commits())
	}
	if snapshot := h.snapshot(); snapshot.Status != runs.AwaitingDomainConfirmation {
		t.Fatalf("run state = %s, want the submit boundary the effect was sent from", snapshot.Status)
	}

	// Recovery re-executes the identical durable operation.
	h.domain.LoseAnswer(false)
	commit.Version = h.snapshot().Version
	result, err := h.ops.Commit(context.Background(), op, commit)
	if err != nil {
		t.Fatal(err)
	}
	if result.Outcome != workflow.CommitCompleted {
		t.Fatalf("outcome = %+v, want the recorded domain confirmation", result)
	}
	if h.domain.Commits() != 1 {
		t.Fatalf("domain commits = %d, want the effect never repeated", h.domain.Commits())
	}
	if h.domain.Reconciliations() == 0 {
		t.Fatal("recovery must ask the authoritative owner what became of the effect")
	}
	if len(h.commitAuthority.Issued()) != 1 {
		t.Fatalf("issued authorizations = %d, want no authorization minted after the effect", len(h.commitAuthority.Issued()))
	}
	if snapshot := h.snapshot(); snapshot.Status != runs.Completed {
		t.Fatalf("run state = %s, want completed", snapshot.Status)
	}
}

// An authoritative owner that holds the operation but has not decided it
// leaves the run at the submit boundary. Nothing is repeated, nothing is
// re-authorized, and the stop is typed so the durable operation is retried.
func TestUncertainDomainOutcomeHoldsTheRunAtTheSubmitBoundary(t *testing.T) {
	h := newHarness(t, [][]byte{finalPlan()})
	_, op, commit, release := approvedCommit(t, h, "approve-uncertain")
	defer close(release)

	h.domain.LoseAnswer(true)
	h.domain.HoldUndecided(true)
	if _, err := h.ops.Commit(context.Background(), op, commit); err == nil {
		t.Fatal("a lost domain answer must not report a settled commit")
	}
	commit.Version = h.snapshot().Version
	_, err := h.ops.Commit(context.Background(), op, commit)
	var details problem.Details
	if !errors.As(err, &details) || details.Code != string(problem.CodeDomainOutcomeUncertain) {
		t.Fatalf("error = %v, want %s", err, problem.CodeDomainOutcomeUncertain)
	}
	if h.domain.Commits() != 1 {
		t.Fatalf("domain commits = %d, want the effect never repeated while uncertain", h.domain.Commits())
	}
	if snapshot := h.snapshot(); snapshot.Status != runs.AwaitingDomainConfirmation {
		t.Fatalf("run state = %s, want the run held at the submit boundary", snapshot.Status)
	}

	// Once the owner settles, the same durable operation converges.
	h.domain.HoldUndecided(false)
	commit.Version = h.snapshot().Version
	result, err := h.ops.Commit(context.Background(), op, commit)
	if err != nil || result.Outcome != workflow.CommitCompleted {
		t.Fatalf("result = %+v err = %v", result, err)
	}
	if h.domain.Commits() != 1 {
		t.Fatalf("domain commits = %d, want exactly one governed effect in total", h.domain.Commits())
	}
}

// A submission that never reached the authoritative owner leaves no effect.
// That is the one condition under which the run may fail out of the submit
// boundary, and it must do so with a legal, retryable transition rather than
// stalling there forever.
func TestASubmissionTheDomainOwnerNeverReceivedFailsWithALegalTransition(t *testing.T) {
	h := newHarness(t, [][]byte{finalPlan()})
	_, op, commit, release := approvedCommit(t, h, "approve-lost")
	defer close(release)

	h.domain.LoseSubmission(true)
	if _, err := h.ops.Commit(context.Background(), op, commit); err == nil {
		t.Fatal("a lost submission must not report a settled commit")
	}
	if snapshot := h.snapshot(); snapshot.Status != runs.AwaitingDomainConfirmation {
		t.Fatalf("run state = %s, want the submit boundary", snapshot.Status)
	}
	commit.Version = h.snapshot().Version
	result, err := h.ops.Commit(context.Background(), op, commit)
	if err != nil {
		t.Fatal(err)
	}
	if result.Outcome != workflow.CommitFailed || result.Problem == nil || result.Problem.Code != string(problem.CodeDomainOutcomeUncertain) {
		t.Fatalf("result = %+v, want a reconciled failure", result)
	}
	if result.Problem.Retryability != "safe-after-backoff" {
		t.Fatalf("retryability = %q, want a reconciled failure to be retryable", result.Problem.Retryability)
	}
	if h.domain.Commits() != 0 {
		t.Fatalf("domain commits = %d, want none: the owner never received the submission", h.domain.Commits())
	}
	snapshot := h.snapshot()
	if snapshot.Status != runs.Failed {
		t.Fatalf("run state = %s, want a run that left the submit boundary", snapshot.Status)
	}
}

// A run whose governed effect may exist must not be terminalized on the
// workflow's say-so. The terminal boundary refuses and points at
// reconciliation instead, so the run is never stranded on a state with no
// legal exit.
func TestTerminalizingAnUnsettledGovernedEffectIsRefused(t *testing.T) {
	h := newHarness(t, [][]byte{finalPlan()})
	input, op, commit, release := approvedCommit(t, h, "approve-terminal")
	defer close(release)

	h.domain.LoseAnswer(true)
	if _, err := h.ops.Commit(context.Background(), op, commit); err == nil {
		t.Fatal("a lost domain answer must not report a settled commit")
	}
	failure := problem.Internal("")
	_, err := h.ops.Terminalize(context.Background(), opID(input, "terminal-failed-0000"), workflow.TerminalInput{Run: input, Turn: 0, Kind: workflow.TerminalFailed, Problem: &failure})
	var details problem.Details
	if !errors.As(err, &details) || details.Code != string(problem.CodeDomainOutcomeUncertain) {
		t.Fatalf("error = %v, want %s", err, problem.CodeDomainOutcomeUncertain)
	}
	if snapshot := h.snapshot(); snapshot.Status != runs.AwaitingDomainConfirmation {
		t.Fatalf("run state = %s, want the run still awaiting reconciliation", snapshot.Status)
	}
}

// Authority is re-read immediately before issuance and again immediately
// before the domain effect. Revoking it after the approval decision must stop
// the commit before an authorization exists, and the run must still have a
// legal transition out of the commit boundary.
func TestAuthorityRevokedBeforeIssuanceStopsTheCommitWithALegalTransition(t *testing.T) {
	h := newHarness(t, [][]byte{finalPlan()})
	_, op, commit, release := approvedCommit(t, h, "approve-revoked")
	defer close(release)

	h.authoritySource.Revoke()
	result, err := h.ops.Commit(context.Background(), op, commit)
	if err != nil {
		t.Fatal(err)
	}
	if result.Halt == nil || result.Halt.Problem.Code != string(problem.CodeAuthorityStale) {
		t.Fatalf("result = %+v, want an authority halt", result)
	}
	if len(h.commitAuthority.Issued()) != 0 {
		t.Fatalf("issued authorizations = %d, want none after revocation", len(h.commitAuthority.Issued()))
	}
	if h.domain.Commits() != 0 {
		t.Fatalf("domain commits = %d, want none after revocation", h.domain.Commits())
	}
	// The halt is recoverable: the run records the stop rather than being
	// stranded at the commit boundary with no legal edge.
	if _, err := h.repo.Transition(context.Background(), testScope(), testRunID, h.snapshot().Version, runs.Command{Kind: runs.RecordFailure, Failure: &result.Halt.Problem, Traceparent: traceparent}); err != nil {
		t.Fatalf("a halted commit had no legal transition out of %s: %v", h.snapshot().Status, err)
	}
	if snapshot := h.snapshot(); snapshot.Status != runs.Failed {
		t.Fatalf("run state = %s, want failed", snapshot.Status)
	}
}

// The domain operation identity is derived from the durable operation, so a
// replayed commit addresses the very same effect at the authoritative owner.
func TestReplayedCommitAddressesTheSameDomainOperation(t *testing.T) {
	h := newHarness(t, [][]byte{finalPlan()})
	_, op, commit, release := approvedCommit(t, h, "approve-identity")
	defer close(release)

	first, err := h.ops.Commit(context.Background(), op, commit)
	if err != nil || first.Outcome != workflow.CommitCompleted {
		t.Fatalf("result = %+v err = %v", first, err)
	}
	second, err := h.ops.Commit(context.Background(), op, commit)
	if err != nil || second.Outcome != workflow.CommitCompleted {
		t.Fatalf("replayed result = %+v err = %v", second, err)
	}
	if h.domain.Commits() != 1 {
		t.Fatalf("domain commits = %d, want the replay to cause no second effect", h.domain.Commits())
	}
	issued := h.commitAuthority.Issued()
	if len(issued) != 1 || !strings.HasPrefix(issued[0].IdempotencyKey, op.WorkflowID) {
		t.Fatalf("authorizations = %+v, want exactly one bound to the durable operation", issued)
	}
}
