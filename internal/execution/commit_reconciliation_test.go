package execution_test

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ancyloce/anvilkit-agent-service/internal/authority"
	"github.com/ancyloce/anvilkit-agent-service/internal/domaincommit"
	"github.com/ancyloce/anvilkit-agent-service/internal/events"
	"github.com/ancyloce/anvilkit-agent-service/internal/execution"
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
	// it can record the outcome. The run holds unsettled at the boundary; it
	// is never failed and never reported as settled.
	h.domain.LoseAnswer(true)
	held, err := h.ops.Commit(context.Background(), op, commit)
	if err != nil || !held.Unsettled {
		t.Fatalf("a lost domain answer must hold unsettled, got %+v err=%v", held, err)
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
	if result.Unsettled {
		t.Fatalf("result = %+v, want the recorded outcome once the owner answers", result)
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
	held, err := h.ops.Commit(context.Background(), op, commit)
	if err != nil || !held.Unsettled {
		t.Fatalf("a lost domain answer must hold unsettled, got %+v err=%v", held, err)
	}
	commit.Version = h.snapshot().Version
	held, err = h.ops.Commit(context.Background(), op, commit)
	if err != nil || !held.Unsettled || held.RetryAfterMillis < 1 {
		t.Fatalf("an undecided owner must hold unsettled with a bounded backoff, got %+v err=%v", held, err)
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

// After an uncertain submission — the durable intent mark is set and the
// owner has no record yet — the run reconciles instead of repeating the
// effect or failing it prematurely. Every uncertain reconciliation is counted
// durably; the bounded window escalates the journal to operator resolution;
// and the audited resolution settles the run — with zero resends throughout.
// This is the MarkIssued → Domain.Commit crash window end to end.
func TestAnUncertainSubmissionHoldsCountsEscalatesAndResolves(t *testing.T) {
	h := newHarness(t, [][]byte{finalPlan()})
	_, op, commit, release := approvedCommit(t, h, "approve-lost")
	defer close(release)
	journalScope := domaincommit.Scope{WorkspaceID: testWorkspace, ProjectID: testProject}

	h.domain.LoseSubmission(true)
	held, err := h.ops.Commit(context.Background(), op, commit)
	if err != nil || !held.Unsettled {
		t.Fatalf("a lost submission must hold unsettled, got %+v err=%v", held, err)
	}
	if snapshot := h.snapshot(); snapshot.Status != runs.AwaitingDomainConfirmation {
		t.Fatalf("run state = %s, want the submit boundary", snapshot.Status)
	}
	// The harness escalation bound is three uncertain reconciliations. Each
	// wake counts durably; the third escalates; and even escalated, every
	// further wake holds — nothing fails, nothing is resent.
	for wake := 0; wake < 4; wake++ {
		commit.Version = h.snapshot().Version
		held, err = h.ops.Commit(context.Background(), op, commit)
		if err != nil || !held.Unsettled || held.RetryAfterMillis < 1 {
			t.Fatalf("wake %d = %+v err=%v, want a bounded unsettled hold", wake, held, err)
		}
	}
	operation, active, err := h.submissions.ActiveForRun(context.Background(), journalScope, testRunID)
	if err != nil || !active {
		t.Fatalf("active operation err=%v active=%v", err, active)
	}
	if operation.Status != domaincommit.Escalated || operation.ReconcileAttempts < 3 || operation.EscalatedAt.IsZero() || operation.FirstUncertainAt.IsZero() {
		t.Fatalf("operation = %+v, want a durably escalated record with its uncertainty trail", operation)
	}
	if h.domain.Commits() != 0 {
		t.Fatalf("domain commits = %d, want no blind resend while the outcome is uncertain", h.domain.Commits())
	}
	if snapshot := h.snapshot(); snapshot.Status != runs.AwaitingDomainConfirmation {
		t.Fatalf("run state = %s, want the run held, never prematurely failed", snapshot.Status)
	}

	// The audited operator resolution decides the journal — here the operator
	// verified against the authoritative owner that nothing landed — and the
	// next reconciliation settles the run from the recorded outcome.
	if _, err := h.submissions.Resolve(context.Background(), journalScope, operation.ID, domaincommit.Rejected, "operator.oncall", "domain-owner audit ticket OPS-1", time.Now().UTC()); err != nil {
		t.Fatal(err)
	}
	commit.Version = h.snapshot().Version
	settled, err := h.ops.Commit(context.Background(), op, commit)
	if err != nil || settled.Unsettled || settled.Outcome != workflow.CommitFailed {
		t.Fatalf("settled = %+v err=%v, want the operator-recorded rejection", settled, err)
	}
	if h.domain.Commits() != 0 {
		t.Fatalf("domain commits = %d, want zero effects for a rejected resolution", h.domain.Commits())
	}
	if snapshot := h.snapshot(); snapshot.Status != runs.Failed {
		t.Fatalf("run state = %s, want the recorded terminal failure", snapshot.Status)
	}
}

// ResolveEscalatedSubmission is the operator entry point when the workflow
// has already released the run at the boundary: after the audited journal
// resolution it drives the run to the recorded outcome without contacting
// the owner or resending anything.
func TestOperatorSettlementDrivesTheHeldRunFromTheResolvedJournal(t *testing.T) {
	h := newHarness(t, [][]byte{finalPlan()})
	_, op, commit, release := approvedCommit(t, h, "approve-operator")
	defer close(release)
	journalScope := domaincommit.Scope{WorkspaceID: testWorkspace, ProjectID: testProject}

	h.domain.LoseSubmission(true)
	if held, err := h.ops.Commit(context.Background(), op, commit); err != nil || !held.Unsettled {
		t.Fatalf("held = %+v err=%v", held, err)
	}
	operation, active, err := h.submissions.ActiveForRun(context.Background(), journalScope, testRunID)
	if err != nil || !active {
		t.Fatalf("active operation err=%v active=%v", err, active)
	}
	// An undecided journal refuses operator settlement outright.
	if _, err := h.executor.ResolveEscalatedSubmission(context.Background(), testScope(), testRunID); err == nil {
		t.Fatal("an undecided journal must refuse operator settlement")
	}
	// The journal resolution requires the escalated state and a complete
	// audit identity.
	if _, err := h.submissions.Resolve(context.Background(), journalScope, operation.ID, domaincommit.Rejected, "operator.oncall", "basis", time.Now().UTC()); err == nil {
		t.Fatal("resolving an unescalated operation must be refused")
	}
	if err := h.submissions.Escalate(context.Background(), journalScope, operation.ID, time.Now().UTC()); err != nil {
		t.Fatal(err)
	}
	if _, err := h.submissions.Resolve(context.Background(), journalScope, operation.ID, domaincommit.Rejected, "", "", time.Now().UTC()); err == nil {
		t.Fatal("an unaudited resolution must be refused")
	}
	if _, err := h.submissions.Resolve(context.Background(), journalScope, operation.ID, domaincommit.Rejected, "operator.oncall", "domain-owner audit ticket OPS-2", time.Now().UTC()); err != nil {
		t.Fatal(err)
	}
	settled, err := h.executor.ResolveEscalatedSubmission(context.Background(), testScope(), testRunID)
	if err != nil || settled.Status != runs.Failed {
		t.Fatalf("settled = %+v err=%v, want the recorded terminal failure", settled, err)
	}
	// Settlement converges: a second operator call reports the settled run.
	again, err := h.executor.ResolveEscalatedSubmission(context.Background(), testScope(), testRunID)
	if err != nil || again.Status != runs.Failed {
		t.Fatalf("again = %+v err=%v", again, err)
	}
	if h.domain.Commits() != 0 {
		t.Fatalf("domain commits = %d, want zero effects", h.domain.Commits())
	}
}

// haltBeforeIssuedMark fails the durable submitted-intent mark exactly once,
// which is what a crash between recording the write-ahead operation and
// sending it looks like to a successor process.
type haltBeforeIssuedMark struct {
	domaincommit.Store
	failures int
}

func (s *haltBeforeIssuedMark) MarkIssued(ctx context.Context, scope domaincommit.Scope, id string, now time.Time) error {
	if s.failures > 0 {
		s.failures--
		return errors.New("injected crash before the submitted-intent mark")
	}
	return s.Store.MarkIssued(ctx, scope, id, now)
}

// A crash before submission is recoverable exactly because the write-ahead
// record exists in the not-submitted state: the replay proves nothing was
// sent and safely submits under the same stable operation identity.
func TestCrashBeforeSubmissionSafelySubmitsUnderTheSameOperationIdentity(t *testing.T) {
	journal := &haltBeforeIssuedMark{Store: domaincommit.NewMemoryStore(), failures: 1}
	h := newHarness(t, [][]byte{finalPlan()}, func(options *harnessOptions) { options.submissions = journal })
	_, op, commit, release := approvedCommit(t, h, "approve-crash-before-send")
	defer close(release)

	if _, err := h.ops.Commit(context.Background(), op, commit); err == nil {
		t.Fatal("the injected crash before the intent mark must surface")
	}
	if h.domain.Commits() != 0 {
		t.Fatalf("domain commits = %d, want none before the intent mark", h.domain.Commits())
	}
	if snapshot := h.snapshot(); snapshot.Status != runs.AwaitingDomainConfirmation {
		t.Fatalf("run state = %s, want the submit boundary", snapshot.Status)
	}
	recorded, active, err := journal.ActiveForRun(context.Background(), domaincommit.Scope{WorkspaceID: testWorkspace, ProjectID: testProject}, testRunID)
	if err != nil || !active || recorded.Status != domaincommit.Recorded {
		t.Fatalf("write-ahead record = %+v active=%v err=%v, want the durable not-submitted state", recorded, active, err)
	}
	// Recovery re-executes the identical durable operation: the not-submitted
	// record authorizes exactly one submission under the recorded identity.
	commit.Version = h.snapshot().Version
	result, err := h.ops.Commit(context.Background(), op, commit)
	if err != nil || result.Outcome != workflow.CommitCompleted {
		t.Fatalf("result = %+v err = %v", result, err)
	}
	if h.domain.Commits() != 1 {
		t.Fatalf("domain commits = %d, want exactly one submission", h.domain.Commits())
	}
	if len(h.commitAuthority.Issued()) != 1 {
		t.Fatalf("issued authorizations = %d, want the original issuance only", len(h.commitAuthority.Issued()))
	}
	settled, err := journal.Get(context.Background(), domaincommit.Scope{WorkspaceID: testWorkspace, ProjectID: testProject}, recorded.ID)
	if err != nil || settled.Status != domaincommit.Applied {
		t.Fatalf("journal record = %+v err=%v, want the applied terminal state", settled, err)
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
	if held, err := h.ops.Commit(context.Background(), op, commit); err != nil || !held.Unsettled {
		t.Fatalf("a lost domain answer must hold unsettled, got %+v err=%v", held, err)
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

// escalatedRun drives a run to a durably escalated governed effect and
// returns the escalated operation.
func escalatedRun(t *testing.T, h *harness, key string) (domaincommit.Operation, func()) {
	t.Helper()
	_, op, commit, release := approvedCommit(t, h, key)
	journalScope := domaincommit.Scope{WorkspaceID: testWorkspace, ProjectID: testProject}
	h.domain.LoseSubmission(true)
	for wake := 0; wake < 5; wake++ {
		commit.Version = h.snapshot().Version
		if _, err := h.ops.Commit(context.Background(), op, commit); err != nil {
			close(release)
			t.Fatalf("wake %d: %v", wake, err)
		}
	}
	operation, active, err := h.submissions.ActiveForRun(context.Background(), journalScope, testRunID)
	if err != nil || !active || operation.Status != domaincommit.Escalated {
		close(release)
		t.Fatalf("operation=%+v active=%v err=%v, want a durably escalated effect", operation, active, err)
	}
	return operation, func() { close(release) }
}

// The production operator recovery path proves every part of the decision
// before it lands: the caller's current authority must admit them as an
// operator in this exact scope, the run must be readable inside that scope,
// the decision must name the run's own operation, and the version the operator
// observed must still be current. Only then is the audited resolution recorded
// and the held run settled.
func TestOperatorRecoveryEnforcesRoleScopeAndBindingBeforeSettling(t *testing.T) {
	h := newHarness(t, [][]byte{finalPlan()})
	operation, done := escalatedRun(t, h, "approve-recovery")
	defer done()

	command := execution.OperatorResolution{
		OperationID: operation.ID,
		Outcome:     execution.DomainRejected,
		OperatorID:  "operator.oncall",
		Basis:       operatorEvidenceBasis,
	}
	version := h.snapshot().Version

	// The run actor is admitted, but not under the operator role.
	if _, err := h.executor.ResolveEscalation(context.Background(), testScope(), testRunID, version, command); !hasProblemCode(err, problem.CodeAuthorizationDenied) {
		t.Fatalf("an actor without the operator role resolved an escalation: %v", err)
	}
	h.grantRole(authority.RoleOperator)

	// A neighbouring tenant cannot reach this run at all.
	foreign := testScope()
	foreign.WorkspaceID = "workspace.other"
	if _, err := h.executor.ResolveEscalation(context.Background(), foreign, testRunID, version, command); err == nil {
		t.Fatal("a foreign workspace resolved this run's escalation")
	}
	foreignProject := testScope()
	foreignProject.ProjectID = "project.other"
	if _, err := h.executor.ResolveEscalation(context.Background(), foreignProject, testRunID, version, command); err == nil {
		t.Fatal("a foreign project resolved this run's escalation")
	}

	// Withdrawn authority denies the recovery on this read, however current it
	// was when the escalation was raised.
	h.authoritySource.Revoke()
	if _, err := h.executor.ResolveEscalation(context.Background(), testScope(), testRunID, version, command); !hasProblemCode(err, problem.CodeAuthorityStale) {
		t.Fatalf("revoked authority resolved an escalation: %v", err)
	}
	h.authoritySource.Restore()

	// A decision naming another operation never lands on this run's one.
	mismatched := command
	mismatched.OperationID = "domain.some-other-operation"
	if _, err := h.executor.ResolveEscalation(context.Background(), testScope(), testRunID, version, mismatched); !hasProblemCode(err, problem.CodeIdempotencyConflict) {
		t.Fatalf("a mismatched operation identity was accepted: %v", err)
	}

	// The audit identity is mandatory, the outcome must be an authoritative
	// domain outcome, and the basis must be the bounded evidence reference the
	// canonical contract defines — never operator prose, which would carry
	// unbounded content of unknown sensitivity into an immutable audit record.
	for name, invalid := range map[string]execution.OperatorResolution{
		"no-operator":      {OperationID: operation.ID, Outcome: execution.DomainRejected, Basis: operatorEvidenceBasis},
		"no-basis":         {OperationID: operation.ID, Outcome: execution.DomainRejected, OperatorID: "operator.oncall"},
		"blank-basis":      {OperationID: operation.ID, Outcome: execution.DomainRejected, OperatorID: "operator.oncall", Basis: "   "},
		"prose-basis":      {OperationID: operation.ID, Outcome: execution.DomainRejected, OperatorID: "operator.oncall", Basis: "the owner has no record of this operation, see OPS-7"},
		"foreign-scheme":   {OperationID: operation.ID, Outcome: execution.DomainRejected, OperatorID: "operator.oncall", Basis: "https://audit.example.com/OPS-7-no-record"},
		"authorityless":    {OperationID: operation.ID, Outcome: execution.DomainRejected, OperatorID: "operator.oncall", Basis: "anvilkit://evidence/OPS-7-no-record-of-operation"},
		"uppercase-issuer": {OperationID: operation.ID, Outcome: execution.DomainRejected, OperatorID: "operator.oncall", Basis: "anvilkit://evidence/Domain-Owner-Audit/OPS-7"},
		"oversized-record": {OperationID: operation.ID, Outcome: execution.DomainRejected, OperatorID: "operator.oncall", Basis: "anvilkit://evidence/domain-owner-audit/" + strings.Repeat("a", 129)},
		"bad-outcome":      {OperationID: operation.ID, Outcome: "settled-somehow", OperatorID: "operator.oncall", Basis: operatorEvidenceBasis},
	} {
		if _, err := h.executor.ResolveEscalation(context.Background(), testScope(), testRunID, version, invalid); !hasProblemCode(err, problem.CodeRequestInvalid) {
			t.Fatalf("%s was accepted: %v", name, err)
		}
	}

	// The version the operator observed must still be the run's version.
	if _, err := h.executor.ResolveEscalation(context.Background(), testScope(), testRunID, version+7, command); !hasProblemCode(err, problem.CodeVersionConflict) {
		t.Fatalf("a stale version precondition was accepted: %v", err)
	}

	settled, err := h.executor.ResolveEscalation(context.Background(), testScope(), testRunID, version, command)
	if err != nil || settled.Status != runs.Failed {
		t.Fatalf("settled=%+v err=%v, want the recorded terminal failure", settled, err)
	}
	if h.domain.Commits() != 0 {
		t.Fatalf("domain commits = %d, want operator recovery to contact nobody", h.domain.Commits())
	}

	// The journal carries the immutable audit of who decided and on what.
	journalScope := domaincommit.Scope{WorkspaceID: testWorkspace, ProjectID: testProject}
	resolved, err := h.submissions.Get(context.Background(), journalScope, operation.ID)
	if err != nil || resolved.Status != domaincommit.Rejected || resolved.ResolvedBy != command.OperatorID || resolved.ResolutionBasis != command.Basis {
		t.Fatalf("resolved=%+v err=%v, want the audited operator resolution", resolved, err)
	}
	// And so does the evidence store.
	records, err := h.evidence.ReadEvidence(context.Background(), events.Scope{WorkspaceID: testWorkspace, ProjectID: testProject}, testRunID, "test", "assert", 0)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, record := range records {
		if record.Type == "domain.submission-operator-resolved" && record.Payload["resolvedBy"] == command.OperatorID && record.Payload["basis"] == command.Basis && record.Payload["outcome"] == execution.DomainRejected {
			found = true
		}
	}
	if !found {
		t.Fatalf("evidence = %+v, want the immutable operator-recovery record", records)
	}

	// The identical audited decision converges instead of deciding twice.
	again, err := h.executor.ResolveEscalation(context.Background(), testScope(), testRunID, h.snapshot().Version, command)
	if err != nil || again.Status != runs.Failed {
		t.Fatalf("again=%+v err=%v, want convergence", again, err)
	}
	// A different decision on the same, now-decided, effect is refused.
	different := command
	different.Outcome = execution.DomainConfirmed
	if _, err := h.executor.ResolveEscalation(context.Background(), testScope(), testRunID, h.snapshot().Version, different); !hasProblemCode(err, problem.CodeIdempotencyConflict) {
		t.Fatalf("a decided effect was overridden: %v", err)
	}
}

// Racing operators produce exactly one decision. The journal's
// compare-and-set on the escalated state is the arbiter, so the losers are
// refused rather than overwriting the winner.
func TestConcurrentOperatorResolutionsProduceOneDecision(t *testing.T) {
	h := newHarness(t, [][]byte{finalPlan()})
	operation, done := escalatedRun(t, h, "approve-race")
	defer done()
	h.grantRole(authority.RoleOperator)
	version := h.snapshot().Version

	const racers = 8
	var start sync.WaitGroup
	var finished sync.WaitGroup
	start.Add(1)
	accepted := make([]bool, racers)
	for index := 0; index < racers; index++ {
		finished.Add(1)
		go func(index int) {
			defer finished.Done()
			start.Wait()
			_, err := h.executor.ResolveEscalation(context.Background(), testScope(), testRunID, version, execution.OperatorResolution{
				OperationID: operation.ID,
				Outcome:     execution.DomainRejected,
				OperatorID:  fmt.Sprintf("operator.%02d", index),
				Basis:       fmt.Sprintf("anvilkit://evidence/domain-owner-audit/OPS-%02d", index),
			})
			accepted[index] = err == nil
		}(index)
	}
	start.Done()
	finished.Wait()
	winners := 0
	for _, ok := range accepted {
		if ok {
			winners++
		}
	}
	if winners != 1 {
		t.Fatalf("winners=%d, want exactly one audited decision", winners)
	}
	journalScope := domaincommit.Scope{WorkspaceID: testWorkspace, ProjectID: testProject}
	resolved, err := h.submissions.Get(context.Background(), journalScope, operation.ID)
	if err != nil || resolved.Status != domaincommit.Rejected || resolved.ResolvedBy == "" || resolved.ResolutionBasis == "" {
		t.Fatalf("resolved=%+v err=%v", resolved, err)
	}
	if snapshot := h.snapshot(); snapshot.Status != runs.Failed {
		t.Fatalf("run state = %s, want the single decided outcome", snapshot.Status)
	}
}

// hasProblemCode reports whether the error is the named typed problem.
func hasProblemCode(err error, code problem.Code) bool {
	var details problem.Details
	return errors.As(err, &details) && details.Code == string(code)
}

// operatorEvidenceBasis is the bounded evidence reference an operator recovery
// command carries: the authoritative record a reviewer can retrieve, never
// operator prose.
const operatorEvidenceBasis = "anvilkit://evidence/domain-owner-audit/OPS-7-no-record"

// TestOperatorResolutionRefusesAnUnauditableBasisBeforeRecordingAnything
// proves the ordering that keeps a run recoverable. The journal resolution is
// immutable, so a decision whose audit record cannot be stored must be refused
// before the journal holds it — otherwise every retry would re-read the same
// recorded decision, fail on the same evidence, and the run would never
// settle. Here the basis is well-formed but names a record whose identity the
// internal evidence contract prohibits: the command is refused, nothing is
// persisted, and a corrected decision still settles the run.
func TestOperatorResolutionRefusesAnUnauditableBasisBeforeRecordingAnything(t *testing.T) {
	h := newHarness(t, [][]byte{finalPlan()})
	operation, done := escalatedRun(t, h, "approve-unauditable")
	defer done()
	h.grantRole(authority.RoleOperator)
	journalScope := domaincommit.Scope{WorkspaceID: testWorkspace, ProjectID: testProject}

	// Every one of these is a syntactically valid evidence reference the
	// internal evidence contract nonetheless refuses to store.
	for name, basis := range map[string]string{
		"prompt-record": "anvilkit://evidence/domain-owner-audit/prompt-transcript-42",
		"secret-record": "anvilkit://evidence/domain-owner-audit/secret-store-entry",
		"canvas-record": "anvilkit://evidence/domain-owner-audit/canvas-export-9",
	} {
		unauditable := execution.OperatorResolution{
			OperationID: operation.ID,
			Outcome:     execution.DomainRejected,
			OperatorID:  "operator.oncall",
			Basis:       basis,
		}
		if _, err := h.executor.ResolveEscalation(context.Background(), testScope(), testRunID, h.snapshot().Version, unauditable); !hasProblemCode(err, problem.CodeRequestInvalid) {
			t.Fatalf("%s was accepted: %v", name, err)
		}
		// Nothing was persisted: the effect is still escalated, awaiting a
		// decision, and the run is still held at the submit boundary.
		held, err := h.submissions.Get(context.Background(), journalScope, operation.ID)
		if err != nil || held.Status != domaincommit.Escalated || held.ResolvedBy != "" || held.ResolutionBasis != "" {
			t.Fatalf("%s left the journal as %+v err=%v, want the effect still escalated and undecided", name, held, err)
		}
		if snapshot := h.snapshot(); snapshot.Status != runs.AwaitingDomainConfirmation {
			t.Fatalf("%s moved the run to %s, want it still held at the submit boundary", name, snapshot.Status)
		}
	}

	// The run is still recoverable: a decision whose audit record can be
	// stored settles it.
	settled, err := h.executor.ResolveEscalation(context.Background(), testScope(), testRunID, h.snapshot().Version, execution.OperatorResolution{
		OperationID: operation.ID,
		Outcome:     execution.DomainRejected,
		OperatorID:  "operator.oncall",
		Basis:       operatorEvidenceBasis,
	})
	if err != nil || settled.Status != runs.Failed {
		t.Fatalf("settled=%+v err=%v, want the corrected decision to settle the run", settled, err)
	}
}

// refusingEvidence fails the first append of one evidence type and then
// behaves exactly like the store it wraps. It is what a crash between a
// durable decision and its audit record looks like from the executor's side.
type refusingEvidence struct {
	inner    execution.EvidenceRecorder
	lock     sync.Mutex
	failType string
	failed   bool
	appends  map[string]int
}

func newRefusingEvidence(inner execution.EvidenceRecorder, failType string) *refusingEvidence {
	return &refusingEvidence{inner: inner, failType: failType, appends: map[string]int{}}
}

func (r *refusingEvidence) AppendEvidence(ctx context.Context, value events.Evidence) (uint64, error) {
	r.lock.Lock()
	if value.Type == r.failType && !r.failed {
		r.failed = true
		r.lock.Unlock()
		return 0, fmt.Errorf("evidence store unavailable")
	}
	r.appends[value.Type]++
	r.lock.Unlock()
	return r.inner.AppendEvidence(ctx, value)
}

func (r *refusingEvidence) count(evidenceType string) int {
	r.lock.Lock()
	defer r.lock.Unlock()
	return r.appends[evidenceType]
}

// TestOperatorResolutionConvergesWhenEvidenceFailsAfterTheJournalIsDecided
// proves the sequence repairs itself. The decision is durable first because
// the journal compare-and-set is what picks the single winner; if the process
// then dies before the audit record or the run transition lands, repeating the
// same decision converges on the recorded one, records the evidence exactly
// once, and settles the run. The alternate settlement-only recovery path
// reaches the same terminal state from the same journal.
func TestOperatorResolutionConvergesWhenEvidenceFailsAfterTheJournalIsDecided(t *testing.T) {
	var recorder *refusingEvidence
	h := newHarness(t, [][]byte{finalPlan()}, func(options *harnessOptions) {
		options.evidence = func(inner execution.EvidenceRecorder) execution.EvidenceRecorder {
			recorder = newRefusingEvidence(inner, "domain.submission-operator-resolved")
			return recorder
		}
	})
	operation, done := escalatedRun(t, h, "approve-crash")
	defer done()
	h.grantRole(authority.RoleOperator)
	journalScope := domaincommit.Scope{WorkspaceID: testWorkspace, ProjectID: testProject}
	command := execution.OperatorResolution{
		OperationID: operation.ID,
		Outcome:     execution.DomainRejected,
		OperatorID:  "operator.oncall",
		Basis:       operatorEvidenceBasis,
	}

	// The audit record cannot be written. The decision is already durable, so
	// the call fails and the run stays held rather than settling unaudited.
	if _, err := h.executor.ResolveEscalation(context.Background(), testScope(), testRunID, h.snapshot().Version, command); err == nil {
		t.Fatal("a run settled while its operator-recovery audit record was unwritable")
	}
	decided, err := h.submissions.Get(context.Background(), journalScope, operation.ID)
	if err != nil || decided.Status != domaincommit.Rejected || decided.ResolvedBy != command.OperatorID || decided.ResolutionBasis != command.Basis {
		t.Fatalf("journal=%+v err=%v, want the audited decision already durable", decided, err)
	}
	if snapshot := h.snapshot(); snapshot.Status != runs.AwaitingDomainConfirmation {
		t.Fatalf("run=%s, want it still held until its audit record lands", snapshot.Status)
	}

	// Repeating the same decision converges on the recorded one: the evidence
	// is written, the run settles, and nothing is decided twice.
	settled, err := h.executor.ResolveEscalation(context.Background(), testScope(), testRunID, h.snapshot().Version, command)
	if err != nil || settled.Status != runs.Failed {
		t.Fatalf("retry=%+v err=%v, want convergence onto the recorded decision", settled, err)
	}
	if recorder.count("domain.submission-operator-resolved") != 1 {
		t.Fatalf("operator-recovery evidence appended %d times, want exactly one durable record", recorder.count("domain.submission-operator-resolved"))
	}
	records, err := h.evidence.ReadEvidence(context.Background(), events.Scope{WorkspaceID: testWorkspace, ProjectID: testProject}, testRunID, "test", "assert", 0)
	if err != nil {
		t.Fatal(err)
	}
	audited := 0
	for _, record := range records {
		if record.Type == "domain.submission-operator-resolved" {
			audited++
			if record.Payload["resolvedBy"] != command.OperatorID || record.Payload["basis"] != command.Basis || record.Payload["outcome"] != execution.DomainRejected {
				t.Fatalf("evidence payload=%+v, want the journal's own audited facts", record.Payload)
			}
		}
	}
	if audited != 1 {
		t.Fatalf("operator-recovery evidence records=%d, want exactly one", audited)
	}

	// Repeating again still converges, and so does the settlement-only
	// recovery path that exists for an owner's late answer.
	if again, err := h.executor.ResolveEscalation(context.Background(), testScope(), testRunID, h.snapshot().Version, command); err != nil || again.Status != runs.Failed {
		t.Fatalf("second retry=%+v err=%v, want convergence", again, err)
	}
	if settledOnly, err := h.executor.ResolveEscalatedSubmission(context.Background(), testScope(), testRunID); err != nil || settledOnly.Status != runs.Failed {
		t.Fatalf("settlement-only recovery=%+v err=%v, want the same terminal state", settledOnly, err)
	}
	// Retries re-present the same evidence, and the store's own identity
	// dedup keeps exactly one immutable record of the decision.
	after, err := h.evidence.ReadEvidence(context.Background(), events.Scope{WorkspaceID: testWorkspace, ProjectID: testProject}, testRunID, "test", "assert", 0)
	if err != nil {
		t.Fatal(err)
	}
	stored := 0
	for _, record := range after {
		if record.Type == "domain.submission-operator-resolved" {
			stored++
		}
	}
	if stored != 1 {
		t.Fatalf("operator-recovery evidence records after retries=%d, want exactly one", stored)
	}
}
