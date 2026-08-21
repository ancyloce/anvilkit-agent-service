package execution_test

import (
	"context"
	"testing"

	"github.com/ancyloce/anvilkit-agent-service/internal/authority"
	"github.com/ancyloce/anvilkit-agent-service/internal/execution"
	"github.com/ancyloce/anvilkit-agent-service/internal/problem"
	"github.com/ancyloce/anvilkit-agent-service/internal/runs"
)

// TestAuthorizeOperatorRecoveryProvesEveryAxisOnEveryRead is the pipeline half
// of the receipt-replay guard. The application boundary answers a recorded
// operator resolution without running the command, so it asks this call for
// the same proof the command path gets. What the boundary can then rely on is
// exactly what this asserts: authority is re-read on every call, and every
// axis that could have changed since the first request — activation, the
// operator role, revocation of authority over the run's target, and the
// tenant the run belongs to — denies on this read rather than on a memory of
// the last one.
func TestAuthorizeOperatorRecoveryProvesEveryAxisOnEveryRead(t *testing.T) {
	ctx := context.Background()
	h := newHarness(t, [][]byte{finalPlan()})
	operation, done := escalatedRun(t, h, "approve-authorize-recovery")
	defer done()
	_ = operation

	// Admitted, but not under the operator role.
	if err := h.executor.AuthorizeOperatorRecovery(ctx, testScope(), testRunID); !hasProblemCode(err, problem.CodeAuthorizationDenied) {
		t.Fatalf("an actor without the operator role was authorized: %v", err)
	}
	h.grantRole(authority.RoleOperator)
	if err := h.executor.AuthorizeOperatorRecovery(ctx, testScope(), testRunID); err != nil {
		t.Fatalf("an admitted operator was refused: %v", err)
	}

	// A neighbouring tenant cannot reach this run at all, on either axis.
	foreignWorkspace := testScope()
	foreignWorkspace.WorkspaceID = "workspace.other"
	if err := h.executor.AuthorizeOperatorRecovery(ctx, foreignWorkspace, testRunID); err == nil {
		t.Fatal("a foreign workspace was authorized for this run's recovery")
	}
	foreignProject := testScope()
	foreignProject.ProjectID = "project.other"
	if err := h.executor.AuthorizeOperatorRecovery(ctx, foreignProject, testRunID); err == nil {
		t.Fatal("a foreign project was authorized for this run's recovery")
	}
	if err := h.executor.AuthorizeOperatorRecovery(ctx, testScope(), runs.ID("run.absent")); err == nil {
		t.Fatal("an absent run was authorized for recovery")
	}

	// Authority withdrawn since the escalation was raised denies on this read.
	h.authoritySource.Revoke()
	if err := h.executor.AuthorizeOperatorRecovery(ctx, testScope(), testRunID); !hasProblemCode(err, problem.CodeAuthorityStale) {
		t.Fatalf("revoked authority was authorized: %v", err)
	}
	h.authoritySource.Restore()
	h.grantRole(authority.RoleOperator)

	// Authority over the run's exact target is its own revocation axis: the
	// scope stays active and the role stays admitted, and the recovery is
	// still denied.
	revoked := h.currentAuthority(h.authority(defaultHarnessOptions()))
	revoked.ActorRole = authority.RoleOperator
	revoked.RevokedTargets = []string{"page.home"}
	h.authoritySource.Replace(revoked)
	if err := h.executor.AuthorizeOperatorRecovery(ctx, testScope(), testRunID); !hasProblemCode(err, problem.CodeAuthorityStale) {
		t.Fatalf("a revoked target was authorized for recovery: %v", err)
	}
	// The command path refuses the same caller, so a boundary that consults
	// this call before answering a receipt can never be more permissive than
	// the command it stands in for.
	command := execution.OperatorResolution{OperationID: operation.ID, Outcome: execution.DomainRejected, OperatorID: "operator.oncall", Basis: operatorEvidenceBasis}
	if _, err := h.executor.ResolveEscalation(ctx, testScope(), testRunID, h.snapshot().Version, command); !hasProblemCode(err, problem.CodeAuthorityStale) {
		t.Fatalf("the command path admitted a revoked target: %v", err)
	}
}
