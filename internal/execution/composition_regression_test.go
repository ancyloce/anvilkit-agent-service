package execution_test

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/ancyloce/anvilkit-agent-service/internal/authority"
	"github.com/ancyloce/anvilkit-agent-service/internal/execution"
	"github.com/ancyloce/anvilkit-agent-service/internal/problem"
	"github.com/ancyloce/anvilkit-agent-service/internal/recovery"
	"github.com/ancyloce/anvilkit-agent-service/internal/runs"
	"github.com/ancyloce/anvilkit-agent-service/internal/scheduler"
	"github.com/ancyloce/anvilkit-agent-service/internal/tools"
	"github.com/ancyloce/anvilkit-agent-service/internal/usage"
)

// staticToolMaterial serves one attested tool definition for every component.
type staticToolMaterial struct{ definition tools.Definition }

func (m staticToolMaterial) ComponentDigest(string) (string, bool) {
	return m.definition.InputSchema.Digest, true
}

func (m staticToolMaterial) ToolDefinition(string) (tools.Definition, bool) {
	return m.definition, true
}

func dispatchAuthority() *authority.Static {
	material := json.RawMessage(`{"synthetic":true}`)
	return authority.NewStatic(authority.Current{
		Definition: material, ContractBOM: material, Policy: material, Budget: material,
		WorkspaceActive: true, ActorActive: true, PermissionActive: true, PolicyActive: true,
		Grants: authority.Grants{AllowedCapabilities: []string{"fake.execute"}},
	})
}

// fixedDispatchClock serves one instant, so a replayed dispatch derives the
// byte-identical task identity its first execution recorded.
type fixedDispatchClock struct{ value time.Time }

func (c fixedDispatchClock) Now() time.Time { return c.value }

// A worker replay across a newly constructed executor — the shape of a
// process restart over the same durable dispatch record — returns the
// recorded accepted output and never executes the worker again.
func TestWorkerReplayAcrossANewProcessReturnsTheRecordedOutput(t *testing.T) {
	clock := fixedDispatchClock{time.Date(2026, 8, 20, 12, 0, 0, 0, time.UTC)}
	effects := &scheduler.MemoryEffects{}
	dispatch, err := scheduler.New(execution.DispatchIDs{}, clock, scheduler.PrerequisiteFunc(func(context.Context, scheduler.Create) error { return nil }), time.Minute, effects, effects, effects, nil)
	if err != nil {
		t.Fatal(err)
	}
	register, err := recovery.NewMemoryRegister(1)
	if err != nil {
		t.Fatal(err)
	}
	usagePipeline, err := usage.New(usage.NewMemoryStore(), execution.NewControlledUsageSink())
	if err != nil {
		t.Fatal(err)
	}
	material := staticToolMaterial{definition: tools.Definition{
		Kind:       "ToolDefinition",
		ToolID:     "anvilkit.tool.context-echo",
		Capability: "fake.execute",
		InputSchema: tools.SchemaReference{
			ComponentName: "anvilkit.tool.context-echo.arguments",
			Digest:        "sha256:" + strings.Repeat("a", 64),
		},
	}}
	buildIdentity := "sha256:" + strings.Repeat("b", 64)
	invocation := execution.ToolInvocation{
		IdempotencyKey:      "workflow-1:action-0001",
		ToolID:              "anvilkit.tool.context-echo",
		Arguments:           json.RawMessage(`{"query":"context"}`),
		WorkspaceID:         "workspace-01",
		ProjectID:           "project-01",
		RunID:               "run-01",
		RootRunID:           "run-01",
		ActorID:             "actor-01",
		ExecutionGeneration: 1,
		Traceparent:         traceparent,
	}
	firstWorker := execution.NewControlledToolExecutor()
	first, err := execution.NewScheduledToolExecutor(dispatch, register, dispatchAuthority(), material, firstWorker, usagePipeline, execution.NewMemoryToolReservations(), clock, "executor-a", buildIdentity)
	if err != nil {
		t.Fatal(err)
	}
	original, err := first.Execute(context.Background(), invocation)
	if err != nil {
		t.Fatal(err)
	}
	if firstWorker.Executions() != 1 {
		t.Fatalf("first executions = %d, want 1", firstWorker.Executions())
	}
	// A successor process holds none of the first worker's memory. Only the
	// durable dispatch record can answer, and it must.
	successorWorker := execution.NewControlledToolExecutor()
	successor, err := execution.NewScheduledToolExecutor(dispatch, register, dispatchAuthority(), material, successorWorker, usagePipeline, execution.NewMemoryToolReservations(), clock, "executor-b", buildIdentity)
	if err != nil {
		t.Fatal(err)
	}
	replayed, err := successor.Execute(context.Background(), invocation)
	if err != nil {
		t.Fatal(err)
	}
	if string(replayed.Output) != string(original.Output) {
		t.Fatalf("replayed output %s, want the recorded original %s", replayed.Output, original.Output)
	}
	if successorWorker.Executions() != 0 {
		t.Fatalf("successor executions = %d, want the worker never executed again", successorWorker.Executions())
	}
}

// Withdrawing authority over the run's exact target stops the commit like any
// whole-scope revocation: the boundary re-read observes the revocation, no
// authorization is issued, and no domain effect is submitted.
func TestTargetRevocationHaltsTheCommitBoundary(t *testing.T) {
	h := newHarness(t, [][]byte{finalPlan()})
	_, op, commit, release := approvedCommit(t, h, "approve-target-revoked")
	defer close(release)

	revoked := h.currentAuthority(h.authority(defaultHarnessOptions()))
	revoked.RevokedTargets = []string{"page.home"}
	h.authoritySource.Replace(revoked)

	result, err := h.ops.Commit(context.Background(), op, commit)
	if err != nil {
		t.Fatal(err)
	}
	if result.Halt == nil || result.Halt.Problem.Code != string(problem.CodeAuthorityStale) {
		t.Fatalf("result = %+v, want an authority halt for the revoked target", result)
	}
	if len(h.commitAuthority.Issued()) != 0 || h.domain.Commits() != 0 {
		t.Fatalf("issued=%d commits=%d, want nothing after target revocation", len(h.commitAuthority.Issued()), h.domain.Commits())
	}
}

// Revoking the accepted approval denies the commit before issuance: a revoked
// approval can never become a signed capability.
func TestApprovalRevocationDeniesTheCommitBeforeIssuance(t *testing.T) {
	h := newHarness(t, [][]byte{finalPlan()})
	_, op, commit, release := approvedCommit(t, h, "approve-approval-revoked")
	defer close(release)

	revoked := h.currentAuthority(h.authority(defaultHarnessOptions()))
	revoked.RevokedApprovals = []string{commit.RequestID}
	h.authoritySource.Replace(revoked)

	_, err := h.ops.Commit(context.Background(), op, commit)
	var details problem.Details
	if !errors.As(err, &details) || details.Code != string(problem.CodeApplyAuthorizationDenied) {
		t.Fatalf("error = %v, want %s for the revoked approval", err, problem.CodeApplyAuthorizationDenied)
	}
	if len(h.commitAuthority.Issued()) != 0 || h.domain.Commits() != 0 {
		t.Fatalf("issued=%d commits=%d, want nothing after approval revocation", len(h.commitAuthority.Issued()), h.domain.Commits())
	}
	if snapshot := h.snapshot(); snapshot.Status == runs.Completed {
		t.Fatalf("run state = %s, want the commit stopped", snapshot.Status)
	}
}
