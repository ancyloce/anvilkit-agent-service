package execution_test

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/ancyloce/anvilkit-agent-service/internal/execution"
	"github.com/ancyloce/anvilkit-agent-service/internal/interrupts"
	"github.com/ancyloce/anvilkit-agent-service/internal/problem"
	"github.com/ancyloce/anvilkit-agent-service/internal/runs"
	"github.com/ancyloce/anvilkit-agent-service/internal/tools"
	"github.com/ancyloce/anvilkit-agent-service/internal/workflow"
)

// Authority is re-read inside every durable operation that discloses context
// to a model or causes an external effect. Revoking it at each of those
// boundaries in turn must stop the run there — never let it continue, and
// never let the effect that boundary guards happen.
func TestAuthorityRevocationStopsExecutionAtEveryGuardedBoundary(t *testing.T) {
	cases := []struct {
		name      string
		operation string
		script    [][]byte
		step      string
		assert    func(*testing.T, *harness)
	}{
		{
			name:      "manager turn",
			operation: "artifact-validation",
			script:    [][]byte{finalPlan()},
			step:      "turn-0000",
			assert: func(t *testing.T, h *harness) {
				if len(h.adapter.Requests()) != 0 {
					t.Fatal("a revoked run must not disclose context to a provider")
				}
			},
		},
		{
			name:      "tool action",
			operation: "artifact-validation",
			script:    [][]byte{toolPlan(), finalPlan()},
			step:      "action-0000",
			assert: func(t *testing.T, h *harness) {
				if h.tool.Executions() != 0 {
					t.Fatalf("tool executions = %d, want none after revocation", h.tool.Executions())
				}
			},
		},
		{
			name:      "delegation",
			operation: "artifact-validation",
			script:    [][]byte{delegatePlan(), finalPlan()},
			step:      "delegate-open-0000",
			assert: func(t *testing.T, h *harness) {
				if h.ops.callsFor(":delegate-turn-0000-0000") != 0 {
					t.Fatal("a revoked delegation must not open a specialist turn")
				}
			},
		},
		{
			name:      "commit",
			operation: "page-change",
			script:    [][]byte{finalPlan()},
			step:      "commit-0000",
			assert: func(t *testing.T, h *harness) {
				if len(h.commitAuthority.Issued()) != 0 {
					t.Fatalf("issued authorizations = %d, want none after revocation", len(h.commitAuthority.Issued()))
				}
				if h.domain.Commits() != 0 {
					t.Fatalf("domain commits = %d, want none after revocation", h.domain.Commits())
				}
			},
		},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			h := newHarness(t, testCase.script)
			input := h.seedRun(testCase.operation)
			h.ops.before(testCase.step, h.authoritySource.Revoke)
			outcome := runToTerminal(t, h, input, testCase.operation)
			assertAuthorityStale(t, outcome)
			testCase.assert(t, h)
		})
	}
}

// Retry is a fresh authorization decision. Authority revoked while a run is
// waiting for a revision must stop it at the retry boundary.
func TestAuthorityRevocationStopsExecutionAtRetry(t *testing.T) {
	h := newHarness(t, [][]byte{finalPlan(), finalPlan()})
	input := h.seedRun("page-change")
	if err := h.engine.StartRun(context.Background(), input); err != nil {
		t.Fatal(err)
	}
	request := h.openApprovalRequest()
	h.ops.before("revise-0000", h.authoritySource.Revoke)
	if _, err := h.decideApproval(request, interrupts.DecisionReject, "reject-revoked"); err != nil {
		t.Fatal(err)
	}
	assertRecordedAuthorityStale(t, h)
	if h.ops.callsFor(":turn-0001") != 0 {
		t.Fatal("a revoked retry must not start another turn")
	}
}

// Governance material that moves out from under a running run is stale
// authority, not a smaller change: preparation refuses, and the run stops.
func TestPreparationRefusesWhenPinnedMaterialIsNoLongerCurrent(t *testing.T) {
	cases := map[string]func(*harness, *runs.Authority){
		"definition":   func(h *harness, current *runs.Authority) { current.Definition = otherDefinitionReference() },
		"contract bom": func(h *harness, current *runs.Authority) { current.ContractBOM = otherContractBOM() },
		"policy":       func(h *harness, current *runs.Authority) { current.Policy = otherPolicy() },
		"budget":       func(h *harness, current *runs.Authority) { current.Budget = otherBudget() },
	}
	for name, diverge := range cases {
		t.Run(name, func(t *testing.T) {
			h := newHarness(t, [][]byte{finalPlan()})
			input := h.seedRun("artifact-validation")
			current := h.authority(defaultHarnessOptions())
			diverge(h, &current)
			h.authoritySource.Replace(h.currentAuthority(current))
			outcome, err := h.engine.ExecuteRun(context.Background(), input)
			if err != nil {
				t.Fatal(err)
			}
			if outcome.Terminal != workflow.TerminalRefused || outcome.Problem == nil || outcome.Problem.Code != string(problem.CodeAuthorityStale) {
				t.Fatalf("outcome = %+v", outcome)
			}
			if len(h.adapter.Requests()) != 0 {
				t.Fatal("a run refused at preparation must not disclose context to a provider")
			}
		})
	}
}

// A retry revalidates the same four documents preparation did, so a
// definition or budget that changed while the run waited for review stops it
// instead of silently executing under the new material.
func TestRetryRevalidatesTheDefinitionAndTheBudget(t *testing.T) {
	cases := map[string]func(*runs.Authority){
		"definition changed": func(current *runs.Authority) { current.Definition = otherDefinitionReference() },
		"budget changed":     func(current *runs.Authority) { current.Budget = otherBudget() },
	}
	for name, diverge := range cases {
		t.Run(name, func(t *testing.T) {
			h := newHarness(t, [][]byte{finalPlan(), finalPlan()})
			input := h.seedRun("page-change")
			if err := h.engine.StartRun(context.Background(), input); err != nil {
				t.Fatal(err)
			}
			request := h.openApprovalRequest()
			pinned := h.authority(defaultHarnessOptions())
			h.ops.before("revise-0000", func() {
				current := pinned
				diverge(&current)
				h.authoritySource.Replace(h.currentAuthority(current))
			})
			if _, err := h.decideApproval(request, interrupts.DecisionReject, "reject-changed"); err != nil {
				t.Fatal(err)
			}
			assertRecordedAuthorityStale(t, h)
			if h.domain.Commits() != 0 {
				t.Fatal("a stopped retry must never reach the domain owner")
			}
		})
	}
}

// The approved action and the artifact being committed must be the same
// object. A mismatch stops the commit before an authorization is issued, so
// neither the issuer nor the authoritative domain owner is called.
func TestCommitDigestMismatchPreventsIssuerAndDomainCalls(t *testing.T) {
	h := newHarness(t, [][]byte{finalPlan()})
	input := h.seedRun("page-change")
	// The workflow is held on entry to the commit boundary, before it can
	// issue anything, so the mismatched commit is the only one that runs
	// while the assertions are made.
	release, entered := h.ops.hold("commit-0000")
	defer close(release)
	if err := h.engine.StartRun(context.Background(), input); err != nil {
		t.Fatal(err)
	}
	request := h.openApprovalRequest()
	if _, err := h.decideApproval(request, interrupts.DecisionApprove, "approve-mismatch"); err != nil {
		t.Fatal(err)
	}
	<-entered
	forged := "sha256:" + strings.Repeat("b", 64)
	_, err := h.ops.Commit(context.Background(), opID(input, "commit-0000"), workflow.CommitInput{
		Run: input, Turn: 0, RequestID: string(request.ID), ArtifactDigest: forged, Version: h.snapshot().Version,
	})
	var details problem.Details
	if err == nil || !errors.As(err, &details) || details.Code != string(problem.CodeApplyAuthorizationDenied) {
		t.Fatalf("commit under a mismatched action digest = %v", err)
	}
	if len(h.commitAuthority.Issued()) != 0 {
		t.Fatalf("issued authorizations = %d, want none", len(h.commitAuthority.Issued()))
	}
	if h.domain.Commits() != 0 {
		t.Fatalf("domain commits = %d, want none", h.domain.Commits())
	}
	if len(h.artifacts.Queries()) != 0 {
		t.Fatal("an unbound action digest must stop the commit before artifact eligibility is asked")
	}
}

// An artifact that stopped being eligible between approval and commit — it
// was quarantined, deleted, or expired — stops the commit before any
// authorization is issued.
func TestArtifactEligibilityFailureStopsTheCommit(t *testing.T) {
	h := newHarness(t, [][]byte{finalPlan()})
	input := h.seedRun("page-change")
	if err := h.engine.StartRun(context.Background(), input); err != nil {
		t.Fatal(err)
	}
	request := h.openApprovalRequest()
	// The approved action digest is the candidate artifact digest.
	h.artifacts.Withdraw(request.ActionDigest, "quarantined by the artifact owner")
	if _, err := h.decideApproval(request, interrupts.DecisionApprove, "approve-withdrawn"); err != nil {
		t.Fatal(err)
	}
	outcome, err := h.engine.ExecuteRun(context.Background(), input)
	if err != nil {
		t.Fatal(err)
	}
	if outcome.Terminal != workflow.TerminalFailed || outcome.Problem == nil || outcome.Problem.Code != string(problem.CodeApplyAuthorizationDenied) {
		t.Fatalf("outcome = %+v", outcome)
	}
	if len(h.commitAuthority.Issued()) != 0 {
		t.Fatalf("issued authorizations = %d, want none for an ineligible artifact", len(h.commitAuthority.Issued()))
	}
	if h.domain.Commits() != 0 {
		t.Fatalf("domain commits = %d, want none for an ineligible artifact", h.domain.Commits())
	}
	if len(h.artifacts.Queries()) == 0 {
		t.Fatal("eligibility must be asked of the artifact owner, not inferred")
	}
}

// The commit gate runs in one order, and an eligible artifact reaches the
// issuer before the domain owner.
func TestCommitChecksRunInOrderBeforeTheDomainEffect(t *testing.T) {
	h := newHarness(t, [][]byte{finalPlan()})
	input := h.seedRun("page-change")
	if err := h.engine.StartRun(context.Background(), input); err != nil {
		t.Fatal(err)
	}
	request := h.openApprovalRequest()
	if _, err := h.decideApproval(request, interrupts.DecisionApprove, "approve-ordered"); err != nil {
		t.Fatal(err)
	}
	outcome, err := h.engine.ExecuteRun(context.Background(), input)
	if err != nil || outcome.Terminal != workflow.TerminalCompleted {
		t.Fatalf("outcome = %+v err = %v", outcome, err)
	}
	if len(h.artifacts.Queries()) != 1 || h.artifacts.Queries()[0].ArtifactDigest != request.ActionDigest {
		t.Fatalf("artifact eligibility queries = %+v", h.artifacts.Queries())
	}
	if len(h.commitAuthority.Issued()) != 1 {
		t.Fatalf("issued authorizations = %d, want exactly one", len(h.commitAuthority.Issued()))
	}
	issued := h.commitAuthority.Issued()[0]
	if issued.ArtifactDigest != request.ActionDigest || issued.ActionDigest != request.ActionDigest {
		t.Fatalf("authorization is not bound to the approved action: %+v", issued)
	}
	if h.domain.Commits() != 1 {
		t.Fatalf("domain commits = %d, want exactly one", h.domain.Commits())
	}
}

// A run pinned to a definition the approved registry does not carry must fail
// closed instead of resolving something else.
func TestUnapprovedDefinitionReferenceFailsTheRunClosed(t *testing.T) {
	h := newHarness(t, [][]byte{finalPlan()})
	material := h.authority(defaultHarnessOptions())
	material.Definition = otherDefinitionReference()
	input := h.seedSnapshot("artifact-validation", material)
	outcome, err := h.engine.ExecuteRun(context.Background(), input)
	if err != nil {
		t.Fatal(err)
	}
	if outcome.Terminal != workflow.TerminalRefused || outcome.Problem == nil || outcome.Problem.Code != string(problem.CodeContractInvalid) {
		t.Fatalf("outcome = %+v", outcome)
	}
	if len(h.adapter.Requests()) != 0 {
		t.Fatal("an unapproved definition must not reach a provider")
	}
}

// A definition whose frozen digest does not match the approved registry entry
// must fail closed even though its identity is known.
func TestTamperedDefinitionDigestFailsTheRunClosed(t *testing.T) {
	h := newHarness(t, [][]byte{finalPlan()})
	material := h.authority(defaultHarnessOptions())
	material.Definition = json.RawMessage(`{"definitionId":"` + h.manager.DefinitionID + `","definitionDigest":"sha256:` + strings.Repeat("c", 64) + `"}`)
	input := h.seedSnapshot("artifact-validation", material)
	outcome, err := h.engine.ExecuteRun(context.Background(), input)
	if err != nil {
		t.Fatal(err)
	}
	if outcome.Terminal != workflow.TerminalRefused || outcome.Problem == nil || outcome.Problem.Code != string(problem.CodeContractInvalid) {
		t.Fatalf("outcome = %+v", outcome)
	}
}

// The Tool material the process is running must be the material the pinned
// definition references. Divergence fails the run closed rather than letting
// a definition execute against a different tool schema.
func TestRunningToolMaterialMustMatchTheFrozenDefinition(t *testing.T) {
	h := newHarness(t, [][]byte{finalPlan()}, func(options *harnessOptions) {
		options.toolMaterial = divergingToolMaterial{}
	})
	input := h.seedRun("artifact-validation")
	outcome, err := h.engine.ExecuteRun(context.Background(), input)
	if err != nil {
		t.Fatal(err)
	}
	if outcome.Terminal != workflow.TerminalRefused || outcome.Problem == nil || outcome.Problem.Code != string(problem.CodeContractInvalid) {
		t.Fatalf("outcome = %+v", outcome)
	}
	if len(h.adapter.Requests()) != 0 {
		t.Fatal("a definition running against unapproved tool material must not reach a provider")
	}
}

// divergingToolMaterial reports a tool schema digest that is not the one the
// definition froze.
type divergingToolMaterial struct{}

func (divergingToolMaterial) ComponentDigest(string) (string, bool) {
	return "sha256:" + strings.Repeat("d", 64), true
}

func (divergingToolMaterial) ToolDefinition(string) (tools.Definition, bool) {
	return tools.Definition{}, false
}

var _ execution.ToolMaterial = divergingToolMaterial{}

// runToTerminal drives a run to its terminal outcome, answering the approval
// a governed-effect run opens on the way.
func runToTerminal(t *testing.T, h *harness, input workflow.RunInput, operation string) workflow.RunOutcome {
	t.Helper()
	if operation != "page-change" {
		outcome, err := h.engine.ExecuteRun(context.Background(), input)
		if err != nil {
			t.Fatal(err)
		}
		return outcome
	}
	if err := h.engine.StartRun(context.Background(), input); err != nil {
		t.Fatal(err)
	}
	request := h.openApprovalRequest()
	if _, err := h.decideApproval(request, interrupts.DecisionApprove, "approve-boundary"); err != nil {
		t.Fatal(err)
	}
	outcome, err := h.engine.ExecuteRun(context.Background(), input)
	if err != nil {
		t.Fatal(err)
	}
	return outcome
}

// assertRecordedAuthorityStale reads the authoritative aggregate, which is
// where a run stopped by a background execution records why it stopped.
func assertRecordedAuthorityStale(t *testing.T, h *harness) {
	t.Helper()
	snapshot := h.waitForState(runs.Failed)
	if snapshot.Problem == nil || snapshot.Problem.Code != string(problem.CodeAuthorityStale) {
		t.Fatalf("recorded failure = %+v", snapshot.Problem)
	}
}

func assertAuthorityStale(t *testing.T, outcome workflow.RunOutcome) {
	t.Helper()
	if outcome.Terminal != workflow.TerminalFailed && outcome.Terminal != workflow.TerminalRefused {
		t.Fatalf("stale authority must stop the run, got %+v", outcome)
	}
	if outcome.Problem == nil || outcome.Problem.Code != string(problem.CodeAuthorityStale) {
		t.Fatalf("stale authority must be reported as such, got %+v", outcome.Problem)
	}
}

func otherDefinitionReference() json.RawMessage {
	return json.RawMessage(`{"definitionId":"definition.platform.unapproved","definitionDigest":"sha256:` + strings.Repeat("e", 64) + `"}`)
}

func otherContractBOM() json.RawMessage {
	other := "sha256:" + strings.Repeat("f", 64)
	return json.RawMessage(`{"repository":"anvilkit/contracts","bomDigest":"` + other + `","ociManifestDigest":"` + other + `","evidenceManifestDigest":"` + other + `"}`)
}

func otherPolicy() json.RawMessage {
	return json.RawMessage(`{"policyId":"policy.run.rotated","version":"v2","digest":"sha256:` + strings.Repeat("a", 64) + `"}`)
}

// otherBudget is a complete, valid AgentBudget that is not the one the run
// pinned, so a budget change is distinguishable from a malformed budget.
func otherBudget() json.RawMessage {
	rotated := defaultHarnessBudget()
	rotated.modelCalls = 7
	return budgetDocument(rotated)
}
