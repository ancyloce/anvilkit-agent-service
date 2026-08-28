package main

import (
	"encoding/json"
	"io"
	"net/http"
	"testing"
	"time"

	"github.com/ancyloce/anvilkit-agent-service/internal/canonical"
)

// TestCrossProcessInputAndApprovalWaits covers the durable waits reached through
// the cross-process path: the Manager requests input, the wait is answered over
// HTTP, the delegation runs, and the approval wait is answered — the whole
// lifecycle driven through the public API while every turn executes in a
// separate process.
func TestCrossProcessInputAndApprovalWaits(t *testing.T) {
	top := newTopology(t, "plan-need-input,delegate-page-specialist,compose-page")
	runPath := top.createRun("cross-wait-1", "make the hero bolder")
	runID := runIDOf(runPath)

	etag := top.waitForStatus(runPath, "awaiting_input")
	top.answerInput(runPath, etag, "the hero section")
	etag = top.waitForStatus(runPath, "awaiting_approval")
	top.approve(runPath, etag)
	top.waitForStatus(runPath, "completed")

	if artifacts := top.count(`SELECT count(*) FROM agent_artifacts.metadata WHERE run_id=$1 AND state='committed'`, runID); artifacts != 1 {
		t.Fatalf("committed artifacts after the wait lifecycle = %d, want 1", artifacts)
	}
	// The public stream carried both the input request and the approval
	// request; the run has one more committed task than the plain path, the
	// turn that asked for input.
	waited := completed(runPath, 0)
	waited.events = append(waited.events, "run.input-requested")
	waited.fence.tasks, waited.fence.succeeded = 4, 4
	top.assertScenario(waited)
}

// TestCrossProcessCancellationPreventsLaterCommit covers cancellation: a run
// cancelled while a runtime turn is in flight revokes the lease, and a result
// that arrives afterwards cannot commit. The run settles cancelled with no
// artifact.
func TestCrossProcessCancellationPreventsLaterCommit(t *testing.T) {
	top := newTopology(t, "delegate-page-specialist,compose-page")

	// Hold the first manager dispatch so the run is firmly in flight when it
	// is cancelled; then release it. The result that comes back after
	// cancellation cannot commit against a revoked lease.
	release := top.manager.proxy.block()
	runPath := top.createRun("cross-cancel-1", "make the hero bolder")
	runID := runIDOf(runPath)
	top.waitForDispatch(runID)
	// The cancel operation carries an empty body: it is a state transition, not
	// a document. It is bound to the run's current version with If-Match.
	_, etag, _ := top.currentRun(runPath)
	response, payload := top.cancel(runPath, etag)
	if response.StatusCode != http.StatusOK && response.StatusCode != http.StatusAccepted {
		t.Fatalf("cancel status=%d body=%s", response.StatusCode, payload)
	}
	release()

	// The run settles cancelled. A late result against the revoked lease can
	// only ever record evidence, never a commit.
	if terminal := top.waitForTerminal(runPath); terminal != "cancelled" {
		t.Fatalf("a cancelled run settled %q, want cancelled", terminal)
	}
	// A late result against the revoked lease committed nothing: the
	// dispatched attempt ended canceled, never succeeded.
	if artifacts := top.count(`SELECT count(*) FROM agent_artifacts.metadata WHERE run_id=$1 AND state='committed'`, runID); artifacts != 0 {
		t.Fatalf("committed artifacts after cancellation = %d, want 0", artifacts)
	}
	top.assertScenario(scenario{
		run: runPath, final: "cancelled", artifacts: 0,
		events: []string{"run.created", "run.state-changed"},
		fence:  fence{tasks: 1, replaced: 1},
	})
}

// TestCrossProcessBudgetExhaustionBlocksExecution covers budget: a run whose
// pinned budget funds fewer model calls than the delegation needs is halted
// before it can commit an artifact, and the usage it did consume is recorded.
func TestCrossProcessBudgetExhaustionBlocksExecution(t *testing.T) {
	// One model call funded; the happy path needs two (manager plan, specialist
	// compose). The second call is refused by the allowance, halting the run.
	top := newTopologyWithBudget(t, "delegate-page-specialist,compose-page", 1)
	runPath := top.createRun("cross-budget-1", "make the hero bolder")
	runID := runIDOf(runPath)

	terminal := top.waitForTerminal(runPath)
	if terminal == "completed" {
		t.Fatal("a run whose budget funds one call completed a two-call delegation")
	}
	if artifacts := top.count(`SELECT count(*) FROM agent_artifacts.metadata WHERE run_id=$1 AND state='committed'`, runID); artifacts != 0 {
		t.Fatalf("committed artifacts after budget exhaustion = %d, want 0", artifacts)
	}
	// The consumed usage — the one funded call — is still recorded: an
	// exhausted run does not get its spend forgiven.
	if observations := top.count(`SELECT count(*) FROM agent_control.budget_observations WHERE run_id=$1`, runID); observations < 1 {
		t.Fatalf("budget observations after exhaustion = %d, want the consumed usage recorded", observations)
	}
	top.assertScenario(scenario{
		run: runPath, final: terminal, artifacts: 0,
		events: []string{"run.created", "run.state-changed"},
		usage:  1,
		fence:  fence{tasks: 1, succeeded: 1},
	})
}

// TestCrossProcessRunPinsAreImmutable covers the pin half of rollout and
// rollback: once a run is created it is pinned to the runtime release it was
// admitted against — unit, manifest, image, and protocol — and that binding is
// immutable for the life of the run. A registry change (rollout, rollback,
// revoke, disable) changes selection for new runs only; a run already made
// keeps executing on the release it started with, which is what its immutable
// pin guarantees.
func TestCrossProcessRunPinsAreImmutable(t *testing.T) {
	top := newTopology(t, "delegate-page-specialist,compose-page")
	runPath := top.createRun("cross-pins-1", "make the hero bolder")

	before := top.runtimeBinding(runPath)
	if before.RuntimeUnitID == "" || before.RuntimeManifestDigest == "" || before.RuntimeImageDigest == "" || before.InvocationProtocolDigest == "" {
		t.Fatalf("the run was created without a complete runtime pin: %+v", before)
	}
	// The pin matches the released manager the registry selected and verified.
	managerRelease := loadReleaseRecord(t, "runtime.platform.page-change-manager", "release.platform.page-change-manager.json")
	if before.RuntimeManifestDigest != managerRelease.documentDigest {
		t.Fatalf("the run pins manifest %s, but the released manager is %s", before.RuntimeManifestDigest, managerRelease.documentDigest)
	}

	etag := top.waitForStatus(runPath, "awaiting_approval")
	top.approve(runPath, etag)
	top.waitForStatus(runPath, "completed")

	// The pin is unchanged across the run's whole cross-process execution.
	after := top.runtimeBinding(runPath)
	if after != before {
		t.Fatalf("the run's runtime pin changed during execution: %+v then %+v", before, after)
	}
	top.assertScenario(completed(runPath, 0))
}

// waitForDispatch waits until a physical attempt has been dispatched for the run.
func (top *topology) waitForDispatch(runID string) {
	top.t.Helper()
	deadline := time.Now().Add(30 * time.Second)
	for time.Now().Before(deadline) {
		if attempts := top.count(`SELECT count(*) FROM agent_workflow.runtime_attempts a JOIN agent_workflow.runtime_tasks t ON t.workspace_id=a.workspace_id AND t.project_id=a.project_id AND t.task_id=a.task_id WHERE t.run_id=$1 AND a.dispatch_status IN ('running','accepted','succeeded')`, runID); attempts >= 1 {
			return
		}
		time.Sleep(200 * time.Millisecond)
	}
	top.t.Fatalf("no attempt was dispatched for run %s in time", runID)
}

// runtimeBindingView is the run's pinned runtime release, read from the public
// run representation.
type runtimeBindingView struct {
	RuntimeUnitID            string `json:"runtimeUnitId"`
	RuntimeManifestDigest    string `json:"runtimeManifestDigest"`
	RuntimeImageDigest       string `json:"runtimeImageDigest"`
	InvocationProtocolDigest string `json:"invocationProtocolDigest"`
	RuntimeAudience          string `json:"runtimeAudience"`
}

// runtimeBinding reads the run's pinned runtime binding over the public API.
func (top *topology) runtimeBinding(runPath string) runtimeBindingView {
	top.t.Helper()
	response, payload := top.actor(http.MethodGet, runPath, "", "", nil)
	if response.StatusCode != http.StatusOK {
		top.t.Fatalf("get run status=%d body=%s", response.StatusCode, payload)
	}
	var run struct {
		RuntimeBinding runtimeBindingView `json:"runtimeBinding"`
	}
	if err := json.Unmarshal(payload, &run); err != nil {
		top.t.Fatal(err)
	}
	return run.RuntimeBinding
}

// cancel posts the empty-bodied cancel control for the run.
func (top *topology) cancel(runPath, etag string) (*http.Response, []byte) {
	top.t.Helper()
	digest, err := canonical.Digest([]byte("{}"))
	if err != nil {
		top.t.Fatal(err)
	}
	request, err := http.NewRequestWithContext(top.ctx, http.MethodPost, top.service.url+runPath+"/cancel", nil)
	if err != nil {
		top.t.Fatal(err)
	}
	request.Header.Set("Authorization", "Bearer "+top.bearers.actor)
	request.Header.Set("traceparent", top.trace)
	request.Header.Set("Idempotency-Key", "cancel-"+runIDOf(runPath))
	request.Header.Set("If-Match", etag)
	request.Header.Set("X-AnvilKit-Request-Digest", digest)
	response, err := top.client.Do(request)
	if err != nil {
		top.t.Fatal(err)
	}
	payload, err := io.ReadAll(response.Body)
	if err != nil {
		top.t.Fatal(err)
	}
	if err := response.Body.Close(); err != nil {
		top.t.Fatal(err)
	}
	return response, payload
}
