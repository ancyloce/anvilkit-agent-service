package main

import (
	"encoding/json"
	"net/http"
	"testing"
	"time"
)

// TestCrossProcessDuplicateDeliveryChargesOnce covers idempotency: creating the
// same run twice (same idempotency key) is one run, one artifact, one charge.
// The redelivery is the control plane's own — the durable operation replays
// rather than re-executes.
func TestCrossProcessDuplicateDeliveryChargesOnce(t *testing.T) {
	top := newTopology(t, "delegate-page-specialist,compose-page")
	runPath := top.createRun("cross-dup-1", "make the hero bolder")
	runID := runIDOf(runPath)

	// A second create with the same idempotency key replays the first run.
	replayPath := top.createRunReplay("cross-dup-1", "make the hero bolder")
	if replayPath != runPath {
		t.Fatalf("the idempotent replay created a second run: %s then %s", runPath, replayPath)
	}
	etag := top.waitForStatus(runPath, "awaiting_approval")
	top.approve(runPath, etag)
	top.waitForStatus(runPath, "completed")

	// One run, one candidate, one committed artifact, one authorization — the
	// redelivery changed nothing.
	if submissions := top.count(`SELECT count(*) FROM agent_workflow.runtime_artifact_submissions WHERE run_id=$1`, runID); submissions != 1 {
		t.Fatalf("candidate submissions after duplicate delivery = %d, want 1", submissions)
	}
	if artifacts := top.count(`SELECT count(*) FROM agent_artifacts.metadata WHERE run_id=$1 AND state='committed'`, runID); artifacts != 1 {
		t.Fatalf("committed artifacts after duplicate delivery = %d, want 1", artifacts)
	}
	if authorizations := top.count(`SELECT count(*) FROM agent_control.apply_authorizations WHERE run_id=$1`, runID); authorizations != 1 {
		t.Fatalf("authorizations after duplicate delivery = %d, want 1", authorizations)
	}
	top.assertScenario(completed(runPath, 0))
}

// TestCrossProcessLostResponseRecoversWithoutDuplicateCommit covers the network
// case: the runtime accepts a task and executes it, but the response is lost in
// transit. The durable dispatch recovers — a replacement attempt is created —
// and the run still completes with exactly one artifact and no double charge.
func TestCrossProcessLostResponseRecoversWithoutDuplicateCommit(t *testing.T) {
	// The Specialist's first attempt composes the page, submits the candidate,
	// and its response is then dropped: the unit executed, the control plane
	// never learned the outcome. The replacement attempt composes again — the
	// third script step — and its idempotent submission resolves to the same
	// immutable artifact. Faulting the Specialist rather than the Manager keeps
	// the reasoning that was lost re-derivable: a dropped plan would re-plan.
	top := newTopology(t, "delegate-page-specialist,compose-page,compose-page")
	top.specialist.proxy.dropOnce()

	runPath := top.createRun("cross-lost-1", "make the hero bolder")
	runID := runIDOf(runPath)
	etag := top.waitForStatus(runPath, "awaiting_approval")
	top.approve(runPath, etag)
	top.waitForStatus(runPath, "completed")

	// Recovery created more than one attempt for the first manager turn, but
	// only one committed result per logical task, and exactly one artifact:
	// the lost response did not become a second commit or a second charge.
	if artifacts := top.count(`SELECT count(*) FROM agent_artifacts.metadata WHERE run_id=$1 AND state='committed'`, runID); artifacts != 1 {
		t.Fatalf("committed artifacts after a lost response = %d, want exactly 1", artifacts)
	}
	// The replacement Specialist attempt re-composed and re-submitted; a
	// submission is idempotent by content, so the artifact the run committed is
	// singular even though the recovery produced more than one candidate.
	// Every committed result is for a distinct logical task: a lost response
	// never produced two committed results for one task.
	if doubled := top.count(`SELECT count(*) FROM (SELECT r.task_id, count(*) c FROM agent_workflow.runtime_results r JOIN agent_workflow.runtime_tasks t ON t.workspace_id=r.workspace_id AND t.project_id=r.project_id AND t.task_id=r.task_id WHERE t.run_id=$1 GROUP BY r.task_id HAVING count(*)>1) doubled`, runID); doubled != 0 {
		t.Fatalf("%d logical tasks committed more than one result", doubled)
	}
	top.assertScenario(completed(runPath, 1))
}

// TestCrossProcessTimeoutIsBoundedAndRecovered covers the slow-unit case: a
// dispatch that never returns within the deadline is bounded by the dispatch
// timeout, and the durable recovery redispatches to a responsive unit.
func TestCrossProcessTimeoutIsBoundedAndRecovered(t *testing.T) {
	top := newTopology(t, "delegate-page-specialist,compose-page")

	// The first manager dispatch is held past the 8s dispatch deadline, then
	// released to normal so recovery's replacement attempt is served.
	release := top.manager.proxy.block()
	go func() {
		time.Sleep(10 * time.Second)
		release()
	}()

	runPath := top.createRun("cross-timeout-1", "make the hero bolder")
	runID := runIDOf(runPath)
	etag := top.waitForStatus(runPath, "awaiting_approval")
	top.approve(runPath, etag)
	top.waitForStatus(runPath, "completed")

	if artifacts := top.count(`SELECT count(*) FROM agent_artifacts.metadata WHERE run_id=$1 AND state='committed'`, runID); artifacts != 1 {
		t.Fatalf("committed artifacts after a bounded timeout = %d, want exactly 1", artifacts)
	}
	top.assertScenario(completed(runPath, 1))
}

// TestCrossProcessRuntimeUnreachableCreatesAReplacementAttempt covers the
// transport half of a runtime crash: the specialist's dispatch fails closed
// at the wire, and a replacement attempt on the same released unit finishes
// the delegation. The unanswered attempt's fence never commits. The process
// half — a unit killed mid-execution — is
// TestCrossProcessRuntimeCrashMidExecutionIsReplacedOnAFreshProcess.
func TestCrossProcessRuntimeUnreachableCreatesAReplacementAttempt(t *testing.T) {
	top := newTopology(t, "delegate-page-specialist,compose-page")

	// The specialist fails closed for the first delegation dispatch, then is
	// restored so the replacement attempt is served by the same released unit.
	top.specialist.proxy.failOnce()

	runPath := top.createRun("cross-crash-1", "make the hero bolder")
	runID := runIDOf(runPath)
	etag := top.waitForStatus(runPath, "awaiting_approval")
	top.approve(runPath, etag)
	top.waitForStatus(runPath, "completed")

	// The specialist's logical task has more than one attempt, but exactly one
	// succeeded: the crashed attempt's fence never became a commit.
	if artifacts := top.count(`SELECT count(*) FROM agent_artifacts.metadata WHERE run_id=$1 AND state='committed'`, runID); artifacts != 1 {
		t.Fatalf("committed artifacts after a runtime crash = %d, want exactly 1", artifacts)
	}
	// The crashed attempt's fence never became a commit: no logical task has
	// two committed results.
	if doubled := top.count(`SELECT count(*) FROM (SELECT r.task_id, count(*) c FROM agent_workflow.runtime_results r JOIN agent_workflow.runtime_tasks t ON t.workspace_id=r.workspace_id AND t.project_id=r.project_id AND t.task_id=r.task_id WHERE t.run_id=$1 GROUP BY r.task_id HAVING count(*)>1) doubled`, runID); doubled != 0 {
		t.Fatalf("%d logical tasks committed more than one result after a crash", doubled)
	}
	top.assertScenario(completed(runPath, 1))
}

// createRunReplay issues the create with an idempotency key that already exists
// and returns the run path it resolves to.
func (top *topology) createRunReplay(idempotencyKey, userInput string) string {
	top.t.Helper()
	body := []byte(`{"kind":"CreateAgentRunRequest","definition":{"definitionId":"` + top.service.definitionID + `","definitionDigest":"` + top.service.definitionDigest +
		`"},"operation":"page-change","target":{"targetType":"page","targetId":"page-cross-001","workspaceId":"workspace","projectId":"project"},"input":{"userInput":"` + userInput + `"}}`)
	response, payload := top.actor(http.MethodPost, "/v1/workspaces/workspace/agent-runs", idempotencyKey, "", body)
	if response.StatusCode != http.StatusOK || response.Header.Get("Idempotency-Replayed") != "true" {
		top.t.Fatalf("idempotent replay status=%d replayed=%q body=%s", response.StatusCode, response.Header.Get("Idempotency-Replayed"), payload)
	}
	if location := response.Header.Get("Location"); location != "" {
		return location
	}
	var run struct {
		RunID string `json:"runId"`
	}
	if err := json.Unmarshal(payload, &run); err != nil || run.RunID == "" {
		top.t.Fatalf("replayed run undecodable: %v %s", err, payload)
	}
	return "/v1/workspaces/workspace/agent-runs/" + run.RunID
}
