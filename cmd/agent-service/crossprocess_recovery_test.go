package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/ancyloce/anvilkit-agent-service/contracts/generated/schema"
	"github.com/ancyloce/anvilkit-agent-service/internal/dispatch"
	dispatchpg "github.com/ancyloce/anvilkit-agent-service/internal/dispatch/postgres"
	"github.com/ancyloce/anvilkit-agent-service/internal/runtimeboundary"
	"github.com/ancyloce/anvilkit-agent-service/internal/runtimes"
)

// TestCrossProcessSameTaskDeliveredTwiceExecutesOnce covers idempotency at the
// wire: the same AgentTask — same attempt, same bytes, same credential — is
// delivered to the live Specialist twice. The second delivery is answered from
// the unit's replay register without executing: no second model call, no
// second candidate, and the run charges and commits exactly once.
func TestCrossProcessSameTaskDeliveredTwiceExecutesOnce(t *testing.T) {
	top := newTopology(t, "delegate-page-specialist,compose-page")
	top.specialist.proxy.duplicateOnce()

	runPath := top.createRun("cross-redeliver-1", "make the hero bolder")
	runID := runIDOf(runPath)
	etag := top.waitForStatus(runPath, "awaiting_approval")
	top.approve(runPath, etag)
	top.waitForStatus(runPath, "completed")

	deliveries := top.specialist.proxy.duplicateDeliveries()
	if len(deliveries) != 1 {
		t.Fatalf("duplicated deliveries = %d, want 1", len(deliveries))
	}
	if second := deliveries[0]; second.status != http.StatusOK || !second.replayed || !second.identical {
		t.Fatalf("the second delivery of the same task answered status=%d replayed=%v identical=%v; want the recorded answer replayed byte for byte", second.status, second.replayed, second.identical)
	}
	// The Specialist executed once: one candidate submission, and the
	// governed model ledger settled exactly the two operations the script
	// funds — a re-execution would have needed a third.
	if submissions := top.count(`SELECT count(*) FROM agent_workflow.runtime_artifact_submissions WHERE run_id=$1`, runID); submissions != 1 {
		t.Fatalf("candidate submissions after duplicate delivery = %d, want exactly 1", submissions)
	}
	if operations := top.countWith(`SELECT count(*) FROM agent_workflow.controlled_provider_operations WHERE ledger=$1`, top.service.executorID+":controlled-model"); operations != 2 {
		t.Fatalf("governed model operations = %d, want exactly 2 (one manager plan, one specialist composition)", operations)
	}
	top.assertScenario(completed(runPath, 0))
}

// TestCrossProcessRuntimeCrashMidExecutionIsReplacedOnAFreshProcess covers the
// runtime crash the plan names: the Specialist process is killed — SIGKILL,
// no drain — while it is executing a dispatched attempt and waiting on its
// governed model call. A replacement attempt with a new number, lease epoch,
// and fence is dispatched to a fresh process of the same release; the crashed
// attempt's fence never commits and its held callback is never served.
func TestCrossProcessRuntimeCrashMidExecutionIsReplacedOnAFreshProcess(t *testing.T) {
	top := newTopology(t, "delegate-page-specialist,compose-page")
	hold := top.gate.hold(false, callbackFrom(runtimeboundary.PathModelInvocations, top.specialistRelease.audience))

	runPath := top.createRun("cross-crash-mid-1", "make the hero bolder")
	runID := runIDOf(runPath)
	// The Specialist is executing the delegation and is blocked on its
	// governed model call: mid-execution, past admission, before any answer.
	hold.awaitCaught(t, 90*time.Second)
	crashed := top.waitForUnitDispatch(runID, top.specialistRelease.unitID)
	crashedPID := top.specialist.pid

	// Every dispatch that follows waits for the replacement process, so the
	// bounded retry budget is not spent on a unit that is not there yet.
	release := top.specialist.proxy.block()
	top.specialist.kill(t)
	// The held callback's caller is gone; the gate abandons it rather than
	// forwarding a dead process's work.
	if outcome := hold.result(t, 30*time.Second); outcome.forwarded {
		t.Fatal("the crashed attempt's governed model call reached the service after the process died")
	}
	top.specialist = top.specialist.respawn(t)
	if top.specialist.pid == crashedPID {
		t.Fatal("the replacement process is the crashed process")
	}
	release()

	etag := top.waitForStatus(runPath, "awaiting_approval")
	top.approve(runPath, etag)
	top.waitForStatus(runPath, "completed")

	// The crashed attempt was superseded by a replacement with the next
	// attempt number and lease epoch, and only the replacement committed.
	attempts := top.attempts(runID)
	var old, replacement *attemptRow
	for index := range attempts {
		switch row := &attempts[index]; {
		case row.attemptID == crashed.attemptID:
			old = row
		case row.taskID == crashed.taskID && row.status == "succeeded":
			replacement = row
		}
	}
	if old == nil || old.status != "superseded" {
		t.Fatalf("the crashed attempt is %+v, want superseded", old)
	}
	if replacement == nil || replacement.number != old.number+1 || replacement.lease != old.lease+1 {
		t.Fatalf("the replacement attempt is %+v after %+v; want the next attempt number and lease epoch", replacement, old)
	}
	top.assertScenario(completed(runPath, 1))
}

// TestCrossProcessServiceCrashAfterDispatchIsRecoveredBySuccessor covers the
// Agent Service crash the plan names: the production binary, running as its
// own process, is killed — SIGKILL, no ordered shutdown, no checkpoint — after
// it has dispatched a Specialist attempt and before the answer arrives. A
// successor with the crashed executor's identity recovers the durable
// workflow, safely redispatches the turn as a replacement attempt, and the run
// completes with exactly one artifact; the manager turn that had already
// committed is replayed from its registration, not executed again.
func TestCrossProcessServiceCrashAfterDispatchIsRecoveredBySuccessor(t *testing.T) {
	top := newTopologyWithServiceProcess(t, "delegate-page-specialist,compose-page")
	// The Specialist dispatch is held in transit: the attempt has left the
	// service and is recorded as dispatched, and nothing has answered.
	release := top.specialist.proxy.block()

	runPath := top.createRun("cross-service-crash-1", "make the hero bolder")
	runID := runIDOf(runPath)
	dispatched := top.waitForUnitDispatch(runID, top.specialistRelease.unitID)
	crashedPID := top.service.process.pid
	crashedExecutor := top.service.executorID

	successor := top.restartService()
	if successor.pid == crashedPID {
		t.Fatal("the successor is the crashed process")
	}
	if top.service.executorID != crashedExecutor {
		t.Fatalf("the successor took executor identity %q, want the crashed executor's %q", top.service.executorID, crashedExecutor)
	}
	release()

	etag := top.waitForStatus(runPath, "awaiting_approval")
	top.approve(runPath, etag)
	top.waitForStatus(runPath, "completed")

	// The dispatched attempt the crashed process was waiting on never
	// committed; the successor's replacement did. The manager's first turn
	// was not executed again: its logical task has exactly one attempt.
	attempts := top.attempts(runID)
	managerAttempts := 0
	var old *attemptRow
	for index := range attempts {
		row := &attempts[index]
		if row.attemptID == dispatched.attemptID {
			old = row
		}
		if row.unitID == top.managerRelease.unitID && row.taskID == attempts[0].taskID {
			managerAttempts++
		}
	}
	if old == nil || old.status == "succeeded" {
		t.Fatalf("the attempt dispatched by the crashed process is %+v; it must not have committed", old)
	}
	if managerAttempts != 1 {
		t.Fatalf("the committed manager turn has %d attempts after recovery, want 1: a committed task is replayed, not re-executed", managerAttempts)
	}
	if generation := top.count(`SELECT execution_generation FROM agent_control.agent_runs WHERE run_id=$1`, runID); generation != 1 {
		t.Fatalf("execution generation after recovery = %d, want 1: recovery resumes the run, it does not restart it", generation)
	}
	top.assertScenario(completed(runPath, 1))
}

// TestCrossProcessLateResultOfASupersededAttemptIsEvidenceOnly covers the
// late result the plan names: an old attempt that succeeded — the Specialist
// executed it, submitted its candidate, signed its result — whose answer was
// lost, so a replacement took the task over and the run completed on it. The
// old attempt's result then arrives, three ways: re-presented by the live unit
// from its replay register, as a late callback at the served boundary, and as
// a commit attempt against the fence. Each leaves evidence only; the final
// state, the committed result, and the one artifact are unchanged.
func TestCrossProcessLateResultOfASupersededAttemptIsEvidenceOnly(t *testing.T) {
	// The lost answer replaces the attempt at once, so the lease plays no part
	// in the recovery; it is lengthened only so the old attempt's window is
	// still open when its late result is presented, whatever the machine's
	// load. Expiry has its own scenario.
	top := newTopologyWithLease(t, "delegate-page-specialist,compose-page,compose-page", time.Minute)
	top.specialist.proxy.dropOnce()

	runPath := top.createRun("cross-late-1", "make the hero bolder")
	runID := runIDOf(runPath)
	etag := top.waitForStatus(runPath, "awaiting_approval")
	top.approve(runPath, etag)
	top.waitForStatus(runPath, "completed")

	superseded := top.attemptsWhere(runID, top.specialistRelease.unitID, "superseded")
	if len(superseded) != 1 {
		t.Fatalf("superseded specialist attempts = %d, want exactly 1", len(superseded))
	}
	old := superseded[0]
	committedBefore := top.committedResultAttempt(runID, old.taskID)
	if committedBefore == old.attemptID {
		t.Fatal("the committed result belongs to the superseded attempt")
	}

	// 1. The unit still holds the old attempt's successful result and replays
	// it when the same task is presented again — an old attempt that
	// succeeded, produced after its replacement is the committed one. The task
	// presented is the one that was dispatched, byte for byte: the durable
	// offer keeps the fence's digest rather than the token, so the retry's
	// bytes come from what the wire carried.
	task := top.dispatchedTask(top.specialist, old.attemptID)
	credential := top.credentialFor(task)
	status, header, body := top.dispatchToUnit(top.specialist, task, credential)
	if status != http.StatusOK || header.Get("Idempotency-Replayed") != "true" {
		t.Fatalf("re-presenting the superseded attempt answered %d replayed=%q; want the recorded result replayed", status, header.Get("Idempotency-Replayed"))
	}
	var late schema.AgentRuntimeResult
	if err := json.Unmarshal(body, &late); err != nil {
		t.Fatal(err)
	}
	if string(late.PhysicalAttemptId) != old.attemptID || string(late.Status.Status) != "completed" {
		t.Fatalf("the replayed result is for %s with status %s; want the superseded attempt's completed result", late.PhysicalAttemptId, late.Status.Status)
	}

	// 2. Its late callback is refused at the served boundary: the attempt is
	// no longer the current execution of its task.
	content := top.submissionContent(runID)
	if status, problem := top.boundaryCall(runtimeboundary.PathArtifacts, credential, content); status != http.StatusGone || !strings.Contains(string(problem), "no longer the current execution") {
		t.Fatalf("a superseded attempt's late submission answered %d: %s; want 410 for an attempt that is no longer current", status, problem)
	}

	// 3. Offered to the fenced commit — the same commit the runner performs,
	// over the same durable record — it is refused and recorded as evidence:
	// the task is terminal on the replacement's result, and the attempt is
	// superseded. Nothing about the task changes.
	settled := top.settleLate(runID, task, late)
	if settled.Disposition.Committed() || (settled.Disposition != dispatch.DispositionTerminal && settled.Disposition != dispatch.DispositionSuperseded) {
		t.Fatalf("the late result settled with disposition %q (%s), want terminal or superseded evidence", settled.Disposition, settled.Reason)
	}
	if committedAfter := top.committedResultAttempt(runID, old.taskID); committedAfter != committedBefore {
		t.Fatalf("the committed result moved from %s to %s after a late result", committedBefore, committedAfter)
	}
	scenario := completed(runPath, 1)
	scenario.fence.dispositions = map[string]int{string(settled.Disposition): 1}
	top.assertScenario(scenario)
}

// TestCrossProcessStaleFenceResultCannotMutateState covers the stale fence on
// the wire: a validly signed result of a superseded attempt is answered to the
// replacement attempt's dispatch. The signature verifies; the fence does not.
// The Agent Service refuses the state mutation, records the result as unbound
// evidence, and fails closed — the run does not continue on a result it
// cannot attribute to the attempt it dispatched, and nothing commits.
func TestCrossProcessStaleFenceResultCannotMutateState(t *testing.T) {
	top := newTopology(t, "delegate-page-specialist,compose-page,compose-page")
	top.specialist.proxy.dropThenReplayStale()

	runPath := top.createRun("cross-stale-1", "make the hero bolder")
	runID := runIDOf(runPath)
	if terminal := top.waitForTerminal(runPath); terminal == "completed" {
		t.Fatal("a run answered with a stale-fence result completed")
	}

	superseded := top.attemptsWhere(runID, top.specialistRelease.unitID, "superseded")
	if len(superseded) < 1 {
		t.Fatal("the stale result's attempt was never superseded")
	}
	if results := top.countWith(`SELECT count(*) FROM agent_workflow.runtime_results WHERE task_id=$1`, superseded[0].taskID); results != 0 {
		t.Fatalf("the specialist task committed %d results from a stale-fence answer, want 0", results)
	}
	if unbound := top.countWith(`SELECT count(*) FROM agent_workflow.runtime_result_evidence WHERE run_id=$1 AND disposition='unbound' AND reason='RESULT_NOT_FOR_ATTEMPT'`, runID); unbound < 1 {
		t.Fatal("the stale-fence result left no unbound evidence")
	}
	top.assertScenario(scenario{
		run: runPath, final: "failed", artifacts: 0,
		events:   []string{"run.created", "run.state-changed"},
		evidence: 1, usage: 1,
		fence: fence{tasks: 2, succeeded: 1, replaced: 1, dispositions: map[string]int{"unbound": 1}},
	})
}

// TestCrossProcessAttemptPastExpiryCannotCommit covers expiry: a dispatched
// attempt outlives its own expiresAt while executing. The dispatcher's
// deadline replaces it and the replacement completes the run; when the
// expired attempt finally calls back, admission refuses it for its closed
// window, so it can neither invoke the governed model nor commit.
func TestCrossProcessAttemptPastExpiryCannotCommit(t *testing.T) {
	top := newTopology(t, "delegate-page-specialist,compose-page")
	// The unit keeps executing after the dispatcher gives up on it, the way a
	// slow runtime does; the dispatcher's deadline is what bounds the run.
	top.specialist.proxy.detach()
	hold := top.gate.hold(false, callbackFrom(runtimeboundary.PathModelInvocations, top.specialistRelease.audience))

	runPath := top.createRun("cross-expiry-1", "make the hero bolder")
	runID := runIDOf(runPath)
	hold.awaitCaught(t, 90*time.Second)
	expiring := top.waitForUnitDispatch(runID, top.specialistRelease.unitID)

	// The held attempt passes its deadline; the replacement carries the run.
	etag := top.waitForStatus(runPath, "awaiting_approval")
	top.approve(runPath, etag)
	top.waitForStatus(runPath, "completed")
	if remaining := time.Until(expiring.expiresAt.Add(time.Second)); remaining > 0 {
		time.Sleep(remaining)
	}

	hold.Release()
	outcome := hold.result(t, 30*time.Second)
	if !outcome.forwarded || outcome.status != http.StatusGone || !strings.Contains(string(outcome.body), "admission window") {
		t.Fatalf("the expired attempt's governed model call answered forwarded=%v status=%d body=%s; want 410 for a closed admission window", outcome.forwarded, outcome.status, outcome.body)
	}
	for _, row := range top.attempts(runID) {
		if row.attemptID == expiring.attemptID && row.status == "succeeded" {
			t.Fatal("the expired attempt committed")
		}
	}
	if submissions := top.count(`SELECT count(*) FROM agent_workflow.runtime_artifact_submissions WHERE run_id=$1`, runID); submissions != 1 {
		t.Fatalf("candidate submissions = %d, want exactly 1: the expired attempt never reached its submission", submissions)
	}
	top.assertScenario(completed(runPath, 1))
}

// crossProcessClock is the wall clock for a scenario's own fenced commit.
type crossProcessClock struct{}

func (crossProcessClock) Now() time.Time { return time.Now().UTC() }

// settleLate offers one result for one attempt to the fenced commit — the
// coordinator over the durable dispatch record, exactly as the runner commits
// — and reports its disposition.
func (top *topology) settleLate(runID string, task schema.AgentTask, result schema.AgentRuntimeResult) dispatch.Result {
	t := top.t
	t.Helper()
	repository, err := dispatchpg.New(top.observe)
	if err != nil {
		t.Fatal(err)
	}
	coordinator, err := dispatch.New(dispatch.Config{Repository: repository, Tokens: dispatch.RandomTokens{}, Clock: crossProcessClock{}, Lease: 8 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	statement, err := json.Marshal(result)
	if err != nil {
		t.Fatal(err)
	}
	digest, err := runtimes.StatementDigest(result)
	if err != nil {
		t.Fatal(err)
	}
	settled, err := coordinator.Settle(top.ctx, dispatch.Settle{
		Scope: dispatch.Scope{WorkspaceID: "workspace", ProjectID: "project"},
		RunID: runID,
		Predicate: dispatch.Predicate{
			RunID:                    string(task.RunId),
			TaskID:                   string(task.TaskId),
			ExecutionGeneration:      uint64(task.ExecutionGeneration),
			PhysicalAttemptID:        string(task.PhysicalAttemptId),
			AttemptNumber:            uint64(task.AttemptNumber),
			LeaseEpoch:               uint64(task.LeaseEpoch),
			FenceToken:               task.FenceToken,
			RuntimeUnitID:            string(task.RuntimeBinding.RuntimeUnitId),
			RuntimeManifestDigest:    string(task.RuntimeBinding.RuntimeManifestDigest),
			RuntimeImageDigest:       string(task.RuntimeBinding.RuntimeImageDigest),
			InvocationProtocolDigest: string(task.RuntimeBinding.InvocationProtocolDigest),
		},
		Outcome: dispatch.Outcome{
			Status:                string(result.Status.Status),
			ReasonCode:            string(result.Status.ReasonCode),
			ResultStatementDigest: digest,
			SignatureKeyID:        string(result.Signature.KeyId),
			Statement:             statement,
			ObservedAt:            time.Now().UTC(),
		},
	})
	if err != nil {
		t.Fatalf("settle the late result: %v", err)
	}
	return settled
}

// offeredTask reads the canonical task exactly as it was dispatched for one
// attempt, from the durable offer the boundary binds callbacks against.
// dispatchedTask returns the task one attempt was dispatched with, as the
// unit's proxy saw it on the wire.
func (top *topology) dispatchedTask(unit *runtimeUnit, attemptID string) schema.AgentTask {
	top.t.Helper()
	body, known := unit.proxy.dispatchedBody(attemptID)
	if !known {
		top.t.Fatalf("no dispatch of attempt %s reached %s", attemptID, unit.release.unitID)
	}
	var task schema.AgentTask
	if err := json.Unmarshal(body, &task); err != nil {
		top.t.Fatal(err)
	}
	return task
}

func (top *topology) offeredTask(attemptID string) schema.AgentTask {
	top.t.Helper()
	var document []byte
	if err := top.observe.QueryRow(top.ctx, `SELECT task_document FROM agent_workflow.runtime_task_offers WHERE physical_attempt_id=$1`, attemptID).Scan(&document); err != nil {
		top.t.Fatalf("read the offered task: %v", err)
	}
	var task schema.AgentTask
	if err := json.Unmarshal(document, &task); err != nil {
		top.t.Fatal(err)
	}
	return task
}

// credentialFor mints the task-scoped credential the service would issue for
// one task, with the service's own key.
func (top *topology) credentialFor(task schema.AgentTask) string {
	top.t.Helper()
	credential, err := top.credentialIssuer.Issue(context.Background(), task, runtimes.Subject{WorkspaceID: "workspace", ProjectID: "project"})
	if err != nil {
		top.t.Fatal(err)
	}
	return credential.Value
}

// committedResultAttempt reports which attempt's result a logical task holds.
func (top *topology) committedResultAttempt(runID, taskID string) string {
	top.t.Helper()
	var attemptID string
	if err := top.observe.QueryRow(top.ctx, `SELECT r.physical_attempt_id `+resultsOf+` AND r.task_id=$2`, runID, taskID).Scan(&attemptID); err != nil {
		top.t.Fatalf("read the committed result of %s: %v", taskID, err)
	}
	return attemptID
}

// submissionContent reads the candidate bytes a run's Specialist submitted.
func (top *topology) submissionContent(runID string) []byte {
	top.t.Helper()
	var content []byte
	if err := top.observe.QueryRow(top.ctx, `SELECT content FROM agent_workflow.runtime_artifact_submissions WHERE run_id=$1 ORDER BY submitted_at LIMIT 1`, runID).Scan(&content); err != nil {
		top.t.Fatalf("read the submitted candidate: %v", err)
	}
	return content
}

func sha256Digest(raw []byte) string {
	sum := sha256.Sum256(raw)
	return "sha256:" + hex.EncodeToString(sum[:])
}

// dispatchToUnit presents one task to a live unit's /task endpoint directly,
// the way the dispatcher does, and returns what the unit answered.
func (top *topology) dispatchToUnit(unit *runtimeUnit, task schema.AgentTask, token string) (int, http.Header, []byte) {
	top.t.Helper()
	status, header, body, err := top.tryDispatchToUnit(unit, task, token)
	if err != nil {
		top.t.Fatal(err)
	}
	return status, header, body
}

// tryDispatchToUnit presents one task to a unit and reports what it answered,
// or the transport error a unit that is gone produces.
func (top *topology) tryDispatchToUnit(unit *runtimeUnit, task schema.AgentTask, token string) (int, http.Header, []byte, error) {
	top.t.Helper()
	body, err := json.Marshal(task)
	if err != nil {
		return 0, nil, nil, err
	}
	request, err := http.NewRequestWithContext(top.ctx, http.MethodPost, unit.address+"/task", bytes.NewReader(body))
	if err != nil {
		return 0, nil, nil, err
	}
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Accept", "application/json")
	request.Header.Set("Authorization", "Bearer "+token)
	request.Header.Set("Idempotency-Key", string(task.PhysicalAttemptId))
	request.Header.Set("X-AnvilKit-Request-Digest", sha256Digest(body))
	request.Header.Set("traceparent", top.trace)
	response, err := top.client.Do(request)
	if err != nil {
		return 0, nil, nil, err
	}
	defer func() { _ = response.Body.Close() }()
	answer, err := readAll(response)
	if err != nil {
		return 0, nil, nil, err
	}
	return response.StatusCode, response.Header, answer, nil
}

// boundaryCall presents one callback to the served runtime boundary directly,
// as a dispatched attempt would, and returns what the service answered.
func (top *topology) boundaryCall(path, token string, body []byte) (int, []byte) {
	t := top.t
	t.Helper()
	request, err := http.NewRequestWithContext(top.ctx, http.MethodPost, top.service.url+path, bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Authorization", "Bearer "+token)
	request.Header.Set("X-AnvilKit-Request-Digest", sha256Digest(body))
	request.Header.Set("traceparent", top.trace)
	response, err := top.client.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = response.Body.Close() }()
	answer, err := readAll(response)
	if err != nil {
		t.Fatal(err)
	}
	return response.StatusCode, answer
}

func readAll(response *http.Response) ([]byte, error) {
	var buffer bytes.Buffer
	if _, err := buffer.ReadFrom(response.Body); err != nil {
		return nil, err
	}
	return buffer.Bytes(), nil
}
