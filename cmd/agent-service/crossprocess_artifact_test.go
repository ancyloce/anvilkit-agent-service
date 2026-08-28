package main

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/ancyloce/anvilkit-agent-service/contracts/generated/schema"
	"github.com/ancyloce/anvilkit-agent-service/internal/canonical"
	"github.com/ancyloce/anvilkit-agent-service/internal/runtimeboundary"
)

// TestCrossProcessArtifactSubmissionIsImmutableAtTheLiveBoundary covers the
// artifact rows of the matrix at the served boundary, under a real dispatched
// attempt: the Specialist's own submission is held on its way back, and while
// the attempt is still current the same result is submitted again — one
// immutable artifact reference — and a different document is submitted under
// the same attempt — a conflict, never a replacement. The run then completes
// with exactly one committed artifact, after which the settled attempt can no
// longer submit at all.
func TestCrossProcessArtifactSubmissionIsImmutableAtTheLiveBoundary(t *testing.T) {
	// The held attempt must still be inside its window while the boundary is
	// probed on its behalf; the lease is lengthened so that is true whatever
	// the machine's load.
	top := newTopologyWithLease(t, "delegate-page-specialist,compose-page", time.Minute)
	hold := top.gate.hold(true, callbackFrom(runtimeboundary.PathArtifacts, top.specialistRelease.audience))

	runPath := top.createRun("cross-artifact-1", "make the hero bolder")
	runID := runIDOf(runPath)
	// The service has recorded the Specialist's candidate; the Specialist has
	// not yet heard so, and its attempt is still the current execution.
	hold.awaitCaught(t, 90*time.Second)
	current := top.waitForUnitDispatch(runID, top.specialistRelease.unitID)
	task := top.offeredTask(current.attemptID)
	credential := top.credentialFor(task)
	content := top.submissionContent(runID)

	// The same result submitted repeatedly is one immutable artifact reference.
	var recorded, replayed schema.AgentArtifact
	if err := json.Unmarshal(hold.outcomeBody(t), &recorded); err != nil {
		t.Fatalf("the recorded submission is not a canonical artifact: %v", err)
	}
	status, body := top.boundaryCall(runtimeboundary.PathArtifacts, credential, content)
	if status != http.StatusOK {
		t.Fatalf("re-submitting the same candidate answered %d: %s; want the recorded artifact replayed", status, body)
	}
	if err := json.Unmarshal(body, &replayed); err != nil {
		t.Fatal(err)
	}
	if replayed.ArtifactId != recorded.ArtifactId || replayed.Digest != recorded.Digest || string(replayed.Digest) != sha256Digest(content) {
		t.Fatalf("the repeated submission resolved to %s/%s, want the immutable %s/%s", replayed.ArtifactId, replayed.Digest, recorded.ArtifactId, recorded.Digest)
	}

	// A different document under the same attempt identity is a conflict.
	different := alteredCandidate(t, content)
	if status, problem := top.boundaryCall(runtimeboundary.PathArtifacts, credential, different); status != http.StatusConflict || !strings.Contains(string(problem), "IDEMPOTENCY_KEY_REUSED") {
		t.Fatalf("a different document under the same attempt answered %d: %s; want 409 IDEMPOTENCY_KEY_REUSED", status, problem)
	}

	hold.Release()
	etag := top.waitForStatus(runPath, "awaiting_approval")
	top.approve(runPath, etag)
	top.waitForStatus(runPath, "completed")

	// The conflict recorded nothing, and the settled attempt is no longer an
	// execution that can submit.
	if submissions := top.count(`SELECT count(*) FROM agent_workflow.runtime_artifact_submissions WHERE run_id=$1`, runID); submissions != 1 {
		t.Fatalf("candidate submissions = %d, want exactly 1", submissions)
	}
	if status, problem := top.boundaryCall(runtimeboundary.PathArtifacts, credential, content); status != http.StatusGone {
		t.Fatalf("a settled attempt's submission answered %d: %s; want 410", status, problem)
	}
	if committed := top.countWith(`SELECT count(*) FROM agent_artifacts.metadata WHERE run_id=$1 AND state='committed' AND digest=$2`, runID, string(recorded.Digest)); committed != 1 {
		t.Fatalf("the committed artifact is not the one immutable submission %s", recorded.Digest)
	}
	top.assertScenario(completed(runPath, 0))
}

// outcomeBody returns the body the service answered a held-after callback
// with, available as soon as the hold is caught.
func (h *gateHold) outcomeBody(t *testing.T) []byte {
	t.Helper()
	if answer := h.answer.Load(); answer != nil {
		return answer.body
	}
	outcome := h.result(t, 30*time.Second)
	if !outcome.forwarded {
		t.Fatal("the held callback never reached the service")
	}
	return outcome.body
}

// alteredCandidate produces a canonical candidate that differs from the given
// one in content while remaining contract-valid.
func alteredCandidate(t *testing.T, content []byte) []byte {
	t.Helper()
	var candidate map[string]json.RawMessage
	if err := json.Unmarshal(content, &candidate); err != nil {
		t.Fatal(err)
	}
	var generation map[string]json.RawMessage
	if err := json.Unmarshal(candidate["generation"], &generation); err != nil {
		t.Fatal(err)
	}
	summary, err := json.Marshal("a different candidate under the same attempt")
	if err != nil {
		t.Fatal(err)
	}
	generation["summary"] = summary
	regenerated, err := json.Marshal(generation)
	if err != nil {
		t.Fatal(err)
	}
	candidate["generation"] = regenerated
	altered, err := json.Marshal(candidate)
	if err != nil {
		t.Fatal(err)
	}
	canonicalBytes, err := canonical.Bytes(altered)
	if err != nil {
		t.Fatal(err)
	}
	if string(canonicalBytes) == string(content) {
		t.Fatal("the altered candidate is byte-identical to the original")
	}
	return canonicalBytes
}
