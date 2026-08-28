package runtimes

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ancyloce/anvilkit-agent-service/contracts/generated/schema"
	"github.com/ancyloce/anvilkit-agent-service/internal/agent"
	"github.com/ancyloce/anvilkit-agent-service/internal/eligibility"
)

// The doubles answer with complete canonical documents: the generated bindings
// refuse a partial one, which is exactly what they are for, so a test double
// that could not be decoded would be testing nothing.
const canonicalRuntimeResult = `{
 "kind": "AgentRuntimeResult",
 "taskId": "task.0001",
 "runId": "run.synthetic.001",
 "rootRunId": "run.synthetic.001",
 "physicalAttemptId": "attempt.0002",
 "attemptNumber": 1,
 "executionGeneration": 0,
 "leaseEpoch": 0,
 "fenceToken": "fence.synthetic.0001",
 "selected": {
  "runtimeUnitId": "agent.synthetic.001",
  "definitionDigest": "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
  "runtimeManifestDigest": "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
  "invocationProtocolDigest": "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
  "imageDigest": "sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd"
 },
 "status": {
  "status": "completed",
  "reasonCode": "RUNTIME_COMPLETED"
 },
 "turnDecision": {
  "decision": "continue",
  "payload": {},
  "artifactOutputs": []
 },
 "usage": {
  "modelCalls": 0,
  "toolCalls": 0,
  "inputTokens": 0,
  "outputTokens": 0,
  "durationMilliseconds": 0,
  "cost": {
   "amount": "0",
   "currency": "USD"
  }
 },
 "diagnostics": [],
 "signature": {
  "algorithm": "dsse-ed25519-v1",
  "keyId": "urn:anvilkit:key:agent-runtime:synthetic",
  "statementDigest": "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
  "signature": "ssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssss",
  "provenanceReference": "sha256:eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"
 },
 "traceContext": {
  "traceparent": "00-0123456789abcdef0123456789abcdef-0123456789abcdef-01"
 }
}`

const canonicalRuntimeManifest = `{
 "kind": "AgentRuntimeManifest",
 "runtimeUnitId": "runtime.platform.page-change-manager",
 "role": "manager",
 "definition": {
  "definitionId": "definition.synthetic.001",
  "definitionDigest": "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
 },
 "capabilities": [
  "fake.execute"
 ],
 "image": {
  "imageDigest": "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
  "sourceCommit": "0000000000000000000000000000000000000000",
  "provenanceDigest": "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
  "signatureDigest": "sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd"
 },
 "protocol": {
  "invocationProtocolDigest": "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
  "contractBomReference": {
   "repository": "anvilkit/contracts",
   "bomDigest": "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
   "ociManifestDigest": "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
   "evidenceManifestDigest": "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
  }
 },
 "workload": {
  "workloadIdentity": "urn:anvilkit:workload:agent-synthetic-001",
  "audience": "urn:anvilkit:audience:runtime-page-change-manager",
  "allowedControlPlaneEndpoints": [
   "/v1/model-gateway"
  ],
  "networkPolicy": "deny-all-except-allowed-endpoints"
 },
 "execution": {
  "taskChannel": "anvilkit.agent.task.agent-synthetic-001",
  "maxConcurrency": 1,
  "timeoutMilliseconds": 1000,
  "resourceClass": "interactive-cpu",
  "cpuMillis": 1,
  "memoryBytes": 1048576
 },
 "scaling": {
  "minReplicas": 0,
  "maxReplicas": 1,
  "targetConcurrency": 1
 },
 "telemetry": {
  "namespace": "anvilkit_agent_runtime_synthetic",
  "healthPath": "/healthz",
  "readinessPath": "/readyz"
 },
 "release": {
  "owner": "Agent Runtime Release owner",
  "rolloutPolicy": "new-runs-only",
  "drainSeconds": 0,
  "rollbackTarget": "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
 },
 "lifecycle": {
  "state": "active",
  "effectiveAt": "2026-08-27T12:00:00.000Z"
 }
}`

func manifestReporting(t *testing.T, imageDigest string) []byte {
	t.Helper()
	var manifest map[string]any
	if err := json.Unmarshal([]byte(canonicalRuntimeManifest), &manifest); err != nil {
		t.Fatalf("decode canonical manifest: %v", err)
	}
	manifest["image"].(map[string]any)["imageDigest"] = imageDigest
	raw, err := json.Marshal(manifest)
	if err != nil {
		t.Fatalf("encode manifest: %v", err)
	}
	return raw
}

type staticEndpoint struct{ url string }

func (s staticEndpoint) Endpoint(string) (string, error) { return s.url, nil }

func testClock() func() time.Time { return func() time.Time { return time.Unix(1700000000, 0).UTC() } }

func dispatcherFor(t *testing.T, handler http.Handler) (*HTTPDispatcher, *httptest.Server) {
	t.Helper()
	server := httptest.NewServer(handler)
	t.Cleanup(server.Close)
	dispatcher, err := NewHTTPDispatcher(staticEndpoint{server.URL}, &http.Client{Timeout: 5 * time.Second}, testClock())
	if err != nil {
		t.Fatalf("build dispatcher: %v", err)
	}
	return dispatcher, server
}

func testBinding() agent.RuntimeBinding {
	return agent.RuntimeBinding{
		RuntimeUnitID:            "runtime.platform.page-change-manager",
		RuntimeManifestDigest:    "sha256:" + strings.Repeat("a", 64),
		RuntimeImageDigest:       "sha256:" + strings.Repeat("b", 64),
		InvocationProtocolDigest: "sha256:" + strings.Repeat("c", 64),
		RuntimeAudience:          "urn:anvilkit:audience:runtime-page-change-manager",
	}
}

func testCredential() Credential {
	return Credential{Value: "task-scoped", Audience: "urn:anvilkit:audience:runtime-page-change-manager", ExpiresAt: time.Unix(1700000600, 0)}
}

func testDispatchTask() schema.AgentTask {
	return schema.AgentTask{
		Kind:              "AgentTask",
		TaskId:            "task.0001",
		PhysicalAttemptId: "attempt.0002",
		TraceContext:      schema.SharedPrimitivesTraceContext{Traceparent: "00-0123456789abcdef0123456789abcdef-0123456789abcdef-01"},
	}
}

// A dispatch carries the attempt, the task-scoped credential, and the request
// digest of exactly the bytes sent — and nothing else. What travels is what a
// runtime is entitled to know.
func TestDispatchCarriesTheAttemptAndOnlyItsOwnCredential(t *testing.T) {
	var seen *http.Request
	var body []byte
	dispatcher, _ := dispatcherFor(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen = r
		body, _ = readAll(r)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(canonicalRuntimeResult))
	}))

	receipt, err := dispatcher.Dispatch(context.Background(), testBinding(), testDispatchTask(), testCredential())
	if err != nil {
		t.Fatalf("dispatch: %v", err)
	}
	if seen.URL.Path != "/task" || seen.Method != http.MethodPost {
		t.Fatalf("dispatched to %s %s", seen.Method, seen.URL.Path)
	}
	if seen.Header.Get("Authorization") != "Bearer task-scoped" {
		t.Fatalf("authorization = %q", seen.Header.Get("Authorization"))
	}
	if seen.Header.Get("Idempotency-Key") != "attempt.0002" {
		t.Fatalf("idempotency key = %q, want the physical attempt", seen.Header.Get("Idempotency-Key"))
	}
	if seen.Header.Get("X-AnvilKit-Request-Digest") != digestOf(body) {
		t.Fatal("the request digest is not the digest of the dispatched bytes")
	}
	if string(receipt.Result.TaskId) != "task.0001" || receipt.Release != testBinding() {
		t.Fatalf("receipt = %+v", receipt)
	}
}

// A credential issued for one release must not be presented to another: that is
// how a task addressed to one runtime gets executed by a different one.
func TestACredentialForAnotherReleaseIsNeverPresented(t *testing.T) {
	dispatcher, _ := dispatcherFor(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		t.Error("a dispatch was attempted with a credential for another audience")
		w.WriteHeader(http.StatusOK)
	}))
	credential := testCredential()
	credential.Audience = "urn:anvilkit:audience:runtime-page-candidate-specialist"
	if _, err := dispatcher.Dispatch(context.Background(), testBinding(), testDispatchTask(), credential); err == nil {
		t.Fatal("a credential for another release was presented")
	}
}

// A release that answers as something other than the pinned release is
// incompatible, and the caller is told which field disagreed.
func TestCompatibilityComparesWhatTheReleaseReportsWithWhatTheRunPinned(t *testing.T) {
	t.Run("the pinned release", func(t *testing.T) {
		dispatcher, _ := dispatcherFor(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			_, _ = w.Write(manifestReporting(t, "sha256:"+strings.Repeat("b", 64)))
		}))
		result, err := dispatcher.CheckCompatibility(context.Background(), testBinding())
		if err != nil || !result.Compatible || result.Reason != "" {
			t.Fatalf("the pinned release was reported incompatible: %+v (%v)", result, err)
		}
	})
	t.Run("another image", func(t *testing.T) {
		dispatcher, _ := dispatcherFor(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			_, _ = w.Write(manifestReporting(t, "sha256:"+strings.Repeat("9", 64)))
		}))
		result, err := dispatcher.CheckCompatibility(context.Background(), testBinding())
		if err != nil {
			t.Fatalf("compatibility: %v", err)
		}
		if result.Compatible || !strings.Contains(result.Reason, "image digest") {
			t.Fatalf("a replaced image was reported compatible: %+v", result)
		}
	})
}

// A runtime cannot make the control plane read an unbounded body, and a
// non-success answer is reported as the operation that failed rather than as
// whatever prose the runtime chose to return.
func TestARuntimeCannotFloodOrNarrateToTheControlPlane(t *testing.T) {
	t.Run("bounded body", func(t *testing.T) {
		dispatcher, _ := dispatcherFor(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			flood := make([]byte, maximumRuntimeResponseBytes+4096)
			for i := range flood {
				flood[i] = 'x'
			}
			_, _ = w.Write(flood)
		}))
		if _, err := dispatcher.Dispatch(context.Background(), testBinding(), testDispatchTask(), testCredential()); err == nil ||
			!strings.Contains(err.Error(), "bounded contract") {
			t.Fatalf("an unbounded runtime answer was read: %v", err)
		}
	})
	t.Run("no redirect", func(t *testing.T) {
		// The task and its credential must not be delivered wherever the
		// answering endpoint points: a redirect is answered as a status, and
		// the redirect target never sees a request.
		var forwarded atomic.Int32
		mux := http.NewServeMux()
		mux.HandleFunc("/task", func(w http.ResponseWriter, r *http.Request) {
			http.Redirect(w, r, "/elsewhere", http.StatusTemporaryRedirect)
		})
		mux.HandleFunc("/elsewhere", func(w http.ResponseWriter, _ *http.Request) {
			forwarded.Add(1)
			w.WriteHeader(http.StatusOK)
		})
		dispatcher, _ := dispatcherFor(t, mux)
		if _, err := dispatcher.Dispatch(context.Background(), testBinding(), testDispatchTask(), testCredential()); err == nil ||
			!strings.Contains(err.Error(), "answered 307") {
			t.Fatalf("a redirect was not answered as a status: %v", err)
		}
		if forwarded.Load() != 0 {
			t.Fatal("the task and its credential followed a redirect")
		}
	})
	t.Run("no narration", func(t *testing.T) {
		dispatcher, _ := dispatcherFor(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusInternalServerError)
			_, _ = w.Write([]byte("database password is hunter2"))
		}))
		_, err := dispatcher.Dispatch(context.Background(), testBinding(), testDispatchTask(), testCredential())
		if err == nil || strings.Contains(err.Error(), "hunter2") {
			t.Fatalf("a runtime's own text reached the control plane's diagnostics: %v", err)
		}
	})
}

// The adapter must be composable in production, and must refuse to exist
// without a deadline: a dispatch that cannot time out cannot be recovered.
func TestTheHTTPAdapterIsProductionEligibleAndAlwaysBounded(t *testing.T) {
	dispatcher, _ := dispatcherFor(t, http.NotFoundHandler())
	if eligibility.EligibilityOf(dispatcher) != eligibility.ProductionEligible {
		t.Fatal("the HTTP dispatcher does not declare itself fit for production")
	}
	if _, err := NewHTTPDispatcher(staticEndpoint{"http://runtime.invalid"}, &http.Client{}, testClock()); err == nil {
		t.Fatal("a dispatcher was built with no deadline")
	}
}

// Cancellation is not offered by this protocol generation, and the adapter says
// so rather than reporting a cancellation it did not perform.
func TestCancellationIsReportedAsUnofferedRatherThanAssumed(t *testing.T) {
	dispatcher, _ := dispatcherFor(t, http.NotFoundHandler())
	if _, err := dispatcher.Cancel(context.Background(), testBinding(), "attempt.0002"); err == nil {
		t.Fatal("a cancellation this protocol cannot carry was reported as performed")
	}
}

func readAll(r *http.Request) ([]byte, error) {
	defer func() { _ = r.Body.Close() }()
	buffer := make([]byte, 0, 1024)
	chunk := make([]byte, 512)
	for {
		read, err := r.Body.Read(chunk)
		buffer = append(buffer, chunk[:read]...)
		if err != nil {
			return buffer, nil
		}
	}
}
