package runtimes

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/ancyloce/anvilkit-agent-service/contracts/generated/schema"
	"github.com/ancyloce/anvilkit-agent-service/internal/agent"
	"github.com/ancyloce/anvilkit-agent-service/internal/eligibility"
)

// maximumRuntimeResponseBytes bounds what a runtime can make this process read.
// The canonical result contract is bounded; an unbounded reader would let a
// runtime exhaust the control plane's memory with a body no contract admits.
const maximumRuntimeResponseBytes = 1 << 20

// HTTPDispatcher is the first RuntimeDispatcher adapter: HTTP/JSON over the
// canonical runtime boundary description.
//
// It is the only place in the service that knows a runtime is reached over
// HTTP. It carries the task-scoped credential and nothing else — no service
// identity, no provider credential — so a runtime learns exactly the authority
// the attempt was issued.
type HTTPDispatcher struct {
	endpoints Endpoints
	client    *http.Client
	now       func() time.Time
}

// NewHTTPDispatcher binds the adapter to the deployment's endpoint resolution
// and a bounded HTTP client.
func NewHTTPDispatcher(endpoints Endpoints, client *http.Client, now func() time.Time) (*HTTPDispatcher, error) {
	if endpoints == nil || client == nil || now == nil {
		return nil, fmt.Errorf("runtime dispatcher: endpoint resolution, an HTTP client, and a clock are all required")
	}
	if client.Timeout <= 0 {
		return nil, fmt.Errorf("runtime dispatcher: the HTTP client must carry a deadline; a dispatch that cannot time out cannot be recovered")
	}
	// A redirect is never followed. A dispatch carries the task — its fence
	// token included — and the attempt's credential, and a client that
	// followed a 307 or 308 would deliver both, body intact, wherever the
	// answering endpoint pointed. The endpoint a release answers on is
	// deployment material this service resolved; anything else is a hop it
	// did not decide. A redirect is therefore read as what it is: a status
	// that is not a result.
	bounded := *client
	bounded.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	return &HTTPDispatcher{endpoints: endpoints, client: &bounded, now: now}, nil
}

// Eligibility declares this adapter fit for production: it talks to a real
// runtime process over the canonical protocol.
func (*HTTPDispatcher) Eligibility() eligibility.Eligibility {
	return eligibility.ProductionEligible
}

func (d *HTTPDispatcher) Dispatch(ctx context.Context, binding agent.RuntimeBinding, task schema.AgentTask, credential Credential) (DispatchReceipt, error) {
	if credential.Value == "" || credential.Audience == "" {
		return DispatchReceipt{}, fmt.Errorf("runtime dispatch: a task-scoped credential is required")
	}
	// The credential must be the one issued for this release. Presenting a
	// credential for another audience to a runtime is how a task addressed to
	// one release gets executed by another.
	if credential.Audience != binding.RuntimeAudience {
		return DispatchReceipt{}, fmt.Errorf("runtime dispatch: the credential audience %q is not the pinned release audience %q", credential.Audience, binding.RuntimeAudience)
	}
	body, err := json.Marshal(task)
	if err != nil {
		return DispatchReceipt{}, fmt.Errorf("runtime dispatch: encode task: %w", err)
	}
	dispatchedAt := d.now()
	request, err := d.request(ctx, binding, http.MethodPost, "/task", body)
	if err != nil {
		return DispatchReceipt{}, err
	}
	request.Header.Set("Authorization", "Bearer "+credential.Value)
	// The idempotency identity is the attempt itself: a network retry of the
	// same attempt must be the same request, and a replacement attempt is a
	// different one by construction.
	request.Header.Set("Idempotency-Key", string(task.PhysicalAttemptId))
	request.Header.Set("X-AnvilKit-Request-Digest", digestOf(body))
	request.Header.Set("traceparent", task.TraceContext.Traceparent)

	raw, err := d.do(request, http.StatusOK)
	if err != nil {
		return DispatchReceipt{}, err
	}
	var result schema.AgentRuntimeResult
	if err := json.Unmarshal(raw, &result); err != nil {
		return DispatchReceipt{}, fmt.Errorf("runtime dispatch: the release did not answer with a canonical result: %w", err)
	}
	return DispatchReceipt{Release: binding, Result: result, DispatchedAt: dispatchedAt, ObservedAt: d.now()}, nil
}

func (d *HTTPDispatcher) Cancel(_ context.Context, binding agent.RuntimeBinding, _ string) (CancelReceipt, error) {
	return CancelReceipt{}, CancellationNotOfferedError{RuntimeUnitID: binding.RuntimeUnitID}
}

func (d *HTTPDispatcher) CheckCompatibility(ctx context.Context, binding agent.RuntimeBinding) (CompatibilityResult, error) {
	request, err := d.request(ctx, binding, http.MethodGet, "/runtime-release", nil)
	if err != nil {
		return CompatibilityResult{}, err
	}
	raw, err := d.do(request, http.StatusOK)
	if err != nil {
		return CompatibilityResult{}, err
	}
	var manifest schema.AgentRuntimeManifest
	if err := json.Unmarshal(raw, &manifest); err != nil {
		return CompatibilityResult{}, fmt.Errorf("runtime compatibility: the release did not answer with a canonical manifest: %w", err)
	}
	observed := agent.RuntimeBinding{
		RuntimeUnitID: string(manifest.RuntimeUnitId),
		// The manifest cannot carry its own digest, so what a release reports is
		// the material; the digest of that material is what this process
		// compares against the pin.
		RuntimeManifestDigest:    DocumentDigest(raw),
		RuntimeImageDigest:       string(manifest.Image.ImageDigest),
		InvocationProtocolDigest: string(manifest.Protocol.InvocationProtocolDigest),
		RuntimeAudience:          manifest.Workload.Audience,
	}
	result := CompatibilityResult{Compatible: true, Observed: observed, ObservedAt: d.now()}
	// The reported manifest digest is deliberately not compared: a release
	// serialises its manifest as it was mounted, and JSON that means the same
	// thing can differ byte for byte. Identity, image, protocol, and audience
	// are what a dispatch decision rests on.
	for _, mismatch := range []struct {
		field            string
		pinned, observed string
	}{
		{"runtime unit", binding.RuntimeUnitID, observed.RuntimeUnitID},
		{"image digest", binding.RuntimeImageDigest, observed.RuntimeImageDigest},
		{"invocation protocol digest", binding.InvocationProtocolDigest, observed.InvocationProtocolDigest},
		{"workload audience", binding.RuntimeAudience, observed.RuntimeAudience},
	} {
		if mismatch.pinned != mismatch.observed {
			result.Compatible = false
			result.Reason = fmt.Sprintf("the release answering for %s reports %s %q where the run pins %q",
				binding.RuntimeUnitID, mismatch.field, mismatch.observed, mismatch.pinned)
			break
		}
	}
	return result, nil
}

func (d *HTTPDispatcher) request(ctx context.Context, binding agent.RuntimeBinding, method, path string, body []byte) (*http.Request, error) {
	endpoint, err := d.endpoints.Endpoint(binding.RuntimeUnitID)
	if err != nil {
		return nil, fmt.Errorf("runtime dispatch: %w", err)
	}
	var reader io.Reader
	if body != nil {
		reader = bytes.NewReader(body)
	}
	request, err := http.NewRequestWithContext(ctx, method, endpoint+path, reader)
	if err != nil {
		return nil, fmt.Errorf("runtime dispatch: build request: %w", err)
	}
	if body != nil {
		request.Header.Set("Content-Type", "application/json")
	}
	request.Header.Set("Accept", "application/json")
	return request, nil
}

func (d *HTTPDispatcher) do(request *http.Request, want int) ([]byte, error) {
	response, err := d.client.Do(request)
	if err != nil {
		return nil, fmt.Errorf("runtime dispatch: %s %s: %w", request.Method, request.URL.Path, err)
	}
	defer func() { _ = response.Body.Close() }()
	raw, err := io.ReadAll(io.LimitReader(response.Body, maximumRuntimeResponseBytes+1))
	if err != nil {
		return nil, fmt.Errorf("runtime dispatch: read response: %w", err)
	}
	if len(raw) > maximumRuntimeResponseBytes {
		return nil, fmt.Errorf("runtime dispatch: the release answered with more than the bounded contract admits")
	}
	if response.StatusCode != want {
		// The runtime's body is not repeated: a control plane that echoed a
		// runtime's prose would be carrying text it did not author into its own
		// diagnostics. The status and the operation are what a caller acts on.
		return nil, fmt.Errorf("runtime dispatch: %s %s answered %d", request.Method, request.URL.Path, response.StatusCode)
	}
	return raw, nil
}

func digestOf(raw []byte) string {
	sum := sha256.Sum256(raw)
	return "sha256:" + hex.EncodeToString(sum[:])
}
