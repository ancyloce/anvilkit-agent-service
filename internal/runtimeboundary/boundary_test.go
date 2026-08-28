package runtimeboundary

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/ancyloce/anvilkit-agent-service/contracts/generated/schema"
	"github.com/ancyloce/anvilkit-agent-service/internal/agent"
	"github.com/ancyloce/anvilkit-agent-service/internal/canonical"
	"github.com/ancyloce/anvilkit-agent-service/internal/execution"
	"github.com/ancyloce/anvilkit-agent-service/internal/modelgateway"
	"github.com/ancyloce/anvilkit-agent-service/internal/runtimes"
)

const (
	testAudience  = "urn:anvilkit:audience:runtime-page-change-manager"
	testUnit      = "runtime.platform.page-change-manager"
	testAttemptID = "attempt.boundary.0001"
)

type fixture struct {
	boundary    *Boundary
	issuer      *runtimes.TaskCredentials
	register    *MemoryRegister
	attempts    *MemoryAttempts
	submissions *MemorySubmissions
	models      *stubModels
	task        schema.AgentTask
	now         time.Time
}

// stubModels answers one scripted governed output.
type stubModels struct {
	output   []byte
	selectED bool
	invoked  int
	err      error
}

func (s *stubModels) Select(context.Context, string, agent.PolicyReference) (modelgateway.Selection, error) {
	s.selectED = true
	return modelgateway.Selection{Provider: modelgateway.Provider{ID: "stub-provider"}, PolicyVersion: "v1"}, nil
}

func (s *stubModels) Invoke(_ context.Context, request modelgateway.InvokeRequest) (modelgateway.AdapterResponse, modelgateway.InvocationRecord, error) {
	s.invoked++
	if s.err != nil {
		return modelgateway.AdapterResponse{}, modelgateway.InvocationRecord{}, s.err
	}
	completed := time.Unix(1756300000, 0).UTC().Add(250 * time.Millisecond)
	return modelgateway.AdapterResponse{Output: s.output, InputTokens: 100, OutputTokens: 50, CostMicros: 1000},
		modelgateway.InvocationRecord{
			InvocationID: string(modelgateway.InvocationIdentity(request.IdempotencyKey)),
			StartedAt:    time.Unix(1756300000, 0).UTC(),
			CompletedAt:  &completed,
			InputTokens:  100, OutputTokens: 50, CostMicros: 1000,
		}, nil
}

type acceptingValidator struct{ refused bool }

func (v acceptingValidator) Validate(context.Context, agent.SchemaReference, json.RawMessage) error {
	if v.refused {
		return fmt.Errorf("refused")
	}
	return nil
}

func testTask(now time.Time) schema.AgentTask {
	return schema.AgentTask{
		Kind:                "AgentTask",
		TaskId:              "task.boundary.0001",
		RunId:               "run.boundary.0001",
		RootRunId:           "run.boundary.0001",
		PhysicalAttemptId:   testAttemptID,
		AttemptNumber:       1,
		ExecutionGeneration: 1,
		LeaseEpoch:          1,
		FenceToken:          "fence.boundary.0001",
		ExpiresAt:           schema.SharedPrimitivesTimestamp(now.Add(2 * time.Minute)),
		Definition: schema.SharedPrimitivesDefinitionReference{
			DefinitionId:     "definition.platform.page-change-manager",
			DefinitionDigest: schema.SharedPrimitivesDigest("sha256:" + strings.Repeat("1", 64)),
		},
		RuntimeBinding: schema.AgentTaskRuntimeBinding{
			RuntimeUnitId:            testUnit,
			RuntimeManifestDigest:    schema.SharedPrimitivesDigest("sha256:" + strings.Repeat("2", 64)),
			RuntimeImageDigest:       schema.SharedPrimitivesDigest("sha256:" + strings.Repeat("3", 64)),
			InvocationProtocolDigest: schema.SharedPrimitivesDigest("sha256:" + strings.Repeat("4", 64)),
			RuntimeAudience:          testAudience,
		},
		AuthorizationAudience: testAudience,
		Capability:            schema.AgentTaskCapabilityProviderInvoke,
		InputSchema:           schema.SharedPrimitivesSchemaReference{ComponentName: "anvilkit.contract.schema.create-agent-run-request", Digest: schema.SharedPrimitivesDigest("sha256:" + strings.Repeat("5", 64))},
		ArtifactInputs:        []schema.SharedPrimitivesArtifactReference{},
		Parameters: schema.SharedPrimitivesBoundedStringMap{
			"model.contextDigest":   "sha256:" + strings.Repeat("6", 64),
			"model.promptDigest":    "sha256:" + strings.Repeat("7", 64),
			"model.policyId":        "policy.model.default",
			"model.policyVersion":   "v1",
			"model.policyDigest":    "sha256:" + strings.Repeat("8", 64),
			"allowanceModelCalls":   "10",
			"allowanceInputTokens":  "4096",
			"allowanceOutputTokens": "2048",
			"allowanceTotalTokens":  "6144",
			"allowanceCostMicros":   "1000000",
			"target.type":           "page",
			"target.id":             "page.home",
		},
		Resources: schema.AgentTaskResources{ResourceClass: schema.AgentTaskResourcesResourceClassInteractiveCpu, Priority: 500},
		Limits: schema.SharedPrimitivesResourceLimits{
			TimeoutMilliseconds: 60000, MemoryBytes: 1 << 29, CpuMillis: 1000, GpuMillis: 0, OutputBytes: 1 << 20,
		},
		Idempotency:          schema.SharedPrimitivesIdempotency{Scope: "agent-turn", Key: "run.boundary.0001:turn-0001", CanonicalRequestDigest: schema.SharedPrimitivesDigest("sha256:" + strings.Repeat("9", 64))},
		TraceContext:         schema.SharedPrimitivesTraceContext{Traceparent: "00-0123456789abcdef0123456789abcdef-0123456789abcdef-01"},
		ContractBomReference: schema.SharedPrimitivesContractBomReference{Repository: "anvilkit/contracts", BomDigest: schema.SharedPrimitivesDigest("sha256:" + strings.Repeat("b", 64)), OciManifestDigest: schema.SharedPrimitivesDigest("sha256:" + strings.Repeat("c", 64)), EvidenceManifestDigest: schema.SharedPrimitivesDigest("sha256:" + strings.Repeat("d", 64))},
	}
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	now := time.Unix(1756300000, 0).UTC()
	issuer, err := runtimes.NewTaskCredentials(
		"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
		"urn:anvilkit:key:boundary-test-credentials",
		5*time.Minute, func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	source, err := runtimes.NewControlledCredentialTrust(issuer.PublicKey(), issuer.KeyID(), []string{testAudience}, func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	trust, err := runtimes.NewCredentialTrust(source)
	if err != nil {
		t.Fatal(err)
	}
	register := NewMemoryRegister()
	attempts := NewMemoryAttempts()
	submissions := NewMemorySubmissions()
	models := &stubModels{output: []byte(`{"plan":"{\"kind\":\"AgentPlan\",\"steps\":[{\"action\":\"continue\",\"note\":\"ok\"}]}"}`)}
	boundary, err := New(Config{
		Credentials:     trust,
		Audiences:       []string{testAudience},
		Models:          models,
		Validator:       acceptingValidator{},
		CandidateSchema: agent.SchemaReference{ComponentName: "anvilkit.contract.schema.page-candidate", Digest: "sha256:" + strings.Repeat("e", 64)},
		Register:        register,
		Attempts:        attempts,
		Submissions:     submissions,
		Now:             func() time.Time { return now },
	})
	if err != nil {
		t.Fatal(err)
	}
	task := testTask(now)
	if err := register.Offer(context.Background(), task, []byte("compiled")); err != nil {
		t.Fatal(err)
	}
	return &fixture{boundary: boundary, issuer: issuer, register: register, attempts: attempts, submissions: submissions, models: models, task: task, now: now}
}

func (f *fixture) credential(t *testing.T) string {
	t.Helper()
	credential, err := f.issuer.Issue(context.Background(), f.task, runtimes.Subject{WorkspaceID: "workspace", ProjectID: "project"})
	if err != nil {
		t.Fatal(err)
	}
	return credential.Value
}

func (f *fixture) call(t *testing.T, path, token string, body []byte) *httptest.ResponseRecorder {
	t.Helper()
	request := httptest.NewRequest(http.MethodPost, path, bytes.NewReader(body))
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set(requestDigestHeader, digestOf(body))
	if token != "" {
		request.Header.Set("Authorization", "Bearer "+token)
	}
	recorder := httptest.NewRecorder()
	f.boundary.ServeHTTP(recorder, request)
	return recorder
}

// A callback that declares no request digest is refused before anything about
// it is interpreted, exactly as the runtime's own admission refuses a dispatch
// without one.
func TestACallbackWithoutARequestDigestIsRefused(t *testing.T) {
	f := newFixture(t)
	body := f.modelRequest(t)
	request := httptest.NewRequest(http.MethodPost, "/v1/internal/runtime/model-invocations", bytes.NewReader(body))
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Authorization", "Bearer "+f.credential(t))
	recorder := httptest.NewRecorder()
	f.boundary.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusBadRequest {
		t.Fatalf("a callback without a request digest was admitted: %d %s", recorder.Code, recorder.Body.String())
	}
	if f.models.invoked != 0 {
		t.Fatal("a callback without a request digest reached the governed model")
	}
}

// modelRequest builds the canonical invocation exactly the way the runtime SDK
// does, including the canonical request digest over the request without its
// idempotency member.
func (f *fixture) modelRequest(t *testing.T) []byte {
	t.Helper()
	parameters := map[string]string(f.task.Parameters)
	request := schema.ModelInvocationRequest{
		Kind:                "ModelInvocationRequest",
		RunId:               f.task.RunId,
		RootRunId:           f.task.RootRunId,
		TaskId:              f.task.TaskId,
		PhysicalAttemptId:   f.task.PhysicalAttemptId,
		AttemptNumber:       f.task.AttemptNumber,
		ExecutionGeneration: f.task.ExecutionGeneration,
		Definition:          f.task.Definition,
		ModelPolicy: schema.SharedPrimitivesPolicyReference{
			PolicyId: schema.SharedPrimitivesOpaqueId(parameters["model.policyId"]),
			Version:  parameters["model.policyVersion"],
			Digest:   schema.SharedPrimitivesDigest(parameters["model.policyDigest"]),
		},
		ContextDigest:        schema.SharedPrimitivesDigest(parameters["model.contextDigest"]),
		PromptDigest:         schema.SharedPrimitivesDigest(parameters["model.promptDigest"]),
		Limits:               f.task.Limits,
		TraceContext:         f.task.TraceContext,
		ContractBomReference: f.task.ContractBomReference,
		Idempotency: schema.SharedPrimitivesIdempotency{
			Scope: "attempt-and-operation",
			Key:   string(f.task.PhysicalAttemptId) + ":model.plan",
		},
	}
	encoded, err := json.Marshal(request)
	if err != nil {
		t.Fatal(err)
	}
	var document map[string]json.RawMessage
	if err := json.Unmarshal(encoded, &document); err != nil {
		t.Fatal(err)
	}
	delete(document, "idempotency")
	withoutIdempotency, err := json.Marshal(document)
	if err != nil {
		t.Fatal(err)
	}
	digest, err := canonical.Digest(withoutIdempotency)
	if err != nil {
		t.Fatal(err)
	}
	request.Idempotency.CanonicalRequestDigest = schema.SharedPrimitivesDigest(digest)
	body, err := json.Marshal(request)
	if err != nil {
		t.Fatal(err)
	}
	return body
}

// The offer a register keeps is the dispatched task without its fence token:
// the fence is a commit capability, and a durable record that carried it would
// hand every reader the ability to commit an attempt it never ran. Nothing
// that binds a callback to the offer needs it.
func TestAnOfferedTaskKeepsNoFenceToken(t *testing.T) {
	f := newFixture(t)
	if f.task.FenceToken == "" {
		t.Fatal("the fixture must dispatch a task that carries a fence token")
	}
	stored, known, err := f.register.Task(context.Background(), string(f.task.PhysicalAttemptId))
	if err != nil || !known {
		t.Fatalf("offered task: known=%v err=%v", known, err)
	}
	if stored.FenceToken == f.task.FenceToken || stored.FenceToken != Offered(f.task).FenceToken {
		t.Fatal("the offered task must keep the fence token's digest, never the token")
	}
	if stored.TaskId != f.task.TaskId || stored.PhysicalAttemptId != f.task.PhysicalAttemptId || stored.LeaseEpoch != f.task.LeaseEpoch || stored.ExpiresAt != f.task.ExpiresAt {
		t.Fatalf("everything but the fence must be kept as dispatched: %+v", stored)
	}
	// The task still binds its callbacks without the fence.
	recorder := f.call(t, "/v1/internal/runtime/model-invocations", f.credential(t), f.modelRequest(t))
	if recorder.Code != http.StatusOK {
		t.Fatalf("a callback bound to the fence-free offer must be admitted: %d %s", recorder.Code, recorder.Body.String())
	}
}

func TestTheBoundaryAdmitsOnlyVerifiedBoundCredentials(t *testing.T) {
	f := newFixture(t)
	body := f.modelRequest(t)

	if got := f.call(t, PathModelInvocations, "", body); got.Code != http.StatusUnauthorized {
		t.Fatalf("no credential answered %d, want 401", got.Code)
	}
	if got := f.call(t, PathModelInvocations, "not-a-token", body); got.Code != http.StatusUnauthorized {
		t.Fatalf("a malformed credential answered %d, want 401", got.Code)
	}
	if got := f.call(t, "/v1/internal/runtime/unknown", f.credential(t), body); got.Code != http.StatusNotFound {
		t.Fatalf("an unknown path answered %d, want 404", got.Code)
	}

	// A credential for an attempt this service never offered reaches nothing.
	stranger := f.task
	stranger.PhysicalAttemptId = "attempt.boundary.9999"
	strangerCredential, err := f.issuer.Issue(context.Background(), stranger, runtimes.Subject{WorkspaceID: "workspace", ProjectID: "project"})
	if err != nil {
		t.Fatal(err)
	}
	if got := f.call(t, PathModelInvocations, strangerCredential.Value, body); got.Code != http.StatusNotFound {
		t.Fatalf("an unoffered attempt answered %d, want 404", got.Code)
	}

	// GET is not a boundary method.
	request := httptest.NewRequest(http.MethodGet, PathModelInvocations, nil)
	recorder := httptest.NewRecorder()
	f.boundary.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusMethodNotAllowed {
		t.Fatalf("GET answered %d, want 405", recorder.Code)
	}
}

func TestAnExpiredAttemptIsRefusedAtAdmission(t *testing.T) {
	f := newFixture(t)
	// The credential was minted while the attempt's window was open; the
	// window then closed. The boundary reads the offered task, not the
	// credential, so the callback is refused however valid the bearer is.
	fresh := f.task
	fresh.PhysicalAttemptId = "attempt.boundary.0002"
	credential, err := f.issuer.Issue(context.Background(), fresh, runtimes.Subject{WorkspaceID: "workspace", ProjectID: "project"})
	if err != nil {
		t.Fatal(err)
	}
	expired := fresh
	expired.ExpiresAt = schema.SharedPrimitivesTimestamp(f.now.Add(-time.Second))
	if err := f.register.Offer(context.Background(), expired, nil); err != nil {
		t.Fatal(err)
	}
	if got := f.call(t, PathModelInvocations, credential.Value, f.modelRequest(t)); got.Code != http.StatusGone {
		t.Fatalf("an expired attempt answered %d, want 410", got.Code)
	}
}

func TestASupersededAttemptIsRefusedAtAdmission(t *testing.T) {
	f := newFixture(t)
	// The attempt was current when the credential was minted and the task
	// offered; a replacement then took the task over. Every callback it makes
	// from here on is late by construction — a result the control plane has
	// already moved past — and the boundary refuses it however valid the
	// bearer and however open the window, on both served surfaces.
	credential := f.credential(t)
	f.attempts.Supersede(testAttemptID)
	if got := f.call(t, PathModelInvocations, credential, f.modelRequest(t)); got.Code != http.StatusGone {
		t.Fatalf("a superseded attempt's invocation answered %d, want 410", got.Code)
	}
	candidate, err := canonical.Bytes(execution.ControlledPageCandidate())
	if err != nil {
		t.Fatal(err)
	}
	if got := f.call(t, PathArtifacts, credential, candidate); got.Code != http.StatusGone {
		t.Fatalf("a superseded attempt's submission answered %d, want 410", got.Code)
	}
	if f.models.invoked != 0 {
		t.Fatalf("the governed model was invoked %d times for a superseded attempt, want 0", f.models.invoked)
	}
}

func TestGovernedModelInvocationServesTheDispatchedAttempt(t *testing.T) {
	f := newFixture(t)
	got := f.call(t, PathModelInvocations, f.credential(t), f.modelRequest(t))
	if got.Code != http.StatusOK {
		t.Fatalf("invocation answered %d: %s", got.Code, got.Body.String())
	}
	var result schema.ModelInvocationResult
	if err := json.Unmarshal(got.Body.Bytes(), &result); err != nil {
		t.Fatal(err)
	}
	if result.TaskId != f.task.TaskId || result.PhysicalAttemptId != f.task.PhysicalAttemptId ||
		result.AttemptNumber != f.task.AttemptNumber || result.ExecutionGeneration != f.task.ExecutionGeneration {
		t.Fatalf("the result does not belong to the dispatched attempt: %+v", result)
	}
	if result.Outcome != schema.ModelInvocationResultOutcomeOk || result.InvocationId == "" {
		t.Fatalf("outcome = %s invocation = %s", result.Outcome, result.InvocationId)
	}
	// The output digest is the canonical digest of the output map — the same
	// construction the runtime verifies before it reasons over a value.
	encoded, err := json.Marshal(map[string]string(result.Output))
	if err != nil {
		t.Fatal(err)
	}
	digest, err := canonical.Digest(encoded)
	if err != nil {
		t.Fatal(err)
	}
	if digest != string(result.OutputDigest) {
		t.Fatalf("output digest %s does not cover the output", result.OutputDigest)
	}
	if result.Usage.InputTokens != 100 || result.Usage.OutputTokens != 50 || string(result.Usage.Cost.Amount) != "0.001" {
		t.Fatalf("usage = %+v", result.Usage)
	}
}

func TestAnInvocationOutsideItsDispatchIsRefused(t *testing.T) {
	f := newFixture(t)
	tampered := f.modelRequest(t)
	tampered = bytes.Replace(tampered, []byte(strings.Repeat("6", 64)), []byte(strings.Repeat("f", 64)), 1)
	got := f.call(t, PathModelInvocations, f.credential(t), tampered)
	if got.Code != http.StatusForbidden {
		t.Fatalf("a foreign context digest answered %d, want 403", got.Code)
	}

	// A doctored canonical request digest is a contract violation.
	var request map[string]json.RawMessage
	if err := json.Unmarshal(f.modelRequest(t), &request); err != nil {
		t.Fatal(err)
	}
	request["idempotency"] = json.RawMessage(`{"scope":"attempt-and-operation","key":"` + testAttemptID + `:model.plan","canonicalRequestDigest":"sha256:` + strings.Repeat("a", 64) + `"}`)
	doctored, err := json.Marshal(request)
	if err != nil {
		t.Fatal(err)
	}
	if got := f.call(t, PathModelInvocations, f.credential(t), doctored); got.Code != http.StatusUnprocessableEntity {
		t.Fatalf("a doctored request digest answered %d, want 422", got.Code)
	}
}

func TestCandidateSubmissionIsImmutableAndIdempotent(t *testing.T) {
	f := newFixture(t)
	candidate, err := canonical.Bytes(execution.ControlledPageCandidate())
	if err != nil {
		t.Fatal(err)
	}
	first := f.call(t, PathArtifacts, f.credential(t), candidate)
	if first.Code != http.StatusCreated {
		t.Fatalf("submission answered %d: %s", first.Code, first.Body.String())
	}
	var recorded schema.AgentArtifact
	if err := json.Unmarshal(first.Body.Bytes(), &recorded); err != nil {
		t.Fatal(err)
	}
	if string(recorded.Digest) != digestOf(candidate) || recorded.Reference.SizeBytes != len(candidate) {
		t.Fatalf("the recorded artifact does not attest the submitted bytes: %+v", recorded)
	}

	// The same attempt re-submitting the same bytes replays the record.
	replay := f.call(t, PathArtifacts, f.credential(t), candidate)
	if replay.Code != http.StatusOK {
		t.Fatalf("replayed submission answered %d", replay.Code)
	}
	var replayed schema.AgentArtifact
	if err := json.Unmarshal(replay.Body.Bytes(), &replayed); err != nil {
		t.Fatal(err)
	}
	if replayed.ArtifactId != recorded.ArtifactId {
		t.Fatalf("the replay named a second artifact: %s then %s", recorded.ArtifactId, replayed.ArtifactId)
	}

	// The same attempt submitting different bytes is a conflict.
	other, err := canonical.Bytes(bytes.Replace(execution.ControlledPageCandidate(), []byte("synthetic candidate"), []byte("another candidate"), 1))
	if err != nil {
		t.Fatal(err)
	}
	conflict := f.call(t, PathArtifacts, f.credential(t), other)
	if conflict.Code != http.StatusConflict {
		t.Fatalf("a conflicting submission answered %d, want 409", conflict.Code)
	}

	// Non-canonical bytes are refused before anything is recorded.
	if got := f.call(t, PathArtifacts, f.credential(t), append([]byte(" "), candidate...)); got.Code != http.StatusUnprocessableEntity {
		t.Fatalf("non-canonical bytes answered %d, want 422", got.Code)
	}

	// The recorded content reads back by its reference — the candidate the
	// commit path resolves.
	content, err := f.submissions.Content(context.Background(), schema.SharedPrimitivesArtifactReference{
		ArtifactId: recorded.ArtifactId,
		Digest:     recorded.Digest,
		MediaType:  recorded.Reference.MediaType,
		SizeBytes:  recorded.Reference.SizeBytes,
	})
	if err != nil || string(content) != string(candidate) {
		t.Fatalf("content read-back = %q err = %v", content, err)
	}
}

func TestAContentGrantIsScopedToTheDispatchedInputs(t *testing.T) {
	f := newFixture(t)
	request, err := json.Marshal(schema.IssueArtifactContentGrantRequest{Kind: "IssueArtifactContentGrantRequest", ArtifactId: "artifact.unpinned.0001", Purpose: schema.IssueArtifactContentGrantRequestPurposeProducer})
	if err != nil {
		t.Fatal(err)
	}
	if got := f.call(t, PathArtifactContentGrants, f.credential(t), request); got.Code != http.StatusForbidden {
		t.Fatalf("a grant outside the dispatched inputs answered %d, want 403", got.Code)
	}
}
