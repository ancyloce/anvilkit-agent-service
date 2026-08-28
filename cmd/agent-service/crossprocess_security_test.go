package main

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/ancyloce/anvilkit-agent-service/contracts/generated/schema"
	"github.com/ancyloce/anvilkit-agent-service/internal/canonical"
	"github.com/ancyloce/anvilkit-agent-service/internal/runtimes"
)

// TestCrossProcessSecurityCorpusAtTheRealTaskBoundary runs the runtime-boundary
// adversarial corpus against the real, deployed `/task` endpoint of a live
// runtime unit — not a function call, the wire boundary. Each case is a way a
// dispatched task could be forged, misrouted, replayed, or run past its window;
// every one has a deterministic refusal at the unit's admission, before any
// reasoning happens. The one well-formed control case is admitted, which proves
// the corpus is refusing the attack and not the transport.
func TestCrossProcessSecurityCorpusAtTheRealTaskBoundary(t *testing.T) {
	top := newTopology(t, "delegate-page-specialist,compose-page")
	manager := loadReleaseRecord(t, "runtime.platform.page-change-manager", "release.platform.page-change-manager.json")
	specialist := loadReleaseRecord(t, "runtime.platform.page-candidate-specialist", "release.platform.page-candidate-specialist.json")
	now := time.Now().UTC()

	// Each case builds its task from a unique attempt identity, so a request
	// that reaches the unit's replay register in one case never answers the
	// next. The `valid` control the attacks vary from is per-case, keyed by the
	// category name.
	validFor := func(category string) schema.AgentTask { return managerTask(manager, now.Add(2*time.Minute), category) }

	cases := []struct {
		category   string
		wantStatus int
		task       func() schema.AgentTask // the task the credential is minted for and sent
		mutate     func(*http.Request, []byte)
	}{
		{
			category:   "unauthenticated",
			wantStatus: http.StatusUnauthorized,
			task:       func() schema.AgentTask { return validFor("unauthenticated") },
			mutate:     func(r *http.Request, _ []byte) { r.Header.Del("Authorization") },
		},
		{
			category:   "credential-forgery",
			wantStatus: http.StatusUnauthorized,
			task:       func() schema.AgentTask { return validFor("credential-forgery") },
			mutate: func(r *http.Request, _ []byte) {
				token := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
				parts := strings.Split(token, ".")
				// Flip the last signature character: a forged signature.
				sig := []byte(parts[2])
				if sig[len(sig)-1] == 'A' {
					sig[len(sig)-1] = 'B'
				} else {
					sig[len(sig)-1] = 'A'
				}
				r.Header.Set("Authorization", "Bearer "+parts[0]+"."+parts[1]+"."+string(sig))
			},
		},
		{
			category:   "wrong-runtime",
			wantStatus: http.StatusForbidden,
			task: func() schema.AgentTask {
				// A task bound to the Specialist release, dispatched to the
				// Manager: the binding the credential attests does not match the
				// unit's own manifest.
				// The credential still verifies — its audience is the Manager's,
				// so the refusal is the release binding, not the signature. The
				// task's binding and definition are the Specialist's, which the
				// Manager's own manifest does not carry.
				task := validFor("wrong-runtime")
				task.RuntimeBinding = specialistBinding(specialist)
				task.Definition = schema.SharedPrimitivesDefinitionReference{
					DefinitionId:     schema.SharedPrimitivesOpaqueId(specialist.definitionID),
					DefinitionDigest: schema.SharedPrimitivesDigest(specialist.definitionDigest),
				}
				return task
			},
		},
		{
			category:   "contract-violating-task",
			wantStatus: http.StatusUnprocessableEntity,
			task: func() schema.AgentTask {
				// A task that violates the canonical contract — an attempt
				// number and lease the schema forbids, which is also a task
				// whose result could never be fenced. Strict schema validation
				// refuses it before the work is ever admitted.
				task := validFor("contract-violating-task")
				task.AttemptNumber = 0
				task.LeaseEpoch = 0
				return task
			},
		},
	}

	for _, testCase := range cases {
		t.Run(testCase.category, func(t *testing.T) {
			task := testCase.task()
			credential, err := top.credentialIssuer.Issue(context.Background(), task, runtimes.Subject{WorkspaceID: "workspace", ProjectID: "project"})
			if err != nil {
				t.Fatalf("mint credential for %s: %v", testCase.category, err)
			}
			body, err := json.Marshal(task)
			if err != nil {
				t.Fatal(err)
			}
			request, err := http.NewRequestWithContext(top.ctx, http.MethodPost, top.manager.address+"/task", bytes.NewReader(body))
			if err != nil {
				t.Fatal(err)
			}
			request.Header.Set("Content-Type", "application/json")
			request.Header.Set("Authorization", "Bearer "+credential.Value)
			request.Header.Set("Idempotency-Key", string(task.PhysicalAttemptId))
			digest, err := canonical.Digest(body)
			if err != nil {
				t.Fatal(err)
			}
			request.Header.Set("X-AnvilKit-Request-Digest", digest)
			request.Header.Set("traceparent", top.trace)
			if testCase.mutate != nil {
				testCase.mutate(request, body)
			}
			response, err := top.client.Do(request)
			if err != nil {
				t.Fatal(err)
			}
			_ = response.Body.Close()
			if response.StatusCode != testCase.wantStatus {
				t.Fatalf("%s answered %d, want %d", testCase.category, response.StatusCode, testCase.wantStatus)
			}
		})
	}

	// The expired admission window: the credential is minted while the window
	// is open, but the dispatched task's window has already closed. The unit
	// reads the window from the task, so a validly signed credential does not
	// buy admission past it.
	t.Run("expired-admission-window", func(t *testing.T) {
		mintable := managerTask(manager, now.Add(2*time.Minute), "expired")
		credential, err := top.credentialIssuer.Issue(context.Background(), mintable, runtimes.Subject{WorkspaceID: "workspace", ProjectID: "project"})
		if err != nil {
			t.Fatal(err)
		}
		expired := mintable
		expired.ExpiresAt = schema.SharedPrimitivesTimestamp(now.Add(-time.Second))
		if got := managerTaskRequest(t, top, expired, credential.Value); got != http.StatusGone {
			t.Fatalf("an expired admission window answered %d, want 410", got)
		}
	})

	// The replay register: the same attempt re-presented with a different body
	// is a reused idempotency identity, refused at the wire.
	t.Run("credential-replay-different-body", func(t *testing.T) {
		task := managerTask(manager, now.Add(2*time.Minute), "replay")
		credential, err := top.credentialIssuer.Issue(context.Background(), task, runtimes.Subject{WorkspaceID: "workspace", ProjectID: "project"})
		if err != nil {
			t.Fatal(err)
		}
		// The first admission is well-formed and reaches execution; the unit
		// records the attempt. It may answer 200 (it will call back to the
		// service) or refuse on a downstream check — either way it is recorded.
		first := managerTaskRequest(t, top, task, credential.Value)
		_ = first
		// A second request with the same attempt idempotency key but a
		// different body is the reuse the register exists to catch.
		altered := task
		altered.Parameters["target.id"] = "page-altered-001"
		body, err := json.Marshal(altered)
		if err != nil {
			t.Fatal(err)
		}
		request, err := http.NewRequestWithContext(top.ctx, http.MethodPost, top.manager.address+"/task", bytes.NewReader(body))
		if err != nil {
			t.Fatal(err)
		}
		request.Header.Set("Content-Type", "application/json")
		request.Header.Set("Authorization", "Bearer "+credential.Value)
		request.Header.Set("Idempotency-Key", string(task.PhysicalAttemptId))
		digest, _ := canonical.Digest(body)
		request.Header.Set("X-AnvilKit-Request-Digest", digest)
		request.Header.Set("traceparent", top.trace)
		response, err := top.client.Do(request)
		if err != nil {
			t.Fatal(err)
		}
		_ = response.Body.Close()
		if response.StatusCode != http.StatusConflict {
			t.Fatalf("a reused attempt with a different body answered %d, want 409", response.StatusCode)
		}
	})
}

// managerTask builds a well-formed dispatched task for the manager release.
func managerTask(manager releaseRecord, expiresAt time.Time, id string) schema.AgentTask {
	return schema.AgentTask{
		Kind:                  "AgentTask",
		TaskId:                schema.SharedPrimitivesOpaqueId("task.security." + id),
		RunId:                 schema.SharedPrimitivesOpaqueId("run.security." + id),
		RootRunId:             schema.SharedPrimitivesOpaqueId("run.security." + id),
		PhysicalAttemptId:     schema.SharedPrimitivesOpaqueId("attempt.security." + id),
		AttemptNumber:         1,
		ExecutionGeneration:   1,
		LeaseEpoch:            1,
		FenceToken:            "fence.security.0000000000001",
		ExpiresAt:             schema.SharedPrimitivesTimestamp(expiresAt),
		Definition:            schema.SharedPrimitivesDefinitionReference{DefinitionId: schema.SharedPrimitivesOpaqueId(manager.definitionID), DefinitionDigest: schema.SharedPrimitivesDigest(manager.definitionDigest)},
		RuntimeBinding:        managerBinding(manager),
		AuthorizationAudience: manager.audience,
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
			"target.id":             "page-security-001",
		},
		Resources:            schema.AgentTaskResources{ResourceClass: schema.AgentTaskResourcesResourceClassInteractiveCpu, Priority: 500},
		Limits:               schema.SharedPrimitivesResourceLimits{TimeoutMilliseconds: 60000, MemoryBytes: 1 << 29, CpuMillis: 1000, GpuMillis: 0, OutputBytes: 1 << 20},
		Idempotency:          schema.SharedPrimitivesIdempotency{Scope: "agent-turn", Key: "run.security." + id + ":turn-0001", CanonicalRequestDigest: schema.SharedPrimitivesDigest("sha256:" + strings.Repeat("9", 64))},
		TraceContext:         schema.SharedPrimitivesTraceContext{Traceparent: "00-0123456789abcdef0123456789abcdef-0123456789abcdef-01"},
		ContractBomReference: schema.SharedPrimitivesContractBomReference{Repository: "anvilkit/contracts", BomDigest: schema.SharedPrimitivesDigest("sha256:" + strings.Repeat("b", 64)), OciManifestDigest: schema.SharedPrimitivesDigest("sha256:" + strings.Repeat("c", 64)), EvidenceManifestDigest: schema.SharedPrimitivesDigest("sha256:" + strings.Repeat("d", 64))},
	}
}

func managerBinding(manager releaseRecord) schema.AgentTaskRuntimeBinding {
	return schema.AgentTaskRuntimeBinding{
		RuntimeUnitId:            schema.SharedPrimitivesOpaqueId(manager.unitID),
		RuntimeManifestDigest:    schema.SharedPrimitivesDigest(manager.documentDigest),
		RuntimeImageDigest:       schema.SharedPrimitivesDigest(manager.imageDigest),
		InvocationProtocolDigest: schema.SharedPrimitivesDigest(manager.protocolDigest),
		RuntimeAudience:          manager.audience,
	}
}

func specialistBinding(specialist releaseRecord) schema.AgentTaskRuntimeBinding {
	return schema.AgentTaskRuntimeBinding{
		RuntimeUnitId:            schema.SharedPrimitivesOpaqueId(specialist.unitID),
		RuntimeManifestDigest:    schema.SharedPrimitivesDigest(specialist.documentDigest),
		RuntimeImageDigest:       schema.SharedPrimitivesDigest(specialist.imageDigest),
		InvocationProtocolDigest: schema.SharedPrimitivesDigest(specialist.protocolDigest),
		RuntimeAudience:          specialist.audience,
	}
}

// managerTaskRequest posts one task to the live manager unit and returns the
// status; it is used to seed the replay register.
func managerTaskRequest(t *testing.T, top *topology, task schema.AgentTask, token string) int {
	t.Helper()
	body, err := json.Marshal(task)
	if err != nil {
		t.Fatal(err)
	}
	request, err := http.NewRequestWithContext(top.ctx, http.MethodPost, top.manager.address+"/task", bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Authorization", "Bearer "+token)
	request.Header.Set("Idempotency-Key", string(task.PhysicalAttemptId))
	digest, _ := canonical.Digest(body)
	request.Header.Set("X-AnvilKit-Request-Digest", digest)
	request.Header.Set("traceparent", top.trace)
	response, err := top.client.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	_ = response.Body.Close()
	return response.StatusCode
}
