package api

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/ancyloce/anvilkit-agent-service/internal/agent"
	"github.com/ancyloce/anvilkit-agent-service/internal/auth"
	"github.com/ancyloce/anvilkit-agent-service/internal/authority"
	contractguard "github.com/ancyloce/anvilkit-agent-service/internal/contracts"
	"github.com/ancyloce/anvilkit-agent-service/internal/events"
	"github.com/ancyloce/anvilkit-agent-service/internal/journal"
	"github.com/ancyloce/anvilkit-agent-service/internal/problem"
	"github.com/ancyloce/anvilkit-agent-service/internal/runapp"
	"github.com/ancyloce/anvilkit-agent-service/internal/runs"
)

type verifier struct {
	claims auth.Claims
	err    error
}

func apiTestGuard(t *testing.T) *contractguard.Guard {
	t.Helper()
	guard, err := contractguard.NewGuard("../..")
	if err != nil {
		t.Fatal(err)
	}
	return guard
}

// apiTestDefinitions resolves any structurally valid reference; the api tests
// exercise transport behavior, not catalog membership.
type apiTestDefinitions struct{}

func (apiTestDefinitions) Resolve(reference agent.DefinitionReference) (agent.Definition, error) {
	return agent.Definition{DefinitionID: reference.DefinitionID, DefinitionDigest: reference.DefinitionDigest}, nil
}

func (v verifier) Verify(context.Context, string) (auth.Claims, error) { return v.claims, v.err }

type appClock struct{ now time.Time }

func (c appClock) Now() time.Time { return c.now }

type appTrust struct{}

func (appTrust) KeyActive(context.Context, string) (bool, error)                { return true, nil }
func (appTrust) SubjectActive(context.Context, string) (bool, error)            { return true, nil }
func (appTrust) DelegationActive(context.Context, string, string) (bool, error) { return true, nil }

type appStore struct{ snapshot runs.Snapshot }

func (s appStore) Create(context.Context, runs.CreateRecord) (runs.CreateOutcome, error) {
	return runs.CreateOutcome{}, nil
}
func (s appStore) Get(_ context.Context, _ runs.Scope, id runs.ID) (runs.Snapshot, error) {
	if id == "missing" {
		return runs.Snapshot{}, problem.New(problem.CodeResourceNotFound, "")
	}
	return s.snapshot, nil
}
func (s appStore) List(context.Context, runs.Scope, runs.ListOptions) (runs.Page, error) {
	return runs.Page{Items: []runs.Snapshot{s.snapshot}, PageInfo: runs.PageInfo{Limit: 50}}, nil
}
func (s appStore) Transition(context.Context, runs.Scope, runs.ID, uint64, runs.Command) (runs.Snapshot, error) {
	return s.snapshot, nil
}

type appStarter struct{}

func (appStarter) Ensure(context.Context, runs.Start) error { return nil }

type appIDs struct{}

func (appIDs) NewID() (runs.ID, error) { return "run", nil }

type appEvents struct{}

func (appEvents) Replay(_ context.Context, request events.ReplayRequest) (events.ReplayPage, error) {
	if request.AfterEventID == "expired-cursor" {
		return events.ReplayPage{}, events.CursorExpired()
	}
	return events.ReplayPage{}, nil
}
func (appEvents) Snapshot(context.Context, events.Scope, string) (events.SnapshotProjection, error) {
	return events.SnapshotProjection{Run: json.RawMessage(canonicalRunDocument), Cursor: "run:2"}, nil
}

// canonicalRunDocument is a complete AgentRun as the authoritative store holds
// one. The snapshot recovery response is proved against its canonical
// contract before it leaves the service, so the fake has to answer with a real
// resource rather than a stub.
const canonicalRunDocument = `{
  "kind": "AgentRun",
  "runId": "run",
  "rootRunId": "run",
  "workspaceId": "workspace",
  "actorId": "actor",
  "domain": "platform-agent",
  "operation": "artifact-validation",
  "target": {"targetType": "page", "targetId": "page.1", "workspaceId": "workspace", "projectId": "project"},
  "definition": {"definitionId": "definition.1", "definitionDigest": "sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd"},
  "contractBomReference": {"repository": "anvilkit/contracts", "bomDigest": "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "ociManifestDigest": "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", "evidenceManifestDigest": "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"},
  "policy": {"policyId": "policy.1", "version": "v1", "digest": "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"},
  "budget": {
    "kind": "AgentBudget",
    "modelLimits": {"maximumCalls": 10, "maximumConcurrentCalls": 2},
    "tokenLimits": {"inputTokens": 4096, "outputTokens": 2048, "totalTokens": 6144},
    "workerLimits": {"maximumAttempts": 4, "maximumDurationMilliseconds": 60000},
    "gpuLimits": {"maximumGpuMilliseconds": 0},
    "currencyLimits": {"maximumCost": {"amount": "1000", "currency": "USD"}, "reservedCost": {"amount": "500", "currency": "USD"}},
    "reservationId": "reservation.1",
    "exceedBehavior": "refuse",
    "policy": {"policyId": "policy.1", "version": "v1", "digest": "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}
  },
  "idempotency": {"scope": "workspace:create-run", "key": "idem.1", "canonicalRequestDigest": "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"},
  "status": "created",
  "executionGeneration": 0,
  "resourceRevision": 0,
  "createdAt": "2026-08-09T12:00:00.000Z",
  "updatedAt": "2026-08-09T12:00:00.000Z"
}`

func (appEvents) Wait(context.Context, events.Scope, string, uint64, time.Duration) error { return nil }

type appAuthority struct{}

func (appAuthority) Current(context.Context, authority.Scope) (authority.Current, error) {
	return authority.Current{
		Definition:       []byte(`{"definitionId":"definition.test","definitionDigest":"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}`),
		ContractBOM:      []byte(`{"bom":"test"}`),
		Policy:           []byte(`{"policyId":"policy.test","version":"v1"}`),
		Budget:           []byte(`{"budget":"test"}`),
		WorkspaceActive:  true,
		ActorActive:      true,
		PermissionActive: true,
		PolicyActive:     true,
	}, nil
}

func TestCandidateReadRoutesRequireVerifiedBearerAndEmitStrongETag(t *testing.T) {
	now := time.Now()
	validator, _ := auth.NewValidator(auth.Config{Issuers: []string{"issuer"}, Audience: "agent"}, appTrust{}, appClock{now})
	service := runs.NewService(appStore{snapshot: runs.Snapshot{RunID: "run", WorkspaceID: "workspace", Version: 2}}, appStarter{}, appIDs{}, appClock{now}, journal.NewMemoryStore(), runs.AdmitFunc(func(context.Context, runs.Scope) error { return nil }))
	core := runapp.New(validator, service, appEvents{}, events.StreamConfig{Heartbeat: time.Second, Revalidation: time.Second, ReplayLimit: 10, Bounds: events.Bounds{MaximumBytes: 100}}, appAuthority{}, apiTestGuard(t), apiTestDefinitions{})
	claims := auth.Claims{Verified: true, Source: auth.SourceWorkload, Issuer: "issuer", Audience: "agent", Subject: "actor", ActorID: "actor", WorkspaceID: "workspace", ProjectID: "project", Purpose: "agent", KeyID: "key", Scopes: []string{auth.ScopeRead}, ExpiresAt: now.Add(time.Hour)}
	handler := New(nil, WithAgentCore(core, verifier{claims: claims}))
	request := httptest.NewRequest(http.MethodGet, "/v1/workspaces/workspace/agent-runs/run", nil)
	request.Header.Set("Authorization", "Bearer verified")
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusOK || response.Header().Get("ETag") != `"run:v2"` {
		t.Fatalf("status=%d etag=%q body=%s", response.Code, response.Header().Get("ETag"), response.Body.String())
	}
	request = httptest.NewRequest(http.MethodGet, "/v1/workspaces/workspace/agent-runs/run", nil)
	response = httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusUnauthorized || !strings.Contains(response.Body.String(), "AUTHENTICATION_INVALID") {
		t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
	}
	var details problem.Details
	if err := json.Unmarshal(response.Body.Bytes(), &details); err != nil || len(details.TraceID) != 32 {
		t.Fatalf("protected failure lacks trace reference: %#v err=%v", details, err)
	}
}

func TestMutationTransportRemainsFailClosedWhileGateDOpen(t *testing.T) {
	handler := New(nil, WithAgentCore(nil, nil))
	request := httptest.NewRequest(http.MethodPost, "/v1/workspaces/workspace/agent-runs", strings.NewReader(`{}`))
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusServiceUnavailable || !strings.Contains(response.Body.String(), "INFRASTRUCTURE_UNAVAILABLE") {
		t.Fatalf("unwired mutation status=%d", response.Code)
	}
}

func TestNonSuccessResponsesHaveStableClosedProblemShapeAndDoNotDiscloseScope(t *testing.T) {
	now := time.Now()
	validator, _ := auth.NewValidator(auth.Config{Issuers: []string{"issuer"}, Audience: "agent"}, appTrust{}, appClock{now})
	service := runs.NewService(appStore{snapshot: runs.Snapshot{RunID: "run", WorkspaceID: "workspace", Version: 2}}, appStarter{}, appIDs{}, appClock{now}, journal.NewMemoryStore(), runs.AdmitFunc(func(context.Context, runs.Scope) error { return nil }))
	core := runapp.New(validator, service, appEvents{}, events.StreamConfig{Heartbeat: time.Second, Revalidation: time.Second, ReplayLimit: 10, Bounds: events.DefaultBounds()}, appAuthority{}, apiTestGuard(t), apiTestDefinitions{})
	claims := auth.Claims{Verified: true, Source: auth.SourceWorkload, Issuer: "issuer", Audience: "agent", Subject: "actor", ActorID: "actor", WorkspaceID: "workspace", ProjectID: "project", Purpose: "agent", KeyID: "key", Scopes: []string{auth.ScopeRead}, ExpiresAt: now.Add(time.Hour)}
	handler := New(nil, WithAgentCore(core, verifier{claims: claims}))

	request := httptest.NewRequest(http.MethodGet, "/v1/workspaces/workspace/agent-runs/missing", nil)
	request.Header.Set("Authorization", "Bearer verified")
	missing := httptest.NewRecorder()
	handler.ServeHTTP(missing, request)
	missingProblem := assertClosedProblem(t, missing, problem.CodeResourceNotFound)

	request = httptest.NewRequest(http.MethodGet, "/v1/workspaces/other/agent-runs/run", nil)
	request.Header.Set("Authorization", "Bearer verified")
	forbidden := httptest.NewRecorder()
	handler.ServeHTTP(forbidden, request)
	forbiddenProblem := assertClosedProblem(t, forbidden, problem.CodeResourceNotFound)
	delete(missingProblem, "traceId")
	delete(forbiddenProblem, "traceId")
	missingRaw, _ := json.Marshal(missingProblem)
	forbiddenRaw, _ := json.Marshal(forbiddenProblem)
	if string(missingRaw) != string(forbiddenRaw) || strings.Contains(forbidden.Body.String(), "other") || strings.Contains(forbidden.Body.String(), "workspace") {
		t.Fatalf("cross-scope response disclosed authority: missing=%s forbidden=%s", missing.Body.String(), forbidden.Body.String())
	}

	request = httptest.NewRequest(http.MethodGet, "/v1/workspaces/workspace/agent-runs", nil)
	unauthenticated := httptest.NewRecorder()
	handler.ServeHTTP(unauthenticated, request)
	assertClosedProblem(t, unauthenticated, problem.CodeAuthenticationInvalid)

	request = httptest.NewRequest(http.MethodGet, "/v1/workspaces/workspace/agent-runs?unknown=true", nil)
	request.Header.Set("Authorization", "Bearer verified")
	invalid := httptest.NewRecorder()
	handler.ServeHTTP(invalid, request)
	assertClosedProblem(t, invalid, problem.CodeRequestInvalid)
}

func assertClosedProblem(t *testing.T, response *httptest.ResponseRecorder, code problem.Code) map[string]any {
	t.Helper()
	if response.Header().Get("Content-Type") != "application/problem+json" {
		t.Fatalf("problem content type=%q body=%s", response.Header().Get("Content-Type"), response.Body.String())
	}
	var payload map[string]any
	if err := json.Unmarshal(response.Body.Bytes(), &payload); err != nil {
		t.Fatal(err)
	}
	wantFields := []string{"kind", "code", "retryability", "message", "fieldErrors", "traceId"}
	if len(payload) != len(wantFields) {
		t.Fatalf("problem fields=%v", payload)
	}
	for _, field := range wantFields {
		if _, ok := payload[field]; !ok {
			t.Fatalf("problem omits %s: %v", field, payload)
		}
	}
	if payload["code"] != string(code) || len(payload["traceId"].(string)) != 32 {
		t.Fatalf("problem=%v want code=%s", payload, code)
	}
	return payload
}

// The snapshot endpoint is the documented recovery path for an expired
// durable cursor: a cursor beyond retention answers 410, and the snapshot
// answers the current resource with the cursor to resume from.
func TestExpiredCursorAnswers410AndSnapshotIsTheRecoveryPath(t *testing.T) {
	now := time.Now()
	validator, _ := auth.NewValidator(auth.Config{Issuers: []string{"issuer"}, Audience: "agent"}, appTrust{}, appClock{now})
	service := runs.NewService(appStore{snapshot: runs.Snapshot{RunID: "run", WorkspaceID: "workspace", Version: 2}}, appStarter{}, appIDs{}, appClock{now}, journal.NewMemoryStore(), runs.AdmitFunc(func(context.Context, runs.Scope) error { return nil }))
	core := runapp.New(validator, service, appEvents{}, events.StreamConfig{Heartbeat: time.Second, Revalidation: time.Second, ReplayLimit: 10, Bounds: events.DefaultBounds()}, appAuthority{}, apiTestGuard(t), apiTestDefinitions{})
	claims := auth.Claims{Verified: true, Source: auth.SourceWorkload, Issuer: "issuer", Audience: "agent", Subject: "actor", ActorID: "actor", WorkspaceID: "workspace", ProjectID: "project", Purpose: "agent", KeyID: "key", Scopes: []string{auth.ScopeRead}, ExpiresAt: now.Add(time.Hour)}
	handler := New(nil, WithAgentCore(core, verifier{claims: claims}))

	expired := httptest.NewRequest(http.MethodGet, "/v1/workspaces/workspace/agent-runs/run/events", nil)
	expired.Header.Set("Authorization", "Bearer verified")
	expired.Header.Set("Last-Event-ID", "expired-cursor")
	expiredResponse := httptest.NewRecorder()
	handler.ServeHTTP(expiredResponse, expired)
	if expiredResponse.Code != http.StatusGone || !strings.Contains(expiredResponse.Body.String(), "EVENT_CURSOR_EXPIRED") {
		t.Fatalf("expired cursor status=%d body=%s", expiredResponse.Code, expiredResponse.Body.String())
	}
	// The recovery path is discoverable from the response itself, and it is
	// scoped to the workspace and run the caller already proved authority for.
	const wantLink = `</v1/workspaces/workspace/agent-runs/run/snapshot>; rel="urn:anvilkit:relation:run-snapshot"`
	if expiredResponse.Header().Get("Link") != wantLink {
		t.Fatalf("expired cursor Link=%q, want %q", expiredResponse.Header().Get("Link"), wantLink)
	}

	snapshot := httptest.NewRequest(http.MethodGet, "/v1/workspaces/workspace/agent-runs/run/snapshot", nil)
	snapshot.Header.Set("Authorization", "Bearer verified")
	snapshotResponse := httptest.NewRecorder()
	handler.ServeHTTP(snapshotResponse, snapshot)
	if snapshotResponse.Code != http.StatusOK || !strings.Contains(snapshotResponse.Body.String(), `"cursor":"run:2"`) {
		t.Fatalf("snapshot status=%d body=%s", snapshotResponse.Code, snapshotResponse.Body.String())
	}
	// The recovery response is the governed contract, not an ad-hoc shape:
	// it declares its kind and carries the artifact collection even when the
	// run has none.
	if !strings.Contains(snapshotResponse.Body.String(), `"kind":"AgentRunSnapshot"`) || !strings.Contains(snapshotResponse.Body.String(), `"artifacts":[]`) {
		t.Fatalf("snapshot body is not the canonical recovery document: %s", snapshotResponse.Body.String())
	}
}
