package api

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/ancyloce/anvilkit-agent-service/internal/auth"
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

func (appEvents) Replay(context.Context, events.ReplayRequest) (events.ReplayPage, error) {
	return events.ReplayPage{}, nil
}
func (appEvents) Snapshot(context.Context, events.Scope, string) (events.SnapshotProjection, error) {
	return events.SnapshotProjection{}, nil
}
func (appEvents) Wait(context.Context, events.Scope, string, uint64, time.Duration) error { return nil }

type appAuthority struct{}

func (appAuthority) Current(context.Context, runs.Scope) (runs.Authority, error) {
	return runs.Authority{}, nil
}

func TestCandidateReadRoutesRequireVerifiedBearerAndEmitStrongETag(t *testing.T) {
	now := time.Now()
	validator, _ := auth.NewValidator(auth.Config{Issuers: []string{"issuer"}, Audience: "agent"}, appTrust{}, appClock{now})
	service := runs.NewService(appStore{snapshot: runs.Snapshot{RunID: "run", WorkspaceID: "workspace", Version: 2}}, appStarter{}, appIDs{}, appClock{now}, journal.NewMemoryStore())
	core := runapp.New(validator, service, appEvents{}, events.StreamConfig{Heartbeat: time.Second, Revalidation: time.Second, ReplayLimit: 10, Bounds: events.Bounds{MaximumBytes: 100}}, appAuthority{})
	claims := auth.Claims{Verified: true, Source: auth.SourceWorkload, Issuer: "issuer", Audience: "agent", Subject: "actor", ActorID: "actor", TenantID: "tenant", WorkspaceID: "workspace", ProjectID: "project", Purpose: "agent", KeyID: "key", Scopes: []string{auth.ScopeRead}, ExpiresAt: now.Add(time.Hour)}
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
	service := runs.NewService(appStore{snapshot: runs.Snapshot{RunID: "run", WorkspaceID: "workspace", Version: 2}}, appStarter{}, appIDs{}, appClock{now}, journal.NewMemoryStore())
	core := runapp.New(validator, service, appEvents{}, events.StreamConfig{Heartbeat: time.Second, Revalidation: time.Second, ReplayLimit: 10, Bounds: events.DefaultBounds()}, appAuthority{})
	claims := auth.Claims{Verified: true, Source: auth.SourceWorkload, Issuer: "issuer", Audience: "agent", Subject: "actor", ActorID: "actor", TenantID: "tenant", WorkspaceID: "workspace", ProjectID: "project", Purpose: "agent", KeyID: "key", Scopes: []string{auth.ScopeRead}, ExpiresAt: now.Add(time.Hour)}
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
	wantFields := []string{"apiVersion", "kind", "code", "retryability", "message", "fieldErrors", "traceId"}
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
