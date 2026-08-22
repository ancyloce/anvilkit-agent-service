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

// Every operation the router names reaches a production handler.
//
// The routing table and the canonical description are checked against each
// other by the repository gate, and the router resolves through the table
// before dispatching — but neither of those says a handler exists on the other
// side of the dispatch. Both halves passed while two governed operations were
// declared, routed, documented, and answered by the fallthrough that means
// "declared, and nothing here handles it".
//
// That fallthrough is the only thing asserted here. Whatever the handler
// decides is fine — a refusal, a missing precondition, an unbound dependency —
// because those are decisions something made about the request. What must
// never come back is the router reporting that it found nobody, and that is
// exactly the answer the two missing operations used to produce.
//
// It is driven through the real HTTP surface with the real application core,
// so what is exercised is the composition a request actually meets rather than
// a table read back to itself.
func TestEveryRoutedOperationReachesAProductionHandler(t *testing.T) {
	handler, _ := routingConformanceHandler(t)
	for _, operation := range Operations() {
		t.Run(operation.ID, func(t *testing.T) {
			response := httptest.NewRecorder()
			handler.ServeHTTP(response, routingConformanceRequest(operation))
			if detail := unroutedDetailOf(t, response); detail != "" {
				t.Fatalf("%s %s reached no production handler: %s", operation.Method, operation.Template, detail)
			}
			if response.Code == 0 {
				t.Fatalf("%s %s produced no answer at all", operation.Method, operation.Template)
			}
		})
	}
}

// And the fallthrough is still reachable, so the assertion above is a real
// check rather than one that could never fail. A path the router serves whose
// sub-resource nothing handles is the shape the missing operations had.
func TestTheUnhandledOperationAnswerIsStillReachable(t *testing.T) {
	handler, claims := routingConformanceHandler(t)
	_ = claims
	// The artifact surface serves two shapes and answers the unhandled
	// fallthrough for anything else beneath a workspace's artifact — which is
	// what a declared-but-unhandled artifact operation would meet.
	request := httptest.NewRequest(http.MethodPut, ServedPrefix+"/workspaces/workspace/artifacts/artifact-01/custody", strings.NewReader("{}"))
	request.Header.Set("Authorization", "Bearer verified")
	request.Header.Set("traceparent", routingConformanceTrace)
	response := httptest.NewRecorder()
	// The router refuses it before dispatch because the table does not name
	// that method, so the fallthrough is reached through the handler directly:
	// what is being proved is that the detector below sees the answer when it
	// is produced.
	handlerServeArtifactUnhandled(t, handler, response)
	if detail := unroutedDetailOf(t, response); detail == "" {
		t.Fatalf("the unhandled-operation answer was not recognised: status=%d body=%s", response.Code, response.Body.String())
	}
}

// handlerServeArtifactUnhandled drives the artifact surface at a sub-resource
// nothing handles, which is the shape a declared-but-unhandled operation has.
func handlerServeArtifactUnhandled(t *testing.T, handler *Handler, response *httptest.ResponseRecorder) {
	t.Helper()
	request := httptest.NewRequest(http.MethodPost, ServedPrefix+"/workspaces/workspace/artifacts/artifact-01/retention", strings.NewReader("{}"))
	request.Header.Set("traceparent", routingConformanceTrace)
	handler.serveArtifact(response, request, auth.Claims{}, strings.Split(strings.Trim(request.URL.Path, "/"), "/"))
}

// routingConformanceTrace is a well-formed trace so a request is refused for
// what it is about rather than for the header it forgot.
const routingConformanceTrace = "00-11111111111111111111111111111111-2222222222222222-01"

// routingConformanceHandler composes the real transport over the real
// application core. The optional surfaces are deliberately left unbound: an
// unbound surface answers as unavailable, which is a decision a handler made,
// and the assertion is only ever about the router finding nobody.
func routingConformanceHandler(t *testing.T) (*Handler, auth.Claims) {
	t.Helper()
	now := time.Now()
	validator, err := auth.NewValidator(auth.Config{Issuers: []string{"issuer"}, Audience: "agent"}, appTrust{}, appClock{now})
	if err != nil {
		t.Fatal(err)
	}
	service := runs.NewService(
		appStore{snapshot: runs.Snapshot{RunID: "run", WorkspaceID: "workspace", Version: 2}},
		appStarter{}, appIDs{}, appClock{now}, journal.NewMemoryStore(),
		runs.AdmitFunc(func(ctx context.Context, _ runs.Scope) error { return nil }),
	)
	core := runapp.New(validator, service, appEvents{},
		events.StreamConfig{Heartbeat: time.Second, Revalidation: time.Second, ReplayLimit: 10, Bounds: events.DefaultBounds()},
		appAuthority{}, apiTestGuard(t), apiTestDefinitions{})
	claims := auth.Claims{
		Verified: true, Source: auth.SourceWorkload, Issuer: "issuer", Audience: "agent",
		Subject: "actor", ActorID: "actor", WorkspaceID: "workspace", ProjectID: "project",
		Purpose: "agent", KeyID: "key", Scopes: []string{auth.ScopeRead, auth.ScopeWrite},
		ExpiresAt: now.Add(time.Hour),
	}
	return New(nil, WithAgentCore(core, verifier{claims: claims})), claims
}

// routingConformanceRequest addresses one operation with everything transport
// needs to get past its own header checks: the concurrency, idempotency,
// digest, purpose, and trace headers every mutating or disclosing operation
// declares. A request refused for a missing header would never reach the
// handler, and this test would then prove nothing.
func routingConformanceRequest(operation Operation) *http.Request {
	path := ServedPrefix + instantiateTemplate(operation.Template)
	var body *strings.Reader
	if operation.Method == http.MethodPost {
		body = strings.NewReader("{}")
	} else {
		body = strings.NewReader("")
	}
	request := httptest.NewRequest(operation.Method, path, body)
	request.Header.Set("Authorization", "Bearer verified")
	request.Header.Set("traceparent", routingConformanceTrace)
	request.Header.Set("Idempotency-Key", "routing-conformance")
	request.Header.Set("X-AnvilKit-Request-Digest", "sha256:"+strings.Repeat("a", 64))
	request.Header.Set("If-Match", `"run:v2"`)
	request.Header.Set("X-AnvilKit-Access-Purpose", "read")
	return request
}

// instantiateTemplate turns a path template into a concrete path.
func instantiateTemplate(template string) string {
	segments := strings.Split(strings.TrimPrefix(template, "/"), "/")
	for index, segment := range segments {
		if strings.HasPrefix(segment, "{") && strings.HasSuffix(segment, "}") {
			segments[index] = "identifier-" + strings.Trim(segment, "{}")
		}
	}
	return "/" + strings.Join(segments, "/")
}

// unroutedDetailOf returns the router's "declared but unhandled" detail when a
// response carries it, and the empty string otherwise.
func unroutedDetailOf(t *testing.T, response *httptest.ResponseRecorder) string {
	t.Helper()
	if response.Code != http.StatusNotFound {
		return ""
	}
	var details problem.Details
	if err := json.Unmarshal(response.Body.Bytes(), &details); err != nil {
		return ""
	}
	if strings.Contains(details.Detail, unroutedDetail) {
		return details.Detail
	}
	return ""
}
