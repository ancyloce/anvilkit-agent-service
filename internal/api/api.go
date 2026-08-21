// Package api owns HTTP transport only; it delegates all decisions inward.
package api

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"strings"
	"sync/atomic"
	"time"

	contractvalidator "github.com/ancyloce/anvilkit-agent-service/contracts/validator"
	"github.com/ancyloce/anvilkit-agent-service/internal/auth"
	"github.com/ancyloce/anvilkit-agent-service/internal/problem"
	"github.com/ancyloce/anvilkit-agent-service/internal/runapp"
)

type Readiness interface {
	ServeHTTP(http.ResponseWriter, *http.Request)
}

type TokenVerifier interface {
	Verify(context.Context, string) (auth.Claims, error)
}
type Handler struct {
	readiness Readiness
	draining  atomic.Bool
	core      *runapp.App
	verifier  TokenVerifier
}

type Option func(*Handler)

func WithAgentCore(core *runapp.App, verifier TokenVerifier) Option {
	return func(handler *Handler) { handler.core, handler.verifier = core, verifier }
}
func New(readiness Readiness, options ...Option) *Handler {
	handler := &Handler{readiness: readiness}
	for _, option := range options {
		option(handler)
	}
	return handler
}

func (h *Handler) ServeHTTP(response http.ResponseWriter, request *http.Request) {
	if request.URL.Path == "/healthz" {
		response.WriteHeader(http.StatusOK)
		return
	}
	if request.URL.Path == "/readyz" && h.readiness != nil {
		h.readiness.ServeHTTP(response, request)
		return
	}
	ensureTraceparent(request)
	if h.draining.Load() {
		response.Header().Set("Retry-After", "5")
		writeProblem(response, problem.New(problem.CodeInfrastructureUnavailable, request.Header.Get("traceparent")), request.Header.Get("traceparent"))
		return
	}
	if strings.HasPrefix(request.URL.Path, "/v1/") {
		if h.core != nil && h.verifier != nil && strings.HasPrefix(request.URL.Path, "/v1/workspaces/") {
			h.serveAgent(response, request)
			return
		}
		writeProblem(response, problem.New(problem.CodeInfrastructureUnavailable, request.Header.Get("traceparent")), request.Header.Get("traceparent"))
		return
	}
	http.NotFound(response, request)
}

func (h *Handler) serveAgent(response http.ResponseWriter, request *http.Request) {
	claims, err := h.verify(request)
	if err != nil {
		writeProblem(response, err, request.Header.Get("traceparent"))
		return
	}
	parts := strings.Split(strings.Trim(request.URL.Path, "/"), "/")
	if len(parts) < 4 || parts[0] != "v1" || parts[1] != "workspaces" || parts[3] != "agent-runs" {
		writeProblem(response, problem.New(problem.CodeResourceNotFound, request.Header.Get("traceparent")), request.Header.Get("traceparent"))
		return
	}
	workspaceID := parts[2]
	if len(parts) == 4 && request.Method == http.MethodGet {
		for name := range request.URL.Query() {
			if name != "cursor" && name != "limit" {
				writeProblem(response, problem.New(problem.CodeRequestInvalid, request.Header.Get("traceparent")), request.Header.Get("traceparent"))
				return
			}
		}
		limit, err := runapp.ParseLimit(request.URL.Query().Get("limit"))
		if err != nil {
			writeProblem(response, problem.New(problem.CodeRequestInvalid, ""), request.Header.Get("traceparent"))
			return
		}
		result, err := h.core.List(request.Context(), claims, workspaceID, request.URL.Query().Get("cursor"), limit, "")
		h.writeRepresentation(response, result, err, request)
		return
	}
	if len(parts) == 4 && request.Method == http.MethodPost {
		raw, err := io.ReadAll(http.MaxBytesReader(response, request.Body, 1<<20))
		if err != nil {
			writeProblem(response, problem.New(problem.CodeRequestInvalid, ""), request.Header.Get("traceparent"))
			return
		}
		result, err := h.core.Create(request.Context(), claims, workspaceID, request.Header.Get("Idempotency-Key"), request.Header.Get("X-AnvilKit-Request-Digest"), request.Header.Get("traceparent"), raw)
		// The first successful creation answers 201 with the resource
		// location; a replayed key answers the recorded result (ADR-021).
		if err == nil && result.RunID != "" && !result.Replayed {
			response.Header().Set("Location", request.URL.Path+"/"+result.RunID)
			h.writeRepresentationStatus(response, result, err, request, http.StatusCreated)
			return
		}
		h.writeRepresentation(response, result, err, request)
		return
	}
	if len(parts) == 5 && request.Method == http.MethodGet {
		result, err := h.core.Get(request.Context(), claims, workspaceID, parts[4])
		h.writeRepresentation(response, result, err, request)
		return
	}
	if len(parts) == 6 && parts[5] == "snapshot" && request.Method == http.MethodGet {
		result, err := h.core.Snapshot(request.Context(), claims, workspaceID, parts[4])
		h.writeRepresentation(response, result, err, request)
		return
	}
	if len(parts) == 6 && parts[5] == "events" && request.Method == http.MethodGet {
		tracked := &trackedResponse{ResponseWriter: response}
		if err := h.core.Stream(request.Context(), claims, workspaceID, parts[4], request.Header.Get("Last-Event-ID"), tracked); err != nil {
			if !tracked.wrote {
				linkCursorRecovery(response, err, request.URL.Path)
				writeProblem(response, err, request.Header.Get("traceparent"))
			}
		}
		return
	}
	// The governed AgentRun mutation surface is part of the production API.
	// Authentication, authorization, If-Match concurrency, idempotency,
	// canonical schema validation, and bounded-body enforcement each fail
	// closed on their own; no feature gate stands in front of them.
	if request.Method == http.MethodPost && len(parts) >= 6 {
		input := runapp.ControlInput{WorkspaceID: workspaceID, RunID: parts[4], ETag: request.Header.Get("If-Match"), Key: request.Header.Get("Idempotency-Key"), Digest: request.Header.Get("X-AnvilKit-Request-Digest"), Traceparent: request.Header.Get("traceparent")}
		if len(parts) == 6 && (parts[5] == "cancel" || parts[5] == "retry" || parts[5] == "discard") {
			if request.Body != nil {
				raw, readErr := io.ReadAll(http.MaxBytesReader(response, request.Body, 1))
				if readErr != nil || len(raw) != 0 {
					writeProblem(response, problem.New(problem.CodeRequestInvalid, ""), request.Header.Get("traceparent"))
					return
				}
			}
			var result runapp.Representation
			switch parts[5] {
			case "cancel":
				result, err = h.core.Cancel(request.Context(), claims, input)
			case "retry":
				result, err = h.core.Retry(request.Context(), claims, input)
			case "discard":
				result, err = h.core.Discard(request.Context(), claims, input)
			}
			h.writeRepresentation(response, result, err, request)
			return
		}
		if len(parts) == 8 && parts[5] == "inputs" && parts[7] == "responses" {
			raw, err := readBoundedCommand(response, request)
			if err != nil {
				writeProblem(response, err, request.Header.Get("traceparent"))
				return
			}
			result, err := h.core.RespondInput(request.Context(), claims, input, parts[6], raw)
			h.writeRepresentation(response, result, err, request)
			return
		}
		// Operator recovery of a durably escalated governed effect. The
		// operation identity is in the path, so the decision is bound to the
		// exact submission the operator reviewed; the resolving operator is
		// never in the body — the application derives it from the verified
		// request authority.
		if len(parts) == 8 && parts[5] == "domain-operations" && parts[7] == "resolution" {
			// Transport hands the bounded canonical bytes inward untouched:
			// the application validates them against the pinned
			// ResolveDomainOperationRequest contract before decoding anything.
			raw, err := readBoundedCommand(response, request)
			if err != nil {
				writeProblem(response, err, request.Header.Get("traceparent"))
				return
			}
			result, err := h.core.ResolveEscalation(request.Context(), claims, input, parts[6], raw)
			h.writeRepresentation(response, result, err, request)
			return
		}
		if len(parts) == 8 && parts[5] == "approvals" && parts[7] == "decisions" {
			raw, err := readBoundedCommand(response, request)
			if err != nil {
				writeProblem(response, err, request.Header.Get("traceparent"))
				return
			}
			result, err := h.core.DecideApproval(request.Context(), claims, input, parts[6], raw)
			h.writeRepresentation(response, result, err, request)
			return
		}
	}
	writeProblem(response, problem.New(problem.CodeResourceNotFound, request.Header.Get("traceparent")), request.Header.Get("traceparent"))
}

// readBoundedCommand reads one bounded command body and admits it as strict
// canonical JSON without interpreting it.
func readBoundedCommand(response http.ResponseWriter, request *http.Request) ([]byte, error) {
	raw, err := io.ReadAll(http.MaxBytesReader(response, request.Body, 64*1024))
	if err != nil {
		return nil, problem.New(problem.CodeRequestInvalid, "")
	}
	if _, err := contractvalidator.Admit(raw); err != nil {
		return nil, problem.New(problem.CodeRequestInvalid, "")
	}
	return raw, nil
}

func decodeBoundedCommand(response http.ResponseWriter, request *http.Request, target any) error {
	raw, err := readBoundedCommand(response, request)
	if err != nil {
		return err
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return problem.New(problem.CodeRequestInvalid, "")
	}
	var extra any
	if err := decoder.Decode(&extra); err != io.EOF {
		return problem.New(problem.CodeRequestInvalid, "")
	}
	return nil
}

func (h *Handler) verify(request *http.Request) (auth.Claims, error) {
	header := request.Header.Get("Authorization")
	if !strings.HasPrefix(header, "Bearer ") || len(header) <= 7 {
		return auth.Claims{}, problem.New(problem.CodeAuthenticationInvalid, "")
	}
	claims, err := h.verifier.Verify(request.Context(), header[7:])
	if err != nil {
		return auth.Claims{}, problem.New(problem.CodeAuthenticationInvalid, request.Header.Get("traceparent"))
	}
	return claims, nil
}
func (h *Handler) writeRepresentation(response http.ResponseWriter, result runapp.Representation, err error, request *http.Request) {
	h.writeRepresentationStatus(response, result, err, request, http.StatusOK)
}

func (h *Handler) writeRepresentationStatus(response http.ResponseWriter, result runapp.Representation, err error, request *http.Request, status int) {
	if err != nil {
		writeProblem(response, err, request.Header.Get("traceparent"))
		return
	}
	response.Header().Set("Content-Type", "application/json")
	if result.ETag != "" {
		response.Header().Set("ETag", result.ETag)
	}
	if result.Digest != "" {
		response.Header().Set("X-AnvilKit-Request-Digest", result.Digest)
	}
	if result.Replayed {
		response.Header().Set("Idempotency-Replayed", "true")
	}
	response.WriteHeader(status)
	_, _ = response.Write(result.Body)
}

// snapshotRecoveryRelation is the RFC 8288 relation type the canonical Agent
// Service description declares for the run snapshot an expired event cursor
// recovers through.
const snapshotRecoveryRelation = "urn:anvilkit:relation:run-snapshot"

// linkCursorRecovery names the tenant- and run-scoped snapshot operation on an
// expired-cursor response. The recovery path is derived from the stream route
// the caller already proved authority for, so the link a client discovers can
// only ever point at its own run.
func linkCursorRecovery(response http.ResponseWriter, err error, streamPath string) {
	var details problem.Details
	if !errors.As(err, &details) || details.Code != string(problem.CodeCursorExpired) {
		return
	}
	response.Header().Set("Link", "<"+strings.TrimSuffix(streamPath, "/events")+"/snapshot>; rel=\""+snapshotRecoveryRelation+"\"")
}

func writeProblem(response http.ResponseWriter, err error, traceReference string) {
	var details problem.Details
	if !errors.As(err, &details) {
		details = problem.Internal(traceReference)
	}
	if details.TraceID == "" {
		details.TraceID = traceReference
	}
	response.Header().Set("Content-Type", "application/problem+json")
	response.WriteHeader(details.Status)
	_ = json.NewEncoder(response).Encode(details)
}

func ensureTraceparent(request *http.Request) {
	if validTraceparent(request.Header.Get("traceparent")) {
		return
	}
	trace := make([]byte, 16)
	span := make([]byte, 8)
	if _, err := rand.Read(trace); err != nil {
		trace[15] = 1
	}
	if _, err := rand.Read(span); err != nil {
		span[7] = 1
	}
	request.Header.Set("traceparent", "00-"+hex.EncodeToString(trace)+"-"+hex.EncodeToString(span)+"-01")
}

func validTraceparent(value string) bool {
	parts := strings.Split(value, "-")
	if len(parts) != 4 || len(parts[0]) != 2 || len(parts[1]) != 32 || len(parts[2]) != 16 || len(parts[3]) != 2 {
		return false
	}
	for _, part := range parts {
		if _, err := hex.DecodeString(part); err != nil || strings.ToLower(part) != part {
			return false
		}
	}
	return parts[1] != strings.Repeat("0", 32) && parts[2] != strings.Repeat("0", 16)
}

type trackedResponse struct {
	http.ResponseWriter
	wrote bool
}

func (r *trackedResponse) WriteHeader(status int) {
	r.wrote = true
	r.ResponseWriter.WriteHeader(status)
}
func (r *trackedResponse) Write(body []byte) (int, error) {
	r.wrote = true
	return r.ResponseWriter.Write(body)
}

// Unwrap exposes the writer underneath so http.ResponseController can reach
// the server's own deadline and flush support through this wrapper. Without
// it a long-lived stream would silently lose both: write deadlines would be
// unavailable and every flush would look successful.
func (r *trackedResponse) Unwrap() http.ResponseWriter { return r.ResponseWriter }

// FlushError flushes through the underlying writer and reports what happened.
// It deliberately replaces a plain Flush: an http.Flusher on a wrapper makes
// http.ResponseController stop unwrapping and report success unconditionally,
// which is exactly how a failed hand-off to a stalled consumer becomes
// invisible.
func (r *trackedResponse) FlushError() error {
	r.wrote = true
	return http.NewResponseController(r.ResponseWriter).Flush()
}

func (h *Handler) BeginDrain() { h.draining.Store(true) }

type Server struct{ server *http.Server }

func NewServer(address string, handler http.Handler) *Server {
	return &Server{server: &http.Server{Addr: address, Handler: handler, ReadHeaderTimeout: 5 * time.Second}}
}
func (s *Server) Run() error                         { return s.server.ListenAndServe() }
func (s *Server) Serve(listener net.Listener) error  { return s.server.Serve(listener) }
func (s *Server) Shutdown(ctx context.Context) error { return s.server.Shutdown(ctx) }
