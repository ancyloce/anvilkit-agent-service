// Package runtimeboundary is the Agent Service side of the canonical runtime
// boundary: the four internal operations a dispatched Manager or Specialist
// calls back on — governed model invocations, candidate submission, artifact
// content grants, and governed contract-runtime invocations.
//
// Every request is admitted the way the runtime units admit a task: the bearer
// is the task-scoped credential this service itself issued for one physical
// attempt, verified against the operator trust root and bound to the dispatched
// task before anything else is read. A unit holds no other authority, so this
// boundary accepts no other.
package runtimeboundary

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/ancyloce/anvilkit-agent-service/contracts/generated/schema"
	"github.com/ancyloce/anvilkit-agent-service/internal/agent"
	"github.com/ancyloce/anvilkit-agent-service/internal/modelgateway"
	"github.com/ancyloce/anvilkit-agent-service/internal/runtimes"
)

const (
	// maximumRequestBytes bounds one callback body. The largest governed
	// document this boundary accepts is a candidate at its contract bound.
	maximumRequestBytes = 262144
	// maximumBodyReadWindow bounds how long one callback may take to deliver
	// its body. A unit sends a bounded document in one write; a body that
	// takes longer than this to arrive is a connection being held, not a
	// callback being made.
	maximumBodyReadWindow = 30 * time.Second
	// maximumHeaderBytes bounds what a caller may spend on headers.
	maximumHeaderBytes = 16384

	requestDigestHeader = "X-AnvilKit-Request-Digest"
	idempotencyHeader   = "Idempotency-Key"

	// idempotencyScope is the one identity space runtime callbacks use:
	// attempt and operation, exactly as the runtime SDK constructs it.
	idempotencyScope = "attempt-and-operation"

	// PathModelInvocations and its siblings are the served paths, stated here
	// so the router and this boundary cannot drift apart silently.
	PathModelInvocations         = "/v1/internal/runtime/model-invocations"
	PathContractInvocations      = "/v1/internal/runtime/contract-runtime-invocations"
	PathArtifactContentGrants    = "/v1/internal/runtime/artifact-content-grants"
	PathArtifacts                = "/v1/internal/runtime/artifacts"
	candidateSubmissionOperation = "artifact.candidate"
)

// ModelPort is the governed model gateway this boundary drives. The controlled
// model stack satisfies it; a real provider stack would satisfy it identically.
type ModelPort interface {
	Select(ctx context.Context, workspaceID string, policy agent.PolicyReference) (modelgateway.Selection, error)
	Invoke(ctx context.Context, request modelgateway.InvokeRequest) (modelgateway.AdapterResponse, modelgateway.InvocationRecord, error)
}

// SchemaValidator validates one document against one pinned schema reference.
type SchemaValidator interface {
	Validate(ctx context.Context, reference agent.SchemaReference, document json.RawMessage) error
}

// TaskRegister records what was dispatched so a callback can be bound to it.
// Offer is the runner's disclosure port: it runs inside the durable dispatch
// step, before the task leaves this process, so a recovered dispatch re-offers
// before it re-dispatches.
type TaskRegister interface {
	Offer(ctx context.Context, task schema.AgentTask, compiled []byte) error
	Task(ctx context.Context, physicalAttemptID string) (schema.AgentTask, bool, error)
}

// AttemptRegister reports whether a dispatched attempt is still the current
// execution of its task. A callback from an attempt a replacement has taken
// over from, or from one that already settled, is late by construction: the
// boundary refuses it the way it refuses an attempt past its window, so an
// execution the control plane has moved on from can neither be served nor
// record anything against the task.
type AttemptRegister interface {
	Current(ctx context.Context, workspaceID, projectID, taskID, physicalAttemptID string) (bool, error)
}

// Submission is one recorded candidate submission.
type Submission struct {
	WorkspaceID, ProjectID    string
	RunID, TaskID             string
	PhysicalAttemptID         string
	ArtifactID, Digest        string
	MediaType                 string
	SizeBytes                 int
	Content                   []byte
	SubmittedAt               time.Time
	ExecutionGeneration       int
	AttemptNumber, LeaseEpoch int
}

// SubmissionStore durably records candidate submissions. Record is idempotent
// by (run, digest): the same document is one immutable artifact however many
// attempts submit it, and a second document under the same attempt identity is
// a conflict, never a replacement.
type SubmissionStore interface {
	Record(ctx context.Context, submission Submission) (Submission, bool, error)
	Content(ctx context.Context, reference schema.SharedPrimitivesArtifactReference) ([]byte, error)
}

// GrantPort issues one artifact content grant, when the artifact's content is
// actually held somewhere a grant can be honoured against.
type GrantPort interface {
	Issue(ctx context.Context, workspaceID, projectID, artifactID, purpose, actorID string) (schema.ArtifactContentGrant, error)
}

// ContractPort validates one canonical input against one pinned contract.
type ContractPort interface {
	Validate(ctx context.Context, request schema.ContractRuntimeRequest) (schema.ContractRuntimeResult, error)
}

// Config wires the boundary.
type Config struct {
	Credentials *runtimes.CredentialTrust
	// Audiences is the governed set of runtime workload audiences this
	// deployment dispatches to. A credential for any other audience is not a
	// credential this boundary resolves keys for.
	Audiences []string
	Models    ModelPort
	Validator SchemaValidator
	// CandidateSchema is the pinned canonical PageCandidate schema submissions
	// are validated against.
	CandidateSchema agent.SchemaReference
	Register        TaskRegister
	Attempts        AttemptRegister
	Submissions     SubmissionStore
	Grants          GrantPort
	Contracts       ContractPort
	Now             func() time.Time
}

// Boundary serves the four internal runtime operations.
type Boundary struct {
	cfg Config
}

// New builds the boundary. The model, register, submission, and validation
// dependencies are required; grants and contract invocations degrade to
// governed refusals when their backing capability is absent.
func New(cfg Config) (*Boundary, error) {
	if cfg.Credentials == nil || len(cfg.Audiences) == 0 {
		return nil, fmt.Errorf("runtime boundary: credential verification and the governed audience set are required")
	}
	if cfg.Models == nil || cfg.Register == nil || cfg.Attempts == nil || cfg.Submissions == nil || cfg.Validator == nil {
		return nil, fmt.Errorf("runtime boundary: the model port, task register, attempt register, submission store, and schema validator are required")
	}
	if cfg.CandidateSchema.ComponentName == "" || cfg.CandidateSchema.Digest == "" {
		return nil, fmt.Errorf("runtime boundary: the pinned candidate schema reference is required")
	}
	if cfg.Now == nil {
		return nil, fmt.Errorf("runtime boundary: a clock is required")
	}
	return &Boundary{cfg: cfg}, nil
}

// ServeHTTP routes the four served operations. Anything else under the
// boundary prefix is a governed not-found, in the problem shape every governed
// operation answers with.
func (b *Boundary) ServeHTTP(response http.ResponseWriter, request *http.Request) {
	if headerBytes(request.Header) > maximumHeaderBytes {
		b.refuse(response, http.StatusBadRequest, "MALFORMED_REQUEST", "the request headers exceed the accepted bound")
		return
	}
	if request.Method != http.MethodPost {
		b.refuse(response, http.StatusMethodNotAllowed, "MALFORMED_REQUEST", "runtime boundary operations are POST-only")
		return
	}
	switch request.URL.Path {
	case PathModelInvocations:
		b.serveModelInvocation(response, request)
	case PathArtifacts:
		b.serveArtifactSubmission(response, request)
	case PathArtifactContentGrants:
		b.serveContentGrant(response, request)
	case PathContractInvocations:
		b.serveContractInvocation(response, request)
	default:
		b.refuse(response, http.StatusNotFound, "RESOURCE_NOT_FOUND", "the runtime boundary serves no operation at this path")
	}
}

// admitted is one verified, task-bound callback.
type admitted struct {
	credential runtimes.VerifiedCredential
	task       schema.AgentTask
	body       []byte
}

// admit is the whole §10-style admission chain for a callback: bounded body,
// declared content type, verified bearer, a dispatched task this service
// offered, a credential that binds exactly that task and the execute
// operation, an admission window that is still open, and an attempt that is
// still the current execution of its task. Nothing about the request body is
// interpreted before the caller is admitted.
func (b *Boundary) admit(response http.ResponseWriter, request *http.Request) (admitted, bool) {
	if media := mediaTypeOf(request.Header.Get("Content-Type")); media != "application/json" {
		b.refuse(response, http.StatusBadRequest, "MALFORMED_REQUEST", "runtime boundary operations accept application/json")
		return admitted{}, false
	}
	// The body is read under its own deadline. The server carries no request
	// read deadline — the event stream it also serves legitimately lasts —
	// so a caller that opened a callback and never finished sending it would
	// otherwise hold the connection for as long as it liked. The controller
	// answers not-supported where the response is not a real connection,
	// which is the recorder every test writes to, and that is not a refusal.
	_ = http.NewResponseController(response).SetReadDeadline(b.cfg.Now().Add(maximumBodyReadWindow))
	body, err := io.ReadAll(io.LimitReader(request.Body, maximumRequestBytes+1))
	if err != nil {
		b.refuse(response, http.StatusBadRequest, "MALFORMED_REQUEST", "the request body could not be read")
		return admitted{}, false
	}
	if len(body) > maximumRequestBytes {
		b.refuse(response, http.StatusBadRequest, "MALFORMED_REQUEST", "the request body exceeds the accepted bound")
		return admitted{}, false
	}
	// The request digest is required, as the canonical boundary description
	// names it and as the runtime's own admission requires it of a dispatch:
	// a callback that declares no digest cannot prove the body it carries is
	// the one its idempotency identity was computed over.
	declared := request.Header.Get(requestDigestHeader)
	if declared == "" {
		b.refuse(response, http.StatusBadRequest, "MALFORMED_REQUEST", "a request digest over the request body is required")
		return admitted{}, false
	}
	if declared != digestOf(body) {
		b.refuse(response, http.StatusBadRequest, "MALFORMED_REQUEST", "the declared request digest does not cover the request body")
		return admitted{}, false
	}
	token, present := bearerOf(request.Header.Get("Authorization"))
	if !present {
		b.refuse(response, http.StatusUnauthorized, "UNAUTHENTICATED", "a task-scoped credential is required")
		return admitted{}, false
	}
	// The audience is selected from the token's own claim, then enforced: the
	// claimed audience must be one this deployment governs, and verification
	// resolves the signing key for that audience and no other. A token
	// claiming an ungoverned audience never reaches signature verification.
	audience, err := claimedAudience(token)
	if err != nil {
		b.refuse(response, http.StatusUnauthorized, "UNAUTHENTICATED", "the credential is not readable")
		return admitted{}, false
	}
	if !contains(b.cfg.Audiences, audience) {
		b.refuse(response, http.StatusUnauthorized, "UNAUTHENTICATED", "the credential audience is not a governed runtime audience")
		return admitted{}, false
	}
	verified, err := b.cfg.Credentials.Verify(token, audience, b.cfg.Now())
	if err != nil {
		b.refuse(response, http.StatusUnauthorized, "UNAUTHENTICATED", "the credential does not verify")
		return admitted{}, false
	}
	task, known, err := b.cfg.Register.Task(request.Context(), verified.Binding.PhysicalAttemptID)
	if err != nil {
		b.refuse(response, http.StatusInternalServerError, "INTERNAL", "the dispatched task could not be resolved")
		return admitted{}, false
	}
	if !known {
		b.refuse(response, http.StatusNotFound, "RESOURCE_NOT_FOUND", "the credential names no dispatched attempt this service offered")
		return admitted{}, false
	}
	if reason := runtimes.BindsTask(verified, task, runtimes.OperationExecute); reason != "" {
		b.refuse(response, http.StatusForbidden, "NOT_AUTHORIZED", "the credential does not bind the dispatched attempt")
		return admitted{}, false
	}
	if expired(task, b.cfg.Now()) {
		b.refuse(response, http.StatusGone, "ADMISSION_WINDOW_CLOSED", "the dispatched attempt is past its admission window")
		return admitted{}, false
	}
	// The window is checked before currency so an attempt that is both
	// expired and replaced is refused under the reason that closed it first.
	current, err := b.cfg.Attempts.Current(request.Context(), verified.Binding.WorkspaceID, verified.Binding.ProjectID, string(task.TaskId), verified.Binding.PhysicalAttemptID)
	if err != nil {
		b.refuse(response, http.StatusInternalServerError, "INTERNAL", "the dispatched attempt could not be resolved")
		return admitted{}, false
	}
	if !current {
		b.refuse(response, http.StatusGone, "ADMISSION_WINDOW_CLOSED", "the dispatched attempt is no longer the current execution of its task")
		return admitted{}, false
	}
	return admitted{credential: verified, task: task, body: body}, true
}

// refuse answers one governed refusal in the canonical problem shape. The
// detail names the rule, never the values that failed it.
func (b *Boundary) refuse(response http.ResponseWriter, status int, code, detail string) {
	// The refusal is logged by its stable code and the rule it names, never by
	// anything the request carried: a callback's credential, body, or digest
	// would otherwise outlive the request in a log.
	slog.Warn("runtime boundary refused a callback", "code", code, "status", status, "detail", detail)
	response.Header().Set("Content-Type", "application/problem+json")
	response.WriteHeader(status)
	document, err := json.Marshal(map[string]any{
		"type":   "urn:anvilkit:problem:" + strings.ToLower(strings.ReplaceAll(code, "_", "-")),
		"title":  code,
		"status": status,
		"detail": detail,
		"code":   code,
	})
	if err != nil {
		return
	}
	_, _ = response.Write(document)
}

func (b *Boundary) answerJSON(response http.ResponseWriter, status int, document any) {
	encoded, err := json.Marshal(document)
	if err != nil {
		b.refuse(response, http.StatusInternalServerError, "INTERNAL", "the answer could not be encoded")
		return
	}
	response.Header().Set("Content-Type", "application/json")
	response.WriteHeader(status)
	_, _ = response.Write(encoded)
}

// decodeStrict decodes exactly one JSON document with unknown members refused.
func decodeStrict(raw []byte, target any) error {
	decoder := json.NewDecoder(strings.NewReader(string(raw)))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return err
	}
	if _, err := decoder.Token(); !errors.Is(err, io.EOF) {
		return fmt.Errorf("trailing content after the document")
	}
	return nil
}

// claimedAudience reads the unverified audience claim so the verifier can be
// asked for exactly that audience. Nothing else about the token is read before
// verification.
func claimedAudience(token string) (string, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return "", fmt.Errorf("the credential is not a compact JWS")
	}
	payload, err := base64URLDecode(parts[1])
	if err != nil {
		return "", err
	}
	var claims struct {
		Audience string `json:"aud"`
	}
	if err := json.Unmarshal(payload, &claims); err != nil || claims.Audience == "" {
		return "", fmt.Errorf("the credential carries no audience")
	}
	return claims.Audience, nil
}

func expired(task schema.AgentTask, now time.Time) bool {
	expiresAt := time.Time(task.ExpiresAt)
	if expiresAt.IsZero() {
		return true
	}
	return now.After(expiresAt)
}

func digestOf(raw []byte) string {
	sum := sha256.Sum256(raw)
	return "sha256:" + hex.EncodeToString(sum[:])
}

func mediaTypeOf(header string) string {
	media, _, _ := strings.Cut(header, ";")
	return strings.ToLower(strings.TrimSpace(media))
}

func bearerOf(header string) (string, bool) {
	scheme, token, found := strings.Cut(header, " ")
	if !found || !strings.EqualFold(strings.TrimSpace(scheme), "Bearer") {
		return "", false
	}
	token = strings.TrimSpace(token)
	return token, token != ""
}

func base64URLDecode(value string) ([]byte, error) {
	return base64.RawURLEncoding.DecodeString(value)
}

func headerBytes(header http.Header) int {
	total := 0
	for name, values := range header {
		for _, value := range values {
			total += len(name) + len(value)
		}
	}
	return total
}

func contains(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}
