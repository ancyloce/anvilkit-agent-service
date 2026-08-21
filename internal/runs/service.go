package runs

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"time"

	contractvalidator "github.com/ancyloce/anvilkit-agent-service/contracts/validator"
	"github.com/ancyloce/anvilkit-agent-service/internal/authority"
	"github.com/ancyloce/anvilkit-agent-service/internal/canonical"
	"github.com/ancyloce/anvilkit-agent-service/internal/journal"
	"github.com/ancyloce/anvilkit-agent-service/internal/problem"
)

type Scope struct{ WorkspaceID, ProjectID, ActorID string }

// AuthorityScope projects the run scope onto the shared authority scope so
// every module resolves current authority through one port.
func (s Scope) AuthorityScope() authority.Scope {
	return authority.Scope{WorkspaceID: s.WorkspaceID, ProjectID: s.ProjectID, ActorID: s.ActorID}
}

func (s Scope) Validate() error {
	if !validOpaqueID(s.WorkspaceID) || !validOpaqueID(s.ProjectID) || !validOpaqueID(s.ActorID) {
		return fmt.Errorf("run scope requires bounded workspace, project, and actor identities")
	}
	return nil
}

// CreateRequest is the canonical CreateAgentRunRequest command (ADR-021). The
// caller declares only authorized intent: the definition reference, the
// operation, the fully scoped target, and optional input and labels.
// Server-owned authority fields are structurally absent; the owning domain is
// derived from the operation on the server.
type CreateRequest struct {
	Kind       string                     `json:"kind"`
	Definition DefinitionReferenceCommand `json:"definition"`
	Operation  string                     `json:"operation"`
	Target     TargetCommand              `json:"target"`
	Input      *CreateRunInput            `json:"input,omitempty"`
	Labels     map[string]string          `json:"labels,omitempty"`
}
type DefinitionReferenceCommand struct {
	DefinitionID     string `json:"definitionId"`
	DefinitionDigest string `json:"definitionDigest"`
}
type TargetCommand struct {
	Type        string `json:"targetType"`
	ID          string `json:"targetId"`
	WorkspaceID string `json:"workspaceId"`
	ProjectID   string `json:"projectId"`
}
type CreateRunInput struct {
	UserInput      string                     `json:"userInput,omitempty"`
	ArtifactInputs []ArtifactReferenceCommand `json:"artifactInputs,omitempty"`
}
type ArtifactReferenceCommand struct {
	ArtifactID string `json:"artifactId"`
	Digest     string `json:"digest"`
	MediaType  string `json:"mediaType"`
	SizeBytes  int64  `json:"sizeBytes"`
}

// operationDomain derives the owning domain from the declared operation. The
// domain is a server-owned fact: callers never declare it.
func operationDomain(operation string) string {
	switch operation {
	case "page-change", "image-operation":
		return "pagix-page"
	case "artifact-validation":
		return "contract-runtime"
	case "component-package":
		return "platform-agent"
	default:
		return ""
	}
}

// Authority is the one current-authority observation type, shared with every
// other boundary in the runtime. Run creation pins the material fields onto
// the run; the activation and grant fields are re-read at every later
// boundary through the same source.
type Authority = authority.Current
type Target struct {
	Type        string `json:"targetType"`
	ID          string `json:"targetId"`
	WorkspaceID string `json:"workspaceId"`
	ProjectID   string `json:"projectId"`
}
type IdempotencyProjection struct {
	Scope                  string `json:"scope"`
	Key                    string `json:"key"`
	CanonicalRequestDigest string `json:"canonicalRequestDigest"`
}
type Snapshot struct {
	Kind                string                `json:"kind"`
	RunID               ID                    `json:"runId"`
	RootRunID           ID                    `json:"rootRunId"`
	ParentRunID         *ID                   `json:"parentRunId,omitempty"`
	WorkspaceID         string                `json:"workspaceId"`
	ActorID             string                `json:"actorId"`
	Domain              string                `json:"domain"`
	Operation           string                `json:"operation"`
	Target              Target                `json:"target"`
	Definition          json.RawMessage       `json:"definition"`
	ContractBOM         json.RawMessage       `json:"contractBomReference"`
	Policy              json.RawMessage       `json:"policy"`
	Budget              json.RawMessage       `json:"budget"`
	Idempotency         IdempotencyProjection `json:"idempotency"`
	Status              State                 `json:"status"`
	Version             uint64                `json:"-"`
	ExecutionGeneration uint64                `json:"executionGeneration"`
	Problem             *problem.Details      `json:"problem,omitempty"`
	LatestEventID       string                `json:"-"`
	CreatedAt           time.Time             `json:"createdAt"`
	UpdatedAt           time.Time             `json:"updatedAt"`
}

func (s Snapshot) MarshalJSON() ([]byte, error) {
	type wire struct {
		Kind                string                `json:"kind"`
		RunID               ID                    `json:"runId"`
		RootRunID           ID                    `json:"rootRunId"`
		ParentRunID         *ID                   `json:"parentRunId,omitempty"`
		WorkspaceID         string                `json:"workspaceId"`
		ActorID             string                `json:"actorId"`
		Domain              string                `json:"domain"`
		Operation           string                `json:"operation"`
		Target              Target                `json:"target"`
		Definition          json.RawMessage       `json:"definition"`
		ContractBOM         json.RawMessage       `json:"contractBomReference"`
		Policy              json.RawMessage       `json:"policy"`
		Budget              json.RawMessage       `json:"budget"`
		Idempotency         IdempotencyProjection `json:"idempotency"`
		Status              State                 `json:"status"`
		ExecutionGeneration uint64                `json:"executionGeneration"`
		ResourceRevision    uint64                `json:"resourceRevision"`
		Problem             *problem.Details      `json:"problem,omitempty"`
		CreatedAt           string                `json:"createdAt"`
		UpdatedAt           string                `json:"updatedAt"`
	}
	return json.Marshal(wire{Kind: s.Kind, RunID: s.RunID, RootRunID: s.RootRunID, ParentRunID: s.ParentRunID, WorkspaceID: s.WorkspaceID, ActorID: s.ActorID, Domain: s.Domain, Operation: s.Operation, Target: s.Target, Definition: s.Definition, ContractBOM: s.ContractBOM, Policy: s.Policy, Budget: s.Budget, Idempotency: s.Idempotency, Status: s.Status, ExecutionGeneration: s.ExecutionGeneration, ResourceRevision: s.Version, Problem: s.Problem, CreatedAt: contractTimestamp(s.CreatedAt), UpdatedAt: contractTimestamp(s.UpdatedAt)})
}

func contractTimestamp(value time.Time) string {
	return value.UTC().Truncate(time.Millisecond).Format("2006-01-02T15:04:05.000Z")
}

func (s Snapshot) ETag() string { return fmt.Sprintf("\"%s:v%d\"", s.RunID, s.Version) }

type CreateInput struct {
	Scope              Scope
	Key, ClaimedDigest string
	Traceparent        string
	Raw                []byte
	Authority          Authority
}
type CreateRecord struct {
	Scope                    Scope
	Key, Digest, Traceparent string
	Snapshot                 Snapshot
}
type CreateOutcome struct {
	Snapshot Snapshot
	Bytes    []byte
	Replayed bool
}
type ListOptions struct {
	Cursor string
	Limit  int
	State  State
}
type Page struct {
	Items    []Snapshot `json:"items"`
	PageInfo PageInfo   `json:"pageInfo"`
}
type PageInfo struct {
	Limit      int    `json:"limit"`
	HasMore    bool   `json:"hasMore"`
	NextCursor string `json:"nextCursor,omitempty"`
}
type Start struct {
	Scope       Scope
	RunID       ID
	Generation  uint64
	Traceparent string
}
type Starter interface {
	Ensure(context.Context, Start) error
}
type Store interface {
	Create(context.Context, CreateRecord) (CreateOutcome, error)
	Get(context.Context, Scope, ID) (Snapshot, error)
	List(context.Context, Scope, ListOptions) (Page, error)
	Transition(context.Context, Scope, ID, uint64, Command) (Snapshot, error)
}
type IDGenerator interface{ NewID() (ID, error) }
type Clock interface{ Now() time.Time }

// Admission is the gate a new run must pass before it exists. It is where
// service-wide trust material is revalidated: material that was valid when the
// process started can expire or be revoked while it runs, and new work must
// stop at that point instead of inheriting a decision made at startup.
type Admission interface {
	Admit(context.Context, Scope) error
}

// AdmitFunc adapts a function to the Admission gate.
type AdmitFunc func(context.Context, Scope) error

func (f AdmitFunc) Admit(ctx context.Context, scope Scope) error { return f(ctx, scope) }

type Service struct {
	store     Store
	starter   Starter
	ids       IDGenerator
	clock     Clock
	receipts  journal.Store
	admission Admission
}

func NewService(store Store, starter Starter, ids IDGenerator, clock Clock, receipts journal.Store, admission Admission) *Service {
	return &Service{store: store, starter: starter, ids: ids, clock: clock, receipts: receipts, admission: admission}
}

func DecodeCreateRequest(raw []byte) (CreateRequest, error) {
	if len(raw) == 0 || len(raw) > 1<<20 {
		return CreateRequest{}, requestProblem("body must contain at most 1048576 bytes")
	}
	if _, err := contractvalidator.Admit(raw); err != nil {
		return CreateRequest{}, requestProblem("body violates strict JSON admission")
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	var request CreateRequest
	if err := decoder.Decode(&request); err != nil {
		return CreateRequest{}, requestProblem("body does not match the candidate create command")
	}
	if err := consumeEOF(decoder); err != nil {
		return CreateRequest{}, requestProblem("body must contain exactly one JSON value")
	}
	if request.Kind != "CreateAgentRunRequest" {
		return CreateRequest{}, requestProblem("kind must be CreateAgentRunRequest")
	}
	if !validOpaqueID(request.Definition.DefinitionID) || !validDigest(request.Definition.DefinitionDigest) {
		return CreateRequest{}, requestProblem("definition reference must carry a bounded identity and digest")
	}
	if !oneOf(request.Operation, "page-change", "artifact-validation", "image-operation", "component-package") || !validTargetType(request.Target.Type) || !validOpaqueID(request.Target.ID) || !validOpaqueID(request.Target.WorkspaceID) || !validOpaqueID(request.Target.ProjectID) {
		return CreateRequest{}, requestProblem("operation and fully scoped target must use bounded values")
	}
	if request.Input != nil {
		if request.Input.UserInput == "" && len(request.Input.ArtifactInputs) == 0 {
			return CreateRequest{}, requestProblem("input must carry user input or artifact references")
		}
		if len(request.Input.UserInput) > 16384 || len(request.Input.ArtifactInputs) > 32 {
			return CreateRequest{}, requestProblem("input exceeds the bounded command")
		}
		for _, reference := range request.Input.ArtifactInputs {
			if !validOpaqueID(reference.ArtifactID) || !validDigest(reference.Digest) || reference.MediaType == "" || len(reference.MediaType) > 128 || reference.SizeBytes < 1 {
				return CreateRequest{}, requestProblem("artifact references must be bounded and digest-pinned")
			}
		}
	}
	if len(request.Labels) > 16 {
		return CreateRequest{}, requestProblem("labels exceed the bounded command")
	}
	for key, value := range request.Labels {
		if key == "" || len(key) > 64 || len(value) > 256 {
			return CreateRequest{}, requestProblem("labels must use bounded keys and values")
		}
	}
	return request, nil
}

func (s *Service) Create(ctx context.Context, input CreateInput) (CreateOutcome, error) {
	if err := input.Scope.Validate(); err != nil {
		return CreateOutcome{}, requestProblem(err.Error())
	}
	// Nothing is decoded, allocated, or persisted before admission: trust
	// material that has expired or been revoked since startup stops new runs
	// here rather than after a run identity exists.
	if s.admission == nil {
		return CreateOutcome{}, fmt.Errorf("create run: no admission gate is configured")
	}
	if err := s.admission.Admit(ctx, input.Scope); err != nil {
		return CreateOutcome{}, err
	}
	request, err := DecodeCreateRequest(input.Raw)
	if err != nil {
		return CreateOutcome{}, err
	}
	// The declared target must bind the authenticated workspace and the
	// project the caller's verified claims authorize; a caller cannot aim a
	// run at another workspace's or project's target by declaration.
	if request.Target.WorkspaceID != input.Scope.WorkspaceID || request.Target.ProjectID != input.Scope.ProjectID {
		denied := problem.New(problem.CodeAuthorizationDenied, "")
		denied.Detail = "the declared target must bind the authenticated workspace and an authorized project"
		return CreateOutcome{}, denied
	}
	// The one authority observation the caller resolved must still govern the
	// exact target the run would act on. The application boundary performs the
	// same check; this one holds even for callers that reach the service
	// directly, so no composition can create a run against a revoked target.
	if input.Authority.TargetRevoked(request.Target.ID) {
		stale := problem.New(problem.CodeAuthorityStale, "")
		stale.Detail = "authority over the declared target is revoked"
		return CreateOutcome{}, stale
	}
	digest, err := canonical.Digest(input.Raw)
	if err != nil {
		return CreateOutcome{}, requestProblem("request is not canonicalizable under the pinned profile")
	}
	if input.ClaimedDigest == "" || input.ClaimedDigest != digest {
		details := problem.New(problem.CodeRequestInvalid, "")
		details.Detail = "X-AnvilKit-Request-Digest does not match the canonical request"
		return CreateOutcome{}, details
	}
	if input.Key == "" || len(input.Key) > 256 {
		return CreateOutcome{}, requestProblem("idempotency key is required and bounded")
	}
	if !validTraceparent(input.Traceparent) {
		return CreateOutcome{}, requestProblem("traceparent is required and must use the W3C format")
	}
	if len(input.Authority.Definition) == 0 || len(input.Authority.ContractBOM) == 0 || len(input.Authority.Policy) == 0 || len(input.Authority.Budget) == 0 {
		return CreateOutcome{}, fmt.Errorf("create run: server authority is incomplete")
	}
	runID, err := s.ids.NewID()
	if err != nil {
		return CreateOutcome{}, fmt.Errorf("allocate run identity: %w", err)
	}
	if !validRunID(runID) {
		return CreateOutcome{}, fmt.Errorf("allocate run identity: generated identity violates the bounded run/event contract")
	}
	now := s.clock.Now().UTC()
	if now.IsZero() {
		return CreateOutcome{}, problem.New(problem.CodeAuthorityStale, "")
	}
	snapshot := Snapshot{Kind: "AgentRun", RunID: runID, RootRunID: runID, WorkspaceID: input.Scope.WorkspaceID, ActorID: input.Scope.ActorID, Domain: operationDomain(request.Operation), Operation: request.Operation, Target: Target{Type: request.Target.Type, ID: request.Target.ID, WorkspaceID: input.Scope.WorkspaceID, ProjectID: input.Scope.ProjectID}, Definition: append(json.RawMessage(nil), input.Authority.Definition...), ContractBOM: append(json.RawMessage(nil), input.Authority.ContractBOM...), Policy: append(json.RawMessage(nil), input.Authority.Policy...), Budget: append(json.RawMessage(nil), input.Authority.Budget...), Idempotency: IdempotencyProjection{Scope: input.Scope.WorkspaceID + ":create-run", Key: input.Key, CanonicalRequestDigest: digest}, Status: Created, Version: 1, ExecutionGeneration: 1, LatestEventID: string(runID) + ":1", CreatedAt: now, UpdatedAt: now}
	outcome, err := s.store.Create(ctx, CreateRecord{Scope: input.Scope, Key: input.Key, Digest: digest, Traceparent: input.Traceparent, Snapshot: snapshot})
	if err != nil {
		return CreateOutcome{}, err
	}
	if s.receipts == nil {
		return CreateOutcome{}, fmt.Errorf("create run: independent receipt journal unavailable")
	}
	factRaw, err := json.Marshal(struct {
		Scope            Scope           `json:"scope"`
		IdempotencyKey   string          `json:"idempotencyKey"`
		CanonicalDigest  string          `json:"canonicalDigest"`
		CanonicalRequest json.RawMessage `json:"canonicalRequest"`
		RunID            ID              `json:"runId"`
		InitialVersion   uint64          `json:"initialVersion"`
		InitialEventID   string          `json:"initialEventId"`
	}{input.Scope, input.Key, digest, json.RawMessage(input.Raw), outcome.Snapshot.RunID, outcome.Snapshot.Version, outcome.Snapshot.LatestEventID})
	if err != nil {
		return CreateOutcome{}, fmt.Errorf("marshal acknowledged create fact: %w", err)
	}
	canonicalFact, err := canonical.Bytes(factRaw)
	if err != nil {
		return CreateOutcome{}, fmt.Errorf("canonicalize acknowledged create fact: %w", err)
	}
	fact, err := journal.NewFact(input.Scope.WorkspaceID+":create-run:"+input.Key, input.Scope.WorkspaceID, input.Scope.ProjectID, journal.FactCreate, canonicalFact, outcome.Bytes)
	if err != nil {
		return CreateOutcome{}, err
	}
	if _, err := s.receipts.Append(ctx, fact); err != nil {
		return CreateOutcome{}, fmt.Errorf("create authority fact remains unacknowledged: %w", err)
	}
	if err := s.starter.Ensure(ctx, Start{Scope: input.Scope, RunID: outcome.Snapshot.RunID, Generation: 1, Traceparent: input.Traceparent}); err != nil {
		return CreateOutcome{}, fmt.Errorf("ensure durable create workflow: %w", err)
	}
	return outcome, nil
}

func (s *Service) Get(ctx context.Context, scope Scope, id ID) (Snapshot, error) {
	if err := scope.Validate(); err != nil || id == "" {
		return Snapshot{}, problem.New(problem.CodeResourceNotFound, "")
	}
	return s.store.Get(ctx, scope, id)
}
func (s *Service) List(ctx context.Context, scope Scope, options ListOptions) (Page, error) {
	if err := scope.Validate(); err != nil {
		return Page{}, problem.New(problem.CodeResourceNotFound, "")
	}
	if options.Limit == 0 {
		options.Limit = 50
	}
	if options.Limit < 1 || options.Limit > 100 || len(options.Cursor) > 512 {
		return Page{}, requestProblem("list cursor or limit exceeds the bounded contract")
	}
	if options.State != "" && !validState(options.State) {
		return Page{}, requestProblem("state filter is invalid")
	}
	return s.store.List(ctx, scope, options)
}
func (s *Service) Transition(ctx context.Context, scope Scope, id ID, expectedVersion uint64, command Command) (Snapshot, error) {
	if err := scope.Validate(); err != nil || id == "" {
		return Snapshot{}, problem.New(problem.CodeResourceNotFound, "")
	}
	if expectedVersion == 0 {
		details := problem.New(problem.CodeVersionConflict, "")
		details.Detail = "an explicit current version is required"
		return Snapshot{}, details
	}
	if !validTraceparent(command.Traceparent) {
		return Snapshot{}, requestProblem("traceparent is required and must use the W3C format")
	}
	return s.store.Transition(ctx, scope, id, expectedVersion, command)
}

func requestProblem(detail string) problem.Details {
	value := problem.New(problem.CodeRequestInvalid, "")
	value.Detail = detail
	return value
}
func consumeEOF(decoder *json.Decoder) error {
	var extra any
	if err := decoder.Decode(&extra); err != io.EOF {
		return fmt.Errorf("trailing JSON")
	}
	return nil
}
func oneOf(value string, values ...string) bool {
	for _, candidate := range values {
		if value == candidate {
			return true
		}
	}
	return false
}
func validState(value State) bool {
	for _, state := range States() {
		if value == state {
			return true
		}
	}
	return false
}
func validTraceparent(value string) bool {
	if len(value) != 55 || value[2] != '-' || value[35] != '-' || value[52] != '-' {
		return false
	}
	for index, character := range value {
		if index == 2 || index == 35 || index == 52 {
			continue
		}
		if !lowerHexDigit(character) {
			return false
		}
	}
	return value[:2] != "ff" && value[3:35] != strings.Repeat("0", 32) && value[36:52] != strings.Repeat("0", 16)
}

func validOpaqueID(value string) bool {
	if len(value) < 1 || len(value) > 128 || !asciiAlphaNumeric(value[0]) {
		return false
	}
	for index := 1; index < len(value); index++ {
		if !asciiAlphaNumeric(value[index]) && !strings.ContainsRune("._:-", rune(value[index])) {
			return false
		}
	}
	return true
}

func validRunID(value ID) bool {
	// Reserve one separator plus the maximum uint64 sequence width so derived
	// event identities remain within the frozen 128-byte OpaqueId bound.
	return len(value) <= 107 && validOpaqueID(string(value))
}

func validTargetType(value string) bool {
	if len(value) < 1 || len(value) > 64 || value[0] < 'a' || value[0] > 'z' {
		return false
	}
	for index := 1; index < len(value); index++ {
		character := value[index]
		if (character < 'a' || character > 'z') && (character < '0' || character > '9') && character != '.' && character != '-' {
			return false
		}
	}
	return true
}

func asciiAlphaNumeric(character byte) bool {
	return character >= 'A' && character <= 'Z' || character >= 'a' && character <= 'z' || character >= '0' && character <= '9'
}

func ParseETag(value string, id ID) (uint64, error) {
	// A missing precondition and a stale one are different answers: the
	// caller who sent nothing gets 428 and retries with the current ETag; the
	// caller who sent a stale value gets 412.
	if strings.TrimSpace(value) == "" {
		return 0, problem.New(problem.CodePreconditionRequired, "")
	}
	prefix := "\"" + string(id) + ":v"
	if !strings.HasPrefix(value, prefix) || !strings.HasSuffix(value, "\"") {
		return 0, problem.New(problem.CodeVersionConflict, "")
	}
	var version uint64
	if _, err := fmt.Sscanf(value, prefix+"%d\"", &version); err != nil || version == 0 {
		return 0, problem.New(problem.CodeVersionConflict, "")
	}
	return version, nil
}

// lowerHexDigit reports whether the character is a lower-case hexadecimal
// digit. Digest and trace identities are lower-case only, so an upper-case
// digit is rejected rather than normalized.
func lowerHexDigit(character rune) bool {
	return character >= '0' && character <= '9' || character >= 'a' && character <= 'f'
}
