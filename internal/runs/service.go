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
	"github.com/ancyloce/anvilkit-agent-service/internal/canonical"
	"github.com/ancyloce/anvilkit-agent-service/internal/journal"
	"github.com/ancyloce/anvilkit-agent-service/internal/problem"
)

type Scope struct{ TenantID, WorkspaceID, ProjectID, ActorID string }

func (s Scope) Validate() error {
	if !validOpaqueID(s.TenantID) || !validOpaqueID(s.WorkspaceID) || !validOpaqueID(s.ProjectID) || !validOpaqueID(s.ActorID) {
		return fmt.Errorf("run scope requires bounded tenant, workspace, project, and actor identities")
	}
	return nil
}

// CreateRequest is an internal candidate command. Server-owned authority fields
// are structurally absent and this type is not frozen as the interaction wire shape.
type CreateRequest struct {
	Domain    string        `json:"domain"`
	Operation string        `json:"operation"`
	Target    TargetCommand `json:"target"`
}
type TargetCommand struct {
	Type string `json:"targetType"`
	ID   string `json:"targetId"`
}

type Authority struct {
	ContractBOM json.RawMessage
	Policy      json.RawMessage
	Budget      json.RawMessage
}
type Target struct {
	Type        string `json:"targetType"`
	ID          string `json:"targetId"`
	WorkspaceID string `json:"workspaceId"`
}
type IdempotencyProjection struct {
	Scope                  string `json:"scope"`
	Key                    string `json:"key"`
	CanonicalRequestDigest string `json:"canonicalRequestDigest"`
}
type Snapshot struct {
	APIVersion          string                `json:"apiVersion"`
	Kind                string                `json:"kind"`
	RunID               ID                    `json:"runId"`
	RootRunID           ID                    `json:"rootRunId"`
	ParentRunID         *ID                   `json:"parentRunId,omitempty"`
	TenantID            string                `json:"tenantId"`
	WorkspaceID         string                `json:"workspaceId"`
	ActorID             string                `json:"actorId"`
	Domain              string                `json:"domain"`
	Operation           string                `json:"operation"`
	Target              Target                `json:"target"`
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
		APIVersion          string                `json:"apiVersion"`
		Kind                string                `json:"kind"`
		RunID               ID                    `json:"runId"`
		RootRunID           ID                    `json:"rootRunId"`
		ParentRunID         *ID                   `json:"parentRunId,omitempty"`
		TenantID            string                `json:"tenantId"`
		WorkspaceID         string                `json:"workspaceId"`
		ActorID             string                `json:"actorId"`
		Domain              string                `json:"domain"`
		Operation           string                `json:"operation"`
		Target              Target                `json:"target"`
		ContractBOM         json.RawMessage       `json:"contractBomReference"`
		Policy              json.RawMessage       `json:"policy"`
		Budget              json.RawMessage       `json:"budget"`
		Idempotency         IdempotencyProjection `json:"idempotency"`
		Status              State                 `json:"status"`
		ExecutionGeneration uint64                `json:"executionGeneration"`
		Problem             *problem.Details      `json:"problem,omitempty"`
		CreatedAt           string                `json:"createdAt"`
		UpdatedAt           string                `json:"updatedAt"`
	}
	return json.Marshal(wire{APIVersion: s.APIVersion, Kind: s.Kind, RunID: s.RunID, RootRunID: s.RootRunID, ParentRunID: s.ParentRunID, TenantID: s.TenantID, WorkspaceID: s.WorkspaceID, ActorID: s.ActorID, Domain: s.Domain, Operation: s.Operation, Target: s.Target, ContractBOM: s.ContractBOM, Policy: s.Policy, Budget: s.Budget, Idempotency: s.Idempotency, Status: s.Status, ExecutionGeneration: s.ExecutionGeneration, Problem: s.Problem, CreatedAt: contractTimestamp(s.CreatedAt), UpdatedAt: contractTimestamp(s.UpdatedAt)})
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
	WorkflowID string
	Scope      Scope
	RunID      ID
	Version    int
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
type Service struct {
	store    Store
	starter  Starter
	ids      IDGenerator
	clock    Clock
	receipts journal.Store
}

func NewService(store Store, starter Starter, ids IDGenerator, clock Clock, receipts journal.Store) *Service {
	return &Service{store: store, starter: starter, ids: ids, clock: clock, receipts: receipts}
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
	if !oneOf(request.Domain, "platform-agent", "pagix-page", "contract-runtime") || !oneOf(request.Operation, "page-change", "artifact-validation", "image-operation", "component-package") || !validTargetType(request.Target.Type) || !validOpaqueID(request.Target.ID) {
		return CreateRequest{}, requestProblem("domain, operation, and target must use bounded values")
	}
	return request, nil
}

func (s *Service) Create(ctx context.Context, input CreateInput) (CreateOutcome, error) {
	if err := input.Scope.Validate(); err != nil {
		return CreateOutcome{}, requestProblem(err.Error())
	}
	request, err := DecodeCreateRequest(input.Raw)
	if err != nil {
		return CreateOutcome{}, err
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
	if len(input.Authority.ContractBOM) == 0 || len(input.Authority.Policy) == 0 || len(input.Authority.Budget) == 0 {
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
	snapshot := Snapshot{APIVersion: "anvilkit.io/contracts/v1", Kind: "AgentRun", RunID: runID, RootRunID: runID, TenantID: input.Scope.TenantID, WorkspaceID: input.Scope.WorkspaceID, ActorID: input.Scope.ActorID, Domain: request.Domain, Operation: request.Operation, Target: Target{Type: request.Target.Type, ID: request.Target.ID, WorkspaceID: input.Scope.WorkspaceID}, ContractBOM: append(json.RawMessage(nil), input.Authority.ContractBOM...), Policy: append(json.RawMessage(nil), input.Authority.Policy...), Budget: append(json.RawMessage(nil), input.Authority.Budget...), Idempotency: IdempotencyProjection{Scope: input.Scope.WorkspaceID + ":create-run", Key: input.Key, CanonicalRequestDigest: digest}, Status: Created, Version: 1, ExecutionGeneration: 1, LatestEventID: string(runID) + ":1", CreatedAt: now, UpdatedAt: now}
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
	if err := s.starter.Ensure(ctx, Start{WorkflowID: string(outcome.Snapshot.RunID) + ":v1", Scope: input.Scope, RunID: outcome.Snapshot.RunID, Version: 1}); err != nil {
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
		if !((character >= '0' && character <= '9') || (character >= 'a' && character <= 'f')) {
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
