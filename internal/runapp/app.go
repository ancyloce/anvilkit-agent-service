// Package runapp is the application boundary between HTTP transport and run,
// event, and authorization modules.
package runapp

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"

	"github.com/ancyloce/anvilkit-agent-service/internal/agent"
	"github.com/ancyloce/anvilkit-agent-service/internal/auth"
	"github.com/ancyloce/anvilkit-agent-service/internal/authority"
	"github.com/ancyloce/anvilkit-agent-service/internal/canonical"
	contractguard "github.com/ancyloce/anvilkit-agent-service/internal/contracts"
	"github.com/ancyloce/anvilkit-agent-service/internal/events"
	"github.com/ancyloce/anvilkit-agent-service/internal/execution"
	"github.com/ancyloce/anvilkit-agent-service/internal/interrupts"
	"github.com/ancyloce/anvilkit-agent-service/internal/problem"
	"github.com/ancyloce/anvilkit-agent-service/internal/runs"
)

// createAgentRunRequestSchema pins the canonical wire contract every create
// command is validated against before any decoding happens.
const createAgentRunRequestSchema = "anvilkit://schema/create-agent-run-request?digest=sha256:ae244db518fe7b181990406994ff42623cfebe97756e4b073fc9ea3df83b8fb0"

// resolveDomainOperationRequestSchema pins the canonical wire contract every
// operator recovery command is validated against before any decoding happens.
const resolveDomainOperationRequestSchema = "anvilkit://schema/resolve-domain-operation-request?digest=sha256:c8118aaaa8f7e73b84f9d307def3536463926ce6290b8ad4b3ad9cad804b1d8b"

// submitInputResponseRequestSchema and submitApprovalDecisionRequestSchema pin
// the canonical wire contracts for the two interrupt-response commands. Both
// are validated before any decoding happens, exactly like run creation and
// operator recovery: a governed mutation surface that the canonical contract
// describes but nothing validates against is a contract in name only.
const submitInputResponseRequestSchema = "anvilkit://schema/submit-input-response-request?digest=sha256:70154bbdeba06c4a875de34fb925c6d708bd67d215a126d38dd869747a44f0d8"
const submitApprovalDecisionRequestSchema = "anvilkit://schema/submit-approval-decision-request?digest=sha256:580f4673c28360cf4d0bb68ed922aad20ea7eab56879bf69c0dd82459afe7a8e"

// CommandGuard validates canonical bytes at the API-in boundary. The pinned
// contract guard satisfies it.
type CommandGuard interface {
	Require(ctx context.Context, boundary contractguard.Boundary, schemaURI string, raw []byte) error
}

// DefinitionResolver resolves a caller-declared definition reference against
// the approved catalog. The agent registry satisfies it.
type DefinitionResolver interface {
	Resolve(agent.DefinitionReference) (agent.Definition, error)
}

// AuthorityProvider is the single current-authority port, shared with the
// execution pipeline and the interrupt authority. Creating a run is itself a
// guarded boundary: authority must be active and its material complete.
type AuthorityProvider = authority.Source

// EscalationResolver is the operator recovery path for a run whose governed
// effect is durably escalated. The execution pipeline satisfies it: it owns
// the submission journal, the current-authority re-read, the evidence store,
// and the run aggregate, which is where every part of the decision has to be
// proved. This boundary only resolves the request into a scoped, authenticated
// command.
type EscalationResolver interface {
	// AuthorizeOperatorRecovery proves current authority admits this actor as
	// an operator for this run right now, on this request. It exists as its
	// own call because a recorded receipt is answered without running the
	// command: the boundary needs the same proof for a replay that the command
	// path gets from the pipeline, and only the pipeline can supply it — it
	// owns the run lookup that resolves the tenant scope and the target the
	// revocation axis is checked against.
	AuthorizeOperatorRecovery(ctx context.Context, scope runs.Scope, id runs.ID) error
	ResolveEscalation(ctx context.Context, scope runs.Scope, id runs.ID, expectedVersion uint64, command execution.OperatorResolution) (runs.Snapshot, error)
}

type App struct {
	validator    *auth.Validator
	runs         *runs.Service
	events       events.Reader
	streamConfig events.StreamConfig
	authority    AuthorityProvider
	interrupts   *interrupts.Service
	escalations  EscalationResolver
	receipts     CommandReceipts
	guard        CommandGuard
	definitions  DefinitionResolver
}

func (a *App) WithInterrupts(service *interrupts.Service) *App { a.interrupts = service; return a }

// WithEscalations publishes the operator recovery path together with the
// receipt store its idempotency is kept in. They are bound as one because a
// governed mutation with no durable receipt is a mutation whose replay
// semantics are undefined: the pair is what makes the route's ADR-021 §4
// contract real, so neither half is separately installable.
func (a *App) WithEscalations(resolver EscalationResolver, receipts CommandReceipts) *App {
	a.escalations = resolver
	a.receipts = receipts
	return a
}

func New(validator *auth.Validator, runService *runs.Service, eventReader events.Reader, streamConfig events.StreamConfig, authority AuthorityProvider, guard CommandGuard, definitions DefinitionResolver) *App {
	return &App{validator: validator, runs: runService, events: eventReader, streamConfig: streamConfig, authority: authority, guard: guard, definitions: definitions}
}

type Representation struct {
	Body     []byte
	ETag     string
	Replayed bool
	Digest   string
	// RunID names the created resource on creation responses so transport can
	// answer 201 with a Location header.
	RunID string
}

func (a *App) Create(ctx context.Context, claims auth.Claims, workspaceID, key, digest, traceparent string, raw []byte) (Representation, error) {
	if a.guard == nil || a.definitions == nil {
		return Representation{}, fmt.Errorf("create run: the command guard and definition resolver are required")
	}
	scope, err := a.scope(ctx, claims, auth.OpCreateRun, workspaceID)
	if err != nil {
		return Representation{}, err
	}
	// The wire shape is validated against the pinned canonical contract
	// before anything is decoded: a command carrying caller-owned server
	// fields is structurally rejected here, never silently trusted.
	if err := a.guard.Require(ctx, contractguard.APIIn, createAgentRunRequestSchema, raw); err != nil {
		invalid := problem.New(problem.CodeRequestInvalid, "")
		invalid.Detail = "the command violates the canonical CreateAgentRunRequest contract"
		return Representation{}, invalid
	}
	request, err := runs.DecodeCreateRequest(raw)
	if err != nil {
		return Representation{}, err
	}
	resolved, err := a.definitions.Resolve(agent.DefinitionReference{DefinitionID: request.Definition.DefinitionID, DefinitionDigest: request.Definition.DefinitionDigest})
	if err != nil {
		unknown := problem.New(problem.CodeContractInvalid, "")
		unknown.Detail = "the declared definition is not an approved definition"
		return Representation{}, unknown
	}
	current, err := a.authority.Current(ctx, scope.AuthorityScope())
	if err != nil {
		return Representation{}, fmt.Errorf("resolve create authority: %w", err)
	}
	if !current.Active() || !current.MaterialComplete() {
		denied := problem.New(problem.CodeAuthorityStale, "")
		denied.Detail = "current authority does not permit creating a run"
		return Representation{}, denied
	}
	// Creating a run against a target whose authority has been individually
	// withdrawn is denied even while the scope itself stays active: the target
	// axis is checked wherever a specific target is about to be acted on.
	if current.TargetRevoked(request.Target.ID) {
		denied := problem.New(problem.CodeAuthorityStale, "")
		denied.Detail = "authority over the declared target is revoked"
		return Representation{}, denied
	}
	// The requested definition and the definition current authority pins must
	// be the same approved material: a caller cannot select a definition the
	// run's authority does not govern.
	var pinned agent.Definition
	if err := json.Unmarshal(current.Definition, &pinned); err != nil {
		return Representation{}, fmt.Errorf("decode pinned authority definition: %w", err)
	}
	if pinned.DefinitionDigest != resolved.DefinitionDigest {
		mismatched := problem.New(problem.CodeContractInvalid, "")
		mismatched.Detail = "the declared definition is not the definition current authority pins"
		return Representation{}, mismatched
	}
	outcome, err := a.runs.Create(ctx, runs.CreateInput{Scope: scope, Key: key, ClaimedDigest: digest, Traceparent: traceparent, Raw: raw, Authority: current})
	if err != nil {
		return Representation{}, err
	}
	return Representation{Body: outcome.Bytes, ETag: outcome.Snapshot.ETag(), Replayed: outcome.Replayed, Digest: digest, RunID: string(outcome.Snapshot.RunID)}, nil
}
func (a *App) Get(ctx context.Context, claims auth.Claims, workspaceID, runID string) (Representation, error) {
	scope, err := a.scope(ctx, claims, auth.OpGetRun, workspaceID)
	if err != nil {
		return Representation{}, err
	}
	snapshot, err := a.runs.Get(ctx, scope, runs.ID(runID))
	if err != nil {
		return Representation{}, err
	}
	body, err := json.Marshal(snapshot)
	if err != nil {
		return Representation{}, err
	}
	return Representation{Body: body, ETag: snapshot.ETag()}, nil
}
func (a *App) List(ctx context.Context, claims auth.Claims, workspaceID, cursor string, limit int, state string) (Representation, error) {
	scope, err := a.scope(ctx, claims, auth.OpListRuns, workspaceID)
	if err != nil {
		return Representation{}, err
	}
	page, err := a.runs.List(ctx, scope, runs.ListOptions{Cursor: cursor, Limit: limit, State: runs.State(state)})
	if err != nil {
		return Representation{}, err
	}
	body, err := json.Marshal(page)
	return Representation{Body: body}, err
}

// Snapshot is the governed recovery path an expired event cursor points at.
// The rendered document is proved against the canonical AgentRunSnapshot
// contract before it leaves the service, so the recovery a client is told to
// follow always answers in the shape the description promises.
func (a *App) Snapshot(ctx context.Context, claims auth.Claims, workspaceID, runID string) (Representation, error) {
	if a.guard == nil {
		return Representation{}, fmt.Errorf("run snapshot: the contract guard is required")
	}
	scope, err := a.scope(ctx, claims, auth.OpGetRun, workspaceID)
	if err != nil {
		return Representation{}, err
	}
	projection, err := a.events.Snapshot(ctx, events.Scope{WorkspaceID: scope.WorkspaceID, ProjectID: scope.ProjectID}, runID)
	if err != nil {
		return Representation{}, err
	}
	body, err := json.Marshal(projection)
	if err != nil {
		return Representation{}, fmt.Errorf("render run snapshot: %w", err)
	}
	if err := a.guard.Require(ctx, contractguard.SnapshotOut, events.AgentRunSnapshotSchemaURI, body); err != nil {
		return Representation{}, err
	}
	return Representation{Body: body}, nil
}
func (a *App) Stream(ctx context.Context, claims auth.Claims, workspaceID, runID, cursor string, response http.ResponseWriter) error {
	scope, err := a.scope(ctx, claims, auth.OpStreamEvents, workspaceID)
	if err != nil {
		return err
	}
	authority := &streamAuthority{validator: a.validator, claims: claims}
	stream, err := events.NewStream(a.events, authority, a.streamConfig)
	if err != nil {
		return err
	}
	return stream.Serve(ctx, response, events.Scope{WorkspaceID: scope.WorkspaceID, ProjectID: scope.ProjectID}, runID, cursor)
}
func (a *App) Transition(ctx context.Context, claims auth.Claims, operation auth.Operation, workspaceID, runID, etag string, command runs.Command) (Representation, error) {
	scope, err := a.scope(ctx, claims, operation, workspaceID)
	if err != nil {
		return Representation{}, err
	}
	version, err := runs.ParseETag(etag, runs.ID(runID))
	if err != nil {
		return Representation{}, err
	}
	snapshot, err := a.runs.Transition(ctx, scope, runs.ID(runID), version, command)
	if err != nil {
		return Representation{}, err
	}
	body, _ := json.Marshal(snapshot)
	return Representation{Body: body, ETag: snapshot.ETag()}, nil
}

type ControlInput struct {
	WorkspaceID, RunID, ETag, Key, Digest, Traceparent string
}

// InputResponse is the canonical SubmitInputResponseRequest as it arrives on
// the wire. ResponsePayload stays raw so the recorded response schema is
// applied to exactly the bytes the reviewer sent; the canonical guard has
// already proved the payload is a bounded string map.
type InputResponse struct {
	Kind            string          `json:"kind"`
	RequestVersion  uint64          `json:"requestVersion"`
	ResponsePayload json.RawMessage `json:"responsePayload"`
}

// InputResponseKind is the canonical command discriminator.
const InputResponseKind = "SubmitInputResponseRequest"

func (a *App) RespondInput(ctx context.Context, claims auth.Claims, input ControlInput, requestID string, raw []byte) (Representation, error) {
	write, err := a.controlWrite(ctx, claims, auth.OpRespondInput, input)
	if err != nil {
		return Representation{}, err
	}
	var wire InputResponse
	if err := a.decodeCanonicalCommand(ctx, submitInputResponseRequestSchema, "SubmitInputResponseRequest", raw, &wire); err != nil {
		return Representation{}, err
	}
	if wire.Kind != InputResponseKind {
		return Representation{}, canonicalCommandProblem("SubmitInputResponseRequest")
	}
	if err := verifyControlDigest(input.Digest, wire); err != nil {
		return Representation{}, err
	}
	result, err := a.interrupts.RespondInput(ctx, write, interrupts.InputResponseCommand{
		RequestID:      interrupts.RequestID(requestID),
		RequestVersion: wire.RequestVersion,
		Value:          wire.ResponsePayload,
	})
	return controlRepresentation(result.Snapshot, result.Replayed, err)
}

// ApprovalDecision is the canonical SubmitApprovalDecisionRequest as it
// arrives on the wire. ActionDigest is the action the reviewer states they
// decided; the interrupt service proves it is the digest the open request
// carries.
type ApprovalDecision struct {
	Kind            string                  `json:"kind"`
	Decision        interrupts.DecisionKind `json:"decision"`
	DecisionVersion uint64                  `json:"decisionVersion"`
	ActionDigest    string                  `json:"actionDigest"`
	Comment         string                  `json:"comment,omitempty"`
}

// ApprovalDecisionKind is the canonical command discriminator.
const ApprovalDecisionKind = "SubmitApprovalDecisionRequest"

func (a *App) DecideApproval(ctx context.Context, claims auth.Claims, input ControlInput, requestID string, raw []byte) (Representation, error) {
	write, err := a.controlWrite(ctx, claims, auth.OpDecideApproval, input)
	if err != nil {
		return Representation{}, err
	}
	var wire ApprovalDecision
	if err := a.decodeCanonicalCommand(ctx, submitApprovalDecisionRequestSchema, "SubmitApprovalDecisionRequest", raw, &wire); err != nil {
		return Representation{}, err
	}
	if wire.Kind != ApprovalDecisionKind {
		return Representation{}, canonicalCommandProblem("SubmitApprovalDecisionRequest")
	}
	if err := verifyControlDigest(input.Digest, wire); err != nil {
		return Representation{}, err
	}
	result, err := a.interrupts.DecideApproval(ctx, write, interrupts.ApprovalDecisionCommand{
		RequestID:      interrupts.RequestID(requestID),
		RequestVersion: wire.DecisionVersion,
		Decision:       wire.Decision,
		ActionDigest:   wire.ActionDigest,
		Comment:        wire.Comment,
	})
	return controlRepresentation(result.Snapshot, result.Replayed, err)
}
func (a *App) Cancel(ctx context.Context, claims auth.Claims, input ControlInput) (Representation, error) {
	write, err := a.controlWrite(ctx, claims, auth.OpCancel, input)
	if err != nil {
		return Representation{}, err
	}
	if err := verifyControlDigest(input.Digest, struct{}{}); err != nil {
		return Representation{}, err
	}
	result, err := a.interrupts.Cancel(ctx, write)
	return controlRepresentation(result.Snapshot, result.Replayed, err)
}
func (a *App) Retry(ctx context.Context, claims auth.Claims, input ControlInput) (Representation, error) {
	write, err := a.controlWrite(ctx, claims, auth.OpRetry, input)
	if err != nil {
		return Representation{}, err
	}
	if err := verifyControlDigest(input.Digest, struct{}{}); err != nil {
		return Representation{}, err
	}
	result, err := a.interrupts.Retry(ctx, write)
	return controlRepresentation(result.Snapshot, result.Replayed, err)
}
func (a *App) Discard(ctx context.Context, claims auth.Claims, input ControlInput) (Representation, error) {
	write, err := a.controlWrite(ctx, claims, auth.OpDiscard, input)
	if err != nil {
		return Representation{}, err
	}
	if err := verifyControlDigest(input.Digest, struct{}{}); err != nil {
		return Representation{}, err
	}
	result, err := a.interrupts.Discard(ctx, write)
	return controlRepresentation(result.Snapshot, result.Replayed, err)
}

// EscalationResolution is the canonical ResolveDomainOperationRequest as it
// arrives on the wire. It deliberately carries no operator identity: the
// resolving operator is derived from the verified request authority, so a
// caller cannot audit a decision under someone else's name — and the canonical
// contract closes the object, so smuggling one in is structurally rejected.
type EscalationResolution struct {
	Kind        string `json:"kind"`
	OperationID string `json:"operationId"`
	Outcome     string `json:"outcome"`
	Basis       string `json:"basis"`
}

// EscalationResolutionKind is the canonical command discriminator.
const EscalationResolutionKind = "ResolveDomainOperationRequest"

// ResolveEscalation authenticates and authorizes an operator recovery, derives
// the operator identity from the verified request authority, and hands the
// scoped command to the execution pipeline. Concurrency and idempotency are
// the same contract every other governed mutation keeps: If-Match pins the run
// version the operator observed, and the canonical request digest pins the
// exact decision bytes.
//
// The full ADR-021 §4 receipt semantics are kept here rather than assumed of
// the pipeline below. The pipeline converges on its own durable state, which
// makes a second execution harmless — but it cannot make one identical: a
// replay would answer with whatever the run looks like now, not with the
// outcome the first request produced, and nothing would tell the caller which
// of the two they received. So the receipt is claimed before the command runs
// and recorded after it succeeds: an exact replay returns the recorded
// representation marked Idempotency-Replayed, reuse of the key with different
// bytes, a different observed revision, or a different run is a conflict, and
// a duplicate arriving while the first is still in flight is told so instead
// of executing alongside it.
func (a *App) ResolveEscalation(ctx context.Context, claims auth.Claims, input ControlInput, operationID string, raw []byte) (Representation, error) {
	if a.escalations == nil || a.receipts == nil {
		return Representation{}, problem.New(problem.CodeInfrastructureUnavailable, "")
	}
	if a.guard == nil {
		return Representation{}, fmt.Errorf("resolve escalation: the command guard is required")
	}
	scope, err := a.scope(ctx, claims, auth.OpResolveEscalation, input.WorkspaceID)
	if err != nil {
		return Representation{}, err
	}
	version, err := runs.ParseETag(input.ETag, runs.ID(input.RunID))
	if err != nil {
		return Representation{}, err
	}
	if input.Key == "" || len(input.Key) > 256 || !validTraceparent(input.Traceparent) {
		value := problem.New(problem.CodeRequestInvalid, "")
		value.Detail = "control write requires bounded idempotency key and traceparent"
		return Representation{}, value
	}
	// Current authority is proved for this caller, on this request, before the
	// receipt is consulted at all. The token scope this route requires is a
	// claim the caller presents; whether the scope's subject register still
	// admits them as an operator, still holds authority over the run's target,
	// and still reaches the run's tenant is authority-owned state that can
	// have changed since the first request. A recorded operator resolution is
	// a privileged response, so replaying one to a caller whose authority was
	// withdrawn would hand back exactly the decision the revocation was meant
	// to stop — the receipt cannot be allowed to answer before this holds.
	if err := a.escalations.AuthorizeOperatorRecovery(ctx, scope, runs.ID(input.RunID)); err != nil {
		return Representation{}, err
	}
	// The wire shape is validated against the pinned canonical contract before
	// anything is decoded, exactly as run creation is: a command carrying a
	// caller-owned server field — a resolving operator, above all — is
	// structurally rejected here, never silently trusted.
	var command EscalationResolution
	if err := a.decodeCanonicalCommand(ctx, resolveDomainOperationRequestSchema, "ResolveDomainOperationRequest", raw, &command); err != nil {
		return Representation{}, err
	}
	// The operation identity is carried in both the addressed resource and the
	// command, so the canonical request digest covers which effect is being
	// decided. A decision whose body names a different operation than the
	// resource it was sent to is refused rather than redirected.
	if command.Kind != EscalationResolutionKind || command.OperationID != operationID {
		value := problem.New(problem.CodeRequestInvalid, "")
		value.Detail = "the resolution names a different operation than the resource it addresses"
		return Representation{}, value
	}
	if err := verifyControlDigest(input.Digest, command); err != nil {
		return Representation{}, err
	}
	// The receipt is scoped by every element ADR-021 §4 names — workspace,
	// project, authenticated subject, method, normalized route, and key — and
	// checked against the exact command bytes, the observed run revision, and
	// the addressed run.
	//
	// The subject is the verified credential subject, not the actor the scope
	// projects. Under delegation those are different identities and several
	// subjects may be admitted to act as one actor; keying the receipt on the
	// actor would merge their namespaces and let one subject's recorded
	// operator resolution be replayed to another. The audited resolving
	// operator below is the actor, and stays so.
	receipt := CommandReceiptRequest{
		WorkspaceID: scope.WorkspaceID,
		ProjectID:   scope.ProjectID,
		Subject:     claims.Subject,
		Method:      ReceiptMethod,
		Route:       ResolveDomainOperationRoute,
		Key:         input.Key,
		RunID:       input.RunID,
		Digest:      input.Digest,
		Version:     version,
	}
	recorded, claim, replayed, err := a.receipts.Begin(ctx, receipt)
	if err != nil {
		return Representation{}, err
	}
	if replayed {
		return Representation{Body: recorded.Body, ETag: recorded.ETag, Replayed: true, Digest: input.Digest}, nil
	}
	snapshot, err := a.escalations.ResolveEscalation(ctx, scope, runs.ID(input.RunID), version, execution.OperatorResolution{
		OperationID: command.OperationID,
		Outcome:     command.Outcome,
		// The resolving operator is the authenticated actor the validator
		// projected into server-owned scope — never a body field.
		OperatorID: scope.ActorID,
		Basis:      command.Basis,
	})
	if err != nil {
		// The command produced no outcome to record. The claim is released so
		// the key stays usable: holding it would convert a denial the operator
		// can correct into a key they can never retry with.
		_ = a.receipts.Abandon(ctx, receipt, claim)
		return Representation{}, err
	}
	body, marshalErr := json.Marshal(snapshot)
	if marshalErr != nil {
		_ = a.receipts.Abandon(ctx, receipt, claim)
		return Representation{}, marshalErr
	}
	if err := a.receipts.Record(ctx, receipt, claim, CommandReceipt{Body: body, ETag: snapshot.ETag()}); err != nil {
		return Representation{}, err
	}
	return Representation{Body: body, ETag: snapshot.ETag(), Digest: input.Digest}, nil
}

// decodeCanonicalCommand validates one command body against its pinned
// canonical contract and only then decodes it. The order matters: the
// canonical shape is what rejects a caller-owned or unknown field, so nothing
// is interpreted before the contract has accepted the bytes.
func (a *App) decodeCanonicalCommand(ctx context.Context, schemaURI, logicalID string, raw []byte, target any) error {
	if a.guard == nil {
		return fmt.Errorf("decode %s: the command guard is required", logicalID)
	}
	if err := a.guard.Require(ctx, contractguard.APIIn, schemaURI, raw); err != nil {
		return canonicalCommandProblem(logicalID)
	}
	return strictDecode(raw, target)
}

func canonicalCommandProblem(logicalID string) error {
	value := problem.New(problem.CodeRequestInvalid, "")
	value.Detail = "the command violates the canonical " + logicalID + " contract"
	return value
}

// strictDecode decodes exactly one JSON value with no unknown fields. The
// canonical guard has already accepted the bytes; this refuses anything the
// Go shape would otherwise silently drop.
func strictDecode(raw []byte, target any) error {
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

func (a *App) controlWrite(ctx context.Context, claims auth.Claims, operation auth.Operation, input ControlInput) (interrupts.Write, error) {
	if a.interrupts == nil {
		return interrupts.Write{}, problem.New(problem.CodeInfrastructureUnavailable, "")
	}
	scope, err := a.scope(ctx, claims, operation, input.WorkspaceID)
	if err != nil {
		return interrupts.Write{}, err
	}
	version, err := runs.ParseETag(input.ETag, runs.ID(input.RunID))
	if err != nil {
		return interrupts.Write{}, err
	}
	if input.Key == "" || len(input.Key) > 256 || !validTraceparent(input.Traceparent) {
		value := problem.New(problem.CodeRequestInvalid, "")
		value.Detail = "control write requires bounded idempotency key and traceparent"
		return interrupts.Write{}, value
	}
	return interrupts.Write{Scope: scope, RunID: runs.ID(input.RunID), ExpectedVersion: version, IdempotencyKey: input.Key, CanonicalDigest: input.Digest, Traceparent: input.Traceparent}, nil
}
func controlRepresentation(snapshot runs.Snapshot, replayed bool, err error) (Representation, error) {
	if err != nil {
		return Representation{}, err
	}
	body, marshalErr := json.Marshal(snapshot)
	if marshalErr != nil {
		return Representation{}, marshalErr
	}
	return Representation{Body: body, ETag: snapshot.ETag(), Replayed: replayed}, nil
}
func verifyControlDigest(claimed string, command any) error {
	raw, err := json.Marshal(command)
	if err != nil {
		return err
	}
	digest, err := canonical.Digest(raw)
	if err != nil {
		return err
	}
	if claimed == "" || claimed != digest {
		value := problem.New(problem.CodeRequestInvalid, "")
		value.Detail = "X-AnvilKit-Request-Digest does not match the canonical control command"
		return value
	}
	return nil
}
func (a *App) scope(ctx context.Context, claims auth.Claims, operation auth.Operation, workspaceID string) (runs.Scope, error) {
	scope, err := a.validator.Authorize(ctx, claims, operation)
	if err != nil {
		return runs.Scope{}, err
	}
	if scope.WorkspaceID != workspaceID {
		return runs.Scope{}, authNonDisclosure()
	}
	return scope, nil
}

type streamAuthority struct {
	validator *auth.Validator
	claims    auth.Claims
}

func (a *streamAuthority) Revalidate(ctx context.Context) error {
	return a.validator.Revalidate(ctx, a.claims, auth.OpStreamEvents)
}
func ParseLimit(value string) (int, error) {
	if value == "" {
		return 50, nil
	}
	limit, err := strconv.Atoi(value)
	if err != nil || limit < 1 || limit > 100 {
		return 0, fmt.Errorf("limit must be between 1 and 100")
	}
	return limit, nil
}
func authNonDisclosure() error { return problem.New(problem.CodeResourceNotFound, "") }

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

// lowerHexDigit reports whether the character is a lower-case hexadecimal
// digit. Digest and trace identities are lower-case only, so an upper-case
// digit is rejected rather than normalized.
func lowerHexDigit(character rune) bool {
	return character >= '0' && character <= '9' || character >= 'a' && character <= 'f'
}
