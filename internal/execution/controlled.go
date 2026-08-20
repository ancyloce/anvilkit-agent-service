package execution

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sync"
	"time"

	"github.com/ancyloce/anvilkit-agent-service/internal/agent"
	"github.com/ancyloce/anvilkit-agent-service/internal/modelgateway"
	"github.com/ancyloce/anvilkit-agent-service/internal/problem"
	"github.com/ancyloce/anvilkit-agent-service/internal/tools"
)

// ControlledImplementation is the only accepted configuration value for
// selecting the controlled fakes below. Production configuration rejects it;
// nothing selects these implementations implicitly.
const ControlledImplementation = "controlled-fake"

// ControlledProviderID names the controlled fake model provider. The name
// carries "fake" deliberately so production configuration guards reject it.
const ControlledProviderID modelgateway.ProviderID = "controlled-fake-provider"

// ScriptedAdapter is a deterministic controlled model adapter behind the
// production adapter port. Its provider idempotency, settled outcomes, script
// position, and usage evidence all live in a durable, process-external
// ledger, so a replay after a real process or adapter restart reads what
// already happened instead of calling the provider again, advancing the
// script again, or billing again. It also enforces the token and cost
// ceilings the gateway authorized for the attempt.
type ScriptedAdapter struct {
	lock     sync.Mutex
	ledger   ScriptLedger
	script   [][]byte
	requests []modelgateway.AdapterRequest
	Metered  modelgateway.AdapterResponse
	// RetryableFailures makes the first N distinct physical operations fail
	// with a retryable provider error while still reporting the consumption
	// they caused, so retry accounting can be observed exactly. It is part of
	// the settlement proposal, so the count that matters is the durable one.
	RetryableFailures int
}

// NewScriptedAdapter builds the controlled adapter over a durable ledger. The
// ledger is required: an adapter with only process memory behind it would
// re-call the provider after any restart.
func NewScriptedAdapter(ledger ScriptLedger, script ...[]byte) (*ScriptedAdapter, error) {
	if ledger == nil {
		return nil, fmt.Errorf("scripted adapter: a durable provider ledger is required")
	}
	if len(script) == 0 {
		return nil, fmt.Errorf("scripted adapter: at least one scripted output is required")
	}
	copied := make([][]byte, 0, len(script))
	for _, output := range script {
		copied = append(copied, append([]byte(nil), output...))
	}
	return &ScriptedAdapter{
		ledger:  ledger,
		script:  copied,
		Metered: modelgateway.AdapterResponse{InputTokens: 100, OutputTokens: 50, CostMicros: 1000},
	}, nil
}

func (a *ScriptedAdapter) Invoke(ctx context.Context, request modelgateway.AdapterRequest) (modelgateway.AdapterResponse, error) {
	if err := ctx.Err(); err != nil {
		return modelgateway.AdapterResponse{}, err
	}
	a.lock.Lock()
	a.requests = append(a.requests, request)
	metered := modelgateway.AdapterResponse{InputTokens: a.Metered.InputTokens, OutputTokens: a.Metered.OutputTokens, CostMicros: a.Metered.CostMicros}
	failures := a.RetryableFailures
	script := a.script
	a.lock.Unlock()
	if request.IdempotencyKey == "" || request.InvocationID == "" {
		return modelgateway.AdapterResponse{}, fmt.Errorf("scripted adapter: an operation identity is required for every provider call")
	}
	// The durable record answers first. A settled operation replays from what
	// was recorded, whichever process recorded it.
	if recorded, settled, err := a.ledger.Settled(ctx, request.IdempotencyKey); err != nil {
		return modelgateway.AdapterResponse{}, fmt.Errorf("read settled provider operation: %w", err)
	} else if settled {
		return a.replay(recorded, script)
	}
	if metered.InputTokens > request.MaximumInputTokens || metered.OutputTokens > request.MaximumOutputTokens || metered.InputTokens+metered.OutputTokens > request.MaximumTotalTokens || metered.CostMicros > request.MaximumCostMicros {
		// The attempt was authorized for less than this call would consume.
		// Refusing before consuming anything is the enforceable behavior a
		// real adapter must implement for the limits it is handed.
		return modelgateway.AdapterResponse{}, fmt.Errorf("scripted adapter: attempt limits do not authorize this provider call")
	}
	operation, err := a.ledger.Settle(ctx, ScriptProposal{
		Key:               request.IdempotencyKey,
		RetryableFailures: failures,
		ScriptLength:      len(script),
		InputTokens:       metered.InputTokens,
		OutputTokens:      metered.OutputTokens,
		CostMicros:        metered.CostMicros,
	})
	if err != nil {
		return modelgateway.AdapterResponse{}, fmt.Errorf("settle provider operation: %w", err)
	}
	response, replayErr := a.replay(operation, script)
	if replayErr == nil && len(response.Output) > request.MaximumOutputBytes {
		return modelgateway.AdapterResponse{}, fmt.Errorf("scripted output exceeds the output byte limit")
	}
	return response, replayErr
}

// replay renders the response one settled operation stands for. The stored
// record carries the script position and the consumption, so the same
// operation identity always renders the same bytes.
func (a *ScriptedAdapter) replay(operation ScriptOperation, script [][]byte) (modelgateway.AdapterResponse, error) {
	response := modelgateway.AdapterResponse{InputTokens: operation.InputTokens, OutputTokens: operation.OutputTokens, CostMicros: operation.CostMicros}
	if operation.Failure {
		return response, modelgateway.RetryableError{Err: fmt.Errorf("scripted adapter: transient provider failure")}
	}
	if operation.Position < 0 || operation.Position >= len(script) {
		return modelgateway.AdapterResponse{}, fmt.Errorf("scripted adapter: settled script position %d is outside the loaded script", operation.Position)
	}
	response.Output = append([]byte(nil), script[operation.Position]...)
	return response, nil
}

// Requests returns every adapter request the scripted adapter observed, in
// invocation order. Tests use it to prove that a replayed durable step
// reissues the same provider identity instead of a fresh one.
func (a *ScriptedAdapter) Requests() []modelgateway.AdapterRequest {
	a.lock.Lock()
	defer a.lock.Unlock()
	return append([]modelgateway.AdapterRequest(nil), a.requests...)
}

// Billed reports how many distinct provider operations the durable ledger has
// actually metered. A replayed operation key never increases it, and a new
// adapter instance over the same ledger reports the same number.
func (a *ScriptedAdapter) Billed(ctx context.Context) (int, error) {
	return a.ledger.Count(ctx)
}

// ControlledCandidate returns a minimal valid ComponentPackageSpec used as
// the controlled scripted final candidate.
func ControlledCandidate() json.RawMessage {
	return json.RawMessage(`{"kind":"ComponentPackageSpec","packageIntent":{"name":"controlled-section","version":"1.0.0","componentType":"section"},"inputs":[{"artifactId":"artifact.controlled.001","digest":"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","mediaType":"application/json","sizeBytes":128}],"outputs":[{"name":"bundle","schema":{"componentName":"anvilkit.contract.schema.example","digest":"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"},"maximumBytes":10485760}],"validationConstraints":[{"policyId":"policy.controlled","version":"v1","digest":"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}],"buildPolicy":{"policyId":"policy.controlled","version":"v1","digest":"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"},"certificationPolicy":{"policyId":"policy.controlled","version":"v1","digest":"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}}`)
}

// PlanStep renders one typed-plan document proposing a single step.
func PlanStep(tool string, arguments map[string]json.RawMessage) []byte {
	raw, err := json.Marshal(struct {
		Kind  string `json:"kind"`
		Steps []struct {
			Tool      string                     `json:"tool"`
			Arguments map[string]json.RawMessage `json:"arguments"`
		} `json:"steps"`
	}{Kind: "TypedPlan", Steps: []struct {
		Tool      string                     `json:"tool"`
		Arguments map[string]json.RawMessage `json:"arguments"`
	}{{Tool: tool, Arguments: arguments}}})
	if err != nil {
		return nil
	}
	return raw
}

// ModelPolicySource resolves the signed ModelPolicy an AgentDefinition pins.
// Provider selection reads the attested policy through it; the model stack
// declares no eligibility rules of its own, so nothing it selects can diverge
// from what the approved catalog attests.
type ModelPolicySource interface {
	ModelPolicy(policyID, version string) (agent.ModelPolicy, bool)
}

// ControlledModelStack composes the production model gateway around one
// explicitly selected scripted adapter and one controlled provider registry.
// Eligibility comes from the signed model policy the run's definition pins.
type ControlledModelStack struct {
	registry *modelgateway.Registry
	gateway  *modelgateway.Gateway
	policies ModelPolicySource
}

// MemoryModelRecorder records invocation lifecycle facts in memory.
type MemoryModelRecorder struct {
	lock    sync.Mutex
	Records []modelgateway.InvocationRecord
}

func (r *MemoryModelRecorder) BeforeDisclosure(context.Context, modelgateway.InvocationRecord) error {
	return nil
}
func (r *MemoryModelRecorder) BeforeAttempt(context.Context, modelgateway.InvocationRecord) error {
	return nil
}
func (r *MemoryModelRecorder) Complete(_ context.Context, record modelgateway.InvocationRecord) error {
	r.lock.Lock()
	defer r.lock.Unlock()
	r.Records = append(r.Records, record)
	return nil
}

type contextSleeper struct{}

func (contextSleeper) Sleep(ctx context.Context, duration time.Duration) error {
	timer := time.NewTimer(duration)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}

// NewControlledModelStack builds the controlled model composition: one
// enabled controlled provider, the production registry and gateway, and the
// scripted adapter.
func NewControlledModelStack(adapter modelgateway.Adapter, clock Clock, recorder modelgateway.Recorder, policies ModelPolicySource) (*ControlledModelStack, error) {
	if adapter == nil || clock == nil || recorder == nil || policies == nil {
		return nil, fmt.Errorf("controlled model stack: adapter, clock, durable invocation recorder, and signed model policy source are required")
	}
	snapshot := modelgateway.Snapshot{Version: "controlled", Providers: []modelgateway.Provider{{
		ID:                ControlledProviderID,
		ModelVersion:      "controlled",
		Regions:           []string{"local"},
		DataClasses:       []modelgateway.DataClass{modelgateway.Public, modelgateway.Internal},
		Capabilities:      []string{"provider.invoke"},
		SafetyLevel:       3,
		MaximumCostMicros: 1_000_000,
		Priority:          1,
		Enabled:           true,
	}}}
	registry, err := modelgateway.NewRegistry(snapshot)
	if err != nil {
		return nil, fmt.Errorf("controlled model stack: %w", err)
	}
	gateway, err := modelgateway.NewGateway(map[modelgateway.ProviderID]modelgateway.Adapter{ControlledProviderID: adapter}, recorder, clock, contextSleeper{})
	if err != nil {
		return nil, fmt.Errorf("controlled model stack: %w", err)
	}
	return &ControlledModelStack{registry: registry, gateway: gateway, policies: policies}, nil
}

// Select satisfies the runner Selector port. The definition's pinned model
// policy reference is resolved against the approved catalog and must match it
// by identity and digest; the attested rules are then the only eligibility
// input. A reference the catalog does not carry selects nothing.
func (s *ControlledModelStack) Select(_ context.Context, workspaceID string, reference agent.PolicyReference) (modelgateway.Selection, error) {
	signed, approved := s.policies.ModelPolicy(reference.PolicyID, reference.Version)
	if !approved || signed.Digest != reference.Digest {
		details := problem.New(problem.CodeContractInvalid, "")
		details.Detail = "the pinned model policy is not the signed model policy the approved catalog carries"
		return modelgateway.Selection{}, details
	}
	return s.registry.Select(workspaceID, gatewayPolicy(signed))
}

// gatewayPolicy projects the signed model policy onto the gateway's
// eligibility contract. Every axis comes from the attested document; nothing
// is defaulted here, so a rule the policy does not state cannot be invented.
func gatewayPolicy(signed agent.ModelPolicy) modelgateway.Policy {
	policy := modelgateway.Policy{
		Version:           signed.PolicyID + ":" + signed.Version,
		AllowedRegions:    append([]string(nil), signed.Rules.AllowedRegions...),
		Capability:        signed.Rules.Capability,
		AllowRetention:    signed.Rules.AllowRetention,
		AllowTraining:     signed.Rules.AllowTraining,
		MinimumSafety:     signed.Rules.MinimumSafety,
		MaximumCostMicros: signed.Rules.MaximumCostMicros,
	}
	for _, provider := range signed.Rules.AllowedProviders {
		policy.AllowedProviders = append(policy.AllowedProviders, modelgateway.ProviderID(provider))
	}
	for _, class := range signed.Rules.AllowedDataClasses {
		policy.DataClasses = append(policy.DataClasses, modelgateway.DataClass(class))
	}
	return policy
}

// Invoke satisfies the runner Invoker port.
func (s *ControlledModelStack) Invoke(ctx context.Context, request modelgateway.InvokeRequest) (modelgateway.AdapterResponse, modelgateway.InvocationRecord, error) {
	return s.gateway.Invoke(ctx, request)
}

// ControlledToolExecutor is an idempotent echo executor behind the
// production tool executor port. Repeating an idempotency key returns the
// recorded result without executing again.
type ControlledToolExecutor struct {
	lock       sync.Mutex
	results    map[string]ToolResult
	executions int
}

// Executions reports how many tool calls actually executed. Reading it takes
// the same lock the executor writes under, so a test may observe it while a
// run is still in flight.
func (e *ControlledToolExecutor) Executions() int {
	e.lock.Lock()
	defer e.lock.Unlock()
	return e.executions
}

func NewControlledToolExecutor() *ControlledToolExecutor {
	return &ControlledToolExecutor{results: make(map[string]ToolResult)}
}

func (e *ControlledToolExecutor) Execute(_ context.Context, invocation ToolInvocation) (ToolResult, error) {
	if invocation.IdempotencyKey == "" || invocation.ToolID == "" {
		return ToolResult{}, fmt.Errorf("controlled tool executor: idempotency key and tool identity are required")
	}
	e.lock.Lock()
	defer e.lock.Unlock()
	if recorded, replay := e.results[invocation.IdempotencyKey]; replay {
		return recorded, nil
	}
	e.executions++
	output, err := json.Marshal(struct {
		Tool     string          `json:"tool"`
		Echo     json.RawMessage `json:"echo"`
		Executed int             `json:"executed"`
	}{invocation.ToolID, invocation.Arguments, e.executions})
	if err != nil {
		return ToolResult{}, err
	}
	result := ToolResult{Output: output}
	e.results[invocation.IdempotencyKey] = result
	return result, nil
}

// ControlledDomainPort simulates the authoritative domain owner. It is
// idempotent by operation identity, returns the configured outcome, and can
// be driven through the failure shapes a real owner produces: an effect that
// lands while the answer is lost, a submission that never arrives, and an
// operation the owner holds but has not yet decided.
type ControlledDomainPort struct {
	lock     sync.Mutex
	Outcome  string
	commands map[string]DomainOutcome
	commits  int
	// loseAnswer records the effect and then fails the call, which is what a
	// crash or a lost response after a successful domain effect looks like to
	// the caller.
	loseAnswer bool
	// loseSubmission fails the call without recording anything, which is a
	// submission that never reached the owner.
	loseSubmission bool
	// unsettled makes the owner hold recorded operations undecided.
	unsettled bool
	// reconciliations counts how many times the owner was asked what became
	// of an operation.
	reconciliations int
}

// Commits reports how many distinct governed effects were submitted.
func (p *ControlledDomainPort) Commits() int {
	p.lock.Lock()
	defer p.lock.Unlock()
	return p.commits
}

// Reconciliations reports how many times the authoritative record was read.
func (p *ControlledDomainPort) Reconciliations() int {
	p.lock.Lock()
	defer p.lock.Unlock()
	return p.reconciliations
}

// LoseAnswer records effects and then fails the call, modelling a crash after
// a successful domain effect.
func (p *ControlledDomainPort) LoseAnswer(lose bool) {
	p.lock.Lock()
	defer p.lock.Unlock()
	p.loseAnswer = lose
}

// LoseSubmission fails calls without recording anything, modelling a
// submission that never reached the authoritative owner.
func (p *ControlledDomainPort) LoseSubmission(lose bool) {
	p.lock.Lock()
	defer p.lock.Unlock()
	p.loseSubmission = lose
}

// HoldUndecided makes the owner keep recorded operations unsettled.
func (p *ControlledDomainPort) HoldUndecided(hold bool) {
	p.lock.Lock()
	defer p.lock.Unlock()
	p.unsettled = hold
}

func NewControlledDomainPort(outcome string) *ControlledDomainPort {
	return &ControlledDomainPort{Outcome: outcome, commands: make(map[string]DomainOutcome)}
}

func (p *ControlledDomainPort) Commit(_ context.Context, command DomainCommand) (DomainOutcome, error) {
	if command.OperationID == "" || command.AuthorizationID == "" || command.ArtifactDigest == "" {
		return DomainOutcome{}, fmt.Errorf("controlled domain port: operation, authorization, and artifact identity are required")
	}
	p.lock.Lock()
	defer p.lock.Unlock()
	if recorded, replay := p.commands[command.OperationID]; replay {
		return recorded, nil
	}
	if p.loseSubmission {
		return DomainOutcome{}, fmt.Errorf("controlled domain port: the submission never reached the authoritative owner")
	}
	p.commits++
	outcome := DomainOutcome{Status: p.Outcome}
	if outcome.Status == "" {
		outcome.Status = DomainConfirmed
	}
	p.commands[command.OperationID] = outcome
	if p.loseAnswer {
		return DomainOutcome{}, fmt.Errorf("controlled domain port: the effect was applied but the answer was lost")
	}
	return outcome, nil
}

// Reconcile answers what became of one submitted effect. An operation the
// owner has no record of is reported as absent, which is the only answer that
// proves nothing landed.
func (p *ControlledDomainPort) Reconcile(_ context.Context, query DomainQuery) (DomainOutcome, bool, error) {
	if query.OperationID == "" || query.WorkspaceID == "" || query.RunID == "" {
		return DomainOutcome{}, false, fmt.Errorf("controlled domain port: operation, workspace, and run identity are required")
	}
	p.lock.Lock()
	defer p.lock.Unlock()
	p.reconciliations++
	recorded, known := p.commands[query.OperationID]
	if !known {
		return DomainOutcome{}, false, nil
	}
	if p.unsettled {
		return DomainOutcome{Status: DomainUnsettled}, true, nil
	}
	return recorded, true, nil
}

// ControlledCommitAuthority issues deterministic durable authorization
// identities bound to the idempotency key.
type ControlledCommitAuthority struct {
	lock   sync.Mutex
	issued []AuthorizationRequest
}

// Issued returns every authorization request the authority received.
func (a *ControlledCommitAuthority) Issued() []AuthorizationRequest {
	a.lock.Lock()
	defer a.lock.Unlock()
	return append([]AuthorizationRequest(nil), a.issued...)
}

func (a *ControlledCommitAuthority) Issue(_ context.Context, request AuthorizationRequest) (IssuedAuthorization, error) {
	if request.IdempotencyKey == "" || request.ArtifactDigest == "" {
		return IssuedAuthorization{}, fmt.Errorf("controlled commit authority: idempotency key and artifact digest are required")
	}
	a.lock.Lock()
	defer a.lock.Unlock()
	a.issued = append(a.issued, request)
	digest := sha256.Sum256([]byte(request.IdempotencyKey))
	return IssuedAuthorization{AuthorizationID: "authorization." + hex.EncodeToString(digest[:16])}, nil
}

// ControlledArtifactPort answers artifact eligibility for the controlled
// topology. Every candidate is eligible until it is explicitly withdrawn,
// which models quarantine, deletion, or expiry between approval and commit.
type ControlledArtifactPort struct {
	lock       sync.Mutex
	ineligible map[string]string
	queries    []ArtifactQuery
}

// Queries returns every eligibility question the commit gate asked.
func (p *ControlledArtifactPort) Queries() []ArtifactQuery {
	p.lock.Lock()
	defer p.lock.Unlock()
	return append([]ArtifactQuery(nil), p.queries...)
}

func NewControlledArtifactPort() *ControlledArtifactPort {
	return &ControlledArtifactPort{ineligible: make(map[string]string)}
}

// Withdraw makes one artifact digest ineligible from the next check onwards.
func (p *ControlledArtifactPort) Withdraw(artifactDigest, reason string) {
	p.lock.Lock()
	defer p.lock.Unlock()
	p.ineligible[artifactDigest] = reason
}

func (p *ControlledArtifactPort) Eligible(_ context.Context, query ArtifactQuery) (ArtifactEligibility, error) {
	if query.WorkspaceID == "" || query.ProjectID == "" || query.RunID == "" || query.ArtifactDigest == "" {
		return ArtifactEligibility{}, fmt.Errorf("controlled artifact port: workspace, project, run, and artifact identity are required")
	}
	p.lock.Lock()
	defer p.lock.Unlock()
	p.queries = append(p.queries, query)
	if reason, withdrawn := p.ineligible[query.ArtifactDigest]; withdrawn {
		return ArtifactEligibility{Eligible: false, Reason: reason}, nil
	}
	return ArtifactEligibility{Eligible: true}, nil
}

// NewApprovedToolProfile builds the running tool profile from the approved
// catalog's signed ToolDefinitions. The profile is derived from the attested
// material rather than declared beside it, so the capability, side-effect
// class, risk, approval policy, timeout, and retry policy the process
// dispatches under are the ones the catalog signed. Each tool's input schema
// is pinned to the digest of its own argument schema so the Tool Guard
// validates real arguments.
func NewApprovedToolProfile(bindings []agent.ToolBinding, schemaDigest, catalogDigest string, arguments *PinnedToolArgumentValidator) (tools.Profile, error) {
	if arguments == nil {
		return tools.Profile{}, fmt.Errorf("approved tool profile: the pinned argument validator is required")
	}
	if !validDigestString(schemaDigest) || !validDigestString(catalogDigest) {
		return tools.Profile{}, fmt.Errorf("approved tool profile: the pinned schema and catalog digests are required")
	}
	definitions := make([]tools.Definition, 0, len(bindings))
	for _, binding := range bindings {
		inputSchema, err := arguments.Reference(binding.ToolID + ".arguments")
		if err != nil {
			return tools.Profile{}, err
		}
		definitions = append(definitions, toolDefinitionOf(binding, inputSchema, schemaDigest))
	}
	// The profile policy is bound to the exact approved catalog, so a profile
	// built from a different catalog is a different profile by digest.
	policy := tools.PolicyReference{PolicyID: "policy.tool.baseline", Version: "v1", Digest: catalogDigest}
	return tools.NewProfile("profile.approved", "v1", policy, definitions)
}

// toolDefinitionOf projects one signed catalog binding onto the running tool
// definition the guard dispatches. It is the single place the two shapes meet,
// so the executor's per-run material check compares like with like.
func toolDefinitionOf(binding agent.ToolBinding, inputSchema tools.SchemaReference, schemaDigest string) tools.Definition {
	return tools.Definition{
		Kind:                "ToolDefinition",
		Capability:          binding.Capability,
		InputSchema:         inputSchema,
		OutputSchema:        tools.SchemaReference{ComponentName: "anvilkit.contract.schema.tool-definition", Digest: schemaDigest},
		SideEffectClass:     binding.SideEffectClass,
		RiskClass:           binding.RiskClass,
		ApprovalPolicy:      tools.PolicyReference{PolicyID: binding.ApprovalPolicy.PolicyID, Version: binding.ApprovalPolicy.Version, Digest: binding.ApprovalPolicy.Digest},
		TimeoutPolicy:       tools.TimeoutPolicy{TimeoutMilliseconds: binding.TimeoutMilliseconds},
		RetryPolicy:         tools.RetryPolicy{MaximumAttempts: binding.MaximumAttempts, BackoffMilliseconds: binding.BackoffMilliseconds, Retryability: append([]string(nil), binding.Retryability...)},
		AcceptedDataClasses: append([]string(nil), binding.AcceptedDataClasses...),
		ToolID:              binding.ToolID,
	}
}

// MemoryToolRecorder records every Tool Guard decision durably in memory.
type MemoryToolRecorder struct {
	lock      sync.Mutex
	Decisions []RecordedToolDecision
}

type RecordedToolDecision struct {
	Intent   tools.Intent
	Proposal tools.Proposal
	Decision tools.Decision
}

func (r *MemoryToolRecorder) Record(_ context.Context, intent tools.Intent, proposal tools.Proposal, decision tools.Decision) error {
	r.lock.Lock()
	defer r.lock.Unlock()
	r.Decisions = append(r.Decisions, RecordedToolDecision{Intent: intent, Proposal: proposal, Decision: decision})
	return nil
}
