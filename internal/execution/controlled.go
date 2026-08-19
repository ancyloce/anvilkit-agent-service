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
	"github.com/ancyloce/anvilkit-agent-service/internal/agent/runner"
	"github.com/ancyloce/anvilkit-agent-service/internal/modelgateway"
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
// production adapter port. It returns its scripted outputs in invocation
// order and repeats the final entry when the script is exhausted.
type ScriptedAdapter struct {
	lock    sync.Mutex
	script  [][]byte
	index   int
	Metered modelgateway.AdapterResponse
}

func NewScriptedAdapter(script ...[]byte) *ScriptedAdapter {
	copied := make([][]byte, 0, len(script))
	for _, output := range script {
		copied = append(copied, append([]byte(nil), output...))
	}
	return &ScriptedAdapter{script: copied, Metered: modelgateway.AdapterResponse{InputTokens: 100, OutputTokens: 50, CostMicros: 1000}}
}

func (a *ScriptedAdapter) Invoke(ctx context.Context, request modelgateway.AdapterRequest) (modelgateway.AdapterResponse, error) {
	if err := ctx.Err(); err != nil {
		return modelgateway.AdapterResponse{}, err
	}
	a.lock.Lock()
	defer a.lock.Unlock()
	if len(a.script) == 0 {
		return modelgateway.AdapterResponse{}, fmt.Errorf("scripted adapter has no outputs")
	}
	position := a.index
	if position >= len(a.script) {
		position = len(a.script) - 1
	}
	a.index++
	output := append([]byte(nil), a.script[position]...)
	if len(output) > request.MaximumOutputBytes {
		return modelgateway.AdapterResponse{}, fmt.Errorf("scripted output exceeds the output byte limit")
	}
	return modelgateway.AdapterResponse{Output: output, InputTokens: a.Metered.InputTokens, OutputTokens: a.Metered.OutputTokens, CostMicros: a.Metered.CostMicros}, nil
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

// ControlledModelStack composes the production model gateway around one
// explicitly selected scripted adapter and one controlled provider registry.
type ControlledModelStack struct {
	registry *modelgateway.Registry
	gateway  *modelgateway.Gateway
	policy   modelgateway.Policy
}

// ControlledIDs allocates deterministic-format invocation identities.
type ControlledIDs struct {
	lock sync.Mutex
	next int64
}

func (c *ControlledIDs) InvocationID() string {
	c.lock.Lock()
	defer c.lock.Unlock()
	c.next++
	return fmt.Sprintf("invocation.%08d", c.next)
}

func (c *ControlledIDs) AttemptID(attempt int) modelgateway.AttemptID {
	c.lock.Lock()
	defer c.lock.Unlock()
	c.next++
	return modelgateway.AttemptID(fmt.Sprintf("attempt.%08d.%02d", c.next, attempt))
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
func NewControlledModelStack(adapter modelgateway.Adapter, clock Clock) (*ControlledModelStack, error) {
	if adapter == nil || clock == nil {
		return nil, fmt.Errorf("controlled model stack: adapter and clock are required")
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
	gateway, err := modelgateway.NewGateway(map[modelgateway.ProviderID]modelgateway.Adapter{ControlledProviderID: adapter}, &MemoryModelRecorder{}, &ControlledIDs{}, clock, contextSleeper{})
	if err != nil {
		return nil, fmt.Errorf("controlled model stack: %w", err)
	}
	policy := modelgateway.Policy{
		Version:           "controlled",
		AllowedProviders:  []modelgateway.ProviderID{ControlledProviderID},
		AllowedRegions:    []string{"local"},
		DataClasses:       []modelgateway.DataClass{modelgateway.Public, modelgateway.Internal},
		Capability:        "provider.invoke",
		MinimumSafety:     1,
		MaximumCostMicros: 10_000_000,
	}
	return &ControlledModelStack{registry: registry, gateway: gateway, policy: policy}, nil
}

// Select satisfies the runner Selector port.
func (s *ControlledModelStack) Select(_ context.Context, workspaceID string, _ agent.PolicyReference) (modelgateway.Selection, error) {
	return s.registry.Select(workspaceID, s.policy)
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
	Executions int
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
	e.Executions++
	output, err := json.Marshal(struct {
		Tool     string          `json:"tool"`
		Echo     json.RawMessage `json:"echo"`
		Executed int             `json:"executed"`
	}{invocation.ToolID, invocation.Arguments, e.Executions})
	if err != nil {
		return ToolResult{}, err
	}
	result := ToolResult{Output: output}
	e.results[invocation.IdempotencyKey] = result
	return result, nil
}

// ControlledDomainPort simulates the authoritative domain owner. It is
// idempotent by operation identity and returns the configured outcome.
type ControlledDomainPort struct {
	lock     sync.Mutex
	Outcome  string
	commands map[string]DomainOutcome
	Commits  int
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
	p.Commits++
	outcome := DomainOutcome{Status: p.Outcome}
	if outcome.Status == "" {
		outcome.Status = DomainConfirmed
	}
	p.commands[command.OperationID] = outcome
	return outcome, nil
}

// ControlledCommitAuthority issues deterministic durable authorization
// identities bound to the idempotency key.
type ControlledCommitAuthority struct {
	lock   sync.Mutex
	Issued []AuthorizationRequest
}

func (a *ControlledCommitAuthority) Issue(_ context.Context, request AuthorizationRequest) (IssuedAuthorization, error) {
	if request.IdempotencyKey == "" || request.ArtifactDigest == "" {
		return IssuedAuthorization{}, fmt.Errorf("controlled commit authority: idempotency key and artifact digest are required")
	}
	a.lock.Lock()
	defer a.lock.Unlock()
	a.Issued = append(a.Issued, request)
	digest := sha256.Sum256([]byte(request.IdempotencyKey))
	return IssuedAuthorization{AuthorizationID: "authorization." + hex.EncodeToString(digest[:16])}, nil
}

// ControlledAuthorityView reports fully active current authority matching
// the controlled tool topology.
type ControlledAuthorityView struct {
	AllowedTools []string
}

func (v ControlledAuthorityView) Current(context.Context, runner.RunView) (tools.CurrentAuthority, error) {
	return tools.CurrentAuthority{
		WorkspaceActive:  true,
		ActorActive:      true,
		PermissionActive: true,
		PolicyActive:     true,
		AllowedTools:     append([]string(nil), v.AllowedTools...),
		AllowedEffects:   []string{"read"},
		MaximumRisk:      "low",
		DataClasses:      []string{"public", "internal"},
	}, nil
}

// NewControlledToolProfile builds the minimal pinned tool profile for the
// controlled topology. schemaDigest must be the pinned tool-definition
// schema digest.
func NewControlledToolProfile(schemaDigest string) (tools.Profile, error) {
	policy := tools.PolicyReference{PolicyID: "policy.tool.baseline", Version: "v1", Digest: schemaDigest}
	definition := func(toolID, capability, risk string) tools.Definition {
		return tools.Definition{
			Kind:                "ToolDefinition",
			Capability:          capability,
			InputSchema:         tools.SchemaReference{ComponentName: "anvilkit.contract.schema.tool-definition", Digest: schemaDigest},
			OutputSchema:        tools.SchemaReference{ComponentName: "anvilkit.contract.schema.tool-definition", Digest: schemaDigest},
			SideEffectClass:     "read",
			RiskClass:           risk,
			ApprovalPolicy:      policy,
			TimeoutPolicy:       tools.TimeoutPolicy{TimeoutMilliseconds: 30000},
			RetryPolicy:         tools.RetryPolicy{MaximumAttempts: 1, BackoffMilliseconds: 0, Retryability: []string{"safe-immediate"}},
			AcceptedDataClasses: []string{"public", "internal"},
			ToolID:              toolID,
		}
	}
	return tools.NewProfile("profile.controlled", "v1", policy, []tools.Definition{
		definition("anvilkit.tool.context-echo", "fake.execute", "low"),
		definition("anvilkit.tool.contract-validate", "contract.validate", "low"),
		definition("anvilkit.tool.artifact-scan", "artifact.scan", "low"),
	})
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
