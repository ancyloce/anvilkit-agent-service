package runner_test

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"sync"
	"testing"
	"time"

	contractvalidator "github.com/ancyloce/anvilkit-agent-service/contracts/validator"
	"github.com/ancyloce/anvilkit-agent-service/internal/agent"
	"github.com/ancyloce/anvilkit-agent-service/internal/agent/runner"
	"github.com/ancyloce/anvilkit-agent-service/internal/contextcompiler"
	"github.com/ancyloce/anvilkit-agent-service/internal/modelgateway"
	"github.com/ancyloce/anvilkit-agent-service/internal/problem"
	"github.com/ancyloce/anvilkit-agent-service/internal/tools"
)

func testRegistry(t *testing.T) *agent.Registry {
	t.Helper()
	adapter, err := contractvalidator.New("../../..")
	if err != nil {
		t.Fatal(err)
	}
	schemaBytes, err := os.ReadFile("../../../contracts/agent/schemas/agent-definition.schema.json")
	if err != nil {
		t.Fatal(err)
	}
	registry, err := agent.NewRegistry(context.Background(), agent.RegistryConfig{Source: agent.EmbeddedCatalog{}, Validator: adapter, DefinitionSchemaURI: agent.DefinitionSchemaURI(schemaBytes)})
	if err != nil {
		t.Fatal(err)
	}
	return registry
}

func managerDefinition(t *testing.T, registry *agent.Registry) agent.Definition {
	t.Helper()
	for _, definition := range registry.Definitions() {
		if definition.Role == agent.RoleManager {
			return definition
		}
	}
	t.Fatal("manager definition missing")
	return agent.Definition{}
}

func specialistDefinition(t *testing.T, registry *agent.Registry) agent.Definition {
	t.Helper()
	for _, definition := range registry.Definitions() {
		if definition.Role == agent.RoleSpecialist {
			return definition
		}
	}
	t.Fatal("specialist definition missing")
	return agent.Definition{}
}

// scriptedInvoker is a strict scripted model port: it fails when the script
// is exhausted and never invents outputs.
type scriptedInvoker struct {
	lock    sync.Mutex
	outputs [][]byte
	calls   int
}

func (s *scriptedInvoker) Invoke(_ context.Context, request modelgateway.InvokeRequest) (modelgateway.AdapterResponse, modelgateway.InvocationRecord, error) {
	s.lock.Lock()
	defer s.lock.Unlock()
	if len(request.Context) == 0 {
		return modelgateway.AdapterResponse{}, modelgateway.InvocationRecord{}, fmt.Errorf("scripted invoker requires compiled context")
	}
	if s.calls >= len(s.outputs) {
		return modelgateway.AdapterResponse{}, modelgateway.InvocationRecord{}, fmt.Errorf("scripted invoker exhausted after %d calls", s.calls)
	}
	output := s.outputs[s.calls]
	s.calls++
	return modelgateway.AdapterResponse{Output: append([]byte(nil), output...)},
		modelgateway.InvocationRecord{InputTokens: 100, OutputTokens: 50, CostMicros: 1000}, nil
}

type staticSelector struct{}

func (staticSelector) Select(context.Context, string, agent.PolicyReference) (modelgateway.Selection, error) {
	return modelgateway.Selection{MaximumCostMicros: 1_000_000}, nil
}

type staticAuthorityView struct {
	inactive bool
	allowed  []string
}

func (v staticAuthorityView) Current(context.Context, runner.RunView) (tools.CurrentAuthority, error) {
	return tools.CurrentAuthority{
		WorkspaceActive:  !v.inactive,
		ActorActive:      !v.inactive,
		PermissionActive: !v.inactive,
		PolicyActive:     !v.inactive,
		AllowedTools:     v.allowed,
		AllowedEffects:   []string{"read"},
		MaximumRisk:      "low",
		DataClasses:      []string{"public", "internal"},
	}, nil
}

type recordingToolRecorder struct {
	lock     sync.Mutex
	recorded []tools.Decision
}

func (r *recordingToolRecorder) Record(_ context.Context, _ tools.Intent, _ tools.Proposal, decision tools.Decision) error {
	r.lock.Lock()
	defer r.lock.Unlock()
	r.recorded = append(r.recorded, decision)
	return nil
}

type acceptAllValidator struct{ denyComponent string }

func (v acceptAllValidator) Validate(_ context.Context, reference agent.SchemaReference, _ json.RawMessage) error {
	if v.denyComponent != "" && reference.ComponentName == v.denyComponent {
		return problem.New(problem.CodeContractInvalid, "")
	}
	return nil
}

type fixedClock struct{ now time.Time }

func (c fixedClock) Now() time.Time { return c.now }

func testToolProfile(t *testing.T) tools.Profile {
	t.Helper()
	schemaBytes, err := os.ReadFile("../../../contracts/agent/schemas/tool-definition.schema.json")
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(schemaBytes)
	pinned := "sha256:" + hex.EncodeToString(digest[:])
	policy := tools.PolicyReference{PolicyID: "policy.tool.baseline", Version: "v1", Digest: pinned}
	definition := func(toolID, capability string) tools.Definition {
		return tools.Definition{Kind: "ToolDefinition", Capability: capability, InputSchema: tools.SchemaReference{ComponentName: "anvilkit.contract.schema.tool-definition", Digest: pinned}, OutputSchema: tools.SchemaReference{ComponentName: "anvilkit.contract.schema.tool-definition", Digest: pinned}, SideEffectClass: "read", RiskClass: "low", ApprovalPolicy: policy, TimeoutPolicy: tools.TimeoutPolicy{TimeoutMilliseconds: 30000}, RetryPolicy: tools.RetryPolicy{MaximumAttempts: 1, Retryability: []string{"safe-immediate"}}, AcceptedDataClasses: []string{"public", "internal"}, ToolID: toolID}
	}
	profile, err := tools.NewProfile("profile.test", "v1", policy, []tools.Definition{
		definition("anvilkit.tool.context-echo", "fake.execute"),
		definition("anvilkit.tool.contract-validate", "contract.validate"),
		definition("anvilkit.tool.artifact-scan", "artifact.scan"),
	})
	if err != nil {
		t.Fatal(err)
	}
	return profile
}

type runnerHarness struct {
	runner   *runner.Runner
	registry *agent.Registry
	invoker  *scriptedInvoker
	recorder *recordingToolRecorder
}

func newRunnerHarness(t *testing.T, outputs [][]byte, options ...func(*runner.Config)) *runnerHarness {
	t.Helper()
	registry := testRegistry(t)
	invoker := &scriptedInvoker{outputs: outputs}
	recorder := &recordingToolRecorder{}
	guard, err := tools.NewGuard(testToolProfile(t), recorder, fixedClock{time.Unix(1000, 0)}, tools.JSONArgumentValidator{})
	if err != nil {
		t.Fatal(err)
	}
	cfg := runner.Config{
		Registry:  registry,
		Compiler:  contextcompiler.New(nil),
		Selector:  staticSelector{},
		Invoker:   invoker,
		Guard:     guard,
		Authority: staticAuthorityView{allowed: []string{"anvilkit.tool.context-echo"}},
		Validator: acceptAllValidator{},
		Clock:     fixedClock{time.Unix(1000, 0)},
		Limits:    runner.Limits{MaximumOutputBytes: 65536, MaximumInputTokens: 100000, MaximumOutputTokens: 100000, Timeout: 5 * time.Second, MaximumAttempts: 1, RetryBudget: 0, ContextTokens: 4000},
	}
	for _, option := range options {
		option(&cfg)
	}
	built, err := runner.New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	return &runnerHarness{runner: built, registry: registry, invoker: invoker, recorder: recorder}
}

func plan(tool string, arguments string) []byte {
	return []byte(`{"kind":"TypedPlan","steps":[{"tool":"` + tool + `","arguments":` + arguments + `}]}`)
}

func ampleBudget() runner.BudgetView {
	return runner.BudgetView{RemainingModelCalls: 100, RemainingInputTokens: 1_000_000, RemainingOutputTokens: 1_000_000, RemainingCostMicros: 1_000_000, ExceedBehavior: "refuse"}
}

func testRunView() runner.RunView {
	return runner.RunView{RunID: "run.test", WorkspaceID: "workspace", ProjectID: "project", ActorID: "actor", Domain: "platform-agent", Operation: "page-change", TargetType: "page", TargetID: "page.home"}
}

func TestTurnResolvesEveryDecisionKindDeterministically(t *testing.T) {
	cases := []struct {
		name     string
		output   []byte
		want     agent.DecisionKind
		wantTool string
	}{
		{"continue", plan("agent.continue", `{"note":"thinking"}`), agent.DecisionContinue, ""},
		{"need-input", plan("agent.need-input", `{"question":"which page?"}`), agent.DecisionNeedInput, ""},
		{"delegate", plan("agent.delegate", `{"delegate":"`+agent.SpecialistDefinitionID+`","input":{"task":"draft"}}`), agent.DecisionDelegate, ""},
		{"final", plan("agent.final", `{"candidate":{"kind":"ComponentPackageSpec"},"summary":"done"}`), agent.DecisionFinal, ""},
		{"refuse", plan("agent.refuse", `{"reason":"unsafe"}`), agent.DecisionRefuse, ""},
		{"tool-call", plan("anvilkit.tool.context-echo", `{"query":"context"}`), agent.DecisionToolCall, "anvilkit.tool.context-echo"},
		{"unknown-reserved", plan("agent.unknown", `{}`), agent.DecisionRefuse, ""},
		{"tool-outside-profile", plan("anvilkit.tool.other", `{}`), agent.DecisionRefuse, ""},
		{"delegate-not-allowed", plan("agent.delegate", `{"delegate":"definition.platform.other","input":{}}`), agent.DecisionRefuse, ""},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			harness := newRunnerHarness(t, [][]byte{testCase.output})
			outcome, err := harness.runner.Turn(context.Background(), runner.TurnRequest{
				Definition: managerDefinition(t, harness.registry),
				Run:        testRunView(),
				Phase:      runner.PhasePlan,
				Budget:     ampleBudget(),
			})
			if err != nil {
				t.Fatal(err)
			}
			if outcome.Halted != nil {
				t.Fatalf("unexpected halt: %+v", outcome.Halted)
			}
			if outcome.Decision.Kind != testCase.want {
				t.Fatalf("decision = %s, want %s", outcome.Decision.Kind, testCase.want)
			}
			if err := outcome.Decision.Validate(); err != nil {
				t.Fatalf("resolved decision must validate: %v", err)
			}
			if testCase.wantTool != "" && outcome.Decision.ToolCall.ToolID != testCase.wantTool {
				t.Fatalf("tool = %s", outcome.Decision.ToolCall.ToolID)
			}
			if outcome.Usage.ModelCalls != 1 {
				t.Fatalf("usage calls = %d, want 1", outcome.Usage.ModelCalls)
			}
		})
	}
}

func TestTurnBudgetPrecheckHaltsDeterministically(t *testing.T) {
	harness := newRunnerHarness(t, nil)
	budget := ampleBudget()
	budget.RemainingModelCalls = 0
	outcome, err := harness.runner.Turn(context.Background(), runner.TurnRequest{Definition: managerDefinition(t, harness.registry), Run: testRunView(), Phase: runner.PhasePlan, Budget: budget})
	if err != nil {
		t.Fatal(err)
	}
	if outcome.Halted == nil || !outcome.Halted.Refuse || outcome.Halted.Problem.Code != string(problem.CodeBudgetDenied) {
		t.Fatalf("halt = %+v", outcome.Halted)
	}
	if harness.invoker.calls != 0 {
		t.Fatal("exhausted budget must not reach the model")
	}
	budget.ExceedBehavior = "cancel"
	outcome, err = harness.runner.Turn(context.Background(), runner.TurnRequest{Definition: managerDefinition(t, harness.registry), Run: testRunView(), Phase: runner.PhasePlan, Budget: budget})
	if err != nil {
		t.Fatal(err)
	}
	if outcome.Halted == nil || outcome.Halted.Refuse {
		t.Fatalf("cancel behavior halt = %+v", outcome.Halted)
	}
}

func TestTurnBoundedRepairThenRefusal(t *testing.T) {
	broken := []byte(`{"kind":"TypedPlan","steps":[`)
	harness := newRunnerHarness(t, [][]byte{broken, broken, broken})
	outcome, err := harness.runner.Turn(context.Background(), runner.TurnRequest{Definition: managerDefinition(t, harness.registry), Run: testRunView(), Phase: runner.PhasePlan, Budget: ampleBudget()})
	if err != nil {
		t.Fatal(err)
	}
	if outcome.Decision.Kind != agent.DecisionRefuse {
		t.Fatalf("decision = %s, want refuse", outcome.Decision.Kind)
	}
	// bounded-repair with two pinned attempts: one raw try plus two repairs.
	if harness.invoker.calls != 3 {
		t.Fatalf("model calls = %d, want 3", harness.invoker.calls)
	}
	if outcome.Usage.ModelCalls != 3 {
		t.Fatalf("usage must count every physical attempt, got %d", outcome.Usage.ModelCalls)
	}
}

func TestSpecialistCannotRequestInput(t *testing.T) {
	harness := newRunnerHarness(t, [][]byte{plan("agent.need-input", `{"question":"?"}`)})
	outcome, err := harness.runner.Turn(context.Background(), runner.TurnRequest{Definition: specialistDefinition(t, harness.registry), Run: testRunView(), Phase: runner.PhaseDelegate, Budget: ampleBudget()})
	if err != nil {
		t.Fatal(err)
	}
	if outcome.Decision.Kind != agent.DecisionRefuse {
		t.Fatalf("specialist input request must refuse, got %s", outcome.Decision.Kind)
	}
}

func TestDelegateEnforcesEveryConstraint(t *testing.T) {
	candidate := `{"kind":"ComponentPackageSpec","packageIntent":{"name":"x","version":"1.0.0","componentType":"section"}}`
	delegateDecision := agent.DelegateDecision{DelegateID: agent.SpecialistDefinitionID, Input: json.RawMessage(`{"task":"draft"}`)}

	t.Run("happy-path", func(t *testing.T) {
		harness := newRunnerHarness(t, [][]byte{plan("agent.final", `{"candidate":`+candidate+`}`)})
		outcome, err := harness.runner.Delegate(context.Background(), runner.DelegateRequest{Parent: managerDefinition(t, harness.registry), Decision: delegateDecision, Run: testRunView(), Depth: 0, DelegationsUsed: 0, Budget: ampleBudget()})
		if err != nil {
			t.Fatal(err)
		}
		if outcome.Refused != nil || len(outcome.Candidate) == 0 {
			t.Fatalf("delegation outcome = %+v", outcome)
		}
	})
	t.Run("depth-exceeded", func(t *testing.T) {
		harness := newRunnerHarness(t, nil)
		outcome, err := harness.runner.Delegate(context.Background(), runner.DelegateRequest{Parent: managerDefinition(t, harness.registry), Decision: delegateDecision, Run: testRunView(), Depth: 1, Budget: ampleBudget()})
		if err != nil || outcome.Refused == nil {
			t.Fatalf("depth violation must refuse: %+v %v", outcome, err)
		}
		if harness.invoker.calls != 0 {
			t.Fatal("denied delegation must not reach the model")
		}
	})
	t.Run("fan-out-exceeded", func(t *testing.T) {
		harness := newRunnerHarness(t, nil)
		outcome, err := harness.runner.Delegate(context.Background(), runner.DelegateRequest{Parent: managerDefinition(t, harness.registry), Decision: delegateDecision, Run: testRunView(), DelegationsUsed: 2, Budget: ampleBudget()})
		if err != nil || outcome.Refused == nil {
			t.Fatalf("fan-out violation must refuse: %+v %v", outcome, err)
		}
	})
	t.Run("delegate-not-allowed", func(t *testing.T) {
		harness := newRunnerHarness(t, nil)
		outcome, err := harness.runner.Delegate(context.Background(), runner.DelegateRequest{Parent: managerDefinition(t, harness.registry), Decision: agent.DelegateDecision{DelegateID: "definition.platform.other", Input: json.RawMessage(`{}`)}, Run: testRunView(), Budget: ampleBudget()})
		if err != nil || outcome.Refused == nil {
			t.Fatalf("unknown delegate must refuse: %+v %v", outcome, err)
		}
	})
	t.Run("input-schema-violation", func(t *testing.T) {
		harness := newRunnerHarness(t, nil, func(cfg *runner.Config) {
			cfg.Validator = acceptAllValidator{denyComponent: "anvilkit.contract.schema.component-package-spec"}
		})
		outcome, err := harness.runner.Delegate(context.Background(), runner.DelegateRequest{Parent: managerDefinition(t, harness.registry), Decision: delegateDecision, Run: testRunView(), Budget: ampleBudget()})
		if err != nil || outcome.Refused == nil {
			t.Fatalf("input schema violation must refuse: %+v %v", outcome, err)
		}
	})
	t.Run("specialist-refusal", func(t *testing.T) {
		harness := newRunnerHarness(t, [][]byte{plan("agent.refuse", `{"reason":"cannot draft"}`)})
		outcome, err := harness.runner.Delegate(context.Background(), runner.DelegateRequest{Parent: managerDefinition(t, harness.registry), Decision: delegateDecision, Run: testRunView(), Budget: ampleBudget()})
		if err != nil || outcome.Refused == nil {
			t.Fatalf("specialist refusal must propagate: %+v %v", outcome, err)
		}
	})
	t.Run("specialist-tool-call-outside-delegation-contract", func(t *testing.T) {
		harness := newRunnerHarness(t, [][]byte{plan("anvilkit.tool.context-echo", `{}`)})
		outcome, err := harness.runner.Delegate(context.Background(), runner.DelegateRequest{Parent: managerDefinition(t, harness.registry), Decision: delegateDecision, Run: testRunView(), Budget: ampleBudget()})
		if err != nil || outcome.Refused == nil {
			t.Fatalf("specialist tool call must refuse: %+v %v", outcome, err)
		}
	})
	t.Run("specialist-turn-limit", func(t *testing.T) {
		outputs := make([][]byte, 0, 8)
		for range 8 {
			outputs = append(outputs, plan("agent.continue", `{"note":"still drafting"}`))
		}
		harness := newRunnerHarness(t, outputs)
		outcome, err := harness.runner.Delegate(context.Background(), runner.DelegateRequest{Parent: managerDefinition(t, harness.registry), Decision: delegateDecision, Run: testRunView(), Budget: ampleBudget()})
		if err != nil || outcome.Refused == nil {
			t.Fatalf("specialist exhaustion must refuse: %+v %v", outcome, err)
		}
		if outcome.Refused.Code != string(problem.CodeLimitExceeded) {
			t.Fatalf("exhaustion code = %s", outcome.Refused.Code)
		}
	})
}

func TestGuardActionAllowsAndDeniesDurably(t *testing.T) {
	harness := newRunnerHarness(t, nil)
	manager := managerDefinition(t, harness.registry)

	decision, err := harness.runner.GuardAction(context.Background(), manager, testRunView(), agent.ToolCallDecision{ToolID: "anvilkit.tool.context-echo", Arguments: json.RawMessage(`{"query":"x"}`)})
	if err != nil || !decision.Allowed {
		t.Fatalf("allowed tool denied: %+v %v", decision, err)
	}

	_, err = harness.runner.GuardAction(context.Background(), manager, testRunView(), agent.ToolCallDecision{ToolID: "anvilkit.tool.contract-validate", Arguments: json.RawMessage(`{}`)})
	var details problem.Details
	if err == nil || !asProblem(err, &details) || details.Code != string(problem.CodeToolDispatchDenied) {
		t.Fatalf("tool outside pinned intent must deny: %v", err)
	}
	if len(harness.recorder.recorded) != 2 {
		t.Fatalf("guard decisions recorded = %d, want 2", len(harness.recorder.recorded))
	}
	if harness.recorder.recorded[1].Allowed {
		t.Fatal("denial must be recorded as denied")
	}

	inactive := newRunnerHarness(t, nil, func(cfg *runner.Config) {
		cfg.Authority = staticAuthorityView{inactive: true, allowed: []string{"anvilkit.tool.context-echo"}}
	})
	if _, err := inactive.runner.GuardAction(context.Background(), manager, testRunView(), agent.ToolCallDecision{ToolID: "anvilkit.tool.context-echo", Arguments: json.RawMessage(`{}`)}); err == nil {
		t.Fatal("inactive current authority must deny")
	}
}

func asProblem(err error, target *problem.Details) bool {
	details, ok := err.(problem.Details)
	if ok {
		*target = details
		return true
	}
	return false
}
