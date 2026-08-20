package runner_test

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"slices"
	"sync"
	"testing"
	"time"

	contractvalidator "github.com/ancyloce/anvilkit-agent-service/contracts/validator"
	"github.com/ancyloce/anvilkit-agent-service/internal/agent"
	"github.com/ancyloce/anvilkit-agent-service/internal/agent/runner"
	"github.com/ancyloce/anvilkit-agent-service/internal/authority"
	"github.com/ancyloce/anvilkit-agent-service/internal/contextcompiler"
	"github.com/ancyloce/anvilkit-agent-service/internal/contracts"
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
	identity, err := contracts.PinnedIdentity("../../..")
	if err != nil {
		t.Fatal(err)
	}
	registry, err := agent.NewRegistry(context.Background(), agent.RegistryConfig{
		Source:              agent.EmbeddedCatalog{},
		Validator:           adapter,
		DefinitionSchemaURI: agent.DefinitionSchemaURI(schemaBytes),
		Approval:            agent.Approval{ProfileDigest: identity.ProfileDigest, LockDigest: identity.LockDigest, SchemaDigests: identity.SchemaDigests},
	})
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
	keys    []string
	limits  []modelgateway.AttemptLimits
}

func (s *scriptedInvoker) Invoke(_ context.Context, request modelgateway.InvokeRequest) (modelgateway.AdapterResponse, modelgateway.InvocationRecord, error) {
	s.lock.Lock()
	defer s.lock.Unlock()
	if len(request.Context) == 0 {
		return modelgateway.AdapterResponse{}, modelgateway.InvocationRecord{}, fmt.Errorf("scripted invoker requires compiled context")
	}
	if request.Budget == nil {
		return modelgateway.AdapterResponse{}, modelgateway.InvocationRecord{}, fmt.Errorf("scripted invoker requires an attempt budget")
	}
	// Mirror the gateway: authorize the physical attempt before performing it,
	// so a denied attempt never reaches the script and never bills.
	limits, err := request.Budget.Authorize(1, modelgateway.Usage{})
	if err != nil {
		return modelgateway.AdapterResponse{}, modelgateway.InvocationRecord{}, err
	}
	if s.calls >= len(s.outputs) {
		return modelgateway.AdapterResponse{}, modelgateway.InvocationRecord{}, fmt.Errorf("scripted invoker exhausted after %d calls", s.calls)
	}
	output := s.outputs[s.calls]
	s.calls++
	s.keys = append(s.keys, request.IdempotencyKey)
	s.limits = append(s.limits, limits)
	return modelgateway.AdapterResponse{Output: append([]byte(nil), output...)},
		modelgateway.InvocationRecord{PhysicalAttempts: []modelgateway.AttemptID{"attempt.scripted"}, InputTokens: 100, OutputTokens: 50, CostMicros: 1000}, nil
}

type staticSelector struct{}

func (staticSelector) Select(context.Context, string, agent.PolicyReference) (modelgateway.Selection, error) {
	return modelgateway.Selection{MaximumCostMicros: 1_000_000}, nil
}

// activeAuthority is the current-authority observation a caller re-read
// immediately before the boundary under test.
func activeAuthority() authority.Current {
	return authority.Current{
		Definition:       []byte(`{"definitionId":"definition.platform.manager"}`),
		ContractBOM:      []byte(`{"bom":"test"}`),
		Policy:           []byte(`{"policyId":"policy.test"}`),
		Budget:           []byte(`{"budget":"test"}`),
		WorkspaceActive:  true,
		ActorActive:      true,
		PermissionActive: true,
		PolicyActive:     true,
		Grants: authority.Grants{
			AllowedTools:        []string{"anvilkit.tool.context-echo"},
			AllowedCapabilities: []string{"fake.execute", "contract.validate", "artifact.scan"},
			AllowedEffects:      []string{"read"},
			MaximumRisk:         "low",
			DataClasses:         []string{"public", "internal"},
		},
	}
}

// revokedAuthority models authority revoked after the run started.
func revokedAuthority() authority.Current {
	value := activeAuthority()
	value.WorkspaceActive, value.ActorActive, value.PermissionActive, value.PolicyActive = false, false, false, false
	return value
}

// unavailableAuthority models the authority source failing to answer: the
// caller has no observation at all, which must never read as permissive.
func unavailableAuthority() authority.Current { return authority.Current{} }

// admittingArgumentValidator is the test double for the tool guard argument
// port. The pinned-schema argument validator that production wires is
// exercised in the execution suite.
type admittingArgumentValidator struct{}

func (admittingArgumentValidator) Validate(context.Context, tools.SchemaReference, json.RawMessage) error {
	return nil
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
	guard, err := tools.NewGuard(testToolProfile(t), recorder, fixedClock{time.Unix(1000, 0)}, admittingArgumentValidator{})
	if err != nil {
		t.Fatal(err)
	}
	cfg := runner.Config{
		Registry:  registry,
		Compiler:  contextcompiler.New(nil),
		Selector:  staticSelector{},
		Invoker:   invoker,
		Guard:     guard,
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
	return runner.BudgetView{RemainingModelCalls: 100, RemainingInputTokens: 1_000_000, RemainingOutputTokens: 1_000_000, RemainingTotalTokens: 2_000_000, RemainingCostMicros: 1_000_000, ExceedBehavior: "refuse"}
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
				Definition:   managerDefinition(t, harness.registry),
				Run:          testRunView(),
				Phase:        runner.PhasePlan,
				OperationKey: "run.test:g1:turn-0000",
				Authority:    activeAuthority(),
				Budget:       ampleBudget(),
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
	outcome, err := harness.runner.Turn(context.Background(), runner.TurnRequest{Definition: managerDefinition(t, harness.registry), Run: testRunView(), Phase: runner.PhasePlan, OperationKey: "run.test:g1:turn-0000", Authority: activeAuthority(), Budget: budget})
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
	outcome, err = harness.runner.Turn(context.Background(), runner.TurnRequest{Definition: managerDefinition(t, harness.registry), Run: testRunView(), Phase: runner.PhasePlan, OperationKey: "run.test:g1:turn-0000", Authority: activeAuthority(), Budget: budget})
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
	outcome, err := harness.runner.Turn(context.Background(), runner.TurnRequest{Definition: managerDefinition(t, harness.registry), Run: testRunView(), Phase: runner.PhasePlan, OperationKey: "run.test:g1:turn-0000", Authority: activeAuthority(), Budget: ampleBudget()})
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
	outcome, err := harness.runner.Turn(context.Background(), runner.TurnRequest{Definition: specialistDefinition(t, harness.registry), Run: testRunView(), Phase: runner.PhaseDelegate, OperationKey: "run.test:g1:delegate-turn-0000-0000", Authority: activeAuthority(), Budget: ampleBudget()})
	if err != nil {
		t.Fatal(err)
	}
	if outcome.Decision.Kind != agent.DecisionRefuse {
		t.Fatalf("specialist input request must refuse, got %s", outcome.Decision.Kind)
	}
}

func TestDelegationAuthorizationEnforcesEveryConstraint(t *testing.T) {
	delegateDecision := agent.DelegateDecision{DelegateID: agent.SpecialistDefinitionID, Input: json.RawMessage(`{"task":"draft"}`)}

	t.Run("authorized", func(t *testing.T) {
		harness := newRunnerHarness(t, nil)
		grant, denied := harness.runner.AuthorizeDelegation(context.Background(), runner.DelegationRequest{Parent: managerDefinition(t, harness.registry), Decision: delegateDecision, Run: testRunView(), Authority: activeAuthority()})
		if denied != nil {
			t.Fatalf("delegation denied: %+v", denied)
		}
		if grant.Specialist.DefinitionID != agent.SpecialistDefinitionID || grant.TurnLimit < 1 {
			t.Fatalf("grant = %+v", grant)
		}
		if harness.invoker.calls != 0 {
			t.Fatal("authorization must not reach the model")
		}
	})
	for _, testCase := range []struct {
		name    string
		request runner.DelegationRequest
	}{
		{"depth-exceeded", runner.DelegationRequest{Decision: delegateDecision, Depth: 1}},
		{"fan-out-exceeded", runner.DelegationRequest{Decision: delegateDecision, DelegationsUsed: 2}},
		{"delegate-not-allowed", runner.DelegationRequest{Decision: agent.DelegateDecision{DelegateID: "definition.platform.other", Input: json.RawMessage(`{}`)}}},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			harness := newRunnerHarness(t, nil)
			request := testCase.request
			request.Parent, request.Run, request.Authority = managerDefinition(t, harness.registry), testRunView(), activeAuthority()
			_, denied := harness.runner.AuthorizeDelegation(context.Background(), request)
			if denied == nil {
				t.Fatal("constraint violation must deny the delegation")
			}
			if harness.invoker.calls != 0 {
				t.Fatal("denied delegation must not reach the model")
			}
		})
	}
	t.Run("input-schema-violation", func(t *testing.T) {
		harness := newRunnerHarness(t, nil, func(cfg *runner.Config) {
			cfg.Validator = acceptAllValidator{denyComponent: "anvilkit.contract.schema.component-package-spec"}
		})
		_, denied := harness.runner.AuthorizeDelegation(context.Background(), runner.DelegationRequest{Parent: managerDefinition(t, harness.registry), Decision: delegateDecision, Run: testRunView(), Authority: activeAuthority()})
		if denied == nil {
			t.Fatal("input schema violation must deny the delegation")
		}
	})
	// Authority revoked between run creation and delegation must fail closed
	// before any Specialist turn runs.
	t.Run("revoked-authority", func(t *testing.T) {
		harness := newRunnerHarness(t, nil)
		_, denied := harness.runner.AuthorizeDelegation(context.Background(), runner.DelegationRequest{Parent: managerDefinition(t, harness.registry), Decision: delegateDecision, Run: testRunView(), Authority: revokedAuthority()})
		if denied == nil || denied.Code != string(problem.CodeAuthorityStale) {
			t.Fatalf("revoked authority must deny with AUTHORITY_STALE: %+v", denied)
		}
		if harness.invoker.calls != 0 {
			t.Fatal("revoked authority must not reach the model")
		}
	})
	t.Run("authority-unavailable", func(t *testing.T) {
		harness := newRunnerHarness(t, nil)
		_, denied := harness.runner.AuthorizeDelegation(context.Background(), runner.DelegationRequest{Parent: managerDefinition(t, harness.registry), Decision: delegateDecision, Run: testRunView(), Authority: unavailableAuthority()})
		if denied == nil || denied.Code != string(problem.CodeAuthorityStale) {
			t.Fatalf("unavailable authority must fail closed: %+v", denied)
		}
	})
}

func TestDelegateTurnResolvesOneSpecialistTurnAtATime(t *testing.T) {
	candidate := `{"kind":"ComponentPackageSpec","packageIntent":{"name":"x","version":"1.0.0","componentType":"section"}}`
	specialistTurn := func(harness *runnerHarness, last bool) runner.DelegateTurnRequest {
		return runner.DelegateTurnRequest{
			Specialist:   specialistDefinition(t, harness.registry),
			Run:          testRunView(),
			Depth:        1,
			Last:         last,
			Input:        json.RawMessage(`{"task":"draft"}`),
			Budget:       ampleBudget(),
			OperationKey: "run.test:g1:delegate-turn-0000-0000",
			Authority:    activeAuthority(),
		}
	}

	t.Run("candidate-accepted", func(t *testing.T) {
		harness := newRunnerHarness(t, [][]byte{plan("agent.final", `{"candidate":`+candidate+`}`)})
		outcome, err := harness.runner.DelegateTurn(context.Background(), specialistTurn(harness, false))
		if err != nil {
			t.Fatal(err)
		}
		if !outcome.Done || outcome.Refused != nil || len(outcome.Candidate) == 0 {
			t.Fatalf("delegate turn outcome = %+v", outcome)
		}
	})
	t.Run("continue-is-not-done", func(t *testing.T) {
		harness := newRunnerHarness(t, [][]byte{plan("agent.continue", `{"note":"still drafting"}`)})
		outcome, err := harness.runner.DelegateTurn(context.Background(), specialistTurn(harness, false))
		if err != nil {
			t.Fatal(err)
		}
		if outcome.Done || outcome.Refused != nil {
			t.Fatalf("a continuing specialist turn must leave the delegation open: %+v", outcome)
		}
	})
	t.Run("turn-limit-refuses-on-the-last-turn", func(t *testing.T) {
		harness := newRunnerHarness(t, [][]byte{plan("agent.continue", `{"note":"still drafting"}`)})
		outcome, err := harness.runner.DelegateTurn(context.Background(), specialistTurn(harness, true))
		if err != nil {
			t.Fatal(err)
		}
		if !outcome.Done || outcome.Refused == nil || outcome.Refused.Code != string(problem.CodeLimitExceeded) {
			t.Fatalf("exhausted delegation must refuse with LIMIT_EXCEEDED: %+v", outcome)
		}
	})
	t.Run("specialist-refusal", func(t *testing.T) {
		harness := newRunnerHarness(t, [][]byte{plan("agent.refuse", `{"reason":"cannot draft"}`)})
		outcome, err := harness.runner.DelegateTurn(context.Background(), specialistTurn(harness, false))
		if err != nil || !outcome.Done || outcome.Refused == nil {
			t.Fatalf("specialist refusal must conclude the delegation: %+v %v", outcome, err)
		}
	})
	t.Run("decision-outside-the-delegation-contract", func(t *testing.T) {
		harness := newRunnerHarness(t, [][]byte{plan("anvilkit.tool.context-echo", `{"query":"context"}`)})
		outcome, err := harness.runner.DelegateTurn(context.Background(), specialistTurn(harness, false))
		if err != nil || !outcome.Done || outcome.Refused == nil {
			t.Fatalf("specialist tool call must refuse: %+v %v", outcome, err)
		}
	})
	t.Run("candidate-violating-the-pinned-output-schema", func(t *testing.T) {
		harness := newRunnerHarness(t, [][]byte{plan("agent.final", `{"candidate":`+candidate+`}`)}, func(cfg *runner.Config) {
			cfg.Validator = acceptAllValidator{denyComponent: "anvilkit.contract.schema.component-package-spec"}
		})
		outcome, err := harness.runner.DelegateTurn(context.Background(), specialistTurn(harness, false))
		if err != nil || !outcome.Done || outcome.Refused == nil || outcome.Refused.Code != string(problem.CodeContractInvalid) {
			t.Fatalf("invalid candidate must refuse: %+v %v", outcome, err)
		}
	})
	// Authority revoked mid-delegation stops the next Specialist turn before
	// it reaches the model.
	t.Run("revoked-authority-mid-delegation", func(t *testing.T) {
		harness := newRunnerHarness(t, [][]byte{plan("agent.final", `{"candidate":`+candidate+`}`)})
		request := specialistTurn(harness, false)
		request.Authority = revokedAuthority()
		outcome, err := harness.runner.DelegateTurn(context.Background(), request)
		if err != nil || !outcome.Done || outcome.Refused == nil || outcome.Refused.Code != string(problem.CodeAuthorityStale) {
			t.Fatalf("revoked authority must stop the specialist turn: %+v %v", outcome, err)
		}
		if harness.invoker.calls != 0 {
			t.Fatal("revoked authority must not reach the model")
		}
	})
}

func TestGuardActionAllowsAndDeniesDurably(t *testing.T) {
	harness := newRunnerHarness(t, nil)
	manager := managerDefinition(t, harness.registry)

	decision, err := harness.runner.GuardAction(context.Background(), manager, testRunView(), activeAuthority(), agent.ToolCallDecision{ToolID: "anvilkit.tool.context-echo", Arguments: json.RawMessage(`{"query":"x"}`)})
	if err != nil || !decision.Allowed {
		t.Fatalf("allowed tool denied: %+v %v", decision, err)
	}

	_, err = harness.runner.GuardAction(context.Background(), manager, testRunView(), activeAuthority(), agent.ToolCallDecision{ToolID: "anvilkit.tool.contract-validate", Arguments: json.RawMessage(`{}`)})
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

	inactive := newRunnerHarness(t, nil)
	if _, err := inactive.runner.GuardAction(context.Background(), manager, testRunView(), revokedAuthority(), agent.ToolCallDecision{ToolID: "anvilkit.tool.context-echo", Arguments: json.RawMessage(`{}`)}); err == nil {
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

// Bounded repair must obey the same pinned budget as the first attempt.
// Enforcing the budget only before the first model call let a repairing turn
// spend past it.
func TestBoundedRepairStopsAtTheBudget(t *testing.T) {
	broken := []byte(`{"kind":"TypedPlan","steps":[`)
	harness := newRunnerHarness(t, [][]byte{broken, broken, broken})
	budget := ampleBudget()
	budget.RemainingModelCalls = 2
	outcome, err := harness.runner.Turn(context.Background(), runner.TurnRequest{
		Definition:   managerDefinition(t, harness.registry),
		Run:          testRunView(),
		Phase:        runner.PhasePlan,
		OperationKey: "run.test:g1:turn-0000",
		Budget:       budget, Authority: activeAuthority()})
	if err != nil {
		t.Fatal(err)
	}
	if outcome.Halted == nil || outcome.Halted.Problem.Code != string(problem.CodeBudgetDenied) {
		t.Fatalf("exhausted repair must halt on the budget: %+v", outcome)
	}
	if !outcome.Halted.Refuse {
		t.Fatal("a refuse exceed-behavior budget must halt as a refusal")
	}
	if harness.invoker.calls != 2 {
		t.Fatalf("model calls = %d, want exactly the two the budget funds", harness.invoker.calls)
	}
	if outcome.Usage.ModelCalls != 2 {
		t.Fatalf("usage must account every attempt made, got %d", outcome.Usage.ModelCalls)
	}
}

// Each attempt of a turn shrinks the per-attempt provider limits by what the
// previous attempts already consumed.
func TestRepairAttemptLimitsShrinkWithConsumedBudget(t *testing.T) {
	broken := []byte(`{"kind":"TypedPlan","steps":[`)
	harness := newRunnerHarness(t, [][]byte{broken, broken, broken})
	budget := ampleBudget()
	budget.RemainingCostMicros = 5000
	if _, err := harness.runner.Turn(context.Background(), runner.TurnRequest{
		Definition:   managerDefinition(t, harness.registry),
		Run:          testRunView(),
		Phase:        runner.PhasePlan,
		OperationKey: "run.test:g1:turn-0000",
		Budget:       budget, Authority: activeAuthority()}); err != nil {
		t.Fatal(err)
	}
	if harness.invoker.calls != 3 {
		t.Fatalf("model calls = %d, want the three pinned attempts", harness.invoker.calls)
	}
	// The scripted invoker meters 1000 cost micros per attempt.
	for index, want := range []int64{5000, 4000, 3000} {
		if got := harness.invoker.limits[index].MaximumCostMicros; got != want {
			t.Fatalf("attempt %d cost cap = %d, want %d", index, got, want)
		}
	}
}

// Every provider attempt of one turn carries a deterministic identity derived
// from the turn's durable operation key.
func TestTurnAttemptsCarryDeterministicOperationDerivedKeys(t *testing.T) {
	broken := []byte(`{"kind":"TypedPlan","steps":[`)
	harness := newRunnerHarness(t, [][]byte{broken, broken, broken})
	if _, err := harness.runner.Turn(context.Background(), runner.TurnRequest{
		Definition:   managerDefinition(t, harness.registry),
		Run:          testRunView(),
		Phase:        runner.PhasePlan,
		OperationKey: "run.test:g1:turn-0007",
		Budget:       ampleBudget(), Authority: activeAuthority()}); err != nil {
		t.Fatal(err)
	}
	want := []string{
		"run.test:g1:turn-0007:plan-attempt-00",
		"run.test:g1:turn-0007:plan-attempt-01",
		"run.test:g1:turn-0007:plan-attempt-02",
	}
	if !slices.Equal(harness.invoker.keys, want) {
		t.Fatalf("attempt keys = %v, want %v", harness.invoker.keys, want)
	}
}

// A turn without a durable operation key cannot produce stable provider
// identities and must fail closed rather than invent one.
func TestTurnWithoutADurableOperationKeyFailsClosed(t *testing.T) {
	harness := newRunnerHarness(t, [][]byte{plan("agent.continue", `{"note":"x"}`)})
	if _, err := harness.runner.Turn(context.Background(), runner.TurnRequest{
		Definition: managerDefinition(t, harness.registry),
		Run:        testRunView(),
		Phase:      runner.PhasePlan,
		Budget:     ampleBudget(), Authority: activeAuthority()}); err == nil {
		t.Fatal("a turn without an operation key was accepted")
	}
	if harness.invoker.calls != 0 {
		t.Fatal("a turn without an operation key must not reach the model")
	}
}
