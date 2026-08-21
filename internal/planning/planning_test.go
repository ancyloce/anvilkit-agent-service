package planning

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/ancyloce/anvilkit-agent-service/internal/modelgateway"
	"github.com/ancyloce/anvilkit-agent-service/internal/problem"
	toolpolicy "github.com/ancyloce/anvilkit-agent-service/internal/tools"

	contractvalidator "github.com/ancyloce/anvilkit-agent-service/contracts/validator"
	"os"
	"testing"
	"time"
)

type recorder struct{}

func (recorder) BeforeDisclosure(context.Context, modelgateway.InvocationRecord) error { return nil }
func (recorder) BeforeAttempt(context.Context, modelgateway.InvocationRecord) error    { return nil }
func (recorder) Complete(context.Context, modelgateway.InvocationRecord) error         { return nil }

type clock struct{}

func (clock) Now() time.Time { return time.Unix(1, 0) }

type sleeper struct{}

func (sleeper) Sleep(context.Context, time.Duration) error { return nil }

type admittingValidator struct{}

func (admittingValidator) Validate(_ context.Context, _ toolpolicy.SchemaReference, value json.RawMessage) error {
	_, err := contractvalidator.Admit(value)
	return err
}

type toolRecording struct{}

func (toolRecording) Record(context.Context, toolpolicy.Intent, toolpolicy.Proposal, toolpolicy.Decision) error {
	return nil
}

type testCase struct {
	ID, Scenario                 string
	Weight                       int
	Eligible, Invalid, Forbidden bool
	ExpectedOutcome              Outcome
	ExpectedTool                 string
	ExpectedDispatchAllowed      bool
}
type dataset struct {
	DatasetVersion   int
	DatasetID, Owner string
	Cases            []testCase
}

func engine(t *testing.T) *Engine {
	t.Helper()
	gateway, err := modelgateway.NewGateway(map[modelgateway.ProviderID]modelgateway.Adapter{modelgateway.FakeProviderID: modelgateway.FakeAdapter{}}, recorder{}, clock{}, sleeper{})
	if err != nil {
		t.Fatal(err)
	}
	value, err := New(gateway, 32, 1)
	if err != nil {
		t.Fatal(err)
	}
	return value
}

// requestBudget authorizes every attempt at the request's own pinned limits.
// The budget port is mandatory, so no attempt — raw or repair — is exempt.
type requestBudget struct{ request modelgateway.InvokeRequest }

func (b requestBudget) Authorize(int, Usage) (AttemptLimits, error) {
	return AttemptLimits{MaximumInputTokens: b.request.MaximumInputTokens, MaximumOutputTokens: b.request.MaximumOutputTokens, MaximumTotalTokens: b.request.MaximumTotalTokens, MaximumCostMicros: b.request.MaximumCostMicros}, nil
}

func request(scenario string) modelgateway.InvokeRequest {
	registry, _ := modelgateway.NewRegistry(modelgateway.Snapshot{Version: "fake-v1", Providers: []modelgateway.Provider{{ID: modelgateway.FakeProviderID, ModelVersion: "fake-v1", Regions: []string{"test"}, DataClasses: []modelgateway.DataClass{modelgateway.Internal}, Capabilities: []string{"plan"}, SafetyLevel: 3, MaximumCostMicros: 600, Priority: 1, Enabled: true}}})
	selection, _ := registry.Select("workspace", modelgateway.Policy{Version: "policy-v1", AllowedProviders: []modelgateway.ProviderID{modelgateway.FakeProviderID}, AllowedRegions: []string{"test"}, DataClasses: []modelgateway.DataClass{modelgateway.Internal}, Capability: "plan", MinimumSafety: 2, MaximumCostMicros: 1000})
	return modelgateway.InvokeRequest{RunID: "run-" + scenario, WorkspaceID: "workspace", ProjectID: "project", IdempotencyKey: "run-" + scenario + ":g1:turn-0000", Selection: selection, Context: []byte("minimal synthetic context"), DataClasses: []modelgateway.DataClass{modelgateway.Internal}, MaximumOutputBytes: 4096, MaximumInputTokens: 256, MaximumOutputTokens: 2000, MaximumTotalTokens: 2256, MaximumCostMicros: 1000, Timeout: time.Second, MaximumAttempts: 1, RetryBudget: 0, Scenario: scenario}
}
func corpusGuard(t *testing.T) (*toolpolicy.Guard, toolpolicy.Intent, toolpolicy.CurrentAuthority) {
	t.Helper()
	policy := toolpolicy.PolicyReference{PolicyID: "policy", Version: "policy-v1", Digest: "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"}
	schema := toolpolicy.SchemaReference{ComponentName: "anvilkit.contract.schema.synthetic", Digest: "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}
	definition := func(id, capability string) toolpolicy.Definition {
		return toolpolicy.Definition{Kind: "ToolDefinition", Capability: capability, InputSchema: schema, OutputSchema: schema, SideEffectClass: "none", RiskClass: "low", ApprovalPolicy: policy, TimeoutPolicy: toolpolicy.TimeoutPolicy{TimeoutMilliseconds: 1000}, RetryPolicy: toolpolicy.RetryPolicy{MaximumAttempts: 1, Retryability: []string{}}, AcceptedDataClasses: []string{"internal"}, ToolID: id}
	}
	profile, err := toolpolicy.NewProfile("manager", "v1", policy, []toolpolicy.Definition{definition("fake.execute", "fake.execute"), definition("contract.validate", "contract.validate"), definition("artifact.scan", "artifact.scan")})
	if err != nil {
		t.Fatal(err)
	}
	guard, err := toolpolicy.NewGuard(profile, toolRecording{}, clock{}, admittingValidator{})
	if err != nil {
		t.Fatal(err)
	}
	intent := toolpolicy.Intent{RunID: "run", WorkspaceID: "workspace", ProjectID: "project", ActorID: "actor", AllowedTools: []string{"fake.execute", "contract.validate", "artifact.scan"}, AllowedEffects: []string{"none"}, MaximumRisk: "low", DataClasses: []string{"internal"}}
	current := toolpolicy.CurrentAuthority{WorkspaceActive: true, ActorActive: true, PermissionActive: true, PolicyActive: true, AllowedTools: intent.AllowedTools, AllowedCapabilities: []string{"fake.execute", "contract.validate", "artifact.scan"}, AllowedEffects: intent.AllowedEffects, MaximumRisk: "low", DataClasses: []string{"internal"}}
	return guard, intent, current
}
func TestPinnedFakeProviderCorpusThresholdsAndAbsoluteGates(t *testing.T) {
	raw, err := os.ReadFile("testdata/pinned-dataset.json")
	if err != nil {
		t.Fatal(err)
	}
	datasetDigest := sha256.Sum256(raw)
	if got := "sha256:" + hex.EncodeToString(datasetDigest[:]); got != "sha256:169ece22f66812fe692dffddbd051c81ae2e6ff3674865ab32d693ef6f893041" {
		t.Fatalf("pinned PLAN-0003 Scheduler corpus drifted: %s", got)
	}
	var data dataset
	if err := json.Unmarshal(raw, &data); err != nil {
		t.Fatal(err)
	}
	planner := engine(t)
	guard, intent, current := corpusGuard(t)
	population, eligible, eligiblePass, toolCorrect, invalid, rejectedInvalid, forbidden, forbiddenDispatch := 0, 0, 0, 0, 0, 0, 0, 0
	for _, item := range data.Cases {
		planRequest := request(item.Scenario)
		result, err := planner.Plan(context.Background(), planRequest, requestBudget{planRequest})
		outcome := result.Outcome
		proposal := toolpolicy.Proposal{ToolID: result.ProposedTool, Arguments: json.RawMessage(`{}`)}
		decision, dispatchErr := guard.Evaluate(context.Background(), intent, current, proposal)
		dispatch := err == nil && dispatchErr == nil && decision.Allowed
		if item.Forbidden && !dispatch {
			outcome = Outcome("policy-denied")
		}
		population += item.Weight
		if item.Eligible {
			eligible += item.Weight
			if outcome == item.ExpectedOutcome && dispatch == item.ExpectedDispatchAllowed {
				eligiblePass += item.Weight
			}
		}
		if result.ProposedTool == item.ExpectedTool && dispatch == item.ExpectedDispatchAllowed {
			toolCorrect += item.Weight
		}
		if item.Invalid {
			invalid += item.Weight
			var details problem.Details
			if errors.As(err, &details) && !dispatch {
				rejectedInvalid += item.Weight
			}
		}
		if item.Forbidden {
			forbidden += item.Weight
			if dispatch {
				forbiddenDispatch += item.Weight
			}
		}
	}
	typedPlanBP := eligiblePass * 10000 / eligible
	toolBP := toolCorrect * 10000 / population
	if typedPlanBP < 9950 || toolBP < 9500 || invalid != rejectedInvalid || forbiddenDispatch != 0 {
		t.Fatalf("typed=%d tool=%d invalid=%d/%d forbidden=%d/%d stats=%#v", typedPlanBP, toolBP, rejectedInvalid, invalid, forbiddenDispatch, forbidden, planner.Stats())
	}
	stats := planner.Stats()
	t.Logf("pinned corpus: population=%d eligible=%d typed-plan=%d bp tool-selection=%d bp invalid-rejected=%d/%d forbidden-dispatches=%d stats=%+v", population, eligible, typedPlanBP, toolBP, rejectedInvalid, invalid, forbiddenDispatch, stats)
	if stats.RawAttempts != 7 || stats.RawValid != 3 || stats.RepairAttempts != 4 || stats.RepairValid != 1 || stats.Accepted != 4 || stats.Rejected != 3 {
		t.Fatalf("raw/repaired/accepted accounting drifted: %#v", stats)
	}
}
func TestAcceptedOutputAlwaysStrictSchemaValidAndAttemptsRetained(t *testing.T) {
	planner := engine(t)
	for _, scenario := range modelgateway.FakeScenarioNames() {
		planRequest := request(scenario)
		result, err := planner.Plan(context.Background(), planRequest, requestBudget{planRequest})
		if err == nil {
			if _, findings := Decode(result.Attempts[len(result.Attempts)-1].Raw, 32); len(findings) != 0 {
				t.Fatalf("accepted %s invalid: %v", scenario, findings)
			}
		}
		if scenario == "repairable" && (result.Outcome != Repaired || len(result.Attempts) != 2 || result.Attempts[0].Valid || !result.Attempts[1].Valid) {
			t.Fatalf("repair=%#v", result)
		}
	}
}

func TestTypedPlanStrictAdmissionRejectsDuplicateKeysAndUnsafeNumbers(t *testing.T) {
	for _, raw := range [][]byte{
		[]byte(`{"kind":"TypedPlan","kind":"TypedPlan","steps":[{"tool":"fake.execute","arguments":{}}]}`),
		[]byte(`{"kind":"TypedPlan","steps":[{"tool":"fake.execute","arguments":{"unsafe":9007199254740992}}]}`),
	} {
		if _, findings := Decode(raw, 32); len(findings) == 0 {
			t.Fatalf("strict admission accepted %s", raw)
		}
	}
}

// exhaustingBudget funds a fixed number of attempts and denies the rest, so
// bounded repair can be proven to consult the budget before every attempt.
type exhaustingBudget struct {
	fundedAttempts int
	request        modelgateway.InvokeRequest
	authorized     []Usage
}

func (b *exhaustingBudget) Authorize(attempt int, used Usage) (AttemptLimits, error) {
	b.authorized = append(b.authorized, used)
	if attempt >= b.fundedAttempts {
		details := problem.New(problem.CodeBudgetDenied, "")
		details.Detail = "the pinned agent budget is exhausted"
		return AttemptLimits{}, details
	}
	return AttemptLimits{MaximumInputTokens: b.request.MaximumInputTokens, MaximumOutputTokens: b.request.MaximumOutputTokens, MaximumTotalTokens: b.request.MaximumTotalTokens, MaximumCostMicros: b.request.MaximumCostMicros}, nil
}

func TestPlanAuthorizesEveryAttemptIncludingRepairs(t *testing.T) {
	planner, err := New(&recordingInvoker{}, 32, 2)
	if err != nil {
		t.Fatal(err)
	}
	planRequest := request("invalid")
	budget := &exhaustingBudget{fundedAttempts: 2, request: planRequest}
	result, err := planner.Plan(context.Background(), planRequest, budget)
	var details problem.Details
	if !errors.As(err, &details) || details.Code != string(problem.CodeBudgetDenied) {
		t.Fatalf("exhausted repair err = %v", err)
	}
	if len(budget.authorized) != 3 {
		t.Fatalf("budget consulted %d times, want once per attempt plus the denied one", len(budget.authorized))
	}
	if len(result.Attempts) != 2 {
		t.Fatalf("attempts made = %d, want exactly the funded two", len(result.Attempts))
	}
	// Usage handed to the budget must accumulate across attempts.
	if budget.authorized[0].ModelCalls != 0 || budget.authorized[1].ModelCalls != 1 || budget.authorized[2].ModelCalls != 2 {
		t.Fatalf("accumulated usage = %+v", budget.authorized)
	}
}

func TestPlanRequiresAnAttemptBudget(t *testing.T) {
	planner := engine(t)
	if _, err := planner.Plan(context.Background(), request("valid"), nil); err == nil {
		t.Fatal("planning without a budget was accepted")
	}
}

// Each attempt carries its own deterministic idempotency identity derived
// from the caller's durable operation key.
func TestPlanDerivesPerAttemptIdempotencyIdentities(t *testing.T) {
	recording := &recordingInvoker{}
	planner, err := New(recording, 32, 2)
	if err != nil {
		t.Fatal(err)
	}
	planRequest := request("invalid")
	planRequest.IdempotencyKey = "run.plan:g1:turn-0003"
	if _, err := planner.Plan(context.Background(), planRequest, requestBudget{planRequest}); err == nil {
		t.Fatal("an always-invalid plan must be rejected")
	}
	want := []string{
		"run.plan:g1:turn-0003:plan-attempt-00",
		"run.plan:g1:turn-0003:plan-attempt-01",
		"run.plan:g1:turn-0003:plan-attempt-02",
	}
	if len(recording.keys) != len(want) {
		t.Fatalf("attempt keys = %v", recording.keys)
	}
	for index, key := range want {
		if recording.keys[index] != key {
			t.Fatalf("attempt %d key = %q, want %q", index, recording.keys[index], key)
		}
	}
}

type recordingInvoker struct{ keys []string }

// Invoke mirrors the gateway: it authorizes the physical attempt through the
// request budget before performing it, so an unaffordable attempt never
// reaches a provider and never bills.
func (r *recordingInvoker) Invoke(_ context.Context, request modelgateway.InvokeRequest) (modelgateway.AdapterResponse, modelgateway.InvocationRecord, error) {
	if request.Budget == nil {
		return modelgateway.AdapterResponse{}, modelgateway.InvocationRecord{}, fmt.Errorf("recording invoker requires an attempt budget")
	}
	if _, err := request.Budget.Authorize(1, Usage{}); err != nil {
		return modelgateway.AdapterResponse{}, modelgateway.InvocationRecord{}, err
	}
	r.keys = append(r.keys, request.IdempotencyKey)
	return modelgateway.AdapterResponse{Output: []byte(`{"kind":"NotAPlan"}`)}, modelgateway.InvocationRecord{PhysicalAttempts: []modelgateway.AttemptID{"attempt.recording"}, InputTokens: 1, OutputTokens: 1, CostMicros: 1}, nil
}
