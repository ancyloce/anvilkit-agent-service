package runner_test

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ancyloce/anvilkit-agent-service/contracts/generated/schema"
	contractvalidator "github.com/ancyloce/anvilkit-agent-service/contracts/validator"
	"github.com/ancyloce/anvilkit-agent-service/internal/agent"
	"github.com/ancyloce/anvilkit-agent-service/internal/agent/runner"
	"github.com/ancyloce/anvilkit-agent-service/internal/authority"
	"github.com/ancyloce/anvilkit-agent-service/internal/contextcompiler"
	"github.com/ancyloce/anvilkit-agent-service/internal/contracts"
	"github.com/ancyloce/anvilkit-agent-service/internal/dispatch"
	"github.com/ancyloce/anvilkit-agent-service/internal/modelgateway"
	"github.com/ancyloce/anvilkit-agent-service/internal/problem"
	"github.com/ancyloce/anvilkit-agent-service/internal/runtimes"
	"github.com/ancyloce/anvilkit-agent-service/internal/runtimes/inprocess"
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
// is exhausted and never invents outputs. It stands where the governed Model
// Gateway stands for the runtime, not for the runner: after the dispatch cut
// the runner reaches no model at all, and every assertion about model calls
// below is an assertion about what the runtime did on the other side of the
// port.
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

// definitionResolver is what a runtime asks of the approved catalog: the
// definition a task pins, by identity and digest.
type definitionResolver struct{ registry *agent.Registry }

func (d definitionResolver) Resolve(definitionID, definitionDigest string) (agent.Definition, error) {
	return d.registry.Resolve(agent.DefinitionReference{DefinitionID: definitionID, DefinitionDigest: definitionDigest})
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

// interceptingDispatcher sits between the runner and the in-process runtime so
// a test can make a dispatch go unanswered, or tamper with a result after it
// was signed. Both are things a transport can do and a runtime cannot.
type interceptingDispatcher struct {
	inner *inprocess.Runtime
	lock  sync.Mutex
	// unanswered makes the next N dispatches produce no result at all, as a
	// lost response or an unreachable release would.
	unanswered int
	tamper     func(*schema.AgentRuntimeResult)
	tasks      []schema.AgentTask
}

func (d *interceptingDispatcher) Dispatch(ctx context.Context, binding agent.RuntimeBinding, task schema.AgentTask, credential runtimes.Credential) (runtimes.DispatchReceipt, error) {
	d.lock.Lock()
	d.tasks = append(d.tasks, task)
	skip := d.unanswered > 0
	if skip {
		d.unanswered--
	}
	tamper := d.tamper
	d.lock.Unlock()
	if skip {
		return runtimes.DispatchReceipt{}, fmt.Errorf("the release did not answer")
	}
	receipt, err := d.inner.Dispatch(ctx, binding, task, credential)
	if err != nil || tamper == nil {
		return receipt, err
	}
	tamper(&receipt.Result)
	return receipt, nil
}

type runnerHarness struct {
	runner     *runner.Runner
	registry   *agent.Registry
	invoker    *scriptedInvoker
	recorder   *recordingToolRecorder
	repository *dispatch.MemoryRepository
	dispatcher *interceptingDispatcher
	signer     *inprocess.SeededSigner
}

func newRunnerHarness(t *testing.T, outputs [][]byte, options ...func(*runner.Config)) *runnerHarness {
	t.Helper()
	registry := testRegistry(t)
	invoker := &scriptedInvoker{outputs: outputs}
	recorder := &recordingToolRecorder{}
	clock := fixedClock{time.Unix(1000, 0).UTC()}
	guard, err := tools.NewGuard(testToolProfile(t), recorder, clock, admittingArgumentValidator{})
	if err != nil {
		t.Fatal(err)
	}
	signer, err := inprocess.NewSeededSigner(testSigningMaterial, testResultKeyID)
	if err != nil {
		t.Fatal(err)
	}
	credentials, credentialTrust := testCredentialMaterial(t, registry, clock)
	inProcess, err := inprocess.New(inprocess.Config{
		Definitions: definitionResolver{registry: registry},
		Credentials: credentialTrust,
		Selector:    staticSelector{},
		Invoker:     invoker,
		Signer:      signer,
		Now:         clock.Now,
		Repairs:     3,
	})
	if err != nil {
		t.Fatal(err)
	}
	dispatcher := &interceptingDispatcher{inner: inProcess}
	repository := dispatch.NewMemoryRepository()
	tasks, err := dispatch.New(dispatch.Config{Repository: repository, Tokens: dispatch.RandomTokens{}, Clock: clock, Lease: time.Minute})
	if err != nil {
		t.Fatal(err)
	}
	cfg := runner.Config{
		Registry:    registry,
		Compiler:    contextcompiler.New(nil),
		Tasks:       tasks,
		Dispatcher:  dispatcher,
		Credentials: credentials,
		Signatures:  testResultVerifier(t, registry, signer, clock),
		Disclosure:  inProcess,
		Candidates:  inProcess,
		Guard:       guard,
		Validator:   acceptAllValidator{},
		Clock:       clock,
		Limits:      testLimits(),
	}
	for _, option := range options {
		option(&cfg)
	}
	built, err := runner.New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	return &runnerHarness{runner: built, registry: registry, invoker: invoker, recorder: recorder, repository: repository, dispatcher: dispatcher, signer: signer}
}

const testSigningMaterial = "runner-test-signing-material-0123456789"

const (
	testResultKeyID     = "urn:anvilkit:key:test-runtime-result"
	testCredentialKeyID = "urn:anvilkit:key:test-task-credential"
)

// testCredentialMaterial builds both halves of the task-credential boundary
// from one key: the issuer the runner mints with, and the trust the in-process
// runtime admits against. They are built together because a harness that let
// them drift would be testing a boundary neither side of production has.
func testCredentialMaterial(t *testing.T, registry *agent.Registry, clock fixedClock) (*runtimes.TaskCredentials, *runtimes.CredentialTrust) {
	t.Helper()
	issuer, err := runtimes.NewSeededTaskCredentials(testSigningMaterial, testCredentialKeyID, time.Minute, clock.Now)
	if err != nil {
		t.Fatal(err)
	}
	audiences := make([]string, 0)
	for _, definition := range registry.Definitions() {
		audiences = append(audiences, definition.RuntimeBinding.RuntimeAudience)
	}
	source, err := runtimes.NewControlledCredentialTrust(issuer.PublicKey(), issuer.KeyID(), audiences, clock.Now)
	if err != nil {
		t.Fatal(err)
	}
	trust, err := runtimes.NewCredentialTrust(source)
	if err != nil {
		t.Fatal(err)
	}
	return issuer, trust
}

// testResultVerifier trusts the harness signer for every release the catalog
// binds, which is what the operator's trust store does for a real deployment.
func testResultVerifier(t *testing.T, registry *agent.Registry, signer *inprocess.SeededSigner, clock fixedClock) *runtimes.ResultVerifier {
	t.Helper()
	source, err := runtimes.NewControlledSigningTrust(signer.PublicKey(), testResultKeyID, testReleases(registry), clock.Now)
	if err != nil {
		t.Fatal(err)
	}
	verifier, err := runtimes.NewResultVerifier(source)
	if err != nil {
		t.Fatal(err)
	}
	return verifier
}

// testReleases describes the releases the catalog's definitions pin, in the
// shape the trust material is built from.
func testReleases(registry *agent.Registry) []runtimes.Release {
	releases := make([]runtimes.Release, 0)
	for _, definition := range registry.Definitions() {
		releases = append(releases, runtimes.Release{
			RuntimeUnitID:  definition.RuntimeBinding.RuntimeUnitID,
			ManifestDigest: definition.RuntimeBinding.RuntimeManifestDigest,
			Binding:        definition.RuntimeBinding,
		})
	}
	return releases
}

func testLimits() runner.Limits {
	return runner.Limits{
		MaximumOutputBytes: 65536, MaximumInputTokens: 100000, MaximumOutputTokens: 100000,
		Timeout: 5 * time.Second, MaximumAttempts: 1, RetryBudget: 0, ContextTokens: 4000,
		MemoryBytes: 512 << 20, CPUMillis: 2000,
	}
}

func plan(tool string, arguments string) []byte {
	return []byte(`{"kind":"TypedPlan","steps":[{"tool":"` + tool + `","arguments":` + arguments + `}]}`)
}

func ampleBudget() runner.BudgetView {
	return runner.BudgetView{RemainingModelCalls: 100, RemainingInputTokens: 1_000_000, RemainingOutputTokens: 1_000_000, RemainingTotalTokens: 2_000_000, RemainingCostMicros: 1_000_000, ExceedBehavior: "refuse"}
}

func testRunView() runner.RunView {
	return runner.RunView{
		RunID: "run.test", RootRunID: "run.test", WorkspaceID: "workspace", ProjectID: "project",
		ActorID: "actor", Domain: "platform-agent", Operation: "page-change", TargetType: "page", TargetID: "page.home",
		ExecutionGeneration: 1,
		Traceparent:         "00-0123456789abcdef0123456789abcdef-0123456789abcdef-01",
	}
}

func testContractBOM() schema.SharedPrimitivesContractBomReference {
	digest := schema.SharedPrimitivesDigest("sha256:" + strings.Repeat("a", 64))
	return schema.SharedPrimitivesContractBomReference{Repository: "anvilkit/contracts", BomDigest: digest, OciManifestDigest: digest, EvidenceManifestDigest: digest}
}

// turn dispatches one turn for the given definition on the release that
// definition pins.
func (h *runnerHarness) turn(definition agent.Definition, request runner.TurnRequest) (runner.TurnOutcome, error) {
	request.Definition = definition
	request.Runtime = definition.RuntimeBinding
	request.ContractBOM = testContractBOM()
	if request.Run.RunID == "" {
		request.Run = testRunView()
	}
	return h.runner.Turn(context.Background(), request)
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
			outcome, err := harness.turn(managerDefinition(t, harness.registry), runner.TurnRequest{
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

// Every turn leaves a durable account of what was executed: one logical task,
// one physical attempt under it, and a registered result.
func TestTurnRecordsOneLogicalTaskAndOneSettledAttempt(t *testing.T) {
	harness := newRunnerHarness(t, [][]byte{plan("agent.continue", `{"note":"thinking"}`)})
	if _, err := harness.turn(managerDefinition(t, harness.registry), runner.TurnRequest{
		Phase: runner.PhasePlan, OperationKey: "run.test:g1:turn-0000", Authority: activeAuthority(), Budget: ampleBudget(),
	}); err != nil {
		t.Fatal(err)
	}
	task, attempts, found, err := harness.repository.Load(context.Background(), dispatch.Scope{WorkspaceID: "workspace", ProjectID: "project"}, dispatch.TaskID("run.test:g1:turn-0000"))
	if err != nil || !found {
		t.Fatalf("the turn recorded no logical task: %v", err)
	}
	if task.Status != dispatch.Succeeded || task.Attempts != 1 || task.LeaseEpoch != 1 {
		t.Fatalf("task = %+v", task)
	}
	if len(attempts) != 1 || attempts[0].Status != dispatch.Succeeded || attempts[0].ResultStatementDigest == "" {
		t.Fatalf("attempts = %+v", attempts)
	}
	if attempts[0].FenceTokenDigest == "" || strings.Contains(attempts[0].FenceTokenDigest, "=") {
		t.Fatalf("the durable record must hold the fence digest, not the token: %q", attempts[0].FenceTokenDigest)
	}
	if len(harness.dispatcher.tasks) != 1 {
		t.Fatalf("dispatched tasks = %d, want 1", len(harness.dispatcher.tasks))
	}
	dispatched := harness.dispatcher.tasks[0]
	if dispatched.FenceToken == "" || dispatched.AttemptNumber != 1 || dispatched.LeaseEpoch != 1 {
		t.Fatalf("the dispatched task must carry the attempt's own fence: %+v", dispatched)
	}
	if dispatch.Digest(dispatched.FenceToken) != attempts[0].FenceTokenDigest {
		t.Fatal("the dispatched fence token must be the one the record digested")
	}
}

// A dispatch that never answered is replaced by a new physical attempt with a
// new number, lease epoch, and fence. The replaced attempt is superseded, so
// nothing it might still return can commit.
func TestUnansweredDispatchIsReplacedAndTheOldAttemptIsSuperseded(t *testing.T) {
	harness := newRunnerHarness(t, [][]byte{plan("agent.continue", `{"note":"thinking"}`)}, func(cfg *runner.Config) {
		limits := testLimits()
		limits.MaximumAttempts, limits.RetryBudget = 3, time.Minute
		cfg.Limits = limits
	})
	harness.dispatcher.unanswered = 1
	outcome, err := harness.turn(managerDefinition(t, harness.registry), runner.TurnRequest{
		Phase: runner.PhasePlan, OperationKey: "run.test:g1:turn-0000", Authority: activeAuthority(), Budget: ampleBudget(),
	})
	if err != nil {
		t.Fatal(err)
	}
	if outcome.Decision.Kind != agent.DecisionContinue {
		t.Fatalf("the replacement must resolve the turn: %+v", outcome)
	}
	task, attempts, _, err := harness.repository.Load(context.Background(), dispatch.Scope{WorkspaceID: "workspace", ProjectID: "project"}, dispatch.TaskID("run.test:g1:turn-0000"))
	if err != nil {
		t.Fatal(err)
	}
	if task.Attempts != 2 || len(attempts) != 2 {
		t.Fatalf("a replacement must be a second attempt of the same task: %+v", attempts)
	}
	if attempts[0].Status != dispatch.Superseded || attempts[0].FailureReason != dispatch.ReasonDispatchFailed {
		t.Fatalf("the unanswered attempt must be superseded: %+v", attempts[0])
	}
	if attempts[1].LeaseEpoch <= attempts[0].LeaseEpoch || attempts[1].FenceTokenDigest == attempts[0].FenceTokenDigest {
		t.Fatal("a replacement must carry a new lease epoch and a new fence")
	}
	if attempts[1].Status != dispatch.Succeeded {
		t.Fatalf("the replacement must be the attempt that settled: %+v", attempts[1])
	}
	// The provider identity belongs to the logical task, so the replacement
	// replays the same provider operation instead of buying a second one.
	if harness.invoker.calls != 1 {
		t.Fatalf("model calls = %d, want the one the logical task funds", harness.invoker.calls)
	}
}

// A result that does not describe the bytes it arrived in cannot be correlated
// with anything, and must not be committed on the strength of its own claim.
func TestTamperedResultIsRefusedBeforeAnyCommit(t *testing.T) {
	harness := newRunnerHarness(t, [][]byte{plan("agent.continue", `{"note":"thinking"}`)})
	harness.dispatcher.tamper = func(result *schema.AgentRuntimeResult) {
		result.TurnDecision.Payload["note"] = "something else entirely"
	}
	_, err := harness.turn(managerDefinition(t, harness.registry), runner.TurnRequest{
		Phase: runner.PhasePlan, OperationKey: "run.test:g1:turn-0000", Authority: activeAuthority(), Budget: ampleBudget(),
	})
	var details problem.Details
	if err == nil || !asProblem(err, &details) || details.Code != string(problem.CodeContractInvalid) {
		t.Fatalf("a tampered result must be refused: %v", err)
	}
	_, attempts, _, loadErr := harness.repository.Load(context.Background(), dispatch.Scope{WorkspaceID: "workspace", ProjectID: "project"}, dispatch.TaskID("run.test:g1:turn-0000"))
	if loadErr != nil {
		t.Fatal(loadErr)
	}
	if attempts[0].Status == dispatch.Succeeded {
		t.Fatal("a refused result must not settle the attempt")
	}
}

// A result the fence never sees still leaves a trace. An unverifiable
// signature and a result addressed to other work are the two failures most
// worth investigating, and before this they were the only ones that recorded
// nothing while an ordinary stale fence recorded evidence.
func TestAnUnattributableResultIsRecordedAsEvidence(t *testing.T) {
	for name, expectation := range map[string]struct {
		tamper func(*testing.T, *runnerHarness, *schema.AgentRuntimeResult)
		reason string
	}{
		"an unverifiable signature": {
			tamper: func(_ *testing.T, _ *runnerHarness, result *schema.AgentRuntimeResult) {
				// Signed, and not by anything the trust store approves.
				result.Signature.Signature = "AAAA" + result.Signature.Signature[4:]
			},
			reason: "RESULT_SIGNATURE_UNVERIFIED",
		},
		"a result for another attempt": {
			tamper: func(t *testing.T, harness *runnerHarness, result *schema.AgentRuntimeResult) {
				result.PhysicalAttemptId = "attempt.somewhere-else"
				harness.resign(t, result)
			},
			reason: "RESULT_NOT_FOR_ATTEMPT",
		},
		"a misstated statement digest": {
			tamper: func(_ *testing.T, _ *runnerHarness, result *schema.AgentRuntimeResult) {
				result.Signature.StatementDigest = schema.SharedPrimitivesDigest("sha256:" + strings.Repeat("c", 64))
			},
			reason: "RESULT_STATEMENT_DIGEST_MISMATCH",
		},
	} {
		t.Run(name, func(t *testing.T) {
			harness := newRunnerHarness(t, [][]byte{plan("agent.continue", `{"note":"thinking"}`)})
			harness.dispatcher.tamper = func(result *schema.AgentRuntimeResult) {
				expectation.tamper(t, harness, result)
			}
			if _, err := harness.turn(managerDefinition(t, harness.registry), runner.TurnRequest{
				Phase: runner.PhasePlan, OperationKey: "run.test:g1:turn-0000", Authority: activeAuthority(), Budget: ampleBudget(),
			}); err == nil {
				t.Fatal("an unattributable result was not refused")
			}
			evidence := harness.repository.Evidence()
			if len(evidence) != 1 {
				t.Fatalf("recorded %d evidence facts, want exactly one", len(evidence))
			}
			if evidence[0].Disposition != dispatch.DispositionUnbound || evidence[0].Reason != expectation.reason {
				t.Fatalf("evidence = %+v, want an unbound %s", evidence[0], expectation.reason)
			}
			// The evidence names the attempt this service was holding, not the
			// one the result claimed: a record keyed by whatever a hostile
			// result said would be a record an attacker chose the shape of.
			if evidence[0].PhysicalAttemptID == "attempt.somewhere-else" {
				t.Fatal("the evidence was keyed by the identity the result asserted")
			}
			// And nothing committed.
			_, attempts, _, err := harness.repository.Load(context.Background(),
				dispatch.Scope{WorkspaceID: "workspace", ProjectID: "project"}, dispatch.TaskID("run.test:g1:turn-0000"))
			if err != nil {
				t.Fatal(err)
			}
			for _, attempt := range attempts {
				if attempt.Status == dispatch.Succeeded {
					t.Fatal("an unattributable result settled an attempt")
				}
			}
			// The attempt the turn gave up on is closed rather than left as the
			// task's current execution: a runtime still working on it must be
			// refused at the boundary, and only a closed attempt can be.
			if len(attempts) != 1 || attempts[0].Status != dispatch.Failed || attempts[0].FailureReason != dispatch.ReasonResultUnattributable {
				t.Fatalf("the abandoned attempt must be closed as failed for an unattributable result: %+v", attempts)
			}
		})
	}
}

// A result addressed to another attempt is refused before the durable record
// is asked about it.
func TestResultForAnotherAttemptIsRefused(t *testing.T) {
	harness := newRunnerHarness(t, [][]byte{plan("agent.continue", `{"note":"thinking"}`)})
	harness.dispatcher.tamper = func(result *schema.AgentRuntimeResult) {
		result.PhysicalAttemptId = "attempt.somewhere-else"
		harness.resign(t, result)
	}
	_, err := harness.turn(managerDefinition(t, harness.registry), runner.TurnRequest{
		Phase: runner.PhasePlan, OperationKey: "run.test:g1:turn-0000", Authority: activeAuthority(), Budget: ampleBudget(),
	})
	var details problem.Details
	if err == nil || !asProblem(err, &details) || details.Code != string(problem.CodeContractInvalid) {
		t.Fatalf("a result for another attempt must be refused: %v", err)
	}
}

// A candidate that does not match the digest the result pinned is not a
// candidate: the reference is the only thing tying the document to the result.
func TestCandidateDigestMismatchRefusesTheDecision(t *testing.T) {
	harness := newRunnerHarness(t, [][]byte{plan("agent.final", `{"candidate":{"kind":"ComponentPackageSpec"},"summary":"done"}`)})
	harness.dispatcher.tamper = func(result *schema.AgentRuntimeResult) {
		result.TurnDecision.ArtifactOutputs[0].Digest = schema.SharedPrimitivesDigest("sha256:" + strings.Repeat("b", 64))
		harness.resign(t, result)
	}
	outcome, err := harness.turn(managerDefinition(t, harness.registry), runner.TurnRequest{
		Phase: runner.PhasePlan, OperationKey: "run.test:g1:turn-0000", Authority: activeAuthority(), Budget: ampleBudget(),
	})
	if err != nil {
		t.Fatal(err)
	}
	if outcome.Decision.Kind != agent.DecisionRefuse {
		t.Fatalf("an unreadable candidate must refuse: %+v", outcome.Decision)
	}
}

// restatedDigest recomputes the statement digest after a test rewrote the
// statement, so the test exercises the check it means to and not the one
// before it.
func restatedDigest(t *testing.T, result schema.AgentRuntimeResult) schema.SharedPrimitivesDigest {
	t.Helper()
	digest, err := runtimes.StatementDigest(result)
	if err != nil {
		t.Fatal(err)
	}
	return schema.SharedPrimitivesDigest(digest)
}

// resign re-signs a result a test rewrote, in the runtime's own voice.
//
// Restating the digest is no longer enough to reach the checks downstream of
// the signature: a rewritten statement no longer verifies, which is the point
// of verifying it. A test that means to exercise the binding, fence, or
// candidate checks therefore has to produce a result a runtime could actually
// have produced — signed, and signed over what it says.
func (h *runnerHarness) resign(t *testing.T, result *schema.AgentRuntimeResult) {
	t.Helper()
	statement, err := runtimes.StatementBytes(*result)
	if err != nil {
		t.Fatal(err)
	}
	algorithm, keyID, signature, err := h.signer.Sign(statement)
	if err != nil {
		t.Fatal(err)
	}
	result.Signature.Algorithm = schema.AgentRuntimeResultSignatureAlgorithm(algorithm)
	result.Signature.KeyId = keyID
	result.Signature.Signature = signature
	result.Signature.StatementDigest = restatedDigest(t, *result)
}

func TestTurnBudgetPrecheckHaltsDeterministically(t *testing.T) {
	harness := newRunnerHarness(t, nil)
	budget := ampleBudget()
	budget.RemainingModelCalls = 0
	outcome, err := harness.turn(managerDefinition(t, harness.registry), runner.TurnRequest{Phase: runner.PhasePlan, OperationKey: "run.test:g1:turn-0000", Authority: activeAuthority(), Budget: budget})
	if err != nil {
		t.Fatal(err)
	}
	if outcome.Halted == nil || !outcome.Halted.Refuse || outcome.Halted.Problem.Code != string(problem.CodeBudgetDenied) {
		t.Fatalf("halt = %+v", outcome.Halted)
	}
	if harness.invoker.calls != 0 {
		t.Fatal("exhausted budget must not reach the model")
	}
	// An exhausted budget must not even admit the work: a task that exists is
	// a task some later result could try to commit.
	if _, _, found, err := harness.repository.Load(context.Background(), dispatch.Scope{WorkspaceID: "workspace", ProjectID: "project"}, dispatch.TaskID("run.test:g1:turn-0000")); err != nil || found {
		t.Fatal("an exhausted budget must not create a dispatchable task")
	}
	budget.ExceedBehavior = "cancel"
	outcome, err = harness.turn(managerDefinition(t, harness.registry), runner.TurnRequest{Phase: runner.PhasePlan, OperationKey: "run.test:g1:turn-0000", Authority: activeAuthority(), Budget: budget})
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
	outcome, err := harness.turn(managerDefinition(t, harness.registry), runner.TurnRequest{Phase: runner.PhasePlan, OperationKey: "run.test:g1:turn-0000", Authority: activeAuthority(), Budget: ampleBudget()})
	if err != nil {
		t.Fatal(err)
	}
	if outcome.Decision.Kind != agent.DecisionRefuse {
		t.Fatalf("decision = %s, want refuse", outcome.Decision.Kind)
	}
	// The definition's pinned repair policy still decides how many attempts a
	// turn makes; what changed is which process makes them.
	if harness.invoker.calls != 3 {
		t.Fatalf("model calls = %d, want 3", harness.invoker.calls)
	}
	if outcome.Usage.ModelCalls != 3 {
		t.Fatalf("usage must count every physical attempt, got %d", outcome.Usage.ModelCalls)
	}
}

func TestSpecialistCannotRequestInput(t *testing.T) {
	harness := newRunnerHarness(t, [][]byte{plan("agent.need-input", `{"question":"?"}`)})
	outcome, err := harness.turn(specialistDefinition(t, harness.registry), runner.TurnRequest{Phase: runner.PhaseDelegate, OperationKey: "run.test:g1:delegate-turn-0000-0000", Authority: activeAuthority(), Budget: ampleBudget()})
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
	specialistTurn := func(t *testing.T, harness *runnerHarness, last bool) runner.DelegateTurnRequest {
		specialist := specialistDefinition(t, harness.registry)
		return runner.DelegateTurnRequest{
			Specialist:   specialist,
			Run:          testRunView(),
			Runtime:      specialist.RuntimeBinding,
			ContractBOM:  testContractBOM(),
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
		outcome, err := harness.runner.DelegateTurn(context.Background(), specialistTurn(t, harness, false))
		if err != nil {
			t.Fatal(err)
		}
		if !outcome.Done || outcome.Refused != nil || len(outcome.Candidate) == 0 {
			t.Fatalf("delegate turn outcome = %+v", outcome)
		}
	})
	t.Run("continue-is-not-done", func(t *testing.T) {
		harness := newRunnerHarness(t, [][]byte{plan("agent.continue", `{"note":"still drafting"}`)})
		outcome, err := harness.runner.DelegateTurn(context.Background(), specialistTurn(t, harness, false))
		if err != nil {
			t.Fatal(err)
		}
		if outcome.Done || outcome.Refused != nil {
			t.Fatalf("a continuing specialist turn must leave the delegation open: %+v", outcome)
		}
	})
	t.Run("turn-limit-refuses-on-the-last-turn", func(t *testing.T) {
		harness := newRunnerHarness(t, [][]byte{plan("agent.continue", `{"note":"still drafting"}`)})
		outcome, err := harness.runner.DelegateTurn(context.Background(), specialistTurn(t, harness, true))
		if err != nil {
			t.Fatal(err)
		}
		if !outcome.Done || outcome.Refused == nil || outcome.Refused.Code != string(problem.CodeLimitExceeded) {
			t.Fatalf("exhausted delegation must refuse with LIMIT_EXCEEDED: %+v", outcome)
		}
	})
	t.Run("specialist-refusal", func(t *testing.T) {
		harness := newRunnerHarness(t, [][]byte{plan("agent.refuse", `{"reason":"cannot draft"}`)})
		outcome, err := harness.runner.DelegateTurn(context.Background(), specialistTurn(t, harness, false))
		if err != nil || !outcome.Done || outcome.Refused == nil {
			t.Fatalf("specialist refusal must conclude the delegation: %+v %v", outcome, err)
		}
	})
	t.Run("decision-outside-the-delegation-contract", func(t *testing.T) {
		harness := newRunnerHarness(t, [][]byte{plan("anvilkit.tool.context-echo", `{"query":"context"}`)})
		outcome, err := harness.runner.DelegateTurn(context.Background(), specialistTurn(t, harness, false))
		if err != nil || !outcome.Done || outcome.Refused == nil {
			t.Fatalf("specialist tool call must refuse: %+v %v", outcome, err)
		}
	})
	t.Run("candidate-violating-the-pinned-output-schema", func(t *testing.T) {
		harness := newRunnerHarness(t, [][]byte{plan("agent.final", `{"candidate":`+candidate+`}`)}, func(cfg *runner.Config) {
			cfg.Validator = acceptAllValidator{denyComponent: "anvilkit.contract.schema.component-package-spec"}
		})
		outcome, err := harness.runner.DelegateTurn(context.Background(), specialistTurn(t, harness, false))
		if err != nil || !outcome.Done || outcome.Refused == nil || outcome.Refused.Code != string(problem.CodeContractInvalid) {
			t.Fatalf("invalid candidate must refuse: %+v %v", outcome, err)
		}
	})
	// Authority revoked mid-delegation stops the next Specialist turn before
	// it reaches the runtime.
	t.Run("revoked-authority-mid-delegation", func(t *testing.T) {
		harness := newRunnerHarness(t, [][]byte{plan("agent.final", `{"candidate":`+candidate+`}`)})
		request := specialistTurn(t, harness, false)
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

// Every provider attempt of one turn carries an identity derived from the
// logical task, not from the execution that happened to make it. A replacement
// attempt of the same turn must reproduce the same provider operation rather
// than buy a second one.
func TestProviderAttemptsAreIdentifiedByTheLogicalTask(t *testing.T) {
	broken := []byte(`{"kind":"TypedPlan","steps":[`)
	harness := newRunnerHarness(t, [][]byte{broken, broken, broken})
	if _, err := harness.turn(managerDefinition(t, harness.registry), runner.TurnRequest{
		Phase: runner.PhasePlan, OperationKey: "run.test:g1:turn-0007", Budget: ampleBudget(), Authority: activeAuthority(),
	}); err != nil {
		t.Fatal(err)
	}
	for index, key := range harness.invoker.keys {
		want := fmt.Sprintf("run.test:g1:turn-0007:plan-attempt-%02d", index)
		if key != want {
			t.Fatalf("attempt key %d = %q, want %q", index, key, want)
		}
	}
	if len(harness.invoker.keys) != 3 {
		t.Fatalf("attempt keys = %v", harness.invoker.keys)
	}
}

// A turn without a durable operation key has no logical task identity and must
// fail closed rather than invent one.
func TestTurnWithoutADurableOperationKeyFailsClosed(t *testing.T) {
	harness := newRunnerHarness(t, [][]byte{plan("agent.continue", `{"note":"x"}`)})
	if _, err := harness.turn(managerDefinition(t, harness.registry), runner.TurnRequest{
		Phase: runner.PhasePlan, Budget: ampleBudget(), Authority: activeAuthority(),
	}); err == nil {
		t.Fatal("a turn without an operation key was accepted")
	}
	if harness.invoker.calls != 0 {
		t.Fatal("a turn without an operation key must not reach the model")
	}
}
