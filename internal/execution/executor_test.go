package execution_test

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

	contractvalidator "github.com/ancyloce/anvilkit-agent-service/contracts/validator"
	"github.com/ancyloce/anvilkit-agent-service/internal/agent"
	"github.com/ancyloce/anvilkit-agent-service/internal/agent/runner"
	"github.com/ancyloce/anvilkit-agent-service/internal/authority"
	"github.com/ancyloce/anvilkit-agent-service/internal/budget"
	"github.com/ancyloce/anvilkit-agent-service/internal/contextcompiler"
	"github.com/ancyloce/anvilkit-agent-service/internal/contractclient"
	"github.com/ancyloce/anvilkit-agent-service/internal/contracts"
	"github.com/ancyloce/anvilkit-agent-service/internal/domaincommit"
	"github.com/ancyloce/anvilkit-agent-service/internal/events"
	"github.com/ancyloce/anvilkit-agent-service/internal/execution"
	"github.com/ancyloce/anvilkit-agent-service/internal/interrupts"
	"github.com/ancyloce/anvilkit-agent-service/internal/journal"
	"github.com/ancyloce/anvilkit-agent-service/internal/modelgateway"
	"github.com/ancyloce/anvilkit-agent-service/internal/problem"
	"github.com/ancyloce/anvilkit-agent-service/internal/recovery"
	"github.com/ancyloce/anvilkit-agent-service/internal/runs"
	"github.com/ancyloce/anvilkit-agent-service/internal/scheduler"
	"github.com/ancyloce/anvilkit-agent-service/internal/tools"
	"github.com/ancyloce/anvilkit-agent-service/internal/usage"
	"github.com/ancyloce/anvilkit-agent-service/internal/workflow"
	"github.com/ancyloce/anvilkit-agent-service/internal/workflow/memory"
)

const (
	testWorkspace = "workspace.test"
	testProject   = "project.test"
	testActor     = "actor.test"
	testRunID     = "run.test"
	validDigest   = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	traceparent   = "00-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-bbbbbbbbbbbbbbbb-01"
)

func testScope() runs.Scope {
	return runs.Scope{WorkspaceID: testWorkspace, ProjectID: testProject, ActorID: testActor}
}

// countingOps wraps the real executor and counts every operation execution
// by step so exactly-once semantics can be asserted after crash and replay.
type countingOps struct {
	inner workflow.Operations
	lock  sync.Mutex
	calls map[string]int
	// holds blocks a named step until the test releases it, so a crash can
	// be injected at an exact durable boundary.
	holds   map[string]chan struct{}
	entered map[string]chan struct{}
	// hooks run once on entry to a named step, so a test can change external
	// state — revoking authority, for instance — at an exact durable
	// boundary instead of racing it.
	hooks map[string]func()
}

func newCountingOps(inner workflow.Operations) *countingOps {
	return &countingOps{inner: inner, calls: make(map[string]int), holds: make(map[string]chan struct{}), entered: make(map[string]chan struct{}), hooks: make(map[string]func())}
}

// hold makes the named step block on entry. It returns the release channel
// and a channel closed once the step has been entered.
func (c *countingOps) hold(step string) (release chan struct{}, entered chan struct{}) {
	c.lock.Lock()
	defer c.lock.Unlock()
	release, entered = make(chan struct{}), make(chan struct{})
	c.holds[step], c.entered[step] = release, entered
	return release, entered
}

// before registers a one-shot hook that runs when the named step is entered.
func (c *countingOps) before(step string, hook func()) {
	c.lock.Lock()
	defer c.lock.Unlock()
	c.hooks[step] = hook
}

func (c *countingOps) count(op workflow.OpID) {
	c.lock.Lock()
	c.calls[op.Key()]++
	release, held := c.holds[op.Step]
	entered := c.entered[op.Step]
	if held {
		delete(c.holds, op.Step)
		delete(c.entered, op.Step)
	}
	hook, hooked := c.hooks[op.Step]
	if hooked {
		delete(c.hooks, op.Step)
	}
	c.lock.Unlock()
	if hooked {
		hook()
	}
	if held {
		close(entered)
		<-release
	}
}

func (c *countingOps) callsFor(suffix string) int {
	c.lock.Lock()
	defer c.lock.Unlock()
	total := 0
	for key, count := range c.calls {
		if strings.HasSuffix(key, suffix) {
			total += count
		}
	}
	return total
}

func (c *countingOps) Prepare(ctx context.Context, op workflow.OpID, input workflow.RunInput) (workflow.PrepareResult, error) {
	c.count(op)
	return c.inner.Prepare(ctx, op, input)
}
func (c *countingOps) ExecuteTurn(ctx context.Context, op workflow.OpID, input workflow.TurnInput) (workflow.TurnResult, error) {
	c.count(op)
	return c.inner.ExecuteTurn(ctx, op, input)
}
func (c *countingOps) RecordDecision(ctx context.Context, op workflow.OpID, record workflow.DecisionRecord) (workflow.Ack, error) {
	c.count(op)
	return c.inner.RecordDecision(ctx, op, record)
}
func (c *countingOps) ExecuteAction(ctx context.Context, op workflow.OpID, input workflow.ActionInput) (workflow.ActionResult, error) {
	c.count(op)
	return c.inner.ExecuteAction(ctx, op, input)
}
func (c *countingOps) OpenDelegation(ctx context.Context, op workflow.OpID, input workflow.DelegationInput) (workflow.DelegationOpened, error) {
	c.count(op)
	return c.inner.OpenDelegation(ctx, op, input)
}
func (c *countingOps) ExecuteDelegateTurn(ctx context.Context, op workflow.OpID, input workflow.DelegateTurnInput) (workflow.DelegateTurnResult, error) {
	c.count(op)
	return c.inner.ExecuteDelegateTurn(ctx, op, input)
}
func (c *countingOps) OpenInput(ctx context.Context, op workflow.OpID, input workflow.InterruptOpen) (workflow.InterruptOpened, error) {
	c.count(op)
	return c.inner.OpenInput(ctx, op, input)
}
func (c *countingOps) ReadInput(ctx context.Context, op workflow.OpID, ref workflow.InterruptRef) (workflow.InputRead, error) {
	c.count(op)
	return c.inner.ReadInput(ctx, op, ref)
}
func (c *countingOps) ExpireInterrupt(ctx context.Context, op workflow.OpID, expire workflow.ExpireRequest) (workflow.Ack, error) {
	c.count(op)
	return c.inner.ExpireInterrupt(ctx, op, expire)
}
func (c *countingOps) FinalizeCandidate(ctx context.Context, op workflow.OpID, input workflow.FinalizeInput) (workflow.FinalizeResult, error) {
	c.count(op)
	return c.inner.FinalizeCandidate(ctx, op, input)
}
func (c *countingOps) ResolveReview(ctx context.Context, op workflow.OpID, input workflow.ReviewInput) (workflow.ReviewResult, error) {
	c.count(op)
	return c.inner.ResolveReview(ctx, op, input)
}
func (c *countingOps) ReadApproval(ctx context.Context, op workflow.OpID, ref workflow.InterruptRef) (workflow.ApprovalRead, error) {
	c.count(op)
	return c.inner.ReadApproval(ctx, op, ref)
}
func (c *countingOps) Revise(ctx context.Context, op workflow.OpID, input workflow.ReviseInput) (workflow.Ack, error) {
	c.count(op)
	return c.inner.Revise(ctx, op, input)
}
func (c *countingOps) Commit(ctx context.Context, op workflow.OpID, input workflow.CommitInput) (workflow.CommitResult, error) {
	c.count(op)
	return c.inner.Commit(ctx, op, input)
}
func (c *countingOps) Terminalize(ctx context.Context, op workflow.OpID, input workflow.TerminalInput) (workflow.Ack, error) {
	c.count(op)
	return c.inner.Terminalize(ctx, op, input)
}

// engineSignals bridges the interrupts control surface onto whatever engine
// the harness currently runs, mirroring the production wiring.
type engineSignals struct{ harness *harness }

func (s engineSignals) Signal(ctx context.Context, id, topic string, payload json.RawMessage, key string) error {
	runKey, err := workflow.ParseWorkflowID(id)
	if err != nil {
		return err
	}
	return s.harness.engine.Signal(ctx, runKey, topic, payload, key)
}
func (s engineSignals) StartChild(ctx context.Context, child interrupts.Child) error {
	return s.harness.engine.StartRun(ctx, workflow.RunInput{Key: workflow.RunKey{RunID: string(child.RunID), Generation: 1}, Scope: workflow.Scope{WorkspaceID: child.WorkspaceID, ProjectID: child.ProjectID, ActorID: child.ActorID}})
}
func (s engineSignals) StopRun(ctx context.Context, _ runs.Scope, id runs.ID, generation uint64) error {
	return s.harness.engine.CancelRun(ctx, workflow.RunKey{RunID: string(id), Generation: generation})
}
func (s engineSignals) ResumeRun(ctx context.Context, scope runs.Scope, snapshot runs.Snapshot, _ string, _ string) error {
	return s.harness.engine.StartRun(ctx, workflow.RunInput{Key: workflow.RunKey{RunID: string(snapshot.RunID), Generation: snapshot.ExecutionGeneration}, Scope: workflow.Scope{WorkspaceID: scope.WorkspaceID, ProjectID: scope.ProjectID, ActorID: scope.ActorID}})
}

type allowAllAuthority struct{}

func (allowAllAuthority) AuthorizeInput(context.Context, runs.Scope, interrupts.InputRequest) error {
	return nil
}
func (allowAllAuthority) AuthorizeReviewer(context.Context, runs.Scope, interrupts.ApprovalRequest, interrupts.DecisionKind) error {
	return nil
}
func (allowAllAuthority) RetryEligibility(_ context.Context, _ runs.Scope, snapshot runs.Snapshot) (bool, string, error) {
	return snapshot.Status == runs.Failed, "retry", nil
}
func (allowAllAuthority) AuthorizeResume(context.Context, runs.Scope, runs.Snapshot) error {
	return nil
}

type allowReservation struct{}

func (allowReservation) ReserveChild(context.Context, interrupts.ChildBudgetRequest) error {
	return nil
}

type noLeases struct{}

func (noLeases) RevokeRun(context.Context, runs.Scope, runs.ID) error { return nil }

type clearReconciler struct{}

func (clearReconciler) Reconcile(_ context.Context, _ runs.Scope, _ runs.ID, commit bool) (bool, *runs.State, error) {
	return !commit, nil, nil
}

type sequenceIDs struct {
	lock sync.Mutex
	next int
}

func (i *sequenceIDs) NewRequestID() (interrupts.RequestID, error) {
	i.lock.Lock()
	defer i.lock.Unlock()
	i.next++
	return interrupts.RequestID(fmt.Sprintf("request.%04d", i.next)), nil
}
func (i *sequenceIDs) NewRunID() (runs.ID, error) {
	i.lock.Lock()
	defer i.lock.Unlock()
	i.next++
	return runs.ID(fmt.Sprintf("run.child.%04d", i.next)), nil
}

type systemClock struct{}

func (systemClock) Now() time.Time { return time.Now() }

// deferredSettlement mirrors the composition root's late binding of the
// executor into the interrupt service's terminal-budget port.
type deferredSettlement struct{ inner *execution.Executor }

func (d *deferredSettlement) set(executor *execution.Executor) { d.inner = executor }
func (d *deferredSettlement) SettleRunBudget(ctx context.Context, snapshot runs.Snapshot, release bool) error {
	if d.inner == nil {
		return fmt.Errorf("terminal budget settlement is unavailable")
	}
	return d.inner.SettleRunBudget(ctx, snapshot, release)
}
func (d *deferredSettlement) FenceRunBudget(ctx context.Context, snapshot runs.Snapshot) error {
	if d.inner == nil {
		return fmt.Errorf("cancellation budget fencing is unavailable")
	}
	return d.inner.FenceRunBudget(ctx, snapshot)
}
func (d *deferredSettlement) OutstandingCancelledRunBudget(ctx context.Context, snapshot runs.Snapshot) (bool, error) {
	if d.inner == nil {
		return false, fmt.Errorf("cancelled budget hold lookup is unavailable")
	}
	return d.inner.OutstandingCancelledRunBudget(ctx, snapshot)
}
func (d *deferredSettlement) SettleCancelledRunBudget(ctx context.Context, snapshot runs.Snapshot) error {
	if d.inner == nil {
		return fmt.Errorf("cancelled budget settlement is unavailable")
	}
	return d.inner.SettleCancelledRunBudget(ctx, snapshot)
}

type harness struct {
	t        *testing.T
	repo     *interrupts.MemoryRepository
	service  *interrupts.Service
	store    *memory.Store
	engine   *memory.Runtime
	ops      *countingOps
	adapter  *execution.ScriptedAdapter
	tool     *execution.ControlledToolExecutor
	domain   *execution.ControlledDomainPort
	recorder *execution.MemoryToolRecorder
	journal  journal.Store
	registry *agent.Registry
	manager  agent.Definition
	// authoritySource is the one current-authority source every boundary
	// re-reads; tests revoke or replace it mid-run to prove guarded
	// boundaries fail closed.
	authoritySource *authority.Static
	artifacts       *execution.ControlledArtifactPort
	commitAuthority *execution.ControlledCommitAuthority
	submissions     *domaincommit.MemoryStore
	grants          authority.Grants
	// material is the running tool material the executor checks each run's
	// frozen tool profile against.
	material execution.ToolMaterial
	// budgetController and budgetLedger are the harness's durable-contract
	// budget authority; tests assert reservations, observations, and
	// settlement against the ledger.
	budgetController *budget.Controller
	budgetLedger     *budget.MemoryLedger
	// settlement is the deferred terminal-budget port the interrupt service
	// settles cancellation and discard through.
	settlement *deferredSettlement
	// evidence is the immutable evidence store guarded boundaries append to.
	evidence *events.MemoryEvidence
	// actorRole is the role the scope's subject register admits the run actor
	// under; the default is the plain agent actor.
	actorRole string
	// executor is the underlying pipeline, exposed for the operator-facing
	// entry points that live outside the workflow.Operations surface.
	executor *execution.Executor
}

// toolMaterial returns the running tool material this harness built from the
// approved catalog.
func (h *harness) toolMaterial() execution.ToolMaterial { return h.material }

type harnessOptions struct {
	inputTTL            time.Duration
	approvalTTL         time.Duration
	maximumCalls        int64
	allowedTools        []string
	allowedCapabilities []string
	domainOutcome       string
	// toolMaterial overrides the running tool material so a definition can be
	// executed against material it does not reference.
	toolMaterial execution.ToolMaterial
	// providerAttempts and retryableFailures shape the physical provider
	// attempts one invocation makes, so retry accounting is observable.
	providerAttempts  int
	retryableFailures int
	// ledger overrides the durable provider ledger so one store can be shared
	// across adapter instances, which is what a process restart looks like
	// from the store's side.
	ledger execution.ScriptLedger
	// modelRecorder overrides the durable invocation recorder.
	modelRecorder modelgateway.Recorder
	// submissions overrides the durable domain-submission journal, so a test
	// can inject a crash at an exact write-ahead boundary.
	submissions domaincommit.Store
	// evidence wraps the immutable evidence store, so a test can inject a
	// crash between a durable decision and the audit record it must leave.
	evidence func(execution.EvidenceRecorder) execution.EvidenceRecorder
	// modelAdapter wraps the controlled provider adapter, so a test can hold a
	// real billable provider call open across a concurrent control-plane
	// operation instead of simulating one.
	modelAdapter func(modelgateway.Adapter) modelgateway.Adapter
	// reconciler overrides the cancellation reconciler, so a test can supply
	// one that answers from the same in-flight state the production reader
	// answers from.
	reconciler interrupts.CancellationReconciler
	// leases overrides the lease revoker, so a test can prove cancellation
	// revoked the run's leases rather than assume it.
	leases interrupts.LeaseRevoker
	// budgetHeadroomMicros bounds the controller's total held exposure;
	// reconcileLimit bounds uncertain domain reconciliations before
	// escalation, and the retry base/cap shape the unsettled-commit backoff.
	budgetHeadroomMicros int64
	reconcileLimit       int
	domainRetryBase      time.Duration
	domainRetryCap       time.Duration
}

func defaultHarnessOptions() harnessOptions {
	return harnessOptions{inputTTL: time.Minute, approvalTTL: time.Minute, maximumCalls: 100, allowedTools: []string{"anvilkit.tool.context-echo", "anvilkit.tool.contract-validate", "anvilkit.tool.artifact-scan"}, allowedCapabilities: []string{"fake.execute", "contract.validate", "artifact.scan"}, domainOutcome: execution.DomainConfirmed, providerAttempts: 1, budgetHeadroomMicros: 10_000_000_000, reconcileLimit: 3, domainRetryBase: time.Millisecond, domainRetryCap: 4 * time.Millisecond}
}

func newHarness(t *testing.T, script [][]byte, mutate ...func(*harnessOptions)) *harness {
	t.Helper()
	options := defaultHarnessOptions()
	for _, apply := range mutate {
		apply(&options)
	}
	ledger := options.ledger
	if ledger == nil {
		ledger = execution.NewMemoryScriptLedger()
	}
	adapter, err := execution.NewScriptedAdapter(ledger, script...)
	if err != nil {
		t.Fatal(err)
	}
	adapter.RetryableFailures = options.retryableFailures
	clock := systemClock{}
	validatorAdapter, err := contractvalidator.New("../..")
	if err != nil {
		t.Fatal(err)
	}
	definitionSchema, err := os.ReadFile("../../contracts/agent/schemas/agent-definition.schema.json")
	if err != nil {
		t.Fatal(err)
	}
	pinnedIdentity, err := contracts.PinnedIdentity("../..")
	if err != nil {
		t.Fatal(err)
	}
	registry, err := agent.NewRegistry(context.Background(), agent.RegistryConfig{
		Source:              agent.EmbeddedCatalog{},
		Validator:           validatorAdapter,
		DefinitionSchemaURI: agent.DefinitionSchemaURI(definitionSchema),
		Approval:            agent.Approval{ProfileDigest: pinnedIdentity.ProfileDigest, LockDigest: pinnedIdentity.LockDigest, SchemaDigests: pinnedIdentity.SchemaDigests},
	})
	if err != nil {
		t.Fatal(err)
	}
	var modelRecorder modelgateway.Recorder = &execution.MemoryModelRecorder{}
	if options.modelRecorder != nil {
		modelRecorder = options.modelRecorder
	}
	var providerAdapter modelgateway.Adapter = adapter
	if options.modelAdapter != nil {
		providerAdapter = options.modelAdapter(adapter)
	}
	stack, err := execution.NewControlledModelStack(providerAdapter, clock, modelRecorder, registry)
	if err != nil {
		t.Fatal(err)
	}
	toolSchema, err := os.ReadFile("../../contracts/agent/schemas/tool-definition.schema.json")
	if err != nil {
		t.Fatal(err)
	}
	toolDigest := sha256.Sum256(toolSchema)
	toolArguments, err := execution.NewPinnedToolArgumentValidator()
	if err != nil {
		t.Fatal(err)
	}
	profile, err := execution.NewApprovedToolProfile(registry.ToolBindings(), "sha256:"+hex.EncodeToString(toolDigest[:]), registry.CatalogDigest(), toolArguments)
	if err != nil {
		t.Fatal(err)
	}
	recorder := &execution.MemoryToolRecorder{}
	guard, err := tools.NewGuard(profile, recorder, clock, toolArguments)
	if err != nil {
		t.Fatal(err)
	}
	pinnedValidator, err := execution.NewPinnedSchemaValidator("../..")
	if err != nil {
		t.Fatal(err)
	}
	agentRunner, err := runner.New(runner.Config{
		Registry:  registry,
		Compiler:  contextcompiler.New(nil),
		Selector:  stack,
		Invoker:   stack,
		Guard:     guard,
		Validator: pinnedValidator,
		Clock:     clock,
		Limits:    runner.Limits{MaximumOutputBytes: 65536, MaximumInputTokens: 100000, MaximumOutputTokens: 100000, Timeout: 5 * time.Second, MaximumAttempts: options.providerAttempts, RetryBudget: time.Minute, ContextTokens: 4000},
	})
	if err != nil {
		t.Fatal(err)
	}
	lockBytes, err := os.ReadFile("../../contracts/agent/lock/contracts.lock.json")
	if err != nil {
		t.Fatal(err)
	}
	lockDigest := sha256.Sum256(lockBytes)
	var approvedSchemas []agent.SchemaReference
	for _, definition := range registry.Definitions() {
		approvedSchemas = append(approvedSchemas, definition.InputSchema, definition.OutputSchema)
	}
	var approvedPolicyDigests []string
	seenPolicies := map[string]bool{}
	for _, definition := range registry.Definitions() {
		if !seenPolicies[definition.GuardrailPolicy.Digest] {
			seenPolicies[definition.GuardrailPolicy.Digest] = true
			approvedPolicyDigests = append(approvedPolicyDigests, definition.GuardrailPolicy.Digest)
		}
	}
	controlledRuntime, err := execution.NewControlledContractRuntime(pinnedValidator, approvedSchemas, "sha256:"+hex.EncodeToString(lockDigest[:]), registry.CatalogDigest(), approvedPolicyDigests, execution.StaticBOMAuthority{Digest: validDigest})
	if err != nil {
		t.Fatal(err)
	}
	contractValidator, err := contractclient.New(controlledRuntime, &contractclient.MemoryRecorder{}, execution.BoundedSleeper{}, clock, 3, time.Millisecond)
	if err != nil {
		t.Fatal(err)
	}

	h := &harness{t: t, adapter: adapter, recorder: recorder, registry: registry,
		artifacts:       execution.NewControlledArtifactPort(),
		commitAuthority: &execution.ControlledCommitAuthority{},
		grants: authority.Grants{
			AllowedTools:        append([]string(nil), options.allowedTools...),
			AllowedCapabilities: append([]string(nil), options.allowedCapabilities...),
			AllowedEffects:      []string{"read"},
			MaximumRisk:         "low",
			DataClasses:         []string{"public", "internal"},
		},
	}
	h.repo = interrupts.NewMemoryRepository()
	h.journal = journal.NewMemoryStore()
	h.tool = execution.NewControlledToolExecutor()
	h.domain = execution.NewControlledDomainPort(options.domainOutcome)
	h.submissions = domaincommit.NewMemoryStore()
	var submissions domaincommit.Store = h.submissions
	if options.submissions != nil {
		submissions = options.submissions
	}
	// The interrupt service is composed before the executor exists, so it
	// receives the same deferred settlement handle production uses; the real
	// executor is published into it once built.
	h.settlement = &deferredSettlement{}
	var reconciler interrupts.CancellationReconciler = clearReconciler{}
	if options.reconciler != nil {
		reconciler = options.reconciler
	}
	var leases interrupts.LeaseRevoker = noLeases{}
	if options.leases != nil {
		leases = options.leases
	}
	service, err := interrupts.NewService(h.repo, interrupts.BoundSchemaValidator{}, allowAllAuthority{}, engineSignals{h}, leases, reconciler, allowReservation{}, h.settlement, h.journal, clock, &sequenceIDs{}, interrupts.Limits{ChildDepth: 4, ChildFanout: 16})
	if err != nil {
		t.Fatal(err)
	}
	h.service = service
	for _, definition := range registry.Definitions() {
		if definition.Role == agent.RoleManager {
			h.manager = definition
		}
	}
	approvedMaterial, err := execution.NewToolMaterial(profile, toolArguments)
	if err != nil {
		t.Fatal(err)
	}
	var toolMaterial execution.ToolMaterial = approvedMaterial
	if options.toolMaterial != nil {
		toolMaterial = options.toolMaterial
	}
	h.material = toolMaterial
	// The controlled stores prove the same canonical contracts the durable
	// ones do, so a document the contract rejects fails here rather than
	// first failing against a database.
	documentGuard, err := contracts.NewGuard("../..")
	if err != nil {
		t.Fatal(err)
	}
	h.evidence = events.NewMemoryEvidence(events.WithEvidenceContracts(documentGuard.At(contracts.EvidenceIn)))
	var evidenceRecorder execution.EvidenceRecorder = h.evidence
	if options.evidence != nil {
		evidenceRecorder = options.evidence(h.evidence)
	}
	deltaBroker, err := events.NewDeltaBroker(documentGuard.At(contracts.DeltaOut))
	if err != nil {
		t.Fatal(err)
	}
	h.authoritySource = authority.NewStatic(h.currentAuthority(h.authority(options)))
	dispatchEffects := &scheduler.MemoryEffects{}
	dispatchScheduler, err := scheduler.New(execution.DispatchIDs{}, clock, scheduler.PrerequisiteFunc(func(_ context.Context, value scheduler.Create) error {
		if value.ReservationID == "" || !value.ReservationCurrent || !value.PolicyAllowed {
			return fmt.Errorf("task prerequisites are unsatisfied")
		}
		return nil
	}), time.Minute, dispatchEffects, dispatchEffects, dispatchEffects, nil)
	if err != nil {
		t.Fatal(err)
	}
	usagePipeline, err := usage.New(usage.NewMemoryStore(), execution.NewControlledUsageSink())
	if err != nil {
		t.Fatal(err)
	}
	dispatchRegister, err := recovery.NewMemoryRegister(1)
	if err != nil {
		t.Fatal(err)
	}
	fencedTools, err := execution.NewScheduledToolExecutor(dispatchScheduler, dispatchRegister, h.authoritySource, approvedMaterial, h.tool, usagePipeline, execution.NewMemoryToolReservations(), clock, "executor-test", "sha256:"+hex.EncodeToString(lockDigest[:]))
	if err != nil {
		t.Fatal(err)
	}
	h.budgetLedger = budget.NewMemoryLedger(clock.Now)
	budgetController, err := budget.New(h.budgetLedger, repoGenerations{h.repo}, nullExposure{}, clock, budget.HeadroomPolicy{MaximumReservedMicros: options.budgetHeadroomMicros, ReviewAtBasisPoints: 8000})
	if err != nil {
		t.Fatal(err)
	}
	h.budgetController = budgetController
	executor, err := execution.New(execution.Config{
		Registry:          registry,
		Runner:            agentRunner,
		Runs:              h.repo,
		InterruptWriter:   service,
		InterruptReader:   h.repo,
		InterruptExpirer:  h.repo,
		Authority:         h.authoritySource,
		Tools:             fencedTools,
		ToolMaterial:      toolMaterial,
		Artifacts:         h.artifacts,
		Domain:            h.domain,
		Submissions:       submissions,
		CommitAuthority:   h.commitAuthority,
		Contracts:         contractValidator,
		Evidence:          evidenceRecorder,
		Deltas:            deltaBroker,
		Decisions:         h.journal,
		Budget:            budgetController,
		Clock:             clock,
		InputTTL:          options.inputTTL,
		ApprovalTTL:       options.approvalTTL,
		BudgetTTL:         time.Hour,
		TurnLimit:         16,
		ValidatorIdentity: "sha256:" + hex.EncodeToString(lockDigest[:]),
		ReconcileLimit:    options.reconcileLimit,
		DomainRetryBase:   options.domainRetryBase,
		DomainRetryCap:    options.domainRetryCap,
	})
	if err != nil {
		t.Fatal(err)
	}
	h.executor = executor
	h.settlement.set(executor)
	h.ops = newCountingOps(executor)
	h.store = memory.NewStore()
	h.engine = memory.New(h.store, h.ops)
	return h
}

// repoGenerations resolves the active budget generation from the seeded run
// aggregate, mirroring the production run-store-backed generation authority.
type repoGenerations struct{ repo *interrupts.MemoryRepository }

func (g repoGenerations) Current(ctx context.Context, workspaceID, projectID, rootRunID string) (budget.Generation, error) {
	snapshot, err := g.repo.Current(ctx, runs.Scope{WorkspaceID: workspaceID, ProjectID: projectID, ActorID: testActor}, runs.ID(rootRunID))
	if err != nil {
		return 0, err
	}
	return budget.Generation(snapshot.ExecutionGeneration), nil
}

type nullExposure struct{}

func (nullExposure) ObserveExposure(context.Context, string, int64, int64, bool) error { return nil }

// harnessBudget parameterizes the pinned AgentBudget the harness seeds, so
// model-call, token, and cost exhaustion can each be exercised.
type harnessBudget struct {
	modelCalls   int64
	inputTokens  int64
	outputTokens int64
	costAmount   string
}

func defaultHarnessBudget() harnessBudget {
	return harnessBudget{modelCalls: 100, inputTokens: 1000000, outputTokens: 1000000, costAmount: "100"}
}

func (h *harness) authority(options harnessOptions) runs.Authority {
	budget := defaultHarnessBudget()
	budget.modelCalls = options.maximumCalls
	return h.authorityWithBudget(budget)
}

func (h *harness) authorityWithBudget(budget harnessBudget) runs.Authority {
	return runs.Authority{
		Definition:  h.definitionReference(),
		ContractBOM: json.RawMessage(`{"repository":"anvilkit/contracts","bomDigest":"` + validDigest + `","ociManifestDigest":"` + validDigest + `","evidenceManifestDigest":"` + validDigest + `"}`),
		Policy:      json.RawMessage(`{"policyId":"policy.run.default","version":"v1","digest":"` + validDigest + `"}`),
		Budget:      budgetDocument(budget),
	}
}

// budgetDocument renders one pinned AgentBudget document.
func budgetDocument(budget harnessBudget) json.RawMessage {
	return json.RawMessage(fmt.Sprintf(`{"kind":"AgentBudget","modelLimits":{"maximumCalls":%d,"maximumConcurrentCalls":4},"tokenLimits":{"inputTokens":%d,"outputTokens":%d,"totalTokens":2000000},"workerLimits":{"maximumAttempts":4,"maximumDurationMilliseconds":60000},"gpuLimits":{"maximumGpuMilliseconds":0},"currencyLimits":{"maximumCost":{"amount":"%s","currency":"USD"},"reservedCost":{"amount":"0","currency":"USD"}},"reservationId":"reservation.test","exceedBehavior":"refuse","policy":{"policyId":"policy.run.default","version":"v1","digest":"`+validDigest+`"}}`, budget.modelCalls, budget.inputTokens, budget.outputTokens, budget.costAmount))
}

// seedRunWithBudget seeds a run whose pinned budget the caller shapes.
func (h *harness) seedRunWithBudget(operation string, mutate ...func(*harnessBudget)) workflow.RunInput {
	h.t.Helper()
	budget := defaultHarnessBudget()
	for _, apply := range mutate {
		apply(&budget)
	}
	return h.seedSnapshot(operation, h.authorityWithBudget(budget))
}

func (h *harness) definitionReference() json.RawMessage {
	return json.RawMessage(`{"definitionId":"` + h.manager.DefinitionID + `","definitionDigest":"` + h.manager.DefinitionDigest + `"}`)
}

func (h *harness) seedRun(operation string) workflow.RunInput {
	h.t.Helper()
	return h.seedSnapshot(operation, h.authority(defaultHarnessOptions()))
}

// seedSnapshot writes the authoritative run aggregate the workflow drives.
// currentAuthority projects the seeded run material onto the single
// current-authority observation the source serves.
func (h *harness) currentAuthority(material runs.Authority) authority.Current {
	value := material
	value.WorkspaceActive, value.ActorActive, value.PermissionActive, value.PolicyActive = true, true, true, true
	value.Grants = h.grants
	value.ActorRole = h.actorRole
	return value
}

// grantRole republishes the harness's current authority with the actor
// admitted under the named role, modelling the scope's subject register
// admitting (or ceasing to admit) an operator.
func (h *harness) grantRole(role string) {
	h.t.Helper()
	material := h.snapshotAuthority()
	h.actorRole = role
	h.authoritySource.Replace(h.currentAuthority(material))
}

// snapshotAuthority is the run's pinned governance material, which current
// authority must keep agreeing with.
func (h *harness) snapshotAuthority() runs.Authority {
	h.t.Helper()
	snapshot := h.snapshot()
	return runs.Authority{Definition: snapshot.Definition, ContractBOM: snapshot.ContractBOM, Policy: snapshot.Policy, Budget: snapshot.Budget}
}

func (h *harness) seedSnapshot(operation string, material runs.Authority) workflow.RunInput {
	h.t.Helper()
	// Current authority always starts out agreeing with the run's pinned
	// material; tests move one or the other to model divergence.
	if h.authoritySource != nil {
		h.authoritySource.Replace(h.currentAuthority(material))
	}
	now := time.Now().UTC()
	snapshot := runs.Snapshot{
		Kind: "AgentRun", RunID: testRunID, RootRunID: testRunID,
		WorkspaceID: testWorkspace, ActorID: testActor,
		Domain: "platform-agent", Operation: operation,
		Target:     runs.Target{Type: "page", ID: "page.home", WorkspaceID: testWorkspace, ProjectID: testProject},
		Definition: material.Definition, ContractBOM: material.ContractBOM, Policy: material.Policy, Budget: material.Budget,
		Idempotency: runs.IdempotencyProjection{Scope: testWorkspace + ":create-run", Key: "create-1", CanonicalRequestDigest: validDigest},
		Status:      runs.Created, Version: 1, ExecutionGeneration: 1,
		CreatedAt: now, UpdatedAt: now,
	}
	if err := h.repo.Seed(testScope(), snapshot); err != nil {
		h.t.Fatal(err)
	}
	return workflow.RunInput{Key: workflow.RunKey{RunID: testRunID, Generation: 1}, Scope: workflow.Scope{WorkspaceID: testWorkspace, ProjectID: testProject, ActorID: testActor}, Traceparent: traceparent}
}

// seedRunWithCalls seeds a run whose pinned budget funds exactly the given
// number of model calls.
func (h *harness) seedRunWithCalls(operation string, maximumCalls int64) workflow.RunInput {
	h.t.Helper()
	return h.seedRunWithBudget(operation, func(budget *harnessBudget) { budget.modelCalls = maximumCalls })
}

func (h *harness) snapshot() runs.Snapshot {
	h.t.Helper()
	snapshot, err := h.repo.Get(context.Background(), testScope(), testRunID)
	if err != nil {
		h.t.Fatal(err)
	}
	return snapshot
}

// waitForState polls the authoritative aggregate until it reaches the state.
func (h *harness) waitForState(state runs.State) runs.Snapshot {
	h.t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		snapshot := h.snapshot()
		if snapshot.Status == state {
			return snapshot
		}
		time.Sleep(5 * time.Millisecond)
	}
	h.t.Fatalf("run never reached %s; current=%s", state, h.snapshot().Status)
	return runs.Snapshot{}
}

func (h *harness) openInputRequest() interrupts.InputRequest {
	h.t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		snapshot := h.snapshot()
		if snapshot.Status == runs.AwaitingInput {
			request, err := h.repo.Input(context.Background(), testScope(), testRunID, currentRequestID(h, "input"))
			if err == nil {
				return request
			}
		}
		time.Sleep(5 * time.Millisecond)
	}
	h.t.Fatal("input request never opened")
	return interrupts.InputRequest{}
}

func (h *harness) openApprovalRequest() interrupts.ApprovalRequest {
	h.t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		snapshot := h.snapshot()
		if snapshot.Status == runs.AwaitingApproval {
			request, err := h.repo.Approval(context.Background(), testScope(), testRunID, currentRequestID(h, "approval"))
			if err == nil {
				return request
			}
		}
		time.Sleep(5 * time.Millisecond)
	}
	h.t.Fatal("approval request never opened")
	return interrupts.ApprovalRequest{}
}

// currentRequestID finds the newest request identity of a kind through the
// repository's pending records.
func currentRequestID(h *harness, kind string) interrupts.RequestID {
	h.t.Helper()
	for index := 64; index >= 1; index-- {
		id := interrupts.RequestID(fmt.Sprintf("request.%04d", index))
		if kind == "input" {
			if _, err := h.repo.Input(context.Background(), testScope(), testRunID, id); err == nil {
				return id
			}
		} else {
			if _, err := h.repo.Approval(context.Background(), testScope(), testRunID, id); err == nil {
				return id
			}
		}
	}
	return interrupts.RequestID("request.0001")
}

func (h *harness) respondInput(request interrupts.InputRequest, key string) (interrupts.OperationResult, error) {
	h.t.Helper()
	snapshot := h.snapshot()
	return h.service.RespondInput(context.Background(), interrupts.Write{Scope: testScope(), RunID: testRunID, ExpectedVersion: snapshot.Version, IdempotencyKey: key, Traceparent: traceparent}, interrupts.InputResponseCommand{RequestID: request.ID, RequestVersion: request.Version, Value: json.RawMessage(`{"answer":"the home page"}`)})
}

func (h *harness) decideApproval(request interrupts.ApprovalRequest, decision interrupts.DecisionKind, key string) (interrupts.OperationResult, error) {
	h.t.Helper()
	snapshot := h.snapshot()
	return h.service.DecideApproval(context.Background(), interrupts.Write{Scope: testScope(), RunID: testRunID, ExpectedVersion: snapshot.Version, IdempotencyKey: key, Traceparent: traceparent}, interrupts.ApprovalDecisionCommand{RequestID: request.ID, RequestVersion: request.Version, Decision: decision, ActionDigest: request.ActionDigest, Comment: "review feedback"})
}

func finalPlan() []byte {
	return execution.PlanStep("agent.final", map[string]json.RawMessage{"candidate": execution.ControlledCandidate(), "summary": json.RawMessage(`"controlled candidate"`)})
}

func inputPlan() []byte {
	return execution.PlanStep("agent.need-input", map[string]json.RawMessage{"question": json.RawMessage(`"which page should change?"`)})
}

func toolPlan() []byte {
	return execution.PlanStep("anvilkit.tool.context-echo", map[string]json.RawMessage{"query": json.RawMessage(`"page context"`)})
}

func delegatePlan() []byte {
	return execution.PlanStep("agent.delegate", map[string]json.RawMessage{"delegate": json.RawMessage(`"` + agent.SpecialistDefinitionID + `"`), "input": execution.ControlledCandidate()})
}

func TestRunCompletesWithoutGovernedEffect(t *testing.T) {
	h := newHarness(t, [][]byte{finalPlan()})
	input := h.seedRun("artifact-validation")
	outcome, err := h.engine.ExecuteRun(context.Background(), input)
	if err != nil {
		t.Fatal(err)
	}
	if outcome.Terminal != workflow.TerminalCompleted {
		t.Fatalf("outcome = %+v", outcome)
	}
	if snapshot := h.snapshot(); snapshot.Status != runs.Completed {
		t.Fatalf("run state = %s", snapshot.Status)
	}
	facts, err := h.journal.List(context.Background())
	if err != nil || len(facts) == 0 {
		t.Fatalf("turn decisions must be durably recorded: %v", err)
	}
}

func TestRunExecutesGuardedToolAndDelegationBeforeCompleting(t *testing.T) {
	h := newHarness(t, [][]byte{
		toolPlan(),     // manager turn 0: guarded tool call
		delegatePlan(), // manager turn 1: delegate to the specialist
		finalPlan(),    // specialist turn: candidate
		finalPlan(),    // manager turn 2: finalize
	})
	input := h.seedRun("artifact-validation")
	outcome, err := h.engine.ExecuteRun(context.Background(), input)
	if err != nil {
		t.Fatal(err)
	}
	if outcome.Terminal != workflow.TerminalCompleted {
		t.Fatalf("outcome = %+v", outcome)
	}
	if h.tool.Executions() != 1 {
		t.Fatalf("tool executions = %d, want exactly one", h.tool.Executions())
	}
	if h.ops.callsFor(":action-0000") != 1 {
		t.Fatal("the guarded tool action must run exactly once")
	}
	// Delegation is a durable boundary per Specialist turn, not one opaque
	// action step.
	if h.ops.callsFor(":delegate-open-0001") != 1 || h.ops.callsFor(":delegate-turn-0001-0000") != 1 {
		t.Fatalf("delegation must open once and run one specialist turn as its own durable step")
	}
	allowed := 0
	for _, decision := range h.recorder.Decisions {
		if decision.Decision.Allowed {
			allowed++
		}
	}
	if allowed != 1 {
		t.Fatalf("guard must record exactly one allowed decision, got %d", allowed)
	}
}

func TestGuardDenialIsDurableAndNonFatal(t *testing.T) {
	h := newHarness(t, [][]byte{toolPlan(), finalPlan()}, func(options *harnessOptions) {
		options.allowedTools = []string{"anvilkit.tool.contract-validate"}
	})
	input := h.seedRun("artifact-validation")
	outcome, err := h.engine.ExecuteRun(context.Background(), input)
	if err != nil {
		t.Fatal(err)
	}
	if outcome.Terminal != workflow.TerminalCompleted {
		t.Fatalf("outcome = %+v", outcome)
	}
	if h.tool.Executions() != 0 {
		t.Fatal("denied tool must never execute")
	}
	if len(h.recorder.Decisions) != 1 || h.recorder.Decisions[0].Decision.Allowed {
		t.Fatalf("denial must be recorded: %+v", h.recorder.Decisions)
	}
}

func TestRunWaitsForInputAndResumesAfterResponse(t *testing.T) {
	h := newHarness(t, [][]byte{inputPlan(), finalPlan()})
	input := h.seedRun("artifact-validation")
	if err := h.engine.StartRun(context.Background(), input); err != nil {
		t.Fatal(err)
	}
	request := h.openInputRequest()
	if _, err := h.respondInput(request, "respond-1"); err != nil {
		t.Fatal(err)
	}
	outcome, err := h.engine.ExecuteRun(context.Background(), input)
	if err != nil || outcome.Terminal != workflow.TerminalCompleted {
		t.Fatalf("outcome = %+v err = %v", outcome, err)
	}
	if snapshot := h.snapshot(); snapshot.Status != runs.Completed {
		t.Fatalf("run state = %s", snapshot.Status)
	}
}

func TestDuplicateInputDeliveryIsAcceptedExactlyOnce(t *testing.T) {
	h := newHarness(t, [][]byte{inputPlan(), finalPlan()})
	input := h.seedRun("artifact-validation")
	if err := h.engine.StartRun(context.Background(), input); err != nil {
		t.Fatal(err)
	}
	request := h.openInputRequest()
	recorded := h.snapshot().Version
	if _, err := h.respondInput(request, "respond-dup"); err != nil {
		t.Fatal(err)
	}
	second, err := h.service.RespondInput(context.Background(), interrupts.Write{Scope: testScope(), RunID: testRunID, ExpectedVersion: recorded, IdempotencyKey: "respond-dup", Traceparent: traceparent}, interrupts.InputResponseCommand{RequestID: request.ID, RequestVersion: request.Version, Value: json.RawMessage(`{"answer":"the home page"}`)})
	if err != nil {
		t.Fatalf("idempotent duplicate must replay: %v", err)
	}
	if !second.Replayed {
		t.Fatal("duplicate delivery must be marked replayed")
	}
	outcome, err := h.engine.ExecuteRun(context.Background(), input)
	if err != nil || outcome.Terminal != workflow.TerminalCompleted {
		t.Fatalf("outcome = %+v err = %v", outcome, err)
	}
	// A different-content duplicate under the same key fails closed.
	if _, err := h.service.RespondInput(context.Background(), interrupts.Write{Scope: testScope(), RunID: testRunID, ExpectedVersion: recorded, IdempotencyKey: "respond-dup", Traceparent: traceparent}, interrupts.InputResponseCommand{RequestID: request.ID, RequestVersion: request.Version, Value: json.RawMessage(`{"answer":"another answer"}`)}); err == nil {
		t.Fatal("different bytes under a reused idempotency key must fail")
	}
}

func TestApprovalApprovePathCommitsGovernedEffect(t *testing.T) {
	h := newHarness(t, [][]byte{finalPlan()})
	input := h.seedRun("page-change")
	if err := h.engine.StartRun(context.Background(), input); err != nil {
		t.Fatal(err)
	}
	request := h.openApprovalRequest()
	if _, err := h.decideApproval(request, interrupts.DecisionApprove, "approve-1"); err != nil {
		t.Fatal(err)
	}
	outcome, err := h.engine.ExecuteRun(context.Background(), input)
	if err != nil || outcome.Terminal != workflow.TerminalCompleted {
		t.Fatalf("outcome = %+v err = %v", outcome, err)
	}
	if snapshot := h.snapshot(); snapshot.Status != runs.Completed {
		t.Fatalf("run state = %s", snapshot.Status)
	}
	if h.domain.Commits() != 1 {
		t.Fatalf("domain commits = %d, want exactly one", h.domain.Commits())
	}
}

func TestApprovalRejectionForcesRevisionBeforeCompletion(t *testing.T) {
	h := newHarness(t, [][]byte{finalPlan(), finalPlan()})
	input := h.seedRun("page-change")
	if err := h.engine.StartRun(context.Background(), input); err != nil {
		t.Fatal(err)
	}
	first := h.openApprovalRequest()
	if _, err := h.decideApproval(first, interrupts.DecisionReject, "reject-1"); err != nil {
		t.Fatal(err)
	}
	second := h.openApprovalRequest()
	if second.ID == first.ID {
		t.Fatal("revision must open a new approval request identity")
	}
	if _, err := h.decideApproval(second, interrupts.DecisionApprove, "approve-2"); err != nil {
		t.Fatal(err)
	}
	outcome, err := h.engine.ExecuteRun(context.Background(), input)
	if err != nil || outcome.Terminal != workflow.TerminalCompleted {
		t.Fatalf("outcome = %+v err = %v", outcome, err)
	}
	if h.ops.callsFor(":revise-0000") != 1 {
		t.Fatal("rejection must drive exactly one revision")
	}
}

func TestInputExpiryFailsRunAndRejectsLateResponse(t *testing.T) {
	h := newHarness(t, [][]byte{inputPlan(), finalPlan()}, func(options *harnessOptions) {
		options.inputTTL = 250 * time.Millisecond
	})
	input := h.seedRun("artifact-validation")
	if err := h.engine.StartRun(context.Background(), input); err != nil {
		t.Fatal(err)
	}
	request := h.openInputRequest()
	outcome, err := h.engine.ExecuteRun(context.Background(), input)
	if err != nil {
		t.Fatal(err)
	}
	if outcome.Terminal != workflow.TerminalFailed || outcome.Problem == nil || outcome.Problem.Code != string(problem.CodeInputRequestExpired) {
		t.Fatalf("outcome = %+v", outcome)
	}
	snapshot := h.snapshot()
	if snapshot.Status != runs.Failed || snapshot.Problem == nil || snapshot.Problem.Code != string(problem.CodeInputRequestExpired) {
		t.Fatalf("run = %s problem = %+v", snapshot.Status, snapshot.Problem)
	}
	// A late response can never revive the expired request.
	if _, err := h.respondInput(request, "late-1"); err == nil {
		t.Fatal("late response must fail closed")
	}
	if h.snapshot().Status != runs.Failed {
		t.Fatal("late response must not change the failed run")
	}
}

func TestApprovalExpiryFailsRun(t *testing.T) {
	h := newHarness(t, [][]byte{finalPlan()}, func(options *harnessOptions) {
		options.approvalTTL = 250 * time.Millisecond
	})
	input := h.seedRun("page-change")
	if err := h.engine.StartRun(context.Background(), input); err != nil {
		t.Fatal(err)
	}
	outcome, err := h.engine.ExecuteRun(context.Background(), input)
	if err != nil {
		t.Fatal(err)
	}
	if outcome.Terminal != workflow.TerminalFailed || outcome.Problem == nil || outcome.Problem.Code != string(problem.CodeApprovalRequestExpired) {
		t.Fatalf("outcome = %+v", outcome)
	}
	if snapshot := h.snapshot(); snapshot.Status != runs.Failed {
		t.Fatalf("run state = %s", snapshot.Status)
	}
}

func TestCancellationWhileWaitingReconcilesToCancelled(t *testing.T) {
	h := newHarness(t, [][]byte{inputPlan(), finalPlan()})
	input := h.seedRun("artifact-validation")
	if err := h.engine.StartRun(context.Background(), input); err != nil {
		t.Fatal(err)
	}
	h.openInputRequest()
	snapshot := h.snapshot()
	if _, err := h.service.Cancel(context.Background(), interrupts.Write{Scope: testScope(), RunID: testRunID, ExpectedVersion: snapshot.Version, IdempotencyKey: "cancel-1", Traceparent: traceparent}); err != nil {
		t.Fatal(err)
	}
	if final := h.waitForState(runs.Cancelled); final.Status != runs.Cancelled {
		t.Fatalf("run state = %s", final.Status)
	}
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if outcome, done := h.engine.Outcome(input.Key); done {
			if outcome.Terminal != workflow.TerminalCancelled {
				t.Fatalf("engine outcome = %+v", outcome)
			}
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatal("cancelled workflow never finished")
}

func TestExplicitRetryRunsFreshGeneration(t *testing.T) {
	h := newHarness(t, [][]byte{inputPlan(), inputPlan(), finalPlan()}, func(options *harnessOptions) {
		options.inputTTL = 250 * time.Millisecond
	})
	input := h.seedRun("artifact-validation")
	outcome, err := h.engine.ExecuteRun(context.Background(), input)
	if err != nil || outcome.Terminal != workflow.TerminalFailed {
		t.Fatalf("precondition failed run: %+v %v", outcome, err)
	}
	snapshot := h.snapshot()
	if _, err := h.service.Retry(context.Background(), interrupts.Write{Scope: testScope(), RunID: testRunID, ExpectedVersion: snapshot.Version, IdempotencyKey: "retry-1", Traceparent: traceparent}); err != nil {
		t.Fatal(err)
	}
	retried := h.snapshot()
	if retried.ExecutionGeneration != 2 || retried.Status != runs.Preparing {
		t.Fatalf("retry snapshot = generation %d state %s", retried.ExecutionGeneration, retried.Status)
	}
	secondKey := workflow.RunKey{RunID: testRunID, Generation: 2}
	request := h.openInputRequest()
	current := h.snapshot()
	if _, err := h.service.RespondInput(context.Background(), interrupts.Write{Scope: testScope(), RunID: testRunID, ExpectedVersion: current.Version, IdempotencyKey: "respond-g2", Traceparent: traceparent}, interrupts.InputResponseCommand{RequestID: request.ID, RequestVersion: request.Version, Value: json.RawMessage(`{"answer":"retry answer"}`)}); err != nil {
		t.Fatal(err)
	}
	secondOutcome, err := h.engine.ExecuteRun(context.Background(), workflow.RunInput{Key: secondKey, Scope: input.Scope, Traceparent: traceparent})
	if err != nil || secondOutcome.Terminal != workflow.TerminalCompleted {
		t.Fatalf("generation 2 outcome = %+v err = %v", secondOutcome, err)
	}
	if final := h.snapshot(); final.Status != runs.Completed || final.ExecutionGeneration != 2 {
		t.Fatalf("final = %s generation %d", final.Status, final.ExecutionGeneration)
	}
}

func TestStaleGenerationWorkflowExitsSuperseded(t *testing.T) {
	h := newHarness(t, [][]byte{finalPlan()})
	input := h.seedRun("artifact-validation")
	stale := workflow.RunInput{Key: workflow.RunKey{RunID: testRunID, Generation: 7}, Scope: input.Scope, Traceparent: traceparent}
	outcome, err := h.engine.ExecuteRun(context.Background(), stale)
	if err != nil {
		t.Fatal(err)
	}
	if outcome.Terminal != workflow.TerminalSuperseded {
		t.Fatalf("outcome = %+v", outcome)
	}
	if snapshot := h.snapshot(); snapshot.Status != runs.Created {
		t.Fatalf("stale generation must not write state, run = %s", snapshot.Status)
	}
}

func TestBudgetExhaustionRefusesDeterministically(t *testing.T) {
	h := newHarness(t, [][]byte{
		execution.PlanStep("agent.continue", map[string]json.RawMessage{"note": json.RawMessage(`"planning"`)}),
		finalPlan(),
	})
	input := h.seedRunWithCalls("artifact-validation", 1)
	outcome, err := h.engine.ExecuteRun(context.Background(), input)
	if err != nil {
		t.Fatal(err)
	}
	if outcome.Terminal != workflow.TerminalRefused || outcome.Problem == nil || outcome.Problem.Code != string(problem.CodeBudgetDenied) {
		t.Fatalf("outcome = %+v", outcome)
	}
	if snapshot := h.snapshot(); snapshot.Status != runs.Refused {
		t.Fatalf("run state = %s", snapshot.Status)
	}
}

func TestCrashDuringInputWaitRecoversWithoutRepeatingEffects(t *testing.T) {
	h := newHarness(t, [][]byte{inputPlan(), finalPlan()})
	input := h.seedRun("artifact-validation")
	if err := h.engine.StartRun(context.Background(), input); err != nil {
		t.Fatal(err)
	}
	request := h.openInputRequest()
	if err := h.engine.Stop(context.Background()); err != nil {
		t.Fatal(err)
	}
	// Restart: a new engine over the same durable store recovers the
	// workflow, replaying recorded steps instead of re-executing them.
	h.engine = memory.New(h.store, h.ops)
	if err := h.engine.StartRun(context.Background(), input); err != nil {
		t.Fatal(err)
	}
	if _, err := h.respondInput(request, "respond-after-restart"); err != nil {
		t.Fatal(err)
	}
	outcome, err := h.engine.ExecuteRun(context.Background(), input)
	if err != nil || outcome.Terminal != workflow.TerminalCompleted {
		t.Fatalf("outcome = %+v err = %v", outcome, err)
	}
	if got := h.ops.callsFor(":prepare"); got != 1 {
		t.Fatalf("prepare executed %d times across restart, want 1", got)
	}
	if got := h.ops.callsFor(":turn-0000"); got != 1 {
		t.Fatalf("turn 0 executed %d times across restart, want 1", got)
	}
	if got := h.ops.callsFor(":open-input-0000"); got != 1 {
		t.Fatalf("input opened %d times across restart, want 1", got)
	}
}

func TestReplayAfterCompletionReturnsRecordedOutcomeWithoutReexecution(t *testing.T) {
	h := newHarness(t, [][]byte{finalPlan()})
	input := h.seedRun("artifact-validation")
	first, err := h.engine.ExecuteRun(context.Background(), input)
	if err != nil || first.Terminal != workflow.TerminalCompleted {
		t.Fatalf("outcome = %+v err = %v", first, err)
	}
	before := h.ops.callsFor(":prepare") + h.ops.callsFor(":turn-0000") + h.ops.callsFor(":finalize-0000")
	second, err := h.engine.ExecuteRun(context.Background(), input)
	if err != nil {
		t.Fatal(err)
	}
	if second.Terminal != first.Terminal {
		t.Fatalf("replayed outcome = %+v", second)
	}
	after := h.ops.callsFor(":prepare") + h.ops.callsFor(":turn-0000") + h.ops.callsFor(":finalize-0000")
	if before != after {
		t.Fatalf("replay re-executed operations: %d -> %d", before, after)
	}
}
