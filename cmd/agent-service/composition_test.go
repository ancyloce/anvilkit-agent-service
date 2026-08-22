package main

import (
	"context"
	"io"
	"log/slog"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/ancyloce/anvilkit-agent-service/internal/agent"
	"github.com/ancyloce/anvilkit-agent-service/internal/applyauth"
	"github.com/ancyloce/anvilkit-agent-service/internal/artifacts"
	"github.com/ancyloce/anvilkit-agent-service/internal/authority"
	"github.com/ancyloce/anvilkit-agent-service/internal/config"
	"github.com/ancyloce/anvilkit-agent-service/internal/execution"
	"github.com/ancyloce/anvilkit-agent-service/internal/journal"
	"github.com/ancyloce/anvilkit-agent-service/internal/persistence"
	"github.com/ancyloce/anvilkit-agent-service/internal/recovery"
	"github.com/ancyloce/anvilkit-agent-service/internal/runapp"
	"github.com/ancyloce/anvilkit-agent-service/internal/scheduler"
	"github.com/ancyloce/anvilkit-agent-service/internal/securityaudit"
	securityauditpg "github.com/ancyloce/anvilkit-agent-service/internal/securityaudit/postgres"
	"github.com/ancyloce/anvilkit-agent-service/internal/tools"
	"github.com/ancyloce/anvilkit-agent-service/internal/usage"
)

// The production composition must never construct the agent pipeline over a
// controlled fake, and no implementation is ever selected implicitly.

func TestSelectImplementationsFailClosedWithoutExplicitSelection(t *testing.T) {
	cfg := config.Config{}
	if _, err := selectModelImplementation(cfg, persistence.Pools{}, runapp.SystemClock{}, missingModelPolicies{}); err == nil {
		t.Fatal("unset model implementation must fail closed")
	}
	if _, _, err := selectToolImplementation(cfg); err == nil {
		t.Fatal("unset tool implementation must fail closed")
	}
	if _, err := selectDomainImplementation(cfg, persistence.Pools{}, nil, runapp.SystemClock{}); err == nil {
		t.Fatal("unset domain implementation must fail closed")
	}
	cfg.ModelImplementation = "provider-x"
	if _, err := selectModelImplementation(cfg, persistence.Pools{}, runapp.SystemClock{}, missingModelPolicies{}); err == nil {
		t.Fatal("unknown model implementation must fail closed")
	}
	if _, err := selectContractRuntime(config.Config{}, nil, nil, "", persistence.Pools{}, runapp.SystemClock{}, nil); err == nil {
		t.Fatal("unset contract runtime implementation must fail closed")
	}
	if _, err := selectWorkerImplementation(context.Background(), config.Config{}, persistence.Pools{}, runapp.SystemClock{}, nil, nil, nil, ""); err == nil {
		t.Fatal("unset worker implementation must fail closed")
	}
	cfg.WorkerImplementation = "external"
	if _, err := selectWorkerImplementation(context.Background(), cfg, persistence.Pools{}, runapp.SystemClock{}, nil, nil, nil, ""); err == nil {
		t.Fatal("an unavailable worker implementation must fail closed")
	}
}

// The controlled model stack keeps its provider idempotency, settled
// outcomes, script position, and usage evidence in a durable process-external
// ledger. Without the database that holds it, the composition must refuse to
// build a model stack at all rather than fall back to process memory.
func TestControlledModelStackRefusesToBuildWithoutItsDurableLedger(t *testing.T) {
	cfg := config.Config{ModelImplementation: execution.ControlledImplementation, ExecutorID: "executor-1"}
	_, err := selectModelImplementation(cfg, persistence.Pools{}, runapp.SystemClock{}, missingModelPolicies{})
	if err == nil {
		t.Fatal("the controlled model stack was built without its durable provider ledger")
	}
	if !strings.Contains(err.Error(), "durable provider ledger") {
		t.Fatalf("error = %v, want it to name the missing durable ledger", err)
	}
}

func TestControlledImplementationsAreExplicitlySelectable(t *testing.T) {
	cfg := config.Config{ToolImplementation: execution.ControlledImplementation, DomainImplementation: execution.ControlledImplementation}
	if _, _, err := selectToolImplementation(cfg); err != nil {
		t.Fatal(err)
	}
	// The controlled domain owner is strict: without verification keys or the
	// durable redemption record it refuses to build at all.
	if _, err := selectDomainImplementation(cfg, persistence.Pools{}, nil, runapp.SystemClock{}); err == nil || !strings.Contains(err.Error(), "signing key") {
		t.Fatalf("controlled domain owner without verification keys must fail closed, got %v", err)
	}
	ring, err := applyauth.NewSeededKeyRing([]byte("composition-test-signing-material"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := selectDomainImplementation(cfg, persistence.Pools{}, ring, runapp.SystemClock{}); err == nil || !strings.Contains(err.Error(), "control database") {
		t.Fatalf("controlled domain owner without its durable redemption record must fail closed, got %v", err)
	}
}

// Artifacts are a first-party capability with no memory-only mode:
// composition must refuse to build the artifact module without the durable
// artifacts database and the grant-signing secret.
func TestArtifactModuleFailsClosedWithoutDurableStoreOrSigningSecret(t *testing.T) {
	_, _, err := buildArtifactPort(config.Config{}, persistence.Pools{}, authority.NewStatic(authority.Current{}), stubProtectedAudit{}, runapp.SystemClock{})
	if err == nil || !strings.Contains(err.Error(), "artifacts database") {
		t.Fatalf("missing artifacts database must fail closed, got %v", err)
	}
}

// Apply-authorization issuance is a first-party capability with no unsigned
// or memory-only mode: composition must refuse to build a commit authority
// without the operator signing secret and the durable control database that
// holds its audit and issuance records.
func TestCommitAuthorityFailsClosedWithoutSigningKeyOrDurableStores(t *testing.T) {
	_, err := buildCommitAuthority(config.Config{}, persistence.Pools{}, nil, nil, runapp.SystemClock{}, nil, nil, nil, nil, nil)
	if err == nil || !strings.Contains(err.Error(), "ANVILKIT_SIGNING_KEY") {
		t.Fatalf("missing signing key must fail closed naming the secret, got %v", err)
	}
	t.Setenv("ANVILKIT_SIGNING_KEY", "composition-test-signing-material")
	cfg, err := config.Load()
	if err != nil {
		t.Fatal(err)
	}
	ring, err := applyauth.NewSeededKeyRing([]byte("composition-test-signing-material"))
	if err != nil {
		t.Fatal(err)
	}
	_, err = buildCommitAuthority(cfg, persistence.Pools{}, nil, nil, runapp.SystemClock{}, nil, nil, nil, nil, ring)
	if err == nil || !strings.Contains(err.Error(), "control database") {
		t.Fatalf("missing control database must fail closed, got %v", err)
	}
}

// missingModelPolicies carries no approved model policy, which is what an
// unattested or unresolvable policy reference looks like to selection.
type missingModelPolicies struct{}

func (missingModelPolicies) ModelPolicy(string, string) (agent.ModelPolicy, bool) {
	return agent.ModelPolicy{}, false
}

func TestProductionConfigurationRejectsControlledImplementations(t *testing.T) {
	base := config.Config{
		ServiceName:        "agent-service",
		Environment:        config.EnvironmentProduction,
		HTTPAddress:        ":8080",
		MigrationMode:      "validate",
		Limits:             config.Limits{Tools: 5},
		ControlPoolSize:    1,
		WorkflowPoolSize:   1,
		EventsPoolSize:     1,
		ArtifactsPoolSize:  1,
		EvaluationPoolSize: 1,
	}
	base.ModelImplementation = execution.ControlledImplementation
	err := base.Validate()
	if err == nil || !strings.Contains(err.Error(), "forbidden in production") {
		t.Fatalf("production must reject controlled model implementation, got %v", err)
	}
	base.ModelImplementation = ""
	base.ToolImplementation = "fake-tools"
	if err := base.Validate(); err == nil || !strings.Contains(err.Error(), "forbidden in production") {
		t.Fatalf("production must reject fake tool implementation, got %v", err)
	}
	base.ToolImplementation = ""
	base.DomainImplementation = "mock-domain"
	if err := base.Validate(); err == nil || !strings.Contains(err.Error(), "forbidden in production") {
		t.Fatalf("production must reject mock domain implementation, got %v", err)
	}
	base.DomainImplementation = ""
	base.ContractRuntimeImplementation = execution.ControlledImplementation
	if err := base.Validate(); err == nil || !strings.Contains(err.Error(), "forbidden in production") {
		t.Fatalf("production must reject the controlled contract runtime, got %v", err)
	}
	base.ContractRuntimeImplementation = ""
	base.WorkerImplementation = execution.ControlledImplementation
	if err := base.Validate(); err == nil || !strings.Contains(err.Error(), "forbidden in production") {
		t.Fatalf("production must reject the controlled worker fabric, got %v", err)
	}
}

func TestInterruptDeadlinesMustBePositive(t *testing.T) {
	cfg := config.Config{
		ServiceName:   "agent-service",
		Environment:   config.EnvironmentDevelopment,
		HTTPAddress:   ":8080",
		MigrationMode: "validate",
		Limits:        config.Limits{Tools: 5},
	}
	if err := cfg.Validate(); err == nil {
		t.Fatal("zero interrupt deadlines must be rejected")
	}
	cfg.ControlPoolSize = 1
	cfg.WorkflowPoolSize = 1
	cfg.EventsPoolSize = 1
	cfg.ArtifactsPoolSize = 1
	cfg.EvaluationPoolSize = 1
	cfg.InputRequestTTL = time.Minute
	cfg.ApprovalRequestTTL = time.Minute
	cfg.ApplyAuthorizationTTL = time.Minute
	cfg.ArtifactPendingTTL = time.Hour
	cfg.ArtifactGrantTTL = time.Minute
	cfg.ContractRuntimeAttempts = 3
	cfg.ContractRuntimeBackoff = time.Second
	cfg.ControlledModelScript = []string{"final"}
	cfg.EventRetention = time.Hour
	cfg.SSEWriteTimeout = 10 * time.Second
	cfg.RunTimeout = time.Minute
	cfg.DwellDeadline = time.Minute
	cfg.AuthRevalidation = time.Second
	cfg.BudgetUnits = 1
	cfg.BudgetHeadroomMicros = 1
	cfg.BudgetReviewBasisPoints = 1
	cfg.BudgetMaxReservedMicros = 1
	cfg.DomainReconcileLimit = 1
	cfg.DomainRetryBase = time.Second
	cfg.DomainRetryCap = time.Second
	cfg.TurnLimit = 1
	cfg.CircuitFailures = 1
	if err := cfg.Validate(); err != nil {
		t.Fatalf("bounded development configuration must validate: %v", err)
	}
}

// stubProtectedAudit stands in for the protected audit where a composition
// test only proves that an earlier dependency fails closed first.
type stubProtectedAudit struct{}

func (stubProtectedAudit) PrivilegedMutation(context.Context, securityaudit.Record, securityaudit.Mutation) error {
	return nil
}

// Production refuses an implementation that has not declared itself fit for
// production. The previous guarantee was a substring test on the configured
// implementation name, which held only for as long as every controlled
// implementation happened to be named with one of the expected words. This one
// holds because the implementation has to say what it is, and saying nothing
// is a refusal.
func TestProductionRefusesUndeclaredAndControlledImplementations(t *testing.T) {
	controlled := execution.NewControlledToolExecutor()
	if got := execution.EligibilityOf(controlled); got != execution.ControlledOnly {
		t.Fatalf("the controlled tool executor declares %v, want a controlled-only declaration", got)
	}
	if err := requireProductionEligible(config.EnvironmentProduction, "ANVILKIT_TOOL_IMPLEMENTATION", controlled); err == nil {
		t.Fatal("production composed a controlled implementation")
	}
	// An implementation that declares nothing at all is refused too: the
	// default is a refusal, so a port or an implementation added later fails
	// closed without anyone remembering to list it.
	if err := requireProductionEligible(config.EnvironmentProduction, "ANVILKIT_TOOL_IMPLEMENTATION", silentImplementation{}); err == nil {
		t.Fatal("production composed an implementation that declared nothing about itself")
	}
	if err := requireProductionEligible(config.EnvironmentProduction, "ANVILKIT_TOOL_IMPLEMENTATION", nil); err == nil {
		t.Fatal("production composed a missing implementation")
	}
	// Only a positive declaration passes.
	if err := requireProductionEligible(config.EnvironmentProduction, "ANVILKIT_TOOL_IMPLEMENTATION", eligibleImplementation{}); err != nil {
		t.Fatalf("production refused an implementation that declared itself fit: %v", err)
	}
	// Outside production the declaration decides nothing: controlled
	// implementations are exactly what those environments are for.
	for _, environment := range []config.Environment{config.EnvironmentDevelopment, config.EnvironmentTest, config.EnvironmentStaging} {
		if err := requireProductionEligible(environment, "ANVILKIT_TOOL_IMPLEMENTATION", controlled); err != nil {
			t.Fatalf("%s refused a controlled implementation: %v", environment, err)
		}
	}
}

// A production-shaped wrapper around a controlled worker is still a controlled
// worker. The fenced dispatch path is real production machinery — durable
// tasks, leases, fences, usage — so its own name and shape prove nothing about
// whether anything real executes at the end of it.
func TestFencedDispatchInheritsTheEligibilityOfTheWorkerItDispatchesTo(t *testing.T) {
	fenced, err := execution.NewScheduledToolExecutor(
		stubTaskScheduler{}, stubRecoveryEpochs{}, authority.NewStatic(authority.Current{}), stubToolMaterial{},
		execution.NewControlledToolExecutor(), stubUsageAcceptor{}, execution.NewMemoryToolReservations(),
		runapp.SystemClock{}, "executor-01", "sha256:"+strings.Repeat("a", 64))
	if err != nil {
		t.Fatal(err)
	}
	if got := execution.EligibilityOf(fenced); got != execution.ControlledOnly {
		t.Fatalf("fenced dispatch over a controlled worker declares %v, want the worker's own declaration", got)
	}
	if err := requireProductionEligible(config.EnvironmentProduction, "ANVILKIT_WORKER_IMPLEMENTATION", fenced); err == nil {
		t.Fatal("production composed fenced dispatch over a controlled worker")
	}
}

type silentImplementation struct{}

type eligibleImplementation struct{}

func (eligibleImplementation) Eligibility() execution.Eligibility {
	return execution.ProductionEligible
}

type stubTaskScheduler struct{}

func (stubTaskScheduler) Create(context.Context, scheduler.Create) (scheduler.Task, error) {
	return scheduler.Task{}, nil
}

func (stubTaskScheduler) Lease(context.Context, scheduler.Scope, scheduler.TaskID, string) (scheduler.Lease, error) {
	return scheduler.Lease{}, nil
}

func (stubTaskScheduler) Heartbeat(context.Context, scheduler.Scope, scheduler.Lease, time.Time) (scheduler.Lease, error) {
	return scheduler.Lease{}, nil
}

func (stubTaskScheduler) ReclaimExpired(context.Context, scheduler.Scope, scheduler.TaskID) (bool, error) {
	return false, nil
}

func (stubTaskScheduler) AcceptResult(context.Context, scheduler.Scope, scheduler.Result, []byte) (scheduler.Acceptance, error) {
	return scheduler.Acceptance{}, nil
}

func (stubTaskScheduler) AcceptedOutput(context.Context, scheduler.Scope, scheduler.TaskID) ([]byte, scheduler.Result, error) {
	return nil, scheduler.Result{}, nil
}

func (stubTaskScheduler) Get(context.Context, scheduler.Scope, scheduler.TaskID) (scheduler.Task, error) {
	return scheduler.Task{}, nil
}

type stubRecoveryEpochs struct{}

func (stubRecoveryEpochs) Current(context.Context) (recovery.Epoch, error) { return 1, nil }

type stubToolMaterial struct{}

func (stubToolMaterial) ComponentDigest(string) (string, bool) { return "", false }

func (stubToolMaterial) ToolDefinition(string) (tools.Definition, bool) {
	return tools.Definition{}, false
}

type stubUsageAcceptor struct{}

func (stubUsageAcceptor) Accept(context.Context, usage.Observation) (bool, error) { return true, nil }

// The protected audit's schema is established by an administrative connection
// that is closed again, and the running service then connects as a role that
// holds append and read and nothing else. Schema management and runtime
// appending are different privileges, and a process that can rewrite the
// account of its own security decisions is not one whose account means
// anything.
//
// This drives the composition root's own builder against a real database, so
// what is proved is the wiring the service actually starts with.
func TestTheProtectedAuditRunsOnAnAppendOnlyRole(t *testing.T) {
	base := os.Getenv("POSTGRES_TEST_URL")
	if base == "" {
		t.Skip("POSTGRES_TEST_URL is not set")
	}
	ctx := context.Background()
	databaseURL := isolatedSliceDatabase(t, ctx, base)
	now := time.Unix(1_700_000_000, 0).UTC()
	clock, err := securityaudit.NewAuthoritativeClock(auditCompositionTime{now}, auditCompositionLocal{now}, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	cfg := config.Config{Environment: config.EnvironmentProduction}
	cfg.ProtectedAudit.URL = databaseURL
	receipts := journal.NewMemoryStore()
	service, closeAudit, err := buildProtectedAudit(ctx, cfg, clock, receipts, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	defer closeAudit()

	record := securityaudit.Record{
		ID: "audit.composition.1", Action: "artifact-deleted", Actor: "operator-01",
		Workload: "composition-suite", Reason: "least privilege conformance", Ticket: "change-0004",
		OldDigest:   "sha256:" + strings.Repeat("a", 64),
		Traceparent: "00-" + strings.Repeat("1", 32) + "-" + strings.Repeat("2", 16) + "-01",
		Scope:       securityaudit.Scope{WorkspaceID: "workspace-audit", ProjectID: "project-audit", ResourceID: "artifact-audit"},
	}
	if err := service.PrivilegedMutation(ctx, record, func(context.Context) error { return nil }); err != nil {
		t.Fatalf("the composed audit could not record a decision: %v", err)
	}
	if err := service.Verify(ctx); err != nil {
		t.Fatalf("the composed audit chain does not verify: %v", err)
	}

	// The composed connection cannot rewrite what it just wrote.
	pool, err := persistence.OpenPool(ctx, persistence.PoolConfig{URL: databaseURL, Role: securityauditpg.RuntimeRole, Maximum: 2})
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()
	for name, statement := range map[string]string{
		"rewrite a record":     `UPDATE agent_protected_audit.records SET record_digest='sha256:'||repeat('f',64)`,
		"remove a record":      `DELETE FROM agent_protected_audit.records`,
		"truncate the chain":   `TRUNCATE agent_protected_audit.records`,
		"drop the append lock": `ALTER TABLE agent_protected_audit.records DISABLE TRIGGER protected_audit_is_append_only`,
		"redefine the table":   `ALTER TABLE agent_protected_audit.records ADD COLUMN smuggled text`,
	} {
		if _, err := pool.Exec(ctx, statement); err == nil {
			t.Fatalf("the running service could %s", name)
		}
	}
}

type auditCompositionTime struct{ value time.Time }

func (t auditCompositionTime) Now(context.Context) (time.Time, error) { return t.value, nil }

type auditCompositionLocal struct{ value time.Time }

func (t auditCompositionLocal) Now() time.Time { return t.value }

// The custody port production composes is the artifact service itself. The
// assertion is a compile-time one on purpose: a stub that happened to satisfy
// the port would pass any behavioural test written against it, and what has to
// hold is that the type production builds is the type the port admits.
var _ runapp.ArtifactCustodian = (*artifacts.Service)(nil)

// Custody has no unaudited mode. The artifact service refuses to be built
// without the protected audit, so a composition that could not reach the audit
// endpoint has no artifact lifecycle at all rather than one whose custody
// decisions leave no protected account of themselves.
func TestTheArtifactLifecycleRefusesToBuildWithoutItsProtectedAudit(t *testing.T) {
	store := artifacts.NewMemoryStore()
	objects := artifacts.NewMemoryObjects()
	source := authority.NewStatic(authority.Current{})
	if _, err := artifacts.New(store, objects, artifactReaderStub{}, source, nil, time.Hour, time.Minute); err == nil {
		t.Fatal("an artifact lifecycle was composed with no protected audit")
	}
	if _, err := artifacts.New(store, objects, artifactReaderStub{}, nil, stubProtectedAudit{}, time.Hour, time.Minute); err == nil {
		t.Fatal("an artifact lifecycle was composed with no current-authority source")
	}
}

// Production refuses to run without a real protected audit endpoint. The
// in-memory sink exists for local development and is never composed where a
// security decision has to survive the process that made it.
func TestProductionRefusesAnInMemoryProtectedAudit(t *testing.T) {
	ctx := context.Background()
	clock, err := securityaudit.NewAuthoritativeClock(compositionTimeSource{}, compositionClock{}, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	cfg := config.Config{Environment: config.EnvironmentProduction}
	if _, _, err := buildProtectedAudit(ctx, cfg, clock, journal.NewMemoryStore(), slog.New(slog.NewTextHandler(io.Discard, nil))); err == nil {
		t.Fatal("production composed an in-memory protected audit")
	}
	development := config.Config{Environment: config.EnvironmentDevelopment}
	service, closeAudit, err := buildProtectedAudit(ctx, development, clock, journal.NewMemoryStore(), slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil || service == nil {
		t.Fatalf("development could not compose a local protected audit: %v", err)
	}
	closeAudit()
}

// artifactReaderStub stands in for the grant-signing port where a composition
// test only proves that a dependency above it is required.
type artifactReaderStub struct{}

func (artifactReaderStub) SignRead(context.Context, artifacts.Record, artifacts.Grant, time.Duration) (string, error) {
	return "", nil
}
func (artifactReaderStub) Verify(context.Context, artifacts.Record, artifacts.Grant) error {
	return nil
}
func (artifactReaderStub) Revoke(context.Context, artifacts.Record) error { return nil }

type compositionTimeSource struct{}

func (compositionTimeSource) Now(context.Context) (time.Time, error) {
	return time.Unix(1700, 0).UTC(), nil
}

type compositionClock struct{}

func (compositionClock) Now() time.Time { return time.Unix(1700, 0).UTC() }
