package main

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/ancyloce/anvilkit-agent-service/internal/agent"
	"github.com/ancyloce/anvilkit-agent-service/internal/applyauth"
	"github.com/ancyloce/anvilkit-agent-service/internal/authority"
	"github.com/ancyloce/anvilkit-agent-service/internal/config"
	"github.com/ancyloce/anvilkit-agent-service/internal/execution"
	"github.com/ancyloce/anvilkit-agent-service/internal/persistence"
	"github.com/ancyloce/anvilkit-agent-service/internal/runapp"
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
	_, _, err := buildArtifactPort(config.Config{}, persistence.Pools{}, authority.NewStatic(authority.Current{}), runapp.SystemClock{})
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
