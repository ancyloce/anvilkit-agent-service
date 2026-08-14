package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/ancyloce/anvilkit-agent-service/internal/api"
	"github.com/ancyloce/anvilkit-agent-service/internal/auth"
	"github.com/ancyloce/anvilkit-agent-service/internal/config"
	contractguard "github.com/ancyloce/anvilkit-agent-service/internal/contracts"
	"github.com/ancyloce/anvilkit-agent-service/internal/events"
	eventpg "github.com/ancyloce/anvilkit-agent-service/internal/events/postgres"
	"github.com/ancyloce/anvilkit-agent-service/internal/idempotency"
	"github.com/ancyloce/anvilkit-agent-service/internal/interrupts"
	interruptpg "github.com/ancyloce/anvilkit-agent-service/internal/interrupts/postgres"
	"github.com/ancyloce/anvilkit-agent-service/internal/journal"
	journalpg "github.com/ancyloce/anvilkit-agent-service/internal/journal/postgres"
	"github.com/ancyloce/anvilkit-agent-service/internal/lifecycle"
	lifecyclepg "github.com/ancyloce/anvilkit-agent-service/internal/lifecycle/postgres"
	"github.com/ancyloce/anvilkit-agent-service/internal/persistence"
	"github.com/ancyloce/anvilkit-agent-service/internal/runapp"
	"github.com/ancyloce/anvilkit-agent-service/internal/runs"
	runpg "github.com/ancyloce/anvilkit-agent-service/internal/runs/postgres"
	"github.com/ancyloce/anvilkit-agent-service/internal/telemetry"
	"github.com/ancyloce/anvilkit-agent-service/internal/workflow"
	workflowdbos "github.com/ancyloce/anvilkit-agent-service/internal/workflow/dbos"
)

type noOpExecutor struct{}

func (noOpExecutor) Execute(context.Context, workflow.ID, workflow.Step) (json.RawMessage, error) {
	return json.RawMessage(`{}`), nil
}

func main() {
	cfg, err := config.Load()
	if err != nil {
		slog.Error("startup rejected", "problem", err)
		os.Exit(1)
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	redactor := telemetry.NewRedactor([]string{cfg.SigningKey.RedactionValue(), cfg.EncryptionKey.RedactionValue()})
	logger := slog.New(telemetry.NewHandler(slog.NewJSONHandler(os.Stderr, nil), redactor))
	slog.SetDefault(logger)
	observability, err := telemetry.New(cfg.ServiceName, nil, redactor)
	if err != nil {
		logger.Error("telemetry initialization failed", "error", err)
		os.Exit(1)
	}
	if err := contractguard.VerifyPinnedMaterial(cfg.ContractRoot, cfg.Environment == config.EnvironmentProduction); err != nil {
		logger.Error("contract material verification failed", "error", err)
		os.Exit(1)
	}
	guard, err := contractguard.NewGuard(cfg.ContractRoot)
	if err != nil {
		logger.Error("contract material initialization failed", "error", err)
		os.Exit(1)
	}

	var migrationConnection *pgx.Conn
	if cfg.MigrationDatabase != "" {
		migrationConnection, err = pgx.Connect(ctx, cfg.MigrationDatabase)
		if err != nil {
			logger.Error("migration connection failed", "error", err)
			os.Exit(1)
		}
		defer migrationConnection.Close(context.Background())
		migrator := persistence.NewMigrator(migrationConnection)
		if cfg.MigrationMode == "apply" {
			err = migrator.Apply(ctx)
		} else {
			err = migrator.Compatible(ctx)
		}
		if err != nil {
			logger.Error("migration compatibility failed", "error", err)
			os.Exit(1)
		}
	}
	pools, err := openPersistencePools(ctx, cfg)
	if err != nil {
		logger.Error("persistence pool initialization failed", "error", err)
		os.Exit(1)
	}
	defer pools.Close()
	if pools.Control != nil {
		_ = persistence.NewRunRepository(pools.Control)
	}
	if pools.Authority != nil {
		_ = eventpg.New(pools.Authority, nil, guard, events.Bounds{MaximumBytes: cfg.Limits.EventBytes, MaximumFields: 32, MaximumFieldBytes: 512})
		if _, err := idempotency.New(pools.Authority, idempotency.Config{Retention: 30 * 24 * time.Hour, MinimumLifetime: 30 * 24 * time.Hour}); err != nil {
			logger.Error("idempotency initialization failed", "error", err)
			os.Exit(1)
		}
	}

	if cfg.WorkflowDatabase == "" {
		logger.Error("workflow runtime initialization failed", "error", "workflow database unavailable; the production command never embeds the in-memory proof engine")
		os.Exit(1)
	}
	workflowRuntime, err := workflowdbos.New(ctx, workflowdbos.Config{DatabaseURL: cfg.WorkflowDatabase, Schema: "agent_dbos", ExecutorID: cfg.ExecutorID, ApplicationVersion: cfg.ServiceVersion, Logger: logger}, noOpExecutor{})
	if err != nil {
		logger.Error("workflow runtime initialization failed", "error", err)
		os.Exit(1)
	}
	if err := workflowRuntime.Start(ctx); err != nil {
		logger.Error("workflow runtime start failed", "error", err)
		os.Exit(1)
	}

	var journalStore journal.Store
	var journalPool *pgxpool.Pool
	if cfg.ReceiptJournal.URL == "" {
		journalStore = journal.NewMemoryStore()
	} else {
		journalPool, err = pgxpool.New(ctx, cfg.ReceiptJournal.URL)
		if err != nil {
			logger.Error("journal pool failed", "error", err)
			os.Exit(1)
		}
		adapter := journalpg.New(journalPool)
		if err := adapter.EnsureSchema(ctx); err != nil {
			logger.Error("journal schema failed", "error", err)
			os.Exit(1)
		}
		journalStore = adapter
	}
	if journalPool != nil {
		defer journalPool.Close()
	}

	workflowCheck := lifecycle.CheckFunc(func(checkContext context.Context) error {
		if cfg.WorkflowDatabase == "" && cfg.Environment == config.EnvironmentProduction {
			return errors.New("workflow database unavailable")
		}
		if cfg.WorkflowDatabase == "" {
			return nil
		}
		connection, err := pgx.Connect(checkContext, cfg.WorkflowDatabase)
		if err != nil {
			return err
		}
		defer connection.Close(checkContext)
		return connection.Ping(checkContext)
	})
	migrationCheck := lifecycle.CheckFunc(func(checkContext context.Context) error {
		if migrationConnection == nil {
			if cfg.Environment == config.EnvironmentProduction {
				return errors.New("migration database unavailable")
			}
			return nil
		}
		return persistence.NewMigrator(migrationConnection).Compatible(checkContext)
	})
	signingCheck := lifecycle.CheckFunc(func(context.Context) error {
		if !cfg.SigningKey.Present() && cfg.Environment == config.EnvironmentProduction {
			return errors.New("signing capability unavailable")
		}
		return nil
	})
	contractCheck := lifecycle.CheckFunc(func(context.Context) error {
		return contractguard.VerifyPinnedMaterial(cfg.ContractRoot, cfg.Environment == config.EnvironmentProduction)
	})
	policyCheck := lifecycle.FileCheck(cfg.PolicySnapshot)
	if cfg.Environment != config.EnvironmentProduction && cfg.PolicySnapshot == "" {
		policyCheck = lifecycle.FileCheck(cfg.ContractRoot + "/contracts/pin.json")
	}
	readiness := lifecycle.NewReadiness(
		lifecycle.Dependency{Name: "workflow-db", Check: workflowCheck},
		lifecycle.Dependency{Name: "persistence-pools", Check: lifecycle.CheckFunc(func(checkContext context.Context) error {
			for _, pool := range []*pgxpool.Pool{pools.Control, pools.Authority, pools.Events, pools.Workflow, pools.Artifacts, pools.Evaluation} {
				if pool != nil {
					if err := pool.Ping(checkContext); err != nil {
						return err
					}
				}
			}
			return nil
		})},
		lifecycle.Dependency{Name: "migration-compatibility", Check: migrationCheck},
		lifecycle.Dependency{Name: "recovery-register", Check: endpointOrDevelopment(cfg.RecoveryRegister.URL, cfg.Environment)},
		lifecycle.Dependency{Name: "rpo0-journal", Check: journalStore},
		lifecycle.Dependency{Name: "authoritative-time", Check: endpointOrDevelopment(cfg.AuthoritativeTime.URL, cfg.Environment)},
		lifecycle.Dependency{Name: "signing", Check: signingCheck},
		lifecycle.Dependency{Name: "contract-material", Check: contractCheck},
		lifecycle.Dependency{Name: "policy-material", Check: policyCheck},
		lifecycle.Dependency{Name: "protected-audit", Check: endpointOrDevelopment(cfg.ProtectedAudit.URL, cfg.Environment)},
	)

	apiOptions, err := agentAPIOptions(ctx, cfg, pools, workflowRuntime, journalStore, observability, guard)
	if err != nil {
		logger.Error("agent API initialization failed", "error", err)
		os.Exit(1)
	}
	handler := api.New(readiness, apiOptions...)
	server := api.NewServer(cfg.HTTPAddress, handler)
	leaseCleaner := lifecycle.LeaseCleaner(lifecycle.LeaseCleanerFunc(func(context.Context) error { return nil }))
	if pools.Workflow != nil {
		leaseCleaner, err = lifecyclepg.NewLeaseCleaner(pools.Workflow, cfg.ExecutorID)
		if err != nil {
			logger.Error("lease cleanup initialization failed", "error", err)
			os.Exit(1)
		}
	} else if cfg.Environment == config.EnvironmentProduction {
		logger.Error("lease cleanup initialization failed", "error", "workflow database unavailable")
		os.Exit(1)
	}
	shutdown := lifecycle.NewShutdown(
		lifecycle.Hook{Name: "ingress", Stage: lifecycle.StopIngress, Run: func(context.Context) error {
			handler.BeginDrain()
			return nil
		}},
		lifecycle.Hook{Name: "stream-reconnect", Stage: lifecycle.GuideStreamReconnect, Run: server.Shutdown},
		lifecycle.Hook{Name: "workflow-executor", Stage: lifecycle.CheckpointExecutors, Run: workflowRuntime.Stop},
		lifecycle.Hook{Name: "lease-cleanup", Stage: lifecycle.CleanupLeases, Run: leaseCleaner.Cleanup},
	)
	errCh := make(chan error, 1)
	go func() { errCh <- server.Run() }()

	select {
	case <-ctx.Done():
		shutdownContext, cancel := context.WithTimeout(context.Background(), 20*time.Second)
		defer cancel()
		if err := shutdown.Run(shutdownContext); err != nil {
			logger.Error("ordered shutdown failed", "error", err)
		}
		if err := observability.Shutdown(shutdownContext); err != nil {
			logger.Error("telemetry shutdown failed", "error", err)
		}
	case err := <-errCh:
		if !errors.Is(err, http.ErrServerClosed) {
			logger.Error("server stopped", "error", err)
			os.Exit(1)
		}
	}
}

func endpointOrDevelopment(url string, environment config.Environment) lifecycle.Check {
	if url != "" {
		return lifecycle.HTTPCheck{URL: url}
	}
	return lifecycle.CheckFunc(func(context.Context) error {
		if environment == config.EnvironmentProduction {
			return errors.New("critical endpoint unavailable")
		}
		return nil
	})
}

func openPersistencePools(ctx context.Context, cfg config.Config) (persistence.Pools, error) {
	var pools persistence.Pools
	inputs := []struct {
		target    **pgxpool.Pool
		url, role string
		maximum   int32
	}{
		{&pools.Control, cfg.ControlDatabase, "agent_control_rw", int32(cfg.ControlPoolSize)},
		{&pools.Authority, cfg.EventsDatabase, "agent_authority_rw", int32(cfg.EventsPoolSize)},
		{&pools.Events, cfg.EventsDatabase, "agent_events_rw", int32(cfg.EventsPoolSize)},
		{&pools.Workflow, cfg.WorkflowDatabase, "agent_workflow_rw", int32(cfg.WorkflowPoolSize)},
		{&pools.Artifacts, cfg.ArtifactsDatabase, "agent_artifacts_rw", int32(cfg.ArtifactsPoolSize)},
		{&pools.Evaluation, cfg.EvaluationDatabase, "agent_evaluation_rw", int32(cfg.EvaluationPoolSize)},
	}
	for _, input := range inputs {
		if input.url == "" {
			continue
		}
		pool, err := persistence.OpenPool(ctx, persistence.PoolConfig{URL: input.url, Role: input.role, Maximum: input.maximum})
		if err != nil {
			pools.Close()
			return persistence.Pools{}, err
		}
		*input.target = pool
	}
	return pools, nil
}

func agentAPIOptions(ctx context.Context, cfg config.Config, pools persistence.Pools, runtime workflow.Runtime, receipts journal.Store, observability *telemetry.Telemetry, guard *contractguard.Guard) ([]api.Option, error) {
	if pools.Authority == nil || cfg.AuthTrustSnapshot == "" {
		return nil, nil
	}
	registry, err := auth.NewFileRegistry(cfg.AuthTrustSnapshot)
	if err != nil {
		return nil, err
	}
	verifier, err := auth.NewJWSVerifier(registry)
	if err != nil {
		return nil, err
	}
	validator, err := auth.NewValidator(auth.Config{Issuers: cfg.AuthIssuers, Audience: cfg.AuthAudience, MaximumClockSkew: cfg.MaximumClockSkew}, registry, runapp.SystemClock{})
	if err != nil {
		return nil, err
	}
	idempotencyStore, err := idempotency.New(pools.Authority, idempotency.Config{Retention: 30 * 24 * time.Hour, MinimumLifetime: 30 * 24 * time.Hour})
	if err != nil {
		return nil, err
	}
	eventBounds := events.Bounds{MaximumBytes: cfg.Limits.EventBytes, MaximumFields: 32, MaximumFieldBytes: 512}
	runStore := runpg.NewConfigured(pools.Authority, idempotencyStore, eventBounds, nil)
	runService := runs.NewService(runStore, runapp.NewRuntimeStarter(runtime), runapp.RandomIDs{}, runapp.SystemClock{}, receipts)
	authority := runapp.StaticAuthority{}
	if cfg.RunAuthorityFile != "" {
		loaded, err := loadRunAuthority(cfg.RunAuthorityFile, guard)
		if err != nil {
			return nil, err
		}
		authority.Value = loaded
	}
	reader := eventpg.NewReader(pools.Authority, guard, eventBounds)
	application := runapp.New(validator, runService, reader, events.StreamConfig{Heartbeat: cfg.Limits.SSEHeartbeat, Revalidation: cfg.AuthRevalidation, ReplayLimit: 100, Bounds: eventBounds, Observer: observability}, authority)
	interruptStore, err := interruptpg.New(pools.Authority, idempotencyStore)
	if err != nil {
		return nil, err
	}
	interruptService, err := interrupts.NewService(interruptStore, interrupts.BoundSchemaValidator{}, currentInterruptAuthority{}, runtimeSignals{runtime}, workflowLeaseRevoker{pools.Workflow}, safeCancellationReconciler{}, rootBudgetReservation{pools.Authority}, receipts, runapp.SystemClock{}, runapp.RandomIDs{}, interrupts.Limits{ChildDepth: cfg.Limits.ChildDepth, ChildFanout: cfg.Limits.ChildFanout})
	if err != nil {
		return nil, err
	}
	application.WithInterrupts(interruptService)
	policies := make(map[runs.State]interrupts.DwellPolicy)
	for _, state := range []runs.State{runs.Created, runs.Preparing, runs.Planning, runs.AwaitingInput, runs.Executing, runs.Validating, runs.AwaitingReview, runs.AwaitingApproval, runs.Committing, runs.AwaitingDomainConfirmation, runs.Conflict, runs.Cancelling, runs.Failed} {
		policies[state] = interrupts.DwellPolicy{Deadline: cfg.DwellDeadline, Owner: "agent-service-oncall"}
	}
	monitor, err := interrupts.NewMonitor(interruptStore, operatorAlert{}, runapp.SystemClock{}, policies)
	if err != nil {
		return nil, err
	}
	go monitor.Run(ctx, time.Minute)
	options := []api.Option{api.WithAgentCore(application, verifier)}
	if cfg.FeatureGates["candidate-mutations"] && cfg.Environment != config.EnvironmentProduction {
		options = append(options, api.WithCandidateMutations())
	}
	return options, nil
}

type currentInterruptAuthority struct{}

func (currentInterruptAuthority) AuthorizeInput(context.Context, runs.Scope, interrupts.InputRequest) error {
	return nil
}
func (currentInterruptAuthority) AuthorizeReviewer(context.Context, runs.Scope, interrupts.ApprovalRequest, interrupts.DecisionKind) error {
	return nil
}
func (currentInterruptAuthority) RetryEligibility(_ context.Context, _ runs.Scope, snapshot runs.Snapshot) (bool, string, error) {
	if snapshot.Status != runs.Failed {
		return false, "", nil
	}
	if snapshot.Problem != nil && (snapshot.Problem.Retryability == "safe-after-backoff" || snapshot.Problem.Retryability == "operator-action") {
		return true, "preparing:authority", nil
	}
	return false, "", nil
}

type runtimeSignals struct{ runtime workflow.Runtime }

func (r runtimeSignals) Signal(ctx context.Context, id, topic string, payload json.RawMessage, key string) error {
	return r.runtime.Signal(ctx, workflow.ID(id), topic, payload, key)
}
func (r runtimeSignals) StartChild(ctx context.Context, child interrupts.Child) error {
	state, _ := json.Marshal(map[string]any{"runId": child.RunID, "rootRunId": child.RootRunID, "parentRunId": child.ParentRunID, "version": 1})
	_, err := r.runtime.Execute(ctx, workflow.Request{WorkflowID: workflow.ID(string(child.RunID) + ":v1"), Version: 1, Scope: workflow.Scope{WorkspaceID: child.WorkspaceID, ProjectID: child.ProjectID}, State: state})
	return err
}
func (r runtimeSignals) OpenWait(ctx context.Context, scope runs.Scope, id, topic string, duration time.Duration) error {
	if duration <= 0 {
		duration = time.Nanosecond
	}
	return r.runtime.StartWait(ctx, workflow.Request{WorkflowID: workflow.ID(id), Version: 1, Scope: workflow.Scope{WorkspaceID: scope.WorkspaceID, ProjectID: scope.ProjectID}, Steps: []workflow.Step{{Name: "wait", Kind: workflow.StepWait, Topic: topic, Duration: duration}}})
}
func (r runtimeSignals) StopRun(ctx context.Context, _ runs.Scope, id runs.ID, generation uint64) error {
	return r.runtime.Cancel(ctx, workflow.ID(fmt.Sprintf("%s:v%d", id, generation)))
}
func (r runtimeSignals) ResumeRun(ctx context.Context, scope runs.Scope, snapshot runs.Snapshot, checkpoint, resumeKey string) error {
	state, err := json.Marshal(map[string]any{"runId": snapshot.RunID, "executionGeneration": snapshot.ExecutionGeneration, "resumeCheckpoint": checkpoint, "resumeKey": resumeKey})
	if err != nil {
		return err
	}
	workflowID := fmt.Sprintf("%s:v%d", snapshot.RunID, snapshot.ExecutionGeneration)
	if resumeKey != "" {
		workflowID += ":resume:" + resumeKey
	}
	_, err = r.runtime.Execute(ctx, workflow.Request{WorkflowID: workflow.ID(workflowID), Version: int(snapshot.ExecutionGeneration), Scope: workflow.Scope{WorkspaceID: scope.WorkspaceID, ProjectID: scope.ProjectID}, State: state})
	return err
}

type workflowLeaseRevoker struct{ pool *pgxpool.Pool }

func (r workflowLeaseRevoker) RevokeRun(ctx context.Context, scope runs.Scope, id runs.ID) error {
	if r.pool == nil {
		return nil
	}
	_, err := r.pool.Exec(ctx, `DELETE FROM agent_workflow.executor_leases WHERE workspace_id=$1 AND project_id=$2 AND workflow_id=$3`, scope.WorkspaceID, scope.ProjectID, string(id)+":v1")
	return err
}

type safeCancellationReconciler struct{}

func (safeCancellationReconciler) Reconcile(_ context.Context, _ runs.Scope, _ runs.ID, commit bool) (bool, *runs.State, error) {
	return !commit, nil, nil
}

type rootBudgetReservation struct{ pool *pgxpool.Pool }

func (r rootBudgetReservation) ReserveChild(ctx context.Context, scope runs.Scope, parent, child runs.ID, _ interrupts.ChildMode) error {
	if r.pool == nil {
		return errors.New("root budget authority unavailable")
	}
	var present bool
	if err := r.pool.QueryRow(ctx, `SELECT snapshot ? 'budget' FROM agent_control.agent_runs WHERE workspace_id=$1 AND project_id=$2 AND run_id=$3`, scope.WorkspaceID, scope.ProjectID, parent).Scan(&present); err != nil {
		return err
	}
	if !present {
		return errors.New("root budget reservation is absent")
	}
	return nil
}

type operatorAlert struct{}

func (operatorAlert) Alert(_ context.Context, kind string, scope runs.Scope, id runs.ID, state runs.State) error {
	slog.Error("agent run requires operator attention", "alert", kind, "workspace_id", scope.WorkspaceID, "project_id", scope.ProjectID, "run_id", id, "state", state)
	return nil
}

func loadRunAuthority(path string, guard *contractguard.Guard) (runs.Authority, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return runs.Authority{}, fmt.Errorf("read run authority: %w", err)
	}
	var payload struct {
		ContractBOM json.RawMessage `json:"contractBomReference"`
		Policy      json.RawMessage `json:"policy"`
		Budget      json.RawMessage `json:"budget"`
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&payload); err != nil {
		return runs.Authority{}, fmt.Errorf("decode run authority: %w", err)
	}
	var extra any
	if err := decoder.Decode(&extra); err != io.EOF {
		return runs.Authority{}, fmt.Errorf("decode run authority: trailing JSON")
	}
	if len(payload.ContractBOM) == 0 || len(payload.Policy) == 0 || len(payload.Budget) == 0 {
		return runs.Authority{}, fmt.Errorf("run authority is incomplete")
	}
	authority := runs.Authority{ContractBOM: payload.ContractBOM, Policy: payload.Policy, Budget: payload.Budget}
	probe := runs.Snapshot{APIVersion: "anvilkit.io/contracts/v1", Kind: "AgentRun", RunID: "run.authority-validation", RootRunID: "run.authority-validation", TenantID: "tenant.authority-validation", WorkspaceID: "workspace.authority-validation", ActorID: "actor.authority-validation", Domain: "platform-agent", Operation: "artifact-validation", Target: runs.Target{Type: "page", ID: "page.authority-validation", WorkspaceID: "workspace.authority-validation"}, ContractBOM: authority.ContractBOM, Policy: authority.Policy, Budget: authority.Budget, Idempotency: runs.IdempotencyProjection{Scope: "workspace.authority-validation:create-run", Key: "authority-validation", CanonicalRequestDigest: "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}, Status: runs.Created, Version: 1, ExecutionGeneration: 1, CreatedAt: time.Unix(0, 0), UpdatedAt: time.Unix(0, 0)}
	probeBytes, err := json.Marshal(probe)
	if err != nil {
		return runs.Authority{}, fmt.Errorf("marshal run authority probe: %w", err)
	}
	findings := guard.Validate(context.Background(), contractguard.APIIn, "anvilkit://schema/agent-run.v1@1.0.0?digest=sha256:68949242c9b4557a8b5ff965f76de8f2de49c11523a7cc1e64cfd1b4af824233", probeBytes)
	if len(findings) != 0 {
		return runs.Authority{}, fmt.Errorf("run authority violates pinned AgentRunV1 references: %v", findings)
	}
	return authority, nil
}
