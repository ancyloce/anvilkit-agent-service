package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	contractvalidator "github.com/ancyloce/anvilkit-agent-service/contracts/validator"
	"github.com/ancyloce/anvilkit-agent-service/internal/agent"
	"github.com/ancyloce/anvilkit-agent-service/internal/agent/runner"
	"github.com/ancyloce/anvilkit-agent-service/internal/api"
	"github.com/ancyloce/anvilkit-agent-service/internal/applyauth"
	applyauthpg "github.com/ancyloce/anvilkit-agent-service/internal/applyauth/postgres"
	"github.com/ancyloce/anvilkit-agent-service/internal/artifacts"
	artifactspg "github.com/ancyloce/anvilkit-agent-service/internal/artifacts/postgres"
	"github.com/ancyloce/anvilkit-agent-service/internal/auth"
	"github.com/ancyloce/anvilkit-agent-service/internal/authority"
	authoritypg "github.com/ancyloce/anvilkit-agent-service/internal/authority/postgres"
	"github.com/ancyloce/anvilkit-agent-service/internal/budget"
	budgetpg "github.com/ancyloce/anvilkit-agent-service/internal/budget/postgres"
	"github.com/ancyloce/anvilkit-agent-service/internal/cancellation"
	"github.com/ancyloce/anvilkit-agent-service/internal/config"
	"github.com/ancyloce/anvilkit-agent-service/internal/contextcompiler"
	contextpg "github.com/ancyloce/anvilkit-agent-service/internal/contextcompiler/postgres"
	"github.com/ancyloce/anvilkit-agent-service/internal/contractclient"
	contractpg "github.com/ancyloce/anvilkit-agent-service/internal/contractclient/postgres"
	contractguard "github.com/ancyloce/anvilkit-agent-service/internal/contracts"
	domaincommitpg "github.com/ancyloce/anvilkit-agent-service/internal/domaincommit/postgres"
	"github.com/ancyloce/anvilkit-agent-service/internal/events"
	eventpg "github.com/ancyloce/anvilkit-agent-service/internal/events/postgres"
	"github.com/ancyloce/anvilkit-agent-service/internal/execution"
	executionpg "github.com/ancyloce/anvilkit-agent-service/internal/execution/postgres"
	"github.com/ancyloce/anvilkit-agent-service/internal/idempotency"
	"github.com/ancyloce/anvilkit-agent-service/internal/interrupts"
	interruptpg "github.com/ancyloce/anvilkit-agent-service/internal/interrupts/postgres"
	"github.com/ancyloce/anvilkit-agent-service/internal/journal"
	journalpg "github.com/ancyloce/anvilkit-agent-service/internal/journal/postgres"
	"github.com/ancyloce/anvilkit-agent-service/internal/lifecycle"
	lifecyclepg "github.com/ancyloce/anvilkit-agent-service/internal/lifecycle/postgres"
	modelpg "github.com/ancyloce/anvilkit-agent-service/internal/modelgateway/postgres"
	"github.com/ancyloce/anvilkit-agent-service/internal/persistence"
	"github.com/ancyloce/anvilkit-agent-service/internal/problem"
	"github.com/ancyloce/anvilkit-agent-service/internal/queue"
	queuepg "github.com/ancyloce/anvilkit-agent-service/internal/queue/postgres"
	recoverypg "github.com/ancyloce/anvilkit-agent-service/internal/recovery/postgres"
	"github.com/ancyloce/anvilkit-agent-service/internal/runapp"
	runapppg "github.com/ancyloce/anvilkit-agent-service/internal/runapp/postgres"
	"github.com/ancyloce/anvilkit-agent-service/internal/runs"
	runpg "github.com/ancyloce/anvilkit-agent-service/internal/runs/postgres"
	"github.com/ancyloce/anvilkit-agent-service/internal/scheduler"
	schedulerpg "github.com/ancyloce/anvilkit-agent-service/internal/scheduler/postgres"
	"github.com/ancyloce/anvilkit-agent-service/internal/securityaudit"
	"github.com/ancyloce/anvilkit-agent-service/internal/telemetry"
	"github.com/ancyloce/anvilkit-agent-service/internal/tools"
	toolspg "github.com/ancyloce/anvilkit-agent-service/internal/tools/postgres"
	"github.com/ancyloce/anvilkit-agent-service/internal/usage"
	usagepg "github.com/ancyloce/anvilkit-agent-service/internal/usage/postgres"
	"github.com/ancyloce/anvilkit-agent-service/internal/workflow"
	workflowdbos "github.com/ancyloce/anvilkit-agent-service/internal/workflow/dbos"
)

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
	if err := contractguard.VerifyPinnedMaterial(cfg.ContractRoot); err != nil {
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
		defer func() {
			if closeErr := migrationConnection.Close(context.Background()); closeErr != nil {
				logger.Warn("migration connection close failed", "error", closeErr)
			}
		}()
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
	outboxDispatcher, err := newOutboxDispatcher(pools)
	if err != nil {
		logger.Error("outbox dispatcher initialization failed", "error", err)
		os.Exit(1)
	}
	if outboxDispatcher != nil {
		go outboxDispatcher.Run(ctx, 250*time.Millisecond, func(err error) {
			logger.Error("outbox dispatch failed", "error", err)
		})
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

	clock, err := applicationClock(cfg)
	if err != nil {
		logger.Error("application clock initialization failed", "error", err)
		os.Exit(1)
	}

	if cfg.WorkflowDatabase == "" {
		logger.Error("workflow runtime initialization failed", "error", "workflow database unavailable; the production command never embeds the in-memory proof engine")
		os.Exit(1)
	}
	if pools.Authority == nil || pools.Control == nil {
		logger.Error("workflow runtime initialization failed", "error", "the durable agent runtime requires the control and authority databases")
		os.Exit(1)
	}
	handle := &runtimeHandle{}
	core, err := buildRuntimeCore(ctx, cfg, pools, guard, journalStore, clock, handle)
	if err != nil {
		logger.Error("agent runtime pipeline initialization failed", "error", err)
		os.Exit(1)
	}
	workflowRuntime, err := workflowdbos.New(ctx, workflowdbos.Config{DatabaseURL: cfg.WorkflowDatabase, Schema: "agent_dbos", ExecutorID: cfg.ExecutorID, ApplicationVersion: cfg.ServiceVersion, Logger: logger}, core.executor)
	if err != nil {
		logger.Error("workflow runtime initialization failed", "error", err)
		os.Exit(1)
	}
	handle.set(workflowRuntime)
	if err := workflowRuntime.Start(ctx); err != nil {
		logger.Error("workflow runtime start failed", "error", err)
		os.Exit(1)
	}

	workflowCheck := lifecycle.CheckFunc(func(checkContext context.Context) error {
		connection, err := pgx.Connect(checkContext, cfg.WorkflowDatabase)
		if err != nil {
			return err
		}
		// The readiness answer is the ping; a failure to close the probe
		// connection afterwards cannot change it.
		defer func() { _ = connection.Close(checkContext) }()
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
		return contractguard.VerifyPinnedMaterial(cfg.ContractRoot)
	})
	// Trust material is revalidated on every readiness probe, not trusted
	// because it verified at startup: a trust root past its declared freshness
	// bound, a statement outside its validity interval, or a revoked signing
	// key must take the service out of rotation while it is still running.
	definitionTrustCheck := lifecycle.CheckFunc(func(context.Context) error {
		if core.trust == nil {
			if cfg.Environment == config.EnvironmentProduction {
				return errors.New("definition catalog attestation unavailable")
			}
			return nil
		}
		return core.trust.Verify(clock.Now())
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
		lifecycle.Dependency{Name: "migration", Check: migrationCheck},
		lifecycle.Dependency{Name: "authoritative-time", Check: endpointOrDevelopment(cfg.AuthoritativeTime.URL, cfg.Environment)},
		lifecycle.Dependency{Name: "signing", Check: signingCheck},
		lifecycle.Dependency{Name: "contract-material", Check: contractCheck},
		lifecycle.Dependency{Name: "policy-material", Check: policyCheck},
		lifecycle.Dependency{Name: "definition-trust", Check: definitionTrustCheck},
		lifecycle.Dependency{Name: "protected-audit", Check: endpointOrDevelopment(cfg.ProtectedAudit.URL, cfg.Environment)},
	)

	apiOptions, err := agentAPIOptions(ctx, cfg, pools, handle, core, observability)
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

// runtimeCore holds the shared pipeline components constructed once and
// consumed by both the durable runtime and the API layer.
type runtimeCore struct {
	executor         *execution.Executor
	runStore         runs.Store
	interruptStore   *interruptpg.Store
	interruptService *interrupts.Service
	idempotency      *idempotency.Store
	authority        authority.Source
	receipts         journal.Store
	guard            *contractguard.Guard
	clock            applicationTime
	eventBounds      events.Bounds
	artifacts        *artifacts.Service
	registry         *agent.Registry
	deltas           *events.DeltaBroker
	// cancellationReconciler is the authoritative external-effect reader the
	// cancellation recovery sweep asks before it concludes any accounting.
	cancellationReconciler interrupts.CancellationReconciler
	// executorHandle carries the terminal-budget settlement port into services
	// that are composed before the executor exists.
	executorHandle *executorHandle
	// trust revalidates the catalog attestation. It is nil only where no
	// attestation is configured at all, which production configuration
	// rejects before this point.
	trust *agent.CatalogTrust
}

// buildRuntimeCore wires the real Agent execution pipeline. Every
// implementation is explicitly selected; nothing falls back to a controlled
// fake implicitly, and production configuration rejects controlled values.
func buildRuntimeCore(ctx context.Context, cfg config.Config, pools persistence.Pools, guard *contractguard.Guard, receipts journal.Store, clock applicationTime, handle *runtimeHandle) (*runtimeCore, error) {
	core, executionConfig, err := buildRuntimeDependencies(ctx, cfg, pools, guard, receipts, clock, handle)
	if err != nil {
		return nil, err
	}
	executor, err := execution.New(executionConfig)
	if err != nil {
		return nil, err
	}
	core.setExecutor(executor)
	return core, nil
}

// setExecutor publishes the composed executor to the core and to every port
// that was handed the deferred handle before it existed.
func (c *runtimeCore) setExecutor(executor *execution.Executor) {
	c.executor = executor
	c.executorHandle.set(executor)
}

// executorHandle defers terminal-budget settlement to the execution pipeline,
// which is constructed after the lifecycle services that need it. Settling
// through an unresolved handle fails closed rather than skipping the
// settlement.
type executorHandle struct{ inner *execution.Executor }

func (h *executorHandle) set(executor *execution.Executor) { h.inner = executor }

func (h *executorHandle) SettleRunBudget(ctx context.Context, snapshot runs.Snapshot, release bool) error {
	if h.inner == nil {
		return fmt.Errorf("terminal budget settlement is unavailable: the execution pipeline is not composed")
	}
	return h.inner.SettleRunBudget(ctx, snapshot, release)
}

func (h *executorHandle) FenceRunBudget(ctx context.Context, snapshot runs.Snapshot) error {
	if h.inner == nil {
		return fmt.Errorf("cancellation budget fencing is unavailable: the execution pipeline is not composed")
	}
	return h.inner.FenceRunBudget(ctx, snapshot)
}

func (h *executorHandle) SettleCancelledRunBudget(ctx context.Context, snapshot runs.Snapshot) error {
	if h.inner == nil {
		return fmt.Errorf("cancelled budget settlement is unavailable: the execution pipeline is not composed")
	}
	return h.inner.SettleCancelledRunBudget(ctx, snapshot)
}

func (h *executorHandle) OutstandingCancelledRunBudget(ctx context.Context, snapshot runs.Snapshot) (bool, error) {
	if h.inner == nil {
		return false, fmt.Errorf("cancelled budget hold lookup is unavailable: the execution pipeline is not composed")
	}
	return h.inner.OutstandingCancelledRunBudget(ctx, snapshot)
}

var _ interrupts.TerminalBudget = (*executorHandle)(nil)

// buildRuntimeDependencies assembles every durable dependency of the real
// execution pipeline and returns the executor configuration unbuilt. It is
// the one composition path: buildRuntimeCore constructs the executor from it
// directly, and the restart-verification harness constructs it after wrapping
// exact ports with crash injection — so what restart proofs exercise is the
// production composition itself, never a parallel wiring.
func buildRuntimeDependencies(ctx context.Context, cfg config.Config, pools persistence.Pools, guard *contractguard.Guard, receipts journal.Store, clock applicationTime, handle *runtimeHandle) (*runtimeCore, execution.Config, error) {
	idempotencyStore, err := idempotency.New(pools.Authority, idempotency.Config{Retention: 30 * 24 * time.Hour, MinimumLifetime: 30 * 24 * time.Hour})
	if err != nil {
		return nil, execution.Config{}, err
	}
	eventBounds := events.Bounds{MaximumBytes: cfg.Limits.EventBytes, MaximumFields: 32, MaximumFieldBytes: 512}
	runStore := runpg.NewConfigured(pools.Authority, idempotencyStore, eventBounds, guard, nil)
	toolExecutor, grants, err := selectToolImplementation(cfg)
	if err != nil {
		return nil, execution.Config{}, err
	}
	// One current-authority source serves the whole runtime: run creation,
	// Manager turns, the Tool Guard, delegation, retry, approval, artifact
	// access, and commit all re-read this value and no other. The configured
	// authority document seeds the durable scoped source — material, grants,
	// and subjects per workspace/project — and every later read observes the
	// durable activation and revocation state. With no document configured,
	// the static empty source fails closed on every read.
	var authoritySource authority.Source = authority.NewStatic(authority.Current{Grants: grants})
	var bomAuthority execution.BOMAuthority = execution.StaticBOMAuthority{}
	if cfg.RunAuthorityFile != "" {
		durableAuthority, err := seedDurableAuthority(ctx, cfg.RunAuthorityFile, guard, grants, pools.Authority, clock)
		if err != nil {
			return nil, execution.Config{}, err
		}
		authoritySource = durableAuthority
		bomAuthority = durableAuthority
	}
	interruptStore, err := interruptpg.New(pools.Authority, idempotencyStore, guard)
	if err != nil {
		return nil, execution.Config{}, err
	}
	interruptAuthority, err := interrupts.NewCurrentAuthority(interruptStore, authoritySource)
	if err != nil {
		return nil, execution.Config{}, err
	}
	childBudget, err := interruptpg.NewChildBudgetReservation(pools.Control, cfg.BudgetUnits, cfg.BudgetHeadroomMicros, cfg.RunTimeout)
	if err != nil {
		return nil, execution.Config{}, err
	}
	// Cancellation is only safe once every external effect the run caused is
	// known to be settled, so the reconciler reads the authoritative provider,
	// worker, tool, artifact, and domain-effect records.
	cancellationReconciler, err := cancellation.New(cancellation.Pools{Control: pools.Control, Workflow: pools.Workflow, Artifacts: pools.Artifacts, Events: pools.Events})
	if err != nil {
		return nil, execution.Config{}, err
	}
	settlementHandle := &executorHandle{}
	interruptService, err := interrupts.NewService(interruptStore, interrupts.BoundSchemaValidator{}, interruptAuthority, runtimeSignals{handle}, workflowLeaseRevoker{pools.Workflow}, cancellationReconciler, childBudget, settlementHandle, receipts, clock, runapp.RandomIDs{}, interrupts.Limits{ChildDepth: cfg.Limits.ChildDepth, ChildFanout: cfg.Limits.ChildFanout})
	if err != nil {
		return nil, execution.Config{}, err
	}

	definitionSchema, err := os.ReadFile(filepath.Join(cfg.ContractRoot, "contracts", "agent", "schemas", "agent-definition.schema.json"))
	if err != nil {
		return nil, execution.Config{}, fmt.Errorf("read pinned agent definition schema: %w", err)
	}
	toolSchema, err := os.ReadFile(filepath.Join(cfg.ContractRoot, "contracts", "agent", "schemas", "tool-definition.schema.json"))
	if err != nil {
		return nil, execution.Config{}, fmt.Errorf("read pinned tool definition schema: %w", err)
	}
	lockBytes, err := os.ReadFile(filepath.Join(cfg.ContractRoot, "contracts", "agent", "lock", "contracts.lock.json"))
	if err != nil {
		return nil, execution.Config{}, fmt.Errorf("read pinned canonical lock: %w", err)
	}
	schemaValidator, err := contractvalidator.New(cfg.ContractRoot)
	if err != nil {
		return nil, execution.Config{}, fmt.Errorf("load pinned runtime validator: %w", err)
	}
	// The approved definition catalog is authenticated against the contract
	// identity this service verified at startup, so a definition set produced
	// against a different canonical profile or lock cannot be executed.
	pinnedIdentity, err := contractguard.PinnedIdentity(cfg.ContractRoot)
	if err != nil {
		return nil, execution.Config{}, fmt.Errorf("resolve pinned contract identity: %w", err)
	}
	registry, err := agent.NewRegistry(ctx, agent.RegistryConfig{
		Source:              agent.EmbeddedCatalog{},
		Validator:           schemaValidator,
		DefinitionSchemaURI: agent.DefinitionSchemaURI(definitionSchema),
		Approval: agent.Approval{
			ProfileDigest: pinnedIdentity.ProfileDigest,
			LockDigest:    pinnedIdentity.LockDigest,
			SchemaDigests: pinnedIdentity.SchemaDigests,
		},
	})
	if err != nil {
		return nil, execution.Config{}, err
	}
	trust, err := definitionTrust(cfg, registry.CatalogDigest())
	if err != nil {
		return nil, execution.Config{}, err
	}
	if trust != nil {
		if err := trust.Verify(clock.Now()); err != nil {
			return nil, execution.Config{}, err
		}
	}
	pinnedValidator, err := execution.NewPinnedSchemaValidator(cfg.ContractRoot)
	if err != nil {
		return nil, execution.Config{}, err
	}

	modelStack, err := selectModelImplementation(cfg, pools, clock, registry)
	if err != nil {
		return nil, execution.Config{}, err
	}
	contractsValidator, err := selectContractRuntime(cfg, pinnedValidator, registry, digestOfBytes(lockBytes), pools, clock, bomAuthority)
	if err != nil {
		return nil, execution.Config{}, err
	}
	// The apply-authorization signing material also verifies tokens at the
	// controlled domain boundary, so the keyring is built once and shared.
	var signingKeys applyauth.SigningPort
	if cfg.SigningKey.Present() {
		ring, keyErr := applyauth.NewSeededKeyRing([]byte(cfg.SigningKey.RedactionValue()))
		if keyErr != nil {
			return nil, execution.Config{}, fmt.Errorf("derive apply-authorization signing key: %w", keyErr)
		}
		signingKeys = ring
	}
	domainPort, err := selectDomainImplementation(cfg, pools, signingKeys, clock)
	if err != nil {
		return nil, execution.Config{}, err
	}
	artifactPort, artifactService, err := buildArtifactPort(cfg, pools, authoritySource, clock)
	if err != nil {
		return nil, execution.Config{}, err
	}
	commitAuthority, err := buildCommitAuthority(cfg, pools, guard, receipts, clock, runStore, interruptStore, authoritySource, artifactPort, signingKeys)
	if err != nil {
		return nil, execution.Config{}, err
	}
	if pools.Control == nil {
		return nil, execution.Config{}, fmt.Errorf("the domain submission journal requires the control database")
	}
	submissions, err := domaincommitpg.New(pools.Control)
	if err != nil {
		return nil, execution.Config{}, err
	}
	evidenceStore, err := eventpg.NewEvidenceStore(pools.Authority, clockOf{clock}.Now)
	if err != nil {
		return nil, execution.Config{}, err
	}
	deltaBroker := events.NewDeltaBroker()

	toolArguments, err := execution.NewPinnedToolArgumentValidator()
	if err != nil {
		return nil, execution.Config{}, err
	}
	// The running tool profile is derived from the catalog's signed
	// ToolDefinitions, so the capability, side-effect class, risk, approval
	// policy, timeout, and retry policy the process dispatches under are the
	// ones the approved catalog attests.
	toolProfile, err := execution.NewApprovedToolProfile(registry.ToolBindings(), digestOfBytes(toolSchema), registry.CatalogDigest(), toolArguments)
	if err != nil {
		return nil, execution.Config{}, err
	}
	toolMaterial, err := execution.NewToolMaterial(toolProfile, toolArguments)
	if err != nil {
		return nil, execution.Config{}, err
	}
	fencedTools, err := selectWorkerImplementation(ctx, cfg, pools, clock, authoritySource, toolMaterial, toolExecutor, digestOfBytes(lockBytes))
	if err != nil {
		return nil, execution.Config{}, err
	}
	// The guard's decisions and the pinned running tool profile are durable
	// state, never process memory; the authority role spans both stores.
	if pools.Authority == nil {
		return nil, execution.Config{}, fmt.Errorf("the tool guard requires the authority database for durable decisions")
	}
	toolRecorder, err := toolspg.New(pools.Authority)
	if err != nil {
		return nil, execution.Config{}, err
	}
	toolGuard, err := tools.NewGuard(toolProfile, toolRecorder, clockOf{clock}, toolArguments)
	if err != nil {
		return nil, execution.Config{}, err
	}

	if pools.Evaluation == nil {
		return nil, execution.Config{}, fmt.Errorf("the context compiler requires the evaluation database for durable compilation evidence")
	}
	contextRecorder, err := contextpg.New(pools.Evaluation)
	if err != nil {
		return nil, execution.Config{}, err
	}
	agentRunner, err := runner.New(runner.Config{
		Registry:  registry,
		Compiler:  recordingCompiler{compiler: contextcompiler.New([]string{cfg.SigningKey.RedactionValue(), cfg.EncryptionKey.RedactionValue()}), recorder: contextRecorder},
		Selector:  modelStack,
		Invoker:   modelStack,
		Guard:     toolGuard,
		Validator: pinnedValidator,
		Clock:     clockOf{clock},
		Limits: runner.Limits{
			MaximumOutputBytes:  cfg.Limits.EventBytes,
			MaximumInputTokens:  int64(cfg.Limits.ContextTokens),
			MaximumOutputTokens: int64(cfg.Limits.ContextTokens),
			Timeout:             cfg.RunTimeout,
			MaximumAttempts:     cfg.Limits.RetryAttempts,
			RetryBudget:         cfg.RunTimeout,
			ContextTokens:       cfg.Limits.ContextTokens,
		},
	})
	if err != nil {
		return nil, execution.Config{}, err
	}
	// The Platform budget controller is durable end to end: its reservation
	// ledger and observation record live in the control schema, and its
	// generation authority is the run aggregate's execution generation — so a
	// restarted process fences on exactly the state the previous one wrote.
	budgetLedger, err := budgetpg.NewLedger(pools.Authority, clockOf{clock}.Now)
	if err != nil {
		return nil, execution.Config{}, err
	}
	budgetGenerations, err := budgetpg.NewRunGenerations(pools.Authority)
	if err != nil {
		return nil, execution.Config{}, err
	}
	budgetController, err := budget.New(budgetLedger, budgetGenerations, budgetExposure{}, clockOf{clock}, budget.HeadroomPolicy{
		MaximumReservedMicros: cfg.BudgetMaxReservedMicros,
		ReviewAtBasisPoints:   cfg.BudgetReviewBasisPoints,
	})
	if err != nil {
		return nil, execution.Config{}, err
	}
	executionConfig := execution.Config{
		Registry:          registry,
		Runner:            agentRunner,
		Runs:              runStore,
		InterruptWriter:   interruptService,
		InterruptReader:   interruptStore,
		InterruptExpirer:  interruptStore,
		Authority:         authoritySource,
		Tools:             fencedTools,
		ToolMaterial:      toolMaterial,
		Artifacts:         artifactPort,
		Domain:            domainPort,
		Submissions:       submissions,
		CommitAuthority:   commitAuthority,
		Contracts:         contractsValidator,
		Evidence:          evidenceStore,
		Deltas:            deltaBroker,
		Decisions:         receipts,
		Budget:            budgetController,
		Clock:             clockOf{clock},
		InputTTL:          cfg.InputRequestTTL,
		ApprovalTTL:       cfg.ApprovalRequestTTL,
		BudgetTTL:         cfg.RunTimeout,
		TurnLimit:         cfg.TurnLimit,
		ValidatorIdentity: digestOfBytes(lockBytes),
		ReconcileLimit:    cfg.DomainReconcileLimit,
		DomainRetryBase:   cfg.DomainRetryBase,
		DomainRetryCap:    cfg.DomainRetryCap,
	}
	return &runtimeCore{runStore: runStore, interruptStore: interruptStore, interruptService: interruptService, idempotency: idempotencyStore, authority: authoritySource, receipts: receipts, guard: guard, clock: clock, eventBounds: eventBounds, artifacts: artifactService, registry: registry, deltas: deltaBroker, trust: trust, cancellationReconciler: cancellationReconciler, executorHandle: settlementHandle}, executionConfig, nil
}

// selectModelImplementation returns the explicitly configured model stack.
// No implementation is ever selected implicitly, and production configuration
// rejects the controlled value before this point. Provider idempotency,
// settled outcomes, script position, and usage evidence are all durable and
// process-external, so a restart replays what happened instead of calling the
// provider again.
func selectModelImplementation(cfg config.Config, pools persistence.Pools, clock applicationTime, policies execution.ModelPolicySource) (*execution.ControlledModelStack, error) {
	switch cfg.ModelImplementation {
	case execution.ControlledImplementation:
		if pools.Workflow == nil {
			return nil, fmt.Errorf("the model implementation requires the workflow database for its durable provider ledger")
		}
		ledger, err := executionpg.NewScriptLedger(pools.Workflow, cfg.ExecutorID+":controlled-model")
		if err != nil {
			return nil, err
		}
		script, err := controlledModelScript(cfg.ControlledModelScript)
		if err != nil {
			return nil, err
		}
		adapter, err := execution.NewScriptedAdapter(ledger, script...)
		if err != nil {
			return nil, err
		}
		if pools.Authority == nil {
			return nil, fmt.Errorf("the model invocation recorder requires the authority database, whose role spans the invocation and policy-snapshot stores")
		}
		recorder, err := modelpg.NewInvocationRecorder(pools.Authority)
		if err != nil {
			return nil, err
		}
		return execution.NewControlledModelStack(adapter, clockOf{clock}, recorder, policies)
	case "":
		return nil, fmt.Errorf("ANVILKIT_MODEL_IMPLEMENTATION must be explicitly selected; no model integration is assumed")
	default:
		return nil, fmt.Errorf("model implementation %q is not available", cfg.ModelImplementation)
	}
}

// controlledModelScript renders the configured deterministic script the
// controlled adapter plays. Every step is a typed plan; the vocabulary is
// closed so a script cannot smuggle an unattested action.
func controlledModelScript(steps []string) ([][]byte, error) {
	script := make([][]byte, 0, len(steps))
	for _, step := range steps {
		switch step {
		case "final":
			script = append(script, execution.PlanStep("agent.final", map[string]json.RawMessage{"candidate": execution.ControlledCandidate(), "summary": json.RawMessage(`"controlled candidate"`)}))
		case "need-input":
			script = append(script, execution.PlanStep("agent.need-input", map[string]json.RawMessage{"question": json.RawMessage(`"controlled input request"`)}))
		case "tool-echo":
			script = append(script, execution.PlanStep("anvilkit.tool.context-echo", map[string]json.RawMessage{"query": json.RawMessage(`"controlled context"`)}))
		default:
			return nil, fmt.Errorf("controlled model script step %q is not available", step)
		}
	}
	return script, nil
}

// selectToolImplementation returns the explicitly configured tool executor
// and the dispatch grants the current-authority source serves with it. The
// grants are authority state, not tool state, so they are resolved here once
// and read back through the single authority source at every boundary.
func selectToolImplementation(cfg config.Config) (execution.ToolExecutor, authority.Grants, error) {
	switch cfg.ToolImplementation {
	case execution.ControlledImplementation:
		grants := authority.Grants{
			AllowedTools:        []string{"anvilkit.tool.context-echo", "anvilkit.tool.contract-validate", "anvilkit.tool.artifact-scan"},
			AllowedCapabilities: []string{"fake.execute", "contract.validate", "artifact.scan"},
			AllowedEffects:      []string{"read"},
			MaximumRisk:         "low",
			DataClasses:         []string{"public", "internal"},
		}
		return execution.NewControlledToolExecutor(), grants, nil
	case "":
		return nil, authority.Grants{}, fmt.Errorf("ANVILKIT_TOOL_IMPLEMENTATION must be explicitly selected; no tool integration is assumed")
	default:
		return nil, authority.Grants{}, fmt.Errorf("tool implementation %q is not available", cfg.ToolImplementation)
	}
}

// selectDomainImplementation returns the explicitly configured authoritative
// domain owner. The controlled owner is strict: it verifies the complete
// signed apply authorization — signature, key state, audience, expiry, and
// every binding — and redeems it atomically in its durable redemption record,
// so a replay in any process returns the recorded outcome instead of a second
// effect. Production configuration rejects it; the real Pagix owner performs
// the same verification on its side of the boundary.
func selectDomainImplementation(cfg config.Config, pools persistence.Pools, keys applyauth.SigningPort, clock applicationTime) (execution.DomainPort, error) {
	switch cfg.DomainImplementation {
	case execution.ControlledImplementation:
		if keys == nil {
			return nil, fmt.Errorf("the controlled domain owner requires the signing key material to verify apply authorizations")
		}
		if pools.Control == nil {
			return nil, fmt.Errorf("the controlled domain owner requires the control database for its durable redemption record")
		}
		redemptions, err := executionpg.NewRedemptionStore(pools.Control)
		if err != nil {
			return nil, err
		}
		return execution.NewVerifyingDomainPort(execution.DomainConfirmed, keys, redemptions, clockOf{clock})
	case "":
		return nil, fmt.Errorf("ANVILKIT_DOMAIN_IMPLEMENTATION must be explicitly selected; no domain integration is assumed")
	default:
		return nil, fmt.Errorf("domain implementation %q is not available", cfg.DomainImplementation)
	}
}

// buildArtifactPort composes the real artifact module. Artifacts are a
// first-party Agent Service capability, not a selectable integration: every
// topology stores immutable bytes durably, enforces the lifecycle CAS, audits
// every grant, and answers governed-effect eligibility from the finalized
// state. There is no memory-only mode.
func buildArtifactPort(cfg config.Config, pools persistence.Pools, authoritySource authority.Source, clock applicationTime) (execution.ArtifactPort, *artifacts.Service, error) {
	if pools.Artifacts == nil {
		return nil, nil, fmt.Errorf("the artifact module requires the artifacts database for its durable metadata, objects, and grant audit")
	}
	if !cfg.EncryptionKey.Present() {
		return nil, nil, fmt.Errorf("ANVILKIT_ENCRYPTION_KEY is required: artifact read grants have no unsigned mode")
	}
	store, err := artifactspg.NewStore(pools.Artifacts)
	if err != nil {
		return nil, nil, err
	}
	objects, err := artifactspg.NewObjects(pools.Artifacts)
	if err != nil {
		return nil, nil, err
	}
	reader, err := artifactspg.NewHMACReader(pools.Artifacts, []byte(cfg.EncryptionKey.RedactionValue()))
	if err != nil {
		return nil, nil, err
	}
	service, err := artifacts.New(store, objects, reader, authoritySource, cfg.ArtifactPendingTTL, cfg.ArtifactGrantTTL)
	if err != nil {
		return nil, nil, err
	}
	port, err := execution.NewServiceArtifactPort(service, clockOf{clock})
	if err != nil {
		return nil, nil, err
	}
	return port, service, nil
}

// selectWorkerImplementation wraps the explicitly configured worker fabric
// around the selected tool executor. The controlled fabric dispatches every
// tool execution as a fenced task — recovery-epoch and generation fenced,
// lease-guarded, reservation-bound, with an all-attempt durable usage
// observation. Production configuration rejects it, and no fabric is ever
// selected implicitly.
func selectWorkerImplementation(ctx context.Context, cfg config.Config, pools persistence.Pools, clock applicationTime, source authority.Source, material execution.ToolMaterial, worker execution.ToolExecutor, buildIdentity string) (execution.ToolExecutor, error) {
	switch cfg.WorkerImplementation {
	case execution.ControlledImplementation:
		if pools.Control == nil || pools.Authority == nil {
			return nil, fmt.Errorf("the controlled worker fabric requires the control and authority databases for durable usage, reservations, tasks, and recovery state")
		}
		usageStore, err := usagepg.New(pools.Control)
		if err != nil {
			return nil, err
		}
		pipeline, err := usage.New(usageStore, execution.NewControlledUsageSink())
		if err != nil {
			return nil, err
		}
		reservations, err := executionpg.NewToolReservations(pools.Control, cfg.RunTimeout)
		if err != nil {
			return nil, err
		}
		// The recovery epoch and the whole dispatch record — task, lease,
		// fence, accepted result, replayable output — are durable, never
		// process memory: a restarted service replays what already happened.
		// The authoritative non-rollback register is external to Platform
		// Postgres by decision (design 0005 §13); the controlled fabric reads
		// the durable scheduler mirror, and production rejects this fabric
		// entirely.
		register, err := recoverypg.NewMirrorEpochSource(pools.Authority)
		if err != nil {
			return nil, err
		}
		if err := register.EnsureBaseline(ctx); err != nil {
			return nil, err
		}
		dispatch, err := schedulerpg.NewDurableScheduler(pools.Authority, register, execution.DispatchIDs{}, clockOf{clock}, scheduler.PrerequisiteFunc(func(_ context.Context, value scheduler.Create) error {
			if value.ReservationID == "" || !value.ReservationCurrent || !value.PolicyAllowed {
				return fmt.Errorf("task prerequisites are unsatisfied")
			}
			return nil
		}), cfg.DwellDeadline)
		if err != nil {
			return nil, err
		}
		return execution.NewScheduledToolExecutor(dispatch, register, source, material, worker, pipeline, reservations, clockOf{clock}, cfg.ExecutorID, buildIdentity)
	case "":
		return nil, fmt.Errorf("ANVILKIT_WORKER_IMPLEMENTATION must be explicitly selected; no worker fabric is assumed")
	default:
		return nil, fmt.Errorf("worker implementation %q is not available", cfg.WorkerImplementation)
	}
}

// recordingCompiler durably records every compiled context before the runner
// discloses it to a model, so context evidence exists for every turn.
type recordingCompiler struct {
	compiler *contextcompiler.Compiler
	recorder contextcompiler.EvidenceRecorder
}

func (c recordingCompiler) Compile(ctx context.Context, request contextcompiler.Request) (contextcompiler.Result, error) {
	return c.compiler.CompileAndRecord(ctx, request, c.recorder)
}

// selectContractRuntime returns the explicitly configured Contract Runtime
// behind the transport-neutral boundary (ADR-022). The kernel's controlled
// in-process implementation — real parsing, approved subjects only, bounded
// payloads, durable validation evidence — is the only implementation until
// the topology decision lands. Production configuration rejects it, and no
// implementation is ever selected implicitly.
func selectContractRuntime(cfg config.Config, validator execution.SchemaValidator, registry *agent.Registry, runtimeIdentity string, pools persistence.Pools, clock applicationTime, boms execution.BOMAuthority) (execution.ContractValidator, error) {
	switch cfg.ContractRuntimeImplementation {
	case execution.ControlledImplementation:
		if pools.Evaluation == nil {
			return nil, fmt.Errorf("the contract runtime requires the evaluation database for durable validation evidence")
		}
		var approved []agent.SchemaReference
		var policyDigests []string
		approvedPolicies := map[string]bool{}
		for _, definition := range registry.Definitions() {
			approved = append(approved, definition.InputSchema, definition.OutputSchema)
			if !approvedPolicies[definition.GuardrailPolicy.Digest] {
				approvedPolicies[definition.GuardrailPolicy.Digest] = true
				policyDigests = append(policyDigests, definition.GuardrailPolicy.Digest)
			}
		}
		runtime, err := execution.NewControlledContractRuntime(validator, approved, runtimeIdentity, registry.CatalogDigest(), policyDigests, boms)
		if err != nil {
			return nil, err
		}
		recorder, err := contractpg.New(pools.Evaluation)
		if err != nil {
			return nil, err
		}
		return contractclient.New(runtime, recorder, execution.BoundedSleeper{}, clockOf{clock}, cfg.ContractRuntimeAttempts, cfg.ContractRuntimeBackoff)
	case "":
		return nil, fmt.Errorf("ANVILKIT_CONTRACT_RUNTIME_IMPLEMENTATION must be explicitly selected; no contract runtime is assumed")
	default:
		return nil, fmt.Errorf("contract runtime implementation %q is not available", cfg.ContractRuntimeImplementation)
	}
}

// buildCommitAuthority composes the real apply-authorization issuance path.
// Issuance is a first-party Agent Service capability, not a selectable
// integration: every topology signs real authorizations, audits every
// issuance durably, and pins exactly one issued identity to each durable
// commit operation. There is no unsigned or memory-only mode.
func buildCommitAuthority(cfg config.Config, pools persistence.Pools, guard *contractguard.Guard, receipts journal.Store, clock applicationTime, runStore execution.RunStore, reader execution.InterruptReader, authoritySource authority.Source, artifactPort execution.ArtifactPort, keyring applyauth.SigningPort) (execution.CommitAuthority, error) {
	if !cfg.SigningKey.Present() || keyring == nil {
		return nil, fmt.Errorf("ANVILKIT_SIGNING_KEY is required: apply-authorization issuance has no unsigned mode")
	}
	if pools.Control == nil {
		return nil, fmt.Errorf("apply-authorization issuance requires the control database for its durable audit and issuance records")
	}
	resolver, err := execution.NewApplyAuthorityResolver(runStore, reader, authoritySource, artifactPort)
	if err != nil {
		return nil, err
	}
	audit, err := applyauthpg.New(pools.Control)
	if err != nil {
		return nil, err
	}
	issuer, err := applyauth.New(resolver, execution.RandomAuthorizationIDs{}, keyring, audit, receipts, guard, clockOf{clock}, cfg.ApplyAuthorizationTTL)
	if err != nil {
		return nil, err
	}
	issuances, err := executionpg.NewIssuanceStore(pools.Control)
	if err != nil {
		return nil, err
	}
	return execution.NewIssuerCommitAuthority(issuer, issuances)
}

// definitionTrust builds the revalidating gate over the operator-distributed
// trust material that authenticates the approved definition catalog.
// Production configuration requires both the trust root and the statement, so
// there is no environment in which an unattested catalog runs in production.
// The gate re-reads and re-verifies on every check, which is what makes trust
// material that expires or is revoked after startup stop new work.
func definitionTrust(cfg config.Config, catalogDigest string) (*agent.CatalogTrust, error) {
	if cfg.DefinitionTrustRoot == "" && cfg.DefinitionAttestation == "" {
		if cfg.Environment == config.EnvironmentProduction {
			return nil, fmt.Errorf("definition catalog attestation is required in production")
		}
		return nil, nil
	}
	if cfg.DefinitionTrustRoot == "" || cfg.DefinitionAttestation == "" {
		return nil, fmt.Errorf("definition catalog attestation requires both a trust root and a signature statement")
	}
	return agent.NewCatalogTrust(cfg.DefinitionTrustRoot, cfg.DefinitionAttestation, catalogDigest)
}

// trustAdmission is the run-creation gate. It revalidates the catalog trust
// material immediately before a new run is admitted, so a trust root past its
// freshness bound, a statement outside its validity interval, or a revoked
// signing key stops new work even though the process started while all three
// were valid.
type trustAdmission struct {
	trust *agent.CatalogTrust
	clock applicationTime
}

func (a trustAdmission) Admit(context.Context, runs.Scope) error {
	if a.trust == nil {
		return nil
	}
	if err := a.trust.Verify(a.clock.Now()); err != nil {
		details := problem.New(problem.CodeAuthorityStale, "")
		details.Detail = "the approved definition catalog is no longer attested by current trust material"
		return details
	}
	return nil
}

func digestOfBytes(raw []byte) string {
	digest := sha256.Sum256(raw)
	return "sha256:" + hex.EncodeToString(digest[:])
}

// clockOf adapts the application clock to narrow clock ports.
type clockOf struct{ inner applicationTime }

func (c clockOf) Now() time.Time { return c.inner.Now() }

// runtimeHandle defers durable runtime resolution so services constructed
// before the engine can signal it after startup. Using it before the engine
// exists fails closed.
type runtimeHandle struct{ inner workflow.Runtime }

func (h *runtimeHandle) set(runtime workflow.Runtime) { h.inner = runtime }

func (h *runtimeHandle) resolved() (workflow.Runtime, error) {
	if h.inner == nil {
		return nil, fmt.Errorf("durable runtime is not started")
	}
	return h.inner, nil
}

func (h *runtimeHandle) Start(ctx context.Context) error {
	runtime, err := h.resolved()
	if err != nil {
		return err
	}
	return runtime.Start(ctx)
}
func (h *runtimeHandle) Stop(ctx context.Context) error {
	runtime, err := h.resolved()
	if err != nil {
		return err
	}
	return runtime.Stop(ctx)
}
func (h *runtimeHandle) StartRun(ctx context.Context, input workflow.RunInput) error {
	runtime, err := h.resolved()
	if err != nil {
		return err
	}
	return runtime.StartRun(ctx, input)
}
func (h *runtimeHandle) ExecuteRun(ctx context.Context, input workflow.RunInput) (workflow.RunOutcome, error) {
	runtime, err := h.resolved()
	if err != nil {
		return workflow.RunOutcome{}, err
	}
	return runtime.ExecuteRun(ctx, input)
}
func (h *runtimeHandle) Signal(ctx context.Context, key workflow.RunKey, topic string, payload json.RawMessage, idempotencyKey string) error {
	runtime, err := h.resolved()
	if err != nil {
		return err
	}
	return runtime.Signal(ctx, key, topic, payload, idempotencyKey)
}
func (h *runtimeHandle) CancelRun(ctx context.Context, key workflow.RunKey) error {
	runtime, err := h.resolved()
	if err != nil {
		return err
	}
	return runtime.CancelRun(ctx, key)
}

var _ workflow.Runtime = (*runtimeHandle)(nil)

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
	if err := persistence.ValidateColocated(
		persistence.DatabaseTarget{Name: "migration", URL: cfg.MigrationDatabase},
		persistence.DatabaseTarget{Name: "control", URL: cfg.ControlDatabase},
		persistence.DatabaseTarget{Name: "workflow", URL: cfg.WorkflowDatabase},
		persistence.DatabaseTarget{Name: "events", URL: cfg.EventsDatabase},
		persistence.DatabaseTarget{Name: "artifacts", URL: cfg.ArtifactsDatabase},
		persistence.DatabaseTarget{Name: "evaluation", URL: cfg.EvaluationDatabase},
	); err != nil {
		return persistence.Pools{}, err
	}
	inputs := []struct {
		target    **pgxpool.Pool
		url, role string
		maximum   int32
	}{
		{&pools.Control, cfg.ControlDatabase, "agent_control_rw", int32(cfg.ControlPoolSize)},
		{&pools.Authority, cfg.ControlDatabase, "agent_authority_rw", int32(cfg.ControlPoolSize)},
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

func newOutboxDispatcher(pools persistence.Pools) (*events.Dispatcher, error) {
	if pools.Events == nil && pools.Authority == nil {
		return nil, nil
	}
	if pools.Events == nil || pools.Authority == nil {
		return nil, fmt.Errorf("outbox dispatch requires events and authority pools")
	}
	store, err := eventpg.NewOutboxStore(pools.Events)
	if err != nil {
		return nil, err
	}
	broker, err := queuepg.New(pools.Authority)
	if err != nil {
		return nil, err
	}
	return events.NewDispatcher(store, eventQueuePublisher{broker: broker}, 100)
}

type queueMessagePublisher interface {
	Publish(context.Context, queue.Message) error
}

type eventQueuePublisher struct{ broker queueMessagePublisher }

func (p eventQueuePublisher) Publish(ctx context.Context, message events.OutboxMessage) error {
	return p.broker.Publish(ctx, queue.Message{
		ID:          message.ID,
		WorkspaceID: message.WorkspaceID,
		ProjectID:   message.ProjectID,
		RunID:       message.RunID,
		TaskID:      "run-event",
		Topic:       message.Topic,
		Payload:     append([]byte(nil), message.Payload...),
	})
}

var _ events.Publisher = eventQueuePublisher{}

func agentAPIOptions(ctx context.Context, cfg config.Config, pools persistence.Pools, runtime workflow.Runtime, core *runtimeCore, observability *telemetry.Telemetry) ([]api.Option, error) {
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
	validator, err := auth.NewValidator(auth.Config{Issuers: cfg.AuthIssuers, Audience: cfg.AuthAudience, MaximumClockSkew: cfg.MaximumClockSkew}, registry, core.clock)
	if err != nil {
		return nil, err
	}
	runService := runs.NewService(core.runStore, runapp.NewRuntimeStarter(runtime), runapp.RandomIDs{}, core.clock, core.receipts, trustAdmission{trust: core.trust, clock: core.clock})
	reader, err := eventpg.NewRetainedReader(pools.Authority, core.guard, core.eventBounds, cfg.EventRetention, time.Now)
	if err != nil {
		return nil, err
	}
	cursors, err := eventpg.NewStreamCursors(pools.Authority)
	if err != nil {
		return nil, err
	}
	application := runapp.New(validator, runService, reader, events.StreamConfig{Heartbeat: cfg.Limits.SSEHeartbeat, Revalidation: cfg.AuthRevalidation, ReplayLimit: 100, Bounds: core.eventBounds, Observer: observability, WriteTimeout: cfg.SSEWriteTimeout, Cursors: cursors, MaximumConnections: cfg.Limits.SSEConnections, Deltas: core.deltas}, core.authority, core.guard, core.registry)
	application.WithInterrupts(core.interruptService)
	// The operator recovery path is part of the production API: it is
	// authenticated, scoped, role-gated against current authority, audited,
	// and idempotent on its own, so no feature gate stands in front of it.
	// Its receipts share the retention the rest of the write-idempotency
	// record keeps; the claim lease is short because it only has to outlast a
	// single in-flight recovery, and a claim held longer than that is one
	// whose process died.
	escalationReceipts, err := runapppg.NewReceipts(pools.Authority, 30*24*time.Hour, 2*time.Minute, clockOf{core.clock}.Now)
	if err != nil {
		return nil, err
	}
	application.WithEscalations(core.executor, escalationReceipts)
	policies := make(map[runs.State]interrupts.DwellPolicy)
	for _, state := range []runs.State{runs.Created, runs.Preparing, runs.Planning, runs.AwaitingInput, runs.Executing, runs.Validating, runs.AwaitingReview, runs.AwaitingApproval, runs.Committing, runs.AwaitingDomainConfirmation, runs.Conflict, runs.Cancelling, runs.Failed} {
		policies[state] = interrupts.DwellPolicy{Deadline: cfg.DwellDeadline, Owner: "agent-service-oncall"}
	}
	monitor, err := interrupts.NewMonitor(core.interruptStore, operatorAlert{}, core.clock, policies)
	if err != nil {
		return nil, err
	}
	go monitor.Run(ctx, time.Minute)
	// Cancellation fences a run's budget immediately and settles it only once
	// every physical attempt has durably reported. A cancellation that
	// interrupts an in-flight provider call cannot be concluded at request
	// time, and nothing else would ever come back to it, so the recovery sweep
	// is part of the production composition rather than an operator chore.
	cancellationRecovery, err := interrupts.NewCancellationRecovery(core.interruptStore, core.cancellationReconciler, core.executorHandle)
	if err != nil {
		return nil, err
	}
	go cancellationRecovery.Run(ctx, time.Minute)
	// The governed AgentRun mutation surface is part of the production API:
	// authentication, authorization, concurrency, idempotency, and canonical
	// schema validation each fail closed on their own, so no feature gate
	// stands in front of them.
	return []api.Option{api.WithAgentCore(application, verifier)}, nil
}

type applicationTime interface{ Now() time.Time }

func applicationClock(cfg config.Config) (applicationTime, error) {
	local := runapp.SystemClock{}
	if cfg.AuthoritativeTime.URL == "" {
		if cfg.Environment == config.EnvironmentProduction {
			return nil, fmt.Errorf("authoritative time endpoint is required")
		}
		return local, nil
	}
	client := &http.Client{
		Timeout: 2 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	source, err := securityaudit.NewHTTPTimeSource(cfg.AuthoritativeTime.URL, client)
	if err != nil {
		return nil, err
	}
	authority, err := securityaudit.NewAuthoritativeClock(source, local, cfg.MaximumClockSkew)
	if err != nil {
		return nil, err
	}
	return securityaudit.FailClosedClock{Authority: authority}, nil
}

// runtimeSignals bridges the interrupts control surface onto the canonical
// durable runtime port.
type runtimeSignals struct{ runtime workflow.Runtime }

func (r runtimeSignals) Signal(ctx context.Context, id, topic string, payload json.RawMessage, key string) error {
	runKey, err := workflow.ParseWorkflowID(id)
	if err != nil {
		return err
	}
	return r.runtime.Signal(ctx, runKey, topic, payload, key)
}
func (r runtimeSignals) StartChild(ctx context.Context, child interrupts.Child) error {
	return r.runtime.StartRun(ctx, workflow.RunInput{
		Key:   workflow.RunKey{RunID: string(child.RunID), Generation: 1},
		Scope: workflow.Scope{WorkspaceID: child.WorkspaceID, ProjectID: child.ProjectID, ActorID: child.ActorID},
	})
}
func (r runtimeSignals) StopRun(ctx context.Context, _ runs.Scope, id runs.ID, generation uint64) error {
	return r.runtime.CancelRun(ctx, workflow.RunKey{RunID: string(id), Generation: generation})
}
func (r runtimeSignals) ResumeRun(ctx context.Context, scope runs.Scope, snapshot runs.Snapshot, _ string, _ string) error {
	return r.runtime.StartRun(ctx, workflow.RunInput{
		Key:   workflow.RunKey{RunID: string(snapshot.RunID), Generation: snapshot.ExecutionGeneration},
		Scope: workflow.Scope{WorkspaceID: scope.WorkspaceID, ProjectID: scope.ProjectID, ActorID: scope.ActorID},
	})
}

type workflowLeaseRevoker struct{ pool *pgxpool.Pool }

func (r workflowLeaseRevoker) RevokeRun(ctx context.Context, scope runs.Scope, id runs.ID) error {
	if r.pool == nil {
		return nil
	}
	_, err := r.pool.Exec(ctx, `DELETE FROM agent_workflow.executor_leases WHERE workspace_id=$1 AND project_id=$2 AND workflow_id LIKE $3`, scope.WorkspaceID, scope.ProjectID, string(id)+":g%")
	return err
}

// budgetExposure surfaces the budget controller's held-exposure observations
// into structured telemetry; a review-threshold crossing logs at warning so
// operators see approaching exposure before reservations start denying.
type budgetExposure struct{}

func (budgetExposure) ObserveExposure(_ context.Context, rootRunID string, heldMicros, observedMicros int64, review bool) error {
	if review {
		slog.Warn("budget exposure requires review", "root_run_id", rootRunID, "held_micros", heldMicros, "observed_micros", observedMicros)
		return nil
	}
	slog.Debug("budget exposure", "root_run_id", rootRunID, "held_micros", heldMicros, "observed_micros", observedMicros)
	return nil
}

type operatorAlert struct{}

func (operatorAlert) Alert(_ context.Context, kind string, scope runs.Scope, id runs.ID, state runs.State) error {
	slog.Error("agent run requires operator attention", "alert", kind, "workspace_id", scope.WorkspaceID, "project_id", scope.ProjectID, "run_id", id, "state", state)
	return nil
}

// authoritySeed is the operator-supplied scoped authority document: the
// governance material, the exact workspace/project scope it binds, and the
// subjects the workspace admits. It seeds the durable scoped authority store;
// it is never itself the runtime authority source.
type authoritySeed struct {
	Scope struct {
		WorkspaceID string `json:"workspaceId"`
		ProjectID   string `json:"projectId"`
	} `json:"scope"`
	Subjects []struct {
		ActorID string `json:"actorId"`
		Role    string `json:"role"`
	} `json:"subjects"`
	Definition  json.RawMessage `json:"definition"`
	ContractBOM json.RawMessage `json:"contractBomReference"`
	Policy      json.RawMessage `json:"policy"`
	Budget      json.RawMessage `json:"budget"`
}

func loadAuthoritySeed(path string, guard *contractguard.Guard) (authoritySeed, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return authoritySeed{}, fmt.Errorf("read run authority: %w", err)
	}
	var payload authoritySeed
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&payload); err != nil {
		return authoritySeed{}, fmt.Errorf("decode run authority: %w", err)
	}
	var extra any
	if err := decoder.Decode(&extra); err != io.EOF {
		return authoritySeed{}, fmt.Errorf("decode run authority: trailing JSON")
	}
	if payload.Scope.WorkspaceID == "" || payload.Scope.ProjectID == "" {
		return authoritySeed{}, fmt.Errorf("run authority requires the workspace and project scope it binds")
	}
	if len(payload.Subjects) == 0 {
		return authoritySeed{}, fmt.Errorf("run authority requires at least one admitted subject")
	}
	for _, subject := range payload.Subjects {
		if subject.ActorID == "" || subject.Role == "" {
			return authoritySeed{}, fmt.Errorf("run authority subjects require actor identity and role")
		}
	}
	if len(payload.Definition) == 0 || len(payload.ContractBOM) == 0 || len(payload.Policy) == 0 || len(payload.Budget) == 0 {
		return authoritySeed{}, fmt.Errorf("run authority is incomplete")
	}
	probe := runs.Snapshot{Kind: "AgentRun", RunID: "run.authority-validation", RootRunID: "run.authority-validation", WorkspaceID: "workspace.authority-validation", ActorID: "actor.authority-validation", Domain: "platform-agent", Operation: "artifact-validation", Target: runs.Target{Type: "page", ID: "page.authority-validation", WorkspaceID: "workspace.authority-validation", ProjectID: "project.authority-validation"}, Definition: payload.Definition, ContractBOM: payload.ContractBOM, Policy: payload.Policy, Budget: payload.Budget, Idempotency: runs.IdempotencyProjection{Scope: "workspace.authority-validation:create-run", Key: "authority-validation", CanonicalRequestDigest: "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}, Status: runs.Created, Version: 1, ExecutionGeneration: 1, CreatedAt: time.Unix(0, 0), UpdatedAt: time.Unix(0, 0)}
	probeBytes, err := json.Marshal(probe)
	if err != nil {
		return authoritySeed{}, fmt.Errorf("marshal run authority probe: %w", err)
	}
	findings := guard.Validate(context.Background(), contractguard.APIIn, "anvilkit://schema/agent-run?digest=sha256:e293860d680a93c9fa5d8c3907201ac3a6a54b7a81cbb81fd5bcb6f332497564", probeBytes)
	if len(findings) != 0 {
		return authoritySeed{}, fmt.Errorf("run authority violates pinned AgentRun references: %v", findings)
	}
	return payload, nil
}

// seedDurableAuthority validates the operator-supplied authority document and
// seeds the durable scoped authority store with it. The store — not the file —
// answers every later read, so revocations recorded against the scope are
// observed by every boundary on its next re-read.
func seedDurableAuthority(ctx context.Context, path string, guard *contractguard.Guard, grants authority.Grants, pool *pgxpool.Pool, clock applicationTime) (*authoritypg.Store, error) {
	if guard == nil {
		return nil, fmt.Errorf("the durable authority source requires the contract guard")
	}
	if pool == nil {
		return nil, fmt.Errorf("the durable authority source requires the authority database")
	}
	seed, err := loadAuthoritySeed(path, guard)
	if err != nil {
		return nil, err
	}
	store, err := authoritypg.New(pool, clockOf{clock}.Now)
	if err != nil {
		return nil, err
	}
	subjects := make([]authoritypg.Subject, 0, len(seed.Subjects))
	for _, subject := range seed.Subjects {
		subjects = append(subjects, authoritypg.Subject{WorkspaceID: seed.Scope.WorkspaceID, ActorID: subject.ActorID, Role: subject.Role})
	}
	if err := store.Seed(ctx, authoritypg.Binding{
		WorkspaceID: seed.Scope.WorkspaceID,
		ProjectID:   seed.Scope.ProjectID,
		Definition:  seed.Definition,
		ContractBOM: seed.ContractBOM,
		Policy:      seed.Policy,
		Budget:      seed.Budget,
		Grants:      grants,
	}, subjects); err != nil {
		return nil, err
	}
	return store, nil
}
