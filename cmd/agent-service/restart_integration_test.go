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
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/ancyloce/anvilkit-agent-service/internal/api"
	"github.com/ancyloce/anvilkit-agent-service/internal/budget"
	"github.com/ancyloce/anvilkit-agent-service/internal/canonical"
	"github.com/ancyloce/anvilkit-agent-service/internal/config"
	contractguard "github.com/ancyloce/anvilkit-agent-service/internal/contracts"
	"github.com/ancyloce/anvilkit-agent-service/internal/domaincommit"
	commitpg "github.com/ancyloce/anvilkit-agent-service/internal/domaincommit/postgres"
	"github.com/ancyloce/anvilkit-agent-service/internal/execution"
	"github.com/ancyloce/anvilkit-agent-service/internal/interrupts"
	"github.com/ancyloce/anvilkit-agent-service/internal/journal"
	"github.com/ancyloce/anvilkit-agent-service/internal/persistence"
	"github.com/ancyloce/anvilkit-agent-service/internal/runapp"
	"github.com/ancyloce/anvilkit-agent-service/internal/runs"
	"github.com/ancyloce/anvilkit-agent-service/internal/telemetry"
	"github.com/ancyloce/anvilkit-agent-service/internal/workflow"
	workflowdbos "github.com/ancyloce/anvilkit-agent-service/internal/workflow/dbos"
)

// The restart matrix kills a real production-composed process at exact
// durable checkpoints and proves a successor process recovers the workflow to
// its correct outcome with every external effect exactly once. The crashing
// process composes through buildRuntimeDependencies — the composition root's
// own assembly — with a single port wrapped for crash injection, so the
// pipeline under the kill is the production pipeline.
const (
	restartCheckpointEnv = "ANVILKIT_RESTART_CHECKPOINT"
	restartCrashCode     = 137
	restartTrace         = "00-0123456789abcdef0123456789abcdef-0123456789abcdef-01"
)

type restartCheckpoint struct {
	name string
	// script is the controlled model script the checkpoint's run needs.
	script string
	// approveBeforeCrash reports whether the crashing process must decide the
	// approval so the workflow reaches the commit boundary.
	approveBeforeCrash bool
	// approveAfterRecovery reports whether the recovering process finds the
	// approval still undecided and must decide it.
	approveAfterRecovery bool
	// terminal is the outcome recovery must reach.
	terminal workflow.TerminalState
}

func restartCheckpoints() []restartCheckpoint {
	return []restartCheckpoint{
		{name: "budget-reserved", script: "final", approveAfterRecovery: true, terminal: workflow.TerminalCompleted},
		{name: "approval-opened", script: "final", approveAfterRecovery: true, terminal: workflow.TerminalCompleted},
		{name: "worker-accepted", script: "tool-echo,final", approveAfterRecovery: true, terminal: workflow.TerminalCompleted},
		{name: "authorization-issued", script: "final", approveBeforeCrash: true, terminal: workflow.TerminalCompleted},
		{name: "domain-intent-marked", script: "final", approveBeforeCrash: true, terminal: workflow.TerminalFailed},
		{name: "journal-finalized", script: "final", approveBeforeCrash: true, terminal: workflow.TerminalCompleted},
	}
}

// cursorSpool is the durable directory both processes share, so a
// disconnect record the first process held is still there for the second.
func restartEnvironment(databaseURL, authorityPath, trustPath, cursorSpool, script string) map[string]string {
	return map[string]string{
		"ANVILKIT_AUTH_TRUST_SNAPSHOT":             trustPath,
		"ANVILKIT_STREAM_CURSOR_SPOOL":             cursorSpool,
		"ANVILKIT_AUTH_ISSUERS":                    "issuer",
		"ANVILKIT_ENVIRONMENT":                     "development",
		"ANVILKIT_CONTRACT_ROOT":                   "../..",
		"ANVILKIT_CONTROL_DATABASE_URL":            databaseURL,
		"ANVILKIT_WORKFLOW_DATABASE_URL":           databaseURL,
		"ANVILKIT_EVENTS_DATABASE_URL":             databaseURL,
		"ANVILKIT_ARTIFACTS_DATABASE_URL":          databaseURL,
		"ANVILKIT_EVALUATION_DATABASE_URL":         databaseURL,
		"ANVILKIT_MODEL_IMPLEMENTATION":            "controlled-fake",
		"ANVILKIT_TOOL_IMPLEMENTATION":             "controlled-fake",
		"ANVILKIT_DOMAIN_IMPLEMENTATION":           "controlled-fake",
		"ANVILKIT_CONTRACT_RUNTIME_IMPLEMENTATION": "controlled-fake",
		"ANVILKIT_WORKER_IMPLEMENTATION":           "controlled-fake",
		"ANVILKIT_CONTROLLED_MODEL_SCRIPT":         script,
		"ANVILKIT_SIGNING_KEY":                     "restart-signing-material-0123456789",
		"ANVILKIT_ENCRYPTION_KEY":                  "restart-encryption-material-0123456789",
		"ANVILKIT_RUN_AUTHORITY_FILE":              authorityPath,
		"ANVILKIT_EXECUTOR_ID":                     "restart-executor-1",
		"ANVILKIT_DOMAIN_RECONCILE_LIMIT":          "2",
		"ANVILKIT_DOMAIN_RETRY_BASE":               "100ms",
		"ANVILKIT_DOMAIN_RETRY_CAP":                "200ms",
	}
}

// restartComposition is the shared production composition both processes use.
type restartComposition struct {
	cfg     config.Config
	pools   persistence.Pools
	core    *runtimeCore
	config  execution.Config
	handle  *runtimeHandle
	runtime *workflowdbos.Runtime
}

func composeForRestart(ctx context.Context, t *testing.T, mutate func(*execution.Config)) *restartComposition {
	t.Helper()
	cfg, err := config.Load()
	if err != nil {
		t.Fatal(err)
	}
	if err := cfg.Validate(); err != nil {
		t.Fatal(err)
	}
	pools, err := openPersistencePools(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	guard, err := contractguard.NewGuard(cfg.ContractRoot)
	if err != nil {
		t.Fatal(err)
	}
	clock, auditClock, err := applicationClock(cfg)
	if err != nil {
		t.Fatal(err)
	}
	receipts := journal.NewMemoryStore()
	protectedAudit, closeAudit, err := buildProtectedAudit(ctx, cfg, auditClock, receipts, slog.Default())
	if err != nil {
		t.Fatal(err)
	}
	defer closeAudit()
	handle := &runtimeHandle{}
	core, executionConfig, err := buildRuntimeDependencies(ctx, cfg, pools, guard, receipts, clock, protectedAudit, handle)
	if err != nil {
		t.Fatal(err)
	}
	if mutate != nil {
		mutate(&executionConfig)
	}
	executor, err := execution.New(executionConfig)
	if err != nil {
		t.Fatal(err)
	}
	core.setExecutor(executor)
	runtime, err := workflowdbos.New(ctx, workflowdbos.Config{DatabaseURL: cfg.WorkflowDatabase, Schema: "agent_dbos", ExecutorID: cfg.ExecutorID, ApplicationVersion: "restart-proof", Logger: slog.Default()}, executor)
	if err != nil {
		t.Fatal(err)
	}
	handle.set(runtime)
	if err := runtime.Start(ctx); err != nil {
		t.Fatal(err)
	}
	return &restartComposition{cfg: cfg, pools: pools, core: core, config: executionConfig, handle: handle, runtime: runtime}
}

func (c *restartComposition) runService(t *testing.T) *runs.Service {
	t.Helper()
	return runs.NewService(c.core.runStore, runapp.NewRuntimeStarter(c.runtime), runapp.RandomIDs{}, c.core.clock, c.core.receipts, trustAdmission{trust: c.core.trust, clock: c.core.clock})
}

// decideApprovalWhenOpen polls for the run's undecided approval request and
// decides it as the reviewer through the production interrupts service.
func decideApprovalWhenOpen(ctx context.Context, t *testing.T, composition *restartComposition, observe *pgxpool.Pool, runID, key string, deadline time.Time) bool {
	t.Helper()
	for time.Now().Before(deadline) {
		var requestID, actionDigest string
		var version uint64
		// The reviewer states the action they decided; the service proves it
		// is the digest the open request carries.
		err := observe.QueryRow(ctx, `SELECT request_id,decision_version,action_digest FROM agent_control.approval_requests WHERE workspace_id='workspace' AND project_id='project' AND run_id=$1 AND decided_at IS NULL`, runID).Scan(&requestID, &version, &actionDigest)
		if err == nil {
			snapshot, getErr := composition.core.runStore.Get(ctx, runs.Scope{WorkspaceID: "workspace", ProjectID: "project", ActorID: "reviewer"}, runs.ID(runID))
			if getErr != nil {
				t.Fatal(getErr)
			}
			if _, decideErr := composition.core.interruptService.DecideApproval(ctx, interrupts.Write{
				Scope:           runs.Scope{WorkspaceID: "workspace", ProjectID: "project", ActorID: "reviewer"},
				RunID:           runs.ID(runID),
				ExpectedVersion: snapshot.Version,
				IdempotencyKey:  key,
				Traceparent:     restartTrace,
			}, interrupts.ApprovalDecisionCommand{RequestID: interrupts.RequestID(requestID), RequestVersion: version, Decision: interrupts.DecisionApprove, ActionDigest: actionDigest}); decideErr == nil {
				return true
			}
			// A version race retries on the next poll.
		}
		time.Sleep(50 * time.Millisecond)
	}
	return false
}

// crashNow reports the reached checkpoint and hard-kills the process — the
// closest a test can come to SIGKILL from inside its own workflow goroutine.
func crashNow(checkpoint string) {
	fmt.Fprintf(os.Stderr, "restart checkpoint reached: %s\n", checkpoint)
	os.Exit(restartCrashCode)
}

type crashAfterBudgetReserve struct{ execution.BudgetController }

func (c crashAfterBudgetReserve) ReserveInitial(ctx context.Context, estimate budget.Estimate, generation budget.Generation) (budget.Reservation, error) {
	reservation, err := c.BudgetController.ReserveInitial(ctx, estimate, generation)
	if err != nil {
		return reservation, err
	}
	crashNow("budget-reserved")
	return reservation, nil
}

type crashAfterApprovalOpen struct{ execution.InterruptWriter }

func (c crashAfterApprovalOpen) RequestApproval(ctx context.Context, write interrupts.Write, open interrupts.OpenApproval) (interrupts.ApprovalRequest, interrupts.OperationResult, error) {
	request, result, err := c.InterruptWriter.RequestApproval(ctx, write, open)
	if err != nil {
		return request, result, err
	}
	crashNow("approval-opened")
	return request, result, nil
}

type crashAfterWorkerAccept struct{ execution.ToolExecutor }

func (c crashAfterWorkerAccept) Execute(ctx context.Context, invocation execution.ToolInvocation) (execution.ToolResult, error) {
	result, err := c.ToolExecutor.Execute(ctx, invocation)
	if err != nil {
		return result, err
	}
	crashNow("worker-accepted")
	return result, nil
}

type crashAfterIssuance struct{ execution.CommitAuthority }

func (c crashAfterIssuance) Issue(ctx context.Context, request execution.AuthorizationRequest) (execution.IssuedAuthorization, error) {
	issued, err := c.CommitAuthority.Issue(ctx, request)
	if err != nil {
		return issued, err
	}
	crashNow("authorization-issued")
	return issued, nil
}

// crashInsideDomainWindow kills the process after the durable submitted-
// intent mark and before the command reaches the authoritative owner — the
// exact MarkIssued → Domain.Commit crash window.
type crashInsideDomainWindow struct{ execution.DomainPort }

func (c crashInsideDomainWindow) Commit(context.Context, execution.DomainCommand) (execution.DomainOutcome, error) {
	crashNow("domain-intent-marked")
	return execution.DomainOutcome{}, nil
}

type crashAfterJournalFinalize struct{ domaincommit.Store }

func (c crashAfterJournalFinalize) Finalize(ctx context.Context, scope domaincommit.Scope, id string, status domaincommit.Status, at time.Time) error {
	if err := c.Store.Finalize(ctx, scope, id, status, at); err != nil {
		return err
	}
	crashNow("journal-finalized")
	return nil
}

// TestRestartCrashWorkload is the crash-side workload. It runs only when the
// parent restart test re-executes this binary with the checkpoint set.
func TestRestartCrashWorkload(t *testing.T) {
	checkpoint := os.Getenv(restartCheckpointEnv)
	if checkpoint == "" {
		t.Skip("restart crash workload: not invoked")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	composition := composeForRestart(ctx, t, func(executionConfig *execution.Config) {
		switch checkpoint {
		case "budget-reserved":
			executionConfig.Budget = crashAfterBudgetReserve{executionConfig.Budget}
		case "approval-opened":
			executionConfig.InterruptWriter = crashAfterApprovalOpen{executionConfig.InterruptWriter}
		case "worker-accepted":
			executionConfig.Tools = crashAfterWorkerAccept{executionConfig.Tools}
		case "authorization-issued":
			executionConfig.CommitAuthority = crashAfterIssuance{executionConfig.CommitAuthority}
		case "domain-intent-marked":
			executionConfig.Domain = crashInsideDomainWindow{executionConfig.Domain}
		case "journal-finalized":
			executionConfig.Submissions = crashAfterJournalFinalize{executionConfig.Submissions}
		default:
			t.Fatalf("unknown restart checkpoint %q", checkpoint)
		}
	})
	defer composition.pools.Close()

	scope := runs.Scope{WorkspaceID: "workspace", ProjectID: "project", ActorID: "actor"}
	current, err := composition.core.authority.Current(ctx, scope.AuthorityScope())
	if err != nil {
		t.Fatal(err)
	}
	managerID, managerDigest := managerReference(t)
	raw := []byte(`{"kind":"CreateAgentRunRequest","definition":{"definitionId":"` + managerID + `","definitionDigest":"` + managerDigest + `"},"operation":"page-change","target":{"targetType":"page","targetId":"page-restart-001","workspaceId":"workspace","projectId":"project"},"input":{"userInput":"Restart the hero section."}}`)
	digest, err := canonical.Digest(raw)
	if err != nil {
		t.Fatal(err)
	}
	outcome, err := composition.runService(t).Create(ctx, runs.CreateInput{Scope: scope, Key: "restart-create-1", ClaimedDigest: digest, Traceparent: restartTrace, Raw: raw, Authority: current})
	if err != nil {
		t.Fatal(err)
	}
	observe, err := pgxpool.New(ctx, composition.cfg.ControlDatabase)
	if err != nil {
		t.Fatal(err)
	}
	defer observe.Close()
	deadline := time.Now().Add(80 * time.Second)
	if os.Getenv("ANVILKIT_RESTART_APPROVE") == "1" {
		if !decideApprovalWhenOpen(ctx, t, composition, observe, string(outcome.Snapshot.RunID), "restart-approve-crash", deadline) {
			os.Exit(3)
		}
	}
	// The crash checkpoint fires inside the workflow; reaching this deadline
	// means it never did.
	<-ctx.Done()
	os.Exit(3)
}

func TestRestartRecoveryAcrossProductionCheckpoints(t *testing.T) {
	base := os.Getenv("POSTGRES_TEST_URL")
	if base == "" {
		t.Skip("POSTGRES_TEST_URL is not set")
	}
	for _, checkpoint := range restartCheckpoints() {
		t.Run(checkpoint.name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 4*time.Minute)
			defer cancel()
			databaseURL := isolatedSliceDatabase(t, ctx, base)
			migration, err := pgx.Connect(ctx, databaseURL)
			if err != nil {
				t.Fatal(err)
			}
			if err := persistence.NewMigrator(migration).Apply(ctx); err != nil {
				t.Fatal(err)
			}
			if err := migration.Close(ctx); err != nil {
				t.Fatal(err)
			}
			managerID, managerDigest := managerReference(t)
			authorityPath := writeRunAuthority(t, managerID, managerDigest)
			identities := mintBearers(t)
			environment := restartEnvironment(databaseURL, authorityPath, identities.trustPath, filepath.Join(t.TempDir(), "stream-cursors"), checkpoint.script)
			for name, value := range environment {
				t.Setenv(name, value)
			}

			// Phase 1: the crashing process — this test binary re-executed with
			// only the crash workload selected — dies at the checkpoint.
			child := exec.CommandContext(ctx, os.Args[0], "-test.run", "^TestRestartCrashWorkload$", "-test.v", "-test.timeout", "120s")
			child.Env = os.Environ()
			child.Env = append(child.Env, restartCheckpointEnv+"="+checkpoint.name)
			if checkpoint.approveBeforeCrash {
				child.Env = append(child.Env, "ANVILKIT_RESTART_APPROVE=1")
			}
			output, runErr := child.CombinedOutput()
			var exitError *exec.ExitError
			if runErr == nil || !errors.As(runErr, &exitError) || exitError.ExitCode() != restartCrashCode {
				t.Fatalf("crash process err=%v output=%s", runErr, output)
			}

			observe, err := pgxpool.New(ctx, databaseURL)
			if err != nil {
				t.Fatal(err)
			}
			defer observe.Close()
			var runID string
			if err := observe.QueryRow(ctx, `SELECT run_id FROM agent_control.agent_runs`).Scan(&runID); err != nil {
				t.Fatalf("exactly one run must exist after the crash: %v", err)
			}
			if checkpoint.name == "domain-intent-marked" {
				assertCount(t, ctx, observe, `SELECT count(*) FROM agent_control.domain_operations WHERE status='issued'`, 1)
				assertCount(t, ctx, observe, `SELECT count(*) FROM agent_control.domain_redemptions`, 0)
			}

			// Phase 2: a successor process with the crashed executor's identity
			// recovers the pending workflow over the same durable state.
			composition := composeForRestart(ctx, t, nil)
			defer composition.pools.Close()
			defer func() {
				if err := composition.runtime.Stop(context.Background()); err != nil {
					t.Errorf("stop recovery runtime: %v", err)
				}
			}()
			input := workflow.RunInput{Key: workflow.RunKey{RunID: runID, Generation: 1}, Scope: workflow.Scope{WorkspaceID: "workspace", ProjectID: "project", ActorID: "actor"}, Traceparent: restartTrace}
			outcomes := make(chan workflow.RunOutcome, 1)
			failures := make(chan error, 1)
			go func() {
				outcome, err := composition.runtime.ExecuteRun(ctx, input)
				if err != nil {
					failures <- err
					return
				}
				outcomes <- outcome
			}()
			deadline := time.Now().Add(2 * time.Minute)
			if checkpoint.approveAfterRecovery {
				if !decideApprovalWhenOpen(ctx, t, composition, observe, runID, "restart-approve-recovery", deadline) {
					t.Fatal("the recovered run never opened its approval request")
				}
			}
			if checkpoint.name == "domain-intent-marked" {
				// The recovered run holds at the submit boundary — never
				// resending — counts its uncertain reconciliations durably, and
				// escalates within the bounded window. The audited operator
				// resolution then decides it, over the production HTTP surface
				// with a verified operator bearer: this is the same path an
				// on-call operator would use, not a direct store write.
				journalStore, err := commitpg.New(composition.pools.Control)
				if err != nil {
					t.Fatal(err)
				}
				journalScope := domaincommit.Scope{WorkspaceID: "workspace", ProjectID: "project"}
				var operation domaincommit.Operation
				for {
					if time.Now().After(deadline) {
						t.Fatal("the held submission never escalated")
					}
					candidate, found, err := journalStore.LatestForRun(ctx, journalScope, runs.ID(runID))
					if err != nil {
						t.Fatal(err)
					}
					if found && candidate.Status == domaincommit.Escalated {
						operation = candidate
						break
					}
					time.Sleep(50 * time.Millisecond)
				}
				if operation.ReconcileAttempts < 2 || operation.FirstUncertainAt.IsZero() {
					t.Fatalf("escalated operation = %+v, want the durable uncertainty trail", operation)
				}
				resolveEscalationOverAPI(ctx, t, composition, identities, runID, operation.ID)
				settled, err := journalStore.Get(ctx, journalScope, operation.ID)
				if err != nil {
					t.Fatal(err)
				}
				if settled.Status != domaincommit.Rejected || settled.ResolvedBy != "operator" || settled.ResolutionBasis == "" {
					t.Fatalf("resolved operation = %+v, want an audited operator resolution", settled)
				}
			}
			select {
			case err := <-failures:
				dumpRestartDiagnostics(t, ctx, observe, runID)
				t.Fatal(err)
			case outcome := <-outcomes:
				if outcome.Terminal != checkpoint.terminal {
					dumpRestartDiagnostics(t, ctx, observe, runID)
					t.Fatalf("recovered outcome = %+v, want %s", outcome, checkpoint.terminal)
				}
			case <-time.After(2 * time.Minute):
				dumpRestartDiagnostics(t, ctx, observe, runID)
				t.Fatal("the recovered workflow never settled")
			}

			// Exactly-once external effects across both processes.
			assertCount(t, ctx, observe, `SELECT count(*) FROM agent_control.agent_runs`, 1)
			assertCount(t, ctx, observe, `SELECT count(*) FROM agent_control.budget_reservations WHERE reservation_id LIKE 'budget:%'`, 1)
			assertCount(t, ctx, observe, `SELECT count(*) FROM agent_control.approval_requests`, 1)
			switch checkpoint.name {
			case "worker-accepted":
				assertCount(t, ctx, observe, `SELECT count(*) FROM agent_workflow.worker_attempts WHERE state='accepted'`, 1)
				assertCount(t, ctx, observe, `SELECT count(*) FROM agent_workflow.worker_results`, 1)
				assertCount(t, ctx, observe, `SELECT count(*) FROM agent_workflow.worker_outputs`, 1)
			case "authorization-issued", "journal-finalized":
				assertCount(t, ctx, observe, `SELECT count(*) FROM agent_control.apply_authorizations`, 1)
				assertCount(t, ctx, observe, `SELECT count(*) FROM agent_control.commit_issuances`, 1)
				assertCount(t, ctx, observe, `SELECT count(*) FROM agent_control.domain_redemptions`, 1)
			case "domain-intent-marked":
				assertCount(t, ctx, observe, `SELECT count(*) FROM agent_control.apply_authorizations`, 1)
				assertCount(t, ctx, observe, `SELECT count(*) FROM agent_control.domain_redemptions`, 0)
				// The audited resolver is the authenticated operator identity
				// the production path derived from the verified bearer, not
				// anything the request body claimed.
				assertCount(t, ctx, observe, `SELECT count(*) FROM agent_control.domain_operations WHERE status='rejected' AND resolved_by='operator'`, 1)
			}
			var state string
			if err := observe.QueryRow(ctx, `SELECT state FROM agent_control.agent_runs WHERE run_id=$1`, runID).Scan(&state); err != nil {
				t.Fatal(err)
			}
			want := "completed"
			if checkpoint.terminal == workflow.TerminalFailed {
				want = "failed"
			}
			if state != want {
				t.Fatalf("recovered run state = %s, want %s", state, want)
			}
			// The budget settlement matches the outcome: completion releases
			// the standing hold; the operator-rejected run keeps it held.
			var released bool
			if err := observe.QueryRow(ctx, `SELECT released FROM agent_control.budget_reservations WHERE reservation_id LIKE 'budget:%'`).Scan(&released); err != nil {
				t.Fatal(err)
			}
			if released != (checkpoint.terminal == workflow.TerminalCompleted) {
				t.Fatalf("budget released=%v for terminal %s", released, checkpoint.terminal)
			}
		})
	}
}

// dumpRestartDiagnostics logs the durable trail a failed recovery leaves —
// the recorded step outputs and the run's terminal problem — so a restart
// regression names the exact step that diverged.
func dumpRestartDiagnostics(t *testing.T, ctx context.Context, pool *pgxpool.Pool, runID string) {
	t.Helper()
	rows, err := pool.Query(ctx, `SELECT function_id, function_name, COALESCE(output,''), COALESCE(error,'') FROM agent_dbos.operation_outputs ORDER BY function_id`)
	if err != nil {
		t.Logf("step outputs unavailable: %v", err)
	} else {
		defer rows.Close()
		for rows.Next() {
			var id int
			var name, output, failure string
			if err := rows.Scan(&id, &name, &output, &failure); err != nil {
				t.Logf("scan step output: %v", err)
				break
			}
			if len(output) > 300 {
				output = output[:300] + "..."
			}
			t.Logf("step %02d %-24s output=%s error=%s", id, name, output, failure)
		}
	}
	var snapshot string
	if err := pool.QueryRow(ctx, `SELECT snapshot::text FROM agent_control.agent_runs WHERE run_id=$1`, runID).Scan(&snapshot); err == nil {
		t.Logf("run snapshot: %s", snapshot)
	}
}

func assertCount(t *testing.T, ctx context.Context, pool *pgxpool.Pool, query string, want int) {
	t.Helper()
	var got int
	if err := pool.QueryRow(ctx, query).Scan(&got); err != nil {
		t.Fatalf("%s: %v", query, err)
	}
	if got != want {
		t.Fatalf("%s = %d, want %d", query, got, want)
	}
}

// operatorAPI builds the production HTTP surface over the recovery
// composition. It is the composition root's own `agentAPIOptions`, so what the
// operator calls in these proofs is the deployed API, not a test shim.
func operatorAPI(ctx context.Context, t *testing.T, composition *restartComposition) *httptest.Server {
	t.Helper()
	redactor := telemetry.NewRedactor([]string{composition.cfg.SigningKey.RedactionValue(), composition.cfg.EncryptionKey.RedactionValue()})
	observability, err := telemetry.New(composition.cfg.ServiceName, nil, redactor)
	if err != nil {
		t.Fatal(err)
	}
	options, err := agentAPIOptions(ctx, composition.cfg, composition.pools, composition.runtime, composition.core, observability)
	if err != nil {
		t.Fatal(err)
	}
	if len(options) == 0 {
		t.Fatal("the production API surface was not composed")
	}
	server := httptest.NewServer(api.New(readyAlways{}, options...))
	t.Cleanup(server.Close)
	return server
}

// resolveEscalationOverAPI drives the production operator recovery path and
// proves what guards it. The denial cases run first, against the very
// escalation the success case then resolves: a caller without the operate
// scope, a caller that holds the scope but is not admitted under the operator
// role, a caller reaching across a workspace boundary, and a decision naming
// an operation this run does not hold are each refused while the run is still
// resolvable — so none of them can be passing for the wrong reason.
func resolveEscalationOverAPI(ctx context.Context, t *testing.T, composition *restartComposition, identities bearers, runID, operationID string) {
	t.Helper()
	server := operatorAPI(ctx, t, composition)
	client := &http.Client{Timeout: 30 * time.Second}
	runPath := "/v1/workspaces/workspace/agent-runs/" + runID

	call := func(token, path, key, etag string, body []byte) (int, []byte, http.Header) {
		t.Helper()
		var reader *bytes.Reader
		if body == nil {
			reader = bytes.NewReader(nil)
		} else {
			reader = bytes.NewReader(body)
		}
		request, err := http.NewRequestWithContext(ctx, http.MethodPost, server.URL+path, reader)
		if err != nil {
			t.Fatal(err)
		}
		request.Header.Set("Authorization", "Bearer "+token)
		request.Header.Set("traceparent", restartTrace)
		request.Header.Set("Idempotency-Key", key)
		request.Header.Set("If-Match", etag)
		digest, err := canonical.Digest(body)
		if err != nil {
			t.Fatal(err)
		}
		request.Header.Set("X-AnvilKit-Request-Digest", digest)
		response, err := client.Do(request)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = response.Body.Close() }()
		payload, err := io.ReadAll(response.Body)
		if err != nil {
			t.Fatal(err)
		}
		return response.StatusCode, payload, response.Header
	}

	etag := func() string {
		t.Helper()
		request, err := http.NewRequestWithContext(ctx, http.MethodGet, server.URL+runPath, nil)
		if err != nil {
			t.Fatal(err)
		}
		request.Header.Set("Authorization", "Bearer "+identities.operator)
		request.Header.Set("traceparent", restartTrace)
		response, err := client.Do(request)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = response.Body.Close() }()
		_, _ = io.Copy(io.Discard, response.Body)
		if response.StatusCode != http.StatusOK || response.Header.Get("ETag") == "" {
			t.Fatalf("read held run: status=%d etag=%q", response.StatusCode, response.Header.Get("ETag"))
		}
		return response.Header.Get("ETag")
	}

	body, err := json.Marshal(runapp.EscalationResolution{
		Kind:        runapp.EscalationResolutionKind,
		OperationID: operationID,
		Outcome:     execution.DomainRejected,
		Basis:       restartEvidenceBasis,
	})
	if err != nil {
		t.Fatal(err)
	}

	held := etag()
	// The run actor can write to its own run but holds no operate scope.
	if status, payload, _ := call(identities.actor, runPath+"/domain-operations/"+operationID+"/resolution", "restart-resolve-denied-scope", held, body); status != http.StatusForbidden {
		t.Fatalf("actor resolution status=%d body=%s, want the operate scope to be required", status, payload)
	}
	// The impostor holds the operate scope but is admitted under the actor
	// role, so current authority denies the recovery.
	if status, payload, _ := call(identities.impostor, runPath+"/domain-operations/"+operationID+"/resolution", "restart-resolve-denied-role", held, body); status != http.StatusForbidden {
		t.Fatalf("impostor resolution status=%d body=%s, want the operator role to be required", status, payload)
	}
	// A workspace the operator's verified authority does not cover is
	// indistinguishable from a run that does not exist.
	if status, payload, _ := call(identities.operator, "/v1/workspaces/other-workspace/agent-runs/"+runID+"/domain-operations/"+operationID+"/resolution", "restart-resolve-cross-tenant", held, body); status != http.StatusNotFound {
		t.Fatalf("cross-tenant resolution status=%d body=%s, want non-disclosure", status, payload)
	}
	// A decision naming a different operation never lands on this run's one.
	otherBody, err := json.Marshal(runapp.EscalationResolution{Kind: runapp.EscalationResolutionKind, OperationID: "domain.not-this-operation", Outcome: execution.DomainRejected, Basis: restartEvidenceBasis})
	if err != nil {
		t.Fatal(err)
	}
	if status, payload, _ := call(identities.operator, runPath+"/domain-operations/domain.not-this-operation/resolution", "restart-resolve-wrong-operation", held, otherBody); status != http.StatusConflict {
		t.Fatalf("mismatched operation status=%d body=%s, want a conflict", status, payload)
	}
	// The canonical ResolveDomainOperationRequest contract closes the object,
	// so a body smuggling its own resolving operator is refused before
	// anything is decoded: the audited resolver can only ever be the
	// authenticated identity.
	smuggled := []byte(`{"kind":"` + runapp.EscalationResolutionKind + `","operationId":"` + operationID + `","outcome":"` + execution.DomainRejected + `","basis":"` + restartEvidenceBasis + `","resolvedBy":"operator.impersonated"}`)
	if status, payload, _ := call(identities.operator, runPath+"/domain-operations/"+operationID+"/resolution", "restart-resolve-smuggled", held, smuggled); status != http.StatusUnprocessableEntity {
		t.Fatalf("smuggled resolver status=%d body=%s, want the canonical contract to reject it", status, payload)
	}
	// The basis is a bounded evidence reference, not operator prose: a
	// decision whose audit record could carry unbounded content is refused by
	// the canonical contract before anything is decoded.
	prose := []byte(`{"kind":"` + runapp.EscalationResolutionKind + `","operationId":"` + operationID + `","outcome":"` + execution.DomainRejected + `","basis":"the authoritative owner has no record of the operation"}`)
	if status, payload, _ := call(identities.operator, runPath+"/domain-operations/"+operationID+"/resolution", "restart-resolve-prose", held, prose); status != http.StatusUnprocessableEntity {
		t.Fatalf("prose basis status=%d body=%s, want the canonical contract to reject it", status, payload)
	}

	status, payload, headers := call(identities.operator, runPath+"/domain-operations/"+operationID+"/resolution", "restart-resolve", held, body)
	if status != http.StatusOK {
		t.Fatalf("operator resolution status=%d body=%s", status, payload)
	}
	if headers.Get("Idempotency-Replayed") != "" {
		t.Fatal("the first operator resolution reported itself as a replay")
	}
	settledETag := headers.Get("ETag")
	if settledETag == "" {
		t.Fatal("the operator resolution returned no strong revision")
	}
	// The identical command under the same key returns the recorded
	// representation, marked as a replay, instead of deciding twice.
	replayStatus, replayPayload, replayHeaders := call(identities.operator, runPath+"/domain-operations/"+operationID+"/resolution", "restart-resolve", held, body)
	if replayStatus != http.StatusOK || replayHeaders.Get("Idempotency-Replayed") != "true" {
		t.Fatalf("replayed operator resolution status=%d replayed=%q body=%s, want the recorded outcome", replayStatus, replayHeaders.Get("Idempotency-Replayed"), replayPayload)
	}
	if string(replayPayload) != string(payload) || replayHeaders.Get("ETag") != settledETag {
		t.Fatalf("replay body/etag differ from the recorded outcome: %s / %q", replayPayload, replayHeaders.Get("ETag"))
	}
	// Reusing the key against a different observed revision, or with
	// different command bytes, is a conflict rather than a replay.
	if status, payload, _ := call(identities.operator, runPath+"/domain-operations/"+operationID+"/resolution", "restart-resolve", etag(), body); status != http.StatusConflict {
		t.Fatalf("key reuse against a new revision status=%d body=%s, want a conflict", status, payload)
	}
	confirmed, err := json.Marshal(runapp.EscalationResolution{Kind: runapp.EscalationResolutionKind, OperationID: operationID, Outcome: execution.DomainConfirmed, Basis: restartEvidenceBasis})
	if err != nil {
		t.Fatal(err)
	}
	if status, payload, _ := call(identities.operator, runPath+"/domain-operations/"+operationID+"/resolution", "restart-resolve", held, confirmed); status != http.StatusConflict {
		t.Fatalf("key reuse with different bytes status=%d body=%s, want a conflict", status, payload)
	}
}

// restartEvidenceBasis is the bounded evidence reference the restart proof's
// operator recovery cites.
const restartEvidenceBasis = "anvilkit://evidence/domain-owner-audit/restart-proof-no-record"
