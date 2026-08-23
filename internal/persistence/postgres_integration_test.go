package persistence_test

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/ancyloce/anvilkit-agent-service/internal/applyauth"
	applyauthpg "github.com/ancyloce/anvilkit-agent-service/internal/applyauth/postgres"
	"github.com/ancyloce/anvilkit-agent-service/internal/artifacts"
	artifactspg "github.com/ancyloce/anvilkit-agent-service/internal/artifacts/postgres"
	"github.com/ancyloce/anvilkit-agent-service/internal/auth"
	"github.com/ancyloce/anvilkit-agent-service/internal/authority"
	authoritypg "github.com/ancyloce/anvilkit-agent-service/internal/authority/postgres"
	"github.com/ancyloce/anvilkit-agent-service/internal/cancellation"
	"github.com/ancyloce/anvilkit-agent-service/internal/canonical"
	"github.com/ancyloce/anvilkit-agent-service/internal/contextcompiler"
	contextpg "github.com/ancyloce/anvilkit-agent-service/internal/contextcompiler/postgres"
	"github.com/ancyloce/anvilkit-agent-service/internal/contractclient"
	contractpg "github.com/ancyloce/anvilkit-agent-service/internal/contractclient/postgres"
	contractguard "github.com/ancyloce/anvilkit-agent-service/internal/contracts"
	"github.com/ancyloce/anvilkit-agent-service/internal/domaincommit"
	commitpg "github.com/ancyloce/anvilkit-agent-service/internal/domaincommit/postgres"
	"github.com/ancyloce/anvilkit-agent-service/internal/events"
	eventpg "github.com/ancyloce/anvilkit-agent-service/internal/events/postgres"
	"github.com/ancyloce/anvilkit-agent-service/internal/events/spool"
	"github.com/ancyloce/anvilkit-agent-service/internal/execution"
	executionpg "github.com/ancyloce/anvilkit-agent-service/internal/execution/postgres"
	"github.com/ancyloce/anvilkit-agent-service/internal/idempotency"
	"github.com/ancyloce/anvilkit-agent-service/internal/interrupts"
	interruptpg "github.com/ancyloce/anvilkit-agent-service/internal/interrupts/postgres"
	"github.com/ancyloce/anvilkit-agent-service/internal/journal"
	lifecyclepg "github.com/ancyloce/anvilkit-agent-service/internal/lifecycle/postgres"
	"github.com/ancyloce/anvilkit-agent-service/internal/modelgateway"
	modelpg "github.com/ancyloce/anvilkit-agent-service/internal/modelgateway/postgres"
	"github.com/ancyloce/anvilkit-agent-service/internal/persistence"
	"github.com/ancyloce/anvilkit-agent-service/internal/problem"
	"github.com/ancyloce/anvilkit-agent-service/internal/queue"
	queuepg "github.com/ancyloce/anvilkit-agent-service/internal/queue/postgres"
	"github.com/ancyloce/anvilkit-agent-service/internal/recovery"
	recoverypg "github.com/ancyloce/anvilkit-agent-service/internal/recovery/postgres"
	"github.com/ancyloce/anvilkit-agent-service/internal/runs"
	runpg "github.com/ancyloce/anvilkit-agent-service/internal/runs/postgres"
	"github.com/ancyloce/anvilkit-agent-service/internal/scheduler"
	schedulerpg "github.com/ancyloce/anvilkit-agent-service/internal/scheduler/postgres"
	"github.com/ancyloce/anvilkit-agent-service/internal/securityaudit"
	securityauditpg "github.com/ancyloce/anvilkit-agent-service/internal/securityaudit/postgres"
	"github.com/ancyloce/anvilkit-agent-service/internal/tools"
	toolpg "github.com/ancyloce/anvilkit-agent-service/internal/tools/postgres"
	"github.com/ancyloce/anvilkit-agent-service/internal/usage"
	usagepg "github.com/ancyloce/anvilkit-agent-service/internal/usage/postgres"
)

func TestPostgresFoundations(t *testing.T) {
	baseURL := os.Getenv("POSTGRES_TEST_URL")
	if baseURL == "" {
		t.Skip("POSTGRES_TEST_URL is not set")
	}
	ctx := context.Background()
	databaseURL, cleanup := isolatedDatabase(t, ctx, baseURL)
	defer cleanup()
	connection, err := pgx.Connect(ctx, databaseURL)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := connection.Close(ctx); err != nil {
			t.Errorf("close migration connection: %v", err)
		}
	}()
	migrator := persistence.NewMigrator(connection)

	if err := migrator.ApplyThrough(ctx, 1); err != nil {
		t.Fatal(err)
	}
	if _, err := connection.Exec(ctx, `INSERT INTO agent_workflow.checkpoints(workspace_id,project_id,workflow_id,workflow_version,step_name,state_bytes) VALUES('w','p','old-workflow',1,'checkpoint','{}')`); err != nil {
		t.Fatal(err)
	}
	if err := migrator.Apply(ctx); err != nil {
		t.Fatal(err)
	}
	if err := migrator.Compatible(ctx); err != nil {
		t.Fatal(err)
	}
	var checkpoint string
	if err := connection.QueryRow(ctx, `SELECT workflow_id FROM agent_workflow.checkpoints WHERE workspace_id='w' AND project_id='p'`).Scan(&checkpoint); err != nil || checkpoint != "old-workflow" {
		t.Fatalf("N-1 checkpoint did not survive: %q %v", checkpoint, err)
	}

	var memoryTables int
	if err := connection.QueryRow(ctx, `SELECT count(*) FROM information_schema.tables WHERE table_schema='agent_memory'`).Scan(&memoryTables); err != nil || memoryTables != 0 {
		t.Fatalf("memory schema is not empty: %d %v", memoryTables, err)
	}
	assertRoleIsolation(t, ctx, connection)
	pool, err := pgxpool.New(ctx, databaseURL)
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()
	controlPool, err := persistence.OpenPool(ctx, persistence.PoolConfig{URL: databaseURL, Role: "agent_control_rw", Maximum: 2})
	if err != nil {
		t.Fatal(err)
	}
	defer controlPool.Close()
	if err := controlPool.Ping(ctx); err != nil {
		t.Fatal(err)
	}
	authorityPool, err := persistence.OpenPool(ctx, persistence.PoolConfig{URL: databaseURL, Role: "agent_authority_rw", Maximum: 3})
	if err != nil {
		t.Fatal(err)
	}
	defer authorityPool.Close()
	if err := authorityPool.Ping(ctx); err != nil {
		t.Fatal(err)
	}
	if controlPool.Stat().MaxConns() != 2 || authorityPool.Stat().MaxConns() != 3 {
		t.Fatal("bounded pool maximum was not applied")
	}
	assertScopedRepository(t, ctx, controlPool)
	assertProjectedEventsAndInbox(t, ctx, authorityPool)
	assertIdempotency(t, ctx, authorityPool)
	assertDurableRunCore(t, ctx, authorityPool)
	assertDurableRunStoreAtomicity(t, ctx, authorityPool)
	assertControlInterrupts(t, ctx, authorityPool)
	assertDurableInterruptExpiry(t, ctx, authorityPool, pool)
	assertModelEvidence(t, ctx, pool)
	assertCommitBoundaries(t, ctx, pool)
	assertEvidenceStore(t, ctx, pool)
	assertStreamCursorsAndSequenceSeparation(t, ctx, pool)
	assertStreamCursorSpoolRecovery(t, ctx, pool)
	assertPublicEventProvenance(t, ctx, pool)
	assertArtifactLifecycle(t, ctx, pool)
	assertSchedulerBoundaries(t, ctx, pool)
	assertWorkflowLeaseCleanup(t, ctx, pool)
	assertRecoveryBoundaries(t, ctx, pool)
	assertDurableProviderLedger(t, ctx, pool)
	assertCancellationReconciliation(t, ctx, pool)
	assertScopedAuthorityStore(t, ctx, authorityPool)
	assertAuthoritySeedingIsMonotonicAtomicAndExact(t, ctx, authorityPool)
	assertDomainRedemptionAcrossProcesses(t, ctx, pool)
	assertDurableToolDispatch(t, ctx, authorityPool)
	assertDomainEscalationJournal(t, ctx, pool)
	assertBudgetControllerLedger(t, ctx, authorityPool)
	assertBudgetHeadroomIsAtomicAndScoped(t, ctx, authorityPool)
	assertLateSupersededFinalityRecovers(t, ctx, authorityPool)
	assertBudgetSettlementIsConcurrencySafe(t, ctx, authorityPool)
	assertWorkerLeaseRenewal(t, ctx, authorityPool)
	assertIsolatedFabricRefusesDispatch(t, ctx, authorityPool)
	assertDispatchAdmissionIsAtomicWithItsMutation(t, ctx, authorityPool, databaseURL)
	assertProtectedAuditChain(t, ctx, pool, databaseURL)
	assertCommandReceipts(t, ctx, authorityPool)
	if os.Getenv("DURABLE_CREATE_LOAD_TEST") == "1" {
		assertDurableCreateLatency(t, ctx, authorityPool)
	}
	controlPool.Close()
	authorityPool.Close()

	if err := migrator.RollbackLast(ctx); err != nil {
		t.Fatal(err)
	}
	if err := migrator.Apply(ctx); err != nil {
		t.Fatal(err)
	}
	// Rolling back every embedded migration must remove every service
	// schema, so the count is derived from the migration set itself and
	// cannot drift when a migration is added.
	upMigrations, err := filepath.Glob(filepath.Join("migrations", "*.up.sql"))
	if err != nil || len(upMigrations) == 0 {
		t.Fatalf("migration set = %v err = %v", upMigrations, err)
	}
	// The foundation rollback drops the cluster-global service roles, which
	// no concurrent test database may reference while it happens. Packages
	// run in parallel by design, so the full rollback serializes on the
	// shared cluster advisory lock the isolated-database helpers hold in
	// shared mode for as long as their databases exist.
	guard, err := pgx.Connect(ctx, baseURL)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = guard.Close(context.Background()) }()
	if _, err := guard.Exec(ctx, `SELECT pg_advisory_lock($1)`, clusterRoleLockKey); err != nil {
		t.Fatal(err)
	}
	defer func() { _, _ = guard.Exec(context.Background(), `SELECT pg_advisory_unlock($1)`, clusterRoleLockKey) }()
	for range upMigrations {
		if err := migrator.RollbackLast(ctx); err != nil {
			t.Fatal(err)
		}
	}
	var schemas int
	if err := connection.QueryRow(ctx, `SELECT count(*) FROM information_schema.schemata WHERE schema_name IN ('agent_control','agent_events','agent_workflow','agent_artifacts','agent_memory','agent_evaluation')`).Scan(&schemas); err != nil || schemas != 0 {
		t.Fatalf("rollback left service schemas: %d %v", schemas, err)
	}
	if err := migrator.Apply(ctx); err != nil {
		t.Fatal(err)
	}
}

func assertWorkflowLeaseCleanup(t *testing.T, ctx context.Context, pool *pgxpool.Pool) {
	t.Helper()
	now := time.Now().UTC()
	_, err := pool.Exec(ctx, `
INSERT INTO agent_workflow.agent_tasks(workspace_id,project_id,task_id,run_id,root_run_id,recovery_epoch,execution_generation,capability,reservation_id,input_digest,input_object_key,state,lease_epoch,physical_attempts,created_at)
VALUES('workspace-scheduler-injected','project-scheduler','task-workflow-cleanup','run-scheduler-injected','root-scheduler-injected',2,3,'fake.execute','reservation-scheduler-injected',$1,'inputs/cleanup','leased',1,1,$2)`,
		"sha256:"+strings.Repeat("a", 64), now)
	if err != nil {
		t.Fatal(err)
	}
	_, err = pool.Exec(ctx, `
INSERT INTO agent_workflow.worker_attempts(workspace_id,project_id,task_id,physical_attempt_id,recovery_epoch,execution_generation,attempt_number,lease_epoch,owner,issued_at,expires_at,fence_token,state)
VALUES('workspace-scheduler-injected','project-scheduler','task-workflow-cleanup','attempt-workflow-cleanup',2,3,1,1,'executor-cleanup',$1,$2,'opaque-fence-cleanup','active')`, now, now.Add(time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	_, err = pool.Exec(ctx, `
INSERT INTO agent_workflow.executor_leases(workspace_id,project_id,workflow_id,executor_id,lease_epoch,expires_at)
VALUES('workspace-scheduler-injected','project-scheduler','workflow-cleanup-owned','executor-cleanup',1,$1),
      ('workspace-scheduler-injected','project-scheduler','workflow-cleanup-other','executor-other',1,$1)`, now.Add(time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	cleaner, err := lifecyclepg.NewLeaseCleaner(pool, "executor-cleanup")
	if err != nil {
		t.Fatal(err)
	}
	if err := cleaner.Cleanup(ctx); err != nil {
		t.Fatal(err)
	}
	var taskState, attemptState string
	var owned, other int
	err = pool.QueryRow(ctx, `SELECT
 (SELECT state FROM agent_workflow.agent_tasks WHERE task_id='task-workflow-cleanup'),
 (SELECT state FROM agent_workflow.worker_attempts WHERE physical_attempt_id='attempt-workflow-cleanup'),
 (SELECT count(*) FROM agent_workflow.executor_leases WHERE executor_id='executor-cleanup'),
 (SELECT count(*) FROM agent_workflow.executor_leases WHERE executor_id='executor-other')`).Scan(&taskState, &attemptState, &owned, &other)
	if err != nil || taskState != "queued" || attemptState != "lost" || owned != 0 || other != 1 {
		t.Fatalf("task=%s attempt=%s owned=%d other=%d err=%v", taskState, attemptState, owned, other, err)
	}
}

func assertRecoveryBoundaries(t *testing.T, ctx context.Context, pool *pgxpool.Pool) {
	t.Helper()
	now := time.Now().UTC()
	restoreEvidence, err := recoverypg.NewRestoreEvidence(pool)
	if err != nil {
		t.Fatal(err)
	}
	restoreRequest := recovery.RestoreRequest{DrillID: "restore-recovery", Actor: "operator", Workload: "restore-controller", Reason: "PITR proof", Ticket: "RECOVERY-RESTORE", Traceparent: "00-0123456789abcdef0123456789abcdef-0123456789abcdef-01", RestorePoint: now.Add(-time.Minute)}
	staleRestoreRequest := restoreRequest
	staleRestoreRequest.DrillID = "restore-recovery-stale"
	staleRestoreRequest.RestorePoint = now.Add(-6 * time.Minute)
	if err := restoreEvidence.BeginRestore(ctx, staleRestoreRequest, now); err == nil {
		t.Fatal("durable restore evidence accepted an RPO beyond five minutes")
	}
	if err := restoreEvidence.BeginRestore(ctx, restoreRequest, now); err != nil {
		t.Fatal(err)
	}
	if err := restoreEvidence.BeginRestore(ctx, restoreRequest, now); err == nil {
		t.Fatal("duplicate durable restore drill began")
	}
	for _, stage := range recovery.OrderedStages() {
		for _, outcome := range []string{"starting", "completed"} {
			record := recovery.StageRecord{DrillID: restoreRequest.DrillID, Actor: restoreRequest.Actor, Workload: restoreRequest.Workload, Reason: restoreRequest.Reason, Ticket: restoreRequest.Ticket, Traceparent: restoreRequest.Traceparent, Stage: stage, Outcome: outcome, Epoch: 3, At: now}
			if err := restoreEvidence.RecordRestoreStage(ctx, record); err != nil {
				t.Fatalf("restore stage %s %s: %v", stage, outcome, err)
			}
		}
	}
	restoreReport := recovery.RestoreReport{DrillID: restoreRequest.DrillID, Epoch: 3, StartedAt: now, CompletedAt: now.Add(time.Minute), Stages: nil, RPO: time.Minute, RTO: time.Minute, Completed: true}
	if err := restoreEvidence.CompleteRestore(ctx, restoreReport); err != nil {
		t.Fatal(err)
	}
	var restoreState string
	var restoreStages int
	if err := pool.QueryRow(ctx, `SELECT state,(SELECT count(*) FROM agent_workflow.restore_stages WHERE drill_id=$1) FROM agent_workflow.restore_drills WHERE drill_id=$1`, restoreRequest.DrillID).Scan(&restoreState, &restoreStages); err != nil || restoreState != "verified" || restoreStages != 26 {
		t.Fatalf("restore state=%s stages=%d err=%v", restoreState, restoreStages, err)
	}
	if _, err := pool.Exec(ctx, `UPDATE agent_workflow.restore_stages SET outcome='failed' WHERE drill_id=$1 AND sequence=1`, restoreRequest.DrillID); err == nil {
		t.Fatal("append-only restore stage was mutable")
	}
	workflowConnection, err := pool.Acquire(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := workflowConnection.Exec(ctx, `SET ROLE agent_workflow_rw`); err != nil {
		workflowConnection.Release()
		t.Fatal(err)
	}
	if _, err := workflowConnection.Exec(ctx, `SELECT count(*) FROM agent_workflow.restore_stages WHERE drill_id=$1`, restoreRequest.DrillID); err != nil {
		_, _ = workflowConnection.Exec(ctx, `RESET ROLE`)
		workflowConnection.Release()
		t.Fatalf("workflow role cannot read restore evidence: %v", err)
	}
	if _, err := workflowConnection.Exec(ctx, `UPDATE agent_workflow.restore_drills SET reason='tampered' WHERE drill_id=$1`, restoreRequest.DrillID); err == nil {
		_, _ = workflowConnection.Exec(ctx, `RESET ROLE`)
		workflowConnection.Release()
		t.Fatal("ordinary workflow role mutated restore evidence")
	}
	if _, err := workflowConnection.Exec(ctx, `RESET ROLE`); err != nil {
		workflowConnection.Release()
		t.Fatal(err)
	}
	workflowConnection.Release()
	register, _ := recovery.NewMemoryRegister(2)
	current, _ := register.Current(ctx)
	epoch, err := register.Increment(ctx, current, recovery.IncrementEvidence{Actor: "operator", Workload: "restore-controller", Reason: "PITR proof", Ticket: "RECOVERY-RESTORE", Traceparent: "00-0123456789abcdef0123456789abcdef-0123456789abcdef-01", At: now})
	if err != nil || epoch != 3 {
		t.Fatalf("external epoch=%d err=%v", epoch, err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO agent_workflow.executor_leases(workspace_id,project_id,workflow_id,executor_id,lease_epoch,expires_at) VALUES('workspace-scheduler-injected','project-scheduler','workflow-recovery','executor',1,$1)`, now.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	schedulerRecovery, _ := recoverypg.NewScheduler(pool)
	if err := schedulerRecovery.Rotate(ctx, epoch); err != nil {
		t.Fatal(err)
	}
	if err := schedulerRecovery.EnableDualResultFence(ctx, epoch); err != nil {
		t.Fatal(err)
	}
	var leases int
	var mirrored uint64
	var resultIntake, dispatch, ingress bool
	if err := pool.QueryRow(ctx, `SELECT mirrored_epoch,result_intake_enabled,dispatch_enabled,ingress_enabled,(SELECT count(*) FROM agent_workflow.executor_leases) FROM agent_workflow.recovery_state WHERE register_name='platform-recovery-epoch'`).Scan(&mirrored, &resultIntake, &dispatch, &ingress, &leases); err != nil || mirrored != 3 || !resultIntake || dispatch || ingress || leases != 0 {
		t.Fatalf("mirror=%d result=%v dispatch=%v ingress=%v leases=%d err=%v", mirrored, resultIntake, dispatch, ingress, leases, err)
	}
	for name, statement := range map[string]string{
		"epoch rollback":       `UPDATE agent_workflow.recovery_state SET mirrored_epoch=2,version=version+1 WHERE register_name='platform-recovery-epoch'`,
		"unversioned mutation": `UPDATE agent_workflow.recovery_state SET dispatch_enabled=true WHERE register_name='platform-recovery-epoch'`,
		"enabled new epoch":    `UPDATE agent_workflow.recovery_state SET mirrored_epoch=4,version=version+1,result_intake_enabled=true WHERE register_name='platform-recovery-epoch'`,
		"deletion":             `DELETE FROM agent_workflow.recovery_state WHERE register_name='platform-recovery-epoch'`,
	} {
		if _, err := pool.Exec(ctx, statement); err == nil {
			t.Fatalf("recovery state accepted %s", name)
		}
	}
	// Simulate a restored row that appears current inside the bulk database.
	// The external epoch and scheduler mirror still make it powerless.
	if _, err := pool.Exec(ctx, `UPDATE agent_workflow.agent_tasks SET recovery_epoch=2,state='leased',lease_epoch=4 WHERE workspace_id='workspace-scheduler-injected' AND project_id='project-scheduler' AND task_id='task-scheduler-injected'; UPDATE agent_workflow.worker_attempts SET state='active' WHERE workspace_id='workspace-scheduler-injected' AND project_id='project-scheduler' AND physical_attempt_id='attempt-scheduler-injected'`); err != nil {
		t.Fatal(err)
	}
	repository, _ := schedulerpg.New(pool, register, nil)
	digest := "sha256:" + strings.Repeat("b", 64)
	delayed := scheduler.Result{TaskID: "task-scheduler-injected", RecoveryEpoch: 2, ExecutionGeneration: 3, PhysicalAttemptID: "attempt-scheduler-injected", LeaseEpoch: 4, FenceToken: "opaque-fence-scheduler-injected", Capability: "fake.execute", BuildIdentity: "build-scheduler", ArtifactID: "artifact-scheduler-injected", ArtifactDigest: digest, PendingObjectKey: "pending/task-scheduler-injected/r2/g3/attempt-scheduler-injected/output", CompletedAt: now}
	if accepted, err := repository.AcceptResult(ctx, scheduler.Scope{WorkspaceID: "workspace-scheduler-injected", ProjectID: "project-scheduler"}, delayed); err != nil || accepted {
		t.Fatalf("pre-restore result accepted=%v err=%v", accepted, err)
	}
	usageStore, _ := usagepg.New(pool)
	usagePipeline, _ := usage.New(usageStore, &usage.MemorySink{})
	oldUsage := usage.Observation{WorkspaceID: "workspace-scheduler-injected", ProjectID: "project-scheduler", ObservationID: "usage-recovery-old-epoch", RootRunID: "root-scheduler-injected", RunID: "run-scheduler-injected", TaskID: "task-scheduler-injected", RecoveryEpoch: 2, ExecutionGeneration: 3, PhysicalAttemptID: "attempt-scheduler-injected", ReservationID: "reservation-scheduler-injected", ProviderEventID: "billing-recovery-old-epoch", Meter: "provider-cost", Quantity: "10", Unit: "usd-micro", Currency: "USD", CostMicros: 10, MeterSequence: 1, Final: true, ObservedAt: now, Provider: "fake-worker", BuildIdentity: "build-scheduler", Traceparent: "00-0123456789abcdef0123456789abcdef-0123456789abcdef-01"}
	if accepted, err := usagePipeline.Accept(ctx, oldUsage); err != nil || !accepted {
		t.Fatalf("old epoch usage accepted=%v err=%v", accepted, err)
	}
	var results int
	var artifactState string
	var released bool
	if err := pool.QueryRow(ctx, `SELECT (SELECT count(*) FROM agent_workflow.worker_results WHERE workspace_id='workspace-scheduler-injected'),a.state,b.released FROM agent_artifacts.metadata a JOIN agent_control.budget_reservations b ON b.workspace_id=a.workspace_id AND b.project_id=a.project_id AND b.reservation_id='reservation-scheduler-injected' WHERE a.workspace_id='workspace-scheduler-injected' AND a.project_id='project-scheduler' AND a.artifact_id='artifact-scheduler-injected'`).Scan(&results, &artifactState, &released); err != nil || results != 0 || artifactState != "pending" || released {
		t.Fatalf("results=%d artifact=%s released=%v err=%v", results, artifactState, released, err)
	}
	register.SetUnavailable(true)
	if accepted, err := repository.AcceptResult(ctx, scheduler.Scope{WorkspaceID: "workspace-scheduler-injected", ProjectID: "project-scheduler"}, delayed); err == nil || accepted {
		t.Fatalf("unavailable register accepted=%v err=%v", accepted, err)
	}
}

func assertCommitBoundaries(t *testing.T, ctx context.Context, pool *pgxpool.Pool) {
	t.Helper()
	now := time.Unix(500, 0).UTC()
	digest := func(character byte) string { return "sha256:" + strings.Repeat(string(character), 64) }
	audit, err := applyauthpg.New(pool)
	if err != nil {
		t.Fatal(err)
	}
	authRecord := applyauth.AuditRecord{AuthorizationID: "authorization-commit", WorkspaceID: "workspace-commit", ProjectID: "project-commit", RunID: "run-commit", KeyID: "urn:anvilkit:key:commit-synthetic", PayloadDigest: digest('a'), TokenDigest: digest('b'), IssuedAt: now, ExpiresAt: now.Add(2 * time.Minute), OperationKey: "workflow-commit:commit", Token: "synthetic.compact.token"}
	if err := audit.Record(ctx, authRecord); err != nil {
		t.Fatal(err)
	}
	// A replay of the identical audit write converges without a second row.
	if err := audit.Record(ctx, authRecord); err != nil {
		t.Fatalf("identical audit replay must converge: %v", err)
	}
	// A racing issuance for the same durable operation loses atomically: its
	// token is never durably audited and the operation mapping is untouched.
	racingRecord := authRecord
	racingRecord.AuthorizationID = "authorization-racing"
	racingRecord.PayloadDigest = digest('e')
	racingRecord.TokenDigest = digest('f')
	racingRecord.Token = "racing.compact.token"
	racingErr := audit.Record(ctx, racingRecord)
	var racingDetails problem.Details
	if !errors.As(racingErr, &racingDetails) || racingDetails.Code != string(problem.CodeIdempotencyConflict) {
		t.Fatalf("racing issuance must lose with an idempotency conflict, got %v", racingErr)
	}
	var loserRows int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM agent_control.apply_authorizations WHERE workspace_id='workspace-commit' AND project_id='project-commit' AND authorization_id='authorization-racing'`).Scan(&loserRows); err != nil {
		t.Fatal(err)
	}
	if loserRows != 0 {
		t.Fatal("the losing racing token was durably audited")
	}
	issuances, err := executionpg.NewIssuanceStore(pool)
	if err != nil {
		t.Fatal(err)
	}
	if recorded, ok, err := issuances.Recorded(ctx, "workspace-commit", "project-commit", "workflow-commit:commit"); err != nil || !ok || recorded.AuthorizationID != "authorization-commit" || recorded.RunID != "run-commit" || recorded.AuthorizationJWS != "synthetic.compact.token" {
		t.Fatalf("recorded issuance=%#v ok=%v err=%v", recorded, ok, err)
	}
	if _, err := pool.Exec(ctx, `UPDATE agent_control.commit_issuances SET authorization_id='authorization-racing' WHERE workspace_id='workspace-commit' AND project_id='project-commit' AND operation_key='workflow-commit:commit'`); err == nil {
		t.Fatal("recorded commit issuance was mutable")
	}
	operationStore, err := commitpg.New(pool)
	if err != nil {
		t.Fatal(err)
	}
	scope := domaincommit.Scope{WorkspaceID: "workspace-commit", ProjectID: "project-commit"}
	operation := domaincommit.Operation{Scope: scope, RunID: "run-commit", ID: "operation-commit", AuthorizationID: authRecord.AuthorizationID, AuthorizationJWS: "synthetic.header.signature", ActionDigest: digest('c'), ArtifactDigest: digest('d'), ExpectedRevision: "revision-1", IdempotencyKey: "apply-commit", RequestDigest: digest('e'), Status: domaincommit.Recorded, CreatedAt: now, UpdatedAt: now}
	if err := operationStore.Create(ctx, operation); err != nil {
		t.Fatal(err)
	}
	if err := operationStore.MarkIssued(ctx, scope, operation.ID, now.Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	if err := operationStore.MarkAwaiting(ctx, scope, operation.ID, now.Add(2*time.Second)); err != nil {
		t.Fatal(err)
	}
	if err := operationStore.Finalize(ctx, scope, operation.ID, domaincommit.Conflicted, now.Add(3*time.Second)); err != nil {
		t.Fatal(err)
	}
	stored, err := operationStore.Get(ctx, scope, operation.ID)
	if err != nil || stored.Status != domaincommit.Conflicted || !stored.AuthorizationConsumed {
		t.Fatalf("durable operation=%#v err=%v", stored, err)
	}
	if _, err := pool.Exec(ctx, `UPDATE agent_control.domain_operations SET action_digest=$4 WHERE workspace_id=$1 AND project_id=$2 AND operation_id=$3`, scope.WorkspaceID, scope.ProjectID, operation.ID, digest('e')); err == nil {
		t.Fatal("domain operation identity was mutable")
	}
	if _, err := pool.Exec(ctx, `UPDATE agent_control.domain_operations SET authorization_consumed=false WHERE workspace_id=$1 AND project_id=$2 AND operation_id=$3`, scope.WorkspaceID, scope.ProjectID, operation.ID); err == nil {
		t.Fatal("authorization consumption was reversible")
	}
	if _, err := pool.Exec(ctx, `UPDATE agent_control.domain_operations SET status='applied',updated_at=$4 WHERE workspace_id=$1 AND project_id=$2 AND operation_id=$3`, scope.WorkspaceID, scope.ProjectID, operation.ID, now.Add(4*time.Second)); err == nil {
		t.Fatal("terminal domain outcome was mutable")
	}

	validation, err := contractpg.New(pool)
	if err != nil {
		t.Fatal(err)
	}
	if err := validation.Record(ctx, contractclient.Evidence{WorkspaceID: scope.WorkspaceID, ProjectID: scope.ProjectID, RunID: "run-commit", Kind: contractclient.Artifact, BOMDigest: digest('a'), SchemaDigest: digest('b'), ValidatorVersion: "runtime-commit", CatalogDigest: digest('c'), Valid: true, ValidatedAt: now}); err != nil {
		t.Fatal(err)
	}
	var evidence int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM agent_evaluation.validation_evidence WHERE workspace_id=$1 AND project_id=$2 AND run_id='run-commit'`, scope.WorkspaceID, scope.ProjectID).Scan(&evidence); err != nil || evidence != 1 {
		t.Fatalf("validation evidence=%d err=%v", evidence, err)
	}

	if _, err := pool.Exec(ctx, `INSERT INTO agent_control.budget_reservations(workspace_id,project_id,root_run_id,run_id,reservation_id,controller_generation,policy_version,budget_version,upper_bound_micros,expires_at) VALUES($1,$2,'root-commit','run-commit','reservation-commit',2,'policy-commit','budget-commit',100,$3)`, scope.WorkspaceID, scope.ProjectID, now.Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `UPDATE agent_control.budget_reservations SET controller_generation=3 WHERE workspace_id=$1 AND project_id=$2 AND reservation_id='reservation-commit'`, scope.WorkspaceID, scope.ProjectID); err == nil {
		t.Fatal("budget controller generation was mutable")
	}
	if _, err := pool.Exec(ctx, `INSERT INTO agent_control.usage_observations(workspace_id,project_id,root_run_id,run_id,reservation_id,observation_id,task_id,physical_attempt_id,recovery_epoch,execution_generation,meter_sequence,cost_micros,final) VALUES($1,$2,'root-commit','run-commit','reservation-commit','observation-commit','task-commit','attempt-commit',1,1,1,40,true)`, scope.WorkspaceID, scope.ProjectID); err != nil {
		t.Fatal(err)
	}

	if _, err := pool.Exec(ctx, `INSERT INTO agent_artifacts.metadata(workspace_id,project_id,artifact_id,run_id,digest,actual_digest,state,security_generation,lineage,object_reference,schema_identity) VALUES($1,$2,'artifact-commit','run-commit',$3,$3,'finalized',2,'{}','{}','{}')`, scope.WorkspaceID, scope.ProjectID, digest('d')); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO agent_artifacts.access_grants(workspace_id,project_id,artifact_id,grant_id,security_generation,purpose,actor_id,issued_at,expires_at) VALUES($1,$2,'artifact-commit','grant-commit',2,'commit','actor-commit',$3,$4)`, scope.WorkspaceID, scope.ProjectID, now, now.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `UPDATE agent_artifacts.metadata SET state='pending',version=version+1 WHERE workspace_id=$1 AND project_id=$2 AND artifact_id='artifact-commit'`, scope.WorkspaceID, scope.ProjectID); err == nil {
		t.Fatal("artifact lifecycle moved backward")
	}
}

// assertArtifactLifecycle proves the durable artifact module end to end: the
// executor-facing port records an immutable candidate, review finalizes it,
// commit eligibility answers from the finalized state, a confirmed effect
// commits it, grants are audited durably, and the object bytes are write-once.
// assertEvidenceStore proves the durable AgentEvidence boundary: independent
// per-run sequences, idempotent appends, immutable rows, and access-audited
// reads.
func assertEvidenceStore(t *testing.T, ctx context.Context, pool *pgxpool.Pool) {
	t.Helper()
	guard := pinnedGuard(t)
	now := time.Unix(700, 0).UTC()
	store, err := eventpg.NewEvidenceStore(pool, guard.At(contractguard.EvidenceIn), func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	fact := events.Evidence{
		WorkspaceID:    "workspace-evidence",
		ProjectID:      "project-evidence",
		RunID:          "run-evidence",
		EvidenceID:     "evidence-commit-1",
		Type:           "commit.authorization-issued",
		OccurredAt:     time.Unix(699, 0).UTC(),
		Producer:       events.EvidenceProducer{Component: "agent-executor", DefinitionDigest: "sha256:" + strings.Repeat("d", 64), PolicyDigest: "sha256:" + strings.Repeat("a", 64), ContractBOMDigest: "sha256:" + strings.Repeat("c", 64)},
		Classification: "internal",
		Retention:      "audit",
		Traceparent:    "00-0123456789abcdef0123456789abcdef-0123456789abcdef-01",
		Payload:        map[string]string{"authorizationId": "authorization-evidence"},
	}
	first, err := store.AppendEvidence(ctx, fact)
	if err != nil || first != 1 {
		t.Fatalf("first evidence sequence=%d err=%v", first, err)
	}
	second := fact
	second.EvidenceID = "evidence-domain-1"
	second.Type = "domain.effect-confirmed"
	if sequence, err := store.AppendEvidence(ctx, second); err != nil || sequence != 2 {
		t.Fatalf("second evidence sequence=%d err=%v", sequence, err)
	}
	if replayed, err := store.AppendEvidence(ctx, fact); err != nil || replayed != 1 {
		t.Fatalf("replayed evidence sequence=%d err=%v, want the recorded 1", replayed, err)
	}
	if _, err := pool.Exec(ctx, `UPDATE agent_evidence.records SET evidence_type='domain.tampered' WHERE workspace_id='workspace-evidence'`); err == nil {
		t.Fatal("recorded evidence was mutable")
	}
	if _, err := pool.Exec(ctx, `DELETE FROM agent_evidence.records WHERE workspace_id='workspace-evidence'`); err == nil {
		t.Fatal("recorded evidence was deletable")
	}
	// Reusing one identifier for a different fact is refused rather than
	// answered with the first fact's sequence: recorded evidence is
	// immutable, so the second fact has nowhere correct to go.
	reused := fact
	reused.Payload = map[string]string{"authorizationId": "authorization-different"}
	if _, err := store.AppendEvidence(ctx, reused); err == nil {
		t.Fatal("a reused evidence identity carrying different content was accepted")
	} else {
		assertProblemCode(t, err, problem.CodeIdempotencyConflict)
	}
	movedRun := fact
	movedRun.RunID = "run-evidence-other"
	if _, err := store.AppendEvidence(ctx, movedRun); err == nil {
		t.Fatal("a reused evidence identity naming a different run was accepted")
	} else {
		assertProblemCode(t, err, problem.CodeIdempotencyConflict)
	}

	clearedSource := grantedEvidenceAuthority(authority.RoleOperator, "public", "internal", "confidential", "restricted")
	readAuthority := mintedEvidenceAuthority(t, "workspace-evidence", "project-evidence", "operator-1", "integration-verification", clearedSource)
	records, err := store.ReadEvidence(ctx, readAuthority, "run-evidence", 10)
	if err != nil || len(records) != 2 || records[0].Sequence != 1 || records[1].Sequence != 2 {
		t.Fatalf("evidence read records=%d err=%v", len(records), err)
	}
	// A read returns the record's full causal and trace correlation, not a
	// lossy summary of it: a durable evidence read has to be enough to
	// reconstruct what the fact attests.
	if records[0].EvidenceID != "evidence-commit-1" || records[0].Type != "commit.authorization-issued" || records[0].Traceparent != fact.Traceparent || records[0].Producer != fact.Producer || !records[0].OccurredAt.Equal(fact.OccurredAt) {
		t.Fatalf("evidence read lost run correlation: %+v", records[0])
	}
	var audited int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM agent_evidence.access_audit WHERE workspace_id='workspace-evidence' AND accessor='operator-1' AND purpose='integration-verification' AND clearance='restricted'`).Scan(&audited); err != nil || audited != 1 {
		t.Fatalf("evidence access audit rows=%d err=%v", audited, err)
	}

	// An accessor authorized for a different tenant reads nothing, and the
	// denial is still audited under its own scope: the tenant an evidence
	// read reaches is the accessor's own, never a caller-supplied filter.
	neighbour := mintedEvidenceAuthority(t, "workspace-evidence-neighbour", "project-evidence", "operator-1", "integration-verification", grantedEvidenceAuthority(authority.RoleOperator, "restricted"))
	if disclosed, err := store.ReadEvidence(ctx, neighbour, "run-evidence", 10); err != nil || len(disclosed) != 0 {
		t.Fatalf("cross-tenant evidence read records=%d err=%v, want none", len(disclosed), err)
	}
	// Clearance bounds disclosure by data classification.
	confidential := fact
	confidential.EvidenceID = "evidence-confidential-1"
	confidential.Type = "model.call-completed"
	confidential.Classification = "confidential"
	if _, err := store.AppendEvidence(ctx, confidential); err != nil {
		t.Fatal(err)
	}
	limited := mintedEvidenceAuthority(t, "workspace-evidence", "project-evidence", "operator-1", "integration-verification", grantedEvidenceAuthority(authority.RoleOperator, "public", "internal"))
	disclosed, err := store.ReadEvidence(ctx, limited, "run-evidence", 10)
	if err != nil || len(disclosed) != 2 {
		t.Fatalf("clearance-bound read records=%d err=%v, want the two internal facts", len(disclosed), err)
	}
	for _, record := range disclosed {
		if record.Classification == "confidential" {
			t.Fatalf("a confidential fact was disclosed to an internal clearance: %+v", record)
		}
	}
	// Authority that cannot be minted cannot read: an unregistered clearance,
	// an anonymous accessor, a purposeless read, an unscoped read, and an
	// actor the scope admits under no role all fail before any query runs.
	for name, attempt := range map[string]func() (events.EvidenceAuthority, error){
		"unregistered clearance": func() (events.EvidenceAuthority, error) {
			return mintEvidenceAuthority("workspace-evidence", "project-evidence", "operator-1", "integration-verification", grantedEvidenceAuthority(authority.RoleOperator, "unbounded"))
		},
		"anonymous accessor": func() (events.EvidenceAuthority, error) {
			return mintEvidenceAuthority("workspace-evidence", "project-evidence", "", "integration-verification", clearedSource)
		},
		"purposeless read": func() (events.EvidenceAuthority, error) {
			return mintEvidenceAuthority("workspace-evidence", "project-evidence", "operator-1", "", clearedSource)
		},
		"unscoped read": func() (events.EvidenceAuthority, error) {
			return mintEvidenceAuthority("workspace-evidence", "", "operator-1", "integration-verification", clearedSource)
		},
		"unadmitted actor": func() (events.EvidenceAuthority, error) {
			return mintEvidenceAuthority("workspace-evidence", "project-evidence", "operator-1", "integration-verification", grantedEvidenceAuthority("", "restricted"))
		},
	} {
		if _, err := attempt(); err == nil {
			t.Fatalf("%s was allowed to mint an evidence read authority", name)
		}
	}

	// A clearance nobody granted cannot be presented: the only authority a
	// caller can build without minting is the zero value, and it discloses
	// nothing rather than defaulting to anything.
	if _, err := store.ReadEvidence(ctx, events.EvidenceAuthority{}, "run-evidence", 10); err == nil {
		t.Fatal("an unminted evidence authority was allowed to read")
	}

	// Authority is re-read at disclosure, not at minting: an accessor whose
	// authority is revoked after minting reads nothing on the next attempt.
	revocable := grantedEvidenceAuthority(authority.RoleOperator, "restricted")
	revoked := mintedEvidenceAuthority(t, "workspace-evidence", "project-evidence", "operator-1", "integration-verification", revocable)
	if _, err := store.ReadEvidence(ctx, revoked, "run-evidence", 10); err != nil {
		t.Fatalf("an active authority failed to read: %v", err)
	}
	revocable.Revoke()
	if _, err := store.ReadEvidence(ctx, revoked, "run-evidence", 10); err == nil {
		t.Fatal("a revoked authority was still allowed to read evidence")
	}

	// Payload characters that the renderer escapes but RFC 8785 does not are
	// still disclosable: the integrity digest is taken over the canonical
	// form on both sides, so storage re-encoding cannot break verification.
	escaped := fact
	escaped.EvidenceID = "evidence-escaped-1"
	escaped.Payload = map[string]string{"note": "a & b <c> \"q\" \\z \u2028"}
	if _, err := store.AppendEvidence(ctx, escaped); err != nil {
		t.Fatalf("append evidence carrying escaped characters: %v", err)
	}
	roundTripped, err := store.ReadEvidence(ctx, readAuthority, "run-evidence", 10)
	if err != nil {
		t.Fatalf("read evidence carrying escaped characters: %v", err)
	}
	var found bool
	for _, record := range roundTripped {
		if record.EvidenceID == "evidence-escaped-1" {
			found = record.Payload["note"] == escaped.Payload["note"]
		}
	}
	if !found {
		t.Fatalf("escaped payload characters did not survive the durable round trip: %+v", roundTripped)
	}

	// Retention bounds disclosure without rewriting history: past the
	// governed window the rows still exist and stay immutable, but nothing is
	// disclosed any more. The deadline is derived, never stored, so it always
	// reflects the governed window in force.
	window, err := events.RetentionWindow(events.RetentionAudit)
	if err != nil {
		t.Fatal(err)
	}
	if deadline, err := events.DisclosureDeadline(now, events.RetentionAudit); err != nil || !deadline.Equal(now.Add(window)) {
		t.Fatalf("derived disclosure deadline=%v err=%v", deadline, err)
	}
	expired, err := eventpg.NewEvidenceStore(pool, guard.At(contractguard.EvidenceIn), func() time.Time { return now.Add(window).Add(time.Second) })
	if err != nil {
		t.Fatal(err)
	}
	if disclosed, err := expired.ReadEvidence(ctx, readAuthority, "run-evidence", 10); err != nil || len(disclosed) != 0 {
		t.Fatalf("post-retention read records=%d err=%v, want none", len(disclosed), err)
	}
	var retained int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM agent_evidence.records WHERE workspace_id='workspace-evidence'`).Scan(&retained); err != nil || retained != 4 {
		t.Fatalf("retention deleted history: rows=%d err=%v", retained, err)
	}

	// Integrity is re-verified before disclosure: a record whose stored
	// digest no longer attests its document is never returned as evidence.
	tampered := fact
	tampered.RunID = "run-tampered"
	tampered.EvidenceID = "evidence-tampered-1"
	if _, err := pool.Exec(ctx, `INSERT INTO agent_evidence.records(workspace_id,project_id,run_id,evidence_id,evidence_sequence,evidence_type,data_classification,retention_category,evidence_bytes,content_digest,recorded_at) VALUES('workspace-evidence','project-evidence','run-tampered','evidence-tampered-1',1,'commit.authorization-issued','internal','audit',$1,$2,$3)`,
		mustRenderEvidence(t, tampered, 1, now), "sha256:"+strings.Repeat("f", 64), now); err != nil {
		t.Fatal(err)
	}
	if _, err := store.ReadEvidence(ctx, readAuthority, "run-tampered", 10); err == nil {
		t.Fatal("a record whose digest does not attest its document was disclosed")
	}

	// A clock finer than the attested precision must still round-trip: the
	// stored time is recorded at exactly the precision the document attests,
	// so the two can never disagree by construction.
	fine := now.Add(1234 * time.Microsecond)
	precise, err := eventpg.NewEvidenceStore(pool, guard.At(contractguard.EvidenceIn), func() time.Time { return fine })
	if err != nil {
		t.Fatal(err)
	}
	subMillisecond := fact
	subMillisecond.EvidenceID = "evidence-sub-millisecond-1"
	subMillisecond.RunID = "run-precision"
	if _, err := precise.AppendEvidence(ctx, subMillisecond); err != nil {
		t.Fatalf("append under a sub-millisecond clock: %v", err)
	}
	recordedPrecise, err := precise.ReadEvidence(ctx, readAuthority, "run-precision", 10)
	if err != nil || len(recordedPrecise) != 1 {
		t.Fatalf("sub-millisecond read records=%d err=%v", len(recordedPrecise), err)
	}
	if !recordedPrecise[0].RecordedAt.Equal(fine.Truncate(time.Millisecond)) {
		t.Fatalf("recorded time %v does not match the attested precision", recordedPrecise[0].RecordedAt)
	}

	// Only the document is under the digest: relabelling a stored row's
	// classification column to widen a read is refused, not disclosed.
	relabelled := fact
	relabelled.EvidenceID = "evidence-relabelled-1"
	relabelled.RunID = "run-relabelled"
	relabelled.Classification = "restricted"
	rendered := mustRenderEvidence(t, relabelled, 1, now)
	digest, err := events.EvidenceDigest(rendered)
	if err != nil {
		t.Fatal(err)
	}
	// The document attests "restricted" while the row column claims
	// "internal". The database constraint binds the two, so this write is
	// refused before it can widen anyone's read.
	if _, err := pool.Exec(ctx, `INSERT INTO agent_evidence.records(workspace_id,project_id,run_id,evidence_id,evidence_sequence,evidence_type,data_classification,retention_category,evidence_bytes,content_digest,recorded_at) VALUES('workspace-evidence','project-evidence','run-relabelled','evidence-relabelled-1',1,'commit.authorization-issued','internal','audit',$1,$2,$3)`,
		rendered, digest, now); err == nil {
		t.Fatal("a row whose column relabels the attested classification was stored")
	}
	if disclosed, err := store.ReadEvidence(ctx, limited, "run-relabelled", 10); err != nil || len(disclosed) != 0 {
		t.Fatalf("a refused relabelling left %d disclosable records err=%v", len(disclosed), err)
	}
}

// verifiedEvidenceRequest stands in for the service's request-authority
// verification: it returns the tenant scope a caller proved and nothing else.
// Clearance is deliberately not expressible here — it comes from current
// authority, which is what makes a forged clearance impossible rather than
// merely rejected.
type verifiedEvidenceRequest struct{ scope runs.Scope }

func (v verifiedEvidenceRequest) Authorize(context.Context, auth.Claims, auth.Operation) (runs.Scope, error) {
	return v.scope, nil
}

// grantedEvidenceAuthority is a current-authority source that admits the actor
// under a role and grants the named data classes.
func grantedEvidenceAuthority(role string, classes ...string) *authority.Static {
	return authority.NewStatic(authority.Current{
		Definition:       json.RawMessage(`{"definitionId":"definition.1"}`),
		ContractBOM:      json.RawMessage(`{"bomDigest":"sha256:1"}`),
		Policy:           json.RawMessage(`{"policyId":"policy.1"}`),
		Budget:           json.RawMessage(`{"kind":"AgentBudget"}`),
		WorkspaceActive:  true,
		ActorActive:      true,
		PermissionActive: true,
		PolicyActive:     true,
		ActorRole:        role,
		ActorGrants:      authority.ActorAuthority{DataClasses: classes},
	})
}

func mintEvidenceAuthority(workspaceID, projectID, actorID, purpose string, source *authority.Static) (events.EvidenceAuthority, error) {
	return events.MintEvidenceAuthority(
		context.Background(),
		verifiedEvidenceRequest{scope: runs.Scope{WorkspaceID: workspaceID, ProjectID: projectID, ActorID: actorID}},
		source,
		auth.Claims{},
		purpose,
	)
}

func mintedEvidenceAuthority(t *testing.T, workspaceID, projectID, actorID, purpose string, source *authority.Static) events.EvidenceAuthority {
	t.Helper()
	value, err := mintEvidenceAuthority(workspaceID, projectID, actorID, purpose, source)
	if err != nil {
		t.Fatalf("mint evidence authority: %v", err)
	}
	return value
}

// mustRenderEvidence renders one canonical evidence document for a durable
// fixture the store itself did not write.
func mustRenderEvidence(t *testing.T, value events.Evidence, sequence uint64, recordedAt time.Time) []byte {
	t.Helper()
	rendered, err := events.RenderEvidence(value, sequence, recordedAt)
	if err != nil {
		t.Fatal(err)
	}
	return rendered
}

// projectedFact is one public projection together with the producing
// component's attributable material — the only shape a durable public event
// can be written from. The evidence identity and the projector digest are
// deliberately absent: they are derived by the projector, never supplied here.
func projectedFact(t *testing.T, runID, eventID string, sequence uint64, occurredAt time.Time) eventpg.Fact {
	t.Helper()
	contractBOM := json.RawMessage(`{"repository":"anvilkit/contracts","bomDigest":"sha256:` + strings.Repeat("a", 64) + `","ociManifestDigest":"sha256:` + strings.Repeat("b", 64) + `","evidenceManifestDigest":"sha256:` + strings.Repeat("c", 64) + `"}`)
	producer, err := events.ProjectionProducer("agent-runs", nil, contractBOM, json.RawMessage(`{"policyId":"policy.1"}`))
	if err != nil {
		t.Fatal(err)
	}
	return eventpg.Fact{
		Projection: events.Projection{
			WorkspaceID: "w",
			ProjectID:   "p",
			RunID:       runID,
			Sequence:    sequence,
			EventID:     eventID,
			Type:        events.TypeStateChanged,
			OccurredAt:  occurredAt,
			Subject:     events.SystemSubject(),
			Traceparent: "00-0123456789abcdef0123456789abcdef-0123456789abcdef-01",
			ContractBOM: contractBOM,
			Payload:     events.StateChangedPayload("created", "preparing"),
		},
		Producer:    producer,
		Correlation: events.ProjectionCorrelation{WorkflowID: runID + ":g1"},
	}
}

// writeProjectedFact commits one fact through the repository-owned projector,
// which is the only durable public-event write path there is.
func writeProjectedFact(t *testing.T, ctx context.Context, pool *pgxpool.Pool, scope events.Scope, fact eventpg.Fact) events.Projected {
	t.Helper()
	projected, err := attemptProjectedFact(ctx, pool, scope, fact, pinnedGuard(t))
	if err != nil {
		t.Fatal(err)
	}
	return projected
}

func attemptProjectedFact(ctx context.Context, pool *pgxpool.Pool, scope events.Scope, fact eventpg.Fact, guard *contractguard.Guard) (events.Projected, error) {
	writer, err := eventpg.NewProjectionWriter(guard, events.DefaultBounds(), func() time.Time { return fact.Projection.OccurredAt })
	if err != nil {
		return events.Projected{}, err
	}
	tx, err := pool.Begin(ctx)
	if err != nil {
		return events.Projected{}, err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	projected, err := writer.Write(ctx, tx, scope, fact)
	if err != nil {
		return events.Projected{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return events.Projected{}, err
	}
	return projected, nil
}

// withoutConstraint drops one constraint for the duration of the body and
// restores it afterwards. It exists so a test can put a row into the store
// that the database would otherwise refuse — which is the only way to prove
// that replay reports store corruption as corruption rather than trusting the
// constraint to be the sole line of defence.
func withoutConstraint(t *testing.T, ctx context.Context, pool *pgxpool.Pool, table, constraint string, body func()) {
	t.Helper()
	definition := ""
	if err := pool.QueryRow(ctx, `SELECT pg_get_constraintdef(c.oid) FROM pg_constraint c JOIN pg_class r ON r.oid=c.conrelid JOIN pg_namespace n ON n.oid=r.relnamespace WHERE n.nspname||'.'||r.relname=$1 AND c.conname=$2`, table, constraint).Scan(&definition); err != nil {
		t.Fatalf("read %s on %s: %v", constraint, table, err)
	}
	if _, err := pool.Exec(ctx, `ALTER TABLE `+table+` DROP CONSTRAINT `+constraint); err != nil {
		t.Fatal(err)
	}
	defer func() {
		if _, err := pool.Exec(ctx, `ALTER TABLE `+table+` ADD CONSTRAINT `+constraint+` `+definition); err != nil {
			t.Fatalf("restore %s on %s: %v", constraint, table, err)
		}
	}()
	body()
}

// assertPublicEventProvenance proves the public projection is traceable on
// real storage (ADR-020 §2). Every durable public event is written by the
// repository-owned projector from evidence recorded in the same transaction;
// the database refuses provenance that names absent evidence, evidence from
// another run, or an event from another run; recorded provenance cannot be
// rewritten; and replay proves the whole account again from the stored rows,
// reporting anything that does not hold as store corruption rather than
// replaying it as an ordinary public fact.
func assertPublicEventProvenance(t *testing.T, ctx context.Context, pool *pgxpool.Pool) {
	t.Helper()
	guard := pinnedGuard(t)
	reader := eventpg.NewReader(pool, guard)
	scope := events.Scope{WorkspaceID: "w", ProjectID: "p"}
	const runID = "run-provenance"
	const otherRunID = "run-provenance-other"
	now := time.Unix(1200, 0).UTC()

	first := writeProjectedFact(t, ctx, pool, scope, projectedFact(t, runID, runID+":1", 1, now))
	derived, err := events.ProjectionEvidenceID(runID + ":1")
	if err != nil {
		t.Fatal(err)
	}
	if first.EvidenceID != derived {
		t.Fatalf("recorded provenance names evidence %q, want the identity the projector derives (%q)", first.EvidenceID, derived)
	}
	digest, err := events.ProjectorDigest()
	if err != nil {
		t.Fatal(err)
	}
	if first.ProjectorDigest != digest {
		t.Fatalf("recorded projector digest=%q, want the live ruleset identity", first.ProjectorDigest)
	}

	// A second event under one identity is not a shape this store holds: the
	// durable public event is written once, so nothing can append a second
	// account of the same fact.
	if _, err := attemptProjectedFact(ctx, pool, scope, projectedFact(t, runID, runID+":1", 1, now), guard); err == nil {
		t.Fatal("a repeated public event identity was written a second time")
	}

	page, err := reader.Replay(ctx, events.ReplayRequest{Scope: scope, RunID: runID, Limit: 100})
	if err != nil || len(page.Events) != 1 {
		t.Fatalf("replay events=%d err=%v, want exactly the one recorded event", len(page.Events), err)
	}
	if page.Events[0].EvidenceID != first.EvidenceID || page.Events[0].ProjectorDigest != first.ProjectorDigest {
		t.Fatalf("replayed provenance=%+v, want the recorded reference and projector digest", page.Events[0])
	}

	// Provenance is history: it cannot be rewritten to point somewhere else.
	if _, err := pool.Exec(ctx, `UPDATE agent_events.event_provenance SET evidence_id='projection.forged' WHERE workspace_id='w' AND project_id='p' AND event_id=$1`, runID+":1"); err == nil {
		t.Fatal("recorded event provenance was mutable")
	}

	// A second run, so the cross-run cases below have real evidence to point
	// at rather than an absence that would prove less.
	foreign := writeProjectedFact(t, ctx, pool, scope, projectedFact(t, otherRunID, otherRunID+":1", 1, now))

	// A public event with no provenance at all: the only way to create one is
	// to write the event row directly, which is exactly the bypass the store
	// must not serve.
	if _, err := pool.Exec(ctx, `INSERT INTO agent_events.agent_events(workspace_id,project_id,run_id,sequence,event_id,event_bytes,created_at) VALUES('w','p',$1,2,$2,$3,$4)`, runID, runID+":2", validEventBytes(runID+":2", runID, 2, "run.state-changed"), now); err != nil {
		t.Fatal(err)
	}
	if _, err := reader.Replay(ctx, events.ReplayRequest{Scope: scope, RunID: runID, Limit: 100}); err == nil {
		t.Fatal("an event with no recorded provenance was replayed onto the public wire")
	}

	// Provenance naming evidence that does not exist is refused by the store.
	absent := `INSERT INTO agent_events.event_provenance(workspace_id,project_id,run_id,event_id,evidence_id,projector_digest) VALUES('w','p',$1,$2,$3,$4)`
	if _, err := pool.Exec(ctx, absent, runID, runID+":2", "projection.nothing-recorded-this", digest); err == nil {
		t.Fatal("provenance naming evidence that does not exist was recorded")
	}
	// Provenance naming evidence recorded under another run is refused too:
	// the reference carries the run, so correlation is the reference.
	if _, err := pool.Exec(ctx, absent, runID, runID+":2", foreign.EvidenceID, digest); err == nil {
		t.Fatal("provenance naming another run's evidence was recorded")
	}
	// Provenance correlated to a run its event does not belong to is refused
	// by the reference to the event itself.
	if _, err := pool.Exec(ctx, absent, otherRunID, runID+":2", first.EvidenceID, digest); err == nil {
		t.Fatal("provenance correlated to another run's event was recorded")
	}

	// With the store's own refusal removed, replay is what stands between a
	// corrupt row and a consumer. Each case is reported as corruption.
	for _, corruption := range []struct {
		name       string
		constraint string
		runID      string
		evidenceID string
	}{
		{name: "evidence that does not exist", constraint: "event_provenance_names_source_evidence", runID: runID, evidenceID: "projection.nothing-recorded-this"},
		{name: "evidence recorded under another run", constraint: "event_provenance_names_source_evidence", runID: runID, evidenceID: foreign.EvidenceID},
		{name: "provenance correlated to another run", constraint: "event_provenance_explains_its_event", runID: otherRunID, evidenceID: foreign.EvidenceID},
	} {
		withoutConstraint(t, ctx, pool, "agent_events.event_provenance", corruption.constraint, func() {
			if _, err := pool.Exec(ctx, absent, corruption.runID, runID+":2", corruption.evidenceID, digest); err != nil {
				t.Fatalf("%s: %v", corruption.name, err)
			}
			if _, err := reader.Replay(ctx, events.ReplayRequest{Scope: scope, RunID: runID, Limit: 100}); err == nil {
				t.Fatalf("%s: a corrupt public event was replayed onto the public wire", corruption.name)
			}
			if _, err := pool.Exec(ctx, `DELETE FROM agent_events.event_provenance WHERE workspace_id='w' AND project_id='p' AND event_id=$1`, runID+":2"); err != nil {
				t.Fatal(err)
			}
		})
	}

	// The bypassing event row is removed, and the run replays cleanly again.
	if _, err := pool.Exec(ctx, `DELETE FROM agent_events.agent_events WHERE workspace_id='w' AND project_id='p' AND event_id=$1`, runID+":2"); err != nil {
		t.Fatal(err)
	}
	page, err = reader.Replay(ctx, events.ReplayRequest{Scope: scope, RunID: runID, Limit: 100})
	if err != nil || len(page.Events) != 1 {
		t.Fatalf("replay events=%d err=%v, want the run traceable again", len(page.Events), err)
	}
}

// assertStreamCursorSpoolRecovery proves the disconnect record survives a
// cursor-store outage on real storage: a record the store refused is held on
// the instance's durable volume, a successor process finds it there, and the
// reconciler places it in the authoritative store once the store is reachable
// again. The record is the only account of what a disconnected client
// received, so an outage must delay it, never lose it.
func assertStreamCursorSpoolRecovery(t *testing.T, ctx context.Context, pool *pgxpool.Pool) {
	t.Helper()
	scope := events.Scope{WorkspaceID: "w", ProjectID: "p"}
	const runID = "run-cursor-recovery"
	const connectionID = "stream.recovery-1"
	directory := t.TempDir()

	// The process that served the stream: its store write failed, so the
	// record went to the durable spool instead.
	serving, err := spool.NewStore(directory)
	if err != nil {
		t.Fatal(err)
	}
	if err := serving.SpoolCursor(ctx, events.RecordedCursor{Scope: scope, RunID: runID, ConnectionID: connectionID, LastEventID: runID + ":4", Reason: "slow-consumer"}); err != nil {
		t.Fatal(err)
	}
	var present int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM agent_events.stream_cursors WHERE workspace_id=$1 AND project_id=$2 AND connection_id=$3`, scope.WorkspaceID, scope.ProjectID, connectionID).Scan(&present); err != nil || present != 0 {
		t.Fatalf("stream cursors=%d err=%v, want the record still only held", present, err)
	}

	// A successor process over the same durable volume, with the store
	// reachable again.
	successor, err := spool.NewStore(directory)
	if err != nil {
		t.Fatal(err)
	}
	cursors, err := eventpg.NewStreamCursors(pool)
	if err != nil {
		t.Fatal(err)
	}
	reconciler, err := spool.NewReconciler(successor, cursors)
	if err != nil {
		t.Fatal(err)
	}
	report, err := reconciler.ReconcileOnce(ctx)
	if err != nil || report.Placed != 1 {
		t.Fatalf("report=%+v err=%v, want the held record placed", report, err)
	}
	var lastEventID, reason, recordedRun string
	if err := pool.QueryRow(ctx, `SELECT run_id,last_event_id,reason FROM agent_events.stream_cursors WHERE workspace_id=$1 AND project_id=$2 AND connection_id=$3`, scope.WorkspaceID, scope.ProjectID, connectionID).Scan(&recordedRun, &lastEventID, &reason); err != nil {
		t.Fatal(err)
	}
	if recordedRun != runID || lastEventID != runID+":4" || reason != "slow-consumer" {
		t.Fatalf("placed cursor=(%q,%q,%q), want the record exactly as it was held", recordedRun, lastEventID, reason)
	}
	if held, err := successor.Held(); err != nil || held != 0 {
		t.Fatalf("held records=%d err=%v after placement, want none", held, err)
	}
	// A second sweep places nothing: the record was moved, not copied.
	if report, err := reconciler.ReconcileOnce(ctx); err != nil || report.Placed != 0 {
		t.Fatalf("report=%+v err=%v on a second sweep, want nothing left to place", report, err)
	}
}

// assertStreamCursorsAndSequenceSeparation proves the two ADR-020 sequence
// boundaries on real storage: the public sequence stays continuous while
// hidden internal evidence is recorded for the same run, evidence carries its
// own independent sequence, and every ended stream connection leaves exactly
// one durable cursor record under its own connection identity.
func assertStreamCursorsAndSequenceSeparation(t *testing.T, ctx context.Context, pool *pgxpool.Pool) {
	t.Helper()
	guard := pinnedGuard(t)
	now := time.Unix(900, 0).UTC()
	reader := eventpg.NewReader(pool, guard)
	evidenceStore, err := eventpg.NewEvidenceStore(pool, guard.At(contractguard.EvidenceIn), func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	scope := events.Scope{WorkspaceID: "w", ProjectID: "p"}
	const runID = "run-sequence-separation"
	hidden := events.Evidence{
		WorkspaceID:    scope.WorkspaceID,
		ProjectID:      scope.ProjectID,
		RunID:          runID,
		Type:           "model.call-completed",
		OccurredAt:     now,
		Producer:       events.EvidenceProducer{Component: "agent-executor", PolicyDigest: "sha256:" + strings.Repeat("a", 64), ContractBOMDigest: "sha256:" + strings.Repeat("c", 64)},
		Classification: "internal",
		Retention:      "audit",
		Traceparent:    "00-0123456789abcdef0123456789abcdef-0123456789abcdef-01",
	}
	// Public events and hidden evidence interleave for the same run: four
	// internal facts that produce nothing public, around three public events
	// each of which is projected from its own source evidence. Seven internal
	// facts, three public ones — which is exactly the relationship ADR-020 §2
	// says consumers must not assume anything about.
	for sequence := uint64(1); sequence <= 3; sequence++ {
		fact := hidden
		fact.EvidenceID = fmt.Sprintf("evidence-separation-before-%d", sequence)
		if _, err := evidenceStore.AppendEvidence(ctx, fact); err != nil {
			t.Fatal(err)
		}
		eventID := fmt.Sprintf("%s:%d", runID, sequence)
		writeProjectedFact(t, ctx, pool, scope, projectedFact(t, runID, eventID, sequence, now))
	}
	trailing := hidden
	trailing.EvidenceID = "evidence-separation-after"
	if _, err := evidenceStore.AppendEvidence(ctx, trailing); err != nil {
		t.Fatal(err)
	}
	page, err := reader.Replay(ctx, events.ReplayRequest{Scope: scope, RunID: runID, Limit: 100})
	if err != nil || len(page.Events) != 3 {
		t.Fatalf("public replay events=%d err=%v, want the three public events", len(page.Events), err)
	}
	if err := events.ValidateContiguous(page.Events, 0); err != nil {
		t.Fatalf("hidden evidence opened a gap in the public sequence: %v", err)
	}
	separationAuthority := mintedEvidenceAuthority(t, scope.WorkspaceID, scope.ProjectID, "operator-separation", "sequence-separation-verification", grantedEvidenceAuthority(authority.RoleOperator, "restricted"))
	records, err := evidenceStore.ReadEvidence(ctx, separationAuthority, runID, 100)
	if err != nil || len(records) != 7 {
		t.Fatalf("evidence records=%d err=%v, want the four hidden facts and the three projections' source evidence", len(records), err)
	}
	hiddenFacts, projected := 0, 0
	for index, record := range records {
		if record.Sequence != uint64(index+1) {
			t.Fatalf("evidence sequence %d at index %d is not independently continuous", record.Sequence, index)
		}
		if events.PublicEventType(record.Type) {
			t.Fatalf("a public event type was recorded as internal evidence: %q", record.Type)
		}
		if record.PublicEventID == "" {
			hiddenFacts++
			continue
		}
		projected++
		// A projection's source evidence names the public event it produced,
		// and that event is one of the three the run actually published.
		found := false
		for _, event := range page.Events {
			if event.ID == record.PublicEventID {
				found = true
				break
			}
		}
		if !found {
			t.Fatalf("evidence %q names public event %q, which this run never published", record.EvidenceID, record.PublicEventID)
		}
	}
	if hiddenFacts != 4 || projected != 3 {
		t.Fatalf("hidden facts=%d projected facts=%d, want four hidden and three that produced a public event", hiddenFacts, projected)
	}

	cursors, err := eventpg.NewStreamCursors(pool)
	if err != nil {
		t.Fatal(err)
	}
	for _, connection := range []string{"stream.separation-1", "stream.separation-2"} {
		if err := cursors.RecordCursor(ctx, scope, runID, connection, runID+":3", "client-closed"); err != nil {
			t.Fatal(err)
		}
	}
	// A repeated connection identity keeps the record it already has: a
	// duplicate recording never rewrites what a connection actually had.
	if err := cursors.RecordCursor(ctx, scope, runID, "stream.separation-1", runID+":1", "slow-consumer"); err != nil {
		t.Fatal(err)
	}
	var recorded int
	var firstCursor, firstReason string
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM agent_events.stream_cursors WHERE workspace_id=$1 AND project_id=$2 AND run_id=$3`, scope.WorkspaceID, scope.ProjectID, runID).Scan(&recorded); err != nil || recorded != 2 {
		t.Fatalf("recorded stream cursors=%d err=%v, want one per connection", recorded, err)
	}
	if err := pool.QueryRow(ctx, `SELECT last_event_id,reason FROM agent_events.stream_cursors WHERE workspace_id=$1 AND project_id=$2 AND connection_id='stream.separation-1'`, scope.WorkspaceID, scope.ProjectID).Scan(&firstCursor, &firstReason); err != nil {
		t.Fatal(err)
	}
	if firstCursor != runID+":3" || firstReason != "client-closed" {
		t.Fatalf("a duplicate recording rewrote a connection record: cursor=%s reason=%s", firstCursor, firstReason)
	}
	if err := cursors.RecordCursor(ctx, scope, runID, "", "", "client-closed"); err == nil {
		t.Fatal("an incomplete connection record was accepted")
	}
	if _, err := pool.Exec(ctx, `INSERT INTO agent_events.stream_cursors(workspace_id,project_id,run_id,connection_id,last_event_id,reason,recorded_at) VALUES($1,$2,$3,'stream.separation-3','','disconnected',$4)`, scope.WorkspaceID, scope.ProjectID, runID, now); err == nil {
		t.Fatal("an unregistered disconnection reason was recorded")
	}
}

func assertArtifactLifecycle(t *testing.T, ctx context.Context, pool *pgxpool.Pool) {
	t.Helper()
	store, err := artifactspg.NewStore(pool)
	if err != nil {
		t.Fatal(err)
	}
	objects, err := artifactspg.NewObjects(pool)
	if err != nil {
		t.Fatal(err)
	}
	reader, err := artifactspg.NewHMACReader(pool, []byte("integration-grant-signing-secret"))
	if err != nil {
		t.Fatal(err)
	}
	material := json.RawMessage(`{"synthetic":true}`)
	activeAuthority := authority.NewStatic(authority.Current{Definition: material, ContractBOM: material, Policy: material, Budget: material, WorkspaceActive: true, ActorActive: true, PermissionActive: true, PolicyActive: true,
		ActorRole: authority.RoleArtifactCustodian,
		ActorGrants: authority.ActorAuthority{
			Capabilities: []string{string(artifacts.LegalHoldCapability), string(artifacts.DeleteCapability)},
			DataClasses:  []string{artifacts.CustodyDataClass},
		}})
	audit := newPersistenceProtectedAudit()
	service, err := artifacts.New(store, objects, reader, activeAuthority, audit, time.Hour, 5*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Unix(600, 0).UTC()
	clock := testClock{now}
	port, err := execution.NewServiceArtifactPort(service, clock)
	if err != nil {
		t.Fatal(err)
	}
	candidateBytes := []byte(`{"kind":"ComponentPackageSpec","name":"integration-artifact"}`)
	digestOf := sha256.Sum256(candidateBytes)
	candidateDigest := "sha256:" + hex.EncodeToString(digestOf[:])
	sha := func(character byte) string { return "sha256:" + strings.Repeat(string(character), 64) }
	candidate := execution.ArtifactCandidate{
		WorkspaceID:         "workspace-artifact",
		ProjectID:           "project-artifact",
		RunID:               "run-artifact",
		Digest:              candidateDigest,
		Bytes:               candidateBytes,
		SchemaComponent:     "anvilkit.contract.schema.component-package-spec",
		SchemaDigest:        sha('a'),
		BOMDigest:           sha('b'),
		CatalogDigest:       sha('c'),
		OperationKey:        "workflow-artifact:finalize",
		ExecutionGeneration: 1,
		BuildIdentity:       sha('d'),
		Producer:            "anvilkit-agent-runner",
		Kind:                artifacts.WorkerResult,
		Validation:          artifacts.Validation{ValidatedAt: now, Checks: []artifacts.Check{{Name: "schema", Result: "passed", EvidenceDigest: sha('a')}}},
	}
	if err := port.RecordCandidate(ctx, candidate); err != nil {
		t.Fatal(err)
	}
	if err := port.RecordCandidate(ctx, candidate); err != nil {
		t.Fatalf("candidate recording must converge under replay: %v", err)
	}
	query := execution.ArtifactQuery{WorkspaceID: candidate.WorkspaceID, ProjectID: candidate.ProjectID, RunID: candidate.RunID, ArtifactDigest: candidateDigest}
	if eligibility, err := port.Eligible(ctx, query); err != nil || eligibility.Eligible {
		t.Fatalf("a valid but unfinalized artifact must be ineligible, got %+v err=%v", eligibility, err)
	}
	if err := port.EnsureFinalized(ctx, query); err != nil {
		t.Fatal(err)
	}
	if eligibility, err := port.Eligible(ctx, query); err != nil || !eligibility.Eligible {
		t.Fatalf("a finalized artifact must be eligible, got %+v err=%v", eligibility, err)
	}
	artifactID := execution.ArtifactRecordID(candidate.RunID, candidateDigest)
	grant, err := service.Grant(ctx, candidate.WorkspaceID, candidate.ProjectID, artifactID, artifacts.ReadAccess, "actor-artifact", now)
	if err != nil {
		t.Fatal(err)
	}
	var audited int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM agent_artifacts.access_grants WHERE workspace_id=$1 AND project_id=$2 AND artifact_id=$3`, candidate.WorkspaceID, candidate.ProjectID, artifactID).Scan(&audited); err != nil || audited != 1 {
		t.Fatalf("grant audit rows=%d err=%v", audited, err)
	}
	if _, err := service.UseGrant(ctx, candidate.WorkspaceID, candidate.ProjectID, "actor-artifact", grant, now.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	if err := port.EnsureCommitted(ctx, query); err != nil {
		t.Fatal(err)
	}
	record, err := service.Get(ctx, candidate.WorkspaceID, candidate.ProjectID, artifactID)
	if err != nil || record.State != artifacts.Committed {
		t.Fatalf("record=%#v err=%v, want committed", record, err)
	}
	// Committed artifacts leave the governed-effect window: eligibility is
	// exactly the finalized state.
	if eligibility, err := port.Eligible(ctx, query); err != nil || eligibility.Eligible {
		t.Fatalf("a committed artifact must not be re-eligible, got %+v err=%v", eligibility, err)
	}
	// Quarantine after commit increments the security generation and the old
	// grant dies with it.
	quarantined, err := service.Transition(ctx, candidate.WorkspaceID, candidate.ProjectID, artifactID, record.Version, artifacts.Quarantined, now.Add(2*time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	if quarantined.SecurityGeneration <= record.SecurityGeneration {
		t.Fatal("quarantine must increment the security generation")
	}
	if _, err := service.UseGrant(ctx, candidate.WorkspaceID, candidate.ProjectID, "actor-artifact", grant, now.Add(3*time.Minute)); err == nil {
		t.Fatal("a grant must not survive quarantine")
	}
	// Revocation is recorded immutably on the audited rows: the history stays,
	// the revocation marker lands, and neither can be deleted or rewritten.
	var revoked int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM agent_artifacts.access_grants WHERE workspace_id=$1 AND project_id=$2 AND artifact_id=$3 AND revoked_at IS NOT NULL`, candidate.WorkspaceID, candidate.ProjectID, artifactID).Scan(&revoked); err != nil || revoked != 1 {
		t.Fatalf("revocation must mark audited grants immutably, revoked rows=%d err=%v", revoked, err)
	}
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM agent_artifacts.access_grants WHERE workspace_id=$1 AND project_id=$2 AND artifact_id=$3`, candidate.WorkspaceID, candidate.ProjectID, artifactID).Scan(&audited); err != nil || audited != 1 {
		t.Fatalf("revocation must never delete audit history, rows=%d err=%v", audited, err)
	}
	if _, err := pool.Exec(ctx, `DELETE FROM agent_artifacts.access_grants WHERE workspace_id=$1 AND project_id=$2 AND artifact_id=$3`, candidate.WorkspaceID, candidate.ProjectID, artifactID); err == nil {
		t.Fatal("audited artifact grants were deletable")
	}
	if _, err := pool.Exec(ctx, `UPDATE agent_artifacts.access_grants SET revoked_at=NULL WHERE workspace_id=$1 AND project_id=$2 AND artifact_id=$3`, candidate.WorkspaceID, candidate.ProjectID, artifactID); err == nil {
		t.Fatal("a recorded revocation was reversible")
	}
	// Object bytes are write-once at the database boundary.
	if err := objects.PutOnce(ctx, record.Reference, []byte("different bytes")); err == nil {
		t.Fatal("object store accepted a rewrite")
	}
	if _, err := pool.Exec(ctx, `UPDATE agent_artifacts.objects SET bytes=$3 WHERE bucket=$1 AND object_key=$2`, record.Reference.Bucket, record.Reference.ObjectKey, []byte("mutated")); err == nil {
		t.Fatal("artifact object bytes were mutable")
	}
	stored, err := objects.Read(ctx, record.Reference)
	if err != nil || string(stored) != string(candidateBytes) {
		t.Fatalf("stored bytes mismatch err=%v", err)
	}
	assertDeletionOwnershipPrecedesDestruction(t, ctx, pool, store, objects, service, audit, now)
}

// Deletion ownership is taken by compare-and-set before anything is revoked or
// destroyed, and the database holds the same invariants the service does. A
// hold and a deletion that race must never end with live metadata naming
// content that is already gone, so exactly one of them can win and the loser
// is refused rather than partially applied.
func assertDeletionOwnershipPrecedesDestruction(t *testing.T, ctx context.Context, pool *pgxpool.Pool, store *artifactspg.Store, objects *artifactspg.Objects, service *artifacts.Service, audit *persistenceProtectedAudit, now time.Time) {
	t.Helper()
	seed := func(id artifacts.ID) artifacts.Record {
		t.Helper()
		value := []byte("ownership bytes for " + string(id))
		sum := sha256.Sum256(value)
		created, err := service.Create(ctx, artifacts.Create{
			WorkspaceID: "workspace-ownership", ProjectID: "project-ownership", RunID: "run-ownership", ID: id,
			Bytes: value, ClaimedDigest: "sha256:" + hex.EncodeToString(sum[:]),
			Reference: artifacts.Reference{Bucket: "artifacts", ObjectKey: string(id), SizeBytes: int64(len(value)), MediaType: "application/json"},
			Schema:    artifacts.SchemaIdentity{Component: "plan", Version: "1.0.0", Digest: "sha256:" + strings.Repeat("e", 64)},
			Lineage: artifacts.Lineage{
				RunID: "run-ownership", TaskID: "task-ownership", PhysicalAttemptID: "attempt-ownership",
				Producer:      artifacts.Producer{TaskID: "task-ownership", PhysicalAttemptID: "attempt-ownership", RecoveryEpoch: 1, ExecutionGeneration: 1, LeaseEpoch: 1, BuildIdentity: "build-ownership", Provider: "integration"},
				BOMDigest:     "sha256:" + strings.Repeat("a", 64),
				SchemaDigest:  "sha256:" + strings.Repeat("b", 64),
				CatalogDigest: "sha256:" + strings.Repeat("c", 64),
			},
			Kind:       artifacts.WorkerResult,
			Validation: artifacts.Validation{ValidatedAt: now, Checks: []artifacts.Check{{Name: "schema", Result: "passed", EvidenceDigest: "sha256:" + strings.Repeat("b", 64)}}},
			CreatedAt:  now,
		})
		if err != nil {
			t.Fatal(err)
		}
		return created
	}
	custody := artifacts.Custody{ActorID: "actor-ownership", Workload: "artifact-lifecycle", Reason: "ownership conformance", Ticket: "change-0003", Traceparent: "00-" + strings.Repeat("3", 32) + "-" + strings.Repeat("4", 16) + "-01"}
	var details problem.Details

	// A hold that stands refuses the claim outright, so nothing is destroyed.
	held := seed("artifact.ownership.held")
	if _, err := service.SetLegalHold(ctx, held.WorkspaceID, held.ProjectID, held.ID, held.Version, true, custody, now); err != nil {
		t.Fatal(err)
	}
	if _, err := store.ClaimDeletion(ctx, held.WorkspaceID, held.ProjectID, held.ID, held.Version+1, artifacts.DeletionClaim{Decision: "artifact.ownership.attempt", Terminal: artifacts.Expired, At: now}); !errors.As(err, &details) || details.Code != string(problem.CodeArtifactAccessDenied) {
		t.Fatalf("deletion ownership was taken over a standing legal hold: %v", err)
	}
	if exists, err := objects.Exists(ctx, held.Reference); err != nil || !exists {
		t.Fatalf("a refused claim destroyed content: exists=%v err=%v", exists, err)
	}

	// Ownership taken first carries the artifact out of every live state in
	// the same write, and a hold arriving afterwards is refused by the
	// database itself, not only by the service above it.
	owned := seed("artifact.ownership.claimed")
	// The claim below stands for one an interrupted destruction left behind,
	// so the decision that authorized it is on the record — which is the only
	// state production can actually reach, and the only one a successor is
	// permitted to finish.
	audit.authorize(securityaudit.Record{
		ID:     "artifact.ownership.decision",
		Action: "artifact-deleted",
		Actor:  custody.ActorID,
		Reason: custody.Reason,
		Scope:  securityaudit.Scope{WorkspaceID: owned.WorkspaceID, ProjectID: owned.ProjectID, ResourceID: string(owned.ID)},
	})
	claimed, err := store.ClaimDeletion(ctx, owned.WorkspaceID, owned.ProjectID, owned.ID, owned.Version, artifacts.DeletionClaim{Decision: "artifact.ownership.decision", Terminal: artifacts.Expired, At: now})
	if err != nil {
		t.Fatal(err)
	}
	if claimed.State != artifacts.Expired || claimed.DeletionClaim != "artifact.ownership.decision" || claimed.DeletionClaimedAt == nil || claimed.Version != owned.Version+1 || claimed.SecurityGeneration != owned.SecurityGeneration+1 {
		t.Fatalf("ownership did not carry the artifact out of its live state: %+v", claimed)
	}
	if _, err := pool.Exec(ctx, `UPDATE agent_artifacts.metadata SET legal_hold=true,version=version+1,updated_at=$4 WHERE workspace_id=$1 AND project_id=$2 AND artifact_id=$3`, owned.WorkspaceID, owned.ProjectID, owned.ID, now); err == nil {
		t.Fatal("a legal hold was placed on an artifact whose deletion was already owned")
	}
	if _, err := pool.Exec(ctx, `UPDATE agent_artifacts.metadata SET deletion_claim='someone.else',version=version+1,updated_at=$4 WHERE workspace_id=$1 AND project_id=$2 AND artifact_id=$3`, owned.WorkspaceID, owned.ProjectID, owned.ID, now); err == nil {
		t.Fatal("artifact deletion ownership was transferable")
	}
	// The same decision resumes its own claim; another decision is refused.
	resumed, err := store.ClaimDeletion(ctx, owned.WorkspaceID, owned.ProjectID, owned.ID, owned.Version, artifacts.DeletionClaim{Decision: "artifact.ownership.decision", Terminal: artifacts.Expired, At: now})
	if err != nil || resumed.Version != claimed.Version {
		t.Fatalf("the owning decision could not resume its own claim: %+v %v", resumed, err)
	}
	if _, err := store.ClaimDeletion(ctx, owned.WorkspaceID, owned.ProjectID, owned.ID, claimed.Version, artifacts.DeletionClaim{Decision: "artifact.ownership.other", Terminal: artifacts.Expired, At: now}); !errors.As(err, &details) || details.Code != string(problem.CodeVersionConflict) {
		t.Fatalf("a second decision claimed an artifact that was already owned: %v", err)
	}
	// And the owned destruction finishes.
	final, err := service.Delete(ctx, owned.WorkspaceID, owned.ProjectID, owned.ID, owned.Version, custody, now.Add(time.Minute))
	if err != nil || final.State != artifacts.Deleted || final.DeletedAt == nil {
		t.Fatalf("an owned destruction could not be finished: %+v %v", final, err)
	}
	if exists, err := objects.Exists(ctx, owned.Reference); err != nil || exists {
		t.Fatalf("content survived a completed destruction: exists=%v err=%v", exists, err)
	}
}

func assertSchedulerBoundaries(t *testing.T, ctx context.Context, pool *pgxpool.Pool) {
	t.Helper()
	scope := scheduler.Scope{WorkspaceID: "workspace-scheduler", ProjectID: "project-scheduler"}
	now := time.Now().UTC()
	digest := func(c string) string { return "sha256:" + strings.Repeat(c, 64) }
	seedSchedulerResult(t, ctx, pool, scope, "", now)
	if _, err := pool.Exec(ctx, `INSERT INTO agent_workflow.recovery_state(register_name,mirrored_epoch,result_intake_enabled) VALUES('platform-recovery-epoch',2,true)`); err != nil {
		t.Fatal(err)
	}
	register, _ := recovery.NewMemoryRegister(2)
	repository, _ := schedulerpg.New(pool, register, nil)
	lateScope := scheduler.Scope{WorkspaceID: "workspace-scheduler-late", ProjectID: "project-scheduler"}
	lateIssued := time.Now().UTC().Add(-2 * time.Minute)
	seedSchedulerResult(t, ctx, pool, lateScope, "-late", lateIssued)
	late := scheduler.Result{TaskID: "task-scheduler-late", RecoveryEpoch: 2, ExecutionGeneration: 3, PhysicalAttemptID: "attempt-scheduler-late", LeaseEpoch: 4, FenceToken: "opaque-fence-scheduler-late", Capability: "fake.execute", BuildIdentity: "build-scheduler", ArtifactID: "artifact-scheduler-late", ArtifactDigest: digest("b"), PendingObjectKey: "pending/task-scheduler-late/r2/g3/attempt-scheduler-late/output", CompletedAt: lateIssued.Add(time.Second)}
	if accepted, err := repository.AcceptResult(ctx, lateScope, late); err != nil || accepted {
		t.Fatalf("backdated late result accepted=%v err=%v", accepted, err)
	}
	base := scheduler.Result{TaskID: "task-scheduler", RecoveryEpoch: 2, ExecutionGeneration: 3, PhysicalAttemptID: "attempt-scheduler", LeaseEpoch: 4, FenceToken: "opaque-fence-scheduler-0001", Capability: "fake.execute", BuildIdentity: "build-scheduler", ArtifactID: "artifact-scheduler", ArtifactDigest: digest("b"), PendingObjectKey: "pending/task-scheduler/r2/g3/attempt-scheduler/output", CompletedAt: now}
	stale := base
	stale.LeaseEpoch = 3
	if accepted, err := repository.AcceptResult(ctx, scope, stale); err != nil || accepted {
		t.Fatalf("stale accepted=%v err=%v", accepted, err)
	}
	var diagnostics int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM agent_workflow.result_diagnostics WHERE workspace_id=$1 AND project_id=$2`, scope.WorkspaceID, scope.ProjectID).Scan(&diagnostics); err != nil || diagnostics != 1 {
		t.Fatalf("diagnostics=%d err=%v", diagnostics, err)
	}
	if accepted, err := repository.AcceptResult(ctx, scope, base); err != nil || !accepted {
		t.Fatalf("winner accepted=%v err=%v", accepted, err)
	}
	if accepted, err := repository.AcceptResult(ctx, scope, base); err != nil || !accepted {
		t.Fatalf("identical winner replay accepted=%v err=%v", accepted, err)
	}
	var taskState, artifactState, runState string
	var released bool
	if err := pool.QueryRow(ctx, `SELECT t.state,a.state,r.state,b.released FROM agent_workflow.agent_tasks t JOIN agent_artifacts.metadata a ON a.workspace_id=t.workspace_id AND a.project_id=t.project_id AND a.artifact_id='artifact-scheduler' JOIN agent_control.agent_runs r ON r.workspace_id=t.workspace_id AND r.project_id=t.project_id AND r.run_id=t.run_id JOIN agent_control.budget_reservations b ON b.workspace_id=t.workspace_id AND b.project_id=t.project_id AND b.reservation_id=t.reservation_id WHERE t.workspace_id=$1 AND t.project_id=$2 AND t.task_id='task-scheduler'`, scope.WorkspaceID, scope.ProjectID).Scan(&taskState, &artifactState, &runState, &released); err != nil || taskState != "completed" || artifactState != "scanning" || runState != "validating" || !released {
		t.Fatalf("atomic task=%s artifact=%s run=%s released=%v err=%v", taskState, artifactState, runState, released, err)
	}
	usageStore, _ := usagepg.New(pool)
	sink := &usage.MemorySink{}
	pipeline, _ := usage.New(usageStore, sink)
	observation := usage.Observation{WorkspaceID: scope.WorkspaceID, ProjectID: scope.ProjectID, ObservationID: "usage-scheduler", RootRunID: "root-scheduler", RunID: "run-scheduler", TaskID: "task-scheduler", RecoveryEpoch: 2, ExecutionGeneration: 3, PhysicalAttemptID: "attempt-scheduler", ReservationID: "reservation-scheduler", ProviderEventID: "billing-scheduler", Meter: "provider-cost", Quantity: "40", Unit: "usd-micro", Currency: "USD", CostMicros: 40, MeterSequence: 1, Final: true, ObservedAt: now, Provider: "fake-worker", BuildIdentity: "build-scheduler", Traceparent: "00-0123456789abcdef0123456789abcdef-0123456789abcdef-01"}
	if accepted, err := pipeline.Accept(ctx, observation); err != nil || !accepted {
		t.Fatalf("usage accepted=%v err=%v", accepted, err)
	}
	if accepted, err := pipeline.Accept(ctx, observation); err != nil || accepted {
		t.Fatalf("usage replay accepted=%v err=%v", accepted, err)
	}
	conflictingUsage := observation
	conflictingUsage.ObservationID = "usage-scheduler-conflict"
	conflictingUsage.CostMicros++
	if _, err := pipeline.Accept(ctx, conflictingUsage); err == nil {
		t.Fatal("conflicting provider billing identity accepted")
	}
	other := observation
	other.ObservationID = "usage-other"
	other.ProviderEventID = ""
	other.RecoveryEpoch = 3
	other.ExecutionGeneration = 4
	other.PhysicalAttemptID = "attempt-other"
	if accepted, err := pipeline.Accept(ctx, other); err != nil || !accepted {
		t.Fatalf("distinct restored usage collapsed: %v %v", accepted, err)
	}

	injectedScope := scheduler.Scope{WorkspaceID: "workspace-scheduler-injected", ProjectID: "project-scheduler"}
	seedSchedulerResult(t, ctx, pool, injectedScope, "-injected", now)
	injected, _ := schedulerpg.New(pool, register, func(point schedulerpg.FailurePoint) error {
		if point == schedulerpg.AfterPromotion {
			return errors.New("injected transaction failure")
		}
		return nil
	})
	injectedResult := scheduler.Result{TaskID: "task-scheduler-injected", RecoveryEpoch: 2, ExecutionGeneration: 3, PhysicalAttemptID: "attempt-scheduler-injected", LeaseEpoch: 4, FenceToken: "opaque-fence-scheduler-injected", Capability: "fake.execute", BuildIdentity: "build-scheduler", ArtifactID: "artifact-scheduler-injected", ArtifactDigest: digest("b"), PendingObjectKey: "pending/task-scheduler-injected/r2/g3/attempt-scheduler-injected/output", CompletedAt: now}
	if accepted, err := injected.AcceptResult(ctx, injectedScope, injectedResult); err == nil || accepted {
		t.Fatalf("injected result accepted=%v err=%v", accepted, err)
	}
	var resultCount int
	var injectedTask, injectedArtifact, injectedRun string
	var injectedReleased bool
	if err := pool.QueryRow(ctx, `
		SELECT (SELECT count(*) FROM agent_workflow.worker_results WHERE workspace_id=$1),
		       t.state,a.state,r.state,b.released
		FROM agent_workflow.agent_tasks t
		JOIN agent_artifacts.metadata a ON a.workspace_id=t.workspace_id AND a.project_id=t.project_id AND a.artifact_id=$3
		JOIN agent_control.agent_runs r ON r.workspace_id=t.workspace_id AND r.project_id=t.project_id AND r.run_id=t.run_id
		JOIN agent_control.budget_reservations b ON b.workspace_id=t.workspace_id AND b.project_id=t.project_id AND b.reservation_id=t.reservation_id
		WHERE t.workspace_id=$1 AND t.project_id=$2 AND t.task_id=$4`,
		injectedScope.WorkspaceID, injectedScope.ProjectID, "artifact-scheduler-injected", "task-scheduler-injected").Scan(&resultCount, &injectedTask, &injectedArtifact, &injectedRun, &injectedReleased); err != nil || resultCount != 0 || injectedTask != "leased" || injectedArtifact != "pending" || injectedRun != "executing" || injectedReleased {
		t.Fatalf("rollback result=%d task=%s artifact=%s run=%s released=%v err=%v", resultCount, injectedTask, injectedArtifact, injectedRun, injectedReleased, err)
	}

	queueStore, _ := queuepg.New(pool)
	message := queue.Message{ID: "message-scheduler", WorkspaceID: scope.WorkspaceID, ProjectID: scope.ProjectID, RunID: "run-scheduler", TaskID: "task-scheduler", Topic: "agent-tasks", Payload: []byte(`{"runId":"run-scheduler"}`), Attempts: 1}
	if fresh, err := queueStore.Begin(ctx, message); err != nil || !fresh {
		t.Fatalf("queue begin fresh=%v err=%v", fresh, err)
	}
	if err := queueStore.Commit(ctx, message); err != nil {
		t.Fatal(err)
	}
	if fresh, err := queueStore.Begin(ctx, message); err != nil || fresh {
		t.Fatalf("queue duplicate fresh=%v err=%v", fresh, err)
	}
	if err := queueStore.Ack(ctx, message); err != nil {
		t.Fatal(err)
	}
	dlqMessage := queue.Message{ID: "message-scheduler-dlq", WorkspaceID: scope.WorkspaceID, ProjectID: scope.ProjectID, RunID: "run-scheduler", TaskID: "task-scheduler", Topic: "agent-tasks", Payload: []byte(`{"runId":"run-scheduler","taskId":"task-scheduler"}`), Attempts: 1}
	failingProcessor, _ := queue.New(queueStore, queueStore, failingQueueEffect{}, 1, nil)
	if err := failingProcessor.Handle(ctx, dlqMessage); err != nil {
		t.Fatal(err)
	}
	effect := &countingQueueEffect{}
	replayProcessor, _ := queue.New(queueStore, queueStore, effect, 1, nil)
	if err := queueStore.Replay(ctx, scope.WorkspaceID, scope.ProjectID, dlqMessage.ID, replayProcessor); err != nil {
		t.Fatal(err)
	}
	if err := queueStore.Replay(ctx, scope.WorkspaceID, scope.ProjectID, dlqMessage.ID, replayProcessor); err != nil || effect.count != 1 {
		t.Fatalf("durable replay count=%d err=%v", effect.count, err)
	}
}

type failingQueueEffect struct{}

func (failingQueueEffect) Write(context.Context, queue.Message) error {
	return errors.New("queue effect failed")
}

type countingQueueEffect struct{ count int }

func (e *countingQueueEffect) Write(context.Context, queue.Message) error { e.count++; return nil }

func seedSchedulerResult(t *testing.T, ctx context.Context, pool *pgxpool.Pool, scope scheduler.Scope, suffix string, now time.Time) {
	t.Helper()
	digest := func(c string) string { return "sha256:" + strings.Repeat(c, 64) }
	runID, rootRunID := "run-scheduler"+suffix, "root-scheduler"+suffix
	reservationID, artifactID := "reservation-scheduler"+suffix, "artifact-scheduler"+suffix
	taskID, attemptID := "task-scheduler"+suffix, "attempt-scheduler"+suffix
	statements := []struct {
		query string
		args  []any
	}{
		{`INSERT INTO agent_control.agent_runs(workspace_id,project_id,run_id,state,version,execution_generation,snapshot) VALUES($1,$2,$3,'executing',1,3,'{}')`, []any{scope.WorkspaceID, scope.ProjectID, runID}},
		{`INSERT INTO agent_control.budget_reservations(workspace_id,project_id,root_run_id,run_id,reservation_id,controller_generation,policy_version,budget_version,upper_bound_micros,attempt_final,expires_at) VALUES($1,$2,$3,$4,$5,1,'policy','budget',100,true,$6)`, []any{scope.WorkspaceID, scope.ProjectID, rootRunID, runID, reservationID, now.Add(time.Minute)}},
		{`INSERT INTO agent_artifacts.metadata(workspace_id,project_id,artifact_id,run_id,digest,actual_digest,state,security_generation,lineage,object_reference,schema_identity) VALUES($1,$2,$3,$4,$5,$5,'pending',1,'{}','{}','{}')`, []any{scope.WorkspaceID, scope.ProjectID, artifactID, runID, digest("b")}},
		{`INSERT INTO agent_workflow.agent_tasks(workspace_id,project_id,task_id,run_id,root_run_id,recovery_epoch,execution_generation,capability,reservation_id,input_digest,input_object_key,state,lease_epoch,physical_attempts,created_at) VALUES($1,$2,$3,$4,$5,2,3,'fake.execute',$6,$7,'inputs/task','leased',4,1,$8)`, []any{scope.WorkspaceID, scope.ProjectID, taskID, runID, rootRunID, reservationID, digest("a"), now}},
		{`INSERT INTO agent_workflow.worker_attempts(workspace_id,project_id,task_id,physical_attempt_id,recovery_epoch,execution_generation,attempt_number,lease_epoch,owner,issued_at,expires_at,fence_token,state) VALUES($1,$2,$3,$4,2,3,1,4,'worker',$5,$6,$7,'active')`, []any{scope.WorkspaceID, scope.ProjectID, taskID, attemptID, now, now.Add(time.Minute), schedulerFence(suffix)}},
	}
	for _, statement := range statements {
		if _, err := pool.Exec(ctx, statement.query, statement.args...); err != nil {
			t.Fatal(err)
		}
	}
}

func schedulerFence(suffix string) string {
	if suffix == "" {
		return "opaque-fence-scheduler-0001"
	}
	return "opaque-fence-scheduler" + suffix
}

// admittingArgumentValidator is a test double for the tool guard argument
// port; the pinned-schema validator is exercised by the execution suite.
type admittingArgumentValidator struct{}

func (admittingArgumentValidator) Validate(context.Context, tools.SchemaReference, json.RawMessage) error {
	return nil
}

type modelSleeper struct{}

func (modelSleeper) Sleep(context.Context, time.Duration) error { return nil }

type modelKeys struct{ value []byte }

func (keys modelKeys) Key(context.Context, string) ([]byte, error) {
	return append([]byte(nil), keys.value...), nil
}

// fixedAttemptBudget authorizes every physical attempt at the request's own
// ceilings; budget policy itself is exercised by the planning and runner
// suites.
type fixedAttemptBudget struct {
	inputTokens, outputTokens, costMicros int64
}

func (b fixedAttemptBudget) Authorize(int, modelgateway.Usage) (modelgateway.AttemptLimits, error) {
	return modelgateway.AttemptLimits{MaximumInputTokens: b.inputTokens, MaximumOutputTokens: b.outputTokens, MaximumTotalTokens: b.inputTokens + b.outputTokens, MaximumCostMicros: b.costMicros}, nil
}

func assertModelEvidence(t *testing.T, ctx context.Context, pool *pgxpool.Pool) {
	t.Helper()
	snapshot := modelgateway.Snapshot{Version: "v1", Providers: []modelgateway.Provider{{ID: modelgateway.FakeProviderID, ModelVersion: "fake-v1", Regions: []string{"test"}, DataClasses: []modelgateway.DataClass{modelgateway.Internal}, Capabilities: []string{"plan"}, SafetyLevel: 3, MaximumCostMicros: 600, Priority: 1, Enabled: true}}}
	registry, err := modelgateway.NewRegistry(snapshot)
	if err != nil {
		t.Fatal(err)
	}
	snapshotStore, _ := modelpg.NewSnapshotStore(pool)
	if err := snapshotStore.Put(ctx, "workspace-model", "project-model", registry.Current()); err != nil {
		t.Fatal(err)
	}
	changedSnapshot := snapshot
	changedSnapshot.Providers = append([]modelgateway.Provider(nil), snapshot.Providers...)
	changedSnapshot.Providers[0].Enabled = false
	changedRegistry, _ := modelgateway.NewRegistry(changedSnapshot)
	if err := snapshotStore.Put(ctx, "workspace-model", "project-model", changedRegistry.Current()); err == nil {
		t.Fatal("durable registry version was reused for different content")
	}
	recorder, _ := modelpg.NewInvocationRecorder(pool)
	gateway, err := modelgateway.NewGateway(map[modelgateway.ProviderID]modelgateway.Adapter{modelgateway.FakeProviderID: modelgateway.FakeAdapter{}}, recorder, testClock{time.Unix(400, 0)}, modelSleeper{})
	if err != nil {
		t.Fatal(err)
	}
	policy := modelgateway.Policy{Version: "policy-v1", AllowedProviders: []modelgateway.ProviderID{modelgateway.FakeProviderID}, AllowedRegions: []string{"test"}, DataClasses: []modelgateway.DataClass{modelgateway.Internal}, Capability: "plan", MinimumSafety: 2, MaximumCostMicros: 1000}
	_, record, err := gateway.InvokeEligible(ctx, registry, policy, modelgateway.InvokeRequest{RunID: "run-model", WorkspaceID: "workspace-model", ProjectID: "project-model", IdempotencyKey: "run-model:g1:turn-0000", Context: []byte("minimal"), DataClasses: []modelgateway.DataClass{modelgateway.Internal}, MaximumOutputBytes: 4096, MaximumInputTokens: 256, MaximumOutputTokens: 2000, MaximumTotalTokens: 2256, MaximumCostMicros: 1000, Timeout: time.Second, MaximumAttempts: 1, Scenario: "valid", Budget: fixedAttemptBudget{inputTokens: 256, outputTokens: 2000, costMicros: 1000}})
	if err != nil || len(record.PhysicalAttempts) != 1 {
		t.Fatalf("durable invocation=%#v err=%v", record, err)
	}
	// Provider identities are derived from the caller's durable operation
	// key, so the durable evidence must carry exactly that identity.
	invocationID := modelgateway.InvocationIdentity("run-model:g1:turn-0000")
	if record.InvocationID != invocationID {
		t.Fatalf("invocation identity %q is not derived from the durable operation key", record.InvocationID)
	}
	var attempts []byte
	if err := pool.QueryRow(ctx, `SELECT physical_attempt_ids FROM agent_workflow.provider_invocations WHERE workspace_id='workspace-model' AND project_id='project-model' AND invocation_id=$1`, invocationID).Scan(&attempts); err != nil || !bytes.Contains(attempts, []byte(modelgateway.AttemptIdentity(invocationID, 1))) {
		t.Fatalf("physical attempt was not durable before disclosure: %s %v", attempts, err)
	}
	var policyDigest string
	var policySnapshot []byte
	if err := pool.QueryRow(ctx, `SELECT policy_digest,policy_snapshot FROM agent_workflow.provider_invocations WHERE workspace_id='workspace-model' AND project_id='project-model' AND invocation_id=$1`, invocationID).Scan(&policyDigest, &policySnapshot); err != nil || policyDigest != record.PolicyDigest || !bytes.Contains(policySnapshot, []byte(`"policy-v1"`)) {
		t.Fatalf("immutable policy evidence digest=%s snapshot=%s err=%v", policyDigest, policySnapshot, err)
	}
	durableRecord, err := recorder.Get(ctx, "workspace-model", "project-model", invocationID)
	if err != nil || durableRecord.PolicyDigest != record.PolicyDigest || !reflect.DeepEqual(durableRecord.PolicySnapshot, record.PolicySnapshot) || len(durableRecord.PhysicalAttempts) != 1 {
		t.Fatalf("durable invocation reload=%#v err=%v", durableRecord, err)
	}
	if replayed, err := registry.ReplayInvocation(durableRecord); err != nil || replayed.Provider.ID != record.Provider {
		t.Fatalf("historical invocation replay=%#v err=%v", replayed, err)
	}
	changedPolicy := policy
	changedPolicy.MaximumCostMicros--
	independentRegistry, _ := modelgateway.NewRegistry(snapshot)
	changedSelection, _ := independentRegistry.Select("workspace-model", changedPolicy)
	forgedPolicyRecord := record
	forgedPolicyRecord.InvocationID = invocationID + ".forged-policy"
	forgedPolicyRecord.PolicyDigest = changedSelection.PolicyDigest
	forgedPolicyRecord.PolicySnapshot = changedSelection.PolicySnapshot
	if err := recorder.BeforeDisclosure(ctx, forgedPolicyRecord); err == nil {
		t.Fatal("durable provider policy version was reused for different content")
	}
	if _, err := pool.Exec(ctx, `UPDATE agent_workflow.provider_invocations SET provider='mutated' WHERE workspace_id='workspace-model' AND project_id='project-model' AND invocation_id=$1`, invocationID); err == nil {
		t.Fatal("durable invocation identity was mutable")
	}
	if _, err := pool.Exec(ctx, `UPDATE agent_workflow.provider_invocations SET policy_snapshot='{}'::jsonb WHERE workspace_id='workspace-model' AND project_id='project-model' AND invocation_id=$1`, invocationID); err == nil {
		t.Fatal("durable invocation policy snapshot was mutable")
	}
	if _, err := pool.Exec(ctx, `UPDATE agent_workflow.provider_invocations SET cost_micros=cost_micros+1 WHERE workspace_id='workspace-model' AND project_id='project-model' AND invocation_id=$1`, invocationID); err == nil {
		t.Fatal("completed invocation accounting was mutable")
	}

	continuationStore, _ := modelpg.NewContinuationStore(pool, "workspace-model", "project-model")
	continuations, _ := modelgateway.NewContinuations(modelKeys{bytes.Repeat([]byte{4}, 32)}, "kms://model", continuationStore, testClock{time.Unix(400, 0)})
	secret := []byte("provider-continuation-secret")
	binding := "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	if err := continuations.Save(ctx, "continuation-model", modelgateway.FakeProviderID, secret, binding, time.Unix(500, 0), modelgateway.RestartStage); err != nil {
		t.Fatal(err)
	}
	var encrypted, keyReference string
	if err := pool.QueryRow(ctx, `SELECT encrypted_binding,key_reference FROM agent_workflow.provider_continuations WHERE workspace_id='workspace-model' AND project_id='project-model' AND continuation_id='continuation-model'`).Scan(&encrypted, &keyReference); err != nil || bytes.Contains([]byte(encrypted), secret) || keyReference != "kms://model" {
		t.Fatalf("continuation plaintext/key reference persisted incorrectly: key=%s err=%v", keyReference, err)
	}
	resumed, err := continuations.Resume(ctx, "continuation-model", binding, "planning:safe")
	if err != nil || !bytes.Equal(resumed.Continuation, secret) || resumed.Restarted {
		t.Fatalf("durable continuation resume=%#v err=%v", resumed, err)
	}
	if _, err := pool.Exec(ctx, `UPDATE agent_workflow.provider_continuations SET key_reference='kms://substituted' WHERE workspace_id='workspace-model' AND project_id='project-model' AND continuation_id='continuation-model'`); err != nil {
		t.Fatal(err)
	}
	tampered, err := continuations.Resume(ctx, "continuation-model", binding, "planning:safe")
	if err != nil || !tampered.Restarted || tampered.Checkpoint != "planning:safe" {
		t.Fatalf("continuation key substitution became authority: %#v err=%v", tampered, err)
	}

	contextRecorder, _ := contextpg.New(pool)
	contextPolicy := contextcompiler.PolicyReference{PolicyID: "policy", Version: "v1", Digest: binding}
	compiler := contextcompiler.New([]string{"registered-secret"})
	compiled, err := compiler.CompileAndRecord(ctx, contextcompiler.Request{WorkspaceID: "workspace-model", ProjectID: "project-model", RunID: "run-model", Policy: contextPolicy, RedactionPolicy: contextPolicy, TotalTokens: 8, CompiledAt: time.Unix(400, 0), Sources: []contextcompiler.Source{{ID: "system", Trust: contextcompiler.System, Classification: contextcompiler.Internal, Content: "policy", WorkspaceID: "workspace-model", TokenBudget: 2}, {ID: "user", Trust: contextcompiler.User, Classification: contextcompiler.Internal, Content: "registered-secret", WorkspaceID: "workspace-model", TokenBudget: 4}}}, contextRecorder)
	if err != nil || bytes.Contains([]byte(compiled.Disclosure[1].Content), []byte("registered-secret")) {
		t.Fatalf("compiled context=%#v err=%v", compiled, err)
	}

	toolRecorder, _ := toolpg.New(pool)
	toolPolicy := tools.PolicyReference{PolicyID: "policy", Version: "v1", Digest: binding}
	schema := tools.SchemaReference{ComponentName: "anvilkit.contract.schema.synthetic", Digest: binding}
	definition := func(id, capability string) tools.Definition {
		return tools.Definition{Kind: "ToolDefinition", Capability: capability, InputSchema: schema, OutputSchema: schema, SideEffectClass: "none", RiskClass: "low", ApprovalPolicy: toolPolicy, TimeoutPolicy: tools.TimeoutPolicy{TimeoutMilliseconds: 1000}, RetryPolicy: tools.RetryPolicy{MaximumAttempts: 1, Retryability: []string{}}, AcceptedDataClasses: []string{"internal"}, ToolID: id}
	}
	profile, _ := tools.NewProfile("manager", "v1", toolPolicy, []tools.Definition{definition("fake.execute", "fake.execute"), definition("contract.validate", "contract.validate"), definition("artifact.scan", "artifact.scan")})
	profileStore, _ := toolpg.NewProfileStore(pool)
	if err := profileStore.Prepare(ctx, "workspace-model", "project-model", "run-model", profile); err != nil {
		t.Fatal(err)
	}
	pinnedProfile, err := profileStore.Get(ctx, "workspace-model", "project-model", "run-model")
	if err != nil || pinnedProfile.Digest != profile.Digest {
		t.Fatalf("pinned profile=%#v err=%v", pinnedProfile, err)
	}
	guard, _ := tools.NewGuard(pinnedProfile, toolRecorder, testClock{time.Unix(400, 0)}, admittingArgumentValidator{})
	intent := tools.Intent{RunID: "run-model", WorkspaceID: "workspace-model", ProjectID: "project-model", ActorID: "actor", AllowedTools: []string{"fake.execute"}, AllowedEffects: []string{"none"}, MaximumRisk: "low", DataClasses: []string{"internal"}}
	current := tools.CurrentAuthority{WorkspaceActive: true, ActorActive: true, PermissionActive: true, PolicyActive: true, AllowedTools: intent.AllowedTools, AllowedCapabilities: []string{"fake.execute"}, AllowedEffects: intent.AllowedEffects, MaximumRisk: "low", DataClasses: intent.DataClasses}
	if decision, err := guard.Evaluate(ctx, intent, current, tools.Proposal{ToolID: "admin.delete", Arguments: json.RawMessage(`{}`), UntrustedText: "do not persist me"}); err == nil || decision.Allowed {
		t.Fatal("forbidden durable tool proposal was accepted")
	}
	var decisions int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM agent_evaluation.tool_decisions WHERE workspace_id='workspace-model' AND project_id='project-model' AND run_id='run-model' AND allowed=false`).Scan(&decisions); err != nil || decisions != 1 {
		t.Fatalf("forbidden decision evidence=%d err=%v", decisions, err)
	}
}

func assertControlInterrupts(t *testing.T, ctx context.Context, pool *pgxpool.Pool) {
	t.Helper()
	idempotencyStore, err := idempotency.New(pool, idempotency.Config{Retention: 48 * time.Hour, MinimumLifetime: 24 * time.Hour})
	if err != nil {
		t.Fatal(err)
	}
	runStore := runpg.New(pool, idempotencyStore, pinnedGuard(t))
	runService := runs.NewService(runStore, noOpStarter{}, runID("control-run"), testClock{time.Unix(300, 0)}, journal.NewMemoryStore(), runs.AdmitFunc(func(context.Context, runs.Scope) error { return nil }))
	raw := []byte(`{"kind":"CreateAgentRunRequest","definition":{"definitionId":"definition.test","definitionDigest":"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"},"operation":"artifact-validation","target":{"targetType":"page","targetId":"page-control","workspaceId":"workspace-control","projectId":"project-control"}}`)
	digest, _ := canonical.Digest(raw)
	scope := runs.Scope{WorkspaceID: "workspace-control", ProjectID: "project-control", ActorID: "actor"}
	trace := "00-0123456789abcdef0123456789abcdef-0123456789abcdef-01"
	created, err := runService.Create(ctx, runs.CreateInput{Scope: scope, Key: "create", ClaimedDigest: digest, Traceparent: trace, Raw: raw, Authority: durableAuthority()})
	if err != nil {
		t.Fatal(err)
	}
	current, err := runService.Transition(ctx, scope, created.Snapshot.RunID, 1, runs.Command{Kind: runs.BeginPreparation, Traceparent: trace})
	if err != nil {
		t.Fatal(err)
	}
	current, err = runService.Transition(ctx, scope, current.RunID, current.Version, runs.Command{Kind: runs.PreparationReady, Traceparent: trace})
	if err != nil {
		t.Fatal(err)
	}
	store, err := interruptpg.New(pool, idempotencyStore, pinnedGuard(t))
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	schema := json.RawMessage(`{"type":"object","required":["answer"],"properties":{"answer":{"type":"string"}},"additionalProperties":false}`)
	write := interrupts.Write{Scope: scope, RunID: current.RunID, ExpectedVersion: current.Version, IdempotencyKey: "open-input", Traceparent: trace}
	request, result, err := store.OpenInput(ctx, write, interrupts.InputRequest{ID: "input-1", RunID: current.RunID, Version: 1, Question: "question", ResponseSchema: schema, ExpiresAt: now.Add(time.Hour), ResumeCheckpoint: "planning", CreatedAt: now}, "sha256:open")
	if err != nil || result.Snapshot.Status != runs.AwaitingInput {
		t.Fatalf("open input result=%#v err=%v", result, err)
	}
	if _, err := pool.Exec(ctx, `UPDATE agent_control.input_requests SET question='mutated' WHERE workspace_id=$1 AND project_id=$2 AND run_id=$3 AND request_id=$4`, scope.WorkspaceID, scope.ProjectID, current.RunID, request.ID); err == nil {
		t.Fatal("immutable input evidence was mutable")
	}
	responseWrite := interrupts.Write{Scope: scope, RunID: current.RunID, ExpectedVersion: result.Snapshot.Version, IdempotencyKey: "respond-input", Traceparent: trace}
	response, err := store.AcceptInput(ctx, responseWrite, interrupts.InputResponseCommand{RequestID: request.ID, RequestVersion: 1, Value: json.RawMessage(`{"answer":"yes"}`)}, "sha256:response", now)
	if err != nil || response.Snapshot.Status != runs.Planning {
		t.Fatalf("input response=%#v err=%v", response, err)
	}
	replayed, err := store.AcceptInput(ctx, responseWrite, interrupts.InputResponseCommand{RequestID: request.ID, RequestVersion: 1, Value: json.RawMessage(`{"answer":"yes"}`)}, "sha256:response", now)
	if err != nil || !replayed.Replayed || replayed.Snapshot.Version != response.Snapshot.Version {
		t.Fatalf("input replay=%#v err=%v", replayed, err)
	}
	secondWrite := interrupts.Write{Scope: scope, RunID: current.RunID, ExpectedVersion: response.Snapshot.Version, IdempotencyKey: "open-input-2", Traceparent: trace}
	second, secondOpened, err := store.OpenInput(ctx, secondWrite, interrupts.InputRequest{ID: "input-2", RunID: current.RunID, Version: 99, Question: "second question", ResponseSchema: schema, ExpiresAt: now.Add(time.Hour), ResumeCheckpoint: "planning-2", CreatedAt: now}, "sha256:open-2")
	if err != nil || second.Version != 2 || secondOpened.Snapshot.Status != runs.AwaitingInput {
		t.Fatalf("second input=%#v result=%#v err=%v", second, secondOpened, err)
	}
	secondResponseWrite := interrupts.Write{Scope: scope, RunID: current.RunID, ExpectedVersion: secondOpened.Snapshot.Version, IdempotencyKey: "respond-input-2", Traceparent: trace}
	secondResponse, err := store.AcceptInput(ctx, secondResponseWrite, interrupts.InputResponseCommand{RequestID: second.ID, RequestVersion: second.Version, Value: json.RawMessage(`{"answer":"again"}`)}, "sha256:response-2", now)
	if err != nil || secondResponse.Snapshot.Status != runs.Planning {
		t.Fatalf("second input response=%#v err=%v", secondResponse, err)
	}
	var eventCount, checkpointCount int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM agent_events.agent_events WHERE workspace_id=$1 AND project_id=$2 AND run_id=$3`, scope.WorkspaceID, scope.ProjectID, current.RunID).Scan(&eventCount); err != nil {
		t.Fatal(err)
	}
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM agent_workflow.checkpoints WHERE workspace_id=$1 AND project_id=$2 AND workflow_id=$3`, scope.WorkspaceID, scope.ProjectID, string(current.RunID)+":g1").Scan(&checkpointCount); err != nil {
		t.Fatal(err)
	}
	// Seven state transitions checkpoint; the two opened input requests each
	// add a public run.input-requested event without a checkpoint.
	if eventCount != 9 || checkpointCount != 7 {
		t.Fatalf("atomic Control evidence events=%d checkpoints=%d", eventCount, checkpointCount)
	}
	outbox, err := eventpg.NewOutboxStore(pool)
	if err != nil {
		t.Fatal(err)
	}
	publisher := &eventPublisherCapture{}
	if _, err := outbox.DispatchReady(ctx, publisher, 1000); err != nil {
		t.Fatal(err)
	}
	var publishedCount int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM agent_events.outbox WHERE workspace_id=$1 AND project_id=$2 AND run_id=$3 AND published_at IS NOT NULL`, scope.WorkspaceID, scope.ProjectID, current.RunID).Scan(&publishedCount); err != nil || publishedCount != 9 {
		t.Fatalf("published outbox count=%d err=%v", publishedCount, err)
	}
	if len(publisher.messages) < publishedCount {
		t.Fatalf("publisher received %d messages, want at least %d", len(publisher.messages), publishedCount)
	}
	childBudget, err := interruptpg.NewChildBudgetReservation(pool, 400_000_000, 1_000_000_000, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	budgetRequest := interrupts.ChildBudgetRequest{Write: interrupts.Write{Scope: scope, RunID: current.RunID, ExpectedVersion: secondResponse.Snapshot.Version, IdempotencyKey: "reserve-child", Traceparent: trace}, ChildRunID: "budget-child-1", Mode: interrupts.ChildRequired, Digest: "sha256:" + strings.Repeat("a", 64), RequestedAt: now}
	staleBudgetRequest := budgetRequest
	staleBudgetRequest.Write.IdempotencyKey = "reserve-child-stale"
	staleBudgetRequest.Write.ExpectedVersion--
	var staleBudget problem.Details
	if err := childBudget.ReserveChild(ctx, staleBudgetRequest); !errors.As(err, &staleBudget) || staleBudget.Code != string(problem.CodeVersionConflict) {
		t.Fatalf("stale child budget reservation err=%v", err)
	}
	if err := childBudget.ReserveChild(ctx, budgetRequest); err != nil {
		t.Fatalf("child budget reservation failed: %v", err)
	}
	budgetRequest.ChildRunID = "discarded-retry-id"
	if err := childBudget.ReserveChild(ctx, budgetRequest); err != nil {
		t.Fatalf("idempotent child budget replay failed: %v", err)
	}
	changed := budgetRequest
	changed.Digest = "sha256:" + strings.Repeat("b", 64)
	var conflict problem.Details
	if err := childBudget.ReserveChild(ctx, changed); !errors.As(err, &conflict) || conflict.Code != string(problem.CodeIdempotencyConflict) {
		t.Fatalf("changed child reservation replay err=%v", err)
	}
	exhausted := budgetRequest
	exhausted.Write.IdempotencyKey = "reserve-child-exhausted"
	exhausted.ChildRunID = "budget-child-2"
	var denied problem.Details
	if err := childBudget.ReserveChild(ctx, exhausted); !errors.As(err, &denied) || denied.Code != string(problem.CodeBudgetDenied) {
		t.Fatalf("exhausted root budget err=%v", err)
	}
	var childReservations int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM agent_control.budget_reservations WHERE workspace_id=$1 AND project_id=$2 AND root_run_id=$3 AND run_id LIKE 'budget-child-%'`, scope.WorkspaceID, scope.ProjectID, current.RunID).Scan(&childReservations); err != nil || childReservations != 1 {
		t.Fatalf("child budget reservations=%d err=%v", childReservations, err)
	}

	progress, err := store.Progress(ctx)
	if err != nil {
		t.Fatal(err)
	}
	var currentProgress interrupts.Progress
	for _, item := range progress {
		if item.Scope.WorkspaceID == scope.WorkspaceID && item.Scope.ProjectID == scope.ProjectID && item.RunID == current.RunID {
			currentProgress = item
			break
		}
	}
	if currentProgress.RunID == "" || currentProgress.State != runs.Planning {
		t.Fatalf("Control diagnostic progress missing: %#v", currentProgress)
	}
	breachedAt := now.Add(2 * time.Hour)
	if marked, err := store.MarkStuck(ctx, currentProgress, breachedAt, ""); err == nil || marked {
		t.Fatalf("invalid durable alert unexpectedly committed marked=%t err=%v", marked, err)
	}
	var stuckAt *time.Time
	if err := pool.QueryRow(ctx, `SELECT stuck_at FROM agent_control.run_progress WHERE workspace_id=$1 AND project_id=$2 AND run_id=$3`, scope.WorkspaceID, scope.ProjectID, current.RunID).Scan(&stuckAt); err != nil || stuckAt != nil {
		t.Fatalf("failed stuck transaction left marker=%v err=%v", stuckAt, err)
	}
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM agent_events.agent_events WHERE workspace_id=$1 AND project_id=$2 AND run_id=$3`, scope.WorkspaceID, scope.ProjectID, current.RunID).Scan(&eventCount); err != nil || eventCount != 9 {
		t.Fatalf("failed stuck transaction leaked event count=%d err=%v", eventCount, err)
	}
	marked, err := store.MarkStuck(ctx, currentProgress, breachedAt, "agent-service-oncall")
	if err != nil || !marked {
		t.Fatalf("durable stuck marker failed marked=%t err=%v", marked, err)
	}
	marked, err = store.MarkStuck(ctx, currentProgress, breachedAt.Add(time.Minute), "agent-service-oncall")
	if err != nil || marked {
		t.Fatalf("durable stuck marker was not idempotent marked=%t err=%v", marked, err)
	}
	var alertCount int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM agent_control.run_alerts WHERE workspace_id=$1 AND project_id=$2 AND run_id=$3 AND state=$4`, scope.WorkspaceID, scope.ProjectID, current.RunID, runs.Planning).Scan(&alertCount); err != nil || alertCount != 1 {
		t.Fatalf("durable stuck alert count=%d err=%v", alertCount, err)
	}
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM agent_events.agent_events WHERE workspace_id=$1 AND project_id=$2 AND run_id=$3`, scope.WorkspaceID, scope.ProjectID, current.RunID).Scan(&eventCount); err != nil || eventCount != 10 {
		t.Fatalf("durable stuck event count=%d err=%v", eventCount, err)
	}
	afterStuck, err := store.Current(ctx, scope, current.RunID)
	if err != nil || afterStuck.Status != runs.Planning || afterStuck.Version != secondResponse.Snapshot.Version {
		t.Fatalf("dwell breach invented outcome=%#v err=%v", afterStuck, err)
	}
	afterControlTransition, err := runService.Transition(ctx, scope, current.RunID, afterStuck.Version, runs.Command{Kind: runs.BeginExecution, Traceparent: trace})
	if err != nil || afterControlTransition.Status != runs.Executing {
		t.Fatalf("transition after control event=%#v err=%v", afterControlTransition, err)
	}
	staleCancel := interrupts.Write{Scope: scope, RunID: current.RunID, ExpectedVersion: afterStuck.Version - 1, IdempotencyKey: "stale-cancel", Traceparent: trace}
	_, _, err = store.RequestCancellation(ctx, staleCancel, "sha256:stale-cancel", now)
	var staleDetails problem.Details
	if !errors.As(err, &staleDetails) || staleDetails.Code != string(problem.CodeVersionConflict) {
		t.Fatalf("stale Control precondition err=%v", err)
	}
	cancelWrite := interrupts.Write{Scope: scope, RunID: current.RunID, ExpectedVersion: afterControlTransition.Version, IdempotencyKey: "cancel", Traceparent: trace}
	cancellation, cancelling, err := store.RequestCancellation(ctx, cancelWrite, "sha256:cancel", now)
	if err != nil || cancelling.Snapshot.Status != runs.Cancelling {
		t.Fatalf("durable cancellation request=%#v cancellation=%#v err=%v", cancelling, cancellation, err)
	}
	cancellation.DispatchStopped = true
	cancellation.ChildrenPropagated = true
	cancellation.LeasesRevoked = true
	cancellation.Reconciled = true
	if err := store.RecordCancellation(ctx, cancelWrite, cancellation); err != nil {
		t.Fatal(err)
	}
	finishedWrite := interrupts.Write{Scope: scope, RunID: current.RunID, ExpectedVersion: cancelling.Snapshot.Version, IdempotencyKey: "cancel:reconciled", Traceparent: trace}
	finished, err := store.FinishCancellation(ctx, finishedWrite, cancellation)
	if err != nil || finished.Snapshot.Status != runs.Cancelled {
		t.Fatalf("reconciled cancellation=%#v err=%v", finished, err)
	}
	var cancellationEvidence []byte
	if err := pool.QueryRow(ctx, `SELECT evidence FROM agent_control.lifecycle_controls WHERE workspace_id=$1 AND project_id=$2 AND run_id=$3 AND control_id=$4`, scope.WorkspaceID, scope.ProjectID, current.RunID, cancelWrite.IdempotencyKey).Scan(&cancellationEvidence); err != nil {
		t.Fatal(err)
	}
	var durableCancellation interrupts.Cancellation
	if err := json.Unmarshal(cancellationEvidence, &durableCancellation); err != nil || !durableCancellation.DispatchStopped || !durableCancellation.ChildrenPropagated || !durableCancellation.LeasesRevoked || !durableCancellation.Reconciled || durableCancellation.ExternalUncertain {
		t.Fatalf("cancellation progress evidence=%#v err=%v", durableCancellation, err)
	}
	replayedFinish, err := store.FinishCancellation(ctx, finishedWrite, cancellation)
	if err != nil || !replayedFinish.Replayed || replayedFinish.Snapshot.Version != finished.Snapshot.Version {
		t.Fatalf("reconciled cancellation replay=%#v err=%v", replayedFinish, err)
	}
	guard, err := contractguard.NewGuard("../..")
	if err != nil {
		t.Fatal(err)
	}
	replay, err := eventpg.NewReader(pool, guard).Replay(ctx, events.ReplayRequest{Scope: events.Scope{WorkspaceID: scope.WorkspaceID, ProjectID: scope.ProjectID}, RunID: string(current.RunID), Limit: 100})
	if err != nil || len(replay.Events) != 13 {
		t.Fatalf("control event replay: events=%d err=%v", len(replay.Events), err)
	}
	if err := events.ValidateContiguous(replay.Events, 0); err != nil {
		t.Fatal(err)
	}
}

type eventPublisherCapture struct{ messages []events.OutboxMessage }

func (p *eventPublisherCapture) Publish(_ context.Context, message events.OutboxMessage) error {
	p.messages = append(p.messages, message)
	return nil
}

func assertDurableCreateLatency(t *testing.T, ctx context.Context, pool *pgxpool.Pool) {
	t.Helper()
	const arrivalInterval = 50 * time.Millisecond // pinned 20 accepted requests/second
	duration := 25 * time.Second
	if configured := os.Getenv("DURABLE_CREATE_LOAD_DURATION"); configured != "" {
		parsed, err := time.ParseDuration(configured)
		if err != nil || parsed < arrivalInterval {
			t.Fatalf("DURABLE_CREATE_LOAD_DURATION must be a duration of at least %s", arrivalInterval)
		}
		duration = parsed
	}
	if deadline, ok := t.Deadline(); ok && time.Until(deadline) < duration+time.Minute {
		t.Fatalf("go test deadline is too short for DURABLE_CREATE_LOAD_DURATION=%s; use -timeout of at least %s", duration, duration+time.Minute)
	}
	requests := int(duration / arrivalInterval)
	idempotencyStore, err := idempotency.New(pool, idempotency.Config{Retention: 48 * time.Hour, MinimumLifetime: 24 * time.Hour})
	if err != nil {
		t.Fatal(err)
	}
	service := runs.NewService(runpg.New(pool, idempotencyStore, pinnedGuard(t)), noOpStarter{}, &sequentialRunIDs{}, testClock{time.Now().UTC()}, journal.NewMemoryStore(), runs.AdmitFunc(func(context.Context, runs.Scope) error { return nil }))
	scope := runs.Scope{WorkspaceID: "workspace-durable-load", ProjectID: "project-durable-load", ActorID: "actor"}
	authority := durableAuthority()
	latencies := make([]time.Duration, requests)
	errorsByRequest := make(chan error, requests)
	start := time.Now()
	var wait sync.WaitGroup
	for index := range requests {
		wait.Add(1)
		go func(index int) {
			defer wait.Done()
			target := start.Add(time.Duration(index) * arrivalInterval)
			if delay := time.Until(target); delay > 0 {
				timer := time.NewTimer(delay)
				defer timer.Stop()
				select {
				case <-ctx.Done():
					errorsByRequest <- ctx.Err()
					return
				case <-timer.C:
				}
			}
			raw := []byte(fmt.Sprintf(`{"kind":"CreateAgentRunRequest","definition":{"definitionId":"definition.test","definitionDigest":"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"},"operation":"artifact-validation","target":{"targetType":"page","targetId":"load-%06d","workspaceId":"workspace-durable-load","projectId":"project-durable-load"}}`, index))
			digest, digestErr := canonical.Digest(raw)
			if digestErr != nil {
				errorsByRequest <- digestErr
				return
			}
			acceptedAt := time.Now()
			_, createErr := service.Create(ctx, runs.CreateInput{Scope: scope, Key: fmt.Sprintf("durable-load-%06d", index), ClaimedDigest: digest, Traceparent: "00-0123456789abcdef0123456789abcdef-0123456789abcdef-01", Raw: raw, Authority: authority})
			latencies[index] = time.Since(acceptedAt)
			if createErr != nil {
				errorsByRequest <- createErr
			}
		}(index)
	}
	wait.Wait()
	close(errorsByRequest)
	for err := range errorsByRequest {
		t.Error(err)
	}
	if t.Failed() {
		return
	}
	sort.Slice(latencies, func(left, right int) bool { return latencies[left] < latencies[right] })
	p95 := latencies[(requests*95+99)/100-1]
	t.Logf("pinned durable-create load: duration=%s requests=%d arrival_rate=20/s p95=%s", duration, requests, p95)
	if evidencePath := os.Getenv("DURABLE_CREATE_EVIDENCE_PATH"); evidencePath != "" {
		result := struct {
			SchemaVersion         int     `json:"schemaVersion"`
			LoadModel             string  `json:"loadModel"`
			DurationMilliseconds  int64   `json:"durationMilliseconds"`
			Requests              int     `json:"requests"`
			ArrivalRatePerSecond  int     `json:"arrivalRatePerSecond"`
			P95Milliseconds       float64 `json:"p95Milliseconds"`
			ThresholdMilliseconds int64   `json:"thresholdMilliseconds"`
			Passed                bool    `json:"passed"`
		}{1, "agent-service-load-model", duration.Milliseconds(), requests, 20, float64(p95) / float64(time.Millisecond), 300, p95 < 300*time.Millisecond}
		raw, err := json.MarshalIndent(result, "", "  ")
		if err != nil {
			t.Fatal(err)
		}
		if err := os.MkdirAll(filepath.Dir(evidencePath), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(evidencePath, append(raw, '\n'), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if p95 >= 300*time.Millisecond {
		t.Fatalf("durable create P95 %s exceeds 300ms", p95)
	}
}

type noOpStarter struct{}

func (noOpStarter) Ensure(context.Context, runs.Start) error { return nil }

type sequentialRunIDs struct{ next atomic.Uint64 }

func (ids *sequentialRunIDs) NewID() (runs.ID, error) {
	return runs.ID(fmt.Sprintf("durable-load-run-%06d", ids.next.Add(1))), nil
}

func assertDurableRunCore(t *testing.T, ctx context.Context, pool *pgxpool.Pool) {
	t.Helper()
	idempotencyStore, err := idempotency.New(pool, idempotency.Config{Retention: 48 * time.Hour, MinimumLifetime: 24 * time.Hour})
	if err != nil {
		t.Fatal(err)
	}
	store := runpg.New(pool, idempotencyStore, pinnedGuard(t))
	starter := &durableStarter{store: store, started: make(map[string]bool)}
	service := runs.NewService(store, starter, runID("durable-run"), testClock{time.Unix(200, 0)}, journal.NewMemoryStore(), runs.AdmitFunc(func(context.Context, runs.Scope) error { return nil }))
	raw := []byte(`{"kind":"CreateAgentRunRequest","definition":{"definitionId":"definition.test","definitionDigest":"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"},"operation":"artifact-validation","target":{"targetType":"page","targetId":"page-durable","workspaceId":"workspace-durable","projectId":"project-durable"}}`)
	digest, _ := canonical.Digest(raw)
	scope := runs.Scope{WorkspaceID: "workspace-durable", ProjectID: "project-durable", ActorID: "actor"}
	input := runs.CreateInput{Scope: scope, Key: "durable-key", ClaimedDigest: digest, Traceparent: "00-0123456789abcdef0123456789abcdef-0123456789abcdef-01", Raw: raw, Authority: durableAuthority()}
	var wait sync.WaitGroup
	outcomes := make(chan runs.CreateOutcome, 8)
	failures := make(chan error, 8)
	for range 8 {
		wait.Add(1)
		go func() {
			defer wait.Done()
			outcome, err := service.Create(ctx, input)
			if err != nil {
				failures <- err
				return
			}
			outcomes <- outcome
		}()
	}
	wait.Wait()
	close(outcomes)
	close(failures)
	for err := range failures {
		t.Error(err)
	}
	var response []byte
	replayed := 0
	for outcome := range outcomes {
		if response == nil {
			response = outcome.Bytes
		}
		if string(response) != string(outcome.Bytes) {
			t.Fatal("create replay bytes changed")
		}
		if outcome.Replayed {
			replayed++
		}
	}
	if replayed != 7 || starter.Count() != 1 {
		t.Fatalf("replayed=%d workflowStarts=%d", replayed, starter.Count())
	}
	missing, err := service.Get(ctx, runs.Scope{WorkspaceID: "other", ProjectID: "project-durable", ActorID: "actor"}, "durable-run")
	_ = missing
	assertProblemCode(t, err, problem.CodeResourceNotFound)
	_, err = service.Get(ctx, scope, "absent")
	assertProblemCode(t, err, problem.CodeResourceNotFound)
	page, err := service.List(ctx, scope, runs.ListOptions{Limit: 1})
	if err != nil || len(page.Items) != 1 {
		t.Fatalf("page=%#v err=%v", page, err)
	}
	different := []byte(`{"kind":"CreateAgentRunRequest","definition":{"definitionId":"definition.test","definitionDigest":"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"},"operation":"image-operation","target":{"targetType":"page","targetId":"page-durable","workspaceId":"workspace-durable","projectId":"project-durable"}}`)
	differentDigest, _ := canonical.Digest(different)
	conflicting := input
	conflicting.Raw = different
	conflicting.ClaimedDigest = differentDigest
	// The same key with changed canonical bytes is the governed
	// IDEMPOTENCY_KEY_REUSED (ADR-021 §4), reported as its own code rather
	// than folded into the general idempotency conflict.
	_, err = service.Create(ctx, conflicting)
	assertProblemCode(t, err, problem.CodeIdempotencyKeyReused)
	transitionErrors := make(chan error, 2)
	for range 2 {
		wait.Add(1)
		go func() {
			defer wait.Done()
			_, transitionErr := service.Transition(ctx, scope, "durable-run", 1, runs.Command{Kind: runs.BeginPreparation, Traceparent: input.Traceparent})
			transitionErrors <- transitionErr
		}()
	}
	wait.Wait()
	close(transitionErrors)
	winners, conflicts := 0, 0
	for err := range transitionErrors {
		if err == nil {
			winners++
		} else {
			var details problem.Details
			if errors.As(err, &details) && details.Code == string(problem.CodeVersionConflict) {
				conflicts++
			} else {
				t.Errorf("unexpected transition error %v", err)
			}
		}
	}
	if winners != 1 || conflicts != 1 {
		t.Fatalf("winners=%d conflicts=%d", winners, conflicts)
	}
	current, err := service.Get(ctx, scope, "durable-run")
	if err != nil || current.Version != 2 || current.Status != runs.Preparing {
		t.Fatalf("current=%#v err=%v", current, err)
	}
	guard, err := contractguard.NewGuard("../..")
	if err != nil {
		t.Fatal(err)
	}
	reader := eventpg.NewReader(pool, guard)
	eventScope := events.Scope{WorkspaceID: scope.WorkspaceID, ProjectID: scope.ProjectID}
	allEvents, err := reader.Replay(ctx, events.ReplayRequest{Scope: eventScope, RunID: "durable-run", Limit: 100})
	if err != nil || len(allEvents.Events) != 2 {
		t.Fatalf("full replay=%#v err=%v", allEvents, err)
	}
	replay, err := reader.Replay(ctx, events.ReplayRequest{Scope: eventScope, RunID: "durable-run", AfterEventID: "durable-run:1", Limit: 100})
	if err != nil || len(replay.Events) != 1 || replay.Events[0].Sequence != 2 {
		t.Fatalf("strictly-after replay=%#v err=%v", replay, err)
	}
	for _, event := range allEvents.Events {
		findings := guard.Validate(ctx, contractguard.EventIn, "anvilkit://schema/agent-event?digest=sha256:2fdd8937381427507e721675ebbd66144595a193b53ba460534e9712df9b774a", event.Bytes)
		if len(findings) != 0 {
			t.Fatalf("persisted event is not contract-valid: %#v raw=%s", findings, event.Bytes)
		}
	}
	if err := events.ValidateContiguous(replay.Events, 1); err != nil {
		t.Fatal(err)
	}
	projection, err := reader.Snapshot(ctx, eventScope, "durable-run")
	if err != nil || projection.Cursor != "durable-run:2" || len(projection.Run) == 0 {
		t.Fatalf("snapshot=%#v err=%v", projection, err)
	}
	if findings := guard.Validate(ctx, contractguard.APIIn, "anvilkit://schema/agent-run?digest=sha256:e293860d680a93c9fa5d8c3907201ac3a6a54b7a81cbb81fd5bcb6f332497564", projection.Run); len(findings) != 0 {
		t.Fatalf("snapshot run is not contract-valid: %#v raw=%s", findings, projection.Run)
	}
	// The snapshot is the documented recovery path for an expired cursor, so
	// the whole rendered document — not only the run inside it — has to
	// satisfy the governed contract that recovery is described by.
	rendered, err := json.Marshal(projection)
	if err != nil {
		t.Fatal(err)
	}
	if err := guard.Require(ctx, contractguard.SnapshotOut, events.AgentRunSnapshotSchemaURI, rendered); err != nil {
		t.Fatalf("snapshot recovery document is not contract-valid: %v raw=%s", err, rendered)
	}
	var recovered events.SnapshotProjection
	if err := json.Unmarshal(rendered, &recovered); err != nil || recovered.Cursor != projection.Cursor {
		t.Fatalf("snapshot recovery document did not round-trip: %#v err=%v", recovered, err)
	}
	afterSnapshot, err := reader.Replay(ctx, events.ReplayRequest{Scope: eventScope, RunID: "durable-run", AfterEventID: projection.Cursor, Limit: 100})
	if err != nil || len(afterSnapshot.Events) != 0 {
		t.Fatalf("snapshot resume duplicated or lost: %#v %v", afterSnapshot, err)
	}
	advanced, err := service.Transition(ctx, scope, "durable-run", current.Version, runs.Command{Kind: runs.PreparationReady, Traceparent: input.Traceparent})
	if err != nil || advanced.Version != 3 || advanced.Status != runs.Planning {
		t.Fatalf("post-snapshot transition=%#v err=%v", advanced, err)
	}
	afterSnapshot, err = reader.Replay(ctx, events.ReplayRequest{Scope: eventScope, RunID: "durable-run", AfterEventID: projection.Cursor, Limit: 100})
	if err != nil || len(afterSnapshot.Events) != 1 || afterSnapshot.Events[0].ID != "durable-run:3" || afterSnapshot.Events[0].Sequence != 3 {
		t.Fatalf("snapshot resume lost or duplicated post-snapshot event: %#v %v", afterSnapshot, err)
	}
	_, err = reader.Replay(ctx, events.ReplayRequest{Scope: eventScope, RunID: "durable-run", AfterEventID: "expired", Limit: 100})
	assertProblemCode(t, err, problem.CodeCursorExpired)
	// A cursor whose event has aged past the deployment's retention window
	// answers 410 even while the bytes still exist: clients recover through
	// the snapshot, never through an unbounded replay contract.
	retained, err := eventpg.NewRetainedReader(pool, guard, events.DefaultBounds(), time.Hour, func() time.Time { return time.Now().Add(48 * time.Hour) })
	if err != nil {
		t.Fatal(err)
	}
	_, err = retained.Replay(ctx, events.ReplayRequest{Scope: eventScope, RunID: "durable-run", AfterEventID: "durable-run:1", Limit: 100})
	assertProblemCode(t, err, problem.CodeCursorExpired)
	fresh, err := eventpg.NewRetainedReader(pool, guard, events.DefaultBounds(), 720*time.Hour, func() time.Time { return time.Unix(200, 0).Add(time.Minute) })
	if err != nil {
		t.Fatal(err)
	}
	if _, err := fresh.Replay(ctx, events.ReplayRequest{Scope: eventScope, RunID: "durable-run", AfterEventID: "durable-run:1", Limit: 100}); err != nil {
		t.Fatalf("a cursor inside the retention window must replay: %v", err)
	}
	// Eight concurrent creates and every later replay produced one durable
	// event per identity. The store below has no append a caller could use to
	// add a second account of one, so the count is decided by the projector
	// alone: each stored event has exactly one provenance record, and each of
	// those names evidence recorded in the same run.
	var duplicated int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM (SELECT event_id FROM agent_events.agent_events WHERE workspace_id=$1 AND project_id=$2 AND run_id='durable-run' GROUP BY event_id HAVING count(*)>1) repeated`, eventScope.WorkspaceID, eventScope.ProjectID).Scan(&duplicated); err != nil || duplicated != 0 {
		t.Fatalf("event identities stored more than once=%d err=%v", duplicated, err)
	}
	var unexplained int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM agent_events.agent_events e LEFT JOIN agent_events.event_provenance p ON p.workspace_id=e.workspace_id AND p.project_id=e.project_id AND p.event_id=e.event_id LEFT JOIN agent_evidence.records d ON d.workspace_id=p.workspace_id AND d.project_id=p.project_id AND d.evidence_id=p.evidence_id AND d.run_id=p.run_id WHERE e.workspace_id=$1 AND e.project_id=$2 AND e.run_id='durable-run' AND (p.event_id IS NULL OR d.evidence_id IS NULL OR p.run_id<>e.run_id)`, eventScope.WorkspaceID, eventScope.ProjectID).Scan(&unexplained); err != nil || unexplained != 0 {
		t.Fatalf("durable events without correlated provenance and source evidence=%d err=%v", unexplained, err)
	}
}

func assertDurableRunStoreAtomicity(t *testing.T, ctx context.Context, pool *pgxpool.Pool) {
	t.Helper()
	idempotencyStore, err := idempotency.New(pool, idempotency.Config{Retention: 48 * time.Hour, MinimumLifetime: 24 * time.Hour})
	if err != nil {
		t.Fatal(err)
	}
	points := []runpg.FailurePoint{runpg.AfterRunWrite, runpg.AfterEventWrite, runpg.AfterOutboxWrite, runpg.AfterCheckpointWrite}
	traceparent := "00-0123456789abcdef0123456789abcdef-0123456789abcdef-01"
	for index, point := range points {
		runID := runs.ID(fmt.Sprintf("durable-atomic-create-%d", index))
		scope := runs.Scope{WorkspaceID: "workspace-durable-atomic", ProjectID: "project-durable-atomic", ActorID: "actor"}
		raw := []byte(fmt.Sprintf(`{"kind":"CreateAgentRunRequest","definition":{"definitionId":"definition.test","definitionDigest":"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"},"operation":"artifact-validation","target":{"targetType":"page","targetId":"atomic-create-%d","workspaceId":"workspace-durable-atomic","projectId":"project-durable-atomic"}}`, index))
		digest, _ := canonical.Digest(raw)
		store := runpg.NewConfigured(pool, idempotencyStore, events.DefaultBounds(), pinnedGuard(t), func(actual runpg.FailurePoint) error {
			if actual == point {
				return errors.New("fault")
			}
			return nil
		})
		service := runs.NewService(store, noOpStarter{}, runIDGenerator(runID), testClock{time.Unix(250, 0)}, journal.NewMemoryStore(), runs.AdmitFunc(func(context.Context, runs.Scope) error { return nil }))
		if _, err := service.Create(ctx, runs.CreateInput{Scope: scope, Key: fmt.Sprintf("atomic-create-%d", index), ClaimedDigest: digest, Traceparent: traceparent, Raw: raw, Authority: durableAuthority()}); err == nil {
			t.Fatalf("create failure %s did not abort", point)
		}
		assertDurableAtomicCounts(t, ctx, pool, scope, runID, 0, 0)

		base := runs.NewService(runpg.New(pool, idempotencyStore, pinnedGuard(t)), noOpStarter{}, runIDGenerator(runID), testClock{time.Unix(250, 0)}, journal.NewMemoryStore(), runs.AdmitFunc(func(context.Context, runs.Scope) error { return nil }))
		created, err := base.Create(ctx, runs.CreateInput{Scope: scope, Key: fmt.Sprintf("atomic-base-%d", index), ClaimedDigest: digest, Traceparent: traceparent, Raw: raw, Authority: durableAuthority()})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := store.Transition(ctx, scope, runID, created.Snapshot.Version, runs.Command{Kind: runs.BeginPreparation, Traceparent: traceparent}); err == nil {
			t.Fatalf("transition failure %s did not abort", point)
		}
		assertDurableAtomicCounts(t, ctx, pool, scope, runID, 1, 1)
	}
}

func assertDurableAtomicCounts(t *testing.T, ctx context.Context, pool *pgxpool.Pool, scope runs.Scope, runID runs.ID, wantVersion, wantEvidence int) {
	t.Helper()
	var version, eventCount, outboxCount, checkpointCount int
	err := pool.QueryRow(ctx, `SELECT version FROM agent_control.agent_runs WHERE workspace_id=$1 AND project_id=$2 AND run_id=$3`, scope.WorkspaceID, scope.ProjectID, runID).Scan(&version)
	if wantVersion == 0 {
		if !errors.Is(err, pgx.ErrNoRows) {
			t.Fatalf("rolled-back run %s remains visible: version=%d err=%v", runID, version, err)
		}
	} else if err != nil || version != wantVersion {
		t.Fatalf("run %s version=%d err=%v want=%d", runID, version, err, wantVersion)
	}
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM agent_events.agent_events WHERE workspace_id=$1 AND project_id=$2 AND run_id=$3`, scope.WorkspaceID, scope.ProjectID, runID).Scan(&eventCount); err != nil {
		t.Fatal(err)
	}
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM agent_events.outbox WHERE workspace_id=$1 AND project_id=$2 AND run_id=$3`, scope.WorkspaceID, scope.ProjectID, runID).Scan(&outboxCount); err != nil {
		t.Fatal(err)
	}
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM agent_workflow.checkpoints WHERE workspace_id=$1 AND project_id=$2 AND workflow_id=$3`, scope.WorkspaceID, scope.ProjectID, string(runID)+":g1").Scan(&checkpointCount); err != nil {
		t.Fatal(err)
	}
	if eventCount != wantEvidence || outboxCount != wantEvidence || checkpointCount != wantEvidence {
		t.Fatalf("run %s partial evidence: events=%d outbox=%d checkpoints=%d want=%d", runID, eventCount, outboxCount, checkpointCount, wantEvidence)
	}
}

func durableAuthority() runs.Authority {
	policy := []byte(`{"policyId":"policy.synthetic","version":"v1","digest":"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}`)
	return runs.Authority{
		Definition:  []byte(`{"definitionId":"definition.synthetic.001","definitionDigest":"sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd"}`),
		ContractBOM: []byte(`{"repository":"anvilkit/contracts","bomDigest":"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","ociManifestDigest":"sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","evidenceManifestDigest":"sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"}`),
		Policy:      policy,
		Budget:      []byte(`{"kind":"AgentBudget","modelLimits":{"maximumCalls":10,"maximumConcurrentCalls":2},"tokenLimits":{"inputTokens":4096,"outputTokens":2048,"totalTokens":6144},"workerLimits":{"maximumAttempts":4,"maximumDurationMilliseconds":60000},"gpuLimits":{"maximumGpuMilliseconds":0},"currencyLimits":{"maximumCost":{"amount":"1000","currency":"USD"},"reservedCost":{"amount":"500","currency":"USD"}},"reservationId":"reservation.synthetic.001","exceedBehavior":"refuse","policy":` + string(policy) + `}`),
	}
}

type runID string

func (id runID) NewID() (runs.ID, error) { return runs.ID(id), nil }

type runIDGenerator runs.ID

func (id runIDGenerator) NewID() (runs.ID, error) { return runs.ID(id), nil }

func pinnedGuard(t *testing.T) *contractguard.Guard {
	t.Helper()
	guard, err := contractguard.NewGuard("../..")
	if err != nil {
		t.Fatal(err)
	}
	return guard
}

type testClock struct{ value time.Time }

func (c testClock) Now() time.Time { return c.value }

type durableStarter struct {
	lock    sync.Mutex
	store   runs.Store
	started map[string]bool
}

func (s *durableStarter) Ensure(ctx context.Context, start runs.Start) error {
	s.lock.Lock()
	defer s.lock.Unlock()
	if _, err := s.store.Get(ctx, start.Scope, start.RunID); err != nil {
		return fmt.Errorf("workflow started before durable run: %w", err)
	}
	s.started[fmt.Sprintf("%s:g%d", start.RunID, start.Generation)] = true
	return nil
}
func (s *durableStarter) Count() int { s.lock.Lock(); defer s.lock.Unlock(); return len(s.started) }
func assertProblemCode(t *testing.T, err error, code problem.Code) {
	t.Helper()
	var details problem.Details
	if !errors.As(err, &details) || details.Code != string(code) {
		t.Fatalf("got error %v, want %s", err, code)
	}
}

func assertRoleIsolation(t *testing.T, ctx context.Context, connection *pgx.Conn) {
	t.Helper()
	if _, err := connection.Exec(ctx, `SET ROLE agent_control_rw`); err != nil {
		t.Fatal(err)
	}
	if _, err := connection.Exec(ctx, `SELECT count(*) FROM agent_control.agent_runs`); err != nil {
		t.Fatalf("control role cannot read control schema: %v", err)
	}
	if _, err := connection.Exec(ctx, `SELECT count(*) FROM agent_events.agent_events`); err == nil {
		t.Fatal("control role read events schema")
	}
	if _, err := connection.Exec(ctx, `RESET ROLE`); err != nil {
		t.Fatal(err)
	}
}

func assertScopedRepository(t *testing.T, ctx context.Context, pool *pgxpool.Pool) {
	t.Helper()
	repository := persistence.NewRunRepository(pool)
	if err := repository.Insert(ctx, persistence.Scope{}, persistence.RunRecord{RunID: "unscoped"}); err == nil {
		t.Fatal("unscoped repository write accepted")
	}
	record := persistence.RunRecord{RunID: "scoped", State: "created", Version: 1, ExecutionGeneration: 1, Snapshot: []byte(`{"runId":"scoped"}`)}
	if err := repository.Insert(ctx, persistence.Scope{WorkspaceID: "w", ProjectID: "p"}, record); err != nil {
		t.Fatal(err)
	}
	if _, err := repository.Get(ctx, persistence.Scope{WorkspaceID: "other", ProjectID: "p"}, "scoped"); !errors.Is(err, pgx.ErrNoRows) {
		t.Fatalf("cross-workspace get disclosed record: %v", err)
	}
}

// assertProjectedEventsAndInbox proves the two durable boundaries the event
// schema owns. The public one has a single write path — the repository-owned
// projector — and it is atomic: the evidence, the event, its provenance, and
// the outbox hand-off land together or not at all, and a projection outside
// the registry never reaches the store. The consumer inbox is the other, and
// it writes no public event at all.
func assertProjectedEventsAndInbox(t *testing.T, ctx context.Context, pool *pgxpool.Pool) {
	t.Helper()
	guard, err := contractguard.NewGuard("../..")
	if err != nil {
		t.Fatal(err)
	}
	scope := events.Scope{WorkspaceID: "w", ProjectID: "p"}
	const runID = "run-projected"
	now := time.Unix(1300, 0).UTC()

	// A type outside the closed public registry is not projectable, so it
	// never reaches the store.
	unregistered := projectedFact(t, runID, runID+":1", 1, now)
	unregistered.Projection.Type = "model.call-completed"
	if _, err := attemptProjectedFact(ctx, pool, scope, unregistered, guard); err == nil {
		t.Fatal("an internal step name was projected onto the public wire")
	}
	// Neither is a payload whose field set the registry does not declare.
	widened := projectedFact(t, runID, runID+":1", 1, now)
	widened.Projection.Payload = map[string]string{"previousState": "created", "state": "preparing", "providerRequestId": "req-1"}
	if _, err := attemptProjectedFact(ctx, pool, scope, widened, guard); err == nil {
		t.Fatal("an unregistered payload field was projected onto the public wire")
	}
	// Nor is prohibited content, whatever registered field carries it.
	prohibited := projectedFact(t, runID, runID+":1", 1, now)
	prohibited.Projection.Payload = events.StateChangedPayload("created", "secret")
	if _, err := attemptProjectedFact(ctx, pool, scope, prohibited, guard); err == nil {
		t.Fatal("prohibited content was projected onto the public wire")
	}
	assertNoProjectedResidue(t, ctx, pool, runID)

	// A transaction that does not commit leaves nothing behind: the evidence,
	// the event, its provenance, and the outbox hand-off are one write.
	writer, err := eventpg.NewProjectionWriter(guard, events.DefaultBounds(), func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	abandoned, err := pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := writer.Write(ctx, abandoned, scope, projectedFact(t, runID, runID+":1", 1, now)); err != nil {
		t.Fatal(err)
	}
	if err := abandoned.Rollback(ctx); err != nil {
		t.Fatal(err)
	}
	assertNoProjectedResidue(t, ctx, pool, runID)

	// Committed, all four land together.
	projected := writeProjectedFact(t, ctx, pool, scope, projectedFact(t, runID, runID+":1", 1, now))
	var eventCount, provenanceCount, evidenceCount, outboxCount int
	if err := pool.QueryRow(ctx, `SELECT (SELECT count(*) FROM agent_events.agent_events WHERE run_id=$1),(SELECT count(*) FROM agent_events.event_provenance WHERE run_id=$1),(SELECT count(*) FROM agent_evidence.records WHERE run_id=$1),(SELECT count(*) FROM agent_events.outbox WHERE run_id=$1)`, runID).Scan(&eventCount, &provenanceCount, &evidenceCount, &outboxCount); err != nil {
		t.Fatal(err)
	}
	if eventCount != 1 || provenanceCount != 1 || evidenceCount != 1 || outboxCount != 1 {
		t.Fatalf("event=%d provenance=%d evidence=%d outbox=%d, want one of each", eventCount, provenanceCount, evidenceCount, outboxCount)
	}
	var recordedEvidence, recordedDigest string
	if err := pool.QueryRow(ctx, `SELECT evidence_id,projector_digest FROM agent_events.event_provenance WHERE run_id=$1`, runID).Scan(&recordedEvidence, &recordedDigest); err != nil {
		t.Fatal(err)
	}
	if recordedEvidence != projected.EvidenceID || recordedDigest != projected.ProjectorDigest {
		t.Fatalf("recorded provenance=(%q,%q), want the projector's own (%q,%q)", recordedEvidence, recordedDigest, projected.EvidenceID, projected.ProjectorDigest)
	}

	inbox, err := eventpg.NewInbox(pool)
	if err != nil {
		t.Fatal(err)
	}
	message := events.InboxMessage{Scope: scope, Consumer: "consumer", MessageID: "message", Digest: []byte("digest")}
	if got, err := inbox.Accept(ctx, message); err != nil || got != events.InboxAccepted {
		t.Fatalf("first inbox=%s %v", got, err)
	}
	if got, err := inbox.Accept(ctx, message); err != nil || got != events.InboxDuplicate {
		t.Fatalf("duplicate inbox=%s %v", got, err)
	}
	message.Digest = []byte("different")
	if _, err := inbox.Accept(ctx, message); err == nil {
		t.Fatal("duplicate message with different bytes accepted")
	}
	// Accepting a message is a delivery fact, not a public event: nothing the
	// inbox did added to the run's public history.
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM agent_events.agent_events WHERE run_id=$1`, runID).Scan(&eventCount); err != nil || eventCount != 1 {
		t.Fatalf("public events after inbox activity=%d err=%v, want the one projected event", eventCount, err)
	}
}

// assertNoProjectedResidue proves a refused or abandoned projection left
// nothing durable behind — no event, no provenance, no evidence, no hand-off.
func assertNoProjectedResidue(t *testing.T, ctx context.Context, pool *pgxpool.Pool, runID string) {
	t.Helper()
	var eventCount, provenanceCount, evidenceCount, outboxCount int
	if err := pool.QueryRow(ctx, `SELECT (SELECT count(*) FROM agent_events.agent_events WHERE run_id=$1),(SELECT count(*) FROM agent_events.event_provenance WHERE run_id=$1),(SELECT count(*) FROM agent_evidence.records WHERE run_id=$1),(SELECT count(*) FROM agent_events.outbox WHERE run_id=$1)`, runID).Scan(&eventCount, &provenanceCount, &evidenceCount, &outboxCount); err != nil {
		t.Fatal(err)
	}
	if eventCount != 0 || provenanceCount != 0 || evidenceCount != 0 || outboxCount != 0 {
		t.Fatalf("residue after a refused projection: event=%d provenance=%d evidence=%d outbox=%d", eventCount, provenanceCount, evidenceCount, outboxCount)
	}
}

func validEventBytes(eventID, runID string, sequence uint64, eventType string) []byte {
	value := map[string]any{
		"kind":        "AgentEvent",
		"eventId":     eventID,
		"runId":       runID,
		"workspaceId": "w",
		"projectId":   "p",
		"sequence":    sequence,
		"eventType":   eventType,
		"occurredAt":  "2026-08-13T12:00:00.000Z",
		"subject": map[string]string{
			"subjectType": "system",
			"subjectId":   "agent-service",
		},
		"traceContext": map[string]string{
			"traceparent": "00-0123456789abcdef0123456789abcdef-0123456789abcdef-01",
		},
		"contractBomReference": map[string]string{
			"repository":             "anvilkit/contracts",
			"bomDigest":              "sha256:" + strings.Repeat("a", 64),
			"ociManifestDigest":      "sha256:" + strings.Repeat("b", 64),
			"evidenceManifestDigest": "sha256:" + strings.Repeat("c", 64),
		},
		"payload": map[string]string{"state": "preparing"},
	}
	raw, _ := json.Marshal(value)
	return raw
}

func assertIdempotency(t *testing.T, ctx context.Context, pool *pgxpool.Pool) {
	t.Helper()
	if _, err := pool.Exec(ctx, `INSERT INTO agent_control.agent_runs(workspace_id,project_id,run_id,state,version,execution_generation,snapshot) VALUES('w','p','idem','created',1,1,'{}')`); err != nil {
		t.Fatal(err)
	}
	store, err := idempotency.New(pool, idempotency.Config{Retention: 48 * time.Hour, MinimumLifetime: 24 * time.Hour})
	if err != nil {
		t.Fatal(err)
	}
	request := idempotency.Request{WorkspaceID: "w", ProjectID: "p", Subject: "actor-idem", Method: "POST", Operation: "cancel", Key: "same", Digest: []byte("canonical"), RunID: "idem", VersionBound: 1}
	var calls atomic.Int64
	handler := func(ctx context.Context, tx pgx.Tx) (idempotency.Response, error) {
		calls.Add(1)
		time.Sleep(10 * time.Millisecond)
		if _, err := tx.Exec(ctx, `UPDATE agent_control.agent_runs SET version=2 WHERE workspace_id='w' AND project_id='p' AND run_id='idem'`); err != nil {
			return idempotency.Response{}, err
		}
		return idempotency.Response{Status: 200, ContentType: "application/json", Body: []byte(`{"version":2}`)}, nil
	}
	var wait sync.WaitGroup
	results := make(chan idempotency.Response, 12)
	failures := make(chan error, 12)
	for range 12 {
		wait.Add(1)
		go func() {
			defer wait.Done()
			response, err := store.Execute(ctx, request, handler)
			if err != nil {
				failures <- err
				return
			}
			results <- response
		}()
	}
	wait.Wait()
	close(results)
	close(failures)
	for err := range failures {
		t.Error(err)
	}
	for response := range results {
		if string(response.Body) != `{"version":2}` || response.VersionBound != 1 {
			t.Errorf("unstable replay %#v", response)
		}
	}
	if calls.Load() != 1 {
		t.Fatalf("handler called %d times", calls.Load())
	}
	different := request
	different.Digest = []byte("different")
	if _, err := store.Execute(ctx, different, handler); err == nil {
		t.Fatal("same key with different digest accepted")
	}
	stale := request
	stale.Key = "fresh"
	stale.Digest = []byte("fresh")
	stale.VersionBound = 1
	ran := false
	if _, err := store.Execute(ctx, stale, func(context.Context, pgx.Tx) (idempotency.Response, error) {
		ran = true
		return idempotency.Response{}, nil
	}); err == nil || ran {
		t.Fatal("stale precondition with fresh key mutated")
	}
	// Key isolation includes the authenticated subject and the method: a
	// different actor presenting the same key and digest is a fresh execution,
	// never a replay of the first actor's recorded response (ADR-021 §4).
	crossActor := request
	crossActor.Subject = "actor-other"
	crossActor.VersionBound = 2
	crossActorRan := false
	crossActorResponse, err := store.Execute(ctx, crossActor, func(ctx context.Context, tx pgx.Tx) (idempotency.Response, error) {
		crossActorRan = true
		return idempotency.Response{Status: 200, ContentType: "application/json", Body: []byte(`{"actor":"other"}`)}, nil
	})
	if err != nil || !crossActorRan || crossActorResponse.Replayed || string(crossActorResponse.Body) != `{"actor":"other"}` {
		t.Fatalf("cross-actor execution response=%#v ran=%v err=%v, want an independent execution", crossActorResponse, crossActorRan, err)
	}
	crossMethod := request
	crossMethod.Method = "INTERNAL"
	crossMethod.VersionBound = 2
	crossMethodRan := false
	if _, err := store.Execute(ctx, crossMethod, func(context.Context, pgx.Tx) (idempotency.Response, error) {
		crossMethodRan = true
		return idempotency.Response{Status: 200, ContentType: "application/json", Body: []byte(`{}`)}, nil
	}); err != nil || !crossMethodRan {
		t.Fatalf("cross-method execution ran=%v err=%v, want an independent execution", crossMethodRan, err)
	}
}

// clusterRoleLockKey is the cluster-wide advisory lock coordinating the
// cluster-global service roles: isolated test databases hold it shared for
// their lifetime; the migration rollback that drops the roles takes it
// exclusively.
const clusterRoleLockKey = 0x5750334b

func isolatedDatabase(t *testing.T, ctx context.Context, baseURL string) (string, func()) {
	t.Helper()
	admin, err := pgx.Connect(ctx, baseURL)
	if err != nil {
		t.Fatal(err)
	}
	random := make([]byte, 6)
	if _, err := rand.Read(random); err != nil {
		t.Fatal(err)
	}
	name := "agent_workflow_" + hex.EncodeToString(random)
	if _, err := admin.Exec(ctx, fmt.Sprintf(`CREATE DATABASE %s TEMPLATE template0`, pgx.Identifier{name}.Sanitize())); err != nil {
		t.Fatal(err)
	}
	parsed, err := url.Parse(baseURL)
	if err != nil {
		t.Fatal(err)
	}
	parsed.Path = "/" + name
	databaseURL := parsed.String()
	return databaseURL, func() {
		_, _ = admin.Exec(context.Background(), fmt.Sprintf(`DROP DATABASE IF EXISTS %s WITH (FORCE)`, pgx.Identifier{name}.Sanitize()))
		_ = admin.Close(context.Background())
	}
}

// assertDurableInterruptExpiry proves the atomic expiry seam against real
// SQL: expiry and acceptance contend for the same request row, exactly one
// wins, and the durable marker makes the loser fail closed.
func assertDurableInterruptExpiry(t *testing.T, ctx context.Context, pool *pgxpool.Pool, admin *pgxpool.Pool) {
	t.Helper()
	idempotencyStore, err := idempotency.New(pool, idempotency.Config{Retention: 48 * time.Hour, MinimumLifetime: 24 * time.Hour})
	if err != nil {
		t.Fatal(err)
	}
	store, err := interruptpg.New(pool, idempotencyStore, pinnedGuard(t))
	if err != nil {
		t.Fatal(err)
	}
	trace := "00-0123456789abcdef0123456789abcdef-0123456789abcdef-01"
	schema := json.RawMessage(`{"type":"object","required":["answer"],"properties":{"answer":{"type":"string"}},"additionalProperties":false}`)
	now := time.Now().UTC()
	failure := problem.New(problem.CodeInputRequestExpired, "")
	failure.Detail = "the durable input deadline elapsed before a response was accepted"

	awaiting := func(suffix string) (runs.Scope, runs.Snapshot, interrupts.InputRequest, interrupts.OperationResult) {
		t.Helper()
		runStore := runpg.New(pool, idempotencyStore, pinnedGuard(t))
		runService := runs.NewService(runStore, noOpStarter{}, runID("expiry-run-"+suffix), testClock{time.Unix(300, 0)}, journal.NewMemoryStore(), runs.AdmitFunc(func(context.Context, runs.Scope) error { return nil }))
		raw := []byte(fmt.Sprintf(`{"kind":"CreateAgentRunRequest","definition":{"definitionId":"definition.test","definitionDigest":"sha256:%s"},"operation":"artifact-validation","target":{"targetType":"page","targetId":"page-expiry","workspaceId":"workspace-expiry-%s","projectId":"project-expiry"}}`, strings.Repeat("a", 64), suffix))
		digest, _ := canonical.Digest(raw)
		scope := runs.Scope{WorkspaceID: "workspace-expiry-" + suffix, ProjectID: "project-expiry", ActorID: "actor"}
		created, err := runService.Create(ctx, runs.CreateInput{Scope: scope, Key: "create", ClaimedDigest: digest, Traceparent: trace, Raw: raw, Authority: durableAuthority()})
		if err != nil {
			t.Fatal(err)
		}
		current, err := runService.Transition(ctx, scope, created.Snapshot.RunID, 1, runs.Command{Kind: runs.BeginPreparation, Traceparent: trace})
		if err != nil {
			t.Fatal(err)
		}
		current, err = runService.Transition(ctx, scope, current.RunID, current.Version, runs.Command{Kind: runs.PreparationReady, Traceparent: trace})
		if err != nil {
			t.Fatal(err)
		}
		write := interrupts.Write{Scope: scope, RunID: current.RunID, ExpectedVersion: current.Version, IdempotencyKey: "open-input", Traceparent: trace}
		request, opened, err := store.OpenInput(ctx, write, interrupts.InputRequest{ID: interrupts.RequestID("input-expiry-" + suffix), RunID: current.RunID, Version: 1, Question: "question", ResponseSchema: schema, ExpiresAt: now.Add(time.Hour), ResumeCheckpoint: "planning", CreatedAt: now}, "sha256:open-"+suffix)
		if err != nil || opened.Snapshot.Status != runs.AwaitingInput {
			t.Fatalf("open input result=%#v err=%v", opened, err)
		}
		return scope, current, request, opened
	}

	// Expiry commits: the run fails, the request is durably expired, and a
	// response inside its original deadline can no longer revive it.
	scope, current, request, opened := awaiting("expired")
	expireWrite := interrupts.Write{Scope: scope, RunID: current.RunID, ExpectedVersion: opened.Snapshot.Version, IdempotencyKey: "expire-input", Traceparent: trace}
	expiry, err := store.ExpireInput(ctx, expireWrite, request.ID, failure, now)
	if err != nil || expiry.Raced || expiry.Superseded || expiry.Snapshot.Status != runs.Failed {
		t.Fatalf("durable expiry=%#v err=%v", expiry, err)
	}
	stored, err := store.Input(ctx, scope, current.RunID, request.ID)
	if err != nil || stored.ExpiredAt == nil || stored.Response != nil {
		t.Fatalf("expired request=%#v err=%v", stored, err)
	}
	respondWrite := interrupts.Write{Scope: scope, RunID: current.RunID, ExpectedVersion: expiry.Snapshot.Version, IdempotencyKey: "respond-late", Traceparent: trace}
	_, err = store.AcceptInput(ctx, respondWrite, interrupts.InputResponseCommand{RequestID: request.ID, RequestVersion: request.Version, Value: json.RawMessage(`{"answer":"late"}`)}, "sha256:late", now)
	var details problem.Details
	if !errors.As(err, &details) || details.Code != string(problem.CodeInputRequestExpired) {
		t.Fatalf("late response error=%v", err)
	}
	replayedExpiry, err := store.ExpireInput(ctx, expireWrite, request.ID, failure, now)
	if err != nil || replayedExpiry.Snapshot.Version != expiry.Snapshot.Version {
		t.Fatalf("replayed expiry=%#v err=%v", replayedExpiry, err)
	}

	// Acceptance wins: expiry reports the race, writes no marker, and leaves
	// the answered run alive for its workflow.
	answeredScope, answered, answeredRequest, answeredOpened := awaiting("answered")
	acceptWrite := interrupts.Write{Scope: answeredScope, RunID: answered.RunID, ExpectedVersion: answeredOpened.Snapshot.Version, IdempotencyKey: "respond-input", Traceparent: trace}
	accepted, err := store.AcceptInput(ctx, acceptWrite, interrupts.InputResponseCommand{RequestID: answeredRequest.ID, RequestVersion: answeredRequest.Version, Value: json.RawMessage(`{"answer":"yes"}`)}, "sha256:answered", now)
	if err != nil || accepted.Snapshot.Status != runs.Planning {
		t.Fatalf("accepted response=%#v err=%v", accepted, err)
	}
	raced, err := store.ExpireInput(ctx, interrupts.Write{Scope: answeredScope, RunID: answered.RunID, ExpectedVersion: accepted.Snapshot.Version, IdempotencyKey: "expire-answered", Traceparent: trace}, answeredRequest.ID, failure, now)
	if err != nil || !raced.Raced {
		t.Fatalf("answered request lost the race: %#v err=%v", raced, err)
	}
	answeredStored, err := store.Input(ctx, answeredScope, answered.RunID, answeredRequest.ID)
	if err != nil || answeredStored.ExpiredAt != nil {
		t.Fatalf("answered request was also expired: %#v err=%v", answeredStored, err)
	}
	if final, err := store.Current(ctx, answeredScope, answered.RunID); err != nil || final.Status != runs.Planning {
		t.Fatalf("answered run=%#v err=%v", final, err)
	}

	// Another authority moved the run out of the waiting state first. That is
	// the explicit concurrency conflict the superseded outcome exists for: the
	// expiry writes nothing and reports it.
	staleScope, stale, staleRequest, staleOpened := awaiting("stale")
	staleRuns := runs.NewService(runpg.New(pool, idempotencyStore, pinnedGuard(t)), noOpStarter{}, runID(stale.RunID), testClock{time.Unix(300, 0)}, journal.NewMemoryStore(), runs.AdmitFunc(func(context.Context, runs.Scope) error { return nil }))
	cancelling, err := staleRuns.Transition(ctx, staleScope, stale.RunID, staleOpened.Snapshot.Version, runs.Command{Kind: runs.RequestCancellation, Traceparent: trace})
	if err != nil {
		t.Fatal(err)
	}
	superseded, err := store.ExpireInput(ctx, interrupts.Write{Scope: staleScope, RunID: stale.RunID, ExpectedVersion: cancelling.Version, IdempotencyKey: "expire-stale", Traceparent: trace}, staleRequest.ID, failure, now)
	if err != nil || !superseded.Superseded {
		t.Fatalf("superseded expiry=%#v err=%v", superseded, err)
	}
	if current, err := store.Current(ctx, staleScope, stale.RunID); err != nil || current.Status != runs.Cancelling {
		t.Fatalf("superseded expiry moved the run: %#v err=%v", current, err)
	}
	if storedStale, err := store.Input(ctx, staleScope, stale.RunID, staleRequest.ID); err != nil || storedStale.ExpiredAt != nil {
		t.Fatalf("superseded expiry marked the request expired: %#v err=%v", storedStale, err)
	}

	// Infrastructure failures are not concurrency conflicts. A rejected
	// checkpoint and a rejected outbox write must surface as errors so the
	// durable caller retries; reporting either as superseded would record an
	// interrupt as settled that no transaction ever settled.
	for _, injection := range []struct {
		name, suffix, install, remove string
	}{
		{
			name:   "checkpoint",
			suffix: "checkpointfail",
			install: `CREATE OR REPLACE FUNCTION agent_workflow.probe_checkpoint_failure() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF NEW.workflow_id LIKE 'expiry-run-checkpointfail%' THEN
        RAISE EXCEPTION 'injected checkpoint failure';
    END IF;
    RETURN NEW;
END $$;
CREATE TRIGGER probe_checkpoint_failure BEFORE INSERT ON agent_workflow.checkpoints FOR EACH ROW EXECUTE FUNCTION agent_workflow.probe_checkpoint_failure();`,
			remove: `DROP TRIGGER IF EXISTS probe_checkpoint_failure ON agent_workflow.checkpoints; DROP FUNCTION IF EXISTS agent_workflow.probe_checkpoint_failure();`,
		},
		{
			name:   "outbox",
			suffix: "outboxfail",
			install: `CREATE OR REPLACE FUNCTION agent_events.probe_outbox_failure() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF NEW.run_id LIKE 'expiry-run-outboxfail%' THEN
        RAISE EXCEPTION 'injected outbox failure';
    END IF;
    RETURN NEW;
END $$;
CREATE TRIGGER probe_outbox_failure BEFORE INSERT ON agent_events.outbox FOR EACH ROW EXECUTE FUNCTION agent_events.probe_outbox_failure();`,
			remove: `DROP TRIGGER IF EXISTS probe_outbox_failure ON agent_events.outbox; DROP FUNCTION IF EXISTS agent_events.probe_outbox_failure();`,
		},
	} {
		t.Run("expiry-propagates-"+injection.name+"-failure", func(t *testing.T) {
			failScope, failRun, failRequest, failOpened := awaiting(injection.suffix)
			if _, err := admin.Exec(ctx, injection.install); err != nil {
				t.Fatal(err)
			}
			defer func() {
				if _, err := admin.Exec(ctx, injection.remove); err != nil {
					t.Errorf("remove %s failure injection: %v", injection.name, err)
				}
			}()
			expiry, err := store.ExpireInput(ctx, interrupts.Write{Scope: failScope, RunID: failRun.RunID, ExpectedVersion: failOpened.Snapshot.Version, IdempotencyKey: "expire-" + injection.suffix, Traceparent: trace}, failRequest.ID, failure, now)
			if err == nil {
				t.Fatalf("%s failure was swallowed: %#v", injection.name, expiry)
			}
			if expiry.Superseded || expiry.Raced {
				t.Fatalf("%s failure was reported as a concurrency outcome: %#v", injection.name, expiry)
			}
			current, err := store.Current(ctx, failScope, failRun.RunID)
			if err != nil || current.Status != runs.AwaitingInput {
				t.Fatalf("%s failure left the run at %#v err=%v", injection.name, current, err)
			}
			stored, err := store.Input(ctx, failScope, failRun.RunID, failRequest.ID)
			if err != nil || stored.ExpiredAt != nil {
				t.Fatalf("%s failure durably expired the request anyway: %#v err=%v", injection.name, stored, err)
			}
		})
	}
}

// assertDurableProviderLedger proves the controlled model adapter's provider
// idempotency, settled outcomes, script position, and usage evidence survive a
// process restart: a brand new adapter over the same rows replays instead of
// calling the provider again.
func assertDurableProviderLedger(t *testing.T, ctx context.Context, pool *pgxpool.Pool) {
	t.Helper()
	ledger, err := executionpg.NewScriptLedger(pool, "ledger-durability")
	if err != nil {
		t.Fatal(err)
	}
	first := []byte(`{"kind":"TypedPlan","steps":[{"tool":"agent.final","arguments":{}}]}`)
	second := []byte(`{"kind":"TypedPlan","steps":[{"tool":"agent.continue","arguments":{}}]}`)
	adapter, err := execution.NewScriptedAdapter(ledger, first, second)
	if err != nil {
		t.Fatal(err)
	}
	request := modelgateway.AdapterRequest{
		InvocationID: "invocation.durable", IdempotencyKey: "attempt.durable",
		Provider: execution.ControlledProviderID, Context: []byte("context"),
		MaximumOutputBytes: 65536, MaximumInputTokens: 1000, MaximumOutputTokens: 1000, MaximumTotalTokens: 2000, MaximumCostMicros: 1_000_000,
	}
	original, err := adapter.Invoke(ctx, request)
	if err != nil {
		t.Fatal(err)
	}
	billed, err := adapter.Billed(ctx)
	if err != nil || billed != 1 {
		t.Fatalf("billed = %d err = %v", billed, err)
	}

	// A new adapter over the same durable rows is what a restarted process is.
	restarted, err := execution.NewScriptedAdapter(ledger, first, second)
	if err != nil {
		t.Fatal(err)
	}
	replayed, err := restarted.Invoke(ctx, request)
	if err != nil {
		t.Fatal(err)
	}
	if string(replayed.Output) != string(original.Output) || replayed.InputTokens != original.InputTokens || replayed.CostMicros != original.CostMicros {
		t.Fatalf("restart replay = %+v, want the settled outcome %+v", replayed, original)
	}
	billed, err = restarted.Billed(ctx)
	if err != nil || billed != 1 {
		t.Fatalf("billed after restart = %d err = %v, want no duplicate billing", billed, err)
	}
	next := request
	next.IdempotencyKey = "attempt.durable.next"
	advanced, err := restarted.Invoke(ctx, next)
	if err != nil {
		t.Fatal(err)
	}
	if string(advanced.Output) == string(original.Output) {
		t.Fatal("a new operation did not advance the durable script position after restart")
	}
	billed, err = restarted.Billed(ctx)
	if err != nil || billed != 2 {
		t.Fatalf("billed = %d err = %v, want two distinct settled operations", billed, err)
	}

	// A settled operation is history: the store refuses to rewrite or drop it.
	if _, err := pool.Exec(ctx, `UPDATE agent_workflow.controlled_provider_operations SET script_position=script_position+1 WHERE ledger='ledger-durability'`); err == nil {
		t.Fatal("a settled provider operation was rewritten")
	}
	if _, err := pool.Exec(ctx, `DELETE FROM agent_workflow.controlled_provider_operations WHERE ledger='ledger-durability'`); err == nil {
		t.Fatal("a settled provider operation was deleted")
	}
}

// assertCancellationReconciliation proves cancellation is declared safe only
// after the authoritative provider, worker, tool, artifact, and domain-effect
// records say every external effect is settled.
func assertCancellationReconciliation(t *testing.T, ctx context.Context, pool *pgxpool.Pool) {
	t.Helper()
	reconciler, err := cancellation.New(cancellation.Pools{Control: pool, Workflow: pool, Artifacts: pool, Events: pool})
	if err != nil {
		t.Fatal(err)
	}
	scope := runs.Scope{WorkspaceID: "workspace-cancel", ProjectID: "project-cancel", ActorID: "actor"}
	digest := "sha256:" + strings.Repeat("c", 64)

	// A run with no recorded external effect at all is clear.
	clear, authoritative, err := reconciler.Reconcile(ctx, scope, "run-cancel-clean", false)
	if err != nil || !clear || authoritative != nil {
		t.Fatalf("clean run reconcile = (%t, %v, %v)", clear, authoritative, err)
	}

	// An in-flight provider invocation is an unresolved external effect.
	if _, err := pool.Exec(ctx, `INSERT INTO agent_control.provider_policy_snapshots(workspace_id,project_id,policy_version,policy_digest,policy_snapshot) VALUES($1,$2,'cancel-policy',$3,'{}'::jsonb) ON CONFLICT DO NOTHING`, scope.WorkspaceID, scope.ProjectID, digest); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO agent_workflow.provider_invocations(workspace_id,project_id,run_id,invocation_id,registry_snapshot_digest,policy_version,policy_digest,policy_snapshot,provider,model_version,region,disclosed_data_classes,started_at) VALUES($1,$2,'run-cancel-provider','invocation-cancel',$3,'cancel-policy',$3,'{}'::jsonb,'provider','model','region','[]'::jsonb,now())`, scope.WorkspaceID, scope.ProjectID, digest); err != nil {
		t.Fatal(err)
	}
	clear, _, err = reconciler.Reconcile(ctx, scope, "run-cancel-provider", false)
	if err != nil || clear {
		t.Fatalf("an in-flight provider invocation was reported clear: %t %v", clear, err)
	}
	if _, err := pool.Exec(ctx, `UPDATE agent_workflow.provider_invocations SET completed_at=now() WHERE workspace_id=$1 AND project_id=$2 AND invocation_id='invocation-cancel'`, scope.WorkspaceID, scope.ProjectID); err != nil {
		t.Fatal(err)
	}
	clear, _, err = reconciler.Reconcile(ctx, scope, "run-cancel-provider", false)
	if err != nil || !clear {
		t.Fatalf("a completed provider invocation was not reported clear: %t %v", clear, err)
	}

	// A tool dispatch may still be running while an executor lease survives.
	if _, err := pool.Exec(ctx, `INSERT INTO agent_workflow.executor_leases(workspace_id,project_id,workflow_id,executor_id,lease_epoch,expires_at) VALUES($1,$2,'run-cancel-tool:g1','executor-cancel',1,now()+interval '1 hour')`, scope.WorkspaceID, scope.ProjectID); err != nil {
		t.Fatal(err)
	}
	clear, _, err = reconciler.Reconcile(ctx, scope, "run-cancel-tool", false)
	if err != nil || clear {
		t.Fatalf("a live executor lease was reported clear: %t %v", clear, err)
	}

	// An artifact the run left pending is an unsettled external effect.
	if _, err := pool.Exec(ctx, `INSERT INTO agent_artifacts.metadata(workspace_id,project_id,artifact_id,run_id,digest,state,lineage) VALUES($1,$2,'artifact-cancel','run-cancel-artifact',$3,'pending','{}'::jsonb)`, scope.WorkspaceID, scope.ProjectID, digest); err != nil {
		t.Fatal(err)
	}
	clear, _, err = reconciler.Reconcile(ctx, scope, "run-cancel-artifact", false)
	if err != nil || clear {
		t.Fatalf("a pending artifact was reported clear: %t %v", clear, err)
	}

	// An unacknowledged queue delivery is dispatched work nothing has taken.
	if _, err := pool.Exec(ctx, `INSERT INTO agent_events.queue_deliveries(workspace_id,project_id,message_id,run_id,task_id,topic,payload,payload_digest) VALUES($1,$2,'message-cancel','run-cancel-queue','task-cancel','agent.public-events','\x7b7d'::bytea,$3)`, scope.WorkspaceID, scope.ProjectID, digest); err != nil {
		t.Fatal(err)
	}
	clear, _, err = reconciler.Reconcile(ctx, scope, "run-cancel-queue", false)
	if err != nil || clear {
		t.Fatalf("an unacknowledged queue delivery was reported clear: %t %v", clear, err)
	}

	// A governed effect the domain owner already applied is authoritative:
	// cancellation cannot overwrite it, and the real outcome is reported.
	if _, err := pool.Exec(ctx, `INSERT INTO agent_control.apply_authorizations(workspace_id,project_id,run_id,authorization_id,key_id,payload_digest,token_digest,issued_at,expires_at) VALUES($1,$2,'run-cancel-domain','authorization-cancel','key',$3,$3,now(),now()+interval '1 hour')`, scope.WorkspaceID, scope.ProjectID, digest); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO agent_control.domain_operations(workspace_id,project_id,run_id,operation_id,authorization_id,authorization_jws,action_digest,artifact_digest,expected_revision,idempotency_key,request_digest,status,created_at,updated_at) VALUES($1,$2,'run-cancel-domain','operation-cancel','authorization-cancel','jws',$3,$3,'rev','key',$3,'awaiting-domain-confirmation',now(),now())`, scope.WorkspaceID, scope.ProjectID, digest); err != nil {
		t.Fatal(err)
	}
	clear, authoritative, err = reconciler.Reconcile(ctx, scope, "run-cancel-domain", false)
	if err != nil || clear || authoritative != nil {
		t.Fatalf("an unsettled domain effect reconcile = (%t, %v, %v)", clear, authoritative, err)
	}
	if _, err := pool.Exec(ctx, `UPDATE agent_control.domain_operations SET status='applied',authorization_consumed=true,updated_at=now() WHERE workspace_id=$1 AND project_id=$2 AND operation_id='operation-cancel'`, scope.WorkspaceID, scope.ProjectID); err != nil {
		t.Fatal(err)
	}
	clear, authoritative, err = reconciler.Reconcile(ctx, scope, "run-cancel-domain", false)
	if err != nil || clear || authoritative == nil || *authoritative != runs.Completed {
		t.Fatalf("an applied domain effect reconcile = (%t, %v, %v)", clear, authoritative, err)
	}

	// Cancellation arriving inside the commit boundary with no settled record
	// can never be declared safe.
	clear, _, err = reconciler.Reconcile(ctx, scope, "run-cancel-clean", true)
	if err != nil || clear {
		t.Fatalf("commit-phase cancellation was declared safe: %t %v", clear, err)
	}

	// A reconciler that cannot read an effect domain must not exist at all.
	if _, err := cancellation.New(cancellation.Pools{Control: pool, Workflow: pool, Artifacts: pool}); err == nil {
		t.Fatal("a reconciler was built without every effect store")
	}
}

// realClock serves live time for durable dispatch tests whose fences compare
// application time against database transaction time.
type realClock struct{}

func (realClock) Now() time.Time { return time.Now().UTC() }

// dispatchToolMaterial serves one attested tool definition for the durable
// dispatch tests.
type dispatchToolMaterial struct{ definition tools.Definition }

func (m dispatchToolMaterial) ComponentDigest(string) (string, bool) {
	return m.definition.InputSchema.Digest, true
}

func (m dispatchToolMaterial) ToolDefinition(string) (tools.Definition, bool) {
	return m.definition, true
}

// assertScopedAuthorityStore proves the durable current-authority source:
// scoped bindings, subject activation, and every revocation kind observed on
// the next read, with an append-only revocation ledger.
func assertScopedAuthorityStore(t *testing.T, ctx context.Context, pool *pgxpool.Pool) {
	t.Helper()
	store, err := authoritypg.New(pool, func() time.Time { return time.Now().UTC() })
	if err != nil {
		t.Fatal(err)
	}
	material := json.RawMessage(`{"synthetic":true}`)
	bom := json.RawMessage(`{"repository":"anvilkit/contracts","bomDigest":"sha256:` + strings.Repeat("a", 64) + `"}`)
	binding := authoritypg.Binding{WorkspaceID: "workspace-auth", ProjectID: "project-auth", Definition: material, ContractBOM: bom, Policy: material, Budget: material, Grants: authority.Grants{AllowedCapabilities: []string{"fake.execute"}, MaximumRisk: "low"}}
	// The custodian carries its capabilities and clearance on its own subject
	// record; the ordinary actor carries none. They share every dispatch grant
	// the binding holds, which is exactly what must not admit either of them
	// to custody.
	subjects := []authoritypg.Subject{
		{WorkspaceID: "workspace-auth", ProjectID: "project-auth", ActorID: "actor-auth", Role: "agent-actor"},
		{WorkspaceID: "workspace-auth", ProjectID: "project-auth", ActorID: "custodian-auth", Role: "agent-artifact-custodian", Grants: authority.ActorAuthority{
			Capabilities: []string{"artifact-custody.legal-hold"},
			DataClasses:  []string{"internal"},
		}},
	}
	audit := seedAudit(t)
	if _, err := seedAuthority(t, ctx, store, audit, binding, 1, subjects); err != nil {
		t.Fatal(err)
	}
	// Cross-project isolation is proved before the actor-bound assertions
	// below withdraw the custodian: an admission that is gone cannot show
	// that it failed to cross a project boundary.
	assertAdmissionDoesNotCrossProjects(t, ctx, store, audit, binding, subjects)
	assertActorBoundAuthority(t, ctx, store)
	scope := authority.Scope{WorkspaceID: "workspace-auth", ProjectID: "project-auth", ActorID: "actor-auth"}
	current, err := store.Current(ctx, scope)
	if err != nil || !current.Active() || !current.MaterialComplete() || len(current.Grants.AllowedCapabilities) != 1 {
		t.Fatalf("seeded authority=%+v err=%v, want an active, complete, granted scope", current, err)
	}
	if pinned, err := store.PinnedBOMDigest(ctx, "workspace-auth", "project-auth"); err != nil || pinned != "sha256:"+strings.Repeat("a", 64) {
		t.Fatalf("pinned BOM=%q err=%v", pinned, err)
	}
	if _, err := store.Current(ctx, authority.Scope{WorkspaceID: "workspace-auth", ProjectID: "project-unbound", ActorID: "actor-auth"}); err == nil {
		t.Fatal("an unbound scope served authority")
	}
	if unknown, err := store.Current(ctx, authority.Scope{WorkspaceID: "workspace-auth", ProjectID: "project-auth", ActorID: "actor-unknown"}); err != nil || unknown.ActorActive {
		t.Fatalf("unknown actor authority=%+v err=%v, want an inactive actor axis", unknown, err)
	}
	revoke := func(kind authority.RevocationKind, subject string) {
		t.Helper()
		if err := store.Revoke(ctx, authority.Revocation{WorkspaceID: "workspace-auth", ProjectID: "project-auth", RevocationID: "revocation-" + string(kind), Kind: kind, Subject: subject, Reason: "test"}); err != nil {
			t.Fatal(err)
		}
	}
	revoke(authority.RevokeTarget, "page-auth")
	revoke(authority.RevokeApproval, "request.approve-auth")
	current, err = store.Current(ctx, scope)
	if err != nil || !current.TargetRevoked("page-auth") || !current.ApprovalRevoked("request.approve-auth") || !current.Active() {
		t.Fatalf("identity revocations=%+v err=%v, want target and approval withdrawn with the scope still active", current, err)
	}
	revoke(authority.RevokePolicy, "policy")
	if current, err = store.Current(ctx, scope); err != nil || current.PolicyActive {
		t.Fatalf("policy revocation=%+v err=%v", current, err)
	}
	revoke(authority.RevokeBudget, "budget")
	if current, err = store.Current(ctx, scope); err != nil || current.MaterialComplete() {
		t.Fatalf("budget revocation=%+v err=%v, want incomplete material", current, err)
	}
	revoke(authority.RevokeDefinition, "definition")
	if current, err = store.Current(ctx, scope); err != nil || len(current.Definition) != 0 {
		t.Fatalf("definition revocation=%+v err=%v, want withdrawn definition material", current, err)
	}
	revoke(authority.RevokeRole, "agent-actor")
	if current, err = store.Current(ctx, scope); err != nil || current.ActorActive {
		t.Fatalf("role revocation=%+v err=%v", current, err)
	}
	revoke(authority.RevokeActor, "actor-auth")
	revoke(authority.RevokeWorkspace, "workspace-auth")
	if current, err = store.Current(ctx, scope); err != nil || current.WorkspaceActive || current.ActorActive || current.Active() {
		t.Fatalf("workspace and actor revocation=%+v err=%v", current, err)
	}
	// A reseed restores material but never erases the recorded revocations.
	if _, err := seedAuthority(t, ctx, store, audit, binding, 9, subjects); err != nil {
		t.Fatal(err)
	}
	if current, err = store.Current(ctx, scope); err != nil || current.Active() {
		t.Fatalf("reseed=%+v err=%v, want revocations to survive reseeding", current, err)
	}
	if _, err := pool.Exec(ctx, `DELETE FROM agent_control.authority_revocations WHERE workspace_id='workspace-auth'`); err == nil {
		t.Fatal("the authority revocation ledger was deletable")
	}
	if _, err := pool.Exec(ctx, `UPDATE agent_control.authority_revocations SET subject='rewritten' WHERE workspace_id='workspace-auth'`); err == nil {
		t.Fatal("the authority revocation ledger was mutable")
	}
}

// assertAdmissionDoesNotCrossProjects proves the register admits an actor to
// the project it was admitted in and to no other. A workspace holds many
// projects; an actor doing one project's work is not thereby a custodian of
// another project's artifacts, cleared for its content, or holder of any role
// in it.
func assertAdmissionDoesNotCrossProjects(t *testing.T, ctx context.Context, store *authoritypg.Store, audit authoritypg.SeedAudit, binding authoritypg.Binding, subjects []authoritypg.Subject) {
	t.Helper()
	// A sibling project in the same workspace, bound to the same material, so
	// nothing but the project distinguishes the two observations.
	sibling := binding
	sibling.ProjectID = "project-auth-sibling"
	if _, err := seedAuthority(t, ctx, store, audit, sibling, 1, nil); err != nil {
		t.Fatal(err)
	}
	admitted, err := store.Current(ctx, authority.Scope{WorkspaceID: binding.WorkspaceID, ProjectID: binding.ProjectID, ActorID: "custodian-auth"})
	if err != nil {
		t.Fatal(err)
	}
	if admitted.ActorRole != "agent-artifact-custodian" || !admitted.ActorGrants.HasCapability("artifact-custody.legal-hold") || !admitted.ActorGrants.Clears("internal") {
		t.Fatalf("the custodian is not admitted in the project it was admitted to: %+v", admitted)
	}
	// The same actor, the same workspace, the next project along.
	foreign, err := store.Current(ctx, authority.Scope{WorkspaceID: binding.WorkspaceID, ProjectID: sibling.ProjectID, ActorID: "custodian-auth"})
	if err != nil {
		t.Fatal(err)
	}
	if foreign.ActorActive {
		t.Fatalf("an admission in one project made the actor active in another: %+v", foreign)
	}
	if foreign.ActorRole != "" {
		t.Fatalf("a role granted in one project was read in another: %q", foreign.ActorRole)
	}
	if foreign.ActorGrants.HasCapability("artifact-custody.legal-hold") {
		t.Fatal("a custody capability granted in one project was held in another")
	}
	if foreign.ActorGrants.Clears("internal") || foreign.ActorGrants.Clearance() != "" {
		t.Fatalf("an evidence clearance granted in one project was read in another: %q", foreign.ActorGrants.Clearance())
	}
	// Admitting the same actor to the sibling project with a narrower grant
	// leaves the original admission exactly as it was: the two are separate
	// records, not one record being overwritten.
	if _, err := seedAuthority(t, ctx, store, audit, sibling, 2, []authoritypg.Subject{
		{WorkspaceID: binding.WorkspaceID, ProjectID: sibling.ProjectID, ActorID: "custodian-auth", Role: "agent-actor"},
	}); err != nil {
		t.Fatal(err)
	}
	narrowed, err := store.Current(ctx, authority.Scope{WorkspaceID: binding.WorkspaceID, ProjectID: sibling.ProjectID, ActorID: "custodian-auth"})
	if err != nil {
		t.Fatal(err)
	}
	if narrowed.ActorRole != "agent-actor" || narrowed.ActorGrants.HasCapability("artifact-custody.legal-hold") || narrowed.ActorGrants.Clears("internal") {
		t.Fatalf("the sibling admission carried the other project's grants: %+v", narrowed)
	}
	unchanged, err := store.Current(ctx, authority.Scope{WorkspaceID: binding.WorkspaceID, ProjectID: binding.ProjectID, ActorID: "custodian-auth"})
	if err != nil {
		t.Fatal(err)
	}
	if unchanged.ActorRole != "agent-artifact-custodian" || !unchanged.ActorGrants.HasCapability("artifact-custody.legal-hold") {
		t.Fatalf("admitting the actor to a sibling project changed its original admission: %+v", unchanged)
	}
	// A subject seeded without a project is refused: an admission with no
	// project is the workspace-wide admission this register no longer has.
	if _, err := seedAuthority(t, ctx, store, audit, sibling, 3, []authoritypg.Subject{
		{WorkspaceID: binding.WorkspaceID, ActorID: "custodian-auth", Role: "agent-artifact-custodian"},
	}); err == nil {
		t.Fatal("a subject was admitted without naming a project")
	}
	// The original project's admissions are untouched by the sibling's
	// seedings, including the withdrawal pass each of them performs.
	if _, err := seedAuthority(t, ctx, store, audit, binding, 2, subjects); err != nil {
		t.Fatal(err)
	}
}

// seedAuthority applies one authority document at a generation through the
// real protected-audit protocol, which is how production seeds.
func seedAuthority(t *testing.T, ctx context.Context, store *authoritypg.Store, audit authoritypg.SeedAudit, binding authoritypg.Binding, generation uint64, subjects []authoritypg.Subject) (authoritypg.Applied, error) {
	t.Helper()
	seeded := binding
	seeded.Generation = generation
	return store.Seed(ctx, seeded, subjects, audit, authoritypg.SeedDecision{
		ActorID:     "operator.seed",
		Workload:    "agent-service.authority-seeding",
		Reason:      "authority seeding regression",
		Ticket:      "CHG-AUTH-0001",
		Traceparent: "00-" + strings.Repeat("a", 32) + "-" + strings.Repeat("b", 16) + "-01",
	})
}

// seedAudit is the real protected audit protocol over the in-memory sink: the
// seeding path must go through the same record validation, chaining, and
// receipt handling production uses.
func seedAudit(t *testing.T) *securityaudit.Service {
	t.Helper()
	now := time.Now().UTC()
	clock, err := securityaudit.NewAuthoritativeClock(fixedSeedSource{now}, fixedSeedTime{now}, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	service, err := securityaudit.NewService(&securityaudit.MemorySink{}, clock, &securityaudit.MemoryAlerts{}, journal.NewMemoryStore())
	if err != nil {
		t.Fatal(err)
	}
	return service
}

type fixedSeedTime struct{ value time.Time }

func (t fixedSeedTime) Now() time.Time { return t.value }

type fixedSeedSource struct{ value time.Time }

func (t fixedSeedSource) Now(context.Context) (time.Time, error) { return t.value, nil }

// assertAuthoritySeedingIsMonotonicAtomicAndExact proves the four properties
// startup seeding has to hold, each of which is a way authority used to come
// back: an older document is refused rather than applied, an equal one is a
// no-op, the whole document lands or none of it does, and an admission the
// document no longer names is withdrawn.
func assertAuthoritySeedingIsMonotonicAtomicAndExact(t *testing.T, ctx context.Context, pool *pgxpool.Pool) {
	t.Helper()
	store, err := authoritypg.New(pool, func() time.Time { return time.Now().UTC() })
	if err != nil {
		t.Fatal(err)
	}
	audit := seedAudit(t)
	material := json.RawMessage(`{"synthetic":true}`)
	bom := json.RawMessage(`{"repository":"anvilkit/contracts","bomDigest":"sha256:` + strings.Repeat("c", 64) + `"}`)
	binding := authoritypg.Binding{WorkspaceID: "workspace-seed", ProjectID: "project-seed", Definition: material, ContractBOM: bom, Policy: material, Budget: material, Grants: authority.Grants{MaximumRisk: "low"}}
	subject := func(actor, role string, capabilities []string) authoritypg.Subject {
		return authoritypg.Subject{WorkspaceID: binding.WorkspaceID, ProjectID: binding.ProjectID, ActorID: actor, Role: role, Grants: authority.ActorAuthority{Capabilities: capabilities, DataClasses: []string{"internal"}}}
	}
	custodian := subject("custodian-seed", "agent-artifact-custodian", []string{"artifact-custody.delete"})
	assistant := subject("assistant-seed", "agent-actor", nil)

	applied, err := seedAuthority(t, ctx, store, audit, binding, 2, []authoritypg.Subject{custodian, assistant})
	if err != nil || applied.Superseded || applied.Generation != 2 {
		t.Fatalf("the first seeding did not take: %+v err=%v", applied, err)
	}
	// A stale instance holding generation 1 must leave generation 2 alone,
	// and it must leave it alone entirely: not the material, not one subject.
	stale := binding
	stale.Policy = json.RawMessage(`{"synthetic":"stale"}`)
	older, err := seedAuthority(t, ctx, store, audit, stale, 1, []authoritypg.Subject{subject("attacker-seed", "agent-artifact-custodian", []string{"artifact-custody.delete"})})
	if err != nil {
		t.Fatalf("a superseded seeding was reported as a failure: %v", err)
	}
	if !older.Superseded || older.Generation != 2 {
		t.Fatalf("an older authority document was applied over a newer one: %+v", older)
	}
	current, err := store.Current(ctx, authority.Scope{WorkspaceID: binding.WorkspaceID, ProjectID: binding.ProjectID, ActorID: "attacker-seed"})
	if err != nil {
		t.Fatal(err)
	}
	if current.ActorActive {
		t.Fatal("a superseded seeding admitted a subject")
	}
	// The stored material is normalized jsonb, so what is asserted is that
	// the superseded document's own material is not what is in force.
	if strings.Contains(string(current.Policy), "stale") {
		t.Fatalf("a superseded seeding replaced the material in force: %s", current.Policy)
	}
	if standing := seedGeneration(t, ctx, pool, binding); standing != 2 {
		t.Fatalf("a superseded seeding moved the generation to %d", standing)
	}
	// Re-applying the generation in force changes nothing either: seeding on
	// every restart must not be a way to reinstate what is already there over
	// something newer, and equal is not newer.
	equal, err := seedAuthority(t, ctx, store, audit, binding, 2, []authoritypg.Subject{custodian, assistant})
	if err != nil || !equal.Superseded {
		t.Fatalf("re-applying the standing generation was not a no-op: %+v err=%v", equal, err)
	}
	// A newer document that no longer names the custodian withdraws it. An
	// upsert alone could only ever add, which is how a removed custodian
	// stayed a custodian.
	narrowed, err := seedAuthority(t, ctx, store, audit, binding, 3, []authoritypg.Subject{assistant})
	if err != nil || narrowed.Superseded || narrowed.Generation != 3 || narrowed.WithdrawnSubjects != 1 {
		t.Fatalf("the narrowing seeding did not withdraw the admission it dropped: %+v err=%v", narrowed, err)
	}
	withdrawn, err := store.Current(ctx, authority.Scope{WorkspaceID: binding.WorkspaceID, ProjectID: binding.ProjectID, ActorID: custodian.ActorID})
	if err != nil {
		t.Fatal(err)
	}
	if withdrawn.ActorActive || withdrawn.ActorRole != "" || withdrawn.ActorGrants.HasCapability("artifact-custody.delete") {
		t.Fatalf("an admission the document no longer names survived: %+v", withdrawn)
	}
	kept, err := store.Current(ctx, authority.Scope{WorkspaceID: binding.WorkspaceID, ProjectID: binding.ProjectID, ActorID: assistant.ActorID})
	if err != nil || !kept.ActorActive || kept.ActorRole != "agent-actor" {
		t.Fatalf("the admission the document still names was withdrawn: %+v err=%v", kept, err)
	}
	// The generation is monotonic in the database, not only in the
	// application: a writer that gets past the compare-and-set still cannot
	// lower it.
	if _, err := pool.Exec(ctx, `UPDATE agent_control.authority_bindings SET seed_generation=1 WHERE workspace_id=$1 AND project_id=$2`, binding.WorkspaceID, binding.ProjectID); err == nil {
		t.Fatal("the authority seed generation was moved backwards")
	}
	// A seeding with no generation, and one whose subjects belong to another
	// scope, are refused before anything is written.
	if _, err := seedAuthority(t, ctx, store, audit, binding, 0, []authoritypg.Subject{assistant}); err == nil {
		t.Fatal("a seeding without a generation was accepted")
	}
	foreign := assistant
	foreign.ProjectID = "project-elsewhere"
	if _, err := seedAuthority(t, ctx, store, audit, binding, 4, []authoritypg.Subject{foreign}); err == nil {
		t.Fatal("a seeding admitted a subject outside the scope it binds")
	}
	if standing := seedGeneration(t, ctx, pool, binding); standing != 3 {
		t.Fatalf("a refused seeding moved the generation to %d", standing)
	}
	// And a recorded revocation still survives every seeding at every
	// generation.
	if err := store.Revoke(ctx, authority.Revocation{WorkspaceID: binding.WorkspaceID, ProjectID: binding.ProjectID, RevocationID: "revocation-seed", Kind: authority.RevokeActor, Subject: assistant.ActorID, Reason: "test"}); err != nil {
		t.Fatal(err)
	}
	if _, err := seedAuthority(t, ctx, store, audit, binding, 5, []authoritypg.Subject{assistant}); err != nil {
		t.Fatal(err)
	}
	revoked, err := store.Current(ctx, authority.Scope{WorkspaceID: binding.WorkspaceID, ProjectID: binding.ProjectID, ActorID: assistant.ActorID})
	if err != nil || revoked.ActorActive {
		t.Fatalf("a reseed reinstated a revoked actor: %+v err=%v", revoked, err)
	}
}

func seedGeneration(t *testing.T, ctx context.Context, pool *pgxpool.Pool, binding authoritypg.Binding) int64 {
	t.Helper()
	var generation int64
	if err := pool.QueryRow(ctx, `SELECT seed_generation FROM agent_control.authority_bindings WHERE workspace_id=$1 AND project_id=$2`, binding.WorkspaceID, binding.ProjectID).Scan(&generation); err != nil {
		t.Fatal(err)
	}
	return generation
}

// assertDomainRedemptionAcrossProcesses proves the strict domain owner over
// its durable redemption record: one really signed authorization redeems
// exactly once, a newly constructed owner replays the recorded outcome, and
// a second operation or a tampered token is rejected.
func assertDomainRedemptionAcrossProcesses(t *testing.T, ctx context.Context, pool *pgxpool.Pool) {
	t.Helper()
	now := time.Now().UTC()
	digest := func(c string) string { return "sha256:" + strings.Repeat(c, 64) }
	keyring, err := applyauth.NewSeededKeyRing([]byte("integration-domain-signing-01234"))
	if err != nil {
		t.Fatal(err)
	}
	binding := applyauth.Binding{RunID: "run-redeem", ActionDigest: digest("1"), ArtifactDigest: digest("1"), Target: applyauth.Target{Type: "page", ID: "page-redeem", WorkspaceID: "workspace-redeem", ProjectID: "project-redeem"}, BaseRevision: "rev:request.redeem", ActorID: "actor-redeem", WorkspaceID: "workspace-redeem", ApprovalVersion: 1, ContractBOMDigest: digest("2"), PolicyDigest: digest("3"), DefinitionDigest: digest("4")}
	fixedAuthority := fixedApplyAuthority{proof: applyauth.Proof{Approved: binding, Current: binding, ApprovalCurrent: true, ArtifactEligible: true}}
	audit, err := applyauthpg.New(pool)
	if err != nil {
		t.Fatal(err)
	}
	issuer, err := applyauth.New(fixedAuthority, execution.RandomAuthorizationIDs{}, keyring, audit, journal.NewMemoryStore(), pinnedGuard(t), testClock{now}, 2*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	authorization, err := issuer.Issue(ctx, applyauth.Command{WorkspaceID: "workspace-redeem", ProjectID: "project-redeem", RunID: "run-redeem", ApprovalRequestID: "request.redeem", ArtifactID: digest("1"), OperationKey: "workflow-redeem:commit"})
	if err != nil {
		t.Fatal(err)
	}
	redemptions, err := executionpg.NewRedemptionStore(pool)
	if err != nil {
		t.Fatal(err)
	}
	owner, err := execution.NewVerifyingDomainPort(execution.DomainConfirmed, keyring, redemptions, testClock{now.Add(time.Second)})
	if err != nil {
		t.Fatal(err)
	}
	command := execution.DomainCommand{
		OperationID:       "domain.redeem-op",
		WorkspaceID:       "workspace-redeem",
		ProjectID:         "project-redeem",
		RunID:             "run-redeem",
		ArtifactDigest:    digest("1"),
		AuthorizationID:   string(authorization.ID),
		AuthorizationJWS:  authorization.Compact,
		ActionDigest:      digest("1"),
		BaseRevision:      "rev:request.redeem",
		Target:            applyauth.Target{Type: "page", ID: "page-redeem", WorkspaceID: "workspace-redeem", ProjectID: "project-redeem"},
		ActorID:           "actor-redeem",
		DefinitionDigest:  digest("4"),
		ContractBOMDigest: digest("2"),
		PolicyDigest:      digest("3"),
	}
	outcome, err := owner.Commit(ctx, command)
	if err != nil || outcome.Status != execution.DomainConfirmed {
		t.Fatalf("first redemption=%+v err=%v", outcome, err)
	}
	// A newly constructed owner — a successor process — replays the recorded
	// outcome and never applies the effect again.
	successor, err := execution.NewVerifyingDomainPort(execution.DomainConfirmed, keyring, redemptions, testClock{now.Add(2 * time.Second)})
	if err != nil {
		t.Fatal(err)
	}
	replayed, err := successor.Commit(ctx, command)
	if err != nil || replayed.Status != execution.DomainConfirmed {
		t.Fatalf("replayed redemption=%+v err=%v", replayed, err)
	}
	var redeemedRows int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM agent_control.domain_redemptions WHERE workspace_id='workspace-redeem'`).Scan(&redeemedRows); err != nil || redeemedRows != 1 {
		t.Fatalf("redemption rows=%d err=%v, want exactly one", redeemedRows, err)
	}
	secondOperation := command
	secondOperation.OperationID = "domain.redeem-op-2"
	if rejected, err := successor.Commit(ctx, secondOperation); err != nil || rejected.Status != execution.DomainRejected {
		t.Fatalf("second-operation redemption=%+v err=%v, want rejection", rejected, err)
	}
	tampered := command
	parts := strings.Split(tampered.AuthorizationJWS, ".")
	parts[2] = strings.Repeat("A", len(parts[2]))
	tampered.AuthorizationJWS = strings.Join(parts, ".")
	if rejected, err := successor.Commit(ctx, tampered); err != nil || rejected.Status != execution.DomainRejected {
		t.Fatalf("tampered redemption=%+v err=%v, want rejection", rejected, err)
	}
	if _, err := pool.Exec(ctx, `UPDATE agent_control.domain_redemptions SET outcome='rejected' WHERE workspace_id='workspace-redeem'`); err == nil {
		t.Fatal("a recorded domain redemption was mutable")
	}
}

// fixedApplyAuthority resolves every issuance command to one fixed proof.
type fixedApplyAuthority struct{ proof applyauth.Proof }

func (a fixedApplyAuthority) Resolve(context.Context, applyauth.Command) (applyauth.Proof, error) {
	return a.proof, nil
}

// assertDurableToolDispatch proves the durable fenced dispatch record: task,
// lease, fence, recovery epoch, accepted result, and replayable output all
// live in Postgres, and a newly constructed executor — a successor process —
// replays the recorded output without executing the worker again.
func assertDurableToolDispatch(t *testing.T, ctx context.Context, pool *pgxpool.Pool) {
	t.Helper()
	register, err := recoverypg.NewMirrorEpochSource(pool)
	if err != nil {
		t.Fatal(err)
	}
	if err := register.EnsureBaseline(ctx); err != nil {
		t.Fatal(err)
	}
	// An earlier assertion in this suite rotates the recovery state, which
	// isolates the fabric: dispatch, ingress, and result intake are all
	// cleared until a restore re-enables them stage by stage. This assertion
	// is about dispatch under a dispatching fabric, so it restores that state
	// explicitly rather than depending on what ran before it. The isolated
	// case has its own assertion below.
	if _, err := pool.Exec(ctx, `UPDATE agent_workflow.recovery_state SET dispatch_enabled=true,ingress_enabled=true,result_intake_enabled=true,version=version+1 WHERE register_name='platform-recovery-epoch'`); err != nil {
		t.Fatal(err)
	}
	newExecutor := func(owner string, worker execution.ToolExecutor) execution.ToolExecutor {
		t.Helper()
		freshRegister, err := recoverypg.NewMirrorEpochSource(pool)
		if err != nil {
			t.Fatal(err)
		}
		dispatch, err := schedulerpg.NewDurableScheduler(pool, freshRegister, execution.DispatchIDs{}, realClock{}, scheduler.PrerequisiteFunc(func(_ context.Context, value scheduler.Create) error {
			if value.ReservationID == "" || !value.ReservationCurrent || !value.PolicyAllowed {
				return fmt.Errorf("task prerequisites are unsatisfied")
			}
			return nil
		}), time.Minute)
		if err != nil {
			t.Fatal(err)
		}
		usageStore, err := usagepg.New(pool)
		if err != nil {
			t.Fatal(err)
		}
		pipeline, err := usage.New(usageStore, execution.NewControlledUsageSink())
		if err != nil {
			t.Fatal(err)
		}
		reservations, err := executionpg.NewToolReservations(pool, time.Hour)
		if err != nil {
			t.Fatal(err)
		}
		material := dispatchToolMaterial{definition: tools.Definition{Kind: "ToolDefinition", ToolID: "anvilkit.tool.context-echo", Capability: "fake.execute", InputSchema: tools.SchemaReference{ComponentName: "anvilkit.tool.context-echo.arguments", Digest: "sha256:" + strings.Repeat("a", 64)}}}
		synthetic := json.RawMessage(`{"synthetic":true}`)
		source := authority.NewStatic(authority.Current{Definition: synthetic, ContractBOM: synthetic, Policy: synthetic, Budget: synthetic, WorkspaceActive: true, ActorActive: true, PermissionActive: true, PolicyActive: true, Grants: authority.Grants{AllowedCapabilities: []string{"fake.execute"}}})
		executor, err := execution.NewScheduledToolExecutor(dispatch, freshRegister, source, material, worker, pipeline, reservations, realClock{}, owner, "sha256:"+strings.Repeat("b", 64))
		if err != nil {
			t.Fatal(err)
		}
		return executor
	}
	invocation := execution.ToolInvocation{
		IdempotencyKey:      "workflow-dispatch:action-0001",
		ToolID:              "anvilkit.tool.context-echo",
		Arguments:           json.RawMessage(`{"query":"durable"}`),
		WorkspaceID:         "workspace-dispatch",
		ProjectID:           "project-dispatch",
		RunID:               "run-dispatch",
		RootRunID:           "run-dispatch",
		ActorID:             "actor-dispatch",
		ExecutionGeneration: 1,
		Traceparent:         "00-0123456789abcdef0123456789abcdef-0123456789abcdef-01",
	}
	firstWorker := execution.NewControlledToolExecutor()
	original, err := newExecutor("dispatch-executor-a", firstWorker).Execute(ctx, invocation)
	if err != nil {
		t.Fatal(err)
	}
	if firstWorker.Executions() != 1 {
		t.Fatalf("first executions=%d, want 1", firstWorker.Executions())
	}
	successorWorker := execution.NewControlledToolExecutor()
	replayed, err := newExecutor("dispatch-executor-b", successorWorker).Execute(ctx, invocation)
	if err != nil {
		t.Fatal(err)
	}
	if string(replayed.Output) != string(original.Output) {
		t.Fatalf("replayed output=%s, want the recorded original %s", replayed.Output, original.Output)
	}
	if successorWorker.Executions() != 0 {
		t.Fatalf("successor executions=%d, want the worker never executed again", successorWorker.Executions())
	}
	var tasks, attempts, results, outputs int
	if err := pool.QueryRow(ctx, `SELECT
		(SELECT count(*) FROM agent_workflow.agent_tasks WHERE workspace_id='workspace-dispatch' AND state='completed'),
		(SELECT count(*) FROM agent_workflow.worker_attempts WHERE workspace_id='workspace-dispatch' AND state='accepted'),
		(SELECT count(*) FROM agent_workflow.worker_results WHERE workspace_id='workspace-dispatch'),
		(SELECT count(*) FROM agent_workflow.worker_outputs WHERE workspace_id='workspace-dispatch')`).Scan(&tasks, &attempts, &results, &outputs); err != nil || tasks != 1 || attempts != 1 || results != 1 || outputs != 1 {
		t.Fatalf("tasks=%d attempts=%d results=%d outputs=%d err=%v, want one durable dispatch record", tasks, attempts, results, outputs, err)
	}
	if _, err := pool.Exec(ctx, `UPDATE agent_workflow.worker_outputs SET output='\x00' WHERE workspace_id='workspace-dispatch'`); err == nil {
		t.Fatal("a recorded replayable output was mutable")
	}
}

// persistenceProtectedAudit keeps only what the resume contract needs: which
// decision was authorized under which identity. The persistence suite proves
// the durable artifact stores behave, and the protected audit's own chaining,
// receipts, and refusal semantics have their own suite — but a successor
// finishing an interrupted destruction has to be handed the decision it is
// adopting, so that much is real here.
type persistenceProtectedAudit struct {
	lock      sync.Mutex
	decisions map[string]securityaudit.Record
}

func newPersistenceProtectedAudit() *persistenceProtectedAudit {
	return &persistenceProtectedAudit{decisions: map[string]securityaudit.Record{}}
}

// authorize places a decision on the record the way a first process would
// have, so a test can reproduce the state an interrupted decision leaves.
func (a *persistenceProtectedAudit) authorize(record securityaudit.Record) {
	a.lock.Lock()
	defer a.lock.Unlock()
	a.decisions[record.ID] = record
}

func (a *persistenceProtectedAudit) PrivilegedMutation(ctx context.Context, record securityaudit.Record, mutation securityaudit.Mutation) error {
	a.lock.Lock()
	if a.decisions == nil {
		a.decisions = map[string]securityaudit.Record{}
	}
	if _, recorded := a.decisions[record.ID]; !recorded {
		a.decisions[record.ID] = record
	}
	a.lock.Unlock()
	if mutation == nil {
		return nil
	}
	return mutation(ctx)
}

func (a *persistenceProtectedAudit) ResumeMutation(ctx context.Context, id string, admit securityaudit.Admission, mutation securityaudit.AdoptedMutation) error {
	if mutation == nil || admit == nil {
		return nil
	}
	a.lock.Lock()
	record, recorded := a.decisions[id]
	a.lock.Unlock()
	if !recorded {
		return securityaudit.UnrecordedDecision{RecordID: id}
	}
	if err := admit(record); err != nil {
		return err
	}
	return mutation(ctx, record)
}

// A restore isolates the fabric before it repairs anything: the mirrored epoch
// advances and dispatch, ingress, and result intake are all cleared. Result
// intake was already fenced on that state; dispatch was not, so an instance
// that restarted inside the isolated window — or one that simply never noticed
// the restore — went on creating and leasing tasks into a fabric that had been
// deliberately stopped. This proves both ends of the fence: no task is created
// and no lease is issued while the fabric is isolated, and a task recorded
// under a superseded epoch is never leased under the current one.
func assertIsolatedFabricRefusesDispatch(t *testing.T, ctx context.Context, pool *pgxpool.Pool) {
	t.Helper()
	register, err := recoverypg.NewMirrorEpochSource(pool)
	if err != nil {
		t.Fatal(err)
	}
	if err := register.EnsureBaseline(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `UPDATE agent_workflow.recovery_state SET dispatch_enabled=true,ingress_enabled=true,result_intake_enabled=true,version=version+1 WHERE register_name='platform-recovery-epoch'`); err != nil {
		t.Fatal(err)
	}
	dispatch, err := schedulerpg.NewDurableScheduler(pool, register, execution.DispatchIDs{}, realClock{},
		scheduler.PrerequisiteFunc(func(context.Context, scheduler.Create) error { return nil }), time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	epoch, err := register.Current(ctx)
	if err != nil {
		t.Fatal(err)
	}
	scope := scheduler.Scope{WorkspaceID: "workspace-isolation", ProjectID: "project-isolation"}
	// Every task is fenced to a standing reservation, so one is recorded here
	// exactly as dispatch records it.
	reservations, err := executionpg.NewToolReservations(pool, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := reservations.Ensure(ctx, scope.WorkspaceID, scope.ProjectID, "run-isolation", "run-isolation", "reservation-isolation", time.Now().UTC()); err != nil {
		t.Fatal(err)
	}
	create := func(id scheduler.TaskID, at recovery.Epoch) scheduler.Create {
		return scheduler.Create{
			Scope: scope, TaskID: id, RunID: "run-isolation", RootRunID: "run-isolation",
			RecoveryEpoch: uint64(at), ExecutionGeneration: 1, Capability: "fake.execute",
			ReservationID: "reservation-isolation", ReservationCurrent: true, PolicyAllowed: true,
			InputDigest: "sha256:" + strings.Repeat("c", 64), InputObjectKey: "inputs/isolation",
			CreatedAt: time.Now().UTC(),
		}
	}
	// A dispatching fabric admits the task, so the refusals below are the
	// isolation and nothing else.
	admitted, err := dispatch.Create(ctx, create("task.isolation.admitted", epoch))
	if err != nil {
		t.Fatalf("a dispatching fabric refused a task: %v", err)
	}
	if admitted.State != scheduler.Queued {
		t.Fatalf("admitted task state = %v, want queued", admitted.State)
	}

	// The restore isolates the fabric.
	if _, err := pool.Exec(ctx, `UPDATE agent_workflow.recovery_state SET dispatch_enabled=false,version=version+1 WHERE register_name='platform-recovery-epoch'`); err != nil {
		t.Fatal(err)
	}
	var details problem.Details
	if _, err := dispatch.Create(ctx, create("task.isolation.refused", epoch)); !errors.As(err, &details) || details.Code != string(problem.CodeTaskDispatchDenied) {
		t.Fatalf("an isolated fabric created a task: %v", err)
	}
	if _, err := dispatch.Lease(ctx, scope, "task.isolation.admitted", "executor-isolation"); !errors.As(err, &details) || details.Code != string(problem.CodeTaskDispatchDenied) {
		t.Fatalf("an isolated fabric leased a task: %v", err)
	}
	// Nothing was written: the refused task does not exist.
	if _, err := dispatch.Get(ctx, scope, "task.isolation.refused"); !errors.As(err, &details) || details.Code != string(problem.CodeResourceNotFound) {
		t.Fatalf("a refused dispatch left a task record: %v", err)
	}

	// The restore advances the epoch. The database enforces what the restore
	// procedure requires — a new epoch begins fully isolated — so the advance
	// and the re-enabling are separate steps, exactly as a restore performs
	// them.
	if _, err := pool.Exec(ctx, `UPDATE agent_workflow.recovery_state SET dispatch_enabled=false,ingress_enabled=false,result_intake_enabled=false,mirrored_epoch=mirrored_epoch+1,version=version+1 WHERE register_name='platform-recovery-epoch'`); err != nil {
		t.Fatal(err)
	}
	// Dispatch returns, but the epoch has moved past the task that was already
	// queued: a task the restore did not carry forward is never leased under
	// the epoch that replaced it.
	if _, err := pool.Exec(ctx, `UPDATE agent_workflow.recovery_state SET dispatch_enabled=true,version=version+1 WHERE register_name='platform-recovery-epoch'`); err != nil {
		t.Fatal(err)
	}
	if _, err := dispatch.Lease(ctx, scope, "task.isolation.admitted", "executor-isolation"); !errors.As(err, &details) || details.Code != string(problem.CodeWorkerFenceStale) {
		t.Fatalf("a task from a superseded epoch was leased under the current one: %v", err)
	}
	if _, err := dispatch.Create(ctx, create("task.isolation.stale-epoch", epoch)); !errors.As(err, &details) || details.Code != string(problem.CodeWorkerFenceStale) {
		t.Fatalf("a task was created under a superseded epoch: %v", err)
	}

	// Leave the fabric dispatching. The epoch stays where the restore left it:
	// a recovery epoch never rolls back, and the database refuses to let one.
	if _, err := pool.Exec(ctx, `UPDATE agent_workflow.recovery_state SET dispatch_enabled=true,ingress_enabled=true,result_intake_enabled=true,version=version+1 WHERE register_name='platform-recovery-epoch'`); err != nil {
		t.Fatal(err)
	}
}

// protectedAuditRuntimeLogin creates the login the service connects to the
// protected audit as, and returns its name and a connection string for it. It
// is deliberately an ordinary unprivileged login: what it may do to the audit
// is exactly what the runtime role grants it and nothing else.
func protectedAuditRuntimeLogin(t *testing.T, ctx context.Context, pool *pgxpool.Pool, databaseURL string) (string, string) {
	t.Helper()
	const login = "agent_audit_runtime"
	const secret = "agent-audit-runtime-secret"
	if _, err := pool.Exec(ctx, `DO $$ BEGIN CREATE ROLE `+login+` LOGIN PASSWORD '`+secret+`'; EXCEPTION WHEN duplicate_object THEN NULL; END $$`); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		// The login is cluster-global, so it is withdrawn from this database
		// and dropped once nothing depends on it. A drop that cannot happen —
		// another database still granting it something — is not a test
		// failure.
		closing, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		_, _ = pool.Exec(closing, `REVOKE ALL ON SCHEMA agent_protected_audit FROM `+login)
		_, _ = pool.Exec(closing, `REVOKE `+securityauditpg.RuntimeRole+` FROM `+login)
		_, _ = pool.Exec(closing, `DROP ROLE IF EXISTS `+login)
	})
	var database string
	if err := pool.QueryRow(ctx, `SELECT current_database()`).Scan(&database); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `GRANT CONNECT ON DATABASE "`+database+`" TO `+login); err != nil {
		t.Fatal(err)
	}
	parsed, err := url.Parse(databaseURL)
	if err != nil {
		t.Fatal(err)
	}
	parsed.User = url.UserPassword(login, secret)
	return login, parsed.String()
}

// The protected audit is what makes a security decision reconstructable after
// the fact, so it has to hold two properties against a real database: the
// chain must detect any record that was altered, removed, or inserted, and the
// table must refuse to be rewritten in the first place.
func assertProtectedAuditChain(t *testing.T, ctx context.Context, pool *pgxpool.Pool, databaseURL string) {
	t.Helper()
	sink, err := securityauditpg.New(pool)
	if err != nil {
		t.Fatal(err)
	}
	// The service connects as its own login, distinct from the one that
	// administers the audit. Everything below is about keeping those two
	// apart, so the runtime login exists before the schema is established and
	// the grant is made to it by name.
	runtimeLogin, runtimeURL := protectedAuditRuntimeLogin(t, ctx, pool, databaseURL)
	// Nothing has been established yet, so an audit read on this connection
	// reports exactly that. The service asks the same question at startup and
	// refuses rather than creating what it finds missing.
	if err := sink.RequireProvisioned(ctx); err == nil {
		t.Fatal("an unprovisioned protected audit reported itself ready")
	}
	// Provisioning is the one-shot administrative path, run here exactly as
	// the separate provisioning workload runs it.
	if err := securityauditpg.Provision(ctx, pool, runtimeLogin, true); err != nil {
		t.Fatal(err)
	}
	if err := sink.Check(ctx); err != nil {
		t.Fatal(err)
	}
	if err := sink.RequireProvisioned(ctx); err != nil {
		t.Fatalf("a provisioned protected audit did not report itself ready: %v", err)
	}
	// A table whose append-only barrier was dropped is not a protected audit,
	// and the readiness check says so rather than passing on the table's mere
	// existence.
	if _, err := pool.Exec(ctx, `DROP TRIGGER protected_audit_is_append_only ON agent_protected_audit.records`); err != nil {
		t.Fatal(err)
	}
	if err := sink.RequireProvisioned(ctx); err == nil {
		t.Fatal("a protected audit with no append-only barrier reported itself ready")
	}
	if err := securityauditpg.Provision(ctx, pool, runtimeLogin, true); err != nil {
		t.Fatal(err)
	}
	if err := sink.RequireProvisioned(ctx); err != nil {
		t.Fatalf("re-provisioning did not restore the protected audit barriers: %v", err)
	}
	// A barrier is not a name in a catalog. It can be turned off, re-pointed
	// at a function that permits what it was meant to refuse, rewritten in
	// place, re-created to fire on something else, or made conditional on a
	// predicate that is never true — and every one of those leaves a row
	// under the original name that a check for mere existence reads as
	// present. Each is applied, refused, and undone by re-provisioning, so
	// what is proved is that startup distinguishes the barrier it established
	// from anything that merely carries its name.
	for name, disable := range map[string]string{
		"the append-only barrier disabled": `ALTER TABLE agent_protected_audit.records DISABLE TRIGGER protected_audit_is_append_only`,
		"the payload barrier disabled":     `ALTER TABLE agent_protected_audit.records DISABLE TRIGGER protected_audit_columns_match_payload`,
		"every barrier disabled at once":   `ALTER TABLE agent_protected_audit.records DISABLE TRIGGER ALL`,
		"the append-only barrier re-pointed": `CREATE OR REPLACE FUNCTION agent_protected_audit.permit_rewrite() RETURNS trigger AS $permit$ BEGIN RETURN NEW; END; $permit$ LANGUAGE plpgsql;
DROP TRIGGER protected_audit_is_append_only ON agent_protected_audit.records;
CREATE TRIGGER protected_audit_is_append_only BEFORE UPDATE OR DELETE OR TRUNCATE ON agent_protected_audit.records FOR EACH STATEMENT EXECUTE FUNCTION agent_protected_audit.permit_rewrite()`,
		"the append-only function rewritten in place": `CREATE OR REPLACE FUNCTION agent_protected_audit.refuse_rewrite() RETURNS trigger AS $permit$ BEGIN RETURN NEW; END; $permit$ LANGUAGE plpgsql`,
		"the payload function rewritten in place":     `CREATE OR REPLACE FUNCTION agent_protected_audit.guard_authenticated_columns() RETURNS trigger AS $permit$ BEGIN RETURN NEW; END; $permit$ LANGUAGE plpgsql`,
		"the append-only barrier re-armed on another event": `DROP TRIGGER protected_audit_is_append_only ON agent_protected_audit.records;
CREATE TRIGGER protected_audit_is_append_only BEFORE INSERT ON agent_protected_audit.records FOR EACH ROW EXECUTE FUNCTION agent_protected_audit.refuse_rewrite()`,
		"the payload barrier made conditional": `DROP TRIGGER protected_audit_columns_match_payload ON agent_protected_audit.records;
CREATE TRIGGER protected_audit_columns_match_payload BEFORE INSERT ON agent_protected_audit.records FOR EACH ROW WHEN (false) EXECUTE FUNCTION agent_protected_audit.guard_authenticated_columns()`,
	} {
		if _, err := pool.Exec(ctx, disable); err != nil {
			t.Fatalf("could not apply %s: %v", name, err)
		}
		if err := sink.RequireProvisioned(ctx); err == nil {
			t.Fatalf("a protected audit with %s reported itself ready", name)
		}
		if err := securityauditpg.Provision(ctx, pool, runtimeLogin, true); err != nil {
			t.Fatalf("re-provisioning after %s failed: %v", name, err)
		}
		// DISABLE TRIGGER leaves the catalog row in place, so re-establishing
		// the trigger is what re-enables it; a barrier that came back
		// disabled would still be reported as such here.
		if err := sink.RequireProvisioned(ctx); err != nil {
			t.Fatalf("re-provisioning did not restore the audit after %s: %v", name, err)
		}
	}
	if _, err := pool.Exec(ctx, `DROP FUNCTION IF EXISTS agent_protected_audit.permit_rewrite()`); err != nil {
		t.Fatal(err)
	}

	// Provisioning refuses to grant the runtime role to the login that
	// administers the audit, in every environment rather than as a production
	// proof a deployment can be configured out of. Without this the whole
	// separation is a naming convention: the service would run as the account
	// that owns the table and could drop every barrier above.
	var administering string
	if err := pool.QueryRow(ctx, `SELECT current_user`).Scan(&administering); err != nil {
		t.Fatal(err)
	}
	if err := securityauditpg.Provision(ctx, pool, administering, false); err == nil {
		t.Fatal("the protected audit was provisioned with the administering login as its runtime login")
	}

	record := func(id, action string) securityaudit.Record {
		return securityaudit.Record{
			ID: id, Action: action, Actor: "operator-01", Workload: "audit-suite",
			Reason: "protected audit conformance", Ticket: "change-0002",
			OldDigest:   "sha256:" + strings.Repeat("a", 64),
			NewDigest:   "sha256:" + strings.Repeat("b", 64),
			Traceparent: "00-" + strings.Repeat("1", 32) + "-" + strings.Repeat("2", 16) + "-01",
			Outcome:     "applied",
			UTC:         time.Unix(1_700_000_000, 0).UTC(),
			Scope:       securityaudit.Scope{WorkspaceID: "workspace-audit", ProjectID: "project-audit", ResourceID: "artifact-audit"},
		}
	}
	first, inserted, err := sink.Append(ctx, record("audit.chain.1", "artifact-deleted"))
	if err != nil || !inserted {
		t.Fatalf("first append inserted=%v err=%v", inserted, err)
	}
	if first.PreviousDigest != "" || first.Digest == "" {
		t.Fatalf("the first record does not open the chain: %+v", first)
	}
	second, inserted, err := sink.Append(ctx, record("audit.chain.2", "artifact-legal-hold-placed"))
	if err != nil || !inserted {
		t.Fatalf("second append inserted=%v err=%v", inserted, err)
	}
	if second.PreviousDigest != first.Digest {
		t.Fatalf("the second record does not chain onto the first: %+v", second)
	}
	if err := sink.Verify(ctx); err != nil {
		t.Fatalf("a freshly written chain does not verify: %v", err)
	}

	// The same decision recorded again is the same record, not a second one.
	retained, inserted, err := sink.Append(ctx, record("audit.chain.2", "artifact-legal-hold-placed"))
	if err != nil || inserted {
		t.Fatalf("a repeated decision inserted=%v err=%v, want the retained record", inserted, err)
	}
	if retained.Digest != second.Digest {
		t.Fatalf("a repeated decision returned a different record: %+v", retained)
	}
	// The same identity carrying a different decision is a conflict.
	conflicting := record("audit.chain.2", "artifact-legal-hold-lifted")
	var details problem.Details
	if _, _, err := sink.Append(ctx, conflicting); !errors.As(err, &details) || details.Code != string(problem.CodeIdempotencyConflict) {
		t.Fatalf("a reused identity carrying a different decision was accepted: %v", err)
	}

	// A lookup answers with the record that was asked for.
	looked, found, err := sink.Lookup(ctx, "audit.chain.2")
	if err != nil || !found || looked.Digest != second.Digest || looked.Action != "artifact-legal-hold-placed" {
		t.Fatalf("lookup=%+v found=%v err=%v", looked, found, err)
	}
	if _, found, err := sink.Lookup(ctx, "audit.chain.absent"); err != nil || found {
		t.Fatalf("an absent identity was found: found=%v err=%v", found, err)
	}

	// Every column the row duplicates from the authenticated payload is
	// checked against that payload on the way in. Without this a row could be
	// filed under one identity while carrying another, and the dedupe key
	// would have nothing to do with the identity the chain digest covers: a
	// lookup would answer with a record that is not the record asked for.
	authenticPayload, err := securityaudit.ChainPayload(func() securityaudit.Record {
		value := record("audit.chain.forged", "artifact-deleted")
		value.PreviousDigest = second.Digest
		return value
	}())
	if err != nil {
		t.Fatal(err)
	}
	authenticDigest := securityaudit.ChainDigest(authenticPayload)
	for name, insert := range map[string]struct{ id, previous, digest string }{
		"an identity the payload does not claim":       {id: "audit.chain.mislabelled", previous: second.Digest, digest: authenticDigest},
		"a predecessor the payload does not claim":     {id: "audit.chain.forged", previous: first.Digest, digest: authenticDigest},
		"a digest that is not the digest of the bytes": {id: "audit.chain.forged", previous: second.Digest, digest: "sha256:" + strings.Repeat("c", 64)},
	} {
		if _, err := pool.Exec(ctx, `INSERT INTO agent_protected_audit.records(record_id,previous_digest,record_digest,chain_payload) VALUES($1,$2,$3,$4)`,
			insert.id, insert.previous, insert.digest, authenticPayload); err == nil {
			t.Fatalf("the protected audit accepted a row carrying %s", name)
		}
	}

	// The role the service runs as holds append and read and nothing else, so
	// the running process has no privilege to rewrite its own audit even if
	// every trigger above it were removed. A grant widened later is exactly
	// the change nobody notices, so it is asserted rather than assumed.
	//
	// Provision proves this too, on the administrative connection, before the
	// service is ever started; it is re-asserted here directly so a change
	// that loosens the grant fails in the place that describes it.
	if err := sink.VerifyRuntimePrivileges(ctx); err != nil {
		t.Fatalf("the protected audit runtime role is not least-privileged: %v", err)
	}
	// The login the service connects as is separate from the one that
	// administers the audit, is no superuser, and owns neither the schema nor
	// the table. Without that, every barrier above is something the running
	// process could remove: the trigger it would have to drop is on a table it
	// would own.
	if err := sink.VerifyRuntimeSeparation(ctx, runtimeLogin); err != nil {
		t.Fatalf("the protected audit runtime login is not separated from its administration: %v", err)
	}
	// And the separation is a real check rather than a formality: the
	// administrative login itself does not pass it.
	var administrator string
	if err := pool.QueryRow(ctx, `SELECT current_user`).Scan(&administrator); err != nil {
		t.Fatal(err)
	}
	if err := sink.VerifyRuntimeSeparation(ctx, administrator); err == nil {
		t.Fatal("the administrative login passed the runtime separation check")
	}
	runtimePool, err := persistence.OpenPool(ctx, persistence.PoolConfig{URL: runtimeURL, Role: securityauditpg.RuntimeRole, Maximum: 2})
	if err != nil {
		t.Fatal(err)
	}
	defer runtimePool.Close()
	runtimeSink, err := securityauditpg.New(runtimePool)
	if err != nil {
		t.Fatal(err)
	}
	if _, inserted, err := runtimeSink.Append(ctx, record("audit.chain.runtime", "artifact-expired")); err != nil || !inserted {
		t.Fatalf("the runtime role cannot append to its own audit: inserted=%v err=%v", inserted, err)
	}
	if records, err := runtimeSink.Read(ctx); err != nil || len(records) == 0 {
		t.Fatalf("the runtime role cannot read its own audit: records=%d err=%v", len(records), err)
	}
	// Asked from inside the running connection, about the login underneath the
	// role rather than the role it is wearing. Wearing a narrow role proves
	// nothing on its own — RESET ROLE is one statement away — so what is
	// checked is what the login itself may do.
	if err := runtimeSink.VerifyRuntimeIsolation(ctx); err != nil {
		t.Fatalf("the running audit connection is not confined to appending: %v", err)
	}
	if _, err := runtimePool.Exec(ctx, `RESET ROLE`); err != nil {
		t.Fatal(err)
	}
	for name, statement := range map[string]string{
		"rewrite after resetting its role":  `UPDATE agent_protected_audit.records SET record_digest='sha256:'||repeat('f',64)`,
		"remove after resetting its role":   `DELETE FROM agent_protected_audit.records`,
		"truncate after resetting its role": `TRUNCATE agent_protected_audit.records`,
	} {
		if _, err := runtimePool.Exec(ctx, statement); err == nil {
			t.Fatalf("the protected audit runtime login could %s the chain", name)
		}
	}
	for name, statement := range map[string]string{
		"rewrite":  `UPDATE agent_protected_audit.records SET record_digest='sha256:'||repeat('f',64)`,
		"remove":   `DELETE FROM agent_protected_audit.records`,
		"truncate": `TRUNCATE agent_protected_audit.records`,
		"redefine": `ALTER TABLE agent_protected_audit.records DISABLE TRIGGER protected_audit_is_append_only`,
	} {
		if _, err := runtimePool.Exec(ctx, statement); err == nil {
			t.Fatalf("the protected audit runtime role could %s the chain", name)
		}
	}

	// The table refuses to be rewritten. This is the first barrier; the chain
	// below is the evidence that survives someone getting past it.
	if _, err := pool.Exec(ctx, `UPDATE agent_protected_audit.records SET record_digest='sha256:'||repeat('f',64) WHERE record_id='audit.chain.1'`); err == nil {
		t.Fatal("the protected audit accepted an update")
	}
	if _, err := pool.Exec(ctx, `DELETE FROM agent_protected_audit.records WHERE record_id='audit.chain.1'`); err == nil {
		t.Fatal("the protected audit accepted a delete")
	}
	if err := sink.Verify(ctx); err != nil {
		t.Fatalf("a refused rewrite still broke the chain: %v", err)
	}

	// And the chain detects a record that was altered anyway — the trigger
	// dropped, the row rewritten by a superuser, the table restored from
	// somewhere else. The digest no longer matches the bytes.
	if _, err := pool.Exec(ctx, `ALTER TABLE agent_protected_audit.records DISABLE TRIGGER protected_audit_is_append_only`); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `UPDATE agent_protected_audit.records SET chain_payload=convert_to('{"ID":"audit.chain.1","Action":"nothing-happened"}','UTF8') WHERE record_id='audit.chain.1'`); err != nil {
		t.Fatal(err)
	}
	if err := sink.Verify(ctx); err == nil {
		t.Fatal("an altered record verified against the chain")
	}
	// A row whose duplicated columns disagree with its payload is refused by
	// the read path as well as by the trigger, so a row written around the
	// trigger cannot be served as though it were authentic.
	if _, err := pool.Exec(ctx, `ALTER TABLE agent_protected_audit.records DISABLE TRIGGER protected_audit_columns_match_payload`); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO agent_protected_audit.records(record_id,previous_digest,record_digest,chain_payload) VALUES($1,$2,$3,$4)`,
		"audit.chain.smuggled", "", securityaudit.ChainDigest(authenticPayload), authenticPayload); err != nil {
		t.Fatal(err)
	}
	if _, _, err := sink.Lookup(ctx, "audit.chain.smuggled"); err == nil {
		t.Fatal("a record filed under an identity its payload does not claim was served by the read path")
	}
	if _, err := pool.Exec(ctx, `ALTER TABLE agent_protected_audit.records ENABLE TRIGGER protected_audit_columns_match_payload`); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `ALTER TABLE agent_protected_audit.records ENABLE TRIGGER protected_audit_is_append_only`); err != nil {
		t.Fatal(err)
	}
}

// The admission check and the mutation it admits must be one indivisible act.
// A restore's very first move is to stop the fabric, and dispatch used to read
// that state on one connection and write on another: between the two the
// restore could disable dispatch and commit, and the task or the lease still
// landed — admitted by a fact that had already stopped being true.
//
// This proves it deterministically rather than by racing. A holder transaction
// takes the recovery row exactly as a restore's rotation does, dispatch is
// asked for the mutation and must block on it, and only then does the holder
// disable dispatch and commit. If the admission and the mutation are one
// transaction, dispatch wakes to the state the restore left and refuses. If
// they are not, the mutation completes before the holder ever moves, which is
// what the block assertion catches.
func assertDispatchAdmissionIsAtomicWithItsMutation(t *testing.T, ctx context.Context, pool *pgxpool.Pool, databaseURL string) {
	t.Helper()
	register, err := recoverypg.NewMirrorEpochSource(pool)
	if err != nil {
		t.Fatal(err)
	}
	dispatch, err := schedulerpg.NewDurableScheduler(pool, register, execution.DispatchIDs{}, realClock{},
		scheduler.PrerequisiteFunc(func(context.Context, scheduler.Create) error { return nil }), time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	scope := scheduler.Scope{WorkspaceID: "workspace-admission", ProjectID: "project-admission"}
	reservations, err := executionpg.NewToolReservations(pool, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := reservations.Ensure(ctx, scope.WorkspaceID, scope.ProjectID, "run-admission", "run-admission", "reservation-admission", time.Now().UTC()); err != nil {
		t.Fatal(err)
	}
	enableDispatch := func() {
		t.Helper()
		if _, err := pool.Exec(ctx, `UPDATE agent_workflow.recovery_state SET dispatch_enabled=true,ingress_enabled=true,result_intake_enabled=true,version=version+1 WHERE register_name='platform-recovery-epoch'`); err != nil {
			t.Fatal(err)
		}
	}
	enableDispatch()
	epoch, err := register.Current(ctx)
	if err != nil {
		t.Fatal(err)
	}
	create := func(id scheduler.TaskID) scheduler.Create {
		return scheduler.Create{
			Scope: scope, TaskID: id, RunID: "run-admission", RootRunID: "run-admission",
			RecoveryEpoch: uint64(epoch), ExecutionGeneration: 1, Capability: "fake.execute",
			ReservationID: "reservation-admission", ReservationCurrent: true, PolicyAllowed: true,
			InputDigest: "sha256:" + strings.Repeat("d", 64), InputObjectKey: "inputs/admission",
			CreatedAt: time.Now().UTC(),
		}
	}
	var details problem.Details

	// Creation: the restore lands between the admission and the insert.
	createErr := withRestoreHoldingTheRecoveryRow(t, ctx, pool, databaseURL, func() error {
		_, err := dispatch.Create(ctx, create("task.admission.create"))
		return err
	})
	if !errors.As(createErr, &details) || details.Code != string(problem.CodeTaskDispatchDenied) {
		t.Fatalf("create admitted across a restore that disabled dispatch: %v", createErr)
	}
	if _, err := dispatch.Get(ctx, scope, "task.admission.create"); !errors.As(err, &details) || details.Code != string(problem.CodeResourceNotFound) {
		t.Fatalf("a create refused by the restore still recorded a task: %v", err)
	}

	// Leasing: the same window, one step further along the fabric.
	enableDispatch()
	if _, err := dispatch.Create(ctx, create("task.admission.lease")); err != nil {
		t.Fatalf("a dispatching fabric refused the task the lease test needs: %v", err)
	}
	leaseErr := withRestoreHoldingTheRecoveryRow(t, ctx, pool, databaseURL, func() error {
		_, err := dispatch.Lease(ctx, scope, "task.admission.lease", "executor-admission")
		return err
	})
	if !errors.As(leaseErr, &details) || details.Code != string(problem.CodeTaskDispatchDenied) {
		t.Fatalf("lease admitted across a restore that disabled dispatch: %v", leaseErr)
	}
	task, err := dispatch.Get(ctx, scope, "task.admission.lease")
	if err != nil {
		t.Fatal(err)
	}
	if task.State != scheduler.Queued || task.Lease != nil {
		t.Fatalf("a lease refused by the restore still moved the task: state=%v lease=%+v", task.State, task.Lease)
	}
	var attempts int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM agent_workflow.worker_attempts WHERE workspace_id=$1 AND project_id=$2 AND task_id='task.admission.lease'`, scope.WorkspaceID, scope.ProjectID).Scan(&attempts); err != nil {
		t.Fatal(err)
	}
	if attempts != 0 {
		t.Fatalf("a lease refused by the restore recorded %d attempt row(s)", attempts)
	}
	enableDispatch()
}

// withRestoreHoldingTheRecoveryRow runs one dispatch operation while a
// transaction holds the recovery row the way a restore's rotation holds it,
// then disables dispatch and commits. It returns what the operation answered.
//
// The operation is required to block. That requirement is the test: an
// operation that reads the admission on its own connection never waits for the
// holder, so it finishes before the restore has moved and the assertion below
// says so plainly instead of leaving a race to decide the outcome.
func withRestoreHoldingTheRecoveryRow(t *testing.T, ctx context.Context, pool *pgxpool.Pool, databaseURL string, operation func() error) error {
	t.Helper()
	holder, err := pgx.Connect(ctx, databaseURL)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = holder.Close(ctx) }()
	restore, err := holder.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	var mirrored uint64
	if err := restore.QueryRow(ctx, `SELECT mirrored_epoch FROM agent_workflow.recovery_state WHERE register_name='platform-recovery-epoch' FOR UPDATE`).Scan(&mirrored); err != nil {
		_ = restore.Rollback(ctx)
		t.Fatal(err)
	}
	// The waiting session is observed on its own privileged connection.
	// Postgres hides the wait columns of pg_stat_activity from a session that
	// holds no privilege over the waiter's role, so a pooled connection that
	// has assumed a scoped role would report an idle database no matter what
	// was blocked on it.
	observer, err := pgx.Connect(ctx, databaseURL)
	if err != nil {
		_ = restore.Rollback(ctx)
		t.Fatal(err)
	}
	defer func() { _ = observer.Close(ctx) }()
	answered := make(chan error, 1)
	go func() { answered <- operation() }()
	if err := waitUntilBlockedOnALock(ctx, observer, answered); err != nil {
		_ = restore.Rollback(ctx)
		t.Fatalf("the dispatch operation did not serialize against the restore: %v", err)
	}
	if _, err := restore.Exec(ctx, `UPDATE agent_workflow.recovery_state SET dispatch_enabled=false,version=version+1 WHERE register_name='platform-recovery-epoch'`); err != nil {
		_ = restore.Rollback(ctx)
		t.Fatal(err)
	}
	if err := restore.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-answered:
		return err
	case <-time.After(30 * time.Second):
		t.Fatal("the dispatch operation never returned after the restore committed")
		return nil
	}
}

// waitUntilBlockedOnALock waits for the database itself to report a session
// waiting on a lock. It reports an error if the operation answers first, which
// means it never took the lock the restore is holding.
func waitUntilBlockedOnALock(ctx context.Context, observer *pgx.Conn, answered <-chan error) error {
	deadline := time.Now().Add(20 * time.Second)
	for {
		select {
		case err := <-answered:
			return fmt.Errorf("it completed while the recovery row was held (answer: %v)", err)
		default:
		}
		var waiting int
		if err := observer.QueryRow(ctx, `SELECT count(*) FROM pg_stat_activity WHERE datname=current_database() AND wait_event_type='Lock' AND state='active' AND pid<>pg_backend_pid()`).Scan(&waiting); err != nil {
			return err
		}
		if waiting > 0 {
			return nil
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("no session ever waited on the recovery row")
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// Authority that answers for one person is read back bound to that person.
// The register holds the custodian's capability and clearance on its own
// subject row, the ordinary actor in the same scope holds neither, and an
// actor the register stops admitting holds nothing at all.
func assertActorBoundAuthority(t *testing.T, ctx context.Context, store *authoritypg.Store) {
	t.Helper()
	scoped := func(actor string) authority.Current {
		t.Helper()
		current, err := store.Current(ctx, authority.Scope{WorkspaceID: "workspace-auth", ProjectID: "project-auth", ActorID: actor})
		if err != nil {
			t.Fatal(err)
		}
		return current
	}
	custodian := scoped("custodian-auth")
	if !custodian.ActorGrants.HasCapability("artifact-custody.legal-hold") || !custodian.ActorGrants.Clears("internal") {
		t.Fatalf("custodian actor grants=%+v, want its own capability and clearance", custodian.ActorGrants)
	}
	if custodian.ActorGrants.HasCapability("artifact-custody.delete") {
		t.Fatalf("custodian holds a capability the register never bound to it: %+v", custodian.ActorGrants)
	}
	if custodian.ActorGrants.Clears("confidential") {
		t.Fatalf("custodian clears above what the register granted: %+v", custodian.ActorGrants)
	}
	// The same scope, the same dispatch grants, a different person: nothing.
	ordinary := scoped("actor-auth")
	if len(ordinary.ActorGrants.Capabilities) != 0 || len(ordinary.ActorGrants.DataClasses) != 0 {
		t.Fatalf("an ordinary actor in the scope holds %+v, want nothing bound to it", ordinary.ActorGrants)
	}
	if ordinary.Grants.MaximumRisk != custodian.Grants.MaximumRisk {
		t.Fatalf("dispatch grants differ between actors in one scope: %q vs %q", ordinary.Grants.MaximumRisk, custodian.Grants.MaximumRisk)
	}
	// Withdrawing the custodian leaves nothing readable behind it.
	if err := store.Revoke(ctx, authority.Revocation{WorkspaceID: "workspace-auth", ProjectID: "project-auth", RevocationID: "revocation-custodian-auth", Kind: authority.RevokeActor, Subject: "custodian-auth", Reason: "offboarded"}); err != nil {
		t.Fatal(err)
	}
	withdrawn := scoped("custodian-auth")
	if withdrawn.ActorActive || withdrawn.ActorRole != "" || len(withdrawn.ActorGrants.Capabilities) != 0 || len(withdrawn.ActorGrants.DataClasses) != 0 {
		t.Fatalf("a withdrawn custodian still reads as %+v", withdrawn)
	}
}
