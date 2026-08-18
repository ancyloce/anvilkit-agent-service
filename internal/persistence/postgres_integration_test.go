package persistence_test

import (
	"bytes"
	"context"
	"crypto/rand"
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
	defer connection.Close(ctx)
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
	assertAtomicEventsAndInbox(t, ctx, authorityPool)
	assertIdempotency(t, ctx, authorityPool)
	assertDurableRunCore(t, ctx, authorityPool)
	assertDurableRunStoreAtomicity(t, ctx, authorityPool)
	assertControlInterrupts(t, ctx, authorityPool)
	assertModelEvidence(t, ctx, pool)
	assertCommitBoundaries(t, ctx, pool)
	assertSchedulerBoundaries(t, ctx, pool)
	assertWorkflowLeaseCleanup(t, ctx, pool)
	assertRecoveryBoundaries(t, ctx, pool)
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
	if err := migrator.RollbackLast(ctx); err != nil {
		t.Fatal(err)
	}
	if err := migrator.RollbackLast(ctx); err != nil {
		t.Fatal(err)
	}
	if err := migrator.RollbackLast(ctx); err != nil {
		t.Fatal(err)
	}
	if err := migrator.RollbackLast(ctx); err != nil {
		t.Fatal(err)
	}
	if err := migrator.RollbackLast(ctx); err != nil {
		t.Fatal(err)
	}
	if err := migrator.RollbackLast(ctx); err != nil {
		t.Fatal(err)
	}
	if err := migrator.RollbackLast(ctx); err != nil {
		t.Fatal(err)
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
INSERT INTO agent_workflow.agent_tasks(workspace_id,project_id,task_id,run_id,root_run_id,recovery_epoch,execution_generation,capability,capability_version,reservation_id,input_digest,input_object_key,state,lease_epoch,physical_attempts,created_at)
VALUES('workspace-scheduler-injected','project-scheduler','task-workflow-cleanup','run-scheduler-injected','root-scheduler-injected',2,3,'fake.execute','fake.execute/v1','reservation-scheduler-injected',$1,'inputs/cleanup','leased',1,1,$2)`,
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
	authRecord := applyauth.AuditRecord{AuthorizationID: "authorization-commit", WorkspaceID: "workspace-commit", ProjectID: "project-commit", RunID: "run-commit", KeyID: "urn:anvilkit:key:commit-synthetic", PayloadDigest: digest('a'), TokenDigest: digest('b'), IssuedAt: now, ExpiresAt: now.Add(2 * time.Minute)}
	if err := audit.Record(ctx, authRecord); err != nil {
		t.Fatal(err)
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
		{`INSERT INTO agent_workflow.agent_tasks(workspace_id,project_id,task_id,run_id,root_run_id,recovery_epoch,execution_generation,capability,capability_version,reservation_id,input_digest,input_object_key,state,lease_epoch,physical_attempts,created_at) VALUES($1,$2,$3,$4,$5,2,3,'fake.execute','fake.execute/v1',$6,$7,'inputs/task','leased',4,1,$8)`, []any{scope.WorkspaceID, scope.ProjectID, taskID, runID, rootRunID, reservationID, digest("a"), now}},
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

type modelIDs struct{}

func (modelIDs) InvocationID() string { return "invocation-model" }
func (modelIDs) AttemptID(attempt int) modelgateway.AttemptID {
	return modelgateway.AttemptID(fmt.Sprintf("attempt-%d", attempt))
}

type modelSleeper struct{}

func (modelSleeper) Sleep(context.Context, time.Duration) error { return nil }

type modelKeys struct{ value []byte }

func (keys modelKeys) Key(context.Context, string) ([]byte, error) {
	return append([]byte(nil), keys.value...), nil
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
	gateway, err := modelgateway.NewGateway(map[modelgateway.ProviderID]modelgateway.Adapter{modelgateway.FakeProviderID: modelgateway.FakeAdapter{}}, recorder, modelIDs{}, testClock{time.Unix(400, 0)}, modelSleeper{})
	if err != nil {
		t.Fatal(err)
	}
	policy := modelgateway.Policy{Version: "policy-v1", AllowedProviders: []modelgateway.ProviderID{modelgateway.FakeProviderID}, AllowedRegions: []string{"test"}, DataClasses: []modelgateway.DataClass{modelgateway.Internal}, Capability: "plan", MinimumSafety: 2, MaximumCostMicros: 1000}
	_, record, err := gateway.InvokeEligible(ctx, registry, policy, modelgateway.InvokeRequest{RunID: "run-model", WorkspaceID: "workspace-model", ProjectID: "project-model", Context: []byte("minimal"), DataClasses: []modelgateway.DataClass{modelgateway.Internal}, MaximumOutputBytes: 4096, MaximumInputTokens: 256, MaximumOutputTokens: 2000, MaximumCostMicros: 1000, Timeout: time.Second, MaximumAttempts: 1, Scenario: "valid"})
	if err != nil || len(record.PhysicalAttempts) != 1 {
		t.Fatalf("durable invocation=%#v err=%v", record, err)
	}
	var attempts []byte
	if err := pool.QueryRow(ctx, `SELECT physical_attempt_ids FROM agent_workflow.provider_invocations WHERE workspace_id='workspace-model' AND project_id='project-model' AND invocation_id='invocation-model'`).Scan(&attempts); err != nil || !bytes.Contains(attempts, []byte("attempt-1")) {
		t.Fatalf("physical attempt was not durable before disclosure: %s %v", attempts, err)
	}
	var policyDigest string
	var policySnapshot []byte
	if err := pool.QueryRow(ctx, `SELECT policy_digest,policy_snapshot FROM agent_workflow.provider_invocations WHERE workspace_id='workspace-model' AND project_id='project-model' AND invocation_id='invocation-model'`).Scan(&policyDigest, &policySnapshot); err != nil || policyDigest != record.PolicyDigest || !bytes.Contains(policySnapshot, []byte(`"policy-v1"`)) {
		t.Fatalf("immutable policy evidence digest=%s snapshot=%s err=%v", policyDigest, policySnapshot, err)
	}
	durableRecord, err := recorder.Get(ctx, "workspace-model", "project-model", "invocation-model")
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
	forgedPolicyRecord.InvocationID = "invocation-model-forged-policy"
	forgedPolicyRecord.PolicyDigest = changedSelection.PolicyDigest
	forgedPolicyRecord.PolicySnapshot = changedSelection.PolicySnapshot
	if err := recorder.BeforeDisclosure(ctx, forgedPolicyRecord); err == nil {
		t.Fatal("durable provider policy version was reused for different content")
	}
	if _, err := pool.Exec(ctx, `UPDATE agent_workflow.provider_invocations SET provider='mutated' WHERE workspace_id='workspace-model' AND project_id='project-model' AND invocation_id='invocation-model'`); err == nil {
		t.Fatal("durable invocation identity was mutable")
	}
	if _, err := pool.Exec(ctx, `UPDATE agent_workflow.provider_invocations SET policy_snapshot='{}'::jsonb WHERE workspace_id='workspace-model' AND project_id='project-model' AND invocation_id='invocation-model'`); err == nil {
		t.Fatal("durable invocation policy snapshot was mutable")
	}
	if _, err := pool.Exec(ctx, `UPDATE agent_workflow.provider_invocations SET cost_micros=cost_micros+1 WHERE workspace_id='workspace-model' AND project_id='project-model' AND invocation_id='invocation-model'`); err == nil {
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
	compiled, err := compiler.CompileAndRecord(ctx, contextcompiler.Request{TenantID: "tenant", WorkspaceID: "workspace-model", ProjectID: "project-model", RunID: "run-model", Policy: contextPolicy, RedactionPolicy: contextPolicy, TotalTokens: 8, CompiledAt: time.Unix(400, 0), Sources: []contextcompiler.Source{{ID: "system", Trust: contextcompiler.System, Classification: contextcompiler.Internal, Content: "policy", TenantID: "tenant", TokenBudget: 2}, {ID: "user", Trust: contextcompiler.User, Classification: contextcompiler.Internal, Content: "registered-secret", TenantID: "tenant", TokenBudget: 4}}}, contextRecorder)
	if err != nil || bytes.Contains([]byte(compiled.Disclosure[1].Content), []byte("registered-secret")) {
		t.Fatalf("compiled context=%#v err=%v", compiled, err)
	}

	toolRecorder, _ := toolpg.New(pool)
	toolPolicy := tools.PolicyReference{PolicyID: "policy", Version: "v1", Digest: binding}
	schema := tools.SchemaReference{ComponentName: "anvilkit.contract.schema.synthetic.v1", Version: "1.0.0", Digest: binding}
	definition := func(id, capability string) tools.Definition {
		return tools.Definition{APIVersion: "anvilkit.io/contracts/v1", Kind: "ToolDefinition", Capability: capability, CapabilityVersion: capability + "/v1", InputSchema: schema, OutputSchema: schema, SideEffectClass: "none", RiskClass: "low", ApprovalPolicy: toolPolicy, TimeoutPolicy: tools.TimeoutPolicy{TimeoutMilliseconds: 1000}, RetryPolicy: tools.RetryPolicy{MaximumAttempts: 1, Retryability: []string{}}, AcceptedDataClasses: []string{"internal"}, ToolID: id}
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
	guard, _ := tools.NewGuard(pinnedProfile, toolRecorder, testClock{time.Unix(400, 0)}, tools.JSONArgumentValidator{})
	intent := tools.Intent{RunID: "run-model", WorkspaceID: "workspace-model", ProjectID: "project-model", ActorID: "actor", AllowedTools: []string{"fake.execute"}, AllowedEffects: []string{"none"}, MaximumRisk: "low", DataClasses: []string{"internal"}}
	current := tools.CurrentAuthority{WorkspaceActive: true, ActorActive: true, PermissionActive: true, PolicyActive: true, AllowedTools: intent.AllowedTools, AllowedEffects: intent.AllowedEffects, MaximumRisk: "low", DataClasses: intent.DataClasses}
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
	runStore := runpg.New(pool, idempotencyStore)
	runService := runs.NewService(runStore, noOpStarter{}, runID("control-run"), testClock{time.Unix(300, 0)}, journal.NewMemoryStore())
	raw := []byte(`{"domain":"platform-agent","operation":"artifact-validation","target":{"targetType":"page","targetId":"page-control"}}`)
	digest, _ := canonical.Digest(raw)
	scope := runs.Scope{TenantID: "tenant", WorkspaceID: "workspace-control", ProjectID: "project-control", ActorID: "actor"}
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
	store, err := interruptpg.New(pool, idempotencyStore)
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
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM agent_workflow.checkpoints WHERE workspace_id=$1 AND project_id=$2 AND workflow_id=$3`, scope.WorkspaceID, scope.ProjectID, string(current.RunID)+":v1").Scan(&checkpointCount); err != nil {
		t.Fatal(err)
	}
	if eventCount != 7 || checkpointCount != 7 {
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
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM agent_events.outbox WHERE workspace_id=$1 AND project_id=$2 AND run_id=$3 AND published_at IS NOT NULL`, scope.WorkspaceID, scope.ProjectID, current.RunID).Scan(&publishedCount); err != nil || publishedCount != 7 {
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
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM agent_events.agent_events WHERE workspace_id=$1 AND project_id=$2 AND run_id=$3`, scope.WorkspaceID, scope.ProjectID, current.RunID).Scan(&eventCount); err != nil || eventCount != 7 {
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
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM agent_events.agent_events WHERE workspace_id=$1 AND project_id=$2 AND run_id=$3`, scope.WorkspaceID, scope.ProjectID, current.RunID).Scan(&eventCount); err != nil || eventCount != 8 {
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
	if err != nil || len(replay.Events) != 11 {
		t.Fatalf("control event replay=%#v err=%v", replay, err)
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
	service := runs.NewService(runpg.New(pool, idempotencyStore), noOpStarter{}, &sequentialRunIDs{}, testClock{time.Now().UTC()}, journal.NewMemoryStore())
	scope := runs.Scope{TenantID: "tenant", WorkspaceID: "workspace-durable-load", ProjectID: "project-durable-load", ActorID: "actor"}
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
			raw := []byte(fmt.Sprintf(`{"domain":"platform-agent","operation":"artifact-validation","target":{"targetType":"page","targetId":"load-%06d"}}`, index))
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
		}{1, "agent-service-load-model-v1", duration.Milliseconds(), requests, 20, float64(p95) / float64(time.Millisecond), 300, p95 < 300*time.Millisecond}
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
	store := runpg.New(pool, idempotencyStore)
	starter := &durableStarter{store: store, started: make(map[string]bool)}
	service := runs.NewService(store, starter, runID("durable-run"), testClock{time.Unix(200, 0)}, journal.NewMemoryStore())
	raw := []byte(`{"domain":"platform-agent","operation":"artifact-validation","target":{"targetType":"page","targetId":"page-durable"}}`)
	digest, _ := canonical.Digest(raw)
	scope := runs.Scope{TenantID: "tenant", WorkspaceID: "workspace-durable", ProjectID: "project-durable", ActorID: "actor"}
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
	missing, err := service.Get(ctx, runs.Scope{TenantID: "tenant", WorkspaceID: "other", ProjectID: "project-durable", ActorID: "actor"}, "durable-run")
	_ = missing
	assertProblemCode(t, err, problem.CodeResourceNotFound)
	_, err = service.Get(ctx, scope, "absent")
	assertProblemCode(t, err, problem.CodeResourceNotFound)
	page, err := service.List(ctx, scope, runs.ListOptions{Limit: 1})
	if err != nil || len(page.Items) != 1 {
		t.Fatalf("page=%#v err=%v", page, err)
	}
	different := []byte(`{"domain":"platform-agent","operation":"image-operation","target":{"targetType":"page","targetId":"page-durable"}}`)
	differentDigest, _ := canonical.Digest(different)
	conflicting := input
	conflicting.Raw = different
	conflicting.ClaimedDigest = differentDigest
	_, err = service.Create(ctx, conflicting)
	assertProblemCode(t, err, problem.CodeIdempotencyConflict)
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
		findings := guard.Validate(ctx, contractguard.EventIn, "anvilkit://schema/agent-event.v1@1.0.0?digest=sha256:f19775b8dfdd34cac0318fce8067460988671840987a2b9aaeaa3c85710591ab", event.Bytes)
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
	if findings := guard.Validate(ctx, contractguard.APIIn, "anvilkit://schema/agent-run.v1@1.0.0?digest=sha256:68949242c9b4557a8b5ff965f76de8f2de49c11523a7cc1e64cfd1b4af824233", projection.Run); len(findings) != 0 {
		t.Fatalf("snapshot run is not contract-valid: %#v raw=%s", findings, projection.Run)
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
	duplicate := replay.Events[0]
	if err := reader.Append(ctx, eventScope, duplicate); err != nil {
		t.Fatalf("identical event replay rejected: %v", err)
	}
	duplicate.Bytes = []byte(`{"different":true}`)
	if err := reader.Append(ctx, eventScope, duplicate); err == nil {
		t.Fatal("duplicate event ID with different bytes accepted")
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
		scope := runs.Scope{TenantID: "tenant", WorkspaceID: "workspace-durable-atomic", ProjectID: "project-durable-atomic", ActorID: "actor"}
		raw := []byte(fmt.Sprintf(`{"domain":"platform-agent","operation":"artifact-validation","target":{"targetType":"page","targetId":"atomic-create-%d"}}`, index))
		digest, _ := canonical.Digest(raw)
		store := runpg.NewConfigured(pool, idempotencyStore, events.DefaultBounds(), func(actual runpg.FailurePoint) error {
			if actual == point {
				return errors.New("fault")
			}
			return nil
		})
		service := runs.NewService(store, noOpStarter{}, runIDGenerator(runID), testClock{time.Unix(250, 0)}, journal.NewMemoryStore())
		if _, err := service.Create(ctx, runs.CreateInput{Scope: scope, Key: fmt.Sprintf("atomic-create-%d", index), ClaimedDigest: digest, Traceparent: traceparent, Raw: raw, Authority: durableAuthority()}); err == nil {
			t.Fatalf("create failure %s did not abort", point)
		}
		assertDurableAtomicCounts(t, ctx, pool, scope, runID, 0, 0)

		base := runs.NewService(runpg.New(pool, idempotencyStore), noOpStarter{}, runIDGenerator(runID), testClock{time.Unix(250, 0)}, journal.NewMemoryStore())
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
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM agent_workflow.checkpoints WHERE workspace_id=$1 AND project_id=$2 AND workflow_id=$3`, scope.WorkspaceID, scope.ProjectID, string(runID)+":v1").Scan(&checkpointCount); err != nil {
		t.Fatal(err)
	}
	if eventCount != wantEvidence || outboxCount != wantEvidence || checkpointCount != wantEvidence {
		t.Fatalf("run %s partial evidence: events=%d outbox=%d checkpoints=%d want=%d", runID, eventCount, outboxCount, checkpointCount, wantEvidence)
	}
}

func durableAuthority() runs.Authority {
	policy := []byte(`{"policyId":"policy.synthetic","version":"v1","digest":"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}`)
	return runs.Authority{
		ContractBOM: []byte(`{"repository":"anvilkit/contracts","bomDigest":"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","ociManifestDigest":"sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","evidenceManifestDigest":"sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"}`),
		Policy:      policy,
		Budget:      []byte(`{"apiVersion":"anvilkit.io/contracts/v1","kind":"AgentBudget","modelLimits":{"maximumCalls":10,"maximumConcurrentCalls":2},"tokenLimits":{"inputTokens":4096,"outputTokens":2048,"totalTokens":6144},"workerLimits":{"maximumAttempts":4,"maximumDurationMilliseconds":60000},"gpuLimits":{"maximumGpuMilliseconds":0},"currencyLimits":{"maximumCost":{"amount":"1000","currency":"USD"},"reservedCost":{"amount":"500","currency":"USD"}},"reservationId":"reservation.synthetic.001","exceedBehavior":"refuse","policy":` + string(policy) + `}`),
	}
}

type runID string

func (id runID) NewID() (runs.ID, error) { return runs.ID(id), nil }

type runIDGenerator runs.ID

func (id runIDGenerator) NewID() (runs.ID, error) { return runs.ID(id), nil }

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
	s.started[start.WorkflowID] = true
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

func assertAtomicEventsAndInbox(t *testing.T, ctx context.Context, pool *pgxpool.Pool) {
	t.Helper()
	guard, err := contractguard.NewGuard("../..")
	if err != nil {
		t.Fatal(err)
	}
	scope := events.Scope{WorkspaceID: "w", ProjectID: "p"}
	eventBytes := validEventBytes("event-1", "scoped", 1, "run.state-changed")
	change := events.Transition{Scope: scope, RunID: "scoped", ExpectedVersion: 1, NextState: "preparing", Snapshot: []byte(`{"state":"preparing"}`), EventID: "event-1", EventBytes: eventBytes, OutboxID: "outbox-1", Topic: "agent.events", OutboxBytes: eventBytes, WorkflowID: "scoped:v1", WorkflowVersion: 1, Checkpoint: "preparing", CheckpointBytes: []byte(`{"state":"preparing"}`)}
	invalid := change
	invalid.EventBytes = []byte(`{"apiVersion":"attacker"}`)
	if _, err := eventpg.New(pool, nil, guard).Commit(ctx, invalid); err == nil {
		t.Fatal("invalid event crossed the durable event boundary")
	}
	prohibited := change
	prohibited.EventBytes = bytes.Replace(change.EventBytes, []byte(`"state":"preparing"`), []byte(`"state":"secret"`), 1)
	if _, err := eventpg.New(pool, nil, guard).Commit(ctx, prohibited); err == nil {
		t.Fatal("prohibited event content crossed the durable event boundary")
	}
	mismatched := change
	mismatched.EventBytes = validEventBytes("different-event", "scoped", 1, "run.state-changed")
	if _, err := eventpg.New(pool, nil, guard).Commit(ctx, mismatched); err == nil {
		t.Fatal("event body/envelope identity mismatch crossed the durable boundary")
	}
	var unchanged int
	if err := pool.QueryRow(ctx, `SELECT version FROM agent_control.agent_runs WHERE workspace_id='w' AND project_id='p' AND run_id='scoped'`).Scan(&unchanged); err != nil || unchanged != 1 {
		t.Fatalf("invalid event mutated run version=%d err=%v", unchanged, err)
	}
	for _, point := range []eventpg.FailurePoint{eventpg.AfterRunUpdate, eventpg.AfterEventInsert, eventpg.AfterOutboxInsert, eventpg.AfterCheckpointInsert} {
		repository := eventpg.New(pool, func(actual eventpg.FailurePoint) error {
			if actual == point {
				return errors.New("fault")
			}
			return nil
		}, guard)
		if _, err := repository.Commit(ctx, change); err == nil {
			t.Fatalf("failure %s did not abort", point)
		}
		var version, eventCount, outboxCount, checkpointCount int
		if err := pool.QueryRow(ctx, `SELECT version FROM agent_control.agent_runs WHERE workspace_id='w' AND project_id='p' AND run_id='scoped'`).Scan(&version); err != nil {
			t.Fatal(err)
		}
		_ = pool.QueryRow(ctx, `SELECT count(*) FROM agent_events.agent_events WHERE run_id='scoped'`).Scan(&eventCount)
		_ = pool.QueryRow(ctx, `SELECT count(*) FROM agent_events.outbox WHERE run_id='scoped'`).Scan(&outboxCount)
		_ = pool.QueryRow(ctx, `SELECT count(*) FROM agent_workflow.checkpoints WHERE workflow_id='scoped:v1'`).Scan(&checkpointCount)
		if version != 1 || eventCount != 0 || outboxCount != 0 || checkpointCount != 0 {
			t.Fatalf("partial state after %s: version=%d event=%d outbox=%d checkpoint=%d", point, version, eventCount, outboxCount, checkpointCount)
		}
	}
	committed, err := eventpg.New(pool, nil, guard).Commit(ctx, change)
	if err != nil || committed.Version != 2 || committed.Sequence != 1 {
		t.Fatalf("commit=%#v err=%v", committed, err)
	}
	inbox := eventpg.New(pool, nil, guard)
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
}

func validEventBytes(eventID, runID string, sequence uint64, eventType string) []byte {
	value := map[string]any{
		"apiVersion": "anvilkit.io/contracts/v1",
		"kind":       "AgentEvent",
		"eventId":    eventID,
		"runId":      runID,
		"sequence":   sequence,
		"eventType":  eventType,
		"occurredAt": "2026-08-13T12:00:00.000Z",
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
	request := idempotency.Request{WorkspaceID: "w", ProjectID: "p", Operation: "cancel", Key: "same", Digest: []byte("canonical"), RunID: "idem", VersionBound: 1}
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
}

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
