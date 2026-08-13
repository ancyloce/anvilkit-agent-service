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
	assertM2RunCore(t, ctx, authorityPool)
	assertM3Interrupts(t, ctx, authorityPool)
	assertM4Evidence(t, ctx, pool)
	assertM5Boundaries(t, ctx, pool)
	assertM6Boundaries(t, ctx, pool)
	assertM7Boundaries(t, ctx, pool)
	if os.Getenv("M2_LOAD_TEST") == "1" {
		assertM2CreateLatency(t, ctx, authorityPool)
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

func assertM7Boundaries(t *testing.T, ctx context.Context, pool *pgxpool.Pool) {
	t.Helper()
	now := time.Now().UTC()
	register, _ := recovery.NewMemoryRegister(2)
	current, _ := register.Current(ctx)
	epoch, err := register.Increment(ctx, current, recovery.IncrementEvidence{Actor: "operator", Workload: "restore-controller", Reason: "PITR proof", Ticket: "M7-RESTORE", Traceparent: "00-0123456789abcdef0123456789abcdef-0123456789abcdef-01", At: now})
	if err != nil || epoch != 3 {
		t.Fatalf("external epoch=%d err=%v", epoch, err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO agent_workflow.executor_leases(workspace_id,project_id,workflow_id,executor_id,lease_epoch,expires_at) VALUES('workspace-m6-injected','project-m6','workflow-m7','executor',1,$1)`, now.Add(time.Minute)); err != nil {
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
	// Simulate a restored row that appears current inside the bulk database.
	// The external epoch and scheduler mirror still make it powerless.
	if _, err := pool.Exec(ctx, `UPDATE agent_workflow.agent_tasks SET recovery_epoch=2,state='leased',lease_epoch=4 WHERE workspace_id='workspace-m6-injected' AND project_id='project-m6' AND task_id='task-m6-injected'; UPDATE agent_workflow.worker_attempts SET state='active' WHERE workspace_id='workspace-m6-injected' AND project_id='project-m6' AND physical_attempt_id='attempt-m6-injected'`); err != nil {
		t.Fatal(err)
	}
	repository, _ := schedulerpg.New(pool, register, nil)
	digest := "sha256:" + strings.Repeat("b", 64)
	delayed := scheduler.Result{TaskID: "task-m6-injected", RecoveryEpoch: 2, ExecutionGeneration: 3, PhysicalAttemptID: "attempt-m6-injected", LeaseEpoch: 4, FenceToken: "opaque-fence-m6-injected", Capability: "fake.execute", BuildIdentity: "build-m6", ArtifactID: "artifact-m6-injected", ArtifactDigest: digest, PendingObjectKey: "pending/task-m6-injected/r2/g3/attempt-m6-injected/output", CompletedAt: now}
	if accepted, err := repository.AcceptResult(ctx, scheduler.Scope{WorkspaceID: "workspace-m6-injected", ProjectID: "project-m6"}, delayed); err != nil || accepted {
		t.Fatalf("pre-restore result accepted=%v err=%v", accepted, err)
	}
	usageStore, _ := usagepg.New(pool)
	usagePipeline, _ := usage.New(usageStore, &usage.MemorySink{})
	oldUsage := usage.Observation{WorkspaceID: "workspace-m6-injected", ProjectID: "project-m6", ObservationID: "usage-m7-old-epoch", RootRunID: "root-m6-injected", RunID: "run-m6-injected", TaskID: "task-m6-injected", RecoveryEpoch: 2, ExecutionGeneration: 3, PhysicalAttemptID: "attempt-m6-injected", ReservationID: "reservation-m6-injected", ProviderEventID: "billing-m7-old-epoch", Meter: "provider-cost", Quantity: "10", Unit: "usd-micro", Currency: "USD", CostMicros: 10, MeterSequence: 1, Final: true, ObservedAt: now, Provider: "fake-worker", BuildIdentity: "build-m6", Traceparent: "00-0123456789abcdef0123456789abcdef-0123456789abcdef-01"}
	if accepted, err := usagePipeline.Accept(ctx, oldUsage); err != nil || !accepted {
		t.Fatalf("old epoch usage accepted=%v err=%v", accepted, err)
	}
	var results int
	var artifactState string
	var released bool
	if err := pool.QueryRow(ctx, `SELECT (SELECT count(*) FROM agent_workflow.worker_results WHERE workspace_id='workspace-m6-injected'),a.state,b.released FROM agent_artifacts.metadata a JOIN agent_control.budget_reservations b ON b.workspace_id=a.workspace_id AND b.project_id=a.project_id AND b.reservation_id='reservation-m6-injected' WHERE a.workspace_id='workspace-m6-injected' AND a.project_id='project-m6' AND a.artifact_id='artifact-m6-injected'`).Scan(&results, &artifactState, &released); err != nil || results != 0 || artifactState != "pending" || released {
		t.Fatalf("results=%d artifact=%s released=%v err=%v", results, artifactState, released, err)
	}
	register.SetUnavailable(true)
	if accepted, err := repository.AcceptResult(ctx, scheduler.Scope{WorkspaceID: "workspace-m6-injected", ProjectID: "project-m6"}, delayed); err == nil || accepted {
		t.Fatalf("unavailable register accepted=%v err=%v", accepted, err)
	}
}

func assertM5Boundaries(t *testing.T, ctx context.Context, pool *pgxpool.Pool) {
	t.Helper()
	now := time.Unix(500, 0).UTC()
	digest := func(character byte) string { return "sha256:" + strings.Repeat(string(character), 64) }
	audit, err := applyauthpg.New(pool)
	if err != nil {
		t.Fatal(err)
	}
	authRecord := applyauth.AuditRecord{AuthorizationID: "authorization-m5", WorkspaceID: "workspace-m5", ProjectID: "project-m5", RunID: "run-m5", KeyID: "urn:anvilkit:key:m5-synthetic", PayloadDigest: digest('a'), TokenDigest: digest('b'), IssuedAt: now, ExpiresAt: now.Add(2 * time.Minute)}
	if err := audit.Record(ctx, authRecord); err != nil {
		t.Fatal(err)
	}
	operationStore, err := commitpg.New(pool)
	if err != nil {
		t.Fatal(err)
	}
	scope := domaincommit.Scope{WorkspaceID: "workspace-m5", ProjectID: "project-m5"}
	operation := domaincommit.Operation{Scope: scope, RunID: "run-m5", ID: "operation-m5", AuthorizationID: authRecord.AuthorizationID, AuthorizationJWS: "synthetic.header.signature", ActionDigest: digest('c'), ArtifactDigest: digest('d'), ExpectedRevision: "revision-1", Status: domaincommit.Recorded, CreatedAt: now, UpdatedAt: now}
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

	validation, err := contractpg.New(pool)
	if err != nil {
		t.Fatal(err)
	}
	if err := validation.Record(ctx, contractclient.Evidence{WorkspaceID: scope.WorkspaceID, ProjectID: scope.ProjectID, RunID: "run-m5", Kind: contractclient.Artifact, BOMDigest: digest('a'), SchemaDigest: digest('b'), ValidatorVersion: "runtime-m5", CatalogDigest: digest('c'), Valid: true, ValidatedAt: now}); err != nil {
		t.Fatal(err)
	}
	var evidence int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM agent_evaluation.validation_evidence WHERE workspace_id=$1 AND project_id=$2 AND run_id='run-m5'`, scope.WorkspaceID, scope.ProjectID).Scan(&evidence); err != nil || evidence != 1 {
		t.Fatalf("validation evidence=%d err=%v", evidence, err)
	}

	if _, err := pool.Exec(ctx, `INSERT INTO agent_control.budget_reservations(workspace_id,project_id,root_run_id,run_id,reservation_id,controller_generation,policy_version,budget_version,upper_bound_micros,expires_at) VALUES($1,$2,'root-m5','run-m5','reservation-m5',2,'policy-m5','budget-m5',100,$3)`, scope.WorkspaceID, scope.ProjectID, now.Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO agent_control.usage_observations(workspace_id,project_id,root_run_id,run_id,reservation_id,observation_id,task_id,physical_attempt_id,recovery_epoch,execution_generation,meter_sequence,cost_micros,final) VALUES($1,$2,'root-m5','run-m5','reservation-m5','observation-m5','task-m5','attempt-m5',1,1,1,40,true)`, scope.WorkspaceID, scope.ProjectID); err != nil {
		t.Fatal(err)
	}

	if _, err := pool.Exec(ctx, `INSERT INTO agent_artifacts.metadata(workspace_id,project_id,artifact_id,run_id,digest,actual_digest,state,security_generation,lineage,object_reference,schema_identity) VALUES($1,$2,'artifact-m5','run-m5',$3,$3,'finalized',2,'{}','{}','{}')`, scope.WorkspaceID, scope.ProjectID, digest('d')); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO agent_artifacts.access_grants(workspace_id,project_id,artifact_id,grant_id,security_generation,purpose,actor_id,issued_at,expires_at) VALUES($1,$2,'artifact-m5','grant-m5',2,'commit','actor-m5',$3,$4)`, scope.WorkspaceID, scope.ProjectID, now, now.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
}

func assertM6Boundaries(t *testing.T, ctx context.Context, pool *pgxpool.Pool) {
	t.Helper()
	scope := scheduler.Scope{WorkspaceID: "workspace-m6", ProjectID: "project-m6"}
	now := time.Now().UTC()
	digest := func(c string) string { return "sha256:" + strings.Repeat(c, 64) }
	seedM6Result(t, ctx, pool, scope, "", now)
	if _, err := pool.Exec(ctx, `INSERT INTO agent_workflow.recovery_state(register_name,mirrored_epoch,result_intake_enabled) VALUES('platform-recovery-epoch',2,true)`); err != nil {
		t.Fatal(err)
	}
	register, _ := recovery.NewMemoryRegister(2)
	repository, _ := schedulerpg.New(pool, register, nil)
	base := scheduler.Result{TaskID: "task-m6", RecoveryEpoch: 2, ExecutionGeneration: 3, PhysicalAttemptID: "attempt-m6", LeaseEpoch: 4, FenceToken: "opaque-fence-m6-0001", Capability: "fake.execute", BuildIdentity: "build-m6", ArtifactID: "artifact-m6", ArtifactDigest: digest("b"), PendingObjectKey: "pending/task-m6/r2/g3/attempt-m6/output", CompletedAt: now.Add(time.Second)}
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
	if err := pool.QueryRow(ctx, `SELECT t.state,a.state,r.state,b.released FROM agent_workflow.agent_tasks t JOIN agent_artifacts.metadata a ON a.workspace_id=t.workspace_id AND a.project_id=t.project_id AND a.artifact_id='artifact-m6' JOIN agent_control.agent_runs r ON r.workspace_id=t.workspace_id AND r.project_id=t.project_id AND r.run_id=t.run_id JOIN agent_control.budget_reservations b ON b.workspace_id=t.workspace_id AND b.project_id=t.project_id AND b.reservation_id=t.reservation_id WHERE t.workspace_id=$1 AND t.project_id=$2 AND t.task_id='task-m6'`, scope.WorkspaceID, scope.ProjectID).Scan(&taskState, &artifactState, &runState, &released); err != nil || taskState != "completed" || artifactState != "scanning" || runState != "validating" || !released {
		t.Fatalf("atomic task=%s artifact=%s run=%s released=%v err=%v", taskState, artifactState, runState, released, err)
	}
	usageStore, _ := usagepg.New(pool)
	sink := &usage.MemorySink{}
	pipeline, _ := usage.New(usageStore, sink)
	observation := usage.Observation{WorkspaceID: scope.WorkspaceID, ProjectID: scope.ProjectID, ObservationID: "usage-m6", RootRunID: "root-m6", RunID: "run-m6", TaskID: "task-m6", RecoveryEpoch: 2, ExecutionGeneration: 3, PhysicalAttemptID: "attempt-m6", ReservationID: "reservation-m6", ProviderEventID: "billing-m6", Meter: "provider-cost", Quantity: "40", Unit: "usd-micro", Currency: "USD", CostMicros: 40, MeterSequence: 1, Final: true, ObservedAt: now, Provider: "fake-worker", BuildIdentity: "build-m6", Traceparent: "00-0123456789abcdef0123456789abcdef-0123456789abcdef-01"}
	if accepted, err := pipeline.Accept(ctx, observation); err != nil || !accepted {
		t.Fatalf("usage accepted=%v err=%v", accepted, err)
	}
	if accepted, err := pipeline.Accept(ctx, observation); err != nil || accepted {
		t.Fatalf("usage replay accepted=%v err=%v", accepted, err)
	}
	conflictingUsage := observation
	conflictingUsage.ObservationID = "usage-m6-conflict"
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

	injectedScope := scheduler.Scope{WorkspaceID: "workspace-m6-injected", ProjectID: "project-m6"}
	seedM6Result(t, ctx, pool, injectedScope, "-injected", now)
	injected, _ := schedulerpg.New(pool, register, func(point schedulerpg.FailurePoint) error {
		if point == schedulerpg.AfterPromotion {
			return errors.New("injected transaction failure")
		}
		return nil
	})
	injectedResult := scheduler.Result{TaskID: "task-m6-injected", RecoveryEpoch: 2, ExecutionGeneration: 3, PhysicalAttemptID: "attempt-m6-injected", LeaseEpoch: 4, FenceToken: "opaque-fence-m6-injected", Capability: "fake.execute", BuildIdentity: "build-m6", ArtifactID: "artifact-m6-injected", ArtifactDigest: digest("b"), PendingObjectKey: "pending/task-m6-injected/r2/g3/attempt-m6-injected/output", CompletedAt: now.Add(time.Second)}
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
		injectedScope.WorkspaceID, injectedScope.ProjectID, "artifact-m6-injected", "task-m6-injected").Scan(&resultCount, &injectedTask, &injectedArtifact, &injectedRun, &injectedReleased); err != nil || resultCount != 0 || injectedTask != "leased" || injectedArtifact != "pending" || injectedRun != "executing" || injectedReleased {
		t.Fatalf("rollback result=%d task=%s artifact=%s run=%s released=%v err=%v", resultCount, injectedTask, injectedArtifact, injectedRun, injectedReleased, err)
	}

	queueStore, _ := queuepg.New(pool)
	message := queue.Message{ID: "message-m6", WorkspaceID: scope.WorkspaceID, ProjectID: scope.ProjectID, Topic: "agent-tasks", Payload: []byte(`{"runId":"run-m6"}`), Attempts: 1}
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
}

func seedM6Result(t *testing.T, ctx context.Context, pool *pgxpool.Pool, scope scheduler.Scope, suffix string, now time.Time) {
	t.Helper()
	digest := func(c string) string { return "sha256:" + strings.Repeat(c, 64) }
	runID, rootRunID := "run-m6"+suffix, "root-m6"+suffix
	reservationID, artifactID := "reservation-m6"+suffix, "artifact-m6"+suffix
	taskID, attemptID := "task-m6"+suffix, "attempt-m6"+suffix
	statements := []struct {
		query string
		args  []any
	}{
		{`INSERT INTO agent_control.agent_runs(workspace_id,project_id,run_id,state,version,execution_generation,snapshot) VALUES($1,$2,$3,'executing',1,1,'{}')`, []any{scope.WorkspaceID, scope.ProjectID, runID}},
		{`INSERT INTO agent_control.budget_reservations(workspace_id,project_id,root_run_id,run_id,reservation_id,controller_generation,policy_version,budget_version,upper_bound_micros,attempt_final,expires_at) VALUES($1,$2,$3,$4,$5,1,'policy','budget',100,true,$6)`, []any{scope.WorkspaceID, scope.ProjectID, rootRunID, runID, reservationID, now.Add(time.Minute)}},
		{`INSERT INTO agent_artifacts.metadata(workspace_id,project_id,artifact_id,run_id,digest,actual_digest,state,security_generation,lineage,object_reference,schema_identity) VALUES($1,$2,$3,$4,$5,$5,'pending',1,'{}','{}','{}')`, []any{scope.WorkspaceID, scope.ProjectID, artifactID, runID, digest("b")}},
		{`INSERT INTO agent_workflow.agent_tasks(workspace_id,project_id,task_id,run_id,root_run_id,recovery_epoch,execution_generation,capability,capability_version,reservation_id,input_digest,input_object_key,state,lease_epoch,physical_attempts,created_at) VALUES($1,$2,$3,$4,$5,2,3,'fake.execute','fake.execute/v1',$6,$7,'inputs/task','leased',4,1,$8)`, []any{scope.WorkspaceID, scope.ProjectID, taskID, runID, rootRunID, reservationID, digest("a"), now}},
		{`INSERT INTO agent_workflow.worker_attempts(workspace_id,project_id,task_id,physical_attempt_id,recovery_epoch,execution_generation,attempt_number,lease_epoch,owner,issued_at,expires_at,fence_token,state) VALUES($1,$2,$3,$4,2,3,1,4,'worker',$5,$6,$7,'active')`, []any{scope.WorkspaceID, scope.ProjectID, taskID, attemptID, now, now.Add(time.Minute), m6Fence(suffix)}},
	}
	for _, statement := range statements {
		if _, err := pool.Exec(ctx, statement.query, statement.args...); err != nil {
			t.Fatal(err)
		}
	}
}

func m6Fence(suffix string) string {
	if suffix == "" {
		return "opaque-fence-m6-0001"
	}
	return "opaque-fence-m6" + suffix
}

type m4IDs struct{}

func (m4IDs) InvocationID() string { return "invocation-m4" }
func (m4IDs) AttemptID(attempt int) modelgateway.AttemptID {
	return modelgateway.AttemptID(fmt.Sprintf("attempt-%d", attempt))
}

type m4Sleeper struct{}

func (m4Sleeper) Sleep(context.Context, time.Duration) error { return nil }

type m4Keys struct{ value []byte }

func (keys m4Keys) Key(context.Context, string) ([]byte, error) {
	return append([]byte(nil), keys.value...), nil
}

func assertM4Evidence(t *testing.T, ctx context.Context, pool *pgxpool.Pool) {
	t.Helper()
	snapshot := modelgateway.Snapshot{Version: "v1", Providers: []modelgateway.Provider{{ID: modelgateway.FakeProviderID, ModelVersion: "fake-v1", Regions: []string{"test"}, DataClasses: []modelgateway.DataClass{modelgateway.Internal}, Capabilities: []string{"plan"}, SafetyLevel: 3, MaximumCostMicros: 600, Priority: 1, Enabled: true}}}
	registry, err := modelgateway.NewRegistry(snapshot)
	if err != nil {
		t.Fatal(err)
	}
	snapshotStore, _ := modelpg.NewSnapshotStore(pool)
	if err := snapshotStore.Put(ctx, "workspace-m4", "project-m4", registry.Current()); err != nil {
		t.Fatal(err)
	}
	recorder, _ := modelpg.NewInvocationRecorder(pool)
	gateway, err := modelgateway.NewGateway(map[modelgateway.ProviderID]modelgateway.Adapter{modelgateway.FakeProviderID: modelgateway.FakeAdapter{}}, recorder, m4IDs{}, testClock{time.Unix(400, 0)}, m4Sleeper{})
	if err != nil {
		t.Fatal(err)
	}
	policy := modelgateway.Policy{Version: "policy-v1", AllowedProviders: []modelgateway.ProviderID{modelgateway.FakeProviderID}, AllowedRegions: []string{"test"}, DataClasses: []modelgateway.DataClass{modelgateway.Internal}, Capability: "plan", MinimumSafety: 2, MaximumCostMicros: 1000}
	_, record, err := gateway.InvokeEligible(ctx, registry, policy, modelgateway.InvokeRequest{RunID: "run-m4", WorkspaceID: "workspace-m4", ProjectID: "project-m4", Context: []byte("minimal"), DataClasses: []modelgateway.DataClass{modelgateway.Internal}, MaximumOutputBytes: 4096, MaximumInputTokens: 256, MaximumOutputTokens: 2000, MaximumCostMicros: 1000, Timeout: time.Second, MaximumAttempts: 1, Scenario: "valid"})
	if err != nil || len(record.PhysicalAttempts) != 1 {
		t.Fatalf("durable invocation=%#v err=%v", record, err)
	}
	var attempts []byte
	if err := pool.QueryRow(ctx, `SELECT physical_attempt_ids FROM agent_workflow.provider_invocations WHERE workspace_id='workspace-m4' AND project_id='project-m4' AND invocation_id='invocation-m4'`).Scan(&attempts); err != nil || !bytes.Contains(attempts, []byte("attempt-1")) {
		t.Fatalf("physical attempt was not durable before disclosure: %s %v", attempts, err)
	}
	if _, err := pool.Exec(ctx, `UPDATE agent_workflow.provider_invocations SET provider='mutated' WHERE workspace_id='workspace-m4' AND project_id='project-m4' AND invocation_id='invocation-m4'`); err == nil {
		t.Fatal("durable invocation identity was mutable")
	}

	continuationStore, _ := modelpg.NewContinuationStore(pool, "workspace-m4", "project-m4")
	continuations, _ := modelgateway.NewContinuations(m4Keys{bytes.Repeat([]byte{4}, 32)}, "kms://m4", continuationStore, testClock{time.Unix(400, 0)})
	secret := []byte("provider-continuation-secret")
	binding := "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	if err := continuations.Save(ctx, "continuation-m4", modelgateway.FakeProviderID, secret, binding, time.Unix(500, 0), modelgateway.RestartStage); err != nil {
		t.Fatal(err)
	}
	var encrypted string
	if err := pool.QueryRow(ctx, `SELECT encrypted_binding FROM agent_workflow.provider_continuations WHERE workspace_id='workspace-m4' AND project_id='project-m4' AND continuation_id='continuation-m4'`).Scan(&encrypted); err != nil || bytes.Contains([]byte(encrypted), secret) {
		t.Fatalf("continuation plaintext persisted: %v", err)
	}

	contextRecorder, _ := contextpg.New(pool)
	contextPolicy := contextcompiler.PolicyReference{PolicyID: "policy", Version: "v1", Digest: binding}
	compiler := contextcompiler.New([]string{"registered-secret"})
	compiled, err := compiler.CompileAndRecord(ctx, contextcompiler.Request{TenantID: "tenant", WorkspaceID: "workspace-m4", ProjectID: "project-m4", RunID: "run-m4", Policy: contextPolicy, RedactionPolicy: contextPolicy, TotalTokens: 8, CompiledAt: time.Unix(400, 0), Sources: []contextcompiler.Source{{ID: "system", Trust: contextcompiler.System, Classification: contextcompiler.Internal, Content: "policy", TenantID: "tenant", TokenBudget: 2}, {ID: "user", Trust: contextcompiler.User, Classification: contextcompiler.Internal, Content: "registered-secret", TenantID: "tenant", TokenBudget: 4}}}, contextRecorder)
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
	if err := profileStore.Prepare(ctx, "workspace-m4", "project-m4", "run-m4", profile); err != nil {
		t.Fatal(err)
	}
	pinnedProfile, err := profileStore.Get(ctx, "workspace-m4", "project-m4", "run-m4")
	if err != nil || pinnedProfile.Digest != profile.Digest {
		t.Fatalf("pinned profile=%#v err=%v", pinnedProfile, err)
	}
	guard, _ := tools.NewGuard(pinnedProfile, toolRecorder, testClock{time.Unix(400, 0)}, tools.JSONArgumentValidator{})
	intent := tools.Intent{RunID: "run-m4", WorkspaceID: "workspace-m4", ProjectID: "project-m4", ActorID: "actor", AllowedTools: []string{"fake.execute"}, AllowedEffects: []string{"none"}, MaximumRisk: "low", DataClasses: []string{"internal"}}
	current := tools.CurrentAuthority{WorkspaceActive: true, ActorActive: true, PermissionActive: true, PolicyActive: true, AllowedTools: intent.AllowedTools, AllowedEffects: intent.AllowedEffects, MaximumRisk: "low", DataClasses: intent.DataClasses}
	if decision, err := guard.Evaluate(ctx, intent, current, tools.Proposal{ToolID: "admin.delete", Arguments: json.RawMessage(`{}`), UntrustedText: "do not persist me"}); err == nil || decision.Allowed {
		t.Fatal("forbidden durable tool proposal was accepted")
	}
	var decisions int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM agent_evaluation.tool_decisions WHERE workspace_id='workspace-m4' AND project_id='project-m4' AND run_id='run-m4' AND allowed=false`).Scan(&decisions); err != nil || decisions != 1 {
		t.Fatalf("forbidden decision evidence=%d err=%v", decisions, err)
	}
}

func assertM3Interrupts(t *testing.T, ctx context.Context, pool *pgxpool.Pool) {
	t.Helper()
	idempotencyStore, err := idempotency.New(pool, idempotency.Config{Retention: 48 * time.Hour, MinimumLifetime: 24 * time.Hour})
	if err != nil {
		t.Fatal(err)
	}
	runStore := runpg.New(pool, idempotencyStore)
	runService := runs.NewService(runStore, noOpStarter{}, runID("m3-run"), testClock{time.Unix(300, 0)})
	raw := []byte(`{"domain":"platform-agent","operation":"artifact-validation","target":{"targetType":"page","targetId":"page-m3"}}`)
	digest, _ := canonical.Digest(raw)
	scope := runs.Scope{TenantID: "tenant", WorkspaceID: "workspace-m3", ProjectID: "project-m3", ActorID: "actor"}
	trace := "00-0123456789abcdef0123456789abcdef-0123456789abcdef-01"
	created, err := runService.Create(ctx, runs.CreateInput{Scope: scope, Key: "create", ClaimedDigest: digest, Traceparent: trace, Raw: raw, Authority: m2Authority()})
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
	var eventCount, checkpointCount int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM agent_events.agent_events WHERE workspace_id=$1 AND project_id=$2 AND run_id=$3`, scope.WorkspaceID, scope.ProjectID, current.RunID).Scan(&eventCount); err != nil {
		t.Fatal(err)
	}
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM agent_workflow.checkpoints WHERE workspace_id=$1 AND project_id=$2 AND workflow_id=$3`, scope.WorkspaceID, scope.ProjectID, string(current.RunID)+":v1").Scan(&checkpointCount); err != nil {
		t.Fatal(err)
	}
	if eventCount != 5 || checkpointCount != 5 {
		t.Fatalf("atomic M3 evidence events=%d checkpoints=%d", eventCount, checkpointCount)
	}
}

func assertM2CreateLatency(t *testing.T, ctx context.Context, pool *pgxpool.Pool) {
	t.Helper()
	const requests = 500
	const arrivalInterval = 50 * time.Millisecond // pinned 20 accepted requests/second
	idempotencyStore, err := idempotency.New(pool, idempotency.Config{Retention: 48 * time.Hour, MinimumLifetime: 24 * time.Hour})
	if err != nil {
		t.Fatal(err)
	}
	service := runs.NewService(runpg.New(pool, idempotencyStore), noOpStarter{}, &sequentialRunIDs{}, testClock{time.Now().UTC()})
	scope := runs.Scope{TenantID: "tenant", WorkspaceID: "workspace-m2-load", ProjectID: "project-m2-load", ActorID: "actor"}
	authority := m2Authority()
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
			_, createErr := service.Create(ctx, runs.CreateInput{Scope: scope, Key: fmt.Sprintf("m2-load-%06d", index), ClaimedDigest: digest, Traceparent: "00-0123456789abcdef0123456789abcdef-0123456789abcdef-01", Raw: raw, Authority: authority})
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
	t.Logf("M2 durable create pinned load: requests=%d arrival_rate=20/s p95=%s", requests, p95)
	if p95 >= 300*time.Millisecond {
		t.Fatalf("durable create P95 %s exceeds 300ms", p95)
	}
}

type noOpStarter struct{}

func (noOpStarter) Ensure(context.Context, runs.Start) error { return nil }

type sequentialRunIDs struct{ next atomic.Uint64 }

func (ids *sequentialRunIDs) NewID() (runs.ID, error) {
	return runs.ID(fmt.Sprintf("m2-load-run-%06d", ids.next.Add(1))), nil
}

func assertM2RunCore(t *testing.T, ctx context.Context, pool *pgxpool.Pool) {
	t.Helper()
	idempotencyStore, err := idempotency.New(pool, idempotency.Config{Retention: 48 * time.Hour, MinimumLifetime: 24 * time.Hour})
	if err != nil {
		t.Fatal(err)
	}
	store := runpg.New(pool, idempotencyStore)
	starter := &durableStarter{store: store, started: make(map[string]bool)}
	service := runs.NewService(store, starter, runID("m2-run"), testClock{time.Unix(200, 0)})
	raw := []byte(`{"domain":"platform-agent","operation":"artifact-validation","target":{"targetType":"page","targetId":"page-m2"}}`)
	digest, _ := canonical.Digest(raw)
	scope := runs.Scope{TenantID: "tenant", WorkspaceID: "workspace-m2", ProjectID: "project-m2", ActorID: "actor"}
	input := runs.CreateInput{Scope: scope, Key: "m2-key", ClaimedDigest: digest, Traceparent: "00-0123456789abcdef0123456789abcdef-0123456789abcdef-01", Raw: raw, Authority: m2Authority()}
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
	missing, err := service.Get(ctx, runs.Scope{TenantID: "tenant", WorkspaceID: "other", ProjectID: "project-m2", ActorID: "actor"}, "m2-run")
	_ = missing
	assertProblemCode(t, err, problem.CodeResourceNotFound)
	_, err = service.Get(ctx, scope, "absent")
	assertProblemCode(t, err, problem.CodeResourceNotFound)
	page, err := service.List(ctx, scope, runs.ListOptions{Limit: 1})
	if err != nil || len(page.Items) != 1 {
		t.Fatalf("page=%#v err=%v", page, err)
	}
	different := []byte(`{"domain":"platform-agent","operation":"image-operation","target":{"targetType":"page","targetId":"page-m2"}}`)
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
			_, transitionErr := service.Transition(ctx, scope, "m2-run", 1, runs.Command{Kind: runs.BeginPreparation, Traceparent: input.Traceparent})
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
	current, err := service.Get(ctx, scope, "m2-run")
	if err != nil || current.Version != 2 || current.Status != runs.Preparing {
		t.Fatalf("current=%#v err=%v", current, err)
	}
	reader := eventpg.NewReader(pool)
	eventScope := events.Scope{WorkspaceID: scope.WorkspaceID, ProjectID: scope.ProjectID}
	allEvents, err := reader.Replay(ctx, events.ReplayRequest{Scope: eventScope, RunID: "m2-run", Limit: 100})
	if err != nil || len(allEvents.Events) != 2 {
		t.Fatalf("full replay=%#v err=%v", allEvents, err)
	}
	replay, err := reader.Replay(ctx, events.ReplayRequest{Scope: eventScope, RunID: "m2-run", AfterEventID: "m2-run:1", Limit: 100})
	if err != nil || len(replay.Events) != 1 || replay.Events[0].Sequence != 2 {
		t.Fatalf("strictly-after replay=%#v err=%v", replay, err)
	}
	guard, err := contractguard.NewGuard("../..")
	if err != nil {
		t.Fatal(err)
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
	projection, err := reader.Snapshot(ctx, eventScope, "m2-run")
	if err != nil || projection.Cursor != "m2-run:2" || len(projection.Run) == 0 {
		t.Fatalf("snapshot=%#v err=%v", projection, err)
	}
	if findings := guard.Validate(ctx, contractguard.APIIn, "anvilkit://schema/agent-run.v1@1.0.0?digest=sha256:68949242c9b4557a8b5ff965f76de8f2de49c11523a7cc1e64cfd1b4af824233", projection.Run); len(findings) != 0 {
		t.Fatalf("snapshot run is not contract-valid: %#v raw=%s", findings, projection.Run)
	}
	afterSnapshot, err := reader.Replay(ctx, events.ReplayRequest{Scope: eventScope, RunID: "m2-run", AfterEventID: projection.Cursor, Limit: 100})
	if err != nil || len(afterSnapshot.Events) != 0 {
		t.Fatalf("snapshot resume duplicated or lost: %#v %v", afterSnapshot, err)
	}
	_, err = reader.Replay(ctx, events.ReplayRequest{Scope: eventScope, RunID: "m2-run", AfterEventID: "expired", Limit: 100})
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

func m2Authority() runs.Authority {
	policy := []byte(`{"policyId":"policy.synthetic","version":"v1","digest":"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}`)
	return runs.Authority{
		ContractBOM: []byte(`{"repository":"anvilkit/contracts","bomDigest":"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","ociManifestDigest":"sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","evidenceManifestDigest":"sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"}`),
		Policy:      policy,
		Budget:      []byte(`{"apiVersion":"anvilkit.io/contracts/v1","kind":"AgentBudget","modelLimits":{"maximumCalls":10,"maximumConcurrentCalls":2},"tokenLimits":{"inputTokens":4096,"outputTokens":2048,"totalTokens":6144},"workerLimits":{"maximumAttempts":4,"maximumDurationMilliseconds":60000},"gpuLimits":{"maximumGpuMilliseconds":0},"currencyLimits":{"maximumCost":{"amount":"1000","currency":"USD"},"reservedCost":{"amount":"500","currency":"USD"}},"reservationId":"reservation.synthetic.001","exceedBehavior":"refuse","policy":` + string(policy) + `}`),
	}
}

type runID string

func (id runID) NewID() (runs.ID, error) { return runs.ID(id), nil }

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
	scope := events.Scope{WorkspaceID: "w", ProjectID: "p"}
	change := events.Transition{Scope: scope, RunID: "scoped", ExpectedVersion: 1, NextState: "preparing", Snapshot: []byte(`{"state":"preparing"}`), EventID: "event-1", EventBytes: []byte(`{"id":"event-1"}`), OutboxID: "outbox-1", Topic: "agent.events", OutboxBytes: []byte(`{"id":"event-1"}`), WorkflowID: "scoped:v1", WorkflowVersion: 1, Checkpoint: "preparing", CheckpointBytes: []byte(`{"state":"preparing"}`)}
	for _, point := range []eventpg.FailurePoint{eventpg.AfterRunUpdate, eventpg.AfterEventInsert, eventpg.AfterOutboxInsert, eventpg.AfterCheckpointInsert} {
		repository := eventpg.New(pool, func(actual eventpg.FailurePoint) error {
			if actual == point {
				return errors.New("fault")
			}
			return nil
		})
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
	committed, err := eventpg.New(pool, nil).Commit(ctx, change)
	if err != nil || committed.Version != 2 || committed.Sequence != 1 {
		t.Fatalf("commit=%#v err=%v", committed, err)
	}
	inbox := eventpg.New(pool, nil)
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
	name := "agent_m1_" + hex.EncodeToString(random)
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
