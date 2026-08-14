package persistence

import (
	"strings"
	"testing"
)

func TestFoundationScopesEveryServiceTableAndKeepsMemoryEmpty(t *testing.T) {
	body, err := migrationFiles.ReadFile("migrations/0001_foundation.up.sql")
	if err != nil {
		t.Fatal(err)
	}
	sql := string(body)
	if !strings.Contains(sql, "CREATE SCHEMA IF NOT EXISTS agent_memory") {
		t.Fatal("memory schema missing")
	}
	if strings.Contains(sql, "CREATE TABLE IF NOT EXISTS agent_memory") {
		t.Fatal("foundation memory schema must have no tables")
	}
	for _, table := range []string{"agent_runs", "write_idempotency", "agent_events", "outbox", "inbox", "checkpoints", "executor_leases", "metadata", "records"} {
		start := strings.Index(sql, "CREATE TABLE IF NOT EXISTS ")
		_ = start
		needle := table + " ("
		position := strings.Index(sql, needle)
		if position < 0 {
			t.Fatalf("table %s missing", table)
		}
		end := strings.Index(sql[position:], ");")
		definition := sql[position : position+end]
		if !strings.Contains(definition, "workspace_id text NOT NULL") || !strings.Contains(definition, "project_id text NOT NULL") {
			t.Fatalf("table %s lacks mandatory scope", table)
		}
	}
	control, err := migrationFiles.ReadFile("migrations/0003_interrupts.up.sql")
	if err != nil {
		t.Fatal(err)
	}
	for _, table := range []string{"input_requests", "approval_requests", "lifecycle_controls", "run_children", "run_progress", "run_alerts"} {
		if !strings.Contains(string(control), "CREATE TABLE IF NOT EXISTS agent_control."+table) {
			t.Fatalf("interrupt migration missing %s", table)
		}
	}
	model, err := migrationFiles.ReadFile("migrations/0004_model_gateway.up.sql")
	if err != nil {
		t.Fatal(err)
	}
	for _, table := range []string{"provider_registry_snapshots", "provider_policy_snapshots", "provider_invocations", "provider_continuations", "run_tool_profiles", "context_evidence", "tool_decisions"} {
		if !strings.Contains(string(model), table+" (") {
			t.Fatalf("model gateway migration missing %s", table)
		}
	}
	if strings.Contains(string(model), "plaintext") || !strings.Contains(string(model), "encrypted_binding") || !strings.Contains(string(model), "key_reference") || !strings.Contains(string(model), "policy_digest") || !strings.Contains(string(model), "policy_snapshot") {
		t.Fatal("model continuation storage must be encrypted-only")
	}
	commit, err := migrationFiles.ReadFile("migrations/0005_commit_boundaries.up.sql")
	if err != nil {
		t.Fatal(err)
	}
	for _, table := range []string{"budget_reservations", "usage_observations", "validation_evidence", "access_grants", "apply_authorizations", "domain_operations"} {
		if !strings.Contains(string(commit), table+" (") {
			t.Fatalf("commit boundary migration missing %s", table)
		}
	}
	for _, fence := range []string{"domain_operations_active_run_idx", "authorization consumption is irreversible", "domain operation status transition is invalid", "budget reservation identity is immutable", "artifact lifecycle transition is invalid", "idempotency_key", "request_digest"} {
		if !strings.Contains(string(commit), fence) {
			t.Fatalf("commit boundary durable fence missing %s", fence)
		}
	}
	if !strings.Contains(string(commit), "GRANT SELECT, INSERT, DELETE ON agent_artifacts.access_grants") {
		t.Fatal("durable commit fences are missing")
	}
	scheduler, err := migrationFiles.ReadFile("migrations/0006_scheduler_usage_queue.up.sql")
	if err != nil {
		t.Fatal(err)
	}
	for _, table := range []string{"agent_tasks", "worker_attempts", "worker_results", "result_diagnostics", "worker_dlq", "queue_deliveries"} {
		if !strings.Contains(string(scheduler), table+" (") {
			t.Fatalf("scheduler and usage migration missing %s", table)
		}
	}
	for _, fence := range []string{"recovery_epoch", "execution_generation", "physical_attempt_id", "lease_epoch", "fence_token", "tasks_active_attempt_idx", "usage_provider_event_dedup_idx", "usage_attempt_meter_sequence_idx", "observation_digest", "dead_lettered"} {
		if !strings.Contains(string(scheduler), fence) {
			t.Fatalf("scheduler durable fence missing %s", fence)
		}
	}
	recovery, err := migrationFiles.ReadFile("migrations/0007_recovery_state.up.sql")
	if err != nil {
		t.Fatal(err)
	}
	for _, table := range []string{"recovery_state", "restore_drills", "restore_stages"} {
		if !strings.Contains(string(recovery), table+" (") {
			t.Fatalf("recovery migration missing %s", table)
		}
	}
	if strings.Contains(string(recovery), "recovery_register") || !strings.Contains(string(recovery), "external non-rollback register is intentionally absent") {
		t.Fatal("recovery schema must not store the external recovery register")
	}
}

func TestSeparateLeastPrivilegeRolesAreDeclared(t *testing.T) {
	body, err := migrationFiles.ReadFile("migrations/0001_foundation.up.sql")
	if err != nil {
		t.Fatal(err)
	}
	sql := string(body)
	for _, role := range []string{"agent_control_rw", "agent_events_rw", "agent_workflow_rw", "agent_artifacts_rw", "agent_evaluation_rw", "agent_authority_rw"} {
		if !strings.Contains(sql, "CREATE ROLE "+role+" NOLOGIN") {
			t.Fatalf("role %s missing", role)
		}
	}
}
