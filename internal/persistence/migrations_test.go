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
		t.Fatal("Phase 0 memory schema must have no tables")
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
	m3, err := migrationFiles.ReadFile("migrations/0003_m3_interrupts.up.sql")
	if err != nil {
		t.Fatal(err)
	}
	for _, table := range []string{"input_requests", "approval_requests", "lifecycle_controls", "run_children", "run_progress"} {
		if !strings.Contains(string(m3), "CREATE TABLE IF NOT EXISTS agent_control."+table) {
			t.Fatalf("M3 migration missing %s", table)
		}
	}
	m4, err := migrationFiles.ReadFile("migrations/0004_m4_model_gateway.up.sql")
	if err != nil {
		t.Fatal(err)
	}
	for _, table := range []string{"provider_registry_snapshots", "provider_invocations", "provider_continuations", "run_tool_profiles", "context_evidence", "tool_decisions"} {
		if !strings.Contains(string(m4), table+" (") {
			t.Fatalf("M4 migration missing %s", table)
		}
	}
	if strings.Contains(string(m4), "plaintext") || !strings.Contains(string(m4), "encrypted_binding") {
		t.Fatal("M4 continuation storage must be encrypted-only")
	}
	m5, err := migrationFiles.ReadFile("migrations/0005_m5_commit_boundaries.up.sql")
	if err != nil {
		t.Fatal(err)
	}
	for _, table := range []string{"budget_reservations", "usage_observations", "validation_evidence", "access_grants", "apply_authorizations", "domain_operations"} {
		if !strings.Contains(string(m5), table+" (") {
			t.Fatalf("M5 migration missing %s", table)
		}
	}
	if !strings.Contains(string(m5), "domain_operations_active_run_idx") || !strings.Contains(string(m5), "authorization consumption is irreversible") {
		t.Fatal("M5 durable commit fences are missing")
	}
	m6, err := migrationFiles.ReadFile("migrations/0006_m6_scheduler_usage_queue.up.sql")
	if err != nil {
		t.Fatal(err)
	}
	for _, table := range []string{"agent_tasks", "worker_attempts", "worker_results", "result_diagnostics", "worker_dlq", "queue_deliveries"} {
		if !strings.Contains(string(m6), table+" (") {
			t.Fatalf("M6 migration missing %s", table)
		}
	}
	for _, fence := range []string{"recovery_epoch", "execution_generation", "physical_attempt_id", "lease_epoch", "fence_token", "tasks_active_attempt_idx", "usage_provider_event_dedup_idx", "usage_attempt_meter_sequence_idx", "observation_digest", "dead_lettered"} {
		if !strings.Contains(string(m6), fence) {
			t.Fatalf("M6 durable fence missing %s", fence)
		}
	}
	m7, err := migrationFiles.ReadFile("migrations/0007_m7_recovery_state.up.sql")
	if err != nil {
		t.Fatal(err)
	}
	for _, table := range []string{"recovery_state", "restore_drills", "restore_stages"} {
		if !strings.Contains(string(m7), table+" (") {
			t.Fatalf("M7 migration missing %s", table)
		}
	}
	if strings.Contains(string(m7), "recovery_register") || !strings.Contains(string(m7), "external non-rollback register is intentionally absent") {
		t.Fatal("M7 schema must not store the external recovery register")
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
