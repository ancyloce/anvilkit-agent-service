CREATE TABLE IF NOT EXISTS agent_workflow.agent_tasks (
 workspace_id text NOT NULL, project_id text NOT NULL, task_id text NOT NULL, run_id text NOT NULL, root_run_id text NOT NULL,
 recovery_epoch bigint NOT NULL CHECK(recovery_epoch>=0), execution_generation bigint NOT NULL CHECK(execution_generation>0),
 capability text NOT NULL, capability_version text NOT NULL, reservation_id text NOT NULL,
 input_digest text NOT NULL CHECK(input_digest ~ '^sha256:[0-9a-f]{64}$'), input_object_key text NOT NULL,
 state text NOT NULL CHECK(state IN('queued','leased','completed','failed','dead-lettered','cancelled')),
 lease_epoch bigint NOT NULL DEFAULT 0 CHECK(lease_epoch>=0), physical_attempts bigint NOT NULL DEFAULT 0 CHECK(physical_attempts>=0),
 version bigint NOT NULL DEFAULT 1 CHECK(version>0), created_at timestamptz NOT NULL, updated_at timestamptz NOT NULL DEFAULT transaction_timestamp(),
 PRIMARY KEY(workspace_id,project_id,task_id),
 FOREIGN KEY(workspace_id,project_id,reservation_id) REFERENCES agent_control.budget_reservations(workspace_id,project_id,reservation_id));
CREATE TABLE IF NOT EXISTS agent_workflow.worker_attempts (
 workspace_id text NOT NULL, project_id text NOT NULL, task_id text NOT NULL, physical_attempt_id text NOT NULL,
 recovery_epoch bigint NOT NULL CHECK(recovery_epoch>=0), execution_generation bigint NOT NULL CHECK(execution_generation>0),
 attempt_number bigint NOT NULL CHECK(attempt_number>0), lease_epoch bigint NOT NULL CHECK(lease_epoch>0), owner text NOT NULL,
 issued_at timestamptz NOT NULL, expires_at timestamptz NOT NULL, fence_token text NOT NULL,
 state text NOT NULL CHECK(state IN('active','expired','superseded','accepted','lost')),
 PRIMARY KEY(workspace_id,project_id,physical_attempt_id), UNIQUE(workspace_id,project_id,task_id,lease_epoch),
 FOREIGN KEY(workspace_id,project_id,task_id) REFERENCES agent_workflow.agent_tasks(workspace_id,project_id,task_id));
CREATE TABLE IF NOT EXISTS agent_workflow.worker_results (
 workspace_id text NOT NULL, project_id text NOT NULL, task_id text NOT NULL, physical_attempt_id text NOT NULL,
 recovery_epoch bigint NOT NULL, execution_generation bigint NOT NULL, lease_epoch bigint NOT NULL, fence_token text NOT NULL,
 capability text NOT NULL, build_identity text NOT NULL, artifact_id text NOT NULL,
 artifact_digest text NOT NULL CHECK(artifact_digest ~ '^sha256:[0-9a-f]{64}$'), pending_object_key text NOT NULL,
 completed_at timestamptz NOT NULL, accepted_at timestamptz NOT NULL DEFAULT transaction_timestamp(),
 PRIMARY KEY(workspace_id,project_id,task_id), UNIQUE(workspace_id,project_id,physical_attempt_id));
CREATE TABLE IF NOT EXISTS agent_workflow.result_diagnostics (
 workspace_id text NOT NULL, project_id text NOT NULL, diagnostic_id bigint GENERATED ALWAYS AS IDENTITY,
 task_id text NOT NULL, run_id text NOT NULL, physical_attempt_id text NOT NULL, code text NOT NULL, reason text NOT NULL, recorded_at timestamptz NOT NULL,
 PRIMARY KEY(workspace_id,project_id,diagnostic_id));
CREATE TABLE IF NOT EXISTS agent_workflow.worker_dlq (
 workspace_id text NOT NULL, project_id text NOT NULL, dlq_id text NOT NULL, task_id text NOT NULL, run_id text NOT NULL,
 code text NOT NULL, failed_stage text NOT NULL, detail text NOT NULL, replayed boolean NOT NULL DEFAULT false, created_at timestamptz NOT NULL,
 PRIMARY KEY(workspace_id,project_id,dlq_id));
CREATE TABLE IF NOT EXISTS agent_events.queue_deliveries (
 workspace_id text NOT NULL, project_id text NOT NULL, message_id text NOT NULL, topic text NOT NULL,
 payload_digest text NOT NULL CHECK(payload_digest ~ '^sha256:[0-9a-f]{64}$'), effect_recorded boolean NOT NULL DEFAULT false,
 dead_lettered boolean NOT NULL DEFAULT false, acknowledged boolean NOT NULL DEFAULT false,
 attempts integer NOT NULL DEFAULT 0 CHECK(attempts>=0), updated_at timestamptz NOT NULL DEFAULT transaction_timestamp(),
 PRIMARY KEY(workspace_id,project_id,message_id));
ALTER TABLE agent_control.usage_observations
 ADD COLUMN IF NOT EXISTS provider_event_id text, ADD COLUMN IF NOT EXISTS meter text NOT NULL DEFAULT 'provider-cost',
 ADD COLUMN IF NOT EXISTS quantity text NOT NULL DEFAULT '0', ADD COLUMN IF NOT EXISTS unit text NOT NULL DEFAULT 'usd-micro',
 ADD COLUMN IF NOT EXISTS currency text NOT NULL DEFAULT 'USD', ADD COLUMN IF NOT EXISTS provider text NOT NULL DEFAULT 'unknown',
 ADD COLUMN IF NOT EXISTS build_identity text NOT NULL DEFAULT 'unknown',
 ADD COLUMN IF NOT EXISTS traceparent text NOT NULL DEFAULT '00-00000000000000000000000000000000-0000000000000000-00',
 ADD COLUMN IF NOT EXISTS repaired boolean NOT NULL DEFAULT false,
 ADD COLUMN IF NOT EXISTS observation_digest text NOT NULL DEFAULT 'sha256:0000000000000000000000000000000000000000000000000000000000000000'
 CHECK(observation_digest ~ '^sha256:[0-9a-f]{64}$');
CREATE UNIQUE INDEX IF NOT EXISTS usage_provider_event_dedup_idx ON agent_control.usage_observations(workspace_id,project_id,provider,provider_event_id) WHERE provider_event_id IS NOT NULL;
CREATE UNIQUE INDEX IF NOT EXISTS usage_attempt_meter_sequence_idx ON agent_control.usage_observations(workspace_id,project_id,task_id,recovery_epoch,execution_generation,physical_attempt_id,meter,meter_sequence) WHERE provider_event_id IS NULL;
CREATE INDEX IF NOT EXISTS tasks_reclaim_idx ON agent_workflow.worker_attempts(expires_at) WHERE state='active';
CREATE INDEX IF NOT EXISTS tasks_queue_idx ON agent_workflow.agent_tasks(workspace_id,project_id,state,created_at);
CREATE UNIQUE INDEX IF NOT EXISTS tasks_active_attempt_idx ON agent_workflow.worker_attempts(workspace_id,project_id,task_id) WHERE state='active';
CREATE OR REPLACE FUNCTION agent_workflow.guard_worker_result_immutable() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'worker result is immutable'; END $$;
DROP TRIGGER IF EXISTS worker_result_immutable ON agent_workflow.worker_results;
CREATE TRIGGER worker_result_immutable BEFORE UPDATE OR DELETE ON agent_workflow.worker_results FOR EACH ROW EXECUTE FUNCTION agent_workflow.guard_worker_result_immutable();
GRANT SELECT,INSERT,UPDATE ON agent_workflow.agent_tasks,agent_workflow.worker_attempts TO agent_workflow_rw,agent_authority_rw;
GRANT SELECT,INSERT ON agent_workflow.worker_results,agent_workflow.result_diagnostics,agent_workflow.worker_dlq TO agent_workflow_rw,agent_authority_rw;
GRANT UPDATE ON agent_workflow.worker_dlq TO agent_workflow_rw,agent_authority_rw;
GRANT USAGE,SELECT ON SEQUENCE agent_workflow.result_diagnostics_diagnostic_id_seq TO agent_workflow_rw,agent_authority_rw;
GRANT SELECT,INSERT,UPDATE ON agent_events.queue_deliveries TO agent_events_rw,agent_authority_rw;
