CREATE SCHEMA IF NOT EXISTS agent_control;
CREATE SCHEMA IF NOT EXISTS agent_events;
CREATE SCHEMA IF NOT EXISTS agent_workflow;
CREATE SCHEMA IF NOT EXISTS agent_artifacts;
CREATE SCHEMA IF NOT EXISTS agent_memory;
CREATE SCHEMA IF NOT EXISTS agent_evaluation;

DO $$ BEGIN CREATE ROLE agent_control_rw NOLOGIN; EXCEPTION WHEN duplicate_object THEN NULL; END $$;
DO $$ BEGIN CREATE ROLE agent_events_rw NOLOGIN; EXCEPTION WHEN duplicate_object THEN NULL; END $$;
DO $$ BEGIN CREATE ROLE agent_workflow_rw NOLOGIN; EXCEPTION WHEN duplicate_object THEN NULL; END $$;
DO $$ BEGIN CREATE ROLE agent_artifacts_rw NOLOGIN; EXCEPTION WHEN duplicate_object THEN NULL; END $$;
DO $$ BEGIN CREATE ROLE agent_evaluation_rw NOLOGIN; EXCEPTION WHEN duplicate_object THEN NULL; END $$;
DO $$ BEGIN CREATE ROLE agent_authority_rw NOLOGIN; EXCEPTION WHEN duplicate_object THEN NULL; END $$;

CREATE TABLE IF NOT EXISTS agent_control.agent_runs (
    workspace_id text NOT NULL,
    project_id text NOT NULL,
    run_id text NOT NULL,
    state text NOT NULL,
    version bigint NOT NULL CHECK (version > 0),
    execution_generation bigint NOT NULL DEFAULT 1 CHECK (execution_generation > 0),
    next_event_sequence bigint NOT NULL DEFAULT 1 CHECK (next_event_sequence > 0),
    snapshot jsonb NOT NULL,
    created_at timestamptz NOT NULL DEFAULT transaction_timestamp(),
    updated_at timestamptz NOT NULL DEFAULT transaction_timestamp(),
    PRIMARY KEY (workspace_id, project_id, run_id)
);

CREATE TABLE IF NOT EXISTS agent_control.write_idempotency (
    workspace_id text NOT NULL,
    project_id text NOT NULL,
    operation text NOT NULL,
    idempotency_key text NOT NULL,
    request_digest bytea NOT NULL,
    version_bound bigint NOT NULL CHECK (version_bound >= 0),
    response_status integer NOT NULL,
    response_content_type text NOT NULL,
    response_body bytea NOT NULL,
    expires_at timestamptz NOT NULL,
    created_at timestamptz NOT NULL DEFAULT transaction_timestamp(),
    PRIMARY KEY (workspace_id, project_id, operation, idempotency_key)
);

CREATE TABLE IF NOT EXISTS agent_events.agent_events (
    workspace_id text NOT NULL,
    project_id text NOT NULL,
    run_id text NOT NULL,
    sequence bigint NOT NULL CHECK (sequence > 0),
    event_id text NOT NULL,
    event_bytes bytea NOT NULL,
    created_at timestamptz NOT NULL DEFAULT transaction_timestamp(),
    PRIMARY KEY (workspace_id, project_id, run_id, sequence),
    UNIQUE (workspace_id, project_id, event_id)
);

CREATE TABLE IF NOT EXISTS agent_events.outbox (
    workspace_id text NOT NULL,
    project_id text NOT NULL,
    outbox_id text NOT NULL,
    run_id text NOT NULL,
    event_sequence bigint NOT NULL,
    topic text NOT NULL,
    payload bytea NOT NULL,
    available_at timestamptz NOT NULL DEFAULT transaction_timestamp(),
    published_at timestamptz,
    attempts integer NOT NULL DEFAULT 0,
    PRIMARY KEY (workspace_id, project_id, outbox_id),
    UNIQUE (workspace_id, project_id, run_id, event_sequence)
);

CREATE TABLE IF NOT EXISTS agent_events.inbox (
    workspace_id text NOT NULL,
    project_id text NOT NULL,
    consumer text NOT NULL,
    message_id text NOT NULL,
    payload_digest bytea NOT NULL,
    received_at timestamptz NOT NULL DEFAULT transaction_timestamp(),
    PRIMARY KEY (workspace_id, project_id, consumer, message_id)
);

CREATE TABLE IF NOT EXISTS agent_workflow.checkpoints (
    workspace_id text NOT NULL,
    project_id text NOT NULL,
    workflow_id text NOT NULL,
    workflow_version integer NOT NULL,
    step_name text NOT NULL,
    state_bytes bytea NOT NULL,
    problem_bytes bytea,
    updated_at timestamptz NOT NULL DEFAULT transaction_timestamp(),
    PRIMARY KEY (workspace_id, project_id, workflow_id, workflow_version, step_name)
);

CREATE TABLE IF NOT EXISTS agent_workflow.executor_leases (
    workspace_id text NOT NULL,
    project_id text NOT NULL,
    workflow_id text NOT NULL,
    executor_id text NOT NULL,
    lease_epoch bigint NOT NULL CHECK (lease_epoch > 0),
    expires_at timestamptz NOT NULL,
    PRIMARY KEY (workspace_id, project_id, workflow_id)
);

CREATE TABLE IF NOT EXISTS agent_artifacts.metadata (
    workspace_id text NOT NULL,
    project_id text NOT NULL,
    artifact_id text NOT NULL,
    run_id text NOT NULL,
    digest text NOT NULL,
    state text NOT NULL,
    security_generation bigint NOT NULL DEFAULT 1 CHECK (security_generation > 0),
    lineage jsonb NOT NULL,
    created_at timestamptz NOT NULL DEFAULT transaction_timestamp(),
    updated_at timestamptz NOT NULL DEFAULT transaction_timestamp(),
    PRIMARY KEY (workspace_id, project_id, artifact_id)
);

CREATE TABLE IF NOT EXISTS agent_evaluation.records (
    workspace_id text NOT NULL,
    project_id text NOT NULL,
    evaluation_id text NOT NULL,
    run_id text NOT NULL,
    evidence jsonb NOT NULL,
    created_at timestamptz NOT NULL DEFAULT transaction_timestamp(),
    PRIMARY KEY (workspace_id, project_id, evaluation_id)
);

REVOKE ALL ON SCHEMA agent_control, agent_events, agent_workflow, agent_artifacts, agent_memory, agent_evaluation FROM PUBLIC;
GRANT USAGE ON SCHEMA agent_control TO agent_control_rw;
GRANT USAGE ON SCHEMA agent_events TO agent_events_rw;
GRANT USAGE ON SCHEMA agent_workflow TO agent_workflow_rw;
GRANT USAGE ON SCHEMA agent_artifacts TO agent_artifacts_rw;
GRANT USAGE ON SCHEMA agent_evaluation TO agent_evaluation_rw;
GRANT USAGE ON SCHEMA agent_control, agent_events, agent_workflow, agent_artifacts TO agent_authority_rw;
GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA agent_control TO agent_control_rw;
GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA agent_events TO agent_events_rw;
GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA agent_workflow TO agent_workflow_rw;
GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA agent_artifacts TO agent_artifacts_rw;
GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA agent_evaluation TO agent_evaluation_rw;
GRANT SELECT, INSERT, UPDATE ON agent_control.agent_runs, agent_control.write_idempotency TO agent_authority_rw;
GRANT SELECT, INSERT, UPDATE ON agent_events.agent_events, agent_events.outbox, agent_events.inbox TO agent_authority_rw;
GRANT SELECT, INSERT, UPDATE ON agent_workflow.checkpoints TO agent_authority_rw;
GRANT SELECT ON agent_artifacts.metadata TO agent_authority_rw;
