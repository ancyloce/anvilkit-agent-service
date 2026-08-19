CREATE TABLE IF NOT EXISTS agent_control.provider_registry_snapshots (
    workspace_id text NOT NULL,
    project_id text NOT NULL,
    snapshot_digest text NOT NULL CHECK (snapshot_digest ~ '^sha256:[0-9a-f]{64}$'),
    snapshot_version text NOT NULL,
    snapshot jsonb NOT NULL,
    created_at timestamptz NOT NULL DEFAULT transaction_timestamp(),
    PRIMARY KEY (workspace_id, project_id, snapshot_digest),
    UNIQUE (workspace_id, project_id, snapshot_version)
);

CREATE TABLE IF NOT EXISTS agent_control.provider_policy_snapshots (
    workspace_id text NOT NULL,
    project_id text NOT NULL,
    policy_version text NOT NULL,
    policy_digest text NOT NULL CHECK (policy_digest ~ '^sha256:[0-9a-f]{64}$'),
    policy_snapshot jsonb NOT NULL,
    created_at timestamptz NOT NULL DEFAULT transaction_timestamp(),
    PRIMARY KEY (workspace_id, project_id, policy_version),
    UNIQUE (workspace_id, project_id, policy_digest)
);

CREATE TABLE IF NOT EXISTS agent_workflow.provider_invocations (
    workspace_id text NOT NULL,
    project_id text NOT NULL,
    run_id text NOT NULL,
    invocation_id text NOT NULL,
    physical_attempt_ids jsonb NOT NULL DEFAULT '[]'::jsonb,
    registry_snapshot_digest text NOT NULL CHECK (registry_snapshot_digest ~ '^sha256:[0-9a-f]{64}$'),
    policy_version text NOT NULL,
    policy_digest text NOT NULL CHECK (policy_digest ~ '^sha256:[0-9a-f]{64}$'),
    policy_snapshot jsonb NOT NULL,
    provider text NOT NULL,
    model_version text NOT NULL,
    region text NOT NULL,
    disclosed_data_classes jsonb NOT NULL,
    started_at timestamptz NOT NULL,
    completed_at timestamptz,
    input_tokens bigint NOT NULL DEFAULT 0 CHECK (input_tokens >= 0),
    output_tokens bigint NOT NULL DEFAULT 0 CHECK (output_tokens >= 0),
    cost_micros bigint NOT NULL DEFAULT 0 CHECK (cost_micros >= 0),
    output_digest text,
    problem jsonb,
    PRIMARY KEY (workspace_id, project_id, invocation_id)
);

CREATE TABLE IF NOT EXISTS agent_workflow.provider_continuations (
    workspace_id text NOT NULL,
    project_id text NOT NULL,
    continuation_id text NOT NULL,
    kind text NOT NULL CHECK (kind = 'ProviderContinuation'),
    encrypted_binding text NOT NULL,
    key_reference text NOT NULL,
    provider text NOT NULL,
    expires_at timestamptz NOT NULL,
    restart_policy text NOT NULL CHECK (restart_policy IN ('resume-if-valid','restart-stage','restart-run')),
    binding_digest text NOT NULL CHECK (binding_digest ~ '^sha256:[0-9a-f]{64}$'),
    updated_at timestamptz NOT NULL DEFAULT transaction_timestamp(),
    PRIMARY KEY (workspace_id, project_id, continuation_id)
);

CREATE TABLE IF NOT EXISTS agent_workflow.run_tool_profiles (
    workspace_id text NOT NULL,
    project_id text NOT NULL,
    run_id text NOT NULL,
    profile_id text NOT NULL,
    profile_version text NOT NULL,
    profile_digest text NOT NULL CHECK (profile_digest ~ '^sha256:[0-9a-f]{64}$'),
    policy jsonb NOT NULL,
    definitions jsonb NOT NULL CHECK (jsonb_typeof(definitions) = 'array' AND jsonb_array_length(definitions) BETWEEN 3 AND 7),
    prepared_at timestamptz NOT NULL DEFAULT transaction_timestamp(),
    PRIMARY KEY (workspace_id, project_id, run_id)
);

CREATE TABLE IF NOT EXISTS agent_evaluation.context_evidence (
    workspace_id text NOT NULL,
    project_id text NOT NULL,
    run_id text NOT NULL,
    evidence_id text NOT NULL,
    compiled_context jsonb NOT NULL,
    truncations jsonb NOT NULL,
    created_at timestamptz NOT NULL DEFAULT transaction_timestamp(),
    PRIMARY KEY (workspace_id, project_id, evidence_id)
);

CREATE TABLE IF NOT EXISTS agent_evaluation.tool_decisions (
    workspace_id text NOT NULL,
    project_id text NOT NULL,
    run_id text NOT NULL,
    decision_id bigint GENERATED ALWAYS AS IDENTITY,
    actor_id text NOT NULL,
    tool_id text NOT NULL,
    arguments_digest text NOT NULL CHECK (arguments_digest ~ '^sha256:[0-9a-f]{64}$'),
    allowed boolean NOT NULL,
    code text NOT NULL,
    reason text NOT NULL,
    profile_digest text NOT NULL CHECK (profile_digest ~ '^sha256:[0-9a-f]{64}$'),
    policy_version text NOT NULL,
    recorded_at timestamptz NOT NULL,
    PRIMARY KEY (workspace_id, project_id, decision_id)
);

CREATE OR REPLACE FUNCTION agent_workflow.guard_provider_invocation_identity() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF (NEW.workspace_id,NEW.project_id,NEW.run_id,NEW.invocation_id,NEW.registry_snapshot_digest,NEW.policy_version,NEW.policy_digest,NEW.policy_snapshot,NEW.provider,NEW.model_version,NEW.region,NEW.disclosed_data_classes,NEW.started_at)
       IS DISTINCT FROM
       (OLD.workspace_id,OLD.project_id,OLD.run_id,OLD.invocation_id,OLD.registry_snapshot_digest,OLD.policy_version,OLD.policy_digest,OLD.policy_snapshot,OLD.provider,OLD.model_version,OLD.region,OLD.disclosed_data_classes,OLD.started_at) THEN
        RAISE EXCEPTION 'provider invocation identity is immutable';
    END IF;
    RETURN NEW;
END $$;
DROP TRIGGER IF EXISTS provider_invocation_identity ON agent_workflow.provider_invocations;
CREATE TRIGGER provider_invocation_identity BEFORE UPDATE ON agent_workflow.provider_invocations FOR EACH ROW EXECUTE FUNCTION agent_workflow.guard_provider_invocation_identity();

CREATE OR REPLACE FUNCTION agent_workflow.guard_provider_invocation_evidence() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE
    index integer;
BEGIN
    IF jsonb_typeof(NEW.physical_attempt_ids) <> 'array' OR jsonb_array_length(NEW.physical_attempt_ids) < jsonb_array_length(OLD.physical_attempt_ids) THEN
        RAISE EXCEPTION 'provider physical attempts are append-only';
    END IF;
    FOR index IN 0..jsonb_array_length(OLD.physical_attempt_ids)-1 LOOP
        IF NEW.physical_attempt_ids->index IS DISTINCT FROM OLD.physical_attempt_ids->index THEN
            RAISE EXCEPTION 'provider physical attempts are append-only';
        END IF;
    END LOOP;
    IF NEW.input_tokens < OLD.input_tokens OR NEW.output_tokens < OLD.output_tokens OR NEW.cost_micros < OLD.cost_micros THEN
        RAISE EXCEPTION 'provider accounting is monotonic';
    END IF;
    IF OLD.completed_at IS NOT NULL AND (NEW.physical_attempt_ids,NEW.completed_at,NEW.input_tokens,NEW.output_tokens,NEW.cost_micros,NEW.output_digest,NEW.problem)
       IS DISTINCT FROM
       (OLD.physical_attempt_ids,OLD.completed_at,OLD.input_tokens,OLD.output_tokens,OLD.cost_micros,OLD.output_digest,OLD.problem) THEN
        RAISE EXCEPTION 'completed provider evidence is immutable';
    END IF;
    RETURN NEW;
END $$;
DROP TRIGGER IF EXISTS provider_invocation_evidence ON agent_workflow.provider_invocations;
CREATE TRIGGER provider_invocation_evidence BEFORE UPDATE ON agent_workflow.provider_invocations FOR EACH ROW EXECUTE FUNCTION agent_workflow.guard_provider_invocation_evidence();

CREATE INDEX IF NOT EXISTS provider_invocations_run_idx ON agent_workflow.provider_invocations (workspace_id, project_id, run_id, started_at);
CREATE INDEX IF NOT EXISTS provider_continuations_expiry_idx ON agent_workflow.provider_continuations (expires_at);
CREATE INDEX IF NOT EXISTS context_evidence_run_idx ON agent_evaluation.context_evidence (workspace_id, project_id, run_id, created_at);
CREATE INDEX IF NOT EXISTS tool_decisions_run_idx ON agent_evaluation.tool_decisions (workspace_id, project_id, run_id, recorded_at);

GRANT SELECT, INSERT ON agent_control.provider_registry_snapshots, agent_control.provider_policy_snapshots TO agent_control_rw, agent_authority_rw;
GRANT SELECT, INSERT, UPDATE ON agent_workflow.provider_invocations, agent_workflow.provider_continuations TO agent_workflow_rw, agent_authority_rw;
GRANT SELECT, INSERT ON agent_workflow.run_tool_profiles TO agent_workflow_rw, agent_authority_rw;
GRANT DELETE ON agent_workflow.provider_continuations TO agent_workflow_rw, agent_authority_rw;
GRANT SELECT, INSERT ON agent_evaluation.context_evidence, agent_evaluation.tool_decisions TO agent_evaluation_rw;
GRANT USAGE, SELECT ON SEQUENCE agent_evaluation.tool_decisions_decision_id_seq TO agent_evaluation_rw;
