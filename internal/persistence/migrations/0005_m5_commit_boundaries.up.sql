CREATE TABLE IF NOT EXISTS agent_control.budget_reservations (
    workspace_id text NOT NULL,
    project_id text NOT NULL,
    root_run_id text NOT NULL,
    run_id text NOT NULL,
    reservation_id text NOT NULL,
    controller_generation bigint NOT NULL CHECK (controller_generation > 0),
    policy_version text NOT NULL,
    budget_version text NOT NULL,
    upper_bound_micros bigint NOT NULL CHECK (upper_bound_micros >= 0),
    observed_micros bigint NOT NULL DEFAULT 0 CHECK (observed_micros >= 0 AND observed_micros <= upper_bound_micros),
    attempt_final boolean NOT NULL DEFAULT false,
    released boolean NOT NULL DEFAULT false,
    expires_at timestamptz NOT NULL,
    created_at timestamptz NOT NULL DEFAULT transaction_timestamp(),
    updated_at timestamptz NOT NULL DEFAULT transaction_timestamp(),
    PRIMARY KEY (workspace_id, project_id, reservation_id)
);

CREATE TABLE IF NOT EXISTS agent_control.usage_observations (
    workspace_id text NOT NULL,
    project_id text NOT NULL,
    root_run_id text NOT NULL,
    run_id text NOT NULL,
    reservation_id text NOT NULL,
    observation_id text NOT NULL,
    task_id text NOT NULL,
    physical_attempt_id text NOT NULL,
    recovery_epoch bigint NOT NULL CHECK (recovery_epoch >= 0),
    execution_generation bigint NOT NULL CHECK (execution_generation >= 0),
    meter_sequence bigint NOT NULL CHECK (meter_sequence >= 0),
    cost_micros bigint NOT NULL CHECK (cost_micros >= 0),
    final boolean NOT NULL DEFAULT false,
    observed_at timestamptz NOT NULL DEFAULT transaction_timestamp(),
    PRIMARY KEY (workspace_id, project_id, observation_id),
    FOREIGN KEY (workspace_id, project_id, reservation_id) REFERENCES agent_control.budget_reservations(workspace_id, project_id, reservation_id)
);

CREATE TABLE IF NOT EXISTS agent_evaluation.validation_evidence (
    workspace_id text NOT NULL,
    project_id text NOT NULL,
    run_id text NOT NULL,
    evidence_id bigint GENERATED ALWAYS AS IDENTITY,
    boundary_kind text NOT NULL CHECK (boundary_kind IN ('plan','artifact')),
    bom_digest text NOT NULL CHECK (bom_digest ~ '^sha256:[0-9a-f]{64}$'),
    schema_digest text NOT NULL CHECK (schema_digest ~ '^sha256:[0-9a-f]{64}$'),
    validator_version text NOT NULL,
    catalog_digest text NOT NULL CHECK (catalog_digest ~ '^sha256:[0-9a-f]{64}$'),
    valid boolean NOT NULL,
    findings jsonb NOT NULL,
    validated_at timestamptz NOT NULL,
    PRIMARY KEY (workspace_id, project_id, evidence_id)
);

ALTER TABLE agent_artifacts.metadata
    ADD COLUMN IF NOT EXISTS actual_digest text,
    ADD COLUMN IF NOT EXISTS version bigint NOT NULL DEFAULT 1 CHECK (version > 0),
    ADD COLUMN IF NOT EXISTS object_reference jsonb NOT NULL DEFAULT '{}'::jsonb,
    ADD COLUMN IF NOT EXISTS schema_identity jsonb NOT NULL DEFAULT '{}'::jsonb,
    ADD COLUMN IF NOT EXISTS legal_hold boolean NOT NULL DEFAULT false,
    ADD COLUMN IF NOT EXISTS deleted_at timestamptz,
    ADD COLUMN IF NOT EXISTS deletion_reason text;

CREATE TABLE IF NOT EXISTS agent_artifacts.access_grants (
    workspace_id text NOT NULL,
    project_id text NOT NULL,
    artifact_id text NOT NULL,
    grant_id text NOT NULL,
    security_generation bigint NOT NULL CHECK (security_generation > 0),
    purpose text NOT NULL CHECK (purpose IN ('producer','scanner','review','approval','finalization','commit','read')),
    actor_id text NOT NULL,
    issued_at timestamptz NOT NULL,
    expires_at timestamptz NOT NULL,
    PRIMARY KEY (workspace_id, project_id, grant_id),
    FOREIGN KEY (workspace_id, project_id, artifact_id) REFERENCES agent_artifacts.metadata(workspace_id, project_id, artifact_id)
);

CREATE TABLE IF NOT EXISTS agent_control.apply_authorizations (
    workspace_id text NOT NULL,
    project_id text NOT NULL,
    run_id text NOT NULL,
    authorization_id text NOT NULL,
    key_id text NOT NULL,
    payload_digest text NOT NULL CHECK (payload_digest ~ '^sha256:[0-9a-f]{64}$'),
    token_digest text NOT NULL CHECK (token_digest ~ '^sha256:[0-9a-f]{64}$'),
    issued_at timestamptz NOT NULL,
    expires_at timestamptz NOT NULL,
    PRIMARY KEY (workspace_id, project_id, authorization_id)
);

CREATE TABLE IF NOT EXISTS agent_control.domain_operations (
    workspace_id text NOT NULL,
    project_id text NOT NULL,
    run_id text NOT NULL,
    operation_id text NOT NULL,
    authorization_id text NOT NULL,
    authorization_jws text NOT NULL,
    action_digest text NOT NULL CHECK (action_digest ~ '^sha256:[0-9a-f]{64}$'),
    artifact_digest text NOT NULL CHECK (artifact_digest ~ '^sha256:[0-9a-f]{64}$'),
    expected_revision text NOT NULL,
    status text NOT NULL CHECK (status IN ('recorded','issued','awaiting-domain-confirmation','applied','conflict','rejected')),
    authorization_consumed boolean NOT NULL DEFAULT false,
    created_at timestamptz NOT NULL,
    updated_at timestamptz NOT NULL,
    PRIMARY KEY (workspace_id, project_id, operation_id),
    UNIQUE (workspace_id, project_id, authorization_id),
    FOREIGN KEY (workspace_id, project_id, authorization_id) REFERENCES agent_control.apply_authorizations(workspace_id, project_id, authorization_id)
);

CREATE OR REPLACE FUNCTION agent_control.guard_domain_operation_identity() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF (NEW.workspace_id,NEW.project_id,NEW.run_id,NEW.operation_id,NEW.authorization_id,NEW.authorization_jws,NEW.action_digest,NEW.artifact_digest,NEW.expected_revision,NEW.created_at)
       IS DISTINCT FROM
       (OLD.workspace_id,OLD.project_id,OLD.run_id,OLD.operation_id,OLD.authorization_id,OLD.authorization_jws,OLD.action_digest,OLD.artifact_digest,OLD.expected_revision,OLD.created_at) THEN
        RAISE EXCEPTION 'domain operation identity is immutable';
    END IF;
    IF OLD.authorization_consumed AND NOT NEW.authorization_consumed THEN
        RAISE EXCEPTION 'authorization consumption is irreversible';
    END IF;
    RETURN NEW;
END $$;
DROP TRIGGER IF EXISTS domain_operation_identity ON agent_control.domain_operations;
CREATE TRIGGER domain_operation_identity BEFORE UPDATE ON agent_control.domain_operations FOR EACH ROW EXECUTE FUNCTION agent_control.guard_domain_operation_identity();

CREATE INDEX IF NOT EXISTS budget_reservations_root_idx ON agent_control.budget_reservations(workspace_id, project_id, root_run_id);
CREATE INDEX IF NOT EXISTS validation_evidence_run_idx ON agent_evaluation.validation_evidence(workspace_id, project_id, run_id, validated_at);
CREATE INDEX IF NOT EXISTS artifact_pending_reconcile_idx ON agent_artifacts.metadata(updated_at) WHERE state='pending';
CREATE UNIQUE INDEX IF NOT EXISTS domain_operations_active_run_idx ON agent_control.domain_operations(workspace_id, project_id, run_id) WHERE status IN ('recorded','issued','awaiting-domain-confirmation');

GRANT SELECT, INSERT, UPDATE ON agent_control.budget_reservations, agent_control.domain_operations TO agent_control_rw, agent_authority_rw;
GRANT SELECT, INSERT ON agent_control.usage_observations, agent_control.apply_authorizations TO agent_control_rw, agent_authority_rw;
GRANT SELECT, INSERT ON agent_evaluation.validation_evidence TO agent_evaluation_rw;
GRANT USAGE, SELECT ON SEQUENCE agent_evaluation.validation_evidence_evidence_id_seq TO agent_evaluation_rw;
GRANT SELECT, INSERT, UPDATE, DELETE ON agent_artifacts.access_grants TO agent_artifacts_rw;
