-- Complete signed authorization carriage, atomic
-- domain redemption, scoped idempotency, immutable grant revocation, durable
-- scheduler outputs and recovery register, scoped current authority, and
-- policy-identity validation evidence.

-- 1. A recorded issuance carries the complete signed authorization, so a
-- replayed durable commit operation returns the original persisted capability
-- instead of only its identity.
ALTER TABLE agent_control.commit_issuances
    ADD COLUMN IF NOT EXISTS authorization_jws text NOT NULL DEFAULT '',
    ADD COLUMN IF NOT EXISTS expires_at timestamptz;

-- 2. Write idempotency is isolated by authenticated subject, HTTP method, and
-- canonical route/operation in addition to workspace, project, and key
-- (ADR-021 §4), so one actor can never replay another actor's recorded
-- response.
ALTER TABLE agent_control.write_idempotency
    ADD COLUMN IF NOT EXISTS subject text NOT NULL DEFAULT '',
    ADD COLUMN IF NOT EXISTS method text NOT NULL DEFAULT '';
ALTER TABLE agent_control.write_idempotency DROP CONSTRAINT write_idempotency_pkey;
ALTER TABLE agent_control.write_idempotency
    ADD PRIMARY KEY (workspace_id, project_id, subject, method, operation, idempotency_key);

-- 3. The authoritative domain owner's redemption record: one operation redeems
-- exactly one authorization, exactly once. Replay returns the recorded outcome;
-- a different token for the same operation, or a second operation for the same
-- token, fails closed on the unique constraints.
CREATE TABLE IF NOT EXISTS agent_control.domain_redemptions (
    workspace_id text NOT NULL,
    project_id text NOT NULL,
    operation_id text NOT NULL CHECK (length(operation_id) BETWEEN 1 AND 128),
    authorization_id text NOT NULL CHECK (length(authorization_id) BETWEEN 1 AND 128),
    token_digest text NOT NULL CHECK (token_digest ~ '^sha256:[0-9a-f]{64}$'),
    run_id text NOT NULL,
    artifact_digest text NOT NULL CHECK (artifact_digest ~ '^sha256:[0-9a-f]{64}$'),
    outcome text NOT NULL CHECK (outcome IN ('confirmed','conflict','rejected')),
    redeemed_at timestamptz NOT NULL,
    PRIMARY KEY (workspace_id, project_id, operation_id),
    UNIQUE (workspace_id, project_id, authorization_id)
);

CREATE OR REPLACE FUNCTION agent_control.guard_domain_redemptions() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    RAISE EXCEPTION 'domain redemptions are immutable';
END $$;
DROP TRIGGER IF EXISTS domain_redemptions_immutable ON agent_control.domain_redemptions;
CREATE TRIGGER domain_redemptions_immutable
    BEFORE UPDATE OR DELETE ON agent_control.domain_redemptions
    FOR EACH ROW EXECUTE FUNCTION agent_control.guard_domain_redemptions();

GRANT SELECT, INSERT ON agent_control.domain_redemptions TO agent_control_rw, agent_authority_rw;

-- 4. Artifact grant revocation is recorded immutably on the audited grant row.
-- Revoked grants are never deleted: the audit history shows what was issued
-- and what was withdrawn.
ALTER TABLE agent_artifacts.access_grants
    ADD COLUMN IF NOT EXISTS revoked_at timestamptz,
    ADD COLUMN IF NOT EXISTS revocation_reason text;

CREATE OR REPLACE FUNCTION agent_artifacts.guard_access_grants() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF TG_OP = 'DELETE' THEN RAISE EXCEPTION 'artifact grant audit rows are immutable'; END IF;
    IF ROW(NEW.workspace_id,NEW.project_id,NEW.artifact_id,NEW.grant_id,NEW.security_generation,NEW.purpose,NEW.actor_id,NEW.issued_at,NEW.expires_at)
       IS DISTINCT FROM ROW(OLD.workspace_id,OLD.project_id,OLD.artifact_id,OLD.grant_id,OLD.security_generation,OLD.purpose,OLD.actor_id,OLD.issued_at,OLD.expires_at)
    THEN RAISE EXCEPTION 'artifact grant identity is immutable'; END IF;
    IF OLD.revoked_at IS NOT NULL AND (NEW.revoked_at IS DISTINCT FROM OLD.revoked_at OR NEW.revocation_reason IS DISTINCT FROM OLD.revocation_reason)
    THEN RAISE EXCEPTION 'artifact grant revocation is immutable'; END IF;
    RETURN NEW;
END $$;
DROP TRIGGER IF EXISTS access_grants_guard ON agent_artifacts.access_grants;
CREATE TRIGGER access_grants_guard
    BEFORE UPDATE OR DELETE ON agent_artifacts.access_grants
    FOR EACH ROW EXECUTE FUNCTION agent_artifacts.guard_access_grants();

GRANT UPDATE ON agent_artifacts.access_grants TO agent_artifacts_rw, agent_authority_rw;

-- 5. The scoped current-authority record: material in force per workspace and
-- project, subject activation per workspace and actor, and an append-only
-- revocation ledger every boundary observes on its next authority re-read.
CREATE TABLE IF NOT EXISTS agent_control.authority_bindings (
    workspace_id text NOT NULL,
    project_id text NOT NULL,
    definition jsonb NOT NULL,
    contract_bom jsonb NOT NULL,
    policy jsonb NOT NULL,
    budget jsonb NOT NULL,
    grants jsonb NOT NULL,
    version bigint NOT NULL DEFAULT 1 CHECK (version > 0),
    updated_at timestamptz NOT NULL DEFAULT transaction_timestamp(),
    PRIMARY KEY (workspace_id, project_id)
);

CREATE TABLE IF NOT EXISTS agent_control.authority_subjects (
    workspace_id text NOT NULL,
    actor_id text NOT NULL,
    role text NOT NULL CHECK (length(role) BETWEEN 1 AND 128),
    status text NOT NULL CHECK (status IN ('active','revoked')),
    updated_at timestamptz NOT NULL DEFAULT transaction_timestamp(),
    PRIMARY KEY (workspace_id, actor_id)
);

CREATE TABLE IF NOT EXISTS agent_control.authority_revocations (
    workspace_id text NOT NULL,
    project_id text NOT NULL,
    revocation_id text NOT NULL CHECK (length(revocation_id) BETWEEN 1 AND 256),
    kind text NOT NULL CHECK (kind IN ('actor','role','workspace','definition','policy','budget','target','approval')),
    subject text NOT NULL CHECK (length(subject) BETWEEN 1 AND 256),
    reason text NOT NULL DEFAULT '',
    recorded_at timestamptz NOT NULL,
    PRIMARY KEY (workspace_id, project_id, revocation_id)
);

CREATE OR REPLACE FUNCTION agent_control.guard_authority_revocations() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    RAISE EXCEPTION 'authority revocations are append-only';
END $$;
DROP TRIGGER IF EXISTS authority_revocations_immutable ON agent_control.authority_revocations;
CREATE TRIGGER authority_revocations_immutable
    BEFORE UPDATE OR DELETE ON agent_control.authority_revocations
    FOR EACH ROW EXECUTE FUNCTION agent_control.guard_authority_revocations();

GRANT SELECT, INSERT, UPDATE ON agent_control.authority_bindings, agent_control.authority_subjects TO agent_control_rw, agent_authority_rw;
GRANT SELECT, INSERT ON agent_control.authority_revocations TO agent_control_rw, agent_authority_rw;

-- 6. The accepted worker result's replayable output. A replay or a restart
-- reads these recorded bytes instead of executing the worker again.
CREATE TABLE IF NOT EXISTS agent_workflow.worker_outputs (
    workspace_id text NOT NULL,
    project_id text NOT NULL,
    task_id text NOT NULL,
    output bytea NOT NULL,
    output_digest text NOT NULL CHECK (output_digest ~ '^sha256:[0-9a-f]{64}$'),
    recorded_at timestamptz NOT NULL DEFAULT transaction_timestamp(),
    PRIMARY KEY (workspace_id, project_id, task_id),
    FOREIGN KEY (workspace_id, project_id, task_id) REFERENCES agent_workflow.worker_results(workspace_id, project_id, task_id)
);

CREATE OR REPLACE FUNCTION agent_workflow.guard_worker_outputs() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    RAISE EXCEPTION 'worker outputs are immutable';
END $$;
DROP TRIGGER IF EXISTS worker_outputs_immutable ON agent_workflow.worker_outputs;
CREATE TRIGGER worker_outputs_immutable
    BEFORE UPDATE OR DELETE ON agent_workflow.worker_outputs
    FOR EACH ROW EXECUTE FUNCTION agent_workflow.guard_worker_outputs();

GRANT SELECT, INSERT ON agent_workflow.worker_outputs TO agent_workflow_rw, agent_authority_rw;

-- 7. Validation evidence records the policy identity the Contract Runtime
-- actually verified alongside the schema, BOM, and catalog identities.
ALTER TABLE agent_evaluation.validation_evidence
    ADD COLUMN IF NOT EXISTS policy_digest text NOT NULL DEFAULT '';
