ALTER TABLE agent_evaluation.validation_evidence DROP COLUMN IF EXISTS policy_digest;

DROP TRIGGER IF EXISTS worker_outputs_immutable ON agent_workflow.worker_outputs;
DROP TABLE IF EXISTS agent_workflow.worker_outputs;
DROP FUNCTION IF EXISTS agent_workflow.guard_worker_outputs();

DROP TRIGGER IF EXISTS authority_revocations_immutable ON agent_control.authority_revocations;
DROP TABLE IF EXISTS agent_control.authority_revocations;
DROP FUNCTION IF EXISTS agent_control.guard_authority_revocations();
DROP TABLE IF EXISTS agent_control.authority_subjects;
DROP TABLE IF EXISTS agent_control.authority_bindings;

DROP TRIGGER IF EXISTS access_grants_guard ON agent_artifacts.access_grants;
DROP FUNCTION IF EXISTS agent_artifacts.guard_access_grants();
ALTER TABLE agent_artifacts.access_grants
    DROP COLUMN IF EXISTS revoked_at,
    DROP COLUMN IF EXISTS revocation_reason;

DROP TRIGGER IF EXISTS domain_redemptions_immutable ON agent_control.domain_redemptions;
DROP TABLE IF EXISTS agent_control.domain_redemptions;
DROP FUNCTION IF EXISTS agent_control.guard_domain_redemptions();

ALTER TABLE agent_control.write_idempotency DROP CONSTRAINT write_idempotency_pkey;
ALTER TABLE agent_control.write_idempotency
    DROP COLUMN IF EXISTS subject,
    DROP COLUMN IF EXISTS method;
-- Rows that were distinct only by subject or method collapse onto the
-- narrower key; keep one arbitrary survivor per key before restoring it.
DELETE FROM agent_control.write_idempotency a
    USING agent_control.write_idempotency b
    WHERE a.ctid < b.ctid
      AND a.workspace_id = b.workspace_id
      AND a.project_id = b.project_id
      AND a.operation = b.operation
      AND a.idempotency_key = b.idempotency_key;
ALTER TABLE agent_control.write_idempotency
    ADD PRIMARY KEY (workspace_id, project_id, operation, idempotency_key);

ALTER TABLE agent_control.commit_issuances
    DROP COLUMN IF EXISTS authorization_jws,
    DROP COLUMN IF EXISTS expires_at;
