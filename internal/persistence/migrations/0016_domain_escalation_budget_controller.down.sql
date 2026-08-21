DROP TRIGGER IF EXISTS budget_observations_immutable ON agent_control.budget_observations;
DROP TABLE IF EXISTS agent_control.budget_observations;
DROP FUNCTION IF EXISTS agent_control.guard_budget_observations();

-- Escalated operations cannot exist under the narrower status vocabulary.
-- Down migrations are lossy: an escalated operation is recorded as rejected
-- so the restored constraint holds and the authorization stays consumed.
DROP TRIGGER IF EXISTS domain_operation_identity ON agent_control.domain_operations;
UPDATE agent_control.domain_operations
    SET status='rejected', authorization_consumed=true, updated_at=transaction_timestamp()
    WHERE status='escalated';

DROP INDEX IF EXISTS agent_control.domain_operations_active_run_idx;
CREATE UNIQUE INDEX IF NOT EXISTS domain_operations_active_run_idx ON agent_control.domain_operations(workspace_id, project_id, run_id) WHERE status IN ('recorded','issued','awaiting-domain-confirmation');

ALTER TABLE agent_control.domain_operations DROP CONSTRAINT IF EXISTS domain_operations_status_check;
ALTER TABLE agent_control.domain_operations
    ADD CONSTRAINT domain_operations_status_check
    CHECK (status IN ('recorded','issued','awaiting-domain-confirmation','applied','conflict','rejected'));

ALTER TABLE agent_control.domain_operations
    DROP COLUMN IF EXISTS reconcile_attempts,
    DROP COLUMN IF EXISTS first_uncertain_at,
    DROP COLUMN IF EXISTS escalated_at,
    DROP COLUMN IF EXISTS resolved_by,
    DROP COLUMN IF EXISTS resolution_basis;

CREATE OR REPLACE FUNCTION agent_control.guard_domain_operation_identity() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF (NEW.workspace_id,NEW.project_id,NEW.run_id,NEW.operation_id,NEW.authorization_id,NEW.authorization_jws,NEW.action_digest,NEW.artifact_digest,NEW.expected_revision,NEW.idempotency_key,NEW.request_digest,NEW.created_at)
       IS DISTINCT FROM
       (OLD.workspace_id,OLD.project_id,OLD.run_id,OLD.operation_id,OLD.authorization_id,OLD.authorization_jws,OLD.action_digest,OLD.artifact_digest,OLD.expected_revision,OLD.idempotency_key,OLD.request_digest,OLD.created_at) THEN
        RAISE EXCEPTION 'domain operation identity is immutable';
    END IF;
    IF OLD.authorization_consumed AND NOT NEW.authorization_consumed THEN
        RAISE EXCEPTION 'authorization consumption is irreversible';
    END IF;
    IF NEW.updated_at < OLD.updated_at THEN
        RAISE EXCEPTION 'domain operation time is monotonic';
    END IF;
    IF NOT (
        NEW.status = OLD.status OR
        (OLD.status = 'recorded' AND NEW.status = 'issued') OR
        (OLD.status = 'issued' AND NEW.status IN ('awaiting-domain-confirmation','applied','conflict','rejected')) OR
        (OLD.status = 'awaiting-domain-confirmation' AND NEW.status IN ('applied','conflict','rejected'))
    ) THEN
        RAISE EXCEPTION 'domain operation status transition is invalid';
    END IF;
    IF NEW.authorization_consumed IS DISTINCT FROM (NEW.status IN ('applied','conflict','rejected')) THEN
        RAISE EXCEPTION 'terminal domain operation must consume authorization';
    END IF;
    RETURN NEW;
END $$;
CREATE TRIGGER domain_operation_identity BEFORE UPDATE ON agent_control.domain_operations FOR EACH ROW EXECUTE FUNCTION agent_control.guard_domain_operation_identity();
