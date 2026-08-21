-- Bounded, observable recovery of the submitted-but-uncertain domain window
-- with an audited operator-resolution path, and the durable Platform
-- budget-controller observation ledger.

-- 1. The write-ahead domain operation carries its own durable recovery
-- bookkeeping: how many times an uncertain submission was reconciled, when
-- uncertainty began, when the bounded window escalated, and — for an
-- operator-resolved outcome — who resolved it and on what authoritative
-- basis. A submitted operation whose owner never answers can therefore never
-- spin silently: the count is durable, the escalation is a recorded state,
-- and leaving it requires an audited resolution.
ALTER TABLE agent_control.domain_operations
    ADD COLUMN IF NOT EXISTS reconcile_attempts bigint NOT NULL DEFAULT 0 CHECK (reconcile_attempts >= 0),
    ADD COLUMN IF NOT EXISTS first_uncertain_at timestamptz,
    ADD COLUMN IF NOT EXISTS escalated_at timestamptz,
    ADD COLUMN IF NOT EXISTS resolved_by text CHECK (resolved_by IS NULL OR length(resolved_by) BETWEEN 1 AND 128),
    ADD COLUMN IF NOT EXISTS resolution_basis text CHECK (resolution_basis IS NULL OR length(resolution_basis) BETWEEN 1 AND 1024);

ALTER TABLE agent_control.domain_operations DROP CONSTRAINT IF EXISTS domain_operations_status_check;
ALTER TABLE agent_control.domain_operations
    ADD CONSTRAINT domain_operations_status_check
    CHECK (status IN ('recorded','issued','awaiting-domain-confirmation','escalated','applied','conflict','rejected'));

-- An escalated operation is still the run's one active operation.
DROP INDEX IF EXISTS agent_control.domain_operations_active_run_idx;
CREATE UNIQUE INDEX IF NOT EXISTS domain_operations_active_run_idx ON agent_control.domain_operations(workspace_id, project_id, run_id) WHERE status IN ('recorded','issued','awaiting-domain-confirmation','escalated');

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
    IF NEW.reconcile_attempts < OLD.reconcile_attempts THEN
        RAISE EXCEPTION 'domain operation reconciliation count is monotonic';
    END IF;
    IF OLD.first_uncertain_at IS NOT NULL AND NEW.first_uncertain_at IS DISTINCT FROM OLD.first_uncertain_at THEN
        RAISE EXCEPTION 'domain operation uncertainty onset is immutable';
    END IF;
    IF OLD.escalated_at IS NOT NULL AND NEW.escalated_at IS DISTINCT FROM OLD.escalated_at THEN
        RAISE EXCEPTION 'domain operation escalation time is immutable';
    END IF;
    IF OLD.resolved_by IS NOT NULL AND (NEW.resolved_by IS DISTINCT FROM OLD.resolved_by OR NEW.resolution_basis IS DISTINCT FROM OLD.resolution_basis) THEN
        RAISE EXCEPTION 'domain operation resolution audit is immutable';
    END IF;
    IF NOT (
        NEW.status = OLD.status OR
        (OLD.status = 'recorded' AND NEW.status = 'issued') OR
        (OLD.status = 'issued' AND NEW.status IN ('awaiting-domain-confirmation','escalated','applied','conflict','rejected')) OR
        (OLD.status = 'awaiting-domain-confirmation' AND NEW.status IN ('escalated','applied','conflict','rejected')) OR
        (OLD.status = 'escalated' AND NEW.status IN ('applied','conflict','rejected'))
    ) THEN
        RAISE EXCEPTION 'domain operation status transition is invalid';
    END IF;
    IF NEW.status = 'escalated' AND NEW.escalated_at IS NULL THEN
        RAISE EXCEPTION 'domain operation escalation requires its escalation time';
    END IF;
    IF OLD.status = 'escalated' AND NEW.status IN ('applied','conflict','rejected') AND (NEW.resolved_by IS NULL OR NEW.resolution_basis IS NULL) THEN
        RAISE EXCEPTION 'escalated domain operation requires an audited operator resolution';
    END IF;
    IF NEW.authorization_consumed IS DISTINCT FROM (NEW.status IN ('applied','conflict','rejected')) THEN
        RAISE EXCEPTION 'terminal domain operation must consume authorization';
    END IF;
    RETURN NEW;
END $$;
DROP TRIGGER IF EXISTS domain_operation_identity ON agent_control.domain_operations;
CREATE TRIGGER domain_operation_identity BEFORE UPDATE ON agent_control.domain_operations FOR EACH ROW EXECUTE FUNCTION agent_control.guard_domain_operation_identity();

-- 2. The Platform budget controller's durable observation ledger. Each row is
-- one deduplicated cost observation against a reservation; the reservation
-- row itself accumulates observed cost under its monotonic settlement guard.
-- Observations are immutable: usage that was observed is never unobserved.
CREATE TABLE IF NOT EXISTS agent_control.budget_observations (
    workspace_id text NOT NULL,
    project_id text NOT NULL,
    observation_id text NOT NULL CHECK (length(observation_id) BETWEEN 1 AND 256),
    reservation_id text NOT NULL,
    root_run_id text NOT NULL,
    run_id text NOT NULL,
    task_id text NOT NULL,
    physical_attempt_id text NOT NULL,
    recovery_epoch bigint NOT NULL CHECK (recovery_epoch >= 0),
    execution_generation bigint NOT NULL CHECK (execution_generation >= 0),
    meter_sequence bigint NOT NULL CHECK (meter_sequence >= 0),
    cost_micros bigint NOT NULL CHECK (cost_micros >= 0),
    final boolean NOT NULL DEFAULT false,
    observed_at timestamptz NOT NULL,
    PRIMARY KEY (workspace_id, project_id, observation_id),
    FOREIGN KEY (workspace_id, project_id, reservation_id) REFERENCES agent_control.budget_reservations(workspace_id, project_id, reservation_id)
);

CREATE OR REPLACE FUNCTION agent_control.guard_budget_observations() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    RAISE EXCEPTION 'budget observations are immutable';
END $$;
DROP TRIGGER IF EXISTS budget_observations_immutable ON agent_control.budget_observations;
CREATE TRIGGER budget_observations_immutable
    BEFORE UPDATE OR DELETE ON agent_control.budget_observations
    FOR EACH ROW EXECUTE FUNCTION agent_control.guard_budget_observations();

CREATE INDEX IF NOT EXISTS budget_observations_reservation_idx ON agent_control.budget_observations(workspace_id, project_id, reservation_id);

GRANT SELECT, INSERT ON agent_control.budget_observations TO agent_control_rw, agent_authority_rw;
