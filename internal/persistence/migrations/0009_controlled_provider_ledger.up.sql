-- The controlled model adapter's provider idempotency, settled outcomes,
-- script position, and usage evidence are durable process-external state. A
-- replay after a process or adapter restart reads these rows instead of
-- calling the provider again, advancing the script again, or billing again.
CREATE TABLE IF NOT EXISTS agent_workflow.controlled_provider_operations (
    ledger text NOT NULL CHECK (length(ledger) BETWEEN 1 AND 128),
    operation_key text NOT NULL CHECK (length(operation_key) BETWEEN 1 AND 512),
    script_position integer NOT NULL CHECK (script_position >= -1),
    failure boolean NOT NULL,
    input_tokens bigint NOT NULL CHECK (input_tokens >= 0),
    output_tokens bigint NOT NULL CHECK (output_tokens >= 0),
    cost_micros bigint NOT NULL CHECK (cost_micros >= 0),
    settled_at timestamptz NOT NULL DEFAULT transaction_timestamp(),
    PRIMARY KEY (ledger, operation_key)
);

-- A settled provider operation is history. Rewriting or deleting one would
-- let a replay reach the provider a second time.
CREATE OR REPLACE FUNCTION agent_workflow.guard_controlled_provider_operations() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    RAISE EXCEPTION 'settled controlled provider operations are immutable';
END $$;
DROP TRIGGER IF EXISTS controlled_provider_operations_immutable ON agent_workflow.controlled_provider_operations;
CREATE TRIGGER controlled_provider_operations_immutable
    BEFORE UPDATE OR DELETE ON agent_workflow.controlled_provider_operations
    FOR EACH ROW EXECUTE FUNCTION agent_workflow.guard_controlled_provider_operations();

CREATE INDEX IF NOT EXISTS controlled_provider_operations_ledger_idx
    ON agent_workflow.controlled_provider_operations (ledger, settled_at);

GRANT SELECT, INSERT ON agent_workflow.controlled_provider_operations TO agent_workflow_rw, agent_authority_rw;
