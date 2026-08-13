-- The external non-rollback register is intentionally absent from this schema.
-- This table is only the recovered scheduler mirror and cannot authorize alone.
CREATE TABLE IF NOT EXISTS agent_workflow.recovery_state (
    register_name text PRIMARY KEY,
    mirrored_epoch bigint NOT NULL CHECK (mirrored_epoch > 0),
    result_intake_enabled boolean NOT NULL DEFAULT false,
    dispatch_enabled boolean NOT NULL DEFAULT false,
    ingress_enabled boolean NOT NULL DEFAULT false,
    version bigint NOT NULL DEFAULT 1 CHECK (version > 0),
    updated_at timestamptz NOT NULL DEFAULT transaction_timestamp()
);

CREATE TABLE IF NOT EXISTS agent_workflow.restore_drills (
    drill_id text PRIMARY KEY,
    restore_point timestamptz NOT NULL,
    started_at timestamptz NOT NULL,
    completed_at timestamptz,
    external_epoch bigint CHECK (external_epoch > 0),
    state text NOT NULL CHECK (state IN ('isolated','reconciling','verified','failed')),
    report jsonb NOT NULL DEFAULT '{}'::jsonb
);

CREATE TABLE IF NOT EXISTS agent_workflow.restore_stages (
    drill_id text NOT NULL,
    sequence integer NOT NULL CHECK (sequence BETWEEN 1 AND 13),
    stage text NOT NULL,
    outcome text NOT NULL,
    evidence_digest text NOT NULL CHECK (evidence_digest ~ '^sha256:[0-9a-f]{64}$'),
    recorded_at timestamptz NOT NULL,
    PRIMARY KEY (drill_id, sequence),
    FOREIGN KEY (drill_id) REFERENCES agent_workflow.restore_drills(drill_id)
);

GRANT SELECT,INSERT,UPDATE ON agent_workflow.recovery_state,agent_workflow.restore_drills,agent_workflow.restore_stages TO agent_workflow_rw,agent_authority_rw;

