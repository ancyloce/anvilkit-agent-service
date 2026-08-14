-- The external non-rollback register is intentionally absent from this schema.
-- This table is only the recovered scheduler mirror and cannot authorize alone.
CREATE TABLE IF NOT EXISTS agent_workflow.recovery_state (
    register_name text PRIMARY KEY CHECK (length(register_name) BETWEEN 1 AND 128),
    mirrored_epoch bigint NOT NULL CHECK (mirrored_epoch > 0),
    result_intake_enabled boolean NOT NULL DEFAULT false,
    dispatch_enabled boolean NOT NULL DEFAULT false,
    ingress_enabled boolean NOT NULL DEFAULT false,
    version bigint NOT NULL DEFAULT 1 CHECK (version > 0),
    updated_at timestamptz NOT NULL DEFAULT transaction_timestamp()
);

CREATE TABLE IF NOT EXISTS agent_workflow.restore_drills (
    drill_id text PRIMARY KEY CHECK (drill_id ~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'),
    actor text NOT NULL CHECK (actor ~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'),
    workload text NOT NULL CHECK (workload ~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'),
    reason text NOT NULL CHECK (length(reason) BETWEEN 1 AND 1024),
    ticket text NOT NULL CHECK (ticket ~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'),
    traceparent text NOT NULL CHECK (traceparent ~ '^00-[0-9a-f]{32}-[0-9a-f]{16}-[0-9a-f]{2}$'),
    restore_point timestamptz NOT NULL,
    started_at timestamptz NOT NULL,
    completed_at timestamptz,
    external_epoch bigint CHECK (external_epoch > 0),
    state text NOT NULL CHECK (state IN ('isolated','reconciling','verified','failed')),
    failure_stage integer CHECK (failure_stage BETWEEN 1 AND 13),
    failure_code text CHECK (failure_code ~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'),
    report jsonb NOT NULL DEFAULT '{}'::jsonb CHECK (jsonb_typeof(report)='object'),
    CHECK ((state IN ('isolated','reconciling') AND completed_at IS NULL)
        OR (state='verified' AND completed_at IS NOT NULL AND external_epoch IS NOT NULL)
        OR (state='failed' AND completed_at IS NOT NULL AND failure_stage IS NOT NULL AND failure_code IS NOT NULL))
);

CREATE TABLE IF NOT EXISTS agent_workflow.restore_stages (
    drill_id text NOT NULL,
    sequence integer NOT NULL CHECK (sequence BETWEEN 1 AND 26),
    stage_sequence integer NOT NULL CHECK (stage_sequence BETWEEN 1 AND 13),
    stage text NOT NULL CHECK (stage IN ('disable-processing','restore-postgres-isolated','rotate-external-epoch','fence-recovered-scheduler','enable-dual-result-fence','reconcile-acknowledgements','reconcile-current-authority','reconcile-pagix-effects','reconcile-reservations-usage','reconcile-artifacts-grants','rebuild-deliveries-without-dispatch','reauthorize-resume-dispatch-ingress','verify-audit-and-probes')),
    outcome text NOT NULL CHECK (outcome IN ('starting','completed','failed')),
    external_epoch bigint NOT NULL CHECK (external_epoch >= 0),
    record jsonb NOT NULL CHECK (jsonb_typeof(record)='object'),
    evidence_digest text NOT NULL CHECK (evidence_digest ~ '^sha256:[0-9a-f]{64}$'),
    recorded_at timestamptz NOT NULL,
    PRIMARY KEY (drill_id, sequence),
    UNIQUE (drill_id, stage_sequence, outcome),
    FOREIGN KEY (drill_id) REFERENCES agent_workflow.restore_drills(drill_id),
    CHECK ((outcome='starting' AND sequence=stage_sequence*2-1)
        OR (outcome IN ('completed','failed') AND sequence=stage_sequence*2))
);

CREATE OR REPLACE FUNCTION agent_workflow.guard_recovery_state() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF TG_OP='DELETE' OR NEW.register_name<>OLD.register_name THEN RAISE EXCEPTION 'recovery state identity is immutable'; END IF;
    IF NEW.version<>OLD.version+1 OR NEW.mirrored_epoch<OLD.mirrored_epoch THEN RAISE EXCEPTION 'recovery state version or epoch regressed'; END IF;
    IF NEW.mirrored_epoch>OLD.mirrored_epoch AND (NEW.result_intake_enabled OR NEW.dispatch_enabled OR NEW.ingress_enabled) THEN
        RAISE EXCEPTION 'new recovery epoch must begin isolated';
    END IF;
    RETURN NEW;
END $$;
DROP TRIGGER IF EXISTS recovery_state_guard ON agent_workflow.recovery_state;
CREATE TRIGGER recovery_state_guard BEFORE UPDATE OR DELETE ON agent_workflow.recovery_state FOR EACH ROW EXECUTE FUNCTION agent_workflow.guard_recovery_state();

CREATE OR REPLACE FUNCTION agent_workflow.guard_restore_stage_immutable() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN RAISE EXCEPTION 'restore stage evidence is immutable'; END $$;
DROP TRIGGER IF EXISTS restore_stage_immutable ON agent_workflow.restore_stages;
CREATE TRIGGER restore_stage_immutable BEFORE UPDATE OR DELETE ON agent_workflow.restore_stages FOR EACH ROW EXECUTE FUNCTION agent_workflow.guard_restore_stage_immutable();

CREATE OR REPLACE FUNCTION agent_workflow.guard_restore_drill() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF TG_OP='DELETE' THEN RAISE EXCEPTION 'restore drill evidence is immutable'; END IF;
    IF ROW(NEW.drill_id,NEW.actor,NEW.workload,NEW.reason,NEW.ticket,NEW.traceparent,NEW.restore_point,NEW.started_at)
       IS DISTINCT FROM ROW(OLD.drill_id,OLD.actor,OLD.workload,OLD.reason,OLD.ticket,OLD.traceparent,OLD.restore_point,OLD.started_at)
    THEN RAISE EXCEPTION 'restore drill identity is immutable'; END IF;
    IF (OLD.state='isolated' AND NEW.state NOT IN ('isolated','reconciling','failed'))
       OR (OLD.state='reconciling' AND NEW.state NOT IN ('reconciling','verified','failed'))
       OR (OLD.state='failed' AND NEW.state<>'failed')
       OR OLD.state='verified'
    THEN RAISE EXCEPTION 'invalid restore drill transition'; END IF;
    IF OLD.completed_at IS NOT NULL AND NEW.completed_at IS DISTINCT FROM OLD.completed_at
       OR OLD.external_epoch IS NOT NULL AND NEW.external_epoch IS DISTINCT FROM OLD.external_epoch
       OR OLD.failure_stage IS NOT NULL AND NEW.failure_stage IS DISTINCT FROM OLD.failure_stage
       OR OLD.failure_code IS NOT NULL AND NEW.failure_code IS DISTINCT FROM OLD.failure_code
       OR OLD.report<>'{}'::jsonb AND NEW.report IS DISTINCT FROM OLD.report
    THEN RAISE EXCEPTION 'restore drill outcome is immutable'; END IF;
    RETURN NEW;
END $$;
DROP TRIGGER IF EXISTS restore_drill_guard ON agent_workflow.restore_drills;
CREATE TRIGGER restore_drill_guard BEFORE UPDATE OR DELETE ON agent_workflow.restore_drills FOR EACH ROW EXECUTE FUNCTION agent_workflow.guard_restore_drill();

GRANT SELECT ON agent_workflow.recovery_state,agent_workflow.restore_drills,agent_workflow.restore_stages TO agent_workflow_rw;
GRANT SELECT,INSERT,UPDATE ON agent_workflow.recovery_state,agent_workflow.restore_drills,agent_workflow.restore_stages TO agent_authority_rw;
