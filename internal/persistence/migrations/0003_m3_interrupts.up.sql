CREATE TABLE IF NOT EXISTS agent_control.input_requests (
    workspace_id text NOT NULL,
    project_id text NOT NULL,
    run_id text NOT NULL,
    request_id text NOT NULL,
    request_version bigint NOT NULL CHECK (request_version > 0),
    run_version bigint NOT NULL CHECK (run_version > 0),
    question text NOT NULL CHECK (length(question) BETWEEN 1 AND 4096),
    response_schema jsonb NOT NULL,
    resume_checkpoint text NOT NULL,
    expires_at timestamptz NOT NULL,
    created_at timestamptz NOT NULL,
    response_bytes bytea,
    response_digest text,
    response_actor_id text,
    responded_at timestamptz,
    PRIMARY KEY (workspace_id, project_id, run_id, request_id),
    UNIQUE (workspace_id, project_id, run_id, request_version),
    CHECK ((response_bytes IS NULL) = (responded_at IS NULL)),
    CHECK ((response_digest IS NULL) = (responded_at IS NULL)),
    CHECK ((response_actor_id IS NULL) = (responded_at IS NULL))
);

CREATE TABLE IF NOT EXISTS agent_control.approval_requests (
    workspace_id text NOT NULL,
    project_id text NOT NULL,
    run_id text NOT NULL,
    request_id text NOT NULL,
    decision_version bigint NOT NULL CHECK (decision_version > 0),
    run_version bigint NOT NULL CHECK (run_version > 0),
    action_digest text NOT NULL,
    effects jsonb NOT NULL,
    expected_cost jsonb NOT NULL,
    reviewer_policy jsonb NOT NULL,
    resume_checkpoint text NOT NULL,
    expires_at timestamptz NOT NULL,
    created_at timestamptz NOT NULL,
    decision text CHECK (decision IN ('approve','reject','change')),
    decision_reason text,
    reviewer_id text,
    decided_at timestamptz,
    PRIMARY KEY (workspace_id, project_id, run_id, request_id),
    UNIQUE (workspace_id, project_id, run_id, decision_version),
    CHECK ((decision IS NULL) = (decided_at IS NULL)),
    CHECK ((reviewer_id IS NULL) = (decided_at IS NULL))
);

CREATE TABLE IF NOT EXISTS agent_control.lifecycle_controls (
    workspace_id text NOT NULL,
    project_id text NOT NULL,
    run_id text NOT NULL,
    control_id text NOT NULL,
    control_kind text NOT NULL CHECK (control_kind IN ('cancel','retry','discard')),
    run_version bigint NOT NULL CHECK (run_version > 0),
    execution_generation bigint NOT NULL CHECK (execution_generation > 0),
    actor_id text NOT NULL,
    request_digest text NOT NULL,
    evidence jsonb NOT NULL,
    created_at timestamptz NOT NULL,
    PRIMARY KEY (workspace_id, project_id, run_id, control_id)
);

CREATE TABLE IF NOT EXISTS agent_control.run_children (
    workspace_id text NOT NULL,
    project_id text NOT NULL,
    root_run_id text NOT NULL,
    parent_run_id text NOT NULL,
    child_run_id text NOT NULL,
    mode text NOT NULL CHECK (mode IN ('required','optional','fallback')),
    predecessor_run_id text,
    depth integer NOT NULL CHECK (depth > 0),
    actor_id text NOT NULL,
    contract_bom jsonb NOT NULL,
    data_policy jsonb NOT NULL,
    artifact_lineage_reference text,
    outcome_state text,
    warning text,
    created_at timestamptz NOT NULL,
    PRIMARY KEY (workspace_id, project_id, child_run_id),
    CHECK ((mode = 'fallback') = (predecessor_run_id IS NOT NULL))
);

CREATE TABLE IF NOT EXISTS agent_control.run_progress (
    workspace_id text NOT NULL,
    project_id text NOT NULL,
    run_id text NOT NULL,
    state text NOT NULL,
    entered_at timestamptz NOT NULL,
    progress_at timestamptz NOT NULL,
    stuck_at timestamptz,
    PRIMARY KEY (workspace_id, project_id, run_id)
);

CREATE OR REPLACE FUNCTION agent_control.guard_input_request_immutability() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF (NEW.workspace_id,NEW.project_id,NEW.run_id,NEW.request_id,NEW.request_version,NEW.run_version,NEW.question,NEW.response_schema,NEW.resume_checkpoint,NEW.expires_at,NEW.created_at)
       IS DISTINCT FROM
       (OLD.workspace_id,OLD.project_id,OLD.run_id,OLD.request_id,OLD.request_version,OLD.run_version,OLD.question,OLD.response_schema,OLD.resume_checkpoint,OLD.expires_at,OLD.created_at) THEN
        RAISE EXCEPTION 'input request evidence is immutable';
    END IF;
    RETURN NEW;
END $$;
DROP TRIGGER IF EXISTS input_request_immutability ON agent_control.input_requests;
CREATE TRIGGER input_request_immutability BEFORE UPDATE ON agent_control.input_requests FOR EACH ROW EXECUTE FUNCTION agent_control.guard_input_request_immutability();

CREATE OR REPLACE FUNCTION agent_control.guard_approval_request_immutability() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF (NEW.workspace_id,NEW.project_id,NEW.run_id,NEW.request_id,NEW.decision_version,NEW.run_version,NEW.action_digest,NEW.effects,NEW.expected_cost,NEW.reviewer_policy,NEW.resume_checkpoint,NEW.expires_at,NEW.created_at)
       IS DISTINCT FROM
       (OLD.workspace_id,OLD.project_id,OLD.run_id,OLD.request_id,OLD.decision_version,OLD.run_version,OLD.action_digest,OLD.effects,OLD.expected_cost,OLD.reviewer_policy,OLD.resume_checkpoint,OLD.expires_at,OLD.created_at) THEN
        RAISE EXCEPTION 'approval request evidence is immutable';
    END IF;
    RETURN NEW;
END $$;
DROP TRIGGER IF EXISTS approval_request_immutability ON agent_control.approval_requests;
CREATE TRIGGER approval_request_immutability BEFORE UPDATE ON agent_control.approval_requests FOR EACH ROW EXECUTE FUNCTION agent_control.guard_approval_request_immutability();

CREATE OR REPLACE FUNCTION agent_control.guard_required_children_before_completion() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF NEW.state = 'completed' AND EXISTS (
        SELECT 1 FROM agent_control.run_children
        WHERE workspace_id=NEW.workspace_id AND project_id=NEW.project_id
          AND parent_run_id=NEW.run_id AND mode='required'
          AND outcome_state IS DISTINCT FROM 'completed'
    ) THEN
        RAISE EXCEPTION 'required child has not completed';
    END IF;
    RETURN NEW;
END $$;
DROP TRIGGER IF EXISTS required_children_before_completion ON agent_control.agent_runs;
CREATE TRIGGER required_children_before_completion BEFORE UPDATE OF state ON agent_control.agent_runs FOR EACH ROW EXECUTE FUNCTION agent_control.guard_required_children_before_completion();

CREATE INDEX IF NOT EXISTS input_requests_current_idx ON agent_control.input_requests (workspace_id, project_id, run_id, request_version DESC);
CREATE INDEX IF NOT EXISTS approval_requests_current_idx ON agent_control.approval_requests (workspace_id, project_id, run_id, decision_version DESC);
CREATE INDEX IF NOT EXISTS run_children_parent_idx ON agent_control.run_children (workspace_id, project_id, parent_run_id);
CREATE INDEX IF NOT EXISTS run_progress_scan_idx ON agent_control.run_progress (state, progress_at) WHERE stuck_at IS NULL;

GRANT SELECT, INSERT, UPDATE ON agent_control.input_requests, agent_control.approval_requests, agent_control.lifecycle_controls, agent_control.run_children, agent_control.run_progress TO agent_authority_rw;
