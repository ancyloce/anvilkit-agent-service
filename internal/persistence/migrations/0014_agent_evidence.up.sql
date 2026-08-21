-- Internal AgentEvidence (ADR-020): high-fidelity execution facts with their
-- own independent per-run sequence, explicit classification and retention,
-- immutable rows, and access-audited reads. Deliberately stricter than the
-- public event store: only the composition's authority role can touch it.
CREATE SCHEMA IF NOT EXISTS agent_evidence;

CREATE TABLE IF NOT EXISTS agent_evidence.records (
    workspace_id text NOT NULL,
    project_id text NOT NULL,
    run_id text NOT NULL,
    evidence_id text NOT NULL CHECK (length(evidence_id) BETWEEN 1 AND 128),
    evidence_sequence bigint NOT NULL CHECK (evidence_sequence >= 1),
    evidence_type text NOT NULL CHECK (evidence_type ~ '^(agent|model|tool|validation|artifact|approval|commit|domain|recovery)\.[a-z0-9][a-z0-9.-]*$'),
    data_classification text NOT NULL CHECK (data_classification IN ('public','internal','confidential','restricted')),
    retention_category text NOT NULL CHECK (retention_category IN ('operational','audit','security')),
    evidence_bytes jsonb NOT NULL,
    content_digest text NOT NULL CHECK (content_digest ~ '^sha256:[0-9a-f]{64}$'),
    recorded_at timestamptz NOT NULL,
    PRIMARY KEY (workspace_id, project_id, run_id, evidence_sequence),
    UNIQUE (workspace_id, project_id, evidence_id)
);

-- Recorded evidence is history: rewriting or deleting a row would falsify the
-- execution record integrity the digest attests.
CREATE OR REPLACE FUNCTION agent_evidence.guard_records() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    RAISE EXCEPTION 'recorded evidence is immutable';
END $$;
DROP TRIGGER IF EXISTS evidence_records_immutable ON agent_evidence.records;
CREATE TRIGGER evidence_records_immutable
    BEFORE UPDATE OR DELETE ON agent_evidence.records
    FOR EACH ROW EXECUTE FUNCTION agent_evidence.guard_records();

CREATE TABLE IF NOT EXISTS agent_evidence.access_audit (
    audit_id bigint GENERATED ALWAYS AS IDENTITY,
    workspace_id text NOT NULL,
    project_id text NOT NULL,
    run_id text NOT NULL,
    accessor text NOT NULL CHECK (length(accessor) BETWEEN 1 AND 128),
    purpose text NOT NULL CHECK (length(purpose) BETWEEN 1 AND 256),
    accessed_at timestamptz NOT NULL,
    PRIMARY KEY (audit_id)
);

REVOKE ALL ON SCHEMA agent_evidence FROM PUBLIC;
GRANT USAGE ON SCHEMA agent_evidence TO agent_authority_rw;
GRANT SELECT, INSERT ON agent_evidence.records TO agent_authority_rw;
GRANT INSERT ON agent_evidence.access_audit TO agent_authority_rw;
GRANT USAGE, SELECT ON SEQUENCE agent_evidence.access_audit_audit_id_seq TO agent_authority_rw;
