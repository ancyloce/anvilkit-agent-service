-- Public-event provenance and evidence identity attestation (ADR-020 §2, §5).
--
-- Every durable public event now has a provenance record naming the
-- authoritative AgentEvidence it was projected from and the digest of the
-- projection ruleset that produced it, so a public fact can always be traced
-- back to the internal record that explains it and to the exact rules that
-- decided what was disclosed.
--
-- Provenance is a table rather than two columns on the event row because the
-- record must be complete or absent, never fabricated. A column added to a
-- populated table forces a default, and any default here would invent an
-- account of where an event came from; a row either exists with real
-- provenance or does not exist at all.

-- Evidence idempotency is decided on the stable identity of the fact its
-- producer recorded, and that identity is computed from the stored document.
-- This constraint is what makes reading it from the document safe: the row's
-- indexed columns must be exactly what the document attests, so a direct
-- column write can neither relabel a record nor move it to another run,
-- another tenant, or another position in the run's evidence sequence.
ALTER TABLE agent_evidence.records
    ADD CONSTRAINT evidence_document_attests_its_row CHECK (
        evidence_bytes ->> 'evidenceId' = evidence_id
        AND evidence_bytes ->> 'workspaceId' = workspace_id
        AND evidence_bytes ->> 'projectId' = project_id
        AND evidence_bytes ->> 'runId' = run_id
        AND evidence_bytes ->> 'evidenceType' = evidence_type
        AND evidence_bytes ->> 'dataClassification' = data_classification
        AND evidence_bytes ->> 'retentionCategory' = retention_category
        AND (evidence_bytes ->> 'evidenceSequence')::bigint = evidence_sequence
    );

-- The run-qualified identities the provenance foreign keys are declared
-- against. Both tables already hold these columns uniquely; naming them as
-- constraints is what lets a reference carry the run, so correlation is
-- enforced by the reference itself rather than re-checked beside it.
ALTER TABLE agent_events.agent_events
    ADD CONSTRAINT agent_events_run_identity UNIQUE (workspace_id, project_id, run_id, event_id);

ALTER TABLE agent_evidence.records
    ADD CONSTRAINT evidence_run_identity UNIQUE (workspace_id, project_id, run_id, evidence_id);

-- The provenance row is keyed by the public event and carries the run, so both
-- of its references are run-qualified: the event it explains must belong to
-- the run the row names, and the evidence it was projected from must exist in
-- the same workspace, the same project, and that same run. A provenance record
-- that points at an absent, foreign-tenant, or foreign-run fact is not a
-- weaker record — it is a false account of where a public fact came from, so
-- the database refuses it rather than storing it.
CREATE TABLE IF NOT EXISTS agent_events.event_provenance (
    workspace_id text NOT NULL,
    project_id text NOT NULL,
    run_id text NOT NULL,
    event_id text NOT NULL,
    evidence_id text NOT NULL CHECK (length(evidence_id) BETWEEN 1 AND 128),
    projector_digest text NOT NULL CHECK (projector_digest ~ '^sha256:[0-9a-f]{64}$'),
    recorded_at timestamptz NOT NULL DEFAULT transaction_timestamp(),
    PRIMARY KEY (workspace_id, project_id, event_id),
    CONSTRAINT event_provenance_explains_its_event FOREIGN KEY (workspace_id, project_id, run_id, event_id)
        REFERENCES agent_events.agent_events (workspace_id, project_id, run_id, event_id) ON DELETE CASCADE,
    CONSTRAINT event_provenance_names_source_evidence FOREIGN KEY (workspace_id, project_id, run_id, evidence_id)
        REFERENCES agent_evidence.records (workspace_id, project_id, run_id, evidence_id)
);

-- Tracing every public event one internal fact produced is a first-class read.
CREATE INDEX IF NOT EXISTS event_provenance_evidence_idx
    ON agent_events.event_provenance (workspace_id, project_id, evidence_id);

-- Provenance is history: rewriting it would falsify the account of where a
-- public fact came from.
CREATE OR REPLACE FUNCTION agent_events.guard_event_provenance() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    RAISE EXCEPTION 'recorded event provenance is immutable';
END $$;
DROP TRIGGER IF EXISTS event_provenance_immutable ON agent_events.event_provenance;
CREATE TRIGGER event_provenance_immutable
    BEFORE UPDATE ON agent_events.event_provenance
    FOR EACH ROW EXECUTE FUNCTION agent_events.guard_event_provenance();

GRANT SELECT, INSERT ON agent_events.event_provenance TO agent_events_rw, agent_authority_rw;

-- Replay proves every public event against its provenance and the evidence
-- that provenance names, so the reader of the public store must be able to see
-- that an evidence row exists in the run it claims. The grant is existence and
-- correlation only: the evidence document itself stays behind the stricter
-- authorization the internal registry keeps.
GRANT USAGE ON SCHEMA agent_evidence TO agent_events_rw;
GRANT SELECT (workspace_id, project_id, run_id, evidence_id) ON agent_evidence.records TO agent_events_rw;
