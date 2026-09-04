-- Restores the 0029 vocabulary. This fails if a record carries one of the
-- kinds admitted since, which is the intended outcome: a rollback that would
-- orphan recorded artifacts is prohibited (PRD-CAT-0001 §13); migrate forward
-- instead.
ALTER TABLE agent_artifacts.metadata
    DROP CONSTRAINT IF EXISTS artifact_kind_values;

ALTER TABLE agent_artifacts.metadata
    ADD CONSTRAINT artifact_kind_values
    CHECK (kind IS NULL OR kind IN ('compiled-context','target-snapshot','agent-plan','worker-result','validation-report'));
