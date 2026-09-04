-- The artifact-kind registry is the authority for what an artifact may be
-- (CAT-FR-003), and the canonical AgentArtifact schema now mirrors it in full.
-- The CHECK written in 0029 mirrored the schema of its day, which carried only
-- the first five kinds; every artifact of another governed kind — a catalog
-- snapshot, a page candidate, a preview task or result, a component design,
-- intent, or IR — was either refused by the database or recorded under a
-- stand-in kind. The list below is the registry's, in registry order, and
-- internal/artifacts holds it to the pinned schema in a test.
ALTER TABLE agent_artifacts.metadata
    DROP CONSTRAINT IF EXISTS artifact_kind_values;

ALTER TABLE agent_artifacts.metadata
    ADD CONSTRAINT artifact_kind_values
    CHECK (kind IS NULL OR kind IN ('compiled-context','target-snapshot','agent-plan','worker-result','validation-report','catalog-snapshot','page-candidate','page-preview-task','page-preview-result','component-design-spec','component-intent','component-ir'));
