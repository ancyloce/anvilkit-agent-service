ALTER TABLE agent_artifacts.metadata
    DROP CONSTRAINT IF EXISTS artifact_kind_values;

ALTER TABLE agent_artifacts.metadata
    DROP COLUMN IF EXISTS kind,
    DROP COLUMN IF EXISTS validation;
