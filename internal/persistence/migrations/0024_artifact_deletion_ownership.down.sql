DROP TRIGGER IF EXISTS artifact_metadata_deletion_claim ON agent_artifacts.metadata;
DROP FUNCTION IF EXISTS agent_artifacts.guard_deletion_claim();

ALTER TABLE agent_artifacts.metadata
    DROP CONSTRAINT IF EXISTS artifact_deletion_claim_format;

ALTER TABLE agent_artifacts.metadata
    DROP COLUMN IF EXISTS deletion_claim,
    DROP COLUMN IF EXISTS deletion_claimed_at;
