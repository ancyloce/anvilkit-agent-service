-- Durable ownership of an artifact's destruction.
--
-- Deleting an artifact revokes its grants and destroys its bytes, and those
-- acts cannot be undone. They were performed before the metadata had been
-- moved out of its live state, so a legal hold or any other version change
-- that landed in between left the record live — readable, holdable, still
-- naming an object whose bytes no longer existed.
--
-- Ownership is taken first, by compare-and-set on the version, and it carries
-- the artifact out of every live state in the same statement. Nothing is
-- revoked or destroyed until that row is committed, so a concurrent hold
-- either wins the version and stops the deletion outright, or arrives after
-- the artifact has already left the live states and is refused here.
ALTER TABLE agent_artifacts.metadata
    ADD COLUMN IF NOT EXISTS deletion_claim text,
    ADD COLUMN IF NOT EXISTS deletion_claimed_at timestamptz;

ALTER TABLE agent_artifacts.metadata
    ADD CONSTRAINT artifact_deletion_claim_format
    CHECK (deletion_claim IS NULL OR deletion_claim ~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$');

CREATE OR REPLACE FUNCTION agent_artifacts.guard_deletion_claim() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF NEW.deletion_claim IS NOT NULL AND NEW.deletion_claimed_at IS NULL THEN
        RAISE EXCEPTION 'an artifact deletion claim must record when it was taken';
    END IF;
    IF NEW.deletion_claim IS NOT NULL AND NEW.state NOT IN ('quarantined','expired','deleted') THEN
        RAISE EXCEPTION 'a claimed artifact deletion cannot leave the artifact live';
    END IF;
    IF TG_OP = 'UPDATE' THEN
        IF OLD.deletion_claim IS NOT NULL AND NEW.deletion_claim IS DISTINCT FROM OLD.deletion_claim THEN
            RAISE EXCEPTION 'artifact deletion ownership is immutable';
        END IF;
        IF NEW.deletion_claim IS NOT NULL AND OLD.deletion_claim IS NULL AND OLD.legal_hold THEN
            RAISE EXCEPTION 'artifact deletion cannot be claimed while a legal hold stands';
        END IF;
        IF OLD.deletion_claim IS NOT NULL AND NEW.legal_hold AND NOT OLD.legal_hold THEN
            RAISE EXCEPTION 'a legal hold cannot be placed on an artifact whose deletion is already owned';
        END IF;
    END IF;
    RETURN NEW;
END $$;

DROP TRIGGER IF EXISTS artifact_metadata_deletion_claim ON agent_artifacts.metadata;
CREATE TRIGGER artifact_metadata_deletion_claim
    BEFORE INSERT OR UPDATE ON agent_artifacts.metadata
    FOR EACH ROW EXECUTE FUNCTION agent_artifacts.guard_deletion_claim();
