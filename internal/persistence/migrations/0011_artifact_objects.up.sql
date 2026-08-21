-- Immutable artifact bytes. Content is write-once: rewriting an object would
-- change what a recorded digest attests. Deletion stays legal because the
-- metadata lifecycle (tombstones, legal hold, reconciliation) governs it.
CREATE TABLE IF NOT EXISTS agent_artifacts.objects (
    bucket text NOT NULL CHECK (length(bucket) BETWEEN 1 AND 128),
    object_key text NOT NULL CHECK (length(object_key) BETWEEN 1 AND 512),
    bytes bytea NOT NULL,
    size_bytes bigint NOT NULL CHECK (size_bytes = octet_length(bytes)),
    media_type text NOT NULL CHECK (length(media_type) BETWEEN 1 AND 128),
    created_at timestamptz NOT NULL DEFAULT transaction_timestamp(),
    PRIMARY KEY (bucket, object_key)
);

CREATE OR REPLACE FUNCTION agent_artifacts.guard_object_bytes() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    RAISE EXCEPTION 'artifact object bytes are immutable';
END $$;
DROP TRIGGER IF EXISTS artifact_objects_immutable ON agent_artifacts.objects;
CREATE TRIGGER artifact_objects_immutable
    BEFORE UPDATE ON agent_artifacts.objects
    FOR EACH ROW EXECUTE FUNCTION agent_artifacts.guard_object_bytes();

GRANT SELECT, INSERT, DELETE ON agent_artifacts.objects TO agent_artifacts_rw;
