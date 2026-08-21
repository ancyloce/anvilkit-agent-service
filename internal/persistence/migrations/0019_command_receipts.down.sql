ALTER TABLE agent_control.write_idempotency
    DROP COLUMN IF EXISTS reserved_at,
    DROP COLUMN IF EXISTS response_etag,
    DROP COLUMN IF EXISTS run_id;
