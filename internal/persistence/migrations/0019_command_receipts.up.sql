-- ADR-021 §4 receipts for a command whose work is not a single database
-- transaction. Such a command claims its key first and records its outcome
-- afterwards, so the claim needs three facts the single-transaction form never
-- needed: when it was claimed, so a command that died mid-flight cannot block
-- its own retry for ever; the response ETag, so a replay reproduces the
-- concurrency token and not only the body; and the run the receipt belongs to,
-- so a key replayed against a different resource conflicts instead of
-- answering with another resource's recorded outcome.
ALTER TABLE agent_control.write_idempotency
    ADD COLUMN IF NOT EXISTS reserved_at timestamptz NOT NULL DEFAULT transaction_timestamp(),
    ADD COLUMN IF NOT EXISTS response_etag text NOT NULL DEFAULT '',
    ADD COLUMN IF NOT EXISTS run_id text NOT NULL DEFAULT '';
