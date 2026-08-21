-- A command receipt is claimed in one transaction and recorded in another, so
-- the claim can change hands between the two: a claimant whose lease elapses is
-- taken over by the next request. Ownership therefore needs a fence the holder
-- carries, not just a timestamp the row carries. The claim epoch is that fence.
-- It advances on every transfer — the initial claim, a takeover, and a release
-- — so a holder that comes back late is recognized as stale and can neither
-- record over its successor's outcome nor release its successor's claim.
ALTER TABLE agent_control.write_idempotency
    ADD COLUMN IF NOT EXISTS claim_epoch bigint NOT NULL DEFAULT 1 CHECK (claim_epoch > 0);
