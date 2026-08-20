ALTER TABLE agent_control.input_requests
    ADD COLUMN IF NOT EXISTS expired_at timestamptz;

ALTER TABLE agent_control.approval_requests
    ADD COLUMN IF NOT EXISTS expired_at timestamptz;

-- A request is either answered or expired, never both. The durable marker is
-- what makes acceptance and expiry mutually exclusive under contention.
ALTER TABLE agent_control.input_requests
    DROP CONSTRAINT IF EXISTS input_requests_response_xor_expiry;
ALTER TABLE agent_control.input_requests
    ADD CONSTRAINT input_requests_response_xor_expiry
    CHECK (responded_at IS NULL OR expired_at IS NULL);

ALTER TABLE agent_control.approval_requests
    DROP CONSTRAINT IF EXISTS approval_requests_decision_xor_expiry;
ALTER TABLE agent_control.approval_requests
    ADD CONSTRAINT approval_requests_decision_xor_expiry
    CHECK (decided_at IS NULL OR expired_at IS NULL);
