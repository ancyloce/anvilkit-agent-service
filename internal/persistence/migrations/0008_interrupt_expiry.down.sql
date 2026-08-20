ALTER TABLE agent_control.approval_requests
    DROP CONSTRAINT IF EXISTS approval_requests_decision_xor_expiry;
ALTER TABLE agent_control.input_requests
    DROP CONSTRAINT IF EXISTS input_requests_response_xor_expiry;

ALTER TABLE agent_control.approval_requests
    DROP COLUMN IF EXISTS expired_at;
ALTER TABLE agent_control.input_requests
    DROP COLUMN IF EXISTS expired_at;
