ALTER TABLE agent_control.approval_requests DROP CONSTRAINT IF EXISTS approval_requests_decision_check;
UPDATE agent_control.approval_requests SET decision='change' WHERE decision='request-changes';
ALTER TABLE agent_control.approval_requests
    ADD CONSTRAINT approval_requests_decision_check
    CHECK (decision IN ('approve','reject','change'));
