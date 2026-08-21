-- The approval decision vocabulary is the canonical one. ADR-018 governs a
-- single first-party contract system, and both canonical Agent contracts that
-- name a review decision — SubmitApprovalDecisionRequest.decision and
-- ApprovalRequest.allowedDecisions — spell the third decision
-- 'request-changes'. The store admitted 'change', so the service could persist
-- a decision no canonical consumer can name. This is a pre-release coordinated
-- refactor: the stored vocabulary becomes the canonical one and the old value
-- stops being admissible, with no compatibility window and no dual vocabulary.

ALTER TABLE agent_control.approval_requests DROP CONSTRAINT IF EXISTS approval_requests_decision_check;
UPDATE agent_control.approval_requests SET decision='request-changes' WHERE decision='change';
ALTER TABLE agent_control.approval_requests
    ADD CONSTRAINT approval_requests_decision_check
    CHECK (decision IN ('approve','reject','request-changes'));
