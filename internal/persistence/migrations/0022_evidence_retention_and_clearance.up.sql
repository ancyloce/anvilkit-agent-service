-- Evidence retention and read clearance (ADR-020 §5).
--
-- The disclosure deadline is deliberately NOT stored. It is a function of
-- `recorded_at` and `retention_category`, and both of those are already
-- inside the document the integrity digest attests — so deriving the deadline
-- keeps it impossible for a stored deadline to disagree with the governed
-- window, and it needs no backfill of history that is immutable by trigger.
-- This index is what the derived filter reads.
CREATE INDEX IF NOT EXISTS evidence_records_disclosable_idx
    ON agent_evidence.records (workspace_id, project_id, run_id, retention_category, recorded_at);

-- Every read records the clearance it was made under, so an authorization
-- decision is reconstructable from the durable audit alone. Reads recorded
-- before clearance was captured leave it null rather than claiming a
-- clearance that was never presented: an audit trail must not assert a fact
-- that did not happen.
ALTER TABLE agent_evidence.access_audit
    ADD COLUMN IF NOT EXISTS clearance text
        CHECK (clearance IS NULL OR clearance IN ('public','internal','confidential','restricted'));

CREATE INDEX IF NOT EXISTS evidence_access_audit_run_idx
    ON agent_evidence.access_audit (workspace_id, project_id, run_id, accessed_at);
