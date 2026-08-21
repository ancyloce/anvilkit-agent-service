DROP INDEX IF EXISTS agent_evidence.evidence_access_audit_run_idx;
ALTER TABLE agent_evidence.access_audit DROP COLUMN IF EXISTS clearance;
DROP INDEX IF EXISTS agent_evidence.evidence_records_disclosable_idx;
