DROP TABLE IF EXISTS agent_evidence.access_audit;
DROP TRIGGER IF EXISTS evidence_records_immutable ON agent_evidence.records;
DROP FUNCTION IF EXISTS agent_evidence.guard_records();
DROP TABLE IF EXISTS agent_evidence.records;
DROP SCHEMA IF EXISTS agent_evidence;
