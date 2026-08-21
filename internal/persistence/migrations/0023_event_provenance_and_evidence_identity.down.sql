REVOKE SELECT (workspace_id, project_id, run_id, evidence_id) ON agent_evidence.records FROM agent_events_rw;
REVOKE USAGE ON SCHEMA agent_evidence FROM agent_events_rw;
DROP TRIGGER IF EXISTS event_provenance_immutable ON agent_events.event_provenance;
DROP FUNCTION IF EXISTS agent_events.guard_event_provenance();
DROP INDEX IF EXISTS agent_events.event_provenance_evidence_idx;
DROP TABLE IF EXISTS agent_events.event_provenance;
ALTER TABLE agent_evidence.records DROP CONSTRAINT IF EXISTS evidence_run_identity;
ALTER TABLE agent_events.agent_events DROP CONSTRAINT IF EXISTS agent_events_run_identity;
ALTER TABLE agent_evidence.records DROP CONSTRAINT IF EXISTS evidence_document_attests_its_row;
