-- The Tool Guard records its durable decision evidence and the pinned running
-- tool profile in one composition component. The authority role already spans
-- the control and workflow stores that component touches; this grant lets it
-- write the guard's decision evidence as well, so no permissive in-memory
-- recorder is ever needed in composition.
GRANT USAGE ON SCHEMA agent_evaluation TO agent_authority_rw;
GRANT SELECT, INSERT ON agent_evaluation.tool_decisions TO agent_authority_rw;
GRANT USAGE, SELECT ON SEQUENCE agent_evaluation.tool_decisions_decision_id_seq TO agent_authority_rw;
