REVOKE USAGE, SELECT ON SEQUENCE agent_evaluation.tool_decisions_decision_id_seq FROM agent_authority_rw;
REVOKE SELECT, INSERT ON agent_evaluation.tool_decisions FROM agent_authority_rw;
REVOKE USAGE ON SCHEMA agent_evaluation FROM agent_authority_rw;
