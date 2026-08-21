DROP TRIGGER IF EXISTS commit_issuances_immutable ON agent_control.commit_issuances;
DROP FUNCTION IF EXISTS agent_control.guard_commit_issuances();
DROP TABLE IF EXISTS agent_control.commit_issuances;
