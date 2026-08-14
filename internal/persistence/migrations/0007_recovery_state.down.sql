DROP TRIGGER IF EXISTS restore_stage_immutable ON agent_workflow.restore_stages;
DROP FUNCTION IF EXISTS agent_workflow.guard_restore_stage_immutable();
DROP TRIGGER IF EXISTS restore_drill_guard ON agent_workflow.restore_drills;
DROP FUNCTION IF EXISTS agent_workflow.guard_restore_drill();
DROP TRIGGER IF EXISTS recovery_state_guard ON agent_workflow.recovery_state;
DROP FUNCTION IF EXISTS agent_workflow.guard_recovery_state();
DROP TABLE IF EXISTS agent_workflow.restore_stages;
DROP TABLE IF EXISTS agent_workflow.restore_drills;
DROP TABLE IF EXISTS agent_workflow.recovery_state;
