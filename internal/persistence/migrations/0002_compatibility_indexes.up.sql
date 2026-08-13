CREATE INDEX IF NOT EXISTS agent_runs_updated_idx ON agent_control.agent_runs (workspace_id, project_id, updated_at DESC);
CREATE INDEX IF NOT EXISTS outbox_ready_idx ON agent_events.outbox (workspace_id, project_id, available_at) WHERE published_at IS NULL;
CREATE INDEX IF NOT EXISTS checkpoints_updated_idx ON agent_workflow.checkpoints (workspace_id, project_id, updated_at);
CREATE INDEX IF NOT EXISTS artifacts_run_idx ON agent_artifacts.metadata (workspace_id, project_id, run_id);
