-- Cancellation and terminal settlement revoke every open task of one run, and
-- the run is the one thing the logical-task record was not indexed by: the
-- primary key is the task identity, so revoking a run's leases scanned the
-- tenant's whole task set. The index makes the revocation cost proportional
-- to the run rather than to everything the tenant ever dispatched.
CREATE INDEX IF NOT EXISTS runtime_tasks_run_idx
 ON agent_workflow.runtime_tasks(workspace_id,project_id,run_id);
