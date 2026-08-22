-- The write-idempotency receipt addresses more than one kind of resource: a
-- run for the governed run-control commands, and an artifact for a custody
-- decision. The column that carries which resource a key was claimed for is
-- named for that role rather than for the first kind of resource that used it,
-- so a receipt filed against an artifact is not recorded under a run's name.
ALTER TABLE agent_control.write_idempotency RENAME COLUMN run_id TO resource_id;
