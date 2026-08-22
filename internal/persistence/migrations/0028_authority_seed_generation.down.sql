DROP TRIGGER IF EXISTS authority_seed_generation_is_monotonic ON agent_control.authority_bindings;
DROP FUNCTION IF EXISTS agent_control.guard_authority_seed_generation();

ALTER TABLE agent_control.authority_bindings
    DROP COLUMN IF EXISTS seed_generation;
