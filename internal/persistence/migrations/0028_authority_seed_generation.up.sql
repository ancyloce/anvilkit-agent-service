-- Startup seeding is how a deployment's authority document reaches the
-- register, and it used to be an unconditional overwrite. Two things followed
-- from that, and both are ways authority silently comes back.
--
-- An instance still holding an older document — a replica that never restarted
-- through the change, one rolled back, one started from a stale config map —
-- wrote that older document over the newer one on its next start. And a
-- subject the operator had removed from the document stayed admitted, because
-- an upsert only ever writes the rows it is given.
--
-- The generation is the seed's own ordinal, carried in the document and
-- recorded here. A seed is applied only when it is strictly newer than the
-- generation already in force, so an older document is refused rather than
-- applied; the register's rows are then made to match that document exactly,
-- so a withdrawal is a withdrawal.
ALTER TABLE agent_control.authority_bindings
    ADD COLUMN IF NOT EXISTS seed_generation bigint NOT NULL DEFAULT 0
    CHECK (seed_generation >= 0);

-- The generation never moves backwards. A stale writer that gets past the
-- compare-and-set — a replayed statement, a hand-run update — still cannot
-- lower it, so the refusal does not depend on the application asking nicely.
CREATE OR REPLACE FUNCTION agent_control.guard_authority_seed_generation() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF NEW.seed_generation < OLD.seed_generation THEN
        RAISE EXCEPTION 'authority seed generation cannot move backwards (% -> %)', OLD.seed_generation, NEW.seed_generation;
    END IF;
    RETURN NEW;
END $$;

DROP TRIGGER IF EXISTS authority_seed_generation_is_monotonic ON agent_control.authority_bindings;
CREATE TRIGGER authority_seed_generation_is_monotonic
    BEFORE UPDATE ON agent_control.authority_bindings
    FOR EACH ROW EXECUTE FUNCTION agent_control.guard_authority_seed_generation();
