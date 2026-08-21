CREATE OR REPLACE FUNCTION agent_control.guard_budget_reservation() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF (NEW.workspace_id,NEW.project_id,NEW.root_run_id,NEW.run_id,NEW.reservation_id,NEW.controller_generation,NEW.policy_version,NEW.budget_version,NEW.expires_at,NEW.created_at)
       IS DISTINCT FROM
       (OLD.workspace_id,OLD.project_id,OLD.root_run_id,OLD.run_id,OLD.reservation_id,OLD.controller_generation,OLD.policy_version,OLD.budget_version,OLD.expires_at,OLD.created_at) THEN
        RAISE EXCEPTION 'budget reservation identity is immutable';
    END IF;
    IF NEW.updated_at < OLD.updated_at OR NEW.observed_micros < OLD.observed_micros OR NEW.upper_bound_micros > OLD.upper_bound_micros OR (OLD.attempt_final AND NOT NEW.attempt_final) OR (OLD.released AND NOT NEW.released) THEN
        RAISE EXCEPTION 'budget reservation settlement is monotonic';
    END IF;
    IF OLD.expired AND NOT NEW.expired THEN
        RAISE EXCEPTION 'budget reservation expiry fencing is irreversible';
    END IF;
    IF NEW.upper_bound_micros < OLD.upper_bound_micros AND NOT NEW.attempt_final THEN
        RAISE EXCEPTION 'budget reservation cannot reconcile before finality';
    END IF;
    IF NEW.released AND NOT NEW.attempt_final THEN
        RAISE EXCEPTION 'budget reservation cannot release before attempt finality';
    END IF;
    IF OLD.released AND (NEW.upper_bound_micros,NEW.observed_micros,NEW.attempt_final,NEW.released,NEW.expired) IS DISTINCT FROM (OLD.upper_bound_micros,OLD.observed_micros,OLD.attempt_final,OLD.released,OLD.expired) THEN
        RAISE EXCEPTION 'released budget reservation is immutable';
    END IF;
    RETURN NEW;
END $$;

DROP INDEX IF EXISTS agent_control.budget_reservations_cancellation_idx;

ALTER TABLE agent_control.budget_reservations DROP COLUMN IF EXISTS cancelled;
