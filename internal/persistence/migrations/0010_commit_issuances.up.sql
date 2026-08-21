-- One durable commit operation issues exactly one apply authorization. This
-- insert-once record is what a crash replay between issuance and the run's
-- commit-proof transition reads instead of minting a second authorization, so
-- the identity the run pins is the identity the domain effect carries.
CREATE TABLE IF NOT EXISTS agent_control.commit_issuances (
    workspace_id text NOT NULL,
    project_id text NOT NULL,
    run_id text NOT NULL,
    operation_key text NOT NULL CHECK (length(operation_key) BETWEEN 1 AND 512),
    authorization_id text NOT NULL,
    issued_at timestamptz NOT NULL DEFAULT transaction_timestamp(),
    PRIMARY KEY (workspace_id, project_id, operation_key),
    UNIQUE (workspace_id, project_id, authorization_id),
    FOREIGN KEY (workspace_id, project_id, authorization_id) REFERENCES agent_control.apply_authorizations(workspace_id, project_id, authorization_id)
);

-- A recorded issuance is history. Rewriting or deleting one would let a
-- replayed commit operation carry a different authorization than the run's
-- durable commit proof recorded.
CREATE OR REPLACE FUNCTION agent_control.guard_commit_issuances() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    RAISE EXCEPTION 'recorded commit issuances are immutable';
END $$;
DROP TRIGGER IF EXISTS commit_issuances_immutable ON agent_control.commit_issuances;
CREATE TRIGGER commit_issuances_immutable
    BEFORE UPDATE OR DELETE ON agent_control.commit_issuances
    FOR EACH ROW EXECUTE FUNCTION agent_control.guard_commit_issuances();

GRANT SELECT, INSERT ON agent_control.commit_issuances TO agent_control_rw, agent_authority_rw;
