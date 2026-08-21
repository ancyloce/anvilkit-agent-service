-- Every ended event-stream connection records the last public cursor it
-- successfully delivered, so a slow-consumer disconnect is diagnosable and
-- resumable from an operational record rather than from guesswork.
CREATE TABLE IF NOT EXISTS agent_events.stream_cursors (
    workspace_id text NOT NULL,
    project_id text NOT NULL,
    run_id text NOT NULL,
    connection_id text NOT NULL CHECK (length(connection_id) BETWEEN 1 AND 128),
    last_event_id text NOT NULL DEFAULT '',
    reason text NOT NULL CHECK (reason IN ('client-closed','slow-consumer','authority-revoked')),
    recorded_at timestamptz NOT NULL DEFAULT transaction_timestamp(),
    PRIMARY KEY (workspace_id, project_id, connection_id)
);

CREATE INDEX IF NOT EXISTS stream_cursors_run_idx ON agent_events.stream_cursors (workspace_id, project_id, run_id, recorded_at);

-- The public-cursor retention window sweeps by event age; give it an index
-- so expiry never scans the whole event store.
CREATE INDEX IF NOT EXISTS agent_events_created_idx ON agent_events.agent_events (created_at);

GRANT SELECT, INSERT ON agent_events.stream_cursors TO agent_events_rw, agent_authority_rw;
