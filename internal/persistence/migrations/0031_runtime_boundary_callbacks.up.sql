-- The durable record of the runtime boundary's two callback surfaces.
--
-- A dispatched attempt calls back — for a governed model invocation, or to
-- submit the candidate it produced — and the callback may land after the
-- process that dispatched it has been replaced. Both records are therefore
-- durable: the offer is what binds a presented credential to the exact task
-- this service dispatched, and the submission is the immutable document a
-- committed result's candidate is read back from. A submission held only in
-- memory would make every service restart between submission and commit turn a
-- valid run into a refusal.

-- The canonical task deliberately carries no tenant scope — scope travels on
-- the credential — so the offer is keyed by attempt identity alone.
CREATE TABLE IF NOT EXISTS agent_workflow.runtime_task_offers (
 physical_attempt_id text NOT NULL,
 -- The canonical task document exactly as dispatched. The boundary binds a
 -- credential to it and validates every callback against it; storing a
 -- projection would let the two drift.
 task_document jsonb NOT NULL,
 -- The compiled disclosure offered with the task. It is content the guardrail
 -- policy already governed for release to this attempt.
 compiled_context bytea NOT NULL,
 offered_at timestamptz NOT NULL,
 PRIMARY KEY(physical_attempt_id));

-- One immutable candidate record per (run, digest): however many attempts
-- submit the same bytes, they name the same artifact.
CREATE TABLE IF NOT EXISTS agent_workflow.runtime_artifact_submissions (
 workspace_id text NOT NULL, project_id text NOT NULL,
 run_id text NOT NULL, task_id text NOT NULL,
 physical_attempt_id text NOT NULL,
 artifact_id text NOT NULL CHECK(length(artifact_id) BETWEEN 1 AND 128),
 digest text NOT NULL CHECK(digest ~ '^sha256:[0-9a-f]{64}$'),
 media_type text NOT NULL, size_bytes bigint NOT NULL CHECK(size_bytes>=0),
 content bytea NOT NULL,
 execution_generation bigint NOT NULL, attempt_number bigint NOT NULL, lease_epoch bigint NOT NULL,
 submitted_at timestamptz NOT NULL,
 PRIMARY KEY(run_id, digest));
CREATE INDEX IF NOT EXISTS runtime_artifact_submissions_reference_idx
 ON agent_workflow.runtime_artifact_submissions(artifact_id, digest);

-- The per-attempt replay register: one submission per attempt identity. The
-- same attempt re-submitting the same bytes replays the recorded outcome; the
-- same attempt submitting different bytes is a conflict, never a replacement.
CREATE TABLE IF NOT EXISTS agent_workflow.runtime_submission_attempts (
 physical_attempt_id text NOT NULL,
 run_id text NOT NULL,
 digest text NOT NULL CHECK(digest ~ '^sha256:[0-9a-f]{64}$'),
 PRIMARY KEY(physical_attempt_id));

GRANT SELECT, INSERT, UPDATE ON agent_workflow.runtime_task_offers TO agent_workflow_rw;
GRANT SELECT, INSERT ON agent_workflow.runtime_artifact_submissions, agent_workflow.runtime_submission_attempts TO agent_workflow_rw;
