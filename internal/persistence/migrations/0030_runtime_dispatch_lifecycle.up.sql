-- The durable record of work handed to a runtime release.
--
-- Two facts were previously the same fact. A turn was a model call the service
-- made itself, so "the work" and "the execution of the work" could not come
-- apart: there was nothing to recover, nothing to replace, and nothing a late
-- answer could contradict. Dispatching a turn to a separate process separates
-- them permanently. The logical task is what the run asked for; a physical
-- attempt is one execution of it. A retry, a restart, or a runtime that
-- disappears mid-flight produces another attempt of the same task -- never
-- another task -- and only the current attempt may change state.
--
-- The raw fence token is a commit capability. It travels with the task and
-- comes back in the result; only its digest is written here, so a reader of
-- this schema can prove which attempt a result belongs to without being handed
-- the capability to commit one.
CREATE TABLE IF NOT EXISTS agent_workflow.runtime_tasks (
 workspace_id text NOT NULL, project_id text NOT NULL, task_id text NOT NULL,
 run_id text NOT NULL, root_run_id text NOT NULL,
 execution_generation bigint NOT NULL CHECK(execution_generation>0),
 definition_digest text NOT NULL CHECK(definition_digest ~ '^sha256:[0-9a-f]{64}$'),
 -- The runtime release is pinned on the task, not read per attempt: a
 -- replacement attempt of an existing task must reach the same release the
 -- work was admitted against, whatever the registry now selects.
 runtime_unit_id text NOT NULL CHECK(length(runtime_unit_id) BETWEEN 1 AND 128),
 runtime_manifest_digest text NOT NULL CHECK(runtime_manifest_digest ~ '^sha256:[0-9a-f]{64}$'),
 runtime_image_digest text NOT NULL CHECK(runtime_image_digest ~ '^sha256:[0-9a-f]{64}$'),
 invocation_protocol_digest text NOT NULL CHECK(invocation_protocol_digest ~ '^sha256:[0-9a-f]{64}$'),
 runtime_audience text NOT NULL CHECK(length(runtime_audience) BETWEEN 1 AND 256),
 capability text NOT NULL CHECK(length(capability) BETWEEN 1 AND 128),
 -- request_digest is the canonical digest of what was asked, independent of
 -- which attempt carries it. A replay that reaches the same task identity with
 -- different content is a reused identity, not a retry, and is refused.
 request_digest text NOT NULL CHECK(request_digest ~ '^sha256:[0-9a-f]{64}$'),
 status text NOT NULL CHECK(status IN('accepted','running','succeeded','failed','expired','canceled')),
 attempts bigint NOT NULL DEFAULT 0 CHECK(attempts>=0),
 lease_epoch bigint NOT NULL DEFAULT 0 CHECK(lease_epoch>=0),
 expires_at timestamptz NOT NULL,
 created_at timestamptz NOT NULL, updated_at timestamptz NOT NULL DEFAULT transaction_timestamp(),
 PRIMARY KEY(workspace_id,project_id,task_id));

-- One execution of one logical task.
--
-- A task's own status cannot be 'superseded': what a replacement supersedes is
-- an execution, not the work. The work stays accepted until an execution of it
-- reaches a terminal state, which is why the two vocabularies differ by exactly
-- that one value.
CREATE TABLE IF NOT EXISTS agent_workflow.runtime_attempts (
 workspace_id text NOT NULL, project_id text NOT NULL, physical_attempt_id text NOT NULL,
 task_id text NOT NULL,
 attempt_number bigint NOT NULL CHECK(attempt_number>0),
 lease_epoch bigint NOT NULL CHECK(lease_epoch>0),
 fence_token_digest text NOT NULL CHECK(fence_token_digest ~ '^sha256:[0-9a-f]{64}$'),
 runtime_unit_id text NOT NULL CHECK(length(runtime_unit_id) BETWEEN 1 AND 128),
 dispatch_status text NOT NULL CHECK(dispatch_status IN('accepted','running','succeeded','failed','expired','canceled','superseded')),
 result_statement_digest text CHECK(result_statement_digest IS NULL OR result_statement_digest ~ '^sha256:[0-9a-f]{64}$'),
 signature_key_id text CHECK(signature_key_id IS NULL OR length(signature_key_id) BETWEEN 1 AND 256),
 failure_reason text CHECK(failure_reason IS NULL OR failure_reason ~ '^[A-Z][A-Z0-9_]{2,63}$'),
 dispatched_at timestamptz, started_at timestamptz, finished_at timestamptz,
 expires_at timestamptz NOT NULL,
 created_at timestamptz NOT NULL, updated_at timestamptz NOT NULL DEFAULT transaction_timestamp(),
 PRIMARY KEY(workspace_id,project_id,physical_attempt_id),
 UNIQUE(workspace_id,project_id,task_id,attempt_number),
 -- The lease epoch is monotonic per task, so an attempt cannot be issued under
 -- an epoch an earlier one already held.
 UNIQUE(workspace_id,project_id,task_id,lease_epoch),
 FOREIGN KEY(workspace_id,project_id,task_id) REFERENCES agent_workflow.runtime_tasks(workspace_id,project_id,task_id));

-- At most one attempt of a task may be current. The database holds this rather
-- than the code that opens attempts: two live executions of one task is exactly
-- the state a fence cannot rescue, because both would present a valid fence.
CREATE UNIQUE INDEX IF NOT EXISTS runtime_attempts_current_idx
 ON agent_workflow.runtime_attempts(workspace_id,project_id,task_id)
 WHERE dispatch_status IN('accepted','running');

-- The committed outcome of a logical task: one per task, ever.
--
-- Registration is part of the commit transaction, so a result that is recorded
-- is a result that changed state, and a result that changed state is recorded.
-- The statement digest is what makes redelivery of the same result idempotent
-- rather than a second commit.
--
-- The statement itself is kept, not only its digest, because a durable step
-- that committed and then failed before recording its own output has to be
-- re-executable: replaying it must return the answer the task already has
-- rather than execute the work a second time. A digest cannot answer that.
CREATE TABLE IF NOT EXISTS agent_workflow.runtime_results (
 workspace_id text NOT NULL, project_id text NOT NULL, task_id text NOT NULL,
 physical_attempt_id text NOT NULL,
 attempt_number bigint NOT NULL CHECK(attempt_number>0),
 lease_epoch bigint NOT NULL CHECK(lease_epoch>0),
 execution_generation bigint NOT NULL CHECK(execution_generation>0),
 result_statement_digest text NOT NULL CHECK(result_statement_digest ~ '^sha256:[0-9a-f]{64}$'),
 signature_key_id text NOT NULL CHECK(length(signature_key_id) BETWEEN 1 AND 256),
 statement jsonb NOT NULL CHECK(pg_column_size(statement) <= 1048576),
 status text NOT NULL CHECK(status IN('completed','failed','refused','cancelled')),
 reason_code text NOT NULL CHECK(reason_code ~ '^[A-Z][A-Z0-9_]{2,63}$'),
 committed_at timestamptz NOT NULL,
 PRIMARY KEY(workspace_id,project_id,task_id),
 UNIQUE(workspace_id,project_id,result_statement_digest),
 FOREIGN KEY(workspace_id,project_id,physical_attempt_id) REFERENCES agent_workflow.runtime_attempts(workspace_id,project_id,physical_attempt_id));

-- What a result did when it could not commit.
--
-- A late, duplicate, replaced, or unbound result is not an error to discard: it
-- is the only durable account of work a runtime actually performed. It is
-- written here and nowhere else, because the alternative -- letting it touch
-- the attempt it names -- is the duplicate commit the fence exists to stop.
CREATE TABLE IF NOT EXISTS agent_workflow.runtime_result_evidence (
 workspace_id text NOT NULL, project_id text NOT NULL,
 evidence_id bigint GENERATED ALWAYS AS IDENTITY,
 task_id text NOT NULL, run_id text NOT NULL, physical_attempt_id text NOT NULL,
 attempt_number bigint NOT NULL CHECK(attempt_number>=0),
 lease_epoch bigint NOT NULL CHECK(lease_epoch>=0),
 result_statement_digest text NOT NULL CHECK(result_statement_digest ~ '^sha256:[0-9a-f]{64}$'),
 signature_key_id text NOT NULL CHECK(length(signature_key_id) BETWEEN 1 AND 256),
 disposition text NOT NULL CHECK(disposition IN('duplicate','stale-fence','superseded','terminal','expired','canceled','unbound')),
 reason text NOT NULL CHECK(length(reason) BETWEEN 1 AND 512),
 recorded_at timestamptz NOT NULL,
 PRIMARY KEY(workspace_id,project_id,evidence_id));

CREATE INDEX IF NOT EXISTS runtime_result_evidence_task_idx
 ON agent_workflow.runtime_result_evidence(workspace_id,project_id,task_id,recorded_at);

GRANT SELECT, INSERT, UPDATE ON agent_workflow.runtime_tasks, agent_workflow.runtime_attempts TO agent_workflow_rw;
GRANT SELECT, INSERT ON agent_workflow.runtime_results, agent_workflow.runtime_result_evidence TO agent_workflow_rw;
