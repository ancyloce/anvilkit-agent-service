-- The governed artifact representation names what an artifact is and what was
-- checked about it. The record held neither.
--
-- The canonical AgentArtifact contract requires a kind drawn from a closed
-- vocabulary and the validation that was performed — when, and which checks
-- passed against which evidence. Both were facts the pipeline already knew at
-- the moment the artifact was recorded: the Contract Runtime had just
-- validated the candidate against its pinned schema, contract BOM, and
-- guardrail policy, and that result was used and discarded. Serving an
-- artifact meant either withholding those fields, which no client could rely
-- on, or reconstructing them afterwards from something that was not the
-- record.
ALTER TABLE agent_artifacts.metadata
    ADD COLUMN IF NOT EXISTS kind text,
    ADD COLUMN IF NOT EXISTS validation jsonb;

-- Records written before the kind was carried have none, and none can be
-- invented for them: what an artifact is, is decided when it is produced.
-- The column therefore admits null and the representation of such a record is
-- refused rather than guessed.
ALTER TABLE agent_artifacts.metadata
    ADD CONSTRAINT artifact_kind_values
    CHECK (kind IS NULL OR kind IN ('compiled-context','target-snapshot','agent-plan','worker-result','validation-report'));
