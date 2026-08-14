DROP INDEX IF EXISTS agent_control.domain_operations_active_run_idx;
DROP INDEX IF EXISTS agent_artifacts.artifact_pending_reconcile_idx;
DROP INDEX IF EXISTS agent_evaluation.validation_evidence_run_idx;
DROP INDEX IF EXISTS agent_control.budget_reservations_root_idx;
DROP TRIGGER IF EXISTS artifact_metadata_lifecycle ON agent_artifacts.metadata;
DROP FUNCTION IF EXISTS agent_artifacts.guard_metadata_lifecycle();
DROP TRIGGER IF EXISTS budget_reservation_guard ON agent_control.budget_reservations;
DROP FUNCTION IF EXISTS agent_control.guard_budget_reservation();
DROP TRIGGER IF EXISTS domain_operation_identity ON agent_control.domain_operations;
DROP FUNCTION IF EXISTS agent_control.guard_domain_operation_identity();
DROP TABLE IF EXISTS agent_control.domain_operations;
DROP TABLE IF EXISTS agent_control.apply_authorizations;
DROP TABLE IF EXISTS agent_artifacts.access_grants;
ALTER TABLE agent_artifacts.metadata
    DROP CONSTRAINT IF EXISTS artifact_state_values,
    DROP CONSTRAINT IF EXISTS artifact_actual_digest_format,
    DROP CONSTRAINT IF EXISTS artifact_digest_format,
    DROP COLUMN IF EXISTS deletion_reason,
    DROP COLUMN IF EXISTS deleted_at,
    DROP COLUMN IF EXISTS legal_hold,
    DROP COLUMN IF EXISTS schema_identity,
    DROP COLUMN IF EXISTS object_reference,
    DROP COLUMN IF EXISTS version,
    DROP COLUMN IF EXISTS actual_digest;
DROP TABLE IF EXISTS agent_evaluation.validation_evidence;
DROP TABLE IF EXISTS agent_control.usage_observations;
DROP TABLE IF EXISTS agent_control.budget_reservations;
