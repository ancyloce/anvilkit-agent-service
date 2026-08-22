ALTER TABLE agent_control.authority_subjects
    DROP COLUMN IF EXISTS capabilities,
    DROP COLUMN IF EXISTS data_classes;
