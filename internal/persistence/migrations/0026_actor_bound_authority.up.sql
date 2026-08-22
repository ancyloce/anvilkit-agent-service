-- Authority that answers for one person is bound to that person. The scope's
-- grants are dispatch authority every actor in the workspace shares, which is
-- the right shape for what a run may direct a tool to do and the wrong shape
-- for whether one named actor may freeze or destroy an artifact, or read
-- internal evidence. Those are carried on the subject register beside the role
-- it already admits the actor under, so admitting one custodian grants nothing
-- to anyone else.
ALTER TABLE agent_control.authority_subjects
    ADD COLUMN IF NOT EXISTS capabilities text[] NOT NULL DEFAULT '{}',
    ADD COLUMN IF NOT EXISTS data_classes text[] NOT NULL DEFAULT '{}';
