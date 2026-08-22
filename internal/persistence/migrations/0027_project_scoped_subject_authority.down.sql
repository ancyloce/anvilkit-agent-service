-- Rolling back returns the register to a workspace-wide admission, which
-- cannot represent an actor admitted differently in two projects. Collapsing
-- such an actor onto one row would either widen one project's grant across
-- the workspace or silently drop the other, and both are decisions this
-- migration has no standing to make.
--
-- So the register is emptied instead. It is deployment configuration rather
-- than accumulated state: the next startup seeds it again from the operator's
-- authority document, and until then no actor holds a role, a capability, or
-- a clearance — which is the safe direction to be wrong in.
DELETE FROM agent_control.authority_subjects;

ALTER TABLE agent_control.authority_subjects
    DROP CONSTRAINT IF EXISTS authority_subjects_pkey;
ALTER TABLE agent_control.authority_subjects
    DROP COLUMN IF EXISTS project_id;
ALTER TABLE agent_control.authority_subjects
    ADD CONSTRAINT authority_subjects_pkey PRIMARY KEY (workspace_id, actor_id);
