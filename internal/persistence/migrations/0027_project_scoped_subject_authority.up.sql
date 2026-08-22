-- Authority that answers for one person answers for them in one project.
--
-- The subject register bound a role, the capabilities that role's holder may
-- exercise, and the data classifications they are cleared for, to a workspace
-- and an actor. A workspace holds many projects, and every one of them read
-- the same row: an actor admitted as an artifact custodian to do one
-- project's work was an artifact custodian in every other project of that
-- workspace, cleared for their content and able to destroy their artifacts.
-- Nobody granted that, and nothing in the grant said it.
--
-- The project joins the register's identity, so an admission is an admission
-- to the project it was made in and to no other. The scoped binding already
-- keys on (workspace, project); the subject register now agrees with it.
ALTER TABLE agent_control.authority_subjects
    ADD COLUMN IF NOT EXISTS project_id text;

-- A workspace with exactly one bound project has only one project the
-- admission could ever have meant, so the existing row is narrowed to it
-- without changing what anyone may do.
UPDATE agent_control.authority_subjects AS subject
   SET project_id = single.project_id
  FROM (
        SELECT workspace_id, min(project_id) AS project_id, count(*) AS bindings
          FROM agent_control.authority_bindings
         GROUP BY workspace_id
       ) AS single
 WHERE single.workspace_id = subject.workspace_id
   AND single.bindings = 1
   AND subject.project_id IS NULL;

-- Anything left is an admission whose project cannot be determined: the
-- workspace binds several projects, or none. Narrowing it would require
-- choosing a project on the operator's behalf and widening it is the defect
-- being repaired, so the admission is withdrawn. Startup seeding re-admits
-- whatever the operator's authority document declares, now against an
-- explicit project.
DELETE FROM agent_control.authority_subjects WHERE project_id IS NULL;

ALTER TABLE agent_control.authority_subjects
    ALTER COLUMN project_id SET NOT NULL;

ALTER TABLE agent_control.authority_subjects
    DROP CONSTRAINT IF EXISTS authority_subjects_pkey;
ALTER TABLE agent_control.authority_subjects
    ADD CONSTRAINT authority_subjects_pkey PRIMARY KEY (workspace_id, project_id, actor_id);
