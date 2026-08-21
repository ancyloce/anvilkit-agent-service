DROP TRIGGER IF EXISTS artifact_objects_immutable ON agent_artifacts.objects;
DROP FUNCTION IF EXISTS agent_artifacts.guard_object_bytes();
DROP TABLE IF EXISTS agent_artifacts.objects;
