BEGIN;
DROP TABLE IF EXISTS platform.response_policies;
DROP TABLE IF EXISTS platform.response_artifacts;
DROP TRIGGER IF EXISTS response_audit_immutable ON platform.response_action_audit;
DROP FUNCTION IF EXISTS platform.reject_response_audit_mutation();
DROP TABLE IF EXISTS platform.response_action_audit;
DROP TABLE IF EXISTS platform.response_actions;
DELETE FROM platform.schema_migrations WHERE version='0021_response_engine';
COMMIT;
