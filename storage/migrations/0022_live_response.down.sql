BEGIN;
DROP TABLE IF EXISTS platform.live_response_artifacts;
DROP TRIGGER IF EXISTS live_transcript_immutable ON platform.live_response_transcript;
DROP FUNCTION IF EXISTS platform.reject_live_transcript_mutation();
DROP TABLE IF EXISTS platform.live_response_transcript;
DROP TABLE IF EXISTS platform.live_response_commands;
DROP TABLE IF EXISTS platform.live_response_sessions;
DELETE FROM platform.schema_migrations WHERE version='0022_live_response';
COMMIT;
