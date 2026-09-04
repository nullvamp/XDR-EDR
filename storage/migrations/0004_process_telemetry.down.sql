BEGIN;
DROP TABLE IF EXISTS platform.process_telemetry_health;
DROP TABLE IF EXISTS platform.process_entities;
DROP TABLE IF EXISTS platform.process_events;
DROP TABLE IF EXISTS platform.process_batches;
DELETE FROM platform.schema_migrations WHERE version='0004_process_telemetry';
COMMIT;
