BEGIN;
DROP TABLE IF EXISTS platform.endpoint_isolation_state;
DROP TABLE IF EXISTS platform.endpoint_isolation_policies;
DELETE FROM platform.schema_migrations WHERE version='0023_endpoint_isolation';
COMMIT;
