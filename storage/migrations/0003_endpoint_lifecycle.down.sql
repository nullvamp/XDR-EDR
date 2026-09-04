BEGIN;
DROP INDEX IF EXISTS platform.endpoints_lifecycle_scan_idx;
ALTER TABLE platform.endpoints DROP CONSTRAINT IF EXISTS endpoints_lifecycle_status_check;
DROP TABLE IF EXISTS platform.endpoint_status_history;
DELETE FROM platform.schema_migrations WHERE version='0003_endpoint_lifecycle';
COMMIT;
