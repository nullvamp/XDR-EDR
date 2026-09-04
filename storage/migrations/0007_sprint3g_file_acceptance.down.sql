BEGIN;
DROP TABLE IF EXISTS platform.file_export_jobs;
ALTER TABLE platform.file_telemetry_health DROP COLUMN IF EXISTS hash_metrics;
COMMIT;
