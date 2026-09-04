BEGIN;
DROP TABLE IF EXISTS platform.process_policy_audit;
ALTER TABLE platform.process_telemetry_health DROP COLUMN IF EXISTS excluded_events, DROP COLUMN IF EXISTS last_exclusion_rule_id, DROP COLUMN IF EXISTS last_exclusion_category, DROP COLUMN IF EXISTS last_exclusion_at;
DROP TABLE IF EXISTS platform.process_exclusion_metrics;
DROP TABLE IF EXISTS platform.process_policy_acknowledgements;
DROP TABLE IF EXISTS platform.process_policy_assignments;
DROP TABLE IF EXISTS platform.process_policy_versions;
DELETE FROM platform.schema_migrations WHERE version='0005_process_policy';
COMMIT;
