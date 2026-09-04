BEGIN;
DROP TABLE IF EXISTS platform.detection_exports, platform.detection_engine_checkpoints, platform.detection_health,
  platform.detection_finding_history, platform.detection_findings, platform.detection_window_events,
  platform.detection_processed_events, platform.detection_runs, platform.detection_rule_tests,
  platform.detection_exclusions, platform.detection_assignments, platform.detection_definition_versions,
  platform.detection_definitions CASCADE;
COMMIT;
