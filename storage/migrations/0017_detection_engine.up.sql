BEGIN;

CREATE TABLE IF NOT EXISTS platform.detection_definitions(
  tenant_id uuid NOT NULL REFERENCES platform.tenants(id), detection_id uuid NOT NULL,
  name text NOT NULL, current_version integer NOT NULL, status text NOT NULL, enabled boolean NOT NULL,
  created_at timestamptz NOT NULL, updated_at timestamptz NOT NULL,
  PRIMARY KEY(tenant_id,detection_id), UNIQUE(tenant_id,name));
CREATE TABLE IF NOT EXISTS platform.detection_definition_versions(
  tenant_id uuid NOT NULL, detection_id uuid NOT NULL, detection_version integer NOT NULL,
  status text NOT NULL, definition jsonb NOT NULL, definition_sha256 text NOT NULL,
  validation_passed boolean NOT NULL DEFAULT false, validation_result jsonb NOT NULL DEFAULT '{}',
  activated_at timestamptz, deactivated_at timestamptz, created_at timestamptz NOT NULL, created_by text NOT NULL,
  PRIMARY KEY(tenant_id,detection_id,detection_version),
  FOREIGN KEY(tenant_id,detection_id) REFERENCES platform.detection_definitions(tenant_id,detection_id));
CREATE INDEX IF NOT EXISTS detection_versions_status_idx ON platform.detection_definition_versions(tenant_id,status,detection_id,detection_version DESC);

CREATE TABLE IF NOT EXISTS platform.detection_assignments(
  tenant_id uuid NOT NULL, id uuid NOT NULL, detection_id uuid NOT NULL, detection_version integer NOT NULL,
  endpoint_id uuid, endpoint_group_id uuid, enabled boolean NOT NULL, created_at timestamptz NOT NULL, created_by text NOT NULL,
  PRIMARY KEY(tenant_id,id), FOREIGN KEY(tenant_id,detection_id,detection_version)
    REFERENCES platform.detection_definition_versions(tenant_id,detection_id,detection_version));
CREATE INDEX IF NOT EXISTS detection_assignment_target_idx ON platform.detection_assignments(tenant_id,detection_id,enabled,endpoint_id,endpoint_group_id);

CREATE TABLE IF NOT EXISTS platform.detection_exclusions(
  tenant_id uuid NOT NULL, id uuid NOT NULL, version integer NOT NULL, name text NOT NULL,
  field_name text NOT NULL, field_value text NOT NULL, case_insensitive boolean NOT NULL,
  starts_at timestamptz NOT NULL, ends_at timestamptz NOT NULL, reason text NOT NULL, created_by text NOT NULL,
  elevated_match_all_confirmation boolean NOT NULL DEFAULT false, match_count bigint NOT NULL DEFAULT 0,
  created_at timestamptz NOT NULL DEFAULT now(), PRIMARY KEY(tenant_id,id,version));
CREATE INDEX IF NOT EXISTS detection_exclusion_active_idx ON platform.detection_exclusions(tenant_id,starts_at,ends_at);

CREATE TABLE IF NOT EXISTS platform.detection_rule_tests(
  tenant_id uuid NOT NULL, detection_id uuid NOT NULL, detection_version integer NOT NULL,
  fixture_name text NOT NULL, fixture_kind text NOT NULL, fixture_version text NOT NULL,
  passed boolean NOT NULL, expected_findings integer NOT NULL, actual_findings integer NOT NULL,
  result jsonb NOT NULL, completed_at timestamptz NOT NULL,
  PRIMARY KEY(tenant_id,detection_id,detection_version,fixture_name));

CREATE TABLE IF NOT EXISTS platform.detection_runs(
  tenant_id uuid NOT NULL, id uuid NOT NULL, detection_id uuid NOT NULL, detection_version integer NOT NULL,
  mode text NOT NULL, from_time timestamptz NOT NULL, to_time timestamptz NOT NULL, status text NOT NULL,
  events_total bigint NOT NULL DEFAULT 0, events_evaluated bigint NOT NULL DEFAULT 0, matches bigint NOT NULL DEFAULT 0,
  findings bigint NOT NULL DEFAULT 0, production_findings boolean NOT NULL DEFAULT false,
  created_at timestamptz NOT NULL, completed_at timestamptz, cancel_requested boolean NOT NULL DEFAULT false, error text,
  definition_snapshot jsonb NOT NULL, PRIMARY KEY(tenant_id,id));
CREATE INDEX IF NOT EXISTS detection_runs_status_idx ON platform.detection_runs(tenant_id,status,created_at DESC);

CREATE TABLE IF NOT EXISTS platform.detection_processed_events(
  tenant_id uuid NOT NULL, detection_id uuid NOT NULL, detection_version integer NOT NULL,
  event_id uuid NOT NULL, mode text NOT NULL, run_id uuid NOT NULL DEFAULT '00000000-0000-0000-0000-000000000000', processed_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY(tenant_id,detection_id,detection_version,event_id,mode,run_id));
CREATE TABLE IF NOT EXISTS platform.detection_window_events(
  tenant_id uuid NOT NULL, detection_id uuid NOT NULL, detection_version integer NOT NULL,
  evaluation_scope text NOT NULL, group_key text NOT NULL, event_id uuid NOT NULL, event_time timestamptz NOT NULL,
  distinct_value text, evidence jsonb NOT NULL, expires_at timestamptz NOT NULL,
  PRIMARY KEY(tenant_id,detection_id,detection_version,evaluation_scope,group_key,event_id));
CREATE INDEX IF NOT EXISTS detection_window_expiry_idx ON platform.detection_window_events(tenant_id,expires_at);

CREATE TABLE IF NOT EXISTS platform.detection_findings(
  tenant_id uuid NOT NULL, finding_id uuid NOT NULL, detection_id uuid NOT NULL, detection_version integer NOT NULL,
  severity integer NOT NULL, confidence integer NOT NULL, first_seen timestamptz NOT NULL, last_seen timestamptz NOT NULL,
  event_count integer NOT NULL, group_key text NOT NULL, endpoint_id uuid, process_entity_id text, entity_id text,
  suppressed boolean NOT NULL, excluded boolean NOT NULL, execution_mode text NOT NULL,
  finding_data jsonb NOT NULL, created_at timestamptz NOT NULL, revision bigint NOT NULL DEFAULT 1,
  PRIMARY KEY(tenant_id,finding_id));
CREATE INDEX IF NOT EXISTS detection_findings_search_idx ON platform.detection_findings(tenant_id,created_at DESC,finding_id DESC);
CREATE INDEX IF NOT EXISTS detection_findings_rule_idx ON platform.detection_findings(tenant_id,detection_id,detection_version,group_key,last_seen DESC);

CREATE TABLE IF NOT EXISTS platform.detection_finding_history(
  tenant_id uuid NOT NULL, finding_id uuid NOT NULL, sequence bigint GENERATED ALWAYS AS IDENTITY,
  action text NOT NULL, actor text NOT NULL, occurred_at timestamptz NOT NULL, data jsonb NOT NULL,
  PRIMARY KEY(tenant_id,finding_id,sequence));
CREATE TABLE IF NOT EXISTS platform.detection_health(
  tenant_id uuid PRIMARY KEY, health_data jsonb NOT NULL, updated_at timestamptz NOT NULL);
CREATE TABLE IF NOT EXISTS platform.detection_engine_checkpoints(
  engine_name text PRIMARY KEY, last_outbox_created_at timestamptz NOT NULL, last_outbox_id uuid NOT NULL, updated_at timestamptz NOT NULL);

CREATE TABLE IF NOT EXISTS platform.detection_exports(
  tenant_id uuid NOT NULL, id uuid NOT NULL, state text NOT NULL, format text NOT NULL, query jsonb NOT NULL,
  maximum_records integer NOT NULL, output_object_id uuid NOT NULL, manifest_object_id uuid NOT NULL,
  metadata_object_id uuid NOT NULL, output_sha256 text, record_count integer NOT NULL DEFAULT 0,
  requested_by text NOT NULL, created_at timestamptz NOT NULL, updated_at timestamptz NOT NULL, expires_at timestamptz NOT NULL,
  error_code text, PRIMARY KEY(tenant_id,id));
CREATE INDEX IF NOT EXISTS detection_exports_state_idx ON platform.detection_exports(state,created_at);

COMMIT;
