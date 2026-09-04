BEGIN;

CREATE TABLE IF NOT EXISTS platform.correlation_packs(
  tenant_id uuid NOT NULL REFERENCES platform.tenants(id), pack_id uuid NOT NULL, version integer NOT NULL,
  pack_data jsonb NOT NULL, validation_passed boolean NOT NULL, enabled boolean NOT NULL,
  created_at timestamptz NOT NULL, created_by text NOT NULL, PRIMARY KEY(tenant_id,pack_id,version));
CREATE INDEX IF NOT EXISTS correlation_packs_active_idx ON platform.correlation_packs(tenant_id,enabled,pack_id,version DESC);

CREATE TABLE IF NOT EXISTS platform.correlation_rules(
  tenant_id uuid NOT NULL, correlation_rule_id uuid NOT NULL, version integer NOT NULL,
  pack_id uuid NOT NULL, pack_version integer NOT NULL, status text NOT NULL, enabled boolean NOT NULL,
  validation_passed boolean NOT NULL, validation_result jsonb NOT NULL DEFAULT '{}', definition jsonb NOT NULL,
  definition_sha256 text NOT NULL, activated_at timestamptz, deactivated_at timestamptz,
  created_at timestamptz NOT NULL, created_by text NOT NULL,
  PRIMARY KEY(tenant_id,correlation_rule_id,version));
CREATE INDEX IF NOT EXISTS correlation_rules_active_idx ON platform.correlation_rules(tenant_id,status,enabled,pack_id,pack_version);

CREATE TABLE IF NOT EXISTS platform.correlation_rule_tests(
  tenant_id uuid NOT NULL, correlation_rule_id uuid NOT NULL, version integer NOT NULL,
  fixture_name text NOT NULL, fixture_kind text NOT NULL, passed boolean NOT NULL,
  result jsonb NOT NULL, completed_at timestamptz NOT NULL,
  PRIMARY KEY(tenant_id,correlation_rule_id,version,fixture_name));

CREATE TABLE IF NOT EXISTS platform.correlation_assignments(
  tenant_id uuid NOT NULL, id uuid NOT NULL, pack_id uuid NOT NULL, pack_version integer NOT NULL,
  endpoint_id uuid, endpoint_group_id uuid, enabled boolean NOT NULL, created_at timestamptz NOT NULL, created_by text NOT NULL,
  PRIMARY KEY(tenant_id,id));
CREATE INDEX IF NOT EXISTS correlation_assignment_target_idx ON platform.correlation_assignments(tenant_id,pack_id,enabled,endpoint_id,endpoint_group_id);

CREATE TABLE IF NOT EXISTS platform.correlation_exclusions(
  tenant_id uuid NOT NULL, id uuid NOT NULL, version integer NOT NULL, pack_id uuid, correlation_rule_id uuid,
  field_name text NOT NULL, field_value text NOT NULL, starts_at timestamptz NOT NULL, ends_at timestamptz NOT NULL,
  reason text NOT NULL, created_by text NOT NULL, match_count bigint NOT NULL DEFAULT 0, created_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY(tenant_id,id,version));

CREATE TABLE IF NOT EXISTS platform.correlation_processed_observations(
  tenant_id uuid NOT NULL, correlation_rule_id uuid NOT NULL, version integer NOT NULL,
  execution_mode text NOT NULL, run_id uuid NOT NULL DEFAULT '00000000-0000-0000-0000-000000000000',
  observation_id uuid NOT NULL, processed_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY(tenant_id,correlation_rule_id,version,execution_mode,run_id,observation_id));

CREATE TABLE IF NOT EXISTS platform.correlation_observations(
  tenant_id uuid NOT NULL REFERENCES platform.tenants(id), observation_id uuid NOT NULL,
  event_time timestamptz NOT NULL, observation jsonb NOT NULL, created_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY(tenant_id,observation_id));
CREATE INDEX IF NOT EXISTS correlation_observations_replay_idx ON platform.correlation_observations(tenant_id,event_time,observation_id);

CREATE TABLE IF NOT EXISTS platform.correlation_state_observations(
  tenant_id uuid NOT NULL, correlation_rule_id uuid NOT NULL, version integer NOT NULL,
  evaluation_scope text NOT NULL, correlation_key text NOT NULL, observation_id uuid NOT NULL,
  event_time timestamptz NOT NULL, expires_at timestamptz NOT NULL, observation jsonb NOT NULL,
  PRIMARY KEY(tenant_id,correlation_rule_id,version,evaluation_scope,correlation_key,observation_id));
CREATE INDEX IF NOT EXISTS correlation_state_expiry_idx ON platform.correlation_state_observations(tenant_id,expires_at);
CREATE INDEX IF NOT EXISTS correlation_state_lookup_idx ON platform.correlation_state_observations(tenant_id,correlation_rule_id,version,evaluation_scope,correlation_key,event_time);

CREATE TABLE IF NOT EXISTS platform.correlated_findings(
  tenant_id uuid NOT NULL, correlated_finding_id uuid NOT NULL, correlation_rule_id uuid NOT NULL, correlation_rule_version integer NOT NULL,
  pack_id uuid NOT NULL, pack_version integer NOT NULL, endpoint_id uuid, severity integer NOT NULL, confidence integer NOT NULL,
  first_seen timestamptz NOT NULL, last_seen timestamptz NOT NULL, correlation_key text NOT NULL,
  suppressed boolean NOT NULL, excluded boolean NOT NULL, execution_mode text NOT NULL,
  finding_data jsonb NOT NULL, created_at timestamptz NOT NULL, revision bigint NOT NULL DEFAULT 1,
  PRIMARY KEY(tenant_id,correlated_finding_id));
CREATE INDEX IF NOT EXISTS correlated_findings_search_idx ON platform.correlated_findings(tenant_id,created_at DESC,correlated_finding_id DESC);
CREATE INDEX IF NOT EXISTS correlated_findings_rule_idx ON platform.correlated_findings(tenant_id,correlation_rule_id,correlation_rule_version,correlation_key,last_seen DESC);

CREATE TABLE IF NOT EXISTS platform.correlated_finding_history(
  tenant_id uuid NOT NULL, correlated_finding_id uuid NOT NULL, sequence bigint GENERATED ALWAYS AS IDENTITY,
  action text NOT NULL, actor text NOT NULL, occurred_at timestamptz NOT NULL, data jsonb NOT NULL,
  PRIMARY KEY(tenant_id,correlated_finding_id,sequence));

CREATE TABLE IF NOT EXISTS platform.correlation_runs(
  tenant_id uuid NOT NULL, id uuid NOT NULL, correlation_rule_id uuid NOT NULL, rule_version integer NOT NULL,
  pack_id uuid NOT NULL, pack_version integer NOT NULL, mode text NOT NULL, from_time timestamptz NOT NULL, to_time timestamptz NOT NULL,
  status text NOT NULL, observations_total bigint NOT NULL, observations_evaluated bigint NOT NULL DEFAULT 0,
  findings bigint NOT NULL DEFAULT 0, production_findings boolean NOT NULL DEFAULT false,
  rule_snapshot jsonb NOT NULL, cancel_requested boolean NOT NULL DEFAULT false,
  created_at timestamptz NOT NULL, completed_at timestamptz, PRIMARY KEY(tenant_id,id));
CREATE INDEX IF NOT EXISTS correlation_runs_status_idx ON platform.correlation_runs(tenant_id,status,created_at DESC);

CREATE TABLE IF NOT EXISTS platform.correlation_health(
  tenant_id uuid PRIMARY KEY, health_data jsonb NOT NULL, updated_at timestamptz NOT NULL);

CREATE TABLE IF NOT EXISTS platform.correlation_exports(
  tenant_id uuid NOT NULL, id uuid NOT NULL, format text NOT NULL, record_count integer NOT NULL,
  output_object_id uuid NOT NULL, manifest_object_id uuid NOT NULL, output_sha256 text NOT NULL,
  created_at timestamptz NOT NULL, created_by text NOT NULL, PRIMARY KEY(tenant_id,id));

COMMIT;
