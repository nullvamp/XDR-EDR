CREATE TABLE IF NOT EXISTS platform.retention_policies (
 tenant_id uuid NOT NULL, policy_id uuid NOT NULL, version integer NOT NULL CHECK(version>0),
 category text NOT NULL, authority_days integer NOT NULL CHECK(authority_days BETWEEN 1 AND 36500),
 projection_days integer NOT NULL CHECK(projection_days BETWEEN 1 AND 36500),
 batch_size integer NOT NULL CHECK(batch_size BETWEEN 1 AND 5000), archive_before_delete boolean NOT NULL,
 enabled boolean NOT NULL, created_at timestamptz NOT NULL, created_by text NOT NULL,
 previous_hash text NOT NULL, policy_hash text NOT NULL, PRIMARY KEY(tenant_id,policy_id,version));
CREATE UNIQUE INDEX IF NOT EXISTS ux_retention_policy_category_version ON platform.retention_policies(tenant_id,category,version);

CREATE TABLE IF NOT EXISTS platform.retention_holds (
 tenant_id uuid NOT NULL, hold_id uuid NOT NULL, hold_type text NOT NULL,
 category text NOT NULL, target_id text, reason text NOT NULL, active boolean NOT NULL,
 created_at timestamptz NOT NULL, expires_at timestamptz, created_by text NOT NULL,
 PRIMARY KEY(tenant_id,hold_id));
CREATE INDEX IF NOT EXISTS ix_retention_holds_active ON platform.retention_holds(tenant_id,category,active,expires_at);

CREATE TABLE IF NOT EXISTS platform.retention_previews (
 tenant_id uuid NOT NULL, preview_id uuid NOT NULL, policy_id uuid NOT NULL, policy_version integer NOT NULL,
 scope text NOT NULL, cutoff timestamptz NOT NULL, eligible_rows bigint NOT NULL, estimated_bytes bigint NOT NULL,
 held_rows bigint NOT NULL, preview_hash text NOT NULL, created_at timestamptz NOT NULL, expires_at timestamptz NOT NULL,
 PRIMARY KEY(tenant_id,preview_id));
CREATE TABLE IF NOT EXISTS platform.retention_runs (
 tenant_id uuid NOT NULL, run_id uuid NOT NULL, preview_id uuid NOT NULL, policy_id uuid NOT NULL,
 policy_version integer NOT NULL, state text NOT NULL, dry_run boolean NOT NULL, deleted_rows bigint NOT NULL,
 archived_rows bigint NOT NULL, held_rows bigint NOT NULL, started_at timestamptz NOT NULL,
 completed_at timestamptz, actor text NOT NULL, detail text NOT NULL, PRIMARY KEY(tenant_id,run_id));

CREATE TABLE IF NOT EXISTS platform.retention_fixture_records (
 tenant_id uuid NOT NULL, record_id uuid NOT NULL, category text NOT NULL, occurred_at timestamptz NOT NULL,
 payload_bytes integer NOT NULL CHECK(payload_bytes BETWEEN 1 AND 1048576), active_reference boolean NOT NULL,
 content_hash text NOT NULL, PRIMARY KEY(tenant_id,record_id));
CREATE INDEX IF NOT EXISTS ix_retention_fixture_cutoff ON platform.retention_fixture_records(tenant_id,category,occurred_at,record_id);

CREATE TABLE IF NOT EXISTS platform.archive_jobs (
 tenant_id uuid NOT NULL, archive_id uuid NOT NULL, policy_id uuid NOT NULL, policy_version integer NOT NULL,
 scope text NOT NULL, from_time timestamptz NOT NULL, to_time timestamptz NOT NULL, record_count bigint NOT NULL,
 schema_versions text[] NOT NULL, manifest_hash text NOT NULL, state text NOT NULL, created_at timestamptz NOT NULL,
 PRIMARY KEY(tenant_id,archive_id));
CREATE TABLE IF NOT EXISTS platform.cleanup_history (
 tenant_id uuid NOT NULL, cleanup_id uuid NOT NULL, category text NOT NULL, item_count bigint NOT NULL,
 bytes_reclaimed bigint NOT NULL, held_items bigint NOT NULL, state text NOT NULL, occurred_at timestamptz NOT NULL,
 actor text NOT NULL, detail text NOT NULL, PRIMARY KEY(tenant_id,cleanup_id));

CREATE TABLE IF NOT EXISTS platform.tenant_capacity_quotas (
 tenant_id uuid PRIMARY KEY, version integer NOT NULL CHECK(version>0), ingest_per_minute integer NOT NULL,
 search_per_minute integer NOT NULL, replay_per_minute integer NOT NULL, export_per_minute integer NOT NULL,
 forensic_per_minute integer NOT NULL, playbook_per_minute integer NOT NULL, update_per_minute integer NOT NULL,
 max_concurrent_forensic integer NOT NULL, max_concurrent_playbooks integer NOT NULL,
 created_at timestamptz NOT NULL, created_by text NOT NULL, policy_hash text NOT NULL);
CREATE TABLE IF NOT EXISTS platform.tenant_rate_windows (
 tenant_id uuid NOT NULL, category text NOT NULL, window_start timestamptz NOT NULL,
 request_count integer NOT NULL, rejected_count integer NOT NULL, updated_at timestamptz NOT NULL,
 PRIMARY KEY(tenant_id,category,window_start));

CREATE TABLE IF NOT EXISTS platform.capacity_samples (
 sample_id uuid PRIMARY KEY, captured_at timestamptz NOT NULL, platform_version text NOT NULL,
 profile text NOT NULL, duration_seconds numeric NOT NULL, simulated_endpoints integer NOT NULL,
 native_agents integer NOT NULL, generated_events bigint NOT NULL, accepted_events bigint NOT NULL,
 rejected_events bigint NOT NULL, duplicate_events bigint NOT NULL, unexplained_loss bigint NOT NULL,
 events_per_second numeric NOT NULL, postgres_bytes bigint NOT NULL, opensearch_bytes bigint NOT NULL,
 minio_bytes bigint NOT NULL, nats_bytes bigint NOT NULL, environment jsonb NOT NULL, measurements jsonb NOT NULL);
CREATE TABLE IF NOT EXISTS platform.storage_domain_samples (
 sample_id uuid NOT NULL REFERENCES platform.capacity_samples(sample_id) ON DELETE CASCADE,
 domain text NOT NULL, record_count bigint NOT NULL, postgres_bytes bigint NOT NULL,
 opensearch_bytes bigint NOT NULL, minio_bytes bigint NOT NULL, PRIMARY KEY(sample_id,domain));

ALTER TABLE platform.retention_policies ENABLE ROW LEVEL SECURITY;
ALTER TABLE platform.retention_holds ENABLE ROW LEVEL SECURITY;
ALTER TABLE platform.retention_previews ENABLE ROW LEVEL SECURITY;
ALTER TABLE platform.retention_runs ENABLE ROW LEVEL SECURITY;
ALTER TABLE platform.retention_fixture_records ENABLE ROW LEVEL SECURITY;
ALTER TABLE platform.archive_jobs ENABLE ROW LEVEL SECURITY;
ALTER TABLE platform.cleanup_history ENABLE ROW LEVEL SECURITY;
ALTER TABLE platform.tenant_capacity_quotas ENABLE ROW LEVEL SECURITY;

