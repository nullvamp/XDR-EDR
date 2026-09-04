CREATE TABLE IF NOT EXISTS platform.worker_leases (
 job_type text NOT NULL, job_id text NOT NULL, worker_id text NOT NULL,
 generation bigint NOT NULL CHECK(generation > 0), acquired_at timestamptz NOT NULL,
 expires_at timestamptz NOT NULL, heartbeat_at timestamptz NOT NULL,
 state text NOT NULL CHECK(state IN ('Owned','Released','Completed','Failed')),
 PRIMARY KEY(job_type,job_id));
CREATE TABLE IF NOT EXISTS platform.ha_audit (
 audit_id uuid PRIMARY KEY, event_type text NOT NULL, subject text NOT NULL,
 actor text NOT NULL, generation bigint, occurred_at timestamptz NOT NULL, detail text NOT NULL);
CREATE INDEX IF NOT EXISTS ix_ha_audit_time ON platform.ha_audit(occurred_at DESC);
CREATE TABLE IF NOT EXISTS platform.service_instances (
 service_name text NOT NULL, instance_id text NOT NULL, region text NOT NULL,
 version text NOT NULL, started_at timestamptz NOT NULL, heartbeat_at timestamptz NOT NULL,
 live boolean NOT NULL, ready boolean NOT NULL, degraded_reason text,
 PRIMARY KEY(service_name,instance_id));
CREATE TABLE IF NOT EXISTS platform.artifact_transfers (
 tenant_id uuid NOT NULL, transfer_id uuid NOT NULL, endpoint_id uuid NOT NULL,
 owner_id uuid NOT NULL, state text NOT NULL, version bigint NOT NULL,
 updated_at timestamptz NOT NULL, data jsonb NOT NULL,
 PRIMARY KEY(tenant_id,transfer_id));
CREATE UNIQUE INDEX IF NOT EXISTS ux_artifact_transfer_identity ON platform.artifact_transfers(transfer_id);
CREATE INDEX IF NOT EXISTS ix_artifact_transfer_owner ON platform.artifact_transfers(tenant_id,owner_id,updated_at);
ALTER TABLE platform.artifact_transfers ENABLE ROW LEVEL SECURITY;
CREATE TABLE IF NOT EXISTS platform.object_recovery_inventory (
 tenant_id uuid NOT NULL, object_id uuid NOT NULL, object_type text NOT NULL,
 expected_size bigint NOT NULL, expected_sha256 text NOT NULL,
 media_type text NOT NULL, state text NOT NULL, updated_at timestamptz NOT NULL,
 PRIMARY KEY(tenant_id,object_id));
CREATE TABLE IF NOT EXISTS platform.backup_runs (
 backup_id uuid PRIMARY KEY, started_at timestamptz NOT NULL,completed_at timestamptz,
 database_version text NOT NULL,schema_version text NOT NULL,size_bytes bigint,
 sha256 text,method text NOT NULL,state text NOT NULL,retention text NOT NULL,
 protection_state text NOT NULL);
CREATE TABLE IF NOT EXISTS platform.dr_drills (
 drill_id uuid PRIMARY KEY,backup_id uuid NOT NULL REFERENCES platform.backup_runs(backup_id),
 started_at timestamptz NOT NULL,completed_at timestamptz,rpo_boundary text NOT NULL,
 rto_seconds numeric,table_count integer,difference_count integer,state text NOT NULL,detail text NOT NULL);
ALTER TABLE platform.object_recovery_inventory ENABLE ROW LEVEL SECURITY;
