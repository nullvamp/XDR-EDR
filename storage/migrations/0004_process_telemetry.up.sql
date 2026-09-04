BEGIN;
CREATE TABLE IF NOT EXISTS platform.process_batches(
 tenant_id uuid NOT NULL REFERENCES platform.tenants(id), batch_id uuid NOT NULL,
 endpoint_id uuid NOT NULL, agent_id uuid NOT NULL, installation_id text NOT NULL,
 first_sequence bigint NOT NULL CHECK(first_sequence>0), last_sequence bigint NOT NULL CHECK(last_sequence>=first_sequence),
 event_count integer NOT NULL CHECK(event_count BETWEEN 1 AND 500), content_sha256 char(64) NOT NULL,
 received_at timestamptz NOT NULL DEFAULT now(), PRIMARY KEY(tenant_id,batch_id));
CREATE TABLE IF NOT EXISTS platform.process_events(
 tenant_id uuid NOT NULL REFERENCES platform.tenants(id), event_id uuid NOT NULL,
 batch_id uuid NOT NULL, endpoint_id uuid NOT NULL, agent_id uuid NOT NULL,
 process_entity_id char(64) NOT NULL, event_type text NOT NULL CHECK(event_type IN('started','exited')),
 sequence bigint NOT NULL CHECK(sequence>0), observed_at timestamptz NOT NULL,
 received_at timestamptz NOT NULL DEFAULT now(), ingested_at timestamptz NOT NULL DEFAULT now(),
 schema_version text NOT NULL, normalization_version text NOT NULL, collector_type text NOT NULL,
 collector_version text NOT NULL, source_event_id text, raw_sha256 char(64), trace_id text,
 data_quality_flags text[] NOT NULL DEFAULT '{}', late boolean NOT NULL DEFAULT false,
 event_data jsonb NOT NULL, retention_until timestamptz NOT NULL DEFAULT now()+interval '30 days',
 PRIMARY KEY(tenant_id,event_id), UNIQUE(tenant_id,endpoint_id,agent_id,sequence),
 FOREIGN KEY(tenant_id,batch_id) REFERENCES platform.process_batches(tenant_id,batch_id));
CREATE TABLE IF NOT EXISTS platform.process_entities(
 tenant_id uuid NOT NULL REFERENCES platform.tenants(id), endpoint_id uuid NOT NULL,
 process_entity_id char(64) NOT NULL, pid integer NOT NULL CHECK(pid>0), start_time timestamptz NOT NULL,
 exit_time timestamptz, parent_process_entity_id char(64), parent_pid integer,
 lineage_state text NOT NULL, executable_name text, executable_path text, command_line text,
 working_directory text, user_name text, user_id text, session_id text, integrity_level text,
 elevated boolean, architecture text, container_id text, executable_metadata jsonb,
 start_event_id uuid NOT NULL, exit_event_id uuid, first_observed_at timestamptz NOT NULL,
 last_updated_at timestamptz NOT NULL, collector_type text NOT NULL, collector_version text NOT NULL,
 schema_version text NOT NULL, normalization_version text NOT NULL, data_quality_flags text[] NOT NULL DEFAULT '{}',
 late boolean NOT NULL DEFAULT false, duration_ms bigint, exit_code integer,
 retention_until timestamptz NOT NULL DEFAULT now()+interval '30 days',
 PRIMARY KEY(tenant_id,endpoint_id,process_entity_id));
CREATE TABLE IF NOT EXISTS platform.process_telemetry_health(
 tenant_id uuid NOT NULL REFERENCES platform.tenants(id), endpoint_id uuid NOT NULL,
 enabled boolean NOT NULL, collector_type text NOT NULL, collector_version text NOT NULL,
 last_event_at timestamptz, queue_depth bigint NOT NULL DEFAULT 0, oldest_queued_age_seconds bigint NOT NULL DEFAULT 0,
 dropped_events bigint NOT NULL DEFAULT 0, drop_reason text, last_upload_result text NOT NULL,
 policy_version text NOT NULL, last_sequence bigint NOT NULL DEFAULT 0, sequence_gaps bigint NOT NULL DEFAULT 0,
 updated_at timestamptz NOT NULL DEFAULT now(), PRIMARY KEY(tenant_id,endpoint_id));
CREATE INDEX IF NOT EXISTS ix_process_entities_tenant_time ON platform.process_entities(tenant_id,start_time DESC,process_entity_id);
CREATE INDEX IF NOT EXISTS ix_process_entities_endpoint_time ON platform.process_entities(tenant_id,endpoint_id,start_time DESC);
CREATE INDEX IF NOT EXISTS ix_process_entities_name ON platform.process_entities(tenant_id,lower(executable_name));
CREATE INDEX IF NOT EXISTS ix_process_entities_pid ON platform.process_entities(tenant_id,endpoint_id,pid,start_time DESC);
CREATE INDEX IF NOT EXISTS ix_process_entities_parent ON platform.process_entities(tenant_id,endpoint_id,parent_process_entity_id);
CREATE INDEX IF NOT EXISTS ix_process_events_batch ON platform.process_events(tenant_id,batch_id);
INSERT INTO platform.schema_migrations(version,checksum) VALUES('0004_process_telemetry','sha256:sprint2-process-telemetry-v1') ON CONFLICT(version) DO NOTHING;
COMMIT;
