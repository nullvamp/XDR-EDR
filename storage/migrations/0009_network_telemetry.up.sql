BEGIN;
CREATE TABLE platform.network_batches(
 tenant_id uuid NOT NULL REFERENCES platform.tenants(id), batch_id uuid NOT NULL,
 endpoint_id uuid NOT NULL, agent_id uuid NOT NULL, installation_id text NOT NULL,
 first_sequence bigint NOT NULL, last_sequence bigint NOT NULL,
 event_count integer NOT NULL CHECK(event_count BETWEEN 1 AND 1000),
 content_sha256 text NOT NULL CHECK(content_sha256 ~ '^[0-9a-f]{64}$'),
 schema_version text NOT NULL, compression text NOT NULL CHECK(compression='gzip'),
 uncompressed_bytes integer NOT NULL CHECK(uncompressed_bytes BETWEEN 0 AND 4194304),
 compressed_bytes integer NOT NULL CHECK(compressed_bytes BETWEEN 0 AND 1048576),
 received_at timestamptz NOT NULL DEFAULT now(), PRIMARY KEY(tenant_id,batch_id));

CREATE TABLE platform.network_events(
 tenant_id uuid NOT NULL REFERENCES platform.tenants(id), event_id uuid NOT NULL,
 batch_id uuid NOT NULL, endpoint_id uuid NOT NULL, agent_id uuid NOT NULL,
 connection_entity_id text NOT NULL, event_type text NOT NULL CHECK(event_type IN
 ('connection_attempted','connection_established','connection_failed','connection_closed','listener_started','listener_stopped','datagram_observed','operation_observed')),
 sequence bigint NOT NULL CHECK(sequence>0), observed_at timestamptz NOT NULL,
 received_at timestamptz NOT NULL DEFAULT now(), ingested_at timestamptz NOT NULL DEFAULT now(),
 schema_version text NOT NULL, normalization_version text NOT NULL,
 collector_source text NOT NULL, collector_version text NOT NULL, native_provider text NOT NULL,
 native_event_id text, raw_sha256 text, trace_id text, policy_version text,
 local_address inet NOT NULL, local_address_native bytea NOT NULL, local_port integer NOT NULL CHECK(local_port BETWEEN 0 AND 65535),
 remote_address inet, remote_address_native bytea, remote_port integer CHECK(remote_port BETWEEN 0 AND 65535),
 protocol text NOT NULL CHECK(protocol IN('TCP','UDP')), address_family text NOT NULL CHECK(address_family IN('IPv4','IPv6')),
 direction text NOT NULL, connection_state text NOT NULL, process_entity_id text,
 data_quality_flags text[] NOT NULL DEFAULT '{}', late boolean NOT NULL DEFAULT false,
 out_of_order boolean NOT NULL DEFAULT false, event_data jsonb NOT NULL,
 PRIMARY KEY(tenant_id,event_id), UNIQUE(tenant_id,endpoint_id,agent_id,sequence),
 FOREIGN KEY(tenant_id,batch_id) REFERENCES platform.network_batches(tenant_id,batch_id));
CREATE INDEX network_events_timeline ON platform.network_events(tenant_id,endpoint_id,observed_at DESC,event_id DESC);
CREATE INDEX network_events_connection ON platform.network_events(tenant_id,endpoint_id,connection_entity_id,observed_at,event_id);
CREATE INDEX network_events_remote ON platform.network_events(tenant_id,remote_address,remote_port,observed_at DESC);
CREATE INDEX network_events_local ON platform.network_events(tenant_id,local_address,local_port,observed_at DESC);
CREATE INDEX network_events_process ON platform.network_events(tenant_id,endpoint_id,process_entity_id,observed_at DESC) WHERE process_entity_id IS NOT NULL;
CREATE INDEX network_events_protocol_state ON platform.network_events(tenant_id,protocol,direction,connection_state,observed_at DESC);

CREATE TABLE platform.network_connection_entities(
 tenant_id uuid NOT NULL REFERENCES platform.tenants(id), endpoint_id uuid NOT NULL,
 connection_entity_id text NOT NULL, process_entity_id text, protocol text NOT NULL,
 address_family text NOT NULL, local_endpoint jsonb NOT NULL, remote_endpoint jsonb,
 direction text NOT NULL, first_observed timestamptz NOT NULL, last_observed timestamptz NOT NULL,
 attempted_at timestamptz, established_at timestamptz, failed_at timestamptz, closed_at timestamptz,
 duration_milliseconds bigint, state text NOT NULL, latest_event_id uuid NOT NULL,
 source_confidence text NOT NULL, data_quality_flags text[] NOT NULL DEFAULT '{}',
 lifecycle_completeness text NOT NULL, latest_process jsonb, user_identity text, hostname_context jsonb,
 PRIMARY KEY(tenant_id,endpoint_id,connection_entity_id));
CREATE INDEX network_connections_remote ON platform.network_connection_entities(tenant_id,endpoint_id,((remote_endpoint->>'address')),((remote_endpoint->>'port')));
CREATE INDEX network_listeners ON platform.network_connection_entities(tenant_id,endpoint_id,last_observed DESC) WHERE state='listening';

CREATE TABLE platform.network_telemetry_health(
 tenant_id uuid NOT NULL REFERENCES platform.tenants(id), endpoint_id uuid NOT NULL,
 health_data jsonb NOT NULL, updated_at timestamptz NOT NULL DEFAULT now(),
 PRIMARY KEY(tenant_id,endpoint_id));
CREATE TABLE platform.network_policy_versions(
 id uuid PRIMARY KEY, tenant_id uuid NOT NULL REFERENCES platform.tenants(id), name text NOT NULL,
 version integer NOT NULL, policy jsonb NOT NULL, sha256 text NOT NULL, status text NOT NULL,
 created_at timestamptz NOT NULL DEFAULT now(), created_by text NOT NULL, UNIQUE(tenant_id,name,version));
CREATE TABLE platform.network_policy_assignments(
 tenant_id uuid NOT NULL REFERENCES platform.tenants(id), endpoint_id uuid,
 policy_id uuid NOT NULL REFERENCES platform.network_policy_versions(id), assigned_at timestamptz NOT NULL DEFAULT now(),
 assigned_by text NOT NULL, UNIQUE NULLS NOT DISTINCT(tenant_id,endpoint_id));
CREATE TABLE platform.network_policy_acknowledgements(
 tenant_id uuid NOT NULL REFERENCES platform.tenants(id), endpoint_id uuid NOT NULL, policy_id uuid NOT NULL,
 version integer NOT NULL, applied boolean NOT NULL, validation_error text, acknowledged_at timestamptz NOT NULL,
 PRIMARY KEY(tenant_id,endpoint_id));
CREATE TABLE platform.network_export_jobs(
 tenant_id uuid NOT NULL REFERENCES platform.tenants(id), id uuid NOT NULL, created_by text NOT NULL,
 state text NOT NULL CHECK(state IN('pending','running','completed','failed','expired','cancelled')),
 format text NOT NULL CHECK(format IN('jsonl','csv')), query jsonb NOT NULL, fields text[] NOT NULL DEFAULT '{}',
 maximum_records integer NOT NULL CHECK(maximum_records BETWEEN 1 AND 10000), output_object_id uuid NOT NULL,
 manifest_object_id uuid NOT NULL, metadata_object_id uuid NOT NULL, record_count integer, output_size bigint,
 output_sha256 text, error_code text, error_summary text, created_at timestamptz NOT NULL DEFAULT now(),
 updated_at timestamptz NOT NULL DEFAULT now(), started_at timestamptz, completed_at timestamptz,
 expires_at timestamptz NOT NULL, PRIMARY KEY(tenant_id,id), UNIQUE(id), UNIQUE(output_object_id),
 UNIQUE(manifest_object_id), UNIQUE(metadata_object_id));
CREATE INDEX network_export_pending ON platform.network_export_jobs(created_at) WHERE state='pending';
COMMIT;
