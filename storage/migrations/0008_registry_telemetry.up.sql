BEGIN;

CREATE TABLE platform.registry_batches(
    tenant_id uuid NOT NULL REFERENCES platform.tenants(id),
    batch_id uuid NOT NULL,
    endpoint_id uuid NOT NULL,
    agent_id uuid NOT NULL,
    installation_id text NOT NULL,
    first_sequence bigint NOT NULL,
    last_sequence bigint NOT NULL,
    event_count integer NOT NULL CHECK(event_count BETWEEN 1 AND 1000),
    content_sha256 text NOT NULL CHECK(content_sha256 ~ '^[0-9a-f]{64}$'),
    schema_version text NOT NULL,
    compression text NOT NULL CHECK(compression='gzip'),
    uncompressed_bytes integer NOT NULL CHECK(uncompressed_bytes BETWEEN 0 AND 4194304),
    compressed_bytes integer NOT NULL CHECK(compressed_bytes BETWEEN 0 AND 1048576),
    received_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY(tenant_id,batch_id)
);

CREATE TABLE platform.registry_events(
    tenant_id uuid NOT NULL REFERENCES platform.tenants(id),
    event_id uuid NOT NULL,
    batch_id uuid NOT NULL,
    endpoint_id uuid NOT NULL,
    agent_id uuid NOT NULL,
    key_entity_id text NOT NULL,
    value_entity_id text,
    event_type text NOT NULL CHECK(event_type IN('key_created','key_deleted','key_renamed','value_set','value_deleted','key_security_changed')),
    sequence bigint NOT NULL CHECK(sequence>0),
    observed_at timestamptz NOT NULL,
    received_at timestamptz NOT NULL DEFAULT now(),
    ingested_at timestamptz NOT NULL DEFAULT now(),
    schema_version text NOT NULL,
    normalization_version text NOT NULL,
    collector_source text NOT NULL,
    collector_version text NOT NULL,
    source_event_id text,
    raw_sha256 text,
    trace_id text,
    policy_version text,
    data_quality_flags text[] NOT NULL DEFAULT '{}',
    late boolean NOT NULL DEFAULT false,
    event_data jsonb NOT NULL,
    PRIMARY KEY(tenant_id,event_id),
    UNIQUE(tenant_id,endpoint_id,agent_id,sequence),
    FOREIGN KEY(tenant_id,batch_id) REFERENCES platform.registry_batches(tenant_id,batch_id)
);
CREATE INDEX registry_events_timeline ON platform.registry_events(tenant_id,endpoint_id,observed_at DESC,event_id DESC);
CREATE INDEX registry_events_key_history ON platform.registry_events(tenant_id,endpoint_id,key_entity_id,observed_at,event_id);
CREATE INDEX registry_events_value_history ON platform.registry_events(tenant_id,endpoint_id,value_entity_id,observed_at,event_id) WHERE value_entity_id IS NOT NULL;
CREATE INDEX registry_events_process ON platform.registry_events(tenant_id,endpoint_id,((event_data#>>'{process,processEntityId}')),observed_at DESC);
CREATE INDEX registry_events_hive_path ON platform.registry_events(tenant_id,((event_data->>'hive')),((event_data->>'keyPath')),observed_at DESC);

CREATE TABLE platform.registry_key_entities(
    tenant_id uuid NOT NULL REFERENCES platform.tenants(id),
    endpoint_id uuid NOT NULL,
    key_entity_id text NOT NULL,
    hive text NOT NULL,
    current_key_path text NOT NULL,
    previous_paths text[] NOT NULL DEFAULT '{}',
    parent_key_path text,
    first_observed timestamptz NOT NULL,
    last_observed timestamptz NOT NULL,
    created_at timestamptz,
    deleted_at timestamptz,
    state text NOT NULL,
    latest_event_id uuid NOT NULL,
    source_confidence text NOT NULL,
    data_quality_flags text[] NOT NULL DEFAULT '{}',
    latest_process jsonb,
    user_sid text,
    PRIMARY KEY(tenant_id,endpoint_id,key_entity_id)
);
CREATE INDEX registry_keys_path ON platform.registry_key_entities(tenant_id,endpoint_id,hive,current_key_path);

CREATE TABLE platform.registry_value_entities(
    tenant_id uuid NOT NULL REFERENCES platform.tenants(id),
    endpoint_id uuid NOT NULL,
    value_entity_id text NOT NULL,
    key_entity_id text NOT NULL,
    hive text NOT NULL,
    key_path text NOT NULL,
    value_name text NOT NULL,
    value_metadata jsonb NOT NULL,
    first_observed timestamptz NOT NULL,
    last_observed timestamptz NOT NULL,
    created_at timestamptz,
    deleted_at timestamptz,
    state text NOT NULL,
    latest_event_id uuid NOT NULL,
    source_confidence text NOT NULL,
    data_quality_flags text[] NOT NULL DEFAULT '{}',
    latest_process jsonb,
    user_sid text,
    PRIMARY KEY(tenant_id,endpoint_id,value_entity_id)
);
CREATE INDEX registry_values_name ON platform.registry_value_entities(tenant_id,endpoint_id,hive,key_path,value_name);
CREATE INDEX registry_values_hash ON platform.registry_value_entities(tenant_id,((value_metadata->>'sha256'))) WHERE value_metadata->>'sha256' IS NOT NULL;

CREATE TABLE platform.registry_telemetry_health(
    tenant_id uuid NOT NULL REFERENCES platform.tenants(id),
    endpoint_id uuid NOT NULL,
    enabled boolean NOT NULL,
    collector_source text NOT NULL,
    collector_version text NOT NULL,
    last_source_event timestamptz,
    last_accepted_event timestamptz,
    queue_depth bigint NOT NULL DEFAULT 0,
    oldest_queued_seconds bigint NOT NULL DEFAULT 0,
    dropped_events bigint NOT NULL DEFAULT 0,
    excluded_events bigint NOT NULL DEFAULT 0,
    source_losses bigint NOT NULL DEFAULT 0,
    sequence_gaps bigint NOT NULL DEFAULT 0,
    handle_resolution_failures bigint NOT NULL DEFAULT 0,
    path_resolution_failures bigint NOT NULL DEFAULT 0,
    capture_attempts bigint NOT NULL DEFAULT 0,
    capture_skips bigint NOT NULL DEFAULT 0,
    capture_failures bigint NOT NULL DEFAULT 0,
    redacted_values bigint NOT NULL DEFAULT 0,
    last_upload_result text NOT NULL,
    policy_version text NOT NULL,
    applied_version integer,
    drift boolean NOT NULL DEFAULT false,
    last_upload timestamptz,
    last_sequence bigint NOT NULL DEFAULT 0,
    updated_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY(tenant_id,endpoint_id)
);

CREATE TABLE platform.registry_policy_versions(
    id uuid PRIMARY KEY,
    tenant_id uuid NOT NULL REFERENCES platform.tenants(id),
    name text NOT NULL,
    version integer NOT NULL,
    policy jsonb NOT NULL,
    sha256 text NOT NULL,
    status text NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    created_by text NOT NULL,
    UNIQUE(tenant_id,name,version)
);
CREATE TABLE platform.registry_policy_assignments(
    tenant_id uuid NOT NULL REFERENCES platform.tenants(id),
    endpoint_id uuid,
    policy_id uuid NOT NULL REFERENCES platform.registry_policy_versions(id),
    assigned_at timestamptz NOT NULL DEFAULT now(),
    assigned_by text NOT NULL,
    UNIQUE NULLS NOT DISTINCT(tenant_id,endpoint_id)
);
CREATE TABLE platform.registry_policy_acknowledgements(
    tenant_id uuid NOT NULL REFERENCES platform.tenants(id),
    endpoint_id uuid NOT NULL,
    policy_id uuid NOT NULL,
    version integer NOT NULL,
    applied boolean NOT NULL,
    validation_error text,
    acknowledged_at timestamptz NOT NULL,
    PRIMARY KEY(tenant_id,endpoint_id)
);

CREATE TABLE platform.registry_export_jobs(
    tenant_id uuid NOT NULL REFERENCES platform.tenants(id),
    id uuid NOT NULL,
    created_by text NOT NULL,
    state text NOT NULL CHECK(state IN('pending','running','completed','failed','expired','cancelled')),
    format text NOT NULL CHECK(format IN('jsonl','csv')),
    query jsonb NOT NULL,
    fields text[] NOT NULL DEFAULT '{}',
    maximum_records integer NOT NULL CHECK(maximum_records BETWEEN 1 AND 10000),
    output_object_id uuid NOT NULL,
    manifest_object_id uuid NOT NULL,
    metadata_object_id uuid NOT NULL,
    record_count integer,
    output_size bigint,
    output_sha256 text,
    error_code text,
    error_summary text,
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    started_at timestamptz,
    completed_at timestamptz,
    expires_at timestamptz NOT NULL,
    PRIMARY KEY(tenant_id,id),
    UNIQUE(id), UNIQUE(output_object_id), UNIQUE(manifest_object_id), UNIQUE(metadata_object_id)
);
CREATE INDEX registry_export_pending ON platform.registry_export_jobs(created_at) WHERE state='pending';

COMMIT;
