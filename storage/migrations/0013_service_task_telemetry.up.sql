BEGIN;
CREATE TABLE IF NOT EXISTS platform.persistence_batches(
 tenant_id uuid NOT NULL,batch_id uuid NOT NULL,endpoint_id uuid NOT NULL,agent_id uuid NOT NULL,
 installation_id text NOT NULL,first_sequence bigint NOT NULL,last_sequence bigint NOT NULL,
 event_count integer NOT NULL,content_sha256 text NOT NULL,received_at timestamptz NOT NULL DEFAULT now(),
 PRIMARY KEY(tenant_id,batch_id));
CREATE TABLE IF NOT EXISTS platform.persistence_events(
 tenant_id uuid NOT NULL,event_id uuid NOT NULL,batch_id uuid NOT NULL,endpoint_id uuid NOT NULL,
 agent_id uuid NOT NULL,object_kind text NOT NULL,event_type text NOT NULL,entity_id text NOT NULL,
 object_name text NOT NULL,object_path text,account_name text,state text,object_type text,
 process_entity_id text,sequence bigint NOT NULL,observed_at timestamptz NOT NULL,
 data_quality_flags text[] NOT NULL DEFAULT '{}',event_data jsonb NOT NULL,
 PRIMARY KEY(tenant_id,event_id),UNIQUE(tenant_id,agent_id,sequence));
CREATE INDEX IF NOT EXISTS ix_persistence_events_search ON platform.persistence_events(tenant_id,object_kind,observed_at DESC,event_id DESC);
CREATE INDEX IF NOT EXISTS ix_persistence_events_entity ON platform.persistence_events(tenant_id,endpoint_id,entity_id,observed_at);
CREATE TABLE IF NOT EXISTS platform.service_entities(
 tenant_id uuid NOT NULL,endpoint_id uuid NOT NULL,service_entity_id text NOT NULL,service_name text NOT NULL,
 first_observed timestamptz NOT NULL,last_observed timestamptz NOT NULL,created_at timestamptz,
 deleted_at timestamptz,latest_event jsonb NOT NULL,PRIMARY KEY(tenant_id,endpoint_id,service_entity_id));
CREATE TABLE IF NOT EXISTS platform.service_configuration_history(
 tenant_id uuid NOT NULL,endpoint_id uuid NOT NULL,service_entity_id text NOT NULL,event_id uuid NOT NULL,
 observed_at timestamptz NOT NULL,configuration jsonb NOT NULL,PRIMARY KEY(tenant_id,event_id));
CREATE TABLE IF NOT EXISTS platform.scheduled_task_entities(
 tenant_id uuid NOT NULL,endpoint_id uuid NOT NULL,task_entity_id text NOT NULL,task_path text NOT NULL,
 first_observed timestamptz NOT NULL,last_observed timestamptz NOT NULL,registered_at timestamptz,
 deleted_at timestamptz,latest_event jsonb NOT NULL,PRIMARY KEY(tenant_id,endpoint_id,task_entity_id));
CREATE TABLE IF NOT EXISTS platform.scheduled_task_configuration_history(
 tenant_id uuid NOT NULL,endpoint_id uuid NOT NULL,task_entity_id text NOT NULL,event_id uuid NOT NULL,
 observed_at timestamptz NOT NULL,configuration jsonb NOT NULL,PRIMARY KEY(tenant_id,event_id));
CREATE TABLE IF NOT EXISTS platform.scheduled_task_execution_instances(
 tenant_id uuid NOT NULL,endpoint_id uuid NOT NULL,task_entity_id text NOT NULL,event_id uuid NOT NULL,
 instance_id text,process_entity_id text,result text,observed_at timestamptz NOT NULL,event_data jsonb NOT NULL,
 PRIMARY KEY(tenant_id,event_id));
CREATE TABLE IF NOT EXISTS platform.persistence_telemetry_health(
 tenant_id uuid NOT NULL,endpoint_id uuid NOT NULL,health_data jsonb NOT NULL,updated_at timestamptz NOT NULL DEFAULT now(),PRIMARY KEY(tenant_id,endpoint_id));
CREATE TABLE IF NOT EXISTS platform.persistence_policy_versions(
 id uuid PRIMARY KEY,tenant_id uuid NOT NULL,name text NOT NULL,version integer NOT NULL,policy jsonb NOT NULL,
 sha256 text NOT NULL,status text NOT NULL,created_at timestamptz NOT NULL,created_by text NOT NULL,UNIQUE(tenant_id,name,version));
CREATE TABLE IF NOT EXISTS platform.persistence_policy_assignments(
 tenant_id uuid NOT NULL,endpoint_id uuid NULL,policy_id uuid NOT NULL REFERENCES platform.persistence_policy_versions(id),
 assigned_at timestamptz NOT NULL,assigned_by text NOT NULL);
CREATE UNIQUE INDEX IF NOT EXISTS ux_persistence_policy_assignment ON platform.persistence_policy_assignments(tenant_id,COALESCE(endpoint_id,'00000000-0000-0000-0000-000000000000'::uuid));
CREATE TABLE IF NOT EXISTS platform.persistence_policy_acknowledgements(
 tenant_id uuid NOT NULL,endpoint_id uuid NOT NULL,policy_id uuid NOT NULL,version integer NOT NULL,
 applied boolean NOT NULL,validation_error text,acknowledged_at timestamptz NOT NULL,PRIMARY KEY(tenant_id,endpoint_id));
CREATE TABLE IF NOT EXISTS platform.persistence_export_jobs(
 id uuid PRIMARY KEY,tenant_id uuid NOT NULL,created_by text NOT NULL,state text NOT NULL,format text NOT NULL,
 query jsonb NOT NULL,fields text[] NOT NULL,maximum_records integer NOT NULL,output_object_id uuid NOT NULL,
 manifest_object_id uuid NOT NULL,metadata_object_id uuid NOT NULL,created_at timestamptz NOT NULL,
 updated_at timestamptz NOT NULL,expires_at timestamptz NOT NULL,started_at timestamptz,completed_at timestamptz,
 record_count integer,output_size bigint,output_sha256 text,error_code text,error_summary text);
COMMIT;
