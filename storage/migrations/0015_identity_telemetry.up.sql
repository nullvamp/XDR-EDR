BEGIN;
CREATE TABLE IF NOT EXISTS platform.identity_batches(
 tenant_id uuid NOT NULL,batch_id uuid NOT NULL,endpoint_id uuid NOT NULL,agent_id uuid NOT NULL,
 installation_id text NOT NULL,first_sequence bigint NOT NULL,last_sequence bigint NOT NULL,
 event_count integer NOT NULL,content_sha256 text NOT NULL,received_at timestamptz NOT NULL DEFAULT now(),
 PRIMARY KEY(tenant_id,batch_id));
CREATE TABLE IF NOT EXISTS platform.identity_events(
 tenant_id uuid NOT NULL,event_id uuid NOT NULL,batch_id uuid NOT NULL,endpoint_id uuid NOT NULL,
 agent_id uuid NOT NULL,event_type text NOT NULL,entity_id text NOT NULL,account_sid text,
 account_name text,domain_name text,logon_id text,logon_type integer,result text,source_ip inet,
 remote_session boolean,session_id integer,integrity_level text,elevated_token boolean,
 process_entity_id text,privilege_names text[] NOT NULL DEFAULT '{}',sequence bigint NOT NULL,
 observed_at timestamptz NOT NULL,data_quality_flags text[] NOT NULL DEFAULT '{}',event_data jsonb NOT NULL,
 PRIMARY KEY(tenant_id,event_id),UNIQUE(tenant_id,agent_id,sequence));
CREATE INDEX IF NOT EXISTS ix_identity_events_search ON platform.identity_events(tenant_id,observed_at DESC,event_id DESC);
CREATE INDEX IF NOT EXISTS ix_identity_events_account ON platform.identity_events(tenant_id,account_sid,account_name,domain_name,observed_at DESC);
CREATE INDEX IF NOT EXISTS ix_identity_events_logon ON platform.identity_events(tenant_id,endpoint_id,logon_id,observed_at);
CREATE INDEX IF NOT EXISTS ix_identity_events_session ON platform.identity_events(tenant_id,endpoint_id,session_id,observed_at);
CREATE INDEX IF NOT EXISTS ix_identity_events_process ON platform.identity_events(tenant_id,process_entity_id,observed_at);
CREATE TABLE IF NOT EXISTS platform.logon_session_entities(
 tenant_id uuid NOT NULL,endpoint_id uuid NOT NULL,logon_entity_id text NOT NULL,logon_id text,
 account_sid text,first_observed timestamptz NOT NULL,last_observed timestamptz NOT NULL,
 started_at timestamptz,ended_at timestamptz,incomplete boolean NOT NULL,latest_event jsonb NOT NULL,
 PRIMARY KEY(tenant_id,endpoint_id,logon_entity_id));
CREATE TABLE IF NOT EXISTS platform.windows_session_entities(
 tenant_id uuid NOT NULL,endpoint_id uuid NOT NULL,session_entity_id text NOT NULL,session_id integer,
 generation bigint NOT NULL,first_observed timestamptz NOT NULL,last_observed timestamptz NOT NULL,
 created_at timestamptz,ended_at timestamptz,state text,latest_event jsonb NOT NULL,
 PRIMARY KEY(tenant_id,endpoint_id,session_entity_id));
CREATE TABLE IF NOT EXISTS platform.token_entities(
 tenant_id uuid NOT NULL,endpoint_id uuid NOT NULL,token_entity_id text NOT NULL,process_entity_id text,
 user_sid text,first_observed timestamptz NOT NULL,last_observed timestamptz NOT NULL,
 provenance text NOT NULL,latest_state jsonb NOT NULL,PRIMARY KEY(tenant_id,endpoint_id,token_entity_id));
CREATE TABLE IF NOT EXISTS platform.identity_privilege_observations(
 tenant_id uuid NOT NULL,event_id uuid NOT NULL,endpoint_id uuid NOT NULL,token_entity_id text,
 process_entity_id text,privilege_name text NOT NULL,privilege_state text NOT NULL,
 observed_at timestamptz NOT NULL,evidence jsonb NOT NULL,PRIMARY KEY(tenant_id,event_id,privilege_name));
CREATE TABLE IF NOT EXISTS platform.identity_process_relationships(
 tenant_id uuid NOT NULL,event_id uuid NOT NULL,endpoint_id uuid NOT NULL,process_entity_id text NOT NULL,
 logon_entity_id text,session_entity_id text,token_entity_id text,mechanism text NOT NULL,
 confidence text NOT NULL,observed_at timestamptz NOT NULL,PRIMARY KEY(tenant_id,event_id,process_entity_id));
CREATE TABLE IF NOT EXISTS platform.identity_telemetry_health(
 tenant_id uuid NOT NULL,endpoint_id uuid NOT NULL,health_data jsonb NOT NULL,
 updated_at timestamptz NOT NULL DEFAULT now(),PRIMARY KEY(tenant_id,endpoint_id));
CREATE TABLE IF NOT EXISTS platform.identity_policy_versions(
 id uuid PRIMARY KEY,tenant_id uuid NOT NULL,name text NOT NULL,version integer NOT NULL,policy jsonb NOT NULL,
 sha256 text NOT NULL,status text NOT NULL,created_at timestamptz NOT NULL,created_by text NOT NULL,
 UNIQUE(tenant_id,name,version));
CREATE TABLE IF NOT EXISTS platform.identity_policy_assignments(
 tenant_id uuid NOT NULL,endpoint_id uuid NULL,policy_id uuid NOT NULL REFERENCES platform.identity_policy_versions(id),
 assigned_at timestamptz NOT NULL,assigned_by text NOT NULL);
CREATE UNIQUE INDEX IF NOT EXISTS ux_identity_policy_assignment ON platform.identity_policy_assignments(tenant_id,COALESCE(endpoint_id,'00000000-0000-0000-0000-000000000000'::uuid));
CREATE TABLE IF NOT EXISTS platform.identity_policy_acknowledgements(
 tenant_id uuid NOT NULL,endpoint_id uuid NOT NULL,policy_id uuid NOT NULL,version integer NOT NULL,
 applied boolean NOT NULL,validation_error text,acknowledged_at timestamptz NOT NULL,
 PRIMARY KEY(tenant_id,endpoint_id));
CREATE TABLE IF NOT EXISTS platform.identity_export_jobs(
 id uuid PRIMARY KEY,tenant_id uuid NOT NULL,created_by text NOT NULL,state text NOT NULL,format text NOT NULL,
 query jsonb NOT NULL,fields text[] NOT NULL,maximum_records integer NOT NULL,output_object_id uuid NOT NULL,
 manifest_object_id uuid NOT NULL,metadata_object_id uuid NOT NULL,created_at timestamptz NOT NULL,
 updated_at timestamptz NOT NULL,expires_at timestamptz NOT NULL,started_at timestamptz,completed_at timestamptz,
 record_count integer,output_size bigint,output_sha256 text,error_code text,error_summary text);
COMMIT;
