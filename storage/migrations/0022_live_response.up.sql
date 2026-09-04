BEGIN;
CREATE TABLE IF NOT EXISTS platform.live_response_sessions(
 tenant_id uuid NOT NULL REFERENCES platform.tenants(id), session_id uuid NOT NULL,
 endpoint_id uuid NOT NULL, agent_id uuid NOT NULL, agent_installation_id text NOT NULL, analyst_id text NOT NULL,
 state text NOT NULL, capability_hash text NOT NULL CHECK(length(capability_hash)=64), nonce text NOT NULL,
 created_at timestamptz NOT NULL, expires_at timestamptz NOT NULL, absolute_expires_at timestamptz NOT NULL,
 session_revision integer NOT NULL CHECK(session_revision>0), session_data jsonb NOT NULL, updated_at timestamptz NOT NULL,
 PRIMARY KEY(tenant_id,session_id), UNIQUE(tenant_id,nonce),
 FOREIGN KEY(tenant_id,endpoint_id) REFERENCES platform.endpoints(tenant_id,id),
 FOREIGN KEY(tenant_id,agent_id) REFERENCES platform.agents(tenant_id,id));
CREATE INDEX IF NOT EXISTS live_sessions_endpoint_idx ON platform.live_response_sessions(tenant_id,endpoint_id,state,created_at);
CREATE INDEX IF NOT EXISTS live_sessions_expiry_idx ON platform.live_response_sessions(expires_at,absolute_expires_at) WHERE state NOT IN('Closed','Expired','Rejected','Failed');
CREATE TABLE IF NOT EXISTS platform.live_response_commands(
 tenant_id uuid NOT NULL REFERENCES platform.tenants(id), session_id uuid NOT NULL, command_id uuid NOT NULL,
 state text NOT NULL, input_hash text NOT NULL CHECK(length(input_hash)=64), nonce text NOT NULL,
 requested_at timestamptz NOT NULL, command_data jsonb NOT NULL, updated_at timestamptz NOT NULL,
 PRIMARY KEY(tenant_id,command_id), UNIQUE(tenant_id,nonce),
 FOREIGN KEY(tenant_id,session_id) REFERENCES platform.live_response_sessions(tenant_id,session_id));
CREATE INDEX IF NOT EXISTS live_commands_queue_idx ON platform.live_response_commands(tenant_id,session_id,state,requested_at);
CREATE TABLE IF NOT EXISTS platform.live_response_transcript(
 tenant_id uuid NOT NULL REFERENCES platform.tenants(id), event_id uuid NOT NULL, session_id uuid NOT NULL,
 command_id uuid NULL, object_version integer NOT NULL, event_type text NOT NULL, actor text NOT NULL,
 occurred_at timestamptz NOT NULL, integrity_hash text NOT NULL, summary text NOT NULL, metadata jsonb NOT NULL,
 provenance text NOT NULL, PRIMARY KEY(tenant_id,event_id),
 FOREIGN KEY(tenant_id,session_id) REFERENCES platform.live_response_sessions(tenant_id,session_id));
CREATE INDEX IF NOT EXISTS live_transcript_timeline_idx ON platform.live_response_transcript(tenant_id,session_id,occurred_at,event_id);
CREATE OR REPLACE FUNCTION platform.reject_live_transcript_mutation() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'live response transcript is immutable'; END $$;
DROP TRIGGER IF EXISTS live_transcript_immutable ON platform.live_response_transcript;
CREATE TRIGGER live_transcript_immutable BEFORE UPDATE OR DELETE ON platform.live_response_transcript FOR EACH ROW EXECUTE FUNCTION platform.reject_live_transcript_mutation();
CREATE TABLE IF NOT EXISTS platform.live_response_artifacts(
 tenant_id uuid NOT NULL REFERENCES platform.tenants(id), artifact_id uuid NOT NULL, session_id uuid NOT NULL,
 command_id uuid NOT NULL, object_id text NOT NULL, manifest_object_id uuid NOT NULL, name text NOT NULL,
 media_type text NOT NULL, size_bytes bigint NOT NULL CHECK(size_bytes>=0), sha256 text NOT NULL CHECK(length(sha256)=64),
 native_identity text NOT NULL, consistent boolean NOT NULL, created_at timestamptz NOT NULL, expires_at timestamptz NOT NULL,
 PRIMARY KEY(tenant_id,artifact_id), FOREIGN KEY(tenant_id,session_id) REFERENCES platform.live_response_sessions(tenant_id,session_id));
INSERT INTO platform.schema_migrations(version,checksum) VALUES('0022_live_response','generated-at-build') ON CONFLICT(version) DO NOTHING;
COMMIT;
