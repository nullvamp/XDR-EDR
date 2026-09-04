BEGIN;
CREATE TABLE IF NOT EXISTS platform.response_actions(
 tenant_id uuid NOT NULL REFERENCES platform.tenants(id), response_action_id uuid NOT NULL,
 endpoint_id uuid NOT NULL, agent_id uuid NOT NULL, agent_installation_id text NOT NULL,
 action_type text NOT NULL, action_version integer NOT NULL CHECK(action_version>0), analyst_id text NOT NULL,
 state text NOT NULL, approval_state text NOT NULL, parameter_hash text NOT NULL CHECK(length(parameter_hash)=64),
 nonce text NOT NULL, requested_at timestamptz NOT NULL, expires_at timestamptz NOT NULL,
 action_revision integer NOT NULL CHECK(action_revision>0), action_data jsonb NOT NULL, updated_at timestamptz NOT NULL,
 PRIMARY KEY(tenant_id,response_action_id), UNIQUE(tenant_id,nonce),
 FOREIGN KEY(tenant_id,endpoint_id) REFERENCES platform.endpoints(tenant_id,id),
 FOREIGN KEY(tenant_id,agent_id) REFERENCES platform.agents(tenant_id,id));
CREATE INDEX IF NOT EXISTS response_actions_queue_idx ON platform.response_actions(tenant_id,endpoint_id,state,requested_at,response_action_id);
CREATE INDEX IF NOT EXISTS response_actions_expiry_idx ON platform.response_actions(expires_at) WHERE state NOT IN('Succeeded','Failed','TimedOut','Cancelled','Expired','Rejected');
CREATE TABLE IF NOT EXISTS platform.response_action_audit(
 tenant_id uuid NOT NULL REFERENCES platform.tenants(id), audit_id uuid NOT NULL, response_action_id uuid NOT NULL,
 object_version integer NOT NULL, action text NOT NULL, actor text NOT NULL, occurred_at timestamptz NOT NULL,
 parameter_hash text NOT NULL, reason text NOT NULL, before_data jsonb NOT NULL, after_data jsonb NOT NULL,
 provenance text NOT NULL, PRIMARY KEY(tenant_id,audit_id),
 FOREIGN KEY(tenant_id,response_action_id) REFERENCES platform.response_actions(tenant_id,response_action_id));
CREATE UNIQUE INDEX IF NOT EXISTS response_audit_version_idx ON platform.response_action_audit(tenant_id,response_action_id,object_version,action);
CREATE INDEX IF NOT EXISTS response_audit_timeline_idx ON platform.response_action_audit(tenant_id,response_action_id,occurred_at,audit_id);
CREATE OR REPLACE FUNCTION platform.reject_response_audit_mutation() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'response audit is immutable'; END $$;
DROP TRIGGER IF EXISTS response_audit_immutable ON platform.response_action_audit;
CREATE TRIGGER response_audit_immutable BEFORE UPDATE OR DELETE ON platform.response_action_audit FOR EACH ROW EXECUTE FUNCTION platform.reject_response_audit_mutation();
CREATE TABLE IF NOT EXISTS platform.response_artifacts(
 tenant_id uuid NOT NULL REFERENCES platform.tenants(id), artifact_id uuid NOT NULL, response_action_id uuid NOT NULL,
 object_id text NOT NULL, manifest_object_id uuid NOT NULL, name text NOT NULL, media_type text NOT NULL,
 size_bytes bigint NOT NULL CHECK(size_bytes>=0), sha256 text NOT NULL CHECK(length(sha256)=64),
 created_at timestamptz NOT NULL, expires_at timestamptz NOT NULL, cleaned_at timestamptz NULL, PRIMARY KEY(tenant_id,artifact_id),
 FOREIGN KEY(tenant_id,response_action_id) REFERENCES platform.response_actions(tenant_id,response_action_id));
CREATE INDEX IF NOT EXISTS response_artifacts_cleanup_idx ON platform.response_artifacts(expires_at) WHERE cleaned_at IS NULL;
CREATE TABLE IF NOT EXISTS platform.response_policies(
 tenant_id uuid NOT NULL REFERENCES platform.tenants(id), policy_id uuid NOT NULL, policy_version integer NOT NULL,
 enabled boolean NOT NULL, require_diagnostic_approval boolean NOT NULL DEFAULT true,
 maximum_queued_per_endpoint integer NOT NULL DEFAULT 100 CHECK(maximum_queued_per_endpoint BETWEEN 1 AND 1000),
 created_by text NOT NULL, created_at timestamptz NOT NULL, policy_data jsonb NOT NULL,
 PRIMARY KEY(tenant_id,policy_id,policy_version));
INSERT INTO platform.schema_migrations(version,checksum) VALUES('0021_response_engine','generated-at-build') ON CONFLICT(version) DO NOTHING;
COMMIT;
