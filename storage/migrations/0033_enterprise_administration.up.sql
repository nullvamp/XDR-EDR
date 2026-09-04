BEGIN;
CREATE TABLE IF NOT EXISTS platform.administration_states(
 tenant_id uuid PRIMARY KEY REFERENCES platform.tenants(id), revision bigint NOT NULL CHECK(revision>0),
 state_data jsonb NOT NULL, updated_at timestamptz NOT NULL DEFAULT now());
CREATE TABLE IF NOT EXISTS platform.administration_api_credentials(
 tenant_id uuid NOT NULL REFERENCES platform.tenants(id), credential_id uuid PRIMARY KEY, principal_id uuid NOT NULL,
 version integer NOT NULL CHECK(version>0), prefix text NOT NULL UNIQUE, secret_hash text NOT NULL,
 expires_at timestamptz NOT NULL, revoked_at timestamptz, last_used_at timestamptz, metadata jsonb NOT NULL);
CREATE INDEX IF NOT EXISTS administration_api_credentials_tenant_idx ON platform.administration_api_credentials(tenant_id,principal_id,expires_at);
CREATE TABLE IF NOT EXISTS platform.administration_audit(
 tenant_id uuid NOT NULL REFERENCES platform.tenants(id), audit_id uuid NOT NULL, occurred_at timestamptz NOT NULL,
 actor text NOT NULL, action text NOT NULL, resource_type text NOT NULL, resource_id text NOT NULL,
 before_hash text, after_hash text, reason text NOT NULL, request_id text NOT NULL, approval_id uuid,
 result text NOT NULL, event_data jsonb NOT NULL, PRIMARY KEY(tenant_id,audit_id));
CREATE INDEX IF NOT EXISTS administration_audit_search_idx ON platform.administration_audit(tenant_id,occurred_at DESC,action,resource_type);
ALTER TABLE platform.administration_states ENABLE ROW LEVEL SECURITY;
ALTER TABLE platform.administration_api_credentials ENABLE ROW LEVEL SECURITY;
ALTER TABLE platform.administration_audit ENABLE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS tenant_isolation ON platform.administration_states;
DROP POLICY IF EXISTS tenant_isolation ON platform.administration_api_credentials;
DROP POLICY IF EXISTS tenant_isolation ON platform.administration_audit;
CREATE POLICY tenant_isolation ON platform.administration_states USING (tenant_id=nullif(current_setting('app.tenant_id',true),'')::uuid) WITH CHECK(tenant_id=nullif(current_setting('app.tenant_id',true),'')::uuid);
CREATE POLICY tenant_isolation ON platform.administration_api_credentials USING (tenant_id=nullif(current_setting('app.tenant_id',true),'')::uuid) WITH CHECK(tenant_id=nullif(current_setting('app.tenant_id',true),'')::uuid);
CREATE POLICY tenant_isolation ON platform.administration_audit USING (tenant_id=nullif(current_setting('app.tenant_id',true),'')::uuid) WITH CHECK(tenant_id=nullif(current_setting('app.tenant_id',true),'')::uuid);
COMMIT;
