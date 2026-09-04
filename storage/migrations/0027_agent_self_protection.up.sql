CREATE TABLE IF NOT EXISTS platform.agent_protection_policies (
    tenant_id uuid NOT NULL, endpoint_id uuid NOT NULL, policy_version integer NOT NULL,
    installation_id text NOT NULL, policy_hash text NOT NULL, policy_data jsonb NOT NULL,
    created_at timestamptz NOT NULL, PRIMARY KEY(tenant_id,endpoint_id,policy_version));
CREATE INDEX IF NOT EXISTS ix_agent_protection_policy_current ON platform.agent_protection_policies(tenant_id,endpoint_id,policy_version DESC);
CREATE TABLE IF NOT EXISTS platform.agent_protection_snapshots (
    tenant_id uuid NOT NULL, endpoint_id uuid NOT NULL, installation_id text NOT NULL,
    policy_version integer NOT NULL, state text NOT NULL, verified_at timestamptz NOT NULL,
    snapshot_hash text NOT NULL, snapshot_data jsonb NOT NULL, PRIMARY KEY(tenant_id,endpoint_id));
CREATE TABLE IF NOT EXISTS platform.agent_tamper_events (
    tenant_id uuid NOT NULL, event_id uuid NOT NULL, endpoint_id uuid NOT NULL,
    installation_id text NOT NULL, event_type text NOT NULL, resource_id text NOT NULL,
    occurred_at timestamptz NOT NULL, event_hash text NOT NULL, event_data jsonb NOT NULL,
    PRIMARY KEY(tenant_id,event_id));
CREATE INDEX IF NOT EXISTS ix_agent_tamper_events_endpoint ON platform.agent_tamper_events(tenant_id,endpoint_id,occurred_at DESC);
CREATE TABLE IF NOT EXISTS platform.agent_maintenance_authorizations (
    tenant_id uuid NOT NULL, maintenance_id uuid NOT NULL, endpoint_id uuid NOT NULL,
    installation_id text NOT NULL, state text NOT NULL, request_hash text NOT NULL,
    starts_at timestamptz NOT NULL, expires_at timestamptz NOT NULL, authorization_data jsonb NOT NULL,
    PRIMARY KEY(tenant_id,maintenance_id));
CREATE INDEX IF NOT EXISTS ix_agent_maintenance_active ON platform.agent_maintenance_authorizations(tenant_id,endpoint_id,state,expires_at);
CREATE TABLE IF NOT EXISTS platform.agent_protection_repairs (
    tenant_id uuid NOT NULL, repair_id uuid NOT NULL, endpoint_id uuid NOT NULL,
    installation_id text NOT NULL, resource_id text NOT NULL, state text NOT NULL,
    requested_at timestamptz NOT NULL, repair_data jsonb NOT NULL, PRIMARY KEY(tenant_id,repair_id));
CREATE TABLE IF NOT EXISTS platform.agent_protection_audit (
    tenant_id uuid NOT NULL, audit_id uuid NOT NULL, endpoint_id uuid NOT NULL,
    object_type text NOT NULL, object_id text NOT NULL, action text NOT NULL, actor text NOT NULL,
    occurred_at timestamptz NOT NULL DEFAULT now(), object_hash text NOT NULL, reason text NOT NULL,
    PRIMARY KEY(tenant_id,audit_id));
