CREATE TABLE IF NOT EXISTS platform.fleet_endpoint_metadata (
 tenant_id uuid NOT NULL, endpoint_id uuid NOT NULL, installation_id text NOT NULL,
 ring_id text NOT NULL, eligibility text NOT NULL, updated_at timestamptz NOT NULL,
 data jsonb NOT NULL, PRIMARY KEY(tenant_id, endpoint_id));
CREATE TABLE IF NOT EXISTS platform.fleet_groups (
 tenant_id uuid NOT NULL, group_id uuid NOT NULL, version integer NOT NULL,
 group_hash text NOT NULL, updated_at timestamptz NOT NULL, data jsonb NOT NULL,
 PRIMARY KEY(tenant_id, group_id));
CREATE TABLE IF NOT EXISTS platform.deployment_ring_policies (
 tenant_id uuid NOT NULL, policy_id uuid NOT NULL, version integer NOT NULL,
 policy_hash text NOT NULL, created_at timestamptz NOT NULL, data jsonb NOT NULL,
 PRIMARY KEY(tenant_id, policy_id, version));
CREATE TABLE IF NOT EXISTS platform.agent_update_packages (
 tenant_id uuid NOT NULL, package_id uuid NOT NULL, target_version text NOT NULL,
 platform_name text NOT NULL, architecture text NOT NULL, manifest_hash text NOT NULL,
 package_hash text NOT NULL, revoked boolean NOT NULL, expires_at timestamptz NOT NULL,
 data jsonb NOT NULL, PRIMARY KEY(tenant_id, package_id));
CREATE TABLE IF NOT EXISTS platform.agent_update_policies (
 tenant_id uuid NOT NULL, policy_id uuid NOT NULL, version integer NOT NULL,
 policy_hash text NOT NULL, created_at timestamptz NOT NULL, data jsonb NOT NULL,
 PRIMARY KEY(tenant_id, policy_id, version));
CREATE TABLE IF NOT EXISTS platform.agent_update_rollouts (
 tenant_id uuid NOT NULL, rollout_id uuid NOT NULL, package_id uuid NOT NULL,
 state text NOT NULL, current_ring text NOT NULL, updated_at timestamptz NOT NULL DEFAULT now(),
 data jsonb NOT NULL, PRIMARY KEY(tenant_id, rollout_id));
CREATE TABLE IF NOT EXISTS platform.agent_update_assignments (
 tenant_id uuid NOT NULL, assignment_id uuid NOT NULL, rollout_id uuid NOT NULL,
 endpoint_id uuid NOT NULL, installation_id text NOT NULL, package_id uuid NOT NULL,
 state text NOT NULL, updated_at timestamptz NOT NULL, data jsonb NOT NULL,
 PRIMARY KEY(tenant_id, assignment_id));
CREATE UNIQUE INDEX IF NOT EXISTS ux_agent_update_active_endpoint ON platform.agent_update_assignments(tenant_id,endpoint_id)
 WHERE state IN ('Assigned','WaitingForRing','WaitingForWindow','Downloading','Downloaded','Verifying','Staged','Installing','Restarting','VerifyingInstall','RollbackPending','RollingBack');
CREATE TABLE IF NOT EXISTS platform.fleet_update_audit (
 tenant_id uuid NOT NULL, audit_id uuid NOT NULL, object_type text NOT NULL,
 object_id text NOT NULL, action text NOT NULL, actor text NOT NULL,
 occurred_at timestamptz NOT NULL, object_hash text NOT NULL, data jsonb NOT NULL,
 PRIMARY KEY(tenant_id,audit_id));
CREATE INDEX IF NOT EXISTS ix_fleet_update_audit_tenant_time ON platform.fleet_update_audit(tenant_id,occurred_at DESC);
ALTER TABLE platform.fleet_endpoint_metadata ENABLE ROW LEVEL SECURITY;
ALTER TABLE platform.fleet_groups ENABLE ROW LEVEL SECURITY;
ALTER TABLE platform.deployment_ring_policies ENABLE ROW LEVEL SECURITY;
ALTER TABLE platform.agent_update_packages ENABLE ROW LEVEL SECURITY;
ALTER TABLE platform.agent_update_policies ENABLE ROW LEVEL SECURITY;
ALTER TABLE platform.agent_update_rollouts ENABLE ROW LEVEL SECURITY;
ALTER TABLE platform.agent_update_assignments ENABLE ROW LEVEL SECURITY;
ALTER TABLE platform.fleet_update_audit ENABLE ROW LEVEL SECURITY;
