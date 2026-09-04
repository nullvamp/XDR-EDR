CREATE TABLE IF NOT EXISTS platform.forensic_workspace_states (
  tenant_id uuid PRIMARY KEY,
  revision bigint NOT NULL CHECK (revision > 0),
  state_data jsonb NOT NULL,
  updated_at timestamptz NOT NULL DEFAULT now()
);
ALTER TABLE platform.forensic_workspace_states ENABLE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS forensic_workspace_tenant_isolation ON platform.forensic_workspace_states;
CREATE POLICY forensic_workspace_tenant_isolation ON platform.forensic_workspace_states
  USING (tenant_id = nullif(current_setting('app.tenant_id', true), '')::uuid)
  WITH CHECK (tenant_id = nullif(current_setting('app.tenant_id', true), '')::uuid);
COMMENT ON TABLE platform.forensic_workspace_states IS 'Tenant-authoritative immutable-evidence investigation workspace; source object bytes remain in object storage.';
