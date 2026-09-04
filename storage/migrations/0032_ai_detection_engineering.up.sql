CREATE TABLE IF NOT EXISTS platform.ai_hunt_proposals (tenant_id uuid NOT NULL REFERENCES platform.tenants(id),proposal_id uuid NOT NULL,proposal_hash text NOT NULL,state text NOT NULL,proposal_data jsonb NOT NULL,created_at timestamptz NOT NULL,updated_at timestamptz NOT NULL,PRIMARY KEY(tenant_id,proposal_id));
CREATE INDEX IF NOT EXISTS ix_ai_hunt_proposals_tenant_created ON platform.ai_hunt_proposals(tenant_id,created_at DESC);
CREATE TABLE IF NOT EXISTS platform.ai_rule_drafts (tenant_id uuid NOT NULL REFERENCES platform.tenants(id),draft_id uuid NOT NULL,draft_hash text NOT NULL,draft_kind text NOT NULL,state text NOT NULL,draft_data jsonb NOT NULL,created_at timestamptz NOT NULL,updated_at timestamptz NOT NULL,PRIMARY KEY(tenant_id,draft_id));
CREATE INDEX IF NOT EXISTS ix_ai_rule_drafts_tenant_created ON platform.ai_rule_drafts(tenant_id,created_at DESC);
CREATE TABLE IF NOT EXISTS platform.ai_rule_simulations (tenant_id uuid NOT NULL REFERENCES platform.tenants(id),simulation_id uuid NOT NULL,draft_id uuid NOT NULL,simulation_data jsonb NOT NULL,completed_at timestamptz NOT NULL,PRIMARY KEY(tenant_id,simulation_id));
CREATE INDEX IF NOT EXISTS ix_ai_rule_simulations_draft ON platform.ai_rule_simulations(tenant_id,draft_id,completed_at DESC);
CREATE TABLE IF NOT EXISTS platform.ai_rule_comparisons (tenant_id uuid NOT NULL REFERENCES platform.tenants(id),comparison_id uuid NOT NULL,draft_id uuid NOT NULL,comparison_data jsonb NOT NULL,completed_at timestamptz NOT NULL,PRIMARY KEY(tenant_id,comparison_id));
CREATE TABLE IF NOT EXISTS platform.ai_engineering_audit (tenant_id uuid NOT NULL REFERENCES platform.tenants(id),audit_id uuid NOT NULL,actor text NOT NULL,action text NOT NULL,object_type text NOT NULL,object_id uuid NOT NULL,object_hash text NOT NULL,occurred_at timestamptz NOT NULL,detail jsonb NOT NULL,PRIMARY KEY(tenant_id,audit_id));
CREATE INDEX IF NOT EXISTS ix_ai_engineering_audit_tenant_time ON platform.ai_engineering_audit(tenant_id,occurred_at DESC);
ALTER TABLE platform.ai_hunt_proposals ENABLE ROW LEVEL SECURITY;
ALTER TABLE platform.ai_rule_drafts ENABLE ROW LEVEL SECURITY;
ALTER TABLE platform.ai_rule_simulations ENABLE ROW LEVEL SECURITY;
ALTER TABLE platform.ai_rule_comparisons ENABLE ROW LEVEL SECURITY;
ALTER TABLE platform.ai_engineering_audit ENABLE ROW LEVEL SECURITY;
DO $$ DECLARE t text; BEGIN FOREACH t IN ARRAY ARRAY['ai_hunt_proposals','ai_rule_drafts','ai_rule_simulations','ai_rule_comparisons','ai_engineering_audit'] LOOP
 EXECUTE format('DROP POLICY IF EXISTS tenant_isolation ON platform.%I',t);
 EXECUTE format('CREATE POLICY tenant_isolation ON platform.%I USING (tenant_id = nullif(current_setting(''app.tenant_id'',true),'''')::uuid) WITH CHECK (tenant_id = nullif(current_setting(''app.tenant_id'',true),'''')::uuid)',t);
END LOOP; END $$;
