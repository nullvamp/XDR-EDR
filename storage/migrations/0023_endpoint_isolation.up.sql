BEGIN;
CREATE TABLE IF NOT EXISTS platform.endpoint_isolation_policies (
    tenant_id uuid PRIMARY KEY REFERENCES platform.tenants(id),
    policy_version text NOT NULL,
    policy_data jsonb NOT NULL,
    updated_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS platform.endpoint_isolation_state (
    tenant_id uuid NOT NULL REFERENCES platform.tenants(id),
    endpoint_id uuid NOT NULL,
    agent_installation_id text NOT NULL,
    effective_state text NOT NULL,
    policy_version text NOT NULL,
    last_verified_at timestamptz,
    state_data jsonb NOT NULL,
    updated_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (tenant_id, endpoint_id),
    FOREIGN KEY (tenant_id, endpoint_id) REFERENCES platform.endpoints(tenant_id, id)
);

CREATE INDEX IF NOT EXISTS endpoint_isolation_state_effective_idx
    ON platform.endpoint_isolation_state(tenant_id, effective_state, updated_at DESC);
INSERT INTO platform.schema_migrations(version,checksum) VALUES('0023_endpoint_isolation','generated-at-build') ON CONFLICT(version) DO NOTHING;
COMMIT;
