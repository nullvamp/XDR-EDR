CREATE TABLE IF NOT EXISTS platform.tunnel_observations (
    tenant_id uuid NOT NULL, observation_id uuid NOT NULL, observation_data jsonb NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now(), PRIMARY KEY (tenant_id, observation_id));
CREATE INDEX IF NOT EXISTS ix_tunnel_observations_endpoint ON platform.tunnel_observations
    (tenant_id, (observation_data->>'endpointId'), (observation_data->>'lastObserved'));
CREATE INDEX IF NOT EXISTS ix_tunnel_observations_process ON platform.tunnel_observations
    (tenant_id, (observation_data->>'processEntityId'));
CREATE TABLE IF NOT EXISTS platform.tunnel_findings (
    tenant_id uuid NOT NULL, finding_id uuid NOT NULL, finding_data jsonb NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now(), PRIMARY KEY (tenant_id, finding_id));
CREATE INDEX IF NOT EXISTS ix_tunnel_findings_endpoint ON platform.tunnel_findings
    (tenant_id, (finding_data->>'endpointId'), (finding_data->>'lastObserved'));
CREATE TABLE IF NOT EXISTS platform.tunnel_exclusions (
    tenant_id uuid NOT NULL, exclusion_id uuid NOT NULL, version integer NOT NULL,
    exclusion_data jsonb NOT NULL, created_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (tenant_id, exclusion_id, version));
CREATE TABLE IF NOT EXISTS platform.tunnel_audit (
    tenant_id uuid NOT NULL, audit_id uuid NOT NULL, object_type text NOT NULL,
    object_id text NOT NULL, action text NOT NULL, actor text NOT NULL,
    audit_data jsonb NOT NULL, occurred_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (tenant_id, audit_id));
