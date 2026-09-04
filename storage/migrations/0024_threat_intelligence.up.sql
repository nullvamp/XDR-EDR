CREATE TABLE IF NOT EXISTS platform.intelligence_sources (
    tenant_id uuid NOT NULL, source_id uuid NOT NULL, version integer NOT NULL,
    source_data jsonb NOT NULL, created_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (tenant_id, source_id, version)
);
CREATE UNIQUE INDEX IF NOT EXISTS ux_intelligence_source_name ON platform.intelligence_sources
    (tenant_id, lower(source_data->>'name'));

CREATE TABLE IF NOT EXISTS platform.threat_indicators (
    tenant_id uuid NOT NULL, indicator_id uuid NOT NULL, version integer NOT NULL,
    source_id uuid NOT NULL, indicator_type text NOT NULL, canonical_value text NOT NULL,
    valid_from timestamptz NOT NULL, valid_until timestamptz NULL, revoked boolean NOT NULL,
    indicator_data jsonb NOT NULL, created_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (tenant_id, indicator_id, version)
);
CREATE INDEX IF NOT EXISTS ix_threat_indicators_active ON platform.threat_indicators
    (tenant_id, indicator_type, canonical_value, valid_from, valid_until) WHERE NOT revoked;
CREATE INDEX IF NOT EXISTS ix_threat_indicators_source ON platform.threat_indicators (tenant_id, source_id);

CREATE TABLE IF NOT EXISTS platform.threat_relationships (
    tenant_id uuid NOT NULL, relationship_id uuid NOT NULL, source_record_id text NOT NULL,
    target_record_id text NOT NULL, relationship_type text NOT NULL, source_id uuid NOT NULL,
    relationship_data jsonb NOT NULL, created_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (tenant_id, relationship_id)
);
CREATE TABLE IF NOT EXISTS platform.threat_imports (
    tenant_id uuid NOT NULL, import_id uuid NOT NULL, source_id uuid NOT NULL, format text NOT NULL,
    import_data jsonb NOT NULL, created_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (tenant_id, import_id)
);
CREATE TABLE IF NOT EXISTS platform.threat_matches (
    tenant_id uuid NOT NULL, match_id uuid NOT NULL, indicator_id uuid NOT NULL,
    indicator_version integer NOT NULL, evidence_event_id uuid NOT NULL, endpoint_id uuid NOT NULL,
    match_mode text NOT NULL, match_data jsonb NOT NULL, created_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (tenant_id, match_id)
);
CREATE INDEX IF NOT EXISTS ix_threat_matches_indicator ON platform.threat_matches (tenant_id, indicator_id, indicator_version);
CREATE INDEX IF NOT EXISTS ix_threat_matches_evidence ON platform.threat_matches (tenant_id, evidence_event_id);
CREATE TABLE IF NOT EXISTS platform.threat_match_jobs (
    tenant_id uuid NOT NULL, job_id uuid NOT NULL, indicator_id uuid NOT NULL,
    indicator_version integer NOT NULL, job_state text NOT NULL, job_data jsonb NOT NULL,
    updated_at timestamptz NOT NULL DEFAULT now(), PRIMARY KEY (tenant_id, job_id)
);
CREATE TABLE IF NOT EXISTS platform.threat_exclusions (
    tenant_id uuid NOT NULL, exclusion_id uuid NOT NULL, version integer NOT NULL,
    exclusion_data jsonb NOT NULL, created_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (tenant_id, exclusion_id, version)
);
CREATE TABLE IF NOT EXISTS platform.threat_health (
    tenant_id uuid PRIMARY KEY, health_data jsonb NOT NULL, updated_at timestamptz NOT NULL DEFAULT now()
);
CREATE TABLE IF NOT EXISTS platform.threat_audit (
    tenant_id uuid NOT NULL, audit_id uuid NOT NULL, object_type text NOT NULL,
    object_id text NOT NULL, action text NOT NULL, actor text NOT NULL, audit_data jsonb NOT NULL,
    occurred_at timestamptz NOT NULL DEFAULT now(), PRIMARY KEY (tenant_id, audit_id)
);
