BEGIN;
CREATE TABLE platform.process_policy_versions(
 tenant_id uuid NOT NULL REFERENCES platform.tenants(id), id uuid NOT NULL DEFAULT gen_random_uuid(),
 name text NOT NULL CHECK(length(name) BETWEEN 1 AND 200), version integer NOT NULL CHECK(version > 0),
 content jsonb NOT NULL, content_hash text NOT NULL CHECK(content_hash ~ '^[0-9a-f]{64}$'),
 status text NOT NULL CHECK(status IN('active','superseded')), created_by text NOT NULL,
 created_at timestamptz NOT NULL DEFAULT now(), PRIMARY KEY(tenant_id,id), UNIQUE(tenant_id,name,version));
CREATE TABLE platform.process_policy_assignments(
 tenant_id uuid NOT NULL REFERENCES platform.tenants(id), id uuid NOT NULL DEFAULT gen_random_uuid(),
 policy_id uuid NOT NULL, endpoint_id uuid, assigned_by text NOT NULL, assigned_at timestamptz NOT NULL DEFAULT now(),
 PRIMARY KEY(tenant_id,id), FOREIGN KEY(tenant_id,policy_id) REFERENCES platform.process_policy_versions(tenant_id,id),
 FOREIGN KEY(tenant_id,endpoint_id) REFERENCES platform.endpoints(tenant_id,id));
CREATE UNIQUE INDEX process_policy_tenant_default_idx ON platform.process_policy_assignments(tenant_id) WHERE endpoint_id IS NULL;
CREATE UNIQUE INDEX process_policy_endpoint_idx ON platform.process_policy_assignments(tenant_id,endpoint_id) WHERE endpoint_id IS NOT NULL;
CREATE TABLE platform.process_policy_acknowledgements(
 tenant_id uuid NOT NULL, endpoint_id uuid NOT NULL, policy_id uuid NOT NULL, version integer NOT NULL,
 applied boolean NOT NULL, validation_error text, acknowledged_at timestamptz NOT NULL,
 PRIMARY KEY(tenant_id,endpoint_id), FOREIGN KEY(tenant_id,endpoint_id) REFERENCES platform.endpoints(tenant_id,id));
CREATE TABLE platform.process_exclusion_metrics(
 tenant_id uuid NOT NULL, endpoint_id uuid NOT NULL, rule_id uuid NOT NULL, category text NOT NULL,
 events_excluded bigint NOT NULL DEFAULT 0, last_match_at timestamptz,
 PRIMARY KEY(tenant_id,endpoint_id,rule_id), FOREIGN KEY(tenant_id,endpoint_id) REFERENCES platform.endpoints(tenant_id,id));
ALTER TABLE platform.process_telemetry_health ADD COLUMN excluded_events bigint NOT NULL DEFAULT 0,
 ADD COLUMN last_exclusion_rule_id uuid, ADD COLUMN last_exclusion_category text, ADD COLUMN last_exclusion_at timestamptz;
CREATE TABLE platform.process_policy_audit(
 tenant_id uuid NOT NULL, id uuid NOT NULL DEFAULT gen_random_uuid(), actor text NOT NULL, action text NOT NULL,
 policy_id uuid, endpoint_id uuid, details jsonb NOT NULL DEFAULT '{}', occurred_at timestamptz NOT NULL DEFAULT now(),
 PRIMARY KEY(tenant_id,id));
INSERT INTO platform.schema_migrations(version,checksum) VALUES('0005_process_policy','sha256:sprint2b-process-policy-v1') ON CONFLICT(version) DO NOTHING;
COMMIT;
