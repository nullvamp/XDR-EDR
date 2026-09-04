BEGIN;
CREATE TABLE platform.endpoint_status_history(
  id uuid NOT NULL DEFAULT gen_random_uuid(),
  tenant_id uuid NOT NULL,
  endpoint_id uuid NOT NULL,
  previous_status text NOT NULL,
  status text NOT NULL CHECK(status IN('unknown','pending','online','stale','offline','recovered','disabled','revoked')),
  reason text NOT NULL,
  occurred_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY(id),
  FOREIGN KEY(tenant_id,endpoint_id) REFERENCES platform.endpoints(tenant_id,id)
);
CREATE INDEX endpoint_status_history_recent_idx ON platform.endpoint_status_history(tenant_id,endpoint_id,occurred_at DESC);
ALTER TABLE platform.endpoints ADD CONSTRAINT endpoints_lifecycle_status_check CHECK(status IN('unknown','pending','online','stale','offline','recovered','disabled','revoked')) NOT VALID;
ALTER TABLE platform.endpoints VALIDATE CONSTRAINT endpoints_lifecycle_status_check;
CREATE INDEX endpoints_lifecycle_scan_idx ON platform.endpoints(status,last_seen_at) WHERE deleted_at IS NULL AND status IN('online','recovered','stale');
INSERT INTO platform.schema_migrations(version,checksum) VALUES ('0003_endpoint_lifecycle','generated-at-build') ON CONFLICT(version) DO NOTHING;
COMMIT;
