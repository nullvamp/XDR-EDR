BEGIN;
CREATE TABLE platform.enrollment_policies(
  tenant_id uuid NOT NULL REFERENCES platform.tenants(id), id uuid NOT NULL DEFAULT gen_random_uuid(), name text NOT NULL,
  allowed_platforms text[] NOT NULL DEFAULT ARRAY['windows','linux','macos'], heartbeat_interval_seconds integer NOT NULL DEFAULT 30 CHECK(heartbeat_interval_seconds BETWEEN 10 AND 3600),
  stale_after_seconds integer NOT NULL DEFAULT 120 CHECK(stale_after_seconds>heartbeat_interval_seconds), offline_after_seconds integer NOT NULL DEFAULT 600 CHECK(offline_after_seconds>stale_after_seconds),
  status text NOT NULL DEFAULT 'active' CHECK(status IN('active','disabled','archived')), created_by text NOT NULL, created_at timestamptz NOT NULL DEFAULT now(), revision bigint NOT NULL DEFAULT 1,
  PRIMARY KEY(tenant_id,id), UNIQUE(tenant_id,name));
CREATE TABLE platform.enrollment_tokens(
  tenant_id uuid NOT NULL REFERENCES platform.tenants(id), id uuid NOT NULL DEFAULT gen_random_uuid(), secret_hash text NOT NULL,
  expires_at timestamptz NOT NULL, maximum_uses integer NOT NULL CHECK(maximum_uses BETWEEN 1 AND 100000), uses integer NOT NULL DEFAULT 0 CHECK(uses>=0 AND uses<=maximum_uses),
  allowed_platforms text[] NOT NULL, endpoint_group_id uuid, policy_id uuid, revoked_at timestamptz, created_by text NOT NULL, created_at timestamptz NOT NULL DEFAULT now(), last_used_at timestamptz,
  PRIMARY KEY(tenant_id,id), CHECK(cardinality(allowed_platforms)>0));
CREATE INDEX enrollment_tokens_active_idx ON platform.enrollment_tokens(tenant_id,expires_at) WHERE revoked_at IS NULL;
CREATE TABLE platform.endpoint_identities(
  tenant_id uuid NOT NULL, endpoint_id uuid NOT NULL, identity_type text NOT NULL, identity_value text NOT NULL, confidence smallint NOT NULL CHECK(confidence BETWEEN 0 AND 100),
  created_at timestamptz NOT NULL DEFAULT now(), revoked_at timestamptz, PRIMARY KEY(tenant_id,endpoint_id,identity_type,identity_value),
  FOREIGN KEY(tenant_id,endpoint_id) REFERENCES platform.endpoints(tenant_id,id));
CREATE TABLE platform.agent_credentials(
  tenant_id uuid NOT NULL, agent_id uuid NOT NULL, credential_id uuid NOT NULL DEFAULT gen_random_uuid(), credential_type text NOT NULL,
  public_key_sha256 text NOT NULL, certificate_thumbprint text, certificate_not_before timestamptz, certificate_not_after timestamptz,
  issued_at timestamptz NOT NULL DEFAULT now(), revoked_at timestamptz, PRIMARY KEY(tenant_id,credential_id),
  FOREIGN KEY(tenant_id,agent_id) REFERENCES platform.agents(tenant_id,id), UNIQUE(tenant_id,public_key_sha256));
CREATE TABLE platform.enrollment_attempts(
  tenant_id uuid NOT NULL, id uuid NOT NULL DEFAULT gen_random_uuid(), token_id uuid, installation_id text NOT NULL, nonce_hash text NOT NULL,
  request_hash text NOT NULL, outcome text NOT NULL, safe_reason text, endpoint_id uuid, agent_id uuid, occurred_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY(tenant_id,id), UNIQUE(tenant_id,nonce_hash));
CREATE TABLE platform.idempotency_records(
  tenant_id uuid NOT NULL, scope text NOT NULL, idempotency_key text NOT NULL, request_hash text NOT NULL, response_json jsonb,
  state text NOT NULL CHECK(state IN('processing','completed','failed')), created_at timestamptz NOT NULL DEFAULT now(), expires_at timestamptz NOT NULL,
  PRIMARY KEY(tenant_id,scope,idempotency_key));
CREATE INDEX idempotency_expiry_idx ON platform.idempotency_records(expires_at);
CREATE TABLE platform.agent_heartbeats(
  tenant_id uuid NOT NULL, agent_id uuid NOT NULL, endpoint_id uuid NOT NULL, sequence bigint NOT NULL CHECK(sequence>0), occurred_at timestamptz NOT NULL,
  received_at timestamptz NOT NULL DEFAULT now(), agent_version text NOT NULL, protocol_version text NOT NULL, health text NOT NULL,
  queue_depth bigint NOT NULL DEFAULT 0 CHECK(queue_depth>=0), inventory jsonb, data jsonb NOT NULL DEFAULT '{}',
  PRIMARY KEY(tenant_id,agent_id,sequence), FOREIGN KEY(tenant_id,agent_id) REFERENCES platform.agents(tenant_id,id), FOREIGN KEY(tenant_id,endpoint_id) REFERENCES platform.endpoints(tenant_id,id));
CREATE INDEX agent_heartbeats_endpoint_idx ON platform.agent_heartbeats(tenant_id,endpoint_id,received_at DESC);
CREATE TABLE platform.endpoint_inventory_summaries(
  tenant_id uuid NOT NULL, endpoint_id uuid NOT NULL, hostname text NOT NULL, platform text NOT NULL, os_version text NOT NULL, architecture text NOT NULL,
  tags text[] NOT NULL DEFAULT '{}', groups text[] NOT NULL DEFAULT '{}', observed_at timestamptz NOT NULL, source_revision bigint NOT NULL,
  PRIMARY KEY(tenant_id,endpoint_id), FOREIGN KEY(tenant_id,endpoint_id) REFERENCES platform.endpoints(tenant_id,id));
ALTER TABLE platform.outbox ADD COLUMN IF NOT EXISTS subject text NOT NULL DEFAULT 'platform.unknown.v1';
ALTER TABLE platform.outbox ADD COLUMN IF NOT EXISTS trace_id text NOT NULL DEFAULT '';
ALTER TABLE platform.outbox ADD COLUMN IF NOT EXISTS available_at timestamptz NOT NULL DEFAULT now();
ALTER TABLE platform.outbox ADD COLUMN IF NOT EXISTS lease_until timestamptz;
ALTER TABLE platform.outbox ADD COLUMN IF NOT EXISTS failed_at timestamptz;
ALTER TABLE platform.outbox ADD COLUMN IF NOT EXISTS safe_failure text;
CREATE INDEX outbox_pending_idx ON platform.outbox(available_at,created_at) WHERE published_at IS NULL AND failed_at IS NULL;
CREATE TABLE platform.service_registrations(
  service_name text NOT NULL, instance_id text NOT NULL, address text NOT NULL, region text NOT NULL, started_at timestamptz NOT NULL, last_seen_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY(service_name,instance_id));
ALTER TABLE platform.endpoints ADD COLUMN IF NOT EXISTS status text NOT NULL DEFAULT 'pending';
ALTER TABLE platform.endpoints ADD COLUMN IF NOT EXISTS agent_version text;
ALTER TABLE platform.endpoints ADD COLUMN IF NOT EXISTS inventory jsonb;
ALTER TABLE platform.endpoints ADD COLUMN IF NOT EXISTS deleted_at timestamptz;
ALTER TABLE platform.agents ADD COLUMN IF NOT EXISTS protocol_version text NOT NULL DEFAULT '1.0';
ALTER TABLE platform.agents ADD COLUMN IF NOT EXISTS credential_expires_at timestamptz;
INSERT INTO platform.schema_migrations(version,checksum) VALUES ('0002_endpoint_enrollment','generated-at-build') ON CONFLICT(version) DO NOTHING;
COMMIT;
