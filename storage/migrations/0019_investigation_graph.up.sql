BEGIN;

CREATE TABLE IF NOT EXISTS platform.investigation_entities(
  tenant_id uuid NOT NULL REFERENCES platform.tenants(id), entity_id text NOT NULL, entity_type text NOT NULL,
  endpoint_id uuid, first_observed timestamptz NOT NULL, last_observed timestamptz NOT NULL,
  entity_data jsonb NOT NULL, evidence_ids uuid[] NOT NULL, evidence_references text[] NOT NULL,
  provenance text NOT NULL, ambiguous boolean NOT NULL, relationship_version integer NOT NULL,
  PRIMARY KEY(tenant_id,entity_id,entity_type));
CREATE INDEX IF NOT EXISTS investigation_entities_time_idx ON platform.investigation_entities(tenant_id,first_observed,last_observed,entity_type);
CREATE INDEX IF NOT EXISTS investigation_entities_endpoint_idx ON platform.investigation_entities(tenant_id,endpoint_id,entity_type,last_observed DESC);

CREATE TABLE IF NOT EXISTS platform.investigation_relationships(
  tenant_id uuid NOT NULL REFERENCES platform.tenants(id), relationship_id uuid NOT NULL,
  source_entity_id text NOT NULL, source_type text NOT NULL, destination_entity_id text NOT NULL, destination_type text NOT NULL,
  relationship_type text NOT NULL, first_observed timestamptz NOT NULL, last_observed timestamptz NOT NULL,
  confidence integer NOT NULL CHECK(confidence BETWEEN 0 AND 100), provenance text NOT NULL,
  ambiguous boolean NOT NULL, relationship_version integer NOT NULL, evidence_ids uuid[] NOT NULL,
  evidence_references text[] NOT NULL, relationship_data jsonb NOT NULL,
  PRIMARY KEY(tenant_id,relationship_id));
CREATE INDEX IF NOT EXISTS investigation_relationship_source_idx ON platform.investigation_relationships(tenant_id,source_entity_id,relationship_type,last_observed DESC);
CREATE INDEX IF NOT EXISTS investigation_relationship_destination_idx ON platform.investigation_relationships(tenant_id,destination_entity_id,relationship_type,last_observed DESC);
CREATE INDEX IF NOT EXISTS investigation_relationship_time_idx ON platform.investigation_relationships(tenant_id,first_observed,last_observed);

CREATE TABLE IF NOT EXISTS platform.saved_hunts(
  tenant_id uuid NOT NULL REFERENCES platform.tenants(id), hunt_id uuid NOT NULL, version integer NOT NULL,
  name text NOT NULL, owner text NOT NULL, enabled boolean NOT NULL, hunt_data jsonb NOT NULL,
  created_at timestamptz NOT NULL, created_by text NOT NULL, PRIMARY KEY(tenant_id,hunt_id,version));
CREATE INDEX IF NOT EXISTS saved_hunts_owner_idx ON platform.saved_hunts(tenant_id,owner,name,version DESC);

CREATE TABLE IF NOT EXISTS platform.hunt_runs(
  tenant_id uuid NOT NULL REFERENCES platform.tenants(id), run_id uuid NOT NULL, hunt_id uuid NOT NULL,
  hunt_version integer NOT NULL, status text NOT NULL, cancel_requested boolean NOT NULL,
  run_data jsonb NOT NULL, started_at timestamptz NOT NULL, completed_at timestamptz,
  PRIMARY KEY(tenant_id,run_id));
CREATE INDEX IF NOT EXISTS hunt_runs_history_idx ON platform.hunt_runs(tenant_id,hunt_id,started_at DESC);

CREATE TABLE IF NOT EXISTS platform.investigation_audit(
  tenant_id uuid NOT NULL, sequence bigint GENERATED ALWAYS AS IDENTITY, actor text NOT NULL,
  action text NOT NULL, target_type text NOT NULL, target_id text NOT NULL, occurred_at timestamptz NOT NULL,
  details jsonb NOT NULL, PRIMARY KEY(tenant_id,sequence));

COMMIT;
