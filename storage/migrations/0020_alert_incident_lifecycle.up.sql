BEGIN;

CREATE TABLE IF NOT EXISTS platform.alerts(
  tenant_id uuid NOT NULL REFERENCES platform.tenants(id), alert_id uuid NOT NULL,
  deduplication_key text NOT NULL, status text NOT NULL, disposition text NOT NULL,
  severity integer NOT NULL CHECK(severity BETWEEN 0 AND 100), priority integer NOT NULL CHECK(priority BETWEEN 1 AND 5),
  assignee text, team text, first_seen timestamptz NOT NULL, last_seen timestamptz NOT NULL,
  alert_version integer NOT NULL CHECK(alert_version > 0), alert_data jsonb NOT NULL,
  created_at timestamptz NOT NULL, updated_at timestamptz NOT NULL,
  PRIMARY KEY(tenant_id,alert_id));
CREATE INDEX IF NOT EXISTS alerts_queue_idx ON platform.alerts(tenant_id,status,priority DESC,last_seen DESC,alert_id);
CREATE INDEX IF NOT EXISTS alerts_dedup_idx ON platform.alerts(tenant_id,deduplication_key,last_seen DESC);
CREATE INDEX IF NOT EXISTS alerts_assignment_idx ON platform.alerts(tenant_id,assignee,team,status,last_seen DESC);

CREATE TABLE IF NOT EXISTS platform.triage_incidents(
  tenant_id uuid NOT NULL REFERENCES platform.tenants(id), incident_id uuid NOT NULL,
  status text NOT NULL, disposition text NOT NULL, severity integer NOT NULL CHECK(severity BETWEEN 0 AND 100),
  priority integer NOT NULL CHECK(priority BETWEEN 1 AND 5), owner text NOT NULL, assignee text, team text,
  incident_version integer NOT NULL CHECK(incident_version > 0), alert_ids uuid[] NOT NULL,
  incident_data jsonb NOT NULL, created_at timestamptz NOT NULL, updated_at timestamptz NOT NULL, closed_at timestamptz,
  PRIMARY KEY(tenant_id,incident_id));
CREATE INDEX IF NOT EXISTS triage_incidents_queue_idx ON platform.triage_incidents(tenant_id,status,priority DESC,updated_at DESC,incident_id);

CREATE TABLE IF NOT EXISTS platform.lifecycle_audit(
  tenant_id uuid NOT NULL REFERENCES platform.tenants(id), audit_id uuid NOT NULL,
  object_type text NOT NULL CHECK(object_type IN('alert','incident','export','policy')),
  object_id uuid NOT NULL, object_version integer NOT NULL, action text NOT NULL, actor text NOT NULL,
  occurred_at timestamptz NOT NULL, before_data jsonb NOT NULL, after_data jsonb NOT NULL,
  reason text NOT NULL, provenance text NOT NULL, PRIMARY KEY(tenant_id,audit_id));
CREATE UNIQUE INDEX IF NOT EXISTS lifecycle_audit_object_version_idx ON platform.lifecycle_audit(tenant_id,object_type,object_id,object_version,action);
CREATE INDEX IF NOT EXISTS lifecycle_audit_timeline_idx ON platform.lifecycle_audit(tenant_id,object_type,object_id,occurred_at,audit_id);

CREATE OR REPLACE FUNCTION platform.reject_lifecycle_audit_mutation() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN RAISE EXCEPTION 'lifecycle audit is immutable'; END $$;
DROP TRIGGER IF EXISTS lifecycle_audit_immutable ON platform.lifecycle_audit;
CREATE TRIGGER lifecycle_audit_immutable BEFORE UPDATE OR DELETE ON platform.lifecycle_audit FOR EACH ROW EXECUTE FUNCTION platform.reject_lifecycle_audit_mutation();

CREATE TABLE IF NOT EXISTS platform.analyst_notes(
  tenant_id uuid NOT NULL REFERENCES platform.tenants(id), note_id uuid NOT NULL,
  object_type text NOT NULL CHECK(object_type IN('alert','incident')), object_id uuid NOT NULL,
  note_kind text NOT NULL, author text NOT NULL, note_version integer NOT NULL CHECK(note_version > 0),
  content text NOT NULL CHECK(octet_length(content) BETWEEN 1 AND 16384), note_data jsonb NOT NULL,
  created_at timestamptz NOT NULL, audit_id uuid NOT NULL, PRIMARY KEY(tenant_id,note_id),
  FOREIGN KEY(tenant_id,audit_id) REFERENCES platform.lifecycle_audit(tenant_id,audit_id));
CREATE INDEX IF NOT EXISTS analyst_notes_object_idx ON platform.analyst_notes(tenant_id,object_type,object_id,created_at,note_id);

CREATE TABLE IF NOT EXISTS platform.saved_triage_filters(
  tenant_id uuid NOT NULL REFERENCES platform.tenants(id), filter_id uuid NOT NULL,
  owner text NOT NULL, name text NOT NULL, filter_version integer NOT NULL CHECK(filter_version > 0),
  filter_data jsonb NOT NULL, created_at timestamptz NOT NULL, PRIMARY KEY(tenant_id,filter_id));
CREATE INDEX IF NOT EXISTS saved_triage_filters_owner_idx ON platform.saved_triage_filters(tenant_id,owner,name);

CREATE TABLE IF NOT EXISTS platform.triage_policies(
  tenant_id uuid NOT NULL REFERENCES platform.tenants(id), policy_id uuid NOT NULL,
  policy_type text NOT NULL CHECK(policy_type IN('grouping','sla-target')), policy_version integer NOT NULL,
  enabled boolean NOT NULL, policy_data jsonb NOT NULL, created_at timestamptz NOT NULL, created_by text NOT NULL,
  PRIMARY KEY(tenant_id,policy_id,policy_version));

COMMIT;
