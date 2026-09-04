BEGIN;
CREATE TABLE IF NOT EXISTS platform.persistence_configuration_entities(
 tenant_id uuid NOT NULL,endpoint_id uuid NOT NULL,persistence_entity_id text NOT NULL,
 category text NOT NULL,subtype text NOT NULL,native_identity text NOT NULL,object_name text NOT NULL,
 first_observed timestamptz NOT NULL,last_observed timestamptz NOT NULL,created_at timestamptz,
 deleted_at timestamptz,generation bigint NOT NULL,current_state text NOT NULL,latest_event jsonb NOT NULL,
 PRIMARY KEY(tenant_id,endpoint_id,persistence_entity_id));
CREATE INDEX IF NOT EXISTS ix_persistence_configuration_entities_search
 ON platform.persistence_configuration_entities(tenant_id,category,subtype,last_observed DESC);
CREATE TABLE IF NOT EXISTS platform.persistence_configuration_history(
 tenant_id uuid NOT NULL,endpoint_id uuid NOT NULL,persistence_entity_id text NOT NULL,event_id uuid NOT NULL,
 observed_at timestamptz NOT NULL,configuration jsonb NOT NULL,PRIMARY KEY(tenant_id,event_id));
CREATE INDEX IF NOT EXISTS ix_persistence_configuration_history_entity
 ON platform.persistence_configuration_history(tenant_id,endpoint_id,persistence_entity_id,observed_at);
CREATE TABLE IF NOT EXISTS platform.persistence_wmi_relationships(
 tenant_id uuid NOT NULL,endpoint_id uuid NOT NULL,persistence_entity_id text NOT NULL,event_id uuid NOT NULL,
 filter_identity text,consumer_identity text,state text NOT NULL,observed_at timestamptz NOT NULL,
 PRIMARY KEY(tenant_id,event_id));
COMMIT;
