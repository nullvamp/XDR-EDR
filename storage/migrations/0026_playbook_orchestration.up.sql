CREATE TABLE IF NOT EXISTS platform.playbook_definitions (
    tenant_id uuid NOT NULL, playbook_id uuid NOT NULL, playbook_version integer NOT NULL,
    state text NOT NULL, version_hash text NOT NULL, definition_data jsonb NOT NULL,
    created_at timestamptz NOT NULL, updated_at timestamptz NOT NULL,
    PRIMARY KEY (tenant_id, playbook_id, playbook_version));
CREATE INDEX IF NOT EXISTS ix_playbook_definitions_state ON platform.playbook_definitions(tenant_id,state,updated_at);
CREATE TABLE IF NOT EXISTS platform.playbook_fixture_results (
    tenant_id uuid NOT NULL, playbook_id uuid NOT NULL, playbook_version integer NOT NULL,
    fixture_name text NOT NULL, fixture_data jsonb NOT NULL,
    PRIMARY KEY(tenant_id,playbook_id,playbook_version,fixture_name));
CREATE TABLE IF NOT EXISTS platform.playbook_executions (
    tenant_id uuid NOT NULL, execution_id uuid NOT NULL, playbook_id uuid NOT NULL,
    playbook_version integer NOT NULL, state text NOT NULL, idempotency_key text NOT NULL,
    endpoint_id uuid NOT NULL, source_type text NOT NULL, source_object_id text NOT NULL,
    started_at timestamptz NOT NULL, execution_data jsonb NOT NULL, updated_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY(tenant_id,execution_id), UNIQUE(tenant_id,playbook_id,playbook_version,idempotency_key));
CREATE INDEX IF NOT EXISTS ix_playbook_executions_source ON platform.playbook_executions(tenant_id,source_type,source_object_id,started_at);
CREATE INDEX IF NOT EXISTS ix_playbook_executions_state ON platform.playbook_executions(tenant_id,state,updated_at);
CREATE TABLE IF NOT EXISTS platform.playbook_work (
    tenant_id uuid NOT NULL, execution_id uuid NOT NULL, state text NOT NULL, attempts integer NOT NULL DEFAULT 0,
    available_at timestamptz NOT NULL DEFAULT now(), last_error text, updated_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY(tenant_id,execution_id));
CREATE INDEX IF NOT EXISTS ix_playbook_work_pending ON platform.playbook_work(state,available_at) WHERE state='pending';
CREATE TABLE IF NOT EXISTS platform.playbook_audit (
    tenant_id uuid NOT NULL, audit_id uuid NOT NULL, playbook_id uuid NOT NULL, playbook_version integer NOT NULL,
    action text NOT NULL, actor text NOT NULL, object_hash text NOT NULL, reason text NOT NULL,
    occurred_at timestamptz NOT NULL DEFAULT now(), PRIMARY KEY(tenant_id,audit_id));
CREATE TABLE IF NOT EXISTS platform.playbook_execution_audit (
    tenant_id uuid NOT NULL, audit_id uuid NOT NULL, execution_id uuid NOT NULL, step_id text,
    action text NOT NULL, actor text NOT NULL, occurred_at timestamptz NOT NULL,
    object_hash text NOT NULL, reason text NOT NULL, provenance text NOT NULL,
    PRIMARY KEY(tenant_id,audit_id));
