CREATE TABLE IF NOT EXISTS platform.ai_policies (
 tenant_id uuid NOT NULL, policy_id uuid NOT NULL, version integer NOT NULL CHECK(version>0),
 policy_hash text NOT NULL, created_at timestamptz NOT NULL, document jsonb NOT NULL,
 PRIMARY KEY(tenant_id,policy_id,version));
CREATE TABLE IF NOT EXISTS platform.ai_conversations (
 tenant_id uuid NOT NULL, conversation_id uuid NOT NULL, context_type text NOT NULL, context_id text NOT NULL,
 created_at timestamptz NOT NULL, updated_at timestamptz NOT NULL, document jsonb NOT NULL,
 PRIMARY KEY(tenant_id,conversation_id));
CREATE INDEX IF NOT EXISTS ix_ai_conversations_context ON platform.ai_conversations(tenant_id,context_type,context_id,updated_at DESC);
CREATE TABLE IF NOT EXISTS platform.ai_evidence_packages (
 tenant_id uuid NOT NULL, package_id uuid NOT NULL, context_type text NOT NULL, context_id text NOT NULL,
 package_hash text NOT NULL, created_at timestamptz NOT NULL, item_count integer NOT NULL CHECK(item_count BETWEEN 0 AND 200),
 evidence_bytes bigint NOT NULL CHECK(evidence_bytes BETWEEN 0 AND 1048576), document jsonb NOT NULL,
 PRIMARY KEY(tenant_id,package_id));
CREATE TABLE IF NOT EXISTS platform.ai_messages (
 tenant_id uuid NOT NULL, message_id uuid NOT NULL, conversation_id uuid NOT NULL, client_request_id text NOT NULL,
 role text NOT NULL, created_at timestamptz NOT NULL, document jsonb NOT NULL,
 PRIMARY KEY(tenant_id,message_id), UNIQUE(tenant_id,conversation_id,client_request_id),
 FOREIGN KEY(tenant_id,conversation_id) REFERENCES platform.ai_conversations(tenant_id,conversation_id));
CREATE INDEX IF NOT EXISTS ix_ai_messages_conversation ON platform.ai_messages(tenant_id,conversation_id,created_at,message_id);
CREATE TABLE IF NOT EXISTS platform.ai_note_drafts (
 tenant_id uuid NOT NULL, draft_id uuid NOT NULL, conversation_id uuid NOT NULL, context_type text NOT NULL,
 context_id text NOT NULL, accepted boolean NOT NULL, created_at timestamptz NOT NULL, document jsonb NOT NULL,
 PRIMARY KEY(tenant_id,draft_id));
CREATE TABLE IF NOT EXISTS platform.ai_audit (
 tenant_id uuid NOT NULL, audit_id uuid NOT NULL, actor text NOT NULL, action text NOT NULL,
 object_type text NOT NULL, object_id uuid NOT NULL, occurred_at timestamptz NOT NULL, document jsonb NOT NULL,
 PRIMARY KEY(tenant_id,audit_id));
CREATE INDEX IF NOT EXISTS ix_ai_audit_time ON platform.ai_audit(tenant_id,occurred_at DESC);

ALTER TABLE platform.ai_policies ENABLE ROW LEVEL SECURITY;
ALTER TABLE platform.ai_conversations ENABLE ROW LEVEL SECURITY;
ALTER TABLE platform.ai_evidence_packages ENABLE ROW LEVEL SECURITY;
ALTER TABLE platform.ai_messages ENABLE ROW LEVEL SECURITY;
ALTER TABLE platform.ai_note_drafts ENABLE ROW LEVEL SECURITY;
ALTER TABLE platform.ai_audit ENABLE ROW LEVEL SECURITY;
DO $$ DECLARE t text; BEGIN FOREACH t IN ARRAY ARRAY['ai_policies','ai_conversations','ai_evidence_packages','ai_messages','ai_note_drafts','ai_audit'] LOOP
 EXECUTE format('DROP POLICY IF EXISTS tenant_isolation ON platform.%I',t);
 EXECUTE format('CREATE POLICY tenant_isolation ON platform.%I USING (tenant_id = nullif(current_setting(''app.tenant_id'',true),'''')::uuid) WITH CHECK (tenant_id = nullif(current_setting(''app.tenant_id'',true),'''')::uuid)',t);
END LOOP; END $$;
