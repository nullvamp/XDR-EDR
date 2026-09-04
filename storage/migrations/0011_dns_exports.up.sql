BEGIN;
CREATE TABLE IF NOT EXISTS platform.dns_export_jobs(
 tenant_id uuid NOT NULL REFERENCES platform.tenants(id), id uuid NOT NULL, created_by text NOT NULL,
 state text NOT NULL CHECK(state IN('pending','running','completed','failed','expired','cancelled')),
 format text NOT NULL CHECK(format IN('jsonl','csv')), query jsonb NOT NULL, fields text[] NOT NULL DEFAULT '{}',
 maximum_records integer NOT NULL CHECK(maximum_records BETWEEN 1 AND 10000), output_object_id uuid NOT NULL,
 manifest_object_id uuid NOT NULL, metadata_object_id uuid NOT NULL, record_count integer, output_size bigint,
 output_sha256 text, error_code text, error_summary text, created_at timestamptz NOT NULL DEFAULT now(),
 updated_at timestamptz NOT NULL DEFAULT now(), started_at timestamptz, completed_at timestamptz,
 expires_at timestamptz NOT NULL, PRIMARY KEY(tenant_id,id), UNIQUE(id), UNIQUE(output_object_id),
 UNIQUE(manifest_object_id), UNIQUE(metadata_object_id));
CREATE INDEX IF NOT EXISTS dns_export_pending ON platform.dns_export_jobs(created_at) WHERE state='pending';
COMMIT;
