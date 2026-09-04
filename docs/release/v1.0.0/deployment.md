# Deployment guide

Production requires independently managed PostgreSQL, NATS JetStream, S3-compatible object storage, OpenSearch, TLS termination, secrets management, monitoring, backups, and at least the tested gateway runtime image. The gateway container runs as non-root, contains the published runtime/frontend only, declares a health check, and listens internally on 8080 plus endpoint mTLS on 8443.

Required configuration classes are: generated secrets (JWT signing key, enrollment pepper, database/object-store credentials); deployment-required endpoints and certificate paths; secret CA/server private-key passwords; tenant-configurable policies; and safe product defaults. Missing production certificates or required secrets fail startup. External AI is disabled unless a tenant policy explicitly selects an allowed provider/model and transmission mode.

The Compose file is for local qualification. Its single PostgreSQL/NATS/MinIO/OpenSearch instances, local port publishing, self-managed certificates, and disabled OpenSearch security must not be promoted unchanged. Production operators must supply network segmentation, TLS at every trust boundary, authenticated infrastructure services, external secret injection, durable volumes, backup schedules, monitoring, and change control.

Listeners: gateway 8080/TCP internal HTTP (reverse-proxy only), 8443/TCP endpoint HTTPS/mTLS; PostgreSQL 5432, NATS 4222/8222, MinIO 9000/9001, and OpenSearch 9200 are internal administrative/data-plane ports and must not be Internet-exposed.
