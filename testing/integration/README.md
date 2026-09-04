# Integration Tests

Compose-based integration tests verify PostgreSQL migrations/rollback, NATS reconnect and redelivery, MinIO hash metadata, OpenSearch index health, service registration and graceful dependency degradation. They run when Docker is available; core contract tests remain dependency-free.
