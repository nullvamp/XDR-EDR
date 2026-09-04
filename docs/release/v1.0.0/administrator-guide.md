# Administrator guide

Administrators manage tenants, users/service accounts, least-privilege role assignments, API credentials, enrollment, fleet groups/rings, policies, update packages, retention, backup, and immutable audit review. Separate requester/approver roles for high-risk configuration, destructive response, production rule activation, and credential operations.

Daily checks: `/health/ready`, dependency transitions, endpoint heartbeat/policy drift, queue age/depth, outbox failures, NATS consumer pending/ACK-pending, OpenSearch projection lag, object-store inventory, certificate expiry, backup result, and administrative audit. Never delete audit or evidence under an active incident/legal hold.

Use one-use enrollment tokens where practical. Rotate infrastructure/API secrets using the documented secret manager; do not store them in Compose files, source, tickets, or installer logs. Use update canaries and pause on health/reconciliation drift. Default roles do not implicitly grant destructive response, sensitive forensics, policy administration, production rule activation, credential administration, or audit export.
