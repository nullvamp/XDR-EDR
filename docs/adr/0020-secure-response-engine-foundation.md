# ADR 0020: Secure response engine foundation

Status: Accepted (Sprint 16)

## Decision

The platform owns a typed, tenant-bound response control plane. Analysts request only compiled, versioned action definitions. The server resolves authoritative endpoint and agent-installation identity, applies granular authorization and optional exact-hash second approval, then signs an envelope with the established CA. The agent accepts only matching, unexpired, supported and correctly signed envelopes.

Endpoint response execution is isolated from telemetry in a bounded 32-item channel with two consumers. Durable local action-ID/nonce/parameter-hash state makes at-least-once delivery exactly-once logically for the Sprint 16 query-only actions. The server owns the durable lifecycle and immutable audit. An authenticated installation-bound cancellation channel supports both active cancellation and reconnect acknowledgment. Results and diagnostic artifacts are typed, hashed, bounded and tenant/action scoped.

PostgreSQL is authoritative. MinIO stores only the predefined diagnostic artifact with exact-object manifests and signed access. NATS remains a projection transport and is not an execution authority.

## Safety boundary

Sprint 16 contains exactly six safe actions: endpoint status, bounded process inventory, bounded current network connections, one named service status, one authorized file's metadata, and one platform-health diagnostic. No arbitrary command, shell, script, file collection, containment, process control, quarantine, remediation, automated response, SOAR or AI-generated execution is permitted.

## Consequences

- New action types require a versioned definition, typed validator/executor, bounds, authorization, fixtures and release qualification.
- Material parameter changes create a new request and invalidate prior approval by construction.
- Cancellation is best-effort relative to completion: an already completed operation remains completed and is never relabeled as cancelled.
- Native Linux, macOS and hosted-CI qualification remain separate release gates.
