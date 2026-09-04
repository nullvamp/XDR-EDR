# ADR 0012: Windows service and scheduled-task telemetry

Status: Accepted and Windows-qualified.

## Decision

Windows service telemetry preserves separate source semantics. Service Control Manager System-channel events provide installation and start-type evidence; native `QueryServiceStatusEx` snapshots provide running state and PID; bounded Services-registry snapshots provide complete configuration and lifecycle boundaries. Registry snapshots are configuration observations, not actor events. Task telemetry uses the `Microsoft-Windows-TaskScheduler/Operational` channel and optionally queries Task Scheduler COM for bounded metadata. Complete arbitrary task XML is never persisted: the parser prohibits DTD/entity resolution, enforces byte/character bounds, extracts approved fields, redacts secret-like arguments, and retains a SHA-256 evidence reference.

The canonical `persistence-event.v1` envelope carries tenant/endpoint/agent identity, native provider/channel/event identity, lifecycle-aware service or task entity identity, provenance, source operation/status, sequence, timestamps, evidence hash, and quality state. Delete/recreate boundaries advance a locally durable generation even when a canonical name/path is reused. Process relationships require a native PID plus the observed process-start identity; executable-path equality is never used as attribution.

The established durable path is reused: bounded file queue, gzip over mTLS, PostgreSQL transaction, outbox, NATS JetStream, idempotent OpenSearch projection, tenant-scoped API/UI, and asynchronous integrity-manifest export. Policies and audited exclusions are immutable/versioned and reject match-all, malformed, control-character, over-broad wildcard, and unconfirmed disable-all configurations.

## Consequences

- This Windows build does not expose a dependable SCM 7036 stream for the controlled fixture, so state is explicitly labeled `windows.scm-status-snapshot` rather than synthesized as an SCM event.
- Task enable produces an update on this provider build; `scheduled_task.enabled` remains **NOT OBSERVABLE BY SOURCE** unless a distinct native event is supplied. Disable is natively observed as event 142.
- Rapid deletion can make the optional COM metadata lookup race with the Event Log notification. That lookup now fails closed to unavailable metadata without terminating collection.
- A stopped service has no trustworthy running PID; process attribution remains unavailable instead of retaining a stale relationship.
- Driver-service metadata is configuration evidence only. Sprint 8 does not install or load a kernel driver.
- Linux-equivalent qualification is unavailable locally; macOS and hosted CI remain external qualification work.

