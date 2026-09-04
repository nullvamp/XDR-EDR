# ADR 0013: Persistence configuration telemetry

Status: Accepted (Sprint 9, 2026-08-07)

## Decision

Model persistence configuration as `PersistenceConfiguration` observations in the existing `persistence-event.v1` envelope. Windows WMI `root\subscription` snapshots are the native authority for `__EventFilter`, supported consumers, and `__FilterToConsumerBinding`. Existing Registry and File events remain the authoritative raw evidence for COM, autorun, startup configuration, and Startup-folder items; Sprint 9 stores only the derived configuration, mapping provenance, confidence, and raw event references.

Filter, consumer, and binding identities are separate. Identity includes endpoint, category, native identity, scope, registry view, and generation. Delete/recreate advances generation and never collapses history. A binding is not presented as a complete chain unless its referenced filter and consumer are observed.

Commands, arguments, WQL, and metadata are bounded and policy-controlled. Secret-like command arguments are redacted before persistence. The model never infers maliciousness, intent, creator process/user, execution, or successful exploitation.

Late Registry/File arrivals are reconciled asynchronously from PostgreSQL and republished through the transactional outbox so PostgreSQL and OpenSearch converge idempotently.

## Consequences

- Analysts can search configuration, inspect history and WMI relationships, and follow raw evidence without duplicating raw collection.
- Windows per-user `SID_Classes` registry paths are canonicalized to `SID\Software\Classes`.
- File ETW drains are bounded at 5,000 records per cycle and avoid per-event identity I/O for non-create events, preventing source starvation under system-wide load.
- Linux-equivalent qualification remains an environment blocker; macOS and hosted CI remain external blockers.
