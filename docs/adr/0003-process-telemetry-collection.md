# ADR 0003: Process telemetry collection and evidence pipeline

Status: Accepted for Sprint 2

## Decision

Use a versioned `IProcessCollector` boundary. The Linux evaluation runtime uses a bounded `/proc` snapshot adapter because the existing agent contains no Falco event contract; Falco remains the locked long-term Linux runtime adapter and can replace this implementation without changing the canonical envelope. Windows and macOS advertise build-only capabilities until their approved native runtimes are integrated; the server must not assign process policy to those capabilities.

Process identity is SHA-256 over endpoint identity, PID, native start time, and platform start key. The agent persists sequence and an atomic file queue, uploads gzip batches over the existing mTLS channel, and deletes only acknowledged event files. PostgreSQL is authoritative. Process outbox records are created in the same transaction, NATS carries versioned projection messages, and OpenSearch is a rebuildable tenant-scoped projection.

Hashing and signature verification default off. Missing values remain null with explicit lineage, hash, signature, and data-quality outcomes. Command-line secrets matching the approved key patterns are redacted before queuing.

## Consequences

PID reuse and retries cannot merge executions. Offline events survive restart. Search can be rebuilt from PostgreSQL. Polling can miss Linux processes shorter than the sampling interval, which is reported as a collector limitation rather than represented as complete evidence. Native Windows ETW, macOS Endpoint Security, and Falco integration remain separate platform-runtime work, not silent fallbacks.
