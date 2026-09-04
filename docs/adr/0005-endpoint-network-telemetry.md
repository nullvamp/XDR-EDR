# ADR 0005: trustworthy endpoint network telemetry

Status: accepted; Windows engineering qualified under Outcome B-Windows (2026-08-07)

## Decision

Collect endpoint socket-operation metadata from Windows kernel TCP/IP ETW and Linux Falco syscall JSON. Normalize it as `network-event.v1`, retaining native provider, event/operation, status, timestamps, native address bytes, address family, ports, protocol, process relationship, user context, collector version, evidence hash, and explicit quality/limitation fields. PostgreSQL is authoritative; OpenSearch is a rebuildable versioned projection.

The platform does not capture packets, payloads, DNS telemetry, URLs, TLS/HTTP content, byte counts, or inferred hostnames. A TCP `sendto`/`recvfrom` is an operation observation, never a datagram. Missing relationships remain unattributed. Windows connect callbacks are attempts unless the source establishes a stronger fact. Linux connection identity includes PID generation and file descriptor so reuse does not merge unrelated sockets.

Collection reuses endpoint-bound mTLS, bounded gzip batches, the crash-safe queue, transactional outbox, explicit-ACK JetStream projection, tenant-safe APIs, and policy-preserving MinIO exports. Failures in process/file/registry partitions are isolated so they cannot starve network collection.

## Consequences

Windows ETW is qualified from an elevated High-integrity process on Windows build 26200. Runtime evidence proved that native `connid` values can be reused across unrelated sockets, so the raw value remains evidence but is not trusted as the Windows connection-entity key; event identity prevents false merges and incomplete lifecycle remains explicit. Failed-connect results, canonical listener lifecycle, and IPv6 attempt/establishment callbacks are NOT OBSERVABLE BY SOURCE on this build. Falco under Docker Desktop/WSL2 is useful engineering evidence but is not a supported Linux-host qualification. There is no silent synthetic fallback.

No detection, alert, incident, response, blocking, isolation, DNS, packet, payload, TLS, or HTTP feature is introduced.
