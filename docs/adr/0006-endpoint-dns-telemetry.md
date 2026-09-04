# ADR 0006: trustworthy endpoint DNS telemetry

Status: Accepted (Sprint 6, Outcome B-Windows)

## Decision

Use the documented Windows DNS Client ETW provider `Microsoft-Windows-DNS-Client` (`1c95126e-7eea-49a9-a3fe-a378b03ddb4d`) in the platform-owned `OpenSecurityPlatform-DnsClient-v1` session. Normalize native events to `dns-event.v1`, durably queue them, and reuse the established gzip/mTLS/PostgreSQL/outbox/NATS/OpenSearch pipeline.

Transaction entities are created only from a reliable native transaction identity combined with endpoint, installation, process-start identity, question, type, and resolver evidence. When ActivityId is absent, query and response events remain separate. DNS-to-network links are bounded, supporting context and always explicitly ambiguous; they never assert hostname causality.

The current Linux Falco syscall source is `NOT OBSERVABLE BY SOURCE` for trustworthy DNS semantics without prohibited payload inspection. WSL2 is not a native Linux qualification environment.

## Privacy and trust boundaries

- No packet or DNS payload storage, reverse-DNS supplementation, reputation, detection, blocking, alerting, or response.
- Unknown source fields remain null and are presented as unknown, unavailable, or `NOT OBSERVABLE BY SOURCE`.
- Answer records are bounded to 256; names, addresses, timestamps, batches and compressed/uncompressed sizes are validated.
- Process attribution is bound to PID plus process start time when obtainable; PID-only evidence is labeled accordingly.
- Exports are tenant-bound, bounded, hashed, short-lived, and CSV-formula-safe.

## Consequences

Windows queries, responses, failures and answers are investigable with exact provenance. On Windows build 26200, ActivityId, response latency, flags, TTL, authority/additional counts, resolver on every event, and trustworthy CNAME chains are not consistently observable and are not manufactured.
