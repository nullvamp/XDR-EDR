# ADR 0011: Native module and image-load telemetry

Status: Accepted for implementation; runtime qualification pending Administrator token.

## Decision

Windows module evidence uses the documented kernel image-load ETW stream in a deterministic platform-owned session. The callback only copies bounded native fields into a bounded queue. Process/file attribution, SHA-256, and embedded-certificate metadata execute after the callback under policy rate and size limits. Linux reports `linux.unsupported` until a supported native host/source is qualified; macOS remains external.

Canonical `module-event.v1` records distinguish the mapped-image identity from the backing-file identity and preserve process start identity, load base, native sequence, original/normalized path, provenance, quality flags, and incomplete lifecycle. An embedded certificate proves only certificate presence; it is never labeled trusted. Loads remain `IncompleteLifecycle` when unload collection is disabled or unavailable.

The established pipeline is reused: durable agent queue, bounded gzip over mTLS, PostgreSQL transaction and outbox, NATS, strict OpenSearch mapping, tenant-scoped APIs/UI, and integrity-manifest exports. No driver, detection, response, reputation, or memory scanning is introduced.

## Consequences

- Kernel ETW requires an elevated Windows process and fails explicitly without it.
- Device paths without a resolvable volume mapping retain native evidence and an identity-unavailable quality flag.
- Hash and signer work can be rate-limited or fail independently without blocking collection.
- Native Linux and macOS qualification cannot be inferred from Windows or WSL2.
