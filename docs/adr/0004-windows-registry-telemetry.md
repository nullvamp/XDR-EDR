# ADR 0004: Windows registry telemetry semantics

Status: accepted for Sprint 4 Outcome B (2026-08-06)

## Decision

Use `Microsoft-Windows-Kernel-Registry` ETW through the existing owned-session pattern. Preserve the native callback and confidence; do not manufacture distinctions the provider does not expose. In particular, SetValue is normalized as a value set with the native operation retained, and key rename destination and security-descriptor change remain `NOT OBSERVABLE BY SOURCE` for this adapter.

Registry events reuse the established durable queue, gzip/mTLS batch, PostgreSQL transaction/outbox, JetStream consumer, OpenSearch versioned-index/alias, and MinIO export architecture. PostgreSQL is authoritative. Event identity is immutable; key and value entity generations change after delete/recreate. Server `receivedAt` and `ingestedAt` are assigned on receipt and never trusted from agent input.

Collection is metadata-only by default. Hash and bounded preview require an explicit path/type policy. Protected paths and secret-like names can record activity metadata but cannot capture content. Preview reads require `registry:sensitive:read` (or an administrative superset); asynchronous exports never introduce unredacted preview data.

Projection rebuild is a global operation and therefore requires `system:admin`; tenant administrators cannot invoke it. This is the smallest compatible correction to the pre-existing tenant-scoped authorization pattern because the shared alias contains all tenants.

## Consequences

The Windows adapter is trustworthy for key create/delete and value set/delete callbacks with explicit resolution and attribution quality. It does not claim source support for rename destinations, key security changes, reliable value create-versus-modify distinction, or complete value bytes/type in the callback. A future adapter may add those capabilities only under a separately versioned source contract.

No driver, detection, response, blocking, rollback, or remediation capability is introduced.
