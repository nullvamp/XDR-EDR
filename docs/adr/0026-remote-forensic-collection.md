# ADR 0026: bounded remote forensic collection

Status: Accepted for Sprint 22 Windows engineering.

## Decision

Remote collection is a predefined `forensic.collect` response action, never an arbitrary command. Immutable versioned profiles authorize explicit artifact categories and hard limits. Every request is bound to tenant, endpoint, agent installation, analyst, profile hash, policy, nonce, expiry and exact parameter hash; sensitive scopes require separated approval.

The Windows collector uses structured native inventories, read-only Registry access with value data redacted, approved-channel EVTX export, and stable-handle file acquisition with pre/post native identity and authoritative telemetry hash comparison. Directory acquisition is manifest based and bounded by literal root, extensions, depth, count and bytes; reparse/hard-link, traversal, root, wildcard, UNC, device and ADS scopes fail closed.

Each durable acquisition step produces an explicit evidence-item state. Completed bytes are uploaded to tenant/endpoint/collection-bound object storage, SHA-256 verified, and referenced by an immutable collection manifest. Cancellation stops future work and preserves completed evidence. Partial, unstable, truncated and failed items are never upgraded to success. Custody history is an auditable technical record and makes no legal-admissibility claim.

## Consequences

- No physical memory, raw disk, credential extraction, arbitrary scripts, arbitrary recursion or automatic detection-triggered collection.
- Hard ceilings are 32 requested artifacts, 64 evidence items, 32 files, depth 4, 10,000 event records, 1,024 Registry entries, 8 MiB per artifact, 16 MiB per collection, 300 seconds, 2 jobs per endpoint, 16 per tenant and 7-day retention.
- PostgreSQL response records remain authoritative; MinIO stores exact objects; signed URLs authorize one exact retained artifact.
- Linux qualification remains an environment blocker; macOS and hosted CI remain external blockers.
