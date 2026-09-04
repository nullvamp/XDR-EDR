# ADR 0039: Case-centric DFIR investigation workspace

Status: Accepted (Sprint 34)

## Decision

PostgreSQL is the tenant-scoped authority for investigations, collection links, immutable evidence metadata, parser runs, bookmarks, append-only notes, timeline items, custody events, and export records. MinIO stores source, derived, manifest, and package bytes. Existing forensic collection/transfer services remain the only endpoint acquisition path.

Evidence bytes have no update API. Analyst actions create metadata or new derived objects. State writes use revision compare-and-swap; collection imports are collection-idempotent and intentional recollection uses a new collection linked by `recollectionOf`.

The API and analyst workspace expose truthful profile support, partial/unavailable evidence, source-to-object provenance, re-verification, bounded search, timeline/entity pivots, holds, and resumable exports. Tool staging never authorizes execution; registered exact-hash acquisition actions remain mandatory.

## Consequences

- Tenant identity participates in every authority and object lookup; the PostgreSQL state table uses RLS.
- A technical custody history is provided, but no legal-admissibility claim is made.
- Full-disk metadata and memory remain `ToolRequired`; unsupported source types are never represented as acquired.
- Large range requests are capped at 8 MiB per call and bind to the final SHA-256.

