# ADR 0019: Evidence-preserving alert and incident lifecycle

Status: Accepted (Sprint 15)

## Context

Detection and correlation findings are authoritative evidence, but analysts need durable workflow objects for deduplication, ownership, triage, grouping, notes, and closure. Those workflow objects must not become a competing evidence store or allow simulation/replay output to enter production silently.

## Decision

- Use versioned `alert.v1` and `incident.v1` domain records. Alerts reference source findings and exact evidence; incidents aggregate alert references and recompute their evidence/entity summaries from tenant-scoped alerts.
- Admit only live production findings automatically. Simulation, replay, dry-run, or excluded output fails closed unless a future explicitly authorized promotion workflow is added.
- Deduplicate alerts deterministically for 15 minutes by rule/version, endpoint, stable process/entity, and correlation key. Preserve every source ID and evidence reference and increment repeat count.
- Keep rule severity distinct from deterministic explainable priority (`triage-priority.v1`).
- Enforce explicit alert and incident state machines. Closure requires a disposition; every mutation appends a tenant-scoped immutable audit event.
- Store PostgreSQL snapshots for current queues and append-only audit/note rows. A database trigger rejects audit update/delete.
- Permit automatic incident grouping only through bounded `strong-evidence.v1` relationships within one hour. Same severity or display name is insufficient.
- Bound queues, cursors, bulk actions (100), incident membership (500), comments (4,096 characters), exports (1,000), and signed exact-object download URLs.
- Treat comments as immutable plain text and reject HTML, script, and link-style injection.
- Expose granular permissions for alert/incident read and mutation operations. Tenant scope is resolved from the authenticated principal, never request data.
- Provide no automated response, containment, remediation, AI/ML scoring, or external ticketing in Sprint 15.

## Consequences

Analysts receive durable, explainable workflow without weakening evidence authority. Current grouping is intentionally limited to one built-in strong-evidence policy. SLA timing is exposed, but organization-specific targets and breach claims remain unconfigured. Native Linux, macOS, and hosted-CI qualification remain separate release gates.
