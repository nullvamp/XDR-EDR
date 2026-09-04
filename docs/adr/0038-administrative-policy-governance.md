# ADR 0038: Administrative policy governance

Status: Accepted (Sprint 33)

## Decision

All administrable product settings use a typed allowlisted registry. Definitions record type, scope, default, bounds/allowed values, security class, restart behavior, owner subsystem, approval risk, safety-floor behavior, and description. Versions are immutable and carry author, reason, hash, diff, approval, activation, and deactivation evidence.

Resolution order is platform default -> tenant -> endpoint group -> endpoint. Non-overridable safety constraints reject weaker lower-scope values. High-risk versions require a different approver. Preview produces affected count, before/after values, impact, rollout, approval requirement, and confirmation hash; creation rejects stale or forged hashes.

PostgreSQL is authoritative with optimistic revision control and tenant RLS. Endpoint acknowledgements produce `InSync`, `Pending`, `Stale`, `Drifted`, or `Unknown`. Rollout is bounded, maintenance windows are explicit, and urgent manually approved response remains exempt.

Full PostgreSQL backup includes principal metadata, roles/assignments, credential metadata and hashes, configuration state, acknowledgements, and immutable audit. Backup reports expose no secret.

