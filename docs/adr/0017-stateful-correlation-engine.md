# ADR 0017: Stateful correlation engine

Status: Accepted for Sprint 13 Outcome B-Windows on 2026-08-08.

## Decision

PostgreSQL is authoritative for immutable correlation packs/rules/tests, assignments, exclusions, accepted observations, expiring state, replay snapshots/runs, findings/history, health and export metadata. Evaluation uses event time, stable allowlisted entity keys, bounded windows, deterministic evidence-derived IDs and a non-executable declarative condition tree. Accepted canonical events and Sprint 12 findings enter the engine; completed finding changes use the transactional outbox, NATS and a strict OpenSearch projection.

Critical state is never process-memory-only. `correlation_observations` is the authoritative bounded replay ledger; `correlation_state_observations` is restart-safe expiring working state. Process memory adapters exist only for development/test mode. Duplicate keys include tenant, rule/version, mode, run and observation. Replays pin rule and pack versions, sort by event time plus observation ID, and default to non-production simulation.

The engine supports ordered sequences, unordered sets, threshold chains, distinct entities, native parent-child linkage, cross-domain, finding-to-finding, event-to-finding, negative-window completion and confidence accumulation. Late/incomplete evidence remains visible and reduces confidence. Findings preserve exact events, child findings, timeline, matched/unmatched steps, relationships, MITRE attribution, rule/pack versions, execution mode, missing telemetry, suppression/exclusion state and an explicit explanation.

## Security and bounds

Rules are limited to 96 KiB, 16 steps, four allowlisted join keys, seven-day windows and 10,000 step counts. Activation fails closed unless schema validation and positive/negative/boundary fixtures prove determinism, tenant isolation and cost bounds. Exclusions are exact and time bounded; suppression never erases evidence. No arbitrary SQL, regex, script, shell, managed code or plugin executes from a rule.

## Consequences

PostgreSQL write cost is accepted to obtain restart, replay and forensic reproducibility. OpenSearch is disposable/query-only. Negative correlations complete only after an explicit bounded event-time expiry trigger. Linux remains an environment qualification blocker; macOS and hosted CI remain external blockers. No response, incident/case, AI/ML, UEBA, intelligence, YARA or Sigma-import behavior is authorized by this ADR.
