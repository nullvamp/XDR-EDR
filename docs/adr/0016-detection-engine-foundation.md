# ADR 0016: Evidence-first detection engine foundation

Status: Accepted for Sprint 12, 2026-08-08.

## Decision

Detection definitions are immutable, tenant-scoped, versioned JSON records using `detection-rule.v1`. They contain only a bounded declarative condition tree. The engine allowlists canonical fields per telemetry domain and supports typed comparisons, exact/CIDR/path/set predicates, bounded globs, boolean composition, event rules, entity rules, and event-time threshold/distinct-count windows. It never executes SQL, regex, scripts, shell commands, C#, JavaScript, or user code.

PostgreSQL is authoritative for definitions, versions, validation/tests, assignments, exclusions, event-time window state, replay snapshots, findings, evidence, history, health, and audit. Live evaluation is fed only after canonical telemetry has been accepted by PostgreSQL. Historical replay reads PostgreSQL—not OpenSearch—and fixes the rule version and definition snapshot at run creation. Production findings use a transactional outbox, NATS, and the strict `platform-detection-findings` OpenSearch projection.

Finding IDs are deterministic over tenant, immutable rule version, execution mode, group, and ordered evidence IDs. Processed-event keys include execution mode and replay run, making live/replay duplicate handling explicit. Threshold state is restart-safe, scoped per run/mode, event-time based, bounded to seven days/10,000 replay events, and expired by event time. Late/incomplete/missing evidence is preserved rather than inferred.

Simulation and dry-run return evaluation results without analyst-visible persistence. Replay defaults to simulation and creates production findings only when explicitly requested. Suppression preserves the candidate finding, evidence, reason, and original finding ID; exclusions are tenant-bound, versioned, audited, time-bounded, exact, measurable, and reject match-all patterns.

The nine starter rules are controlled repository fixtures only. They demonstrate engine correctness and are not production detection content. Findings are not incidents and have no response side effects.

## Consequences and limits

Rules trade expressive power for deterministic resource bounds and security. Unsupported fields/operators fail closed. OpenSearch is a search projection only. Replay cancellation is cooperative between events; a completed small synchronous replay cannot be retroactively cancelled. Linux-native telemetry qualification remains an environment blocker; macOS and hosted CI remain external blockers.
