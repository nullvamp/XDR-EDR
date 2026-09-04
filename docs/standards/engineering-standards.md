# Engineering Standards

## Design and coding

- Prefer explicit domain names and small cohesive modules. Avoid abbreviations outside established security standards. Types are nouns, commands are imperative verbs, events are past-tense facts.
- No ambient tenant or identity context in background work; pass a verified context envelope explicitly.
- No floating dependency versions, unreviewed generated artifacts, runtime download-and-execute, or secrets in source/config/logs.
- Privileged agent code minimizes unsafe/native surface, allocations in event paths and long-held locks. Platform services bound memory, input size, concurrency and deadlines.
- Comments explain security invariants and rationale, not syntax. Public interfaces and security-sensitive functions require contract documentation.

## Errors, logging and metrics

- Errors are typed, stable and mapped once at boundaries. Never branch on error text. Retry only declared transient failures with jitter and a budget.
- Structured logs require timestamp, severity, service/version, environment/region, request/trace ID, tenant pseudonym, actor type, operation, outcome and stable error code. Raw tokens, secrets, script bodies, email bodies, evidence bytes and full personal data are prohibited.
- Metric names express unit and semantic; labels are bounded. Tenant ID, endpoint ID, user ID and unbounded error text are forbidden metric labels.
- Every service publishes request rate/error/duration, saturation, dependency health, queue lag, data freshness and domain correctness signals. Agent reports CPU/memory/I/O/network/spool/drop health.

## Testing pyramid and gates

| Level | Required scope |
|---|---|
| Unit/property | State machines, parsers, policy precedence, authorization and invariants |
| Contract/conformance | Every API/event/interface/provider implementation against published fixtures |
| Integration | Real supported dependencies, migrations, auth, queues and stores |
| Replay/detection | Versioned benign/attack corpus; expected matches, non-matches and performance |
| End-to-end | Enrollment→event→finding→case→response→evidence export user journeys |
| Security | SAST/SCA/secrets/SBOM, fuzzing, tenant escape, authz, parser and plugin sandbox |
| Performance | OS workload impact, ingest bursts, search concurrency, fleet fan-out and backlog recovery |
| Resilience | dependency loss, partitions, clock skew, certificate/key rotation, region restore |

Changed code must meet coverage defined per risk; coverage percentage never substitutes for invariant tests. Critical authorization, tenant boundary, update, audit, custody and response state machines require branch/property tests and independent security review. Flaky tests are defects and may not be silently retried indefinitely.

## Documentation

Each deployable module must include purpose, owner, data classification, architecture/dependencies, APIs/events, configuration, SLO, scaling, threat model, failure modes, runbook, backup/restore, upgrade/rollback and test evidence. Public changes update documentation in the same PR. Mermaid source lives with its owning document.

## Git, review and release

- Trunk-based development with short-lived branches named `type/issue-summary`; merge queue protects main. Release branches exist only for supported maintenance.
- Commits and release tags are signed. Conventional change categories feed release notes, but semantic version impact is determined by contract tooling and review.
- Two approvals for agent privilege, cryptography, authz, update, evidence, plugin sandbox or destructive response changes; one must be CODEOWNER/security owner.
- PRs are small, linked to an accepted task, include threat/risk statement, tests, documentation and rollout/rollback. Direct pushes and self-approval are prohibited.
- Semantic versioning applies independently to platform release, public API major, agent protocol, schemas, SDKs, plugins and detection content. A platform release BOM pins every constituent version.
- Release flow: freeze BOM → reproducible builds → tests/security scans → sign/attest → staging replay/load → upgrade/rollback rehearsal → canary → health gate → phased rollout → post-release verification.

## Architecture Decision Records

ADRs are immutable after acceptance except status. They contain context, constraints, decision, alternatives, consequences, security/privacy/operations impact, compatibility/migration and validation. Superseding creates a new ADR. Decisions that alter Phase 1 require an explicit impossibility finding and architecture-board approval.

## Definition of Ready

A task is ready only when user/operational outcome, scope/non-scope, owner, dependencies, contract/schema impact, security/privacy classification, acceptance criteria, test fixtures, observability, migration/rollout/rollback and documentation target are known. Unknowns with material architectural impact require a spike/ADR first.

## Definition of Done

Done means accepted contracts and implementation; required tests pass; threat model and dependency scan are current; metrics/logs/runbooks exist; migrations and rollback are rehearsed; accessibility/localization apply; API/schema compatibility is verified; docs/release notes/SBOM are updated; canary evidence meets SLO; no unresolved critical/high vulnerability or unowned risk remains.

## Security response

Follow coordinated disclosure in `SECURITY.md`. A security release can bypass normal cadence but not signing, provenance, targeted regression, rollback or audit. Compromised keys/packages/plugins trigger revocation, customer notification, forensic preservation and root rotation runbooks.

