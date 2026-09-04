# ADR 0036: bounded AI-assisted hunting and detection engineering

Status: Accepted for Sprint 31 Outcome B-Windows.

## Decision

Natural language is never executable platform syntax. `AiEngineeringSafety` translates supported intent into the existing versioned `threat-hunt.v1`, `detection-rule.v1`, or `correlation-rule.v1` contracts. Existing validators, field/operator allowlists, identity rules, cost limits and tenant authorization remain authoritative. Unsupported intent returns `NOT EXPRESSIBLE BY CURRENT DSL`.

AI output is a hash-bound proposal. A hunt requires preview plus explicit execution with the exact proposal hash. A rule may be saved only after an explicit engineer decision, and the repository receives `Draft`, `Enabled=false`, and validation false. There is no AI activation, suppression, response, playbook, shell, SQL, OpenSearch DSL, or arbitrary-code route.

PostgreSQL is the durable authority for tenant-scoped proposals, drafts, simulations, comparisons and audit, with RLS on every Sprint 31 table. Evidence citations, provider/model identity, prompt/evidence/proposal hashes and analyst decisions are retained. ATT&CK suggestions are restricted to the platform-verified inventory. Coverage is derived from telemetry availability, implemented rules, active state, deterministic fixtures and validation—not names.

## Consequences

The deterministic local provider is the only qualified provider. Advisory tuning and exclusions never mutate rules. Historical work is capped at 30 days/10,000 events and the underlying replay source may enforce tighter limits. Remote-model quality, native Linux, physical clusters, macOS and hosted CI remain unqualified.
