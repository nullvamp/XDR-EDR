# ADR 0035: evidence-grounded AI investigation

Status: Accepted for Sprint 30.

## Decision

AI is a tenant-scoped, optional, read-only investigation projection over existing authoritative records. `IAiProvider` is provider-neutral. Sprint 30 qualifies `local-evidence/local-evidence-v1`, a deterministic private evidence renderer; it sends no data externally and exposes no tools. A versioned policy selects provider, permitted models/use cases/evidence, `LOCAL_ONLY`, `REMOTE_REDACTED`, or explicitly authorized `REMOTE_FULL`, redaction, retention, context/output/request/concurrency/retry/timeout bounds. No remote adapter is qualified in this sprint.

PostgreSQL owns policies, conversations, messages, evidence packages, note drafts, acceptance and audit. Model/provider memory is never authoritative. Retrieval is application-owned, deterministic, tenant/RBAC bound, context-specific and bounded; providers receive only a canonical package, never SQL, OpenSearch DSL, credentials, shell, response or playbook tools.

Each material claim is typed `Observed`, `Derived`, `Inference`, `Ambiguous`, or `Unknown`, uses bounded confidence, and must cite an included stable evidence ID. Output is rejected if it is non-read-only, contains active content, omits mandatory citations, duplicates/substitutes/fabricates citations, or returns an unauthorized provider/model. Empty or truncated evidence remains explicit uncertainty.

AI notes remain drafts until an analyst explicitly accepts them. Advice cannot create response actions or start playbooks. AI failure and rate limiting do not affect telemetry, detection, hunting, incidents, response, or transport.

## Consequences

The local qualified provider is intentionally narrower than a general LLM: its value is deterministic evidence explanation and a secure provider boundary. Remote-model quality, external-provider availability and external data handling remain `EXTERNAL BLOCKER` until a separately configured provider is implemented and qualified. Native Linux/cluster scale and hosted platform blockers remain unchanged.
