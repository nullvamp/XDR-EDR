# ADR-0001: Sprint Zero implementation runtime and infrastructure providers

**Status:** Accepted for implementation · **Date:** 2026-08-02

## Context

The implementation handoff leaves language/runtime and concrete provider selection open as implementation ADRs. Sprint Zero needs one cross-platform toolchain, independent service processes, agent portability, deterministic builds and container deployment.

## Decision

Use .NET 8/C# for service and agent foundations; browser-native HTML/CSS/JavaScript for the dependency-free Sprint Zero UI; PostgreSQL 16 for transactional schemas; NATS JetStream for durable messaging; S3-compatible MinIO for local object storage; OpenSearch 2 for local search; JSON structured logs, Prometheus exposition and Activity/OpenTelemetry-compatible trace context. Docker Compose is the supported evaluation profile. Provider-neutral interfaces remain authoritative.

The dependency-free local profile uses durable filesystem adapters so compilation, contract tests and smoke operation do not require external infrastructure. These are supported developer adapters, not production providers. Compose provisions the enterprise-provider classes; Sprint 1 must connect dedicated adapters before claiming enterprise durability.

## Consequences

One service-host binary is configured into independent bounded service processes, eliminating startup-stack drift. It does not merge domain ownership or persistence. The agent shares only stable foundation contracts. No Phase 1 technology decision, public API, domain model or module boundary changes.

## Validation

Release build must produce zero warnings. Core tests validate authentication cryptography, object hash verification, typed durable messages and search health. Smoke tests validate health/readiness, login, authenticated API, registration, heartbeat and frontend rendering.
