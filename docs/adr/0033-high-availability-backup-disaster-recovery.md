# ADR 0033: single-site resilience, durable ownership, and recovery

Status: accepted for Sprint 28 on 2026-08-11.

## Decision

PostgreSQL is the authoritative store for security state, resumable-transfer cursors, service-instance heartbeats, worker leases, fencing generations, object inventory, backup records, and DR-drill records. Two stateless gateways use the same image and may serve any request. Singleton background workers acquire a 20-second PostgreSQL lease, heartbeat every five seconds, and stop when compare-and-swap heartbeat loses the owner/generation. Request/poll domains use a named recovery-coordinator lease while their actual mutations remain transactionally idempotent or CAS fenced.

NATS is durable transport, OpenSearch is a rebuildable projection, and MinIO holds objects whose authoritative size/SHA-256 inventory is in PostgreSQL. Large-transfer metadata is shared in PostgreSQL; chunk bytes use shared gateway storage until verified assembly and upload. Finalization requires every ordered chunk and the overall SHA-256.

Production gateways never run schema migrations. A single external migration owner applies reviewed migrations after backup; each gateway runs a schema-compatibility guard and refuses an incompatible Sprint 28 schema. Rollback is forward-fix or database restore because destructive down-migration is not promised.

## Safety properties

- Lease identity is `(job_type, job_id, worker_id, generation)` with acquisition, expiry, heartbeat, release, and audit.
- A stale owner cannot renew or release a later generation.
- Response/action envelopes, playbook executions, forensic collections, and update assignments retain their existing durable identities and replay protections across gateway replacement.
- Transfer progress is monotonic and tenant/endpoint/agent/installation/owner bound; conflicting duplicates fail closed.
- Object downloads rehash content and fail closed on inventory mismatch.
- Readiness is `503 not_ready` when PostgreSQL authority is unavailable and `200 ready_degraded` when optional NATS, OpenSearch, or MinIO is unavailable.

## Qualification boundary

Qualified: two local gateways, single-site worker takeover, dependency restart, shared transfer resumption, logical PostgreSQL backup and isolated restore, object inventory verification, and exact projection reconciliation. Not qualified: automatic PostgreSQL failover, a NATS cluster, multi-node OpenSearch, distributed MinIO, multi-region routing, native Linux environment, macOS, or hosted CI.

