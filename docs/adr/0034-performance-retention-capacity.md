# ADR 0034: measured capacity, bounded retention, and storage lifecycle

Status: Accepted for Sprint 29 Outcome B-Windows.

PostgreSQL remains authoritative; OpenSearch remains a rebuildable search projection; NATS remains transport; MinIO remains content-addressed object evidence. Capacity samples are versioned and always bind platform version, topology, hardware, native-agent count, simulated identity count, domain mix, duration, dataset size, and retention assumptions. A local simulation is never described as physical endpoint scale.

Retention policies are immutable versions per tenant and evidence class. Destructive execution requires a current preview hash, exact policy version, ten-minute expiry, an isolated supported scope, and batches of at most 5,000. Active incident, forensic, quarantine, legal/administrative, replay, export, and investigation holds exclude evidence. Active references also exclude records. Runs are audited and restart/idempotency safe; archive-before-delete records tenant, time range, schema version, count, and manifest hash.

PostgreSQL lifecycle uses tenant/time indexes, partition-compatible design, bounded batches, and separately qualified time partitions; existing critical tables are not blindly repartitioned. OpenSearch uses versioned indexes, one-shard local rollover fixtures, aliases, and rebuild compatibility; projection expiry never implies authority loss. MinIO lifecycle is exercised only on qualification objects: unheld temporary content is hash-verified and deleted, while held evidence is preserved.

Tenant rate windows cover ingest, search, replay, export, forensic transfer, playbooks, and updates. Concurrency bounds cover forensic and playbook work. Metrics have no tenant/endpoint labels. Planner output is an estimate based on a named measured sample, redundancy, retention, and margin—not a purchasing promise.

Consequences: customer-scale and multi-day claims require representative hardware, physical agents or honestly labeled simulated identities, and longer qualification. True clustered infrastructure remains an environment blocker.
