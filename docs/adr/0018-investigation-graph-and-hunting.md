# ADR 0018: Evidence-first investigation graph and bounded hunting

Status: accepted for Sprint 14 on 2026-08-08.

## Decision

The investigation layer is a reproducible view over authoritative telemetry, detection findings, and correlated findings. Stable native entity identities form nodes. A relationship is persisted only when it carries exact source evidence IDs and references, observation bounds, confidence, provenance, ambiguity, and a relationship version. PostgreSQL owns entities, relationships, saved-hunt versions, and hunt runs. OpenSearch may accelerate existing bounded searches but is never exposed as an analyst query language or treated as authoritative for deterministic relationships.

Process lineage uses `process_entity_id` and explicit `parent_process_entity_id`; PID, display name, path, or temporal proximity alone cannot create an edge. Canonical events project graph data after normalization on the established NATS consumer path. Correlated findings project exact child-finding edges.

Graph traversal is server bounded to depth 8, 500 nodes, 1,000 edges, 100 expansions per node, 30 days, 200 page items, and 10 seconds. Cursors include tenant binding. The hunt DSL allowlists fields, operators, entity types, and relationship joins; it permits no SQL, OpenSearch DSL, regex, script, shell, or executable content. Hunts are bounded to 32 predicates, eight nesting levels, three join levels, 2,000 results, and 10 seconds.

Attack stories contain no new truth or probabilistic narrative. They deterministically order graph entities and relationships and preserve missing telemetry, ambiguity, source gaps, evidence, provenance, findings, and ATT&CK metadata.

## Consequences

Analysts receive repeatable trees, graphs, stories, pivots, hunts, and integrity exports without weakening tenant boundaries. Large traversals truncate and paginate honestly. Restart durability is provided by PostgreSQL. Automated response, incident/case workflow, AI/ML, arbitrary query execution, and remediation remain outside Sprint 14.
