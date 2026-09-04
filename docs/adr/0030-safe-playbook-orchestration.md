# ADR 0030: Safe bounded playbook orchestration

Status: Accepted for Sprint 25

## Decision

Playbooks are immutable, tenant-scoped `playbook.v1` definitions pinned by ID, version and SHA-256 definition hash. Executions are deterministic `playbook-execution.v1` records. PostgreSQL JSONB is authoritative for definitions, fixture results, execution state, work and immutable audit events.

The graph is limited to 64 steps, branching 4, concurrency 4 and one hour. Condition trees are limited to depth 8 and 32 predicates; step input is limited to 16 KiB. Retries are limited to three attempts. Independent LOW-risk structured actions may run concurrently up to the definition cap; all other work remains deterministic and approval-aware. A failed step may select one declared typed failure branch and the final state remains `Partial`, never `Succeeded`.

Only actions already present in `ResponseSafety.Definitions` can be selected. The registry contains no shell, PowerShell, arbitrary Live Response, script, HTTP, SQL, OpenSearch DSL or AI execution primitive. Safe automatic mode executes only LOW-risk registered actions. HIGH and CRITICAL actions require an exact, expiring approval bound to execution, step, target and input hash with requester/approver separation. The response adapter re-resolves endpoint installation and target parameters immediately before creating the existing signed response action, then waits for its verified terminal result.

Simulation and dry-run produce a complete step plan and approval requirements without invoking the response executor. Execution IDs are derived from tenant, immutable playbook identity, trigger source and idempotency key. Recursion depth is zero; source execution and trigger lineage are rejected. Durable work uses a dedicated bounded PostgreSQL queue with row locking, bounded attempts and dead-letter state, separate from telemetry transport.

## Rollback boundary

Compensation is an explicit typed step using an already registered inverse action. Endpoint isolation can use unisolate; quarantine can use restore; supported persistence remediation can use its verified backup/restore contract. Process termination and permanent deletion are irreversible and are never labelled rollback-capable. The orchestrator does not synthesize compensation or execute arbitrary recovery code.

## Consequences

Automation remains constrained by the safety and identity properties of the existing response engine. Repository-controlled executors qualify orchestration paths without mutating the development host. Sprint 25 does not re-qualify every destructive endpoint primitive; those retain their prior victim-VM qualification evidence.
