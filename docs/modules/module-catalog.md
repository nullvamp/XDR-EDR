# Module Catalog and Replacement Boundaries

## Registry telemetry module

The registry adapter boundary is source-specific: Windows native ETW is `windows.etw-registry` and may not be silently replaced or combined with Sysmon semantics. Normalization, durable queue, gateway validation, PostgreSQL authority, outbox/JetStream projection, OpenSearch search, policy/exclusions, health, frontend and export are independently testable through the Sprint 4 suites. A replacement collector must pass the operation, identity, capture, loss, ownership, tenant, recovery and source-limitation contracts before activation.

## Standard module contract

Each module owns its domain state, publishes an OpenAPI/AsyncAPI contract, consumes only declared event versions, exposes health/readiness/metrics, supplies migrations and conformance fixtures, and documents SLO, threat model, data classification and disaster-recovery behavior. Replacement is blue/green: mirror inputs, compare canonical outputs, backfill state, shift reads, shift writes, retain rollback, then retire.

| Module | Purpose; inputs → outputs | Dependencies and interfaces | Scale/test strategy | Replacement strategy |
|---|---|---|---|---|
| Authentication | Federate IdPs and issue sessions; assertions/certs → principal context | external IdP, keys; `IAuthentication` | Stateless replicas; protocol, replay, MFA, outage tests | Broker replacement behind token/session contract |
| Authorization | Central allow/deny/explain; principal+resource+context → decision | tenant graph, roles, audit; `IAuthorization` | Cached decisions with revision invalidation; exhaustive/property/tenant tests | Shadow dual decisions before cutover |
| Tenant Service | Hierarchy, residency, quotas; admin commands → tenant context/events | IAM, KMS, metering | Partition by tenant/region; isolation and ancestry tests | Export/import canonical tenant graph |
| Endpoint Registry | Device/agent identity and lifecycle; enrollment/checkin/inventory → endpoints | PKI, policy, agent gateway; endpoint API | Shard by tenant+device; spoof/dedupe/high-churn tests | Event-rebuildable registry |
| Policy Service | Immutable desired state; versions/assignments → resolved snapshots | registry, authz, update | Cache by source-version tuple; precedence/canary tests | Preserve canonical policy language |
| Configuration Service | Distribute/ack endpoint config; snapshot+capabilities → config/acks | policy, agent transport | Regional cache; offline/mixed-version tests | Agent protocol remains stable |
| Agent Gateway | mTLS transport, sequencing and spool acknowledgements; agent batches/jobs ↔ receipts | PKI, ingest, jobs; `IAgentTransport` | Horizontally partitioned; load/loss/replay/chaos | Protocol conformance enables rewrite |
| Update Service | Signed staged lifecycle; packages+health → rollout state | registry, keys, policy, agent | Rings and regional mirrors; downgrade/power-loss/rollback | Package/manifest protocol is boundary |
| Ingestion | Authenticate, validate, meter and route; batches → raw receipts/events | tenant, schema, queues, raw store | Stateless partitions/backpressure; fuzz/burst/gap tests | Replay raw batches into replacement |
| Normalization | Source adapters to canonical schema; raw → canonical+warnings | schema registry, parser SDK | Source-key partition; golden corpus and loss tests | Parser packages independently replaceable |
| Detection Engine | Compile/evaluate rules; events+content → executions/findings | search/stream, rule registry; `IDetectionEngine` | Engines partition by rule/data; replay, FP, cost tests | Query IR and finding contract isolate engine |
| Correlation Engine | Group findings and build narrative; findings/entities → incidents/edges | entity resolver, graph, CTI | Tenant/time partitions; merge/split/order tests | Rebuild projections from event log |
| Entity Resolver | Canonical identity with confidence; observations → entities/edges | registry, schema, graph | Partition by tenant+key; collision/time tests | Versioned resolver emits superseding links |
| Threat Intelligence | CTI normalization/enrichment; feeds/queries → assertions/verdicts | OpenCTI/MISP adapters; `IThreatIntel` | Cache and async sync; TLP/dedupe/expiry tests | Providers independently swapped |
| Search | Authorized investigation query; IR query → cursor results | index adapters; `ISearch` | Tenant routing, hot/warm tiers; correctness/perf/isolation | Provider adapter + conformance corpus |
| Evidence Store | Immutable custody and export; uploads → verified manifests | object storage, KMS, audit; `IEvidenceProvider` | Multipart regional storage; corruption/hold/export tests | Copy verified objects/manifests, dual verify |
| Artifact Store | Temporary collected objects; job outputs → artifact refs | object storage, malware scan | Quotas/lifecycle; partial upload and malicious file tests | Object-provider neutral manifests |
| Timeline | Ordered investigation projection; events/evidence → cursor timeline | search, entity resolver | Query service/cache; skew/pagination tests | Fully rebuildable projection |
| Response Engine | Validate provider-neutral actions; requests → approved actions/jobs | authz, policy, jobs; `IResponseProvider` | Stateless decision + durable state; blast radius/expiry tests | Provider adapters; action schema stable |
| Job Orchestrator | Durable work state/retry/compensation; jobs/results → transitions | queue, agent, connectors, audit | Partitioned workflow state; idempotency/partition chaos | Export state; workers implement `IJobHandler` |
| Case Management | Cases/tasks/comments; collaboration → case events | IAM, audit, evidence | Tenant partition; concurrency/classification/export tests | Canonical case API supports TheHive/native swap |
| Investigation Engine | Hypotheses, notebooks and graph context; case inputs → conclusions | case, hunt, timeline | Mostly stateless; evidence-citation tests | Notebook/renderers replaceable |
| DFIR Engine | Collection plans and artifact workflows; plan → jobs/evidence | Velociraptor adapter, jobs, evidence | Fan-out with bandwidth budgets; artifact/version/custody tests | `ICollector` isolates Velociraptor |
| Threat Hunting | Federated bounded query execution; query → result set | search, endpoint query, network | Async quota pools; correctness/cancel/cost tests | Query planner targets replaceable providers |
| Connector Runtime | Isolated external integrations; packages/config → typed messages/actions | secrets, jobs, SDK; `IConnector` | Sandboxed workers per trust/tenant; escape/rate/schema tests | Runtime may move to WASM/containers unchanged SDK |
| Plugin Manager | Trust, install, upgrade, revoke; signed package → installation | marketplace, authz, secrets | Control-plane replicas; signature/rollback/compat tests | Manifest/package standard remains canonical |
| Marketplace | Catalog and publisher trust; submissions → signed listings | plugin manager, metering | CDN/read-heavy; supply-chain/admission tests | Catalog backend replaceable via Marketplace API |
| Notification Service | Route redacted messages; events/preferences → deliveries | queue, connectors | Channel workers; retry/dedup/redaction tests | `INotificationChannel` adapters |
| Reporting | Reproducible as-of outputs; definitions → signed artifacts | search, evidence, scheduler | Async workers; snapshot/access/render tests | Renderer/query providers behind contracts |
| Dashboard Service | Saved layouts and aggregates; widget queries → views | search/reporting | Cache tenant-safe results; permission/accessibility tests | UI and aggregate APIs separately replaceable |
| AI Gateway | Governed model/tools and citations; prompt+authorized evidence → messages | authz, model providers, case; `IAIProvider` | Model-specific queues/budgets; injection/leakage/citation evals | Provider-neutral message/tool/citation contract |
| Audit Service | Append-only security record and proof; decisions/actions → audit events | immutable store/KMS; `IAudit` | Partition by tenant/time with external anchors; tamper/gap tests | Dual-write and proof verification before cutover |
| Metrics/Logging | Operational signals with redaction; module telemetry → metrics/logs/traces | observability backend; `IMetrics`,`ILogging` | Regional collectors/sampling; cardinality/redaction tests | Open telemetry contracts prevent lock-in |
| Monitoring/SRE | SLOs, alerts and support bundles; signals → incidents/runbooks | metrics/logging | Independent failure domain; synthetic/chaos tests | Backend replaceable; SLO catalog canonical |
| Metering/Entitlements | Quotas/features/usage reconciliation; usage → decisions/invoices export | tenant, audit | Append usage ledger; bypass/reconciliation tests | Collector replaceable; entitlement API owned |

## Synchronous versus asynchronous rule

Reads and validation previews may be synchronous. Any fan-out, remote endpoint work, scan, report, export, replay, connector sync or action is an asynchronous job returning `202 Accepted`. Domain mutations commit aggregate state and an outbox event atomically; consumers are idempotent. No service waits synchronously for an external security tool.
