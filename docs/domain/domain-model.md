# Canonical Domain Model

## Network connection evidence

`NetworkObservation` is an immutable source event. `NetworkConnectionEntity` is a tenant/endpoint-scoped lifecycle view keyed by native socket identity where reliable, otherwise by process generation, tuple, first observation, and sequence. Out-of-order events may extend history but cannot regress the latest state. Process and hostname relationships are optional evidence, never inferred enrichment.

## Registry telemetry entities

`RegistryKeyEntity` and `RegistryValueEntity` are tenant/endpoint scoped, generation-aware projections of immutable registry events. A key tracks hive/current and previous paths, parent, first/last/create/delete times, state, latest event, confidence, and quality. A value additionally tracks parent key, name, current type/length/hash, change history, and capture/redaction state. Delete followed by recreation creates a new identity even at the same path/name; neither path nor PID alone is an identity key. Histories and process/user edges retain evidence confidence and never infer an unsupported relationship.

## Universal rules

Every aggregate has `id` (typed UUIDv7), `tenant_id`, `created_at`, `created_by`, `updated_at`, `revision`, `labels`, `extensions`, and `schema_version` unless explicitly global. Mutable APIs use optimistic concurrency through `revision`/ETag. Times are UTC RFC 3339 nanoseconds; original source time and offset are preserved. Deletion is stateful (`active → archived → deletion_pending → deleted`) and blocked by legal hold. IDs are never recycled. Cross-tenant foreign keys are prohibited.

Permissions use `resource:verb` with optional conditions and scope, for example `endpoint:read`, `response:isolate`, `evidence:export`. Create/update/delete and sensitive reads emit audit events.

## Identity, tenancy and access

| Object | Purpose and principal fields | Relationships and lifecycle | Permission and extension |
|---|---|---|---|
| **Organization** | Commercial/legal boundary: `name`, `slug`, `billing_profile_ref`, `residency_policy`, `status` | Parent of tenants; provisioned→active→suspended→closed | Platform operator only for creation; extensible regulatory metadata |
| **Tenant** | Hard security/data boundary: `organization_id`, `parent_tenant_id?`, `region`, `kms_key_ref`, `quota_profile_id`, `status` | Hierarchical MSP tree; no implicit child access | `tenant:*`; extensions cannot weaken isolation |
| **Workspace** | Collaborative view boundary: `tenant_id`, `name`, `purpose`, `default_filters`, `retention_overlay?` | Contains cases/dashboards/saved hunts; active→archived | `workspace:*`; not a security substitute for tenant scope |
| **User** | Human principal: `external_subject`, `display_name`, `email`, `status`, `last_auth_at` | Memberships bind users to scopes; invited→active→disabled | PII restricted; authentication remains external |
| **ServiceAccount** | Workload principal: `name`, `owner`, `credential_ids`, `expires_at`, `allowed_networks` | Credentials rotate independently | No interactive session; narrowly scoped |
| **Group** | Principal collection: `name`, `external_group_ref?`, `membership_mode` | Users/service accounts; synced or local | Group administration separate from role grant |
| **Role** | Named permission bundle: `name`, `permissions`, `conditions`, `built_in` | Grants bind role to principal and scope; versioned | Custom role creation requires `role:manage` |
| **Permission** | Global action vocabulary: `resource`, `verb`, `risk_class`, `description` | Referenced by role; append-only vocabulary | Platform-defined; plugins request declared permissions |
| **RoleGrant** | Principal authorization: `principal_id`, `role_id`, `scope_type/id`, `valid_from/to`, `justification` | requested→approved→active→expired/revoked | High-risk grants require separate approver |
| **APICredential** | API key/certificate metadata: `principal_id`, `type`, `public_fingerprint`, `scopes`, `expires_at`, `last_used_at` | issued→active→rotating→revoked | Secret material never stored in domain response |
| **Approval** | Four-eyes decision: `subject_type/id`, `requested_by`, `required_policy`, `decision`, `decided_by`, `expires_at` | pending→approved/rejected/expired/consumed | Requester cannot self-approve when policy forbids |

## Endpoint, agent and configuration

| Object | Purpose and principal fields | Relationships and lifecycle | Permission and extension |
|---|---|---|---|
| **Endpoint** | Canonical managed asset: `device_identity`, `hostname`, `os`, `os_version`, `architecture`, `risk`, `health`, `last_seen_at`, `ownership` | Has agents, inventories, policies, findings; discovered→enrolled→active→stale→retired | Group/scoped endpoint permissions; custom asset fields in extensions |
| **Agent** | Installed platform runtime: `endpoint_id`, `instance_id`, `version`, `capabilities`, `public_key`, `channel`, `health`, `last_checkin` | One active instance per install slot; enrolling→active→quarantined→revoked | Agent may access only its endpoint jobs/config |
| **EnrollmentToken** | Bounded enrollment authority: `scope`, `max_uses`, `uses`, `expires_at`, `constraints`, `secret_hash` | created→active→exhausted/expired/revoked | Reveal once; audit every use |
| **Collector** | Telemetry capability descriptor: `agent_id`, `type`, `version`, `source`, `state`, `cost_profile` | Advertised through capability negotiation | Configuration requires policy permission |
| **EndpointGroup** | Dynamic/static targeting: `name`, `selector`, `membership_mode`, `priority` | Resolves endpoints; membership snapshots versioned | Prevent circular nesting |
| **Policy** | Named desired-state aggregate: `name`, `scope`, `priority`, `current_version_id`, `status` | Has immutable versions and assignments | Draft/edit separate from publish |
| **PolicyVersion** | Immutable policy: `policy_id`, `number`, `schema_version`, `content`, `content_hash`, `compatibility`, `change_summary` | draft→validated→approved→published→superseded | Published version immutable/signed |
| **PolicyAssignment** | Target binding: `policy_version_id`, `target`, `precedence`, `rollout`, `effective_window` | planned→canary→rolling→complete/paused/rolled_back | Dangerous changes require approval |
| **ConfigurationSnapshot** | Fully resolved endpoint config: `endpoint_id`, `source_versions`, `content_hash`, `resolved_content`, `explanation` | generated and acknowledged by agent | Readable by endpoint operators; immutable |
| **AgentUpdate** | Signed rollout: `package_id`, `from/to_version`, `targets`, `rings`, `health_gates`, `rollback_version` | planned→canary→rolling→completed/rolled_back | Release role plus approval |
| **SoftwareInventory** | Installed package snapshot/delta: `endpoint_id`, `observed_at`, `items`, `source` | Temporal; superseded, retained by policy | Read with endpoint inventory scope |
| **HardwareInventory** | CPU/memory/disk/firmware/device snapshot: `endpoint_id`, `observed_at`, `components` | Temporal | Sensitive serials masked by policy |
| **CertificateRecord** | Observed cert metadata: `endpoint_id?`, `subject`, `issuer`, `fingerprints`, `validity`, `locations` | Observed→expired/removed | Private key is never collected |

## Telemetry, evidence and analytics

| Object | Purpose and principal fields | Relationships and lifecycle | Permission and extension |
|---|---|---|---|
| **TelemetryEvent** | Immutable canonical observation: envelope, event kind, actor/target, process/file/network attributes, source and provenance | Links endpoints/entities/evidence; accepted→normalized→tiered→expired | Field-level controls; extensions namespaced |
| **RawEvent** | Unmodified source payload: `source`, `received_at`, `payload_ref/hash`, `parser_hint` | One raw event may produce multiple canonical events | Restricted evidence-like access |
| **TimelineEvent** | Investigation projection: `effective_time`, `time_confidence`, `summary`, `entity_refs`, `source_event_refs` | Rebuildable projection; not evidence | Case/hunt read permission |
| **Artifact** | Collected logical item: `kind`, `name`, `media_type`, `size`, `hashes`, `acquisition`, `object_ref` | May be evidence after custody acceptance | Collection and download separated |
| **Evidence** | Legally defensible artifact/event set: `manifest_ref`, `hashes`, `custody_state`, `classification`, `legal_hold`, `verification` | acquired→verified→sealed→exported→disposed | Export high-risk and audited |
| **CustodyEvent** | Append-only evidence handling record: `evidence_id`, `action`, `actor`, `time`, `location`, `prior_hash`, `record_hash` | Hash-linked sequence | Append by system; verifier read |
| **DetectionRule** | Portable/native rule aggregate: `format`, `content_ref`, `version`, `status`, `severity`, `confidence`, `required_fields`, `cost_budget`, `license`, `tests` | draft→validated→approved→enabled→deprecated | Detection engineer; publish approval |
| **SigmaRule** | Sigma specialization: `sigma_id`, `yaml_ref`, `mapping_profile`, `compiled_plans` | Belongs to DetectionRule | Preserve upstream provenance |
| **YaraRule** | YARA specialization: `namespace`, `source_ref`, `engine_range`, `scan_budget` | Belongs to DetectionRule | Execution sandboxed |
| **DetectionExecution** | Rule evaluation record: `rule_version`, `window`, `engine`, `input_refs`, `metrics`, `result` | Produces zero/more findings | Operational read; immutable |
| **Finding** | Evidence-supported analytic conclusion: `type`, `rule_ref`, `severity`, `confidence`, `status`, `entity_refs`, `evidence_refs`, `reason` | new→triaged→confirmed/benign→closed/reopened | Triage/update; evidence immutable |
| **Alert** | Notification/work-queue projection of findings: `finding_ids`, `priority`, `assignee`, `sla`, `status` | queued→acknowledged→investigating→resolved | SOC workflow permissions |
| **Entity** | Resolved host/user/IP/domain/process/cloud resource: `type`, `canonical_key`, `attributes`, `confidence` | Connected by typed temporal edges | Sensitive identity fields controlled |
| **EntityEdge** | Temporal relationship: `from/to`, `relationship`, `valid_from/to`, `confidence`, `evidence_refs` | Immutable versions | Derived; explainable |
| **Incident** | Correlated security episode: `title`, `severity`, `status`, `finding_ids`, `entity_graph_ref`, `first/last_seen`, `correlation_reason` | detected→triaged→contained→eradicated→recovered→closed | Incident responder role |

## Threat intelligence

| Object | Purpose and principal fields | Relationships and lifecycle | Permission and extension |
|---|---|---|---|
| **Indicator** | Observable with validity: `pattern/type/value`, `valid_from/until`, `confidence`, `tlp`, `sources`, `revoked` | Matches telemetry; feeds/threats | TLP and source license enforced |
| **Threat** | Malware/tool/intrusion-set abstraction: `type`, `name`, `aliases`, `description`, `confidence` | Actors, campaigns, techniques, indicators | CTI editor |
| **ThreatActor** | Actor/group knowledge: `name`, `aliases`, `motivation`, `sophistication`, `confidence` | Campaigns/threats | Assertions retain source/provenance |
| **Campaign** | Time-bounded activity: `name`, `first/last_seen`, `objectives`, `regions`, `sectors` | Actors, indicators, incidents | Tenant overlays do not mutate source intel |
| **ThreatFeed** | Ingestion/share contract: `provider`, `direction`, `schedule`, `marking`, `license`, `health` | Produces CTI objects | Secret refs only |
| **IntelAssertion** | Sourced statement: `subject/predicate/object`, `source_ref`, `confidence`, `marking`, `observed_at` | Enables conflicting claims | Immutable; revocation adds assertion |

## Investigation and response

| Object | Purpose and principal fields | Relationships and lifecycle | Permission and extension |
|---|---|---|---|
| **Case** | Durable collaborative record: `workspace_id`, `title`, `status`, `severity`, `owner`, `incident_ids`, `classification`, `sla` | open→investigating→contained→closed→reopened | Case role and classification controls |
| **Investigation** | Scoped analytic effort: `case_id`, `hypothesis`, `scope`, `lead`, `status`, `conclusion`, `confidence` | planned→active→concluded/cancelled | Conclusions require evidence citations |
| **Task** | Assigned unit of case work: `case_id`, `title`, `assignee`, `due_at`, `status`, `dependencies` | todo→doing→blocked→done/cancelled | Case collaborator |
| **Comment** | Append-oriented collaboration: `parent_type/id`, `body`, `mentions`, `classification`, `edited_at` | Create; edits retain history; redact via controlled event | Authors/editors; export respects marking |
| **SavedHunt** | Versioned query package: `language`, `query`, `parameters`, `sources`, `time_range`, `budget`, `schedule?` | draft→validated→active→archived | Hunt execute separate from edit |
| **HuntExecution** | Query run: `hunt/version`, `requester`, `scope`, `started/completed`, `status`, `cost`, `result_ref` | queued→running→completed/failed/cancelled | Quota and row-level authorization |
| **ResponseAction** | Provider-neutral intended effect: `type`, `target`, `parameters`, `risk`, `justification`, `approval_policy`, `expires_at` | requested→approved→dispatched→succeeded/failed/reversed/expired | Type-specific response permission |
| **ResponseJob** | Durable execution: `action_id`, `provider`, `idempotency_key`, `attempts`, `state`, `result`, `compensation_job_id?` | strict state machine; append transitions | Orchestrator only mutates |
| **Script** | Governed remote content: `name`, `language`, `content_ref/hash`, `signature`, `parameters_schema`, `platforms`, `risk`, `version` | draft→reviewed→approved→deprecated/revoked | Execute and author are separate permissions |
| **CollectionPlan** | DFIR artifact plan: `artifacts`, `targets`, `budgets`, `encryption`, `destination`, `custody_policy` | draft→approved→executing→complete | Collection permission and scope approval |

## Extensibility, integration and experience

| Object | Purpose and principal fields | Relationships and lifecycle | Permission and extension |
|---|---|---|---|
| **Connector** | Configured external integration: `package_id`, `instance_name`, `direction`, `capabilities`, `config_ref`, `health`, `service_account_id` | installing→configured→active→degraded→disabled→removed | Connector admin; secrets never returned |
| **PluginPackage** | Signed distributable: `publisher`, `name`, `version`, `manifest`, `digest`, `signature`, `sbom`, `permissions`, `compatibility` | submitted→scanned→approved→published→deprecated/revoked | Marketplace trust authority |
| **PluginInstallation** | Tenant installation: `package_id`, `config_ref`, `granted_permissions`, `status`, `pinned_version` | requested→approved→installed→upgrading→removed | Grant cannot exceed manifest request |
| **IntegrationHealth** | Operational status: `subject`, `checks`, `last_success`, `lag`, `error_class` | Time-series projection | Operator and support-safe view |
| **Notification** | Routed user/system message: `type`, `recipient`, `channel`, `template_version`, `payload_ref`, `status` | queued→sent/delivered/failed/suppressed | Sensitive fields redacted per channel |
| **ReportDefinition** | Versioned report query/layout: `name`, `parameters`, `data_contracts`, `schedule`, `format` | draft→published→superseded | Report author |
| **ReportRun** | Immutable generated output: `definition_version`, `parameters`, `as_of`, `status`, `artifact_ref` | queued→running→complete/failed/expired | Output classification inherited |
| **Dashboard** | Saved role-oriented view: `workspace_id`, `layout`, `widgets`, `filters`, `visibility` | draft→published→archived | Shared/private controls |
| **AIModel** | Model/provider registration: `provider`, `model_id`, `capabilities`, `residency`, `data_policy`, `evaluation_status` | proposed→evaluated→approved→suspended/retired | AI admin; secrets external |
| **AISession** | Authorized investigation context: `case_id?`, `model_id`, `purpose`, `scope`, `tool_policy`, `status`, `token_usage` | active→closed/expired | Same authorization as underlying evidence |
| **AIMessage** | User/assistant/tool turn: `session_id`, `role`, `content_ref`, `tool_call_ref`, `safety_labels` | Append-only; redaction event possible | Session participants/auditors |
| **AICitation** | Claim-to-evidence link: `message_id`, `claim_span`, `source_ref`, `source_hash`, `retrieved_at`, `support_level` | Immutable | Source permission rechecked on access |
| **AuditEvent** | Security-relevant record: `actor`, `action`, `resource`, `decision`, `request_id`, `source_ip`, `before/after_hash`, `outcome` | Append-only, hash-batched and retained | Auditor read; no tenant admin mutation |

## Aggregate boundaries

Tenant, Endpoint, Policy, DetectionRule, Incident, Case, ResponseAction, PluginPackage and AISession are transaction boundaries. Cross-aggregate effects use outbox events and idempotent consumers; distributed transactions are forbidden. External STIX and vendor objects are preserved as source documents and mapped to canonical projections so future remapping never destroys provenance.
